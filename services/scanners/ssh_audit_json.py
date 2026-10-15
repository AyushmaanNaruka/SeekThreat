"""Pure ssh-audit JSON parser: turns one captured artifact into Observation objects.

Kept separate from `ssh_audit_adapter.py` so the subprocess concern (invoking the tool)
and the parsing concern (interpreting its output) stay independently testable — this
module never touches a process, a socket or a clock.

LICENCE NOTE: ssh-audit (github.com/jtesta/ssh-audit) is MIT licensed. We invoke the
binary and parse its `-j` output; none of its source is vendored or linked.

What ssh-audit's JSON contains (verified against real captures from v2.9.0 and v3.9.0,
see tests/fixtures/ssh_audit/README.md):

  - `target`   "<host>:<port>". For IPv6 the host is NOT bracketed ("::1:22"), so the
               port is whatever follows the last colon.
  - `banner`   {raw, software, protocol, comments}. `protocol` is the string "2.0" in
               v3 and the list [2, 0] in v2; both are accepted.
  - `kex`, `enc`, `mac`, `key`  the server's advertised algorithms. v3 gives each as
               {algorithm, notes: {fail, warn, info lists of strings}, keysize?}. v2 gives
               `kex`/`key` as {algorithm, keysize?} and `enc`/`mac` as bare name strings,
               with no notes anywhere, so it reports weak algorithms only through
               `recommendations`.
  - `recommendations`  {critical|warning: {del|chg|add: {category: [{name, notes}]}}}.
  - `cves`     [{name, cvssv2, description}]. ssh-audit v3 always emits `[]` (its source
               says "Historically, CVE information was returned"); only v2.x populates it.
               It is still parsed so output from an older install is not silently lost.

Observations emitted (all with Source.SCANNER; severity is NOT assigned here — that is
services.enrichment's job):

  SERVICE_VERSION  one per audited listener. subject = `<host>:<port>/tcp`, spelled exactly
                   like nmap's port subject (IPv6 bracketed) so it joins to nmap's
                   port_open / service_version facts. Confidence HIGH: the banner is what
                   the server announced on the wire.
  VULN_CANDIDATE   finding_type=cve, one per entry of ssh-audit's `cves` array. Confidence
                   LOW: ssh-audit derives these purely from the banner's version string.
                   Distributions backport security fixes without changing the upstream
                   version number (Debian/Ubuntu/RHEL openssh packages routinely do), so a
                   banner-only mapping produces false positives. It is an inference, not
                   evidence the vulnerable code path exists. `scanner_cvssv2` keeps
                   ssh-audit's own score verbatim and is NOT a severity.
  VULN_CANDIDATE   finding_type=weak_algorithm, one per (category, algorithm) that ssh-audit
                   labels fail or warn. Confidence HIGH: the server advertised that
                   algorithm in its KEXINIT, a direct protocol fact; `level` records how
                   ssh-audit's own database judged it ("fail" or "warn", never
                   re-labelled here). `recommendations` entries are folded in as
                   `recommendation` rather than emitted separately, so nothing is counted
                   twice. `add` recommendations (algorithms the server lacks) are not
                   findings and are ignored.

Downstream code tells the two candidate kinds apart by the `finding_type` attribute.

ssh-audit's JSON carries no run timestamp, so the adapter keeps the base class's
`_captured_at` (wall clock at capture, stored once on the RawArtifact) and every
observation's observed_at / retrieved_at is that artifact timestamp. Parsing therefore
never reads a clock: same artifact in, byte-identical observations out.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from packages.schema.models.observation import Observation, ObservationKind, RawArtifact
from packages.schema.models.provenance import Confidence, Provenance, Source

__all__ = ["SshAuditParseError", "parse_ssh_audit_json"]


class SshAuditParseError(Exception):
    """Raised when ssh-audit JSON output cannot be safely or meaningfully parsed."""


_ID_NAMESPACE = "seekthreat.obs.v1"
_SCANNER = "ssh-audit"

_MAX_CONTENT_BYTES = 64 * 1024 * 1024
_MAX_ATTR_LEN = 512
_TRUNCATION_MARKER = "…[truncated]"
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")

_CATEGORIES = ("enc", "kex", "key", "mac")
_CVE_RE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
_PORT_RE = re.compile(r"^[0-9]{1,5}$")
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._\-]*[A-Za-z0-9])?$")
# "OpenSSH_8.2p1", "dropbear_2020.81", "Cisco-1.25", "OpenSSH_for_Windows_8.1". The
# product is matched lazily so the version starts at the LAST separator followed by a
# digit.
_SOFTWARE_RE = re.compile(r"^(?P<product>[A-Za-z][A-Za-z0-9._+\-]*?)[_\-](?P<version>[0-9]\S*)$")
_RAW_BANNER_RE = re.compile(r"^SSH-[0-9]+\.[0-9]+-(?P<software>\S+)")

# ssh-audit's own labels, ordered so max() picks the worse one.
_LEVEL_RANK = {"warn": 1, "fail": 2}
# recommendations.<severity> -> the note level it corresponds to.
_RECOMMENDATION_LEVELS = (("critical", "fail"), ("warning", "warn"))
_RECOMMENDATION_ACTIONS = {"del": "remove", "chg": "change"}


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #


def parse_ssh_audit_json(artifact: RawArtifact, engagement_id: str) -> tuple[Observation, ...]:
    """Convert one captured ssh-audit `-j` artifact into Observation objects.

    Pure function of (artifact, engagement_id): re-running this on the same artifact
    always produces byte-identical output in a fixed order.
    """
    data = _load(artifact.content)
    retrieved_at = artifact.captured_at

    host, port = _split_target(data.get("target"))
    endpoint = _endpoint(host, port)

    banner = _as_dict(data.get("banner"))
    banner_raw = _text(banner.get("raw"))

    def build(
        kind: ObservationKind,
        attributes: dict[str, str],
        confidence: Confidence,
        note: str,
    ) -> Observation:
        return _build_observation(
            engagement_id=engagement_id,
            artifact_id=artifact.artifact_id,
            kind=kind,
            subject=endpoint,
            attributes=attributes,
            observed_at=retrieved_at,
            retrieved_at=retrieved_at,
            confidence=confidence,
            note=note,
        )

    observations: list[Observation] = []

    service_attrs = _service_attrs(banner)
    if service_attrs:
        observations.append(
            build(
                ObservationKind.SERVICE_VERSION,
                service_attrs,
                Confidence.HIGH,
                "ssh-audit SSH identification banner",
            )
        )

    for cve in _cve_findings(data.get("cves")):
        attrs = {"finding_type": "cve", "endpoint": endpoint, **cve}
        if banner_raw:
            attrs["banner"] = _sanitize(banner_raw)
        observations.append(
            build(
                ObservationKind.VULN_CANDIDATE,
                attrs,
                Confidence.LOW,
                f"ssh-audit banner-version CVE mapping for {cve['cve_ids']} "
                "(inference; distribution backports can make this a false positive)",
            )
        )

    for weak in _weak_algorithms(data):
        attrs = {"finding_type": "weak_algorithm", "endpoint": endpoint, **weak}
        observations.append(
            build(
                ObservationKind.VULN_CANDIDATE,
                attrs,
                Confidence.HIGH,
                f"ssh-audit {weak['level']}: {weak['category']} {weak['algorithm']} "
                "advertised by the server",
            )
        )

    observations.sort(
        key=lambda o: (
            o.subject,
            o.kind.value,
            o.attributes.get("finding_type", ""),
            o.attributes.get("category", ""),
            o.attributes.get("algorithm", ""),
            o.attributes.get("cve_ids", ""),
            o.observation_id,
        )
    )
    return tuple(observations)


# --------------------------------------------------------------------------- #
# Loading and structural helpers
# --------------------------------------------------------------------------- #


def _load(content: str) -> dict[str, Any]:
    if len(content.encode("utf-8")) > _MAX_CONTENT_BYTES:
        raise SshAuditParseError("ssh-audit output exceeds maximum allowed size (64MB)")
    stripped = content.strip()
    if not stripped:
        raise SshAuditParseError("ssh-audit output is empty; a successful run always emits JSON")
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise SshAuditParseError(f"Malformed ssh-audit JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise SshAuditParseError("ssh-audit JSON is not an object at the top level")
    return data


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _algorithms(value: Any) -> list[tuple[str, dict[str, Any]]]:
    """(name, entry) for each advertised algorithm. v3 entries are objects; v2 `enc` and
    `mac` entries are bare name strings, which carry no further fields."""
    found: list[tuple[str, dict[str, Any]]] = []
    for entry in _as_list(value):
        if isinstance(entry, str):
            name, fields = entry.strip(), {}
        else:
            fields = _as_dict(entry)
            name = _text(fields.get("algorithm"))
        if name:
            found.append((name, fields))
    return found


def _text(value: Any) -> str:
    """A scalar the scanner reported as text; anything structured counts as absent."""
    if isinstance(value, bool) or value is None:
        return ""
    if isinstance(value, str | int | float):
        return str(value).strip()
    return ""


def _sanitize(value: str) -> str:
    """Strip control characters and truncate to max length."""
    cleaned = _CONTROL_CHARS_RE.sub("", value)
    if len(cleaned) > _MAX_ATTR_LEN:
        return cleaned[: _MAX_ATTR_LEN - len(_TRUNCATION_MARKER)] + _TRUNCATION_MARKER
    return cleaned


def _split_target(target: Any) -> tuple[str, int]:
    """Split ssh-audit's `<host>:<port>` target. The last colon is the port separator
    because an IPv6 host is emitted unbracketed."""
    if not isinstance(target, str) or not target.strip():
        raise SshAuditParseError("ssh-audit JSON has no 'target'; cannot attribute the findings")
    head, sep, tail = target.strip().rpartition(":")
    host = head.strip("[]")
    if not sep or not host or not _PORT_RE.match(tail) or not 0 < int(tail) < 65536:
        raise SshAuditParseError(f"ssh-audit 'target' is not <host>:<port>: {target!r}")
    return host, int(tail)


def _endpoint(host: str, port: int) -> str:
    """The nmap-compatible `<host>:<port>/tcp` join key (IPv6 bracketed, compressed).

    nmap's `_port_subject` keys every port_open / service_version observation, so an
    ssh-audit fact must spell its listener identically or nothing can join them.
    """
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        if not _HOSTNAME_RE.match(host):
            raise SshAuditParseError(f"ssh-audit 'target' host is not usable: {host!r}") from None
        return f"{host}:{port}/tcp"
    if ip.version == 6:
        return f"[{ip.compressed}]:{port}/tcp"
    return f"{ip.compressed}:{port}/tcp"


# --------------------------------------------------------------------------- #
# Fact extraction
# --------------------------------------------------------------------------- #


def _service_attrs(banner: Mapping[str, Any]) -> dict[str, str]:
    raw = _text(banner.get("raw"))
    software = _text(banner.get("software"))
    if not software:
        match = _RAW_BANNER_RE.match(raw)
        software = match.group("software") if match else ""
    if not raw and not software:
        return {}

    attrs: dict[str, str] = {"service_name": "ssh"}
    if software:
        split = _SOFTWARE_RE.match(software)
        if split:
            attrs["product"] = _sanitize(split.group("product").lower())
            attrs["version"] = _sanitize(split.group("version"))
        else:
            attrs["product"] = _sanitize(software.lower())
    if raw:
        attrs["banner"] = _sanitize(raw)
    protocol = banner.get("protocol")
    if isinstance(protocol, list):
        proto_text = ".".join(str(p) for p in protocol if isinstance(p, int))
    else:
        proto_text = _text(protocol)
    if proto_text:
        attrs["protocol"] = _sanitize(proto_text)
    comments = _text(banner.get("comments"))
    if comments:
        # Distribution patch level ("Ubuntu-4ubuntu0.5") lives here; it is what tells
        # enrichment whether a banner-based CVE could be a backported false positive.
        attrs["banner_comments"] = _sanitize(comments)
    return attrs


def _cve_findings(cves: Any) -> list[dict[str, str]]:
    """One attribute dict per distinct, well-formed CVE ssh-audit reported."""
    found: dict[str, dict[str, str]] = {}
    for entry in _as_list(cves):
        item = _as_dict(entry)
        cve_id = _text(item.get("name")).upper()
        if not _CVE_RE.fullmatch(cve_id) or cve_id in found:
            continue
        attrs = {"cve_ids": cve_id}
        description = _text(item.get("description"))
        if description:
            attrs["description"] = _sanitize(description)
        cvss = item.get("cvssv2")
        if not isinstance(cvss, bool) and isinstance(cvss, int | float):
            attrs["scanner_cvssv2"] = _sanitize(str(cvss))
        found[cve_id] = attrs
    return [found[key] for key in sorted(found)]


def _note_list(notes: Mapping[str, Any], level: str) -> list[str]:
    return [t for t in (_text(n) for n in _as_list(notes.get(level))) if t]


def _weak_algorithms(data: Mapping[str, Any]) -> list[dict[str, str]]:
    """One attribute dict per (category, algorithm) that ssh-audit rates fail or warn."""
    # (category, algorithm) -> {"fail": [...], "warn": [...]} note texts. `rated` records
    # which levels ssh-audit assigned, since a recommendation can set a level without
    # giving a reason.
    notes_by_alg: dict[tuple[str, str], dict[str, list[str]]] = {}
    rated: dict[tuple[str, str], set[str]] = {}
    keysizes: dict[tuple[str, str], str] = {}
    actions: dict[tuple[str, str], str] = {}

    def slot(category: str, algorithm: str) -> dict[str, list[str]]:
        return notes_by_alg.setdefault((category, algorithm), {"fail": [], "warn": []})

    for category in _CATEGORIES:
        for algorithm, item in _algorithms(data.get(category)):
            notes = _as_dict(item.get("notes"))
            for level in ("fail", "warn"):
                texts = _note_list(notes, level)
                if texts:
                    slot(category, algorithm)[level].extend(texts)
                    rated.setdefault((category, algorithm), set()).add(level)
            keysize = _text(item.get("keysize"))
            if keysize:
                keysizes[(category, algorithm)] = keysize

    # v2 has no per-algorithm notes; v3 repeats the same judgement here. Either way a
    # `critical`/`warning` del/chg recommendation is ssh-audit rating that algorithm
    # fail/warn, so it contributes the level (and its note text when it has one).
    advertised = {
        (category, algorithm)
        for category in _CATEGORIES
        for algorithm, _ in _algorithms(data.get(category))
    }
    recommendations = _as_dict(data.get("recommendations"))
    for severity, level in _RECOMMENDATION_LEVELS:
        by_action = _as_dict(recommendations.get(severity))
        for action, label in _RECOMMENDATION_ACTIONS.items():
            by_category = _as_dict(by_action.get(action))
            for category in _CATEGORIES:
                for entry in _as_list(by_category.get(category)):
                    item = _as_dict(entry)
                    algorithm = _text(item.get("name"))
                    # Recommendations about algorithms the server does not advertise
                    # are advice, not a fact about this host.
                    if not algorithm or (category, algorithm) not in advertised:
                        continue
                    bucket = slot(category, algorithm)
                    rated.setdefault((category, algorithm), set()).add(level)
                    note = _text(item.get("notes"))
                    if note and note not in bucket[level]:
                        bucket[level].append(note)
                    # `del` outranks `chg` if both name the same algorithm.
                    if action == "del" or (category, algorithm) not in actions:
                        actions[(category, algorithm)] = label

    findings: list[dict[str, str]] = []
    for (category, algorithm), levels in sorted(notes_by_alg.items()):
        present = rated.get((category, algorithm), set())
        if not present:
            continue
        level = max(present, key=lambda lvl: _LEVEL_RANK[lvl])
        primary = levels[level]
        attrs: dict[str, str] = {
            "category": category,
            "algorithm": _sanitize(algorithm),
            "level": level,
        }
        if primary:
            attrs["notes"] = _sanitize("; ".join(primary))
        if level == "fail":
            secondary = levels["warn"]
            if secondary:
                attrs["warn_notes"] = _sanitize("; ".join(secondary))
        if (category, algorithm) in keysizes:
            attrs["keysize"] = _sanitize(keysizes[(category, algorithm)])
        if (category, algorithm) in actions:
            attrs["recommendation"] = actions[(category, algorithm)]
        cve_ids = sorted(
            {m.group(0) for texts in levels.values() for t in texts for m in _CVE_RE.finditer(t)}
        )
        if cve_ids:
            attrs["cve_ids"] = _sanitize(", ".join(cve_ids))
        findings.append(attrs)
    return findings


# --------------------------------------------------------------------------- #
# Observation construction
# --------------------------------------------------------------------------- #


def _observation_id(
    engagement_id: str,
    artifact_id: str,
    kind: ObservationKind,
    subject: str,
    attributes: dict[str, str],
    observed_at: datetime,
) -> str:
    canon_attrs = "\x1f".join(f"{k}\x1e{v}" for k, v in sorted(attributes.items()))
    payload = "\x00".join(
        [
            _ID_NAMESPACE,
            engagement_id,
            _SCANNER,
            artifact_id,
            kind.value,
            subject,
            canon_attrs,
            observed_at.isoformat(),
        ]
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"obs:sha256:{digest}"


def _build_observation(
    *,
    engagement_id: str,
    artifact_id: str,
    kind: ObservationKind,
    subject: str,
    attributes: dict[str, str],
    observed_at: datetime,
    retrieved_at: datetime,
    confidence: Confidence,
    note: str | None = None,
) -> Observation:
    return Observation(
        observation_id=_observation_id(
            engagement_id, artifact_id, kind, subject, attributes, observed_at
        ),
        engagement_id=engagement_id,
        scanner=_SCANNER,
        kind=kind,
        subject=subject,
        attributes=attributes,
        artifact_id=artifact_id,
        observed_at=observed_at,
        provenance=Provenance(
            source=Source.SCANNER,
            confidence=confidence,
            retrieved_at=retrieved_at,
            note=_sanitize(note) if note else None,
        ),
    )
