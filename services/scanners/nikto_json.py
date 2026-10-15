"""Pure Nikto JSON parser: turns one captured artifact into Observation objects.

Kept separate from `nikto_adapter.py` so the subprocess concern (invoking the tool) and
the parsing concern (interpreting its output) stay independently testable — this module
never touches a process or a network socket.

Design & Scoping:
  - Emits ObservationKind.VULN_CANDIDATE for every Nikto finding and, when Nikto reports a
    server banner, one ObservationKind.SERVICE_VERSION per listener. No severity, CVSS or
    risk scoring — that belongs to services.enrichment.
  - Reads the shape Nikto 2.5.0 actually emits with `-Format json -o -`: a JSON *array* of
    host objects `{host, ip, port, banner, vulnerabilities: [{id, method, url, msg,
    references?}]}`, with no timestamps anywhere. Older releases (2.1.x) emitted a single
    host object, an `OSVDB`/`osvdb` key per finding and, on some builds, trailing commas;
    all of those are accepted. Concatenated documents (one array per host) are accepted.
  - Nikto reports a target it could not reach as a *finding*: id "0", msg "Unable to connect
    to <ip>:<port>.". That is a scan failure, not a vulnerability candidate, so it is
    dropped here rather than handed to enrichment.
  - Every finding carries an `endpoint` attribute spelled exactly like nmap's port subject
    (`<ip>:<port>/tcp`, IPv6 bracketed), so a vuln_candidate joins to the port_open /
    service_version facts for the same listener. Nikto always reports the port, so no
    default is ever inferred from a scheme.
  - `cve_ids` is extracted from `msg` and `references` with a strict regex. That text comes
    from the scanned target as much as from Nikto's database, so it is a lead for
    enrichment to verify against a CVE source, never proof — hence the confidence choice
    below.
  - Pure function of (artifact, engagement_id): every timestamp derives from the artifact,
    every id is content-addressed sha256, and observations are returned in a deterministic
    sort order with exact duplicates collapsed.

Confidence (Nikto is a heuristic scanner; none of its findings is HIGH):
  - VULN_CANDIDATE is LOW when the message is inferred from a version string (Nikto's
    "appears to be outdated" check compares the Server banner to a hard-coded table, and the
    banner is trivially spoofed or backported). Otherwise MEDIUM: Nikto saw a concrete
    response (header, status, file, method) that matched one of its tests.
  - SERVICE_VERSION is MEDIUM when the banner parses to product/version (the server
    announced it itself, but it is an unverified claim) and LOW otherwise.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import UTC, datetime
from typing import Any

from packages.schema.models.observation import Observation, ObservationKind, RawArtifact
from packages.schema.models.provenance import Confidence, Provenance, Source

__all__ = ["NiktoParseError", "parse_nikto_json", "parse_run_timestamp"]


class NiktoParseError(Exception):
    """Raised when Nikto JSON output cannot be safely or meaningfully parsed."""


_ID_NAMESPACE = "seekthreat.obs.v1"
_SCANNER = "nikto"

_MAX_CONTENT_BYTES = 64 * 1024 * 1024
_MAX_ATTR_LEN = 512
_TRUNCATION_MARKER = "…[truncated]"
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")

# Strict: four-digit year, 4-19 digit sequence, word-bounded. Case-insensitive on input,
# normalised to upper case on output.
_CVE_RE = re.compile(r"(?<![A-Za-z0-9])CVE-[0-9]{4}-[0-9]{4,19}(?![0-9A-Za-z])", re.IGNORECASE)
_PORT_RE = re.compile(r"^[0-9]{1,5}$")
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._\-]*[A-Za-z0-9])?$")
_BANNER_RE = re.compile(r"^\s*([^/\s]+)/(\S+)")
# Messages Nikto derives from comparing a version string to a table, not from a response
# that exhibited the behaviour.
_VERSION_INFERENCE_RE = re.compile(
    r"outdated|end of life|\bEOL\b|appears to be|may be vulnerable|might be vulnerable",
    re.IGNORECASE,
)
# `id: "0"` pseudo-findings that report a scan failure rather than a weakness.
_FAILURE_MSG_RE = re.compile(r"^\s*(unable to connect|no web server found)", re.IGNORECASE)


# --------------------------------------------------------------------------- #
# Public entry points
# --------------------------------------------------------------------------- #


def parse_run_timestamp(raw: str) -> datetime:
    """Return the run timestamp for a captured Nikto output.

    Nikto's JSON report carries no timestamps (no start or end time, per finding or per
    host), so there is nothing to derive one from: this is the wall clock at capture, the
    same fallback the base adapter uses. The output is still validated, so a truncated or
    malformed run fails at capture time instead of being stored as an artifact.
    `parse_nikto_json` never calls this: it reads `artifact.captured_at` and stays pure.
    """
    _check_size(raw)
    _load_hosts(raw)
    return datetime.now(UTC)


def parse_nikto_json(artifact: RawArtifact, engagement_id: str) -> tuple[Observation, ...]:
    """Convert one captured Nikto artifact into Observation objects.

    Pure function of (artifact, engagement_id): re-running this on the same artifact
    always produces byte-identical output in fixed order.
    """
    _check_size(artifact.content)
    hosts = _load_hosts(artifact.content)
    captured_at = artifact.captured_at

    by_id: dict[str, Observation] = {}

    def add(obs: Observation) -> None:
        # Nikto sometimes reports the same finding twice; identical content is one fact.
        by_id.setdefault(obs.observation_id, obs)

    for host_rec in hosts:
        ip = _text(host_rec, "ip")
        host = _text(host_rec, "host")
        port = _text(host_rec, "port")
        endpoint = _endpoint(host=host, ip=ip, port=port)
        subject = endpoint or _sanitize(ip or host or "unknown")

        base_attrs: dict[str, str] = {}
        if endpoint:
            base_attrs["endpoint"] = _sanitize(endpoint)
        if host:
            base_attrs["host"] = _sanitize(host)
        if ip:
            base_attrs["ip"] = _sanitize(ip)
        if port:
            base_attrs["port"] = _sanitize(port)

        banner = _text(host_rec, "banner")
        if banner:
            attrs = dict(base_attrs)
            attrs["banner"] = _sanitize(banner)
            match = _BANNER_RE.match(banner)
            if match:
                attrs["product"] = _sanitize(match.group(1))
                attrs["version"] = _sanitize(match.group(2))
            else:
                attrs["product"] = _sanitize(banner.split()[0])
            add(
                _build_observation(
                    engagement_id=engagement_id,
                    artifact_id=artifact.artifact_id,
                    kind=ObservationKind.SERVICE_VERSION,
                    subject=subject,
                    attributes=attrs,
                    observed_at=captured_at,
                    retrieved_at=captured_at,
                    confidence=Confidence.MEDIUM if match else Confidence.LOW,
                    note="Nikto Server banner",
                )
            )

        vulns = host_rec.get("vulnerabilities")
        if not isinstance(vulns, list):
            continue
        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue
            v = {str(k).lower(): val for k, val in vuln.items()}
            nikto_id = _scalar(v.get("id"))
            msg = _scalar(v.get("msg"))
            if nikto_id == "0" and _FAILURE_MSG_RE.match(msg):
                continue
            if not nikto_id and not msg:
                continue

            references = _scalar(v.get("references"))
            attrs = dict(base_attrs)
            if nikto_id:
                attrs["nikto_id"] = _sanitize(nikto_id)
            method = _scalar(v.get("method"))
            if method:
                attrs["method"] = _sanitize(method.upper())
            url = _scalar(v.get("url"))
            if url:
                attrs["url"] = _sanitize(url)
            if msg:
                attrs["msg"] = _sanitize(msg)
            if references:
                attrs["references"] = _sanitize(references)
            osvdb = _scalar(v.get("osvdb"))
            if osvdb and osvdb != "0":
                attrs["osvdb"] = _sanitize(osvdb)
            cves = _extract_cves(msg, references)
            if cves:
                attrs["cve_ids"] = _format_id_list(cves)

            confidence = Confidence.LOW if _VERSION_INFERENCE_RE.search(msg) else Confidence.MEDIUM
            add(
                _build_observation(
                    engagement_id=engagement_id,
                    artifact_id=artifact.artifact_id,
                    kind=ObservationKind.VULN_CANDIDATE,
                    subject=subject,
                    attributes=attrs,
                    observed_at=captured_at,
                    retrieved_at=captured_at,
                    confidence=confidence,
                    note=f"Nikto test {nikto_id}" if nikto_id else "Nikto finding",
                )
            )

    return tuple(
        sorted(
            by_id.values(),
            key=lambda o: (
                o.subject,
                o.kind.value,
                o.attributes.get("nikto_id", ""),
                o.attributes.get("method", ""),
                o.attributes.get("url", ""),
                o.attributes.get("msg", ""),
                o.observation_id,
            ),
        )
    )


# --------------------------------------------------------------------------- #
# Parsing and validation helpers
# --------------------------------------------------------------------------- #


def _check_size(content: str) -> None:
    if len(content.encode("utf-8")) > _MAX_CONTENT_BYTES:
        raise NiktoParseError("Nikto output exceeds maximum allowed size (64MB)")


def _load_hosts(raw: str) -> list[dict[str, Any]]:
    """Parse Nikto's JSON into a flat list of host-record dictionaries."""
    text = raw.lstrip("﻿").strip()
    if not text:
        return []

    try:
        documents = _decode_documents(text)
    except json.JSONDecodeError:
        # Some Nikto builds leave a trailing comma before a closing bracket. Retry once
        # with those removed; if it still does not parse, the output is genuinely broken.
        try:
            documents = _decode_documents(_strip_trailing_commas(text))
        except json.JSONDecodeError as exc:
            raise NiktoParseError(f"Malformed Nikto JSON: {exc}") from exc

    hosts: list[dict[str, Any]] = []
    for doc in documents:
        if isinstance(doc, list):
            hosts.extend(item for item in doc if isinstance(item, dict))
        elif isinstance(doc, dict):
            hosts.append(doc)
        else:
            raise NiktoParseError(
                f"Nikto JSON top level must be an array or object, got {type(doc).__name__}"
            )
    return hosts


def _decode_documents(text: str) -> list[Any]:
    """Decode one or more concatenated JSON documents (Nikto writes one per host)."""
    decoder = json.JSONDecoder()
    documents: list[Any] = []
    idx, end = 0, len(text)
    while idx < end:
        while idx < end and text[idx] in " \t\r\n,":
            idx += 1
        if idx >= end:
            break
        doc, idx = decoder.raw_decode(text, idx)
        documents.append(doc)
    return documents


def _strip_trailing_commas(text: str) -> str:
    """Drop a comma that is followed only by whitespace and a closing bracket/brace.

    String-aware, so a ",]" inside a finding's message is left alone.
    """
    out: list[str] = []
    in_string = False
    escaped = False
    n = len(text)
    for i, ch in enumerate(text):
        if in_string:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j < n and text[j] in "]}":
                continue
        out.append(ch)
    return "".join(out)


def _scalar(value: Any) -> str:
    """Render a JSON scalar as a stripped string; containers and null become empty."""
    if value is None or isinstance(value, (dict, list)):
        return ""
    return str(value).strip()


def _text(record: dict[str, Any], key: str) -> str:
    return _scalar(record.get(key))


def _extract_cves(*texts: str) -> list[str]:
    found: set[str] = set()
    for text in texts:
        found.update(m.group(0).upper() for m in _CVE_RE.finditer(text))
    return sorted(found)


def _format_id_list(values: list[str]) -> str:
    """Comma-joined, sorted, deduplicated — the same ", " format nuclei_json uses."""
    return _sanitize(", ".join(sorted({v.strip() for v in values if v.strip()})))


def _endpoint(*, host: str, ip: str, port: str) -> str:
    """Build the nmap-compatible `<ip>:<port>/tcp` join key, or "" if it cannot be.

    The IP is preferred over the hostname because nmap keys its port facts by address.
    Emitted only when Nikto actually reported a valid port; nothing is defaulted.
    """
    if not _PORT_RE.match(port) or not 0 < int(port) < 65536:
        return ""
    for candidate in (ip, host):
        addr = candidate.strip().strip("[]")
        if not addr:
            continue
        try:
            parsed = ipaddress.ip_address(addr)
        except ValueError:
            if _HOSTNAME_RE.match(addr):
                return f"{addr}:{int(port)}/tcp"
            continue
        if parsed.version == 6:
            return f"[{parsed.compressed}]:{int(port)}/tcp"
        return f"{parsed}:{int(port)}/tcp"
    return ""


def _sanitize(value: str) -> str:
    """Strip control characters and truncate to max length."""
    cleaned = _CONTROL_CHARS_RE.sub("", value)
    if len(cleaned) > _MAX_ATTR_LEN:
        return cleaned[: _MAX_ATTR_LEN - len(_TRUNCATION_MARKER)] + _TRUNCATION_MARKER
    return cleaned


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
            note=note,
        ),
    )
