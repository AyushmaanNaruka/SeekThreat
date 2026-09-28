"""Pure Nuclei JSON / NDJSON parser: turns one captured artifact into Observation objects.

Kept separate from `nuclei_adapter.py` so the subprocess concern (invoking the tool) and
the parsing concern (interpreting its output) stay independently testable — this module
never touches a process or a live network socket.

Design & Scoping:
  - Emits ObservationKind.VULN_CANDIDATE observations for all template matches.
  - Preserves Nuclei's raw severity and classification metadata in attributes without
    computing downstream risk scores (risk scoring belongs to services.enrichment).
  - Pure function of (artifact, engagement_id): every timestamp derives from the artifact
    or JSON record, every ID is content-addressed sha256, and observations are returned
    in a deterministic sort order.
  - Safely handles both JSON Lines (one JSON object per line) and top-level JSON arrays.
  - Reads the field set nuclei v3 actually emits. For HTTP templates that is a bare
    `host` plus separate `port`/`scheme`/`url` keys, NOT a URL in `host`; network
    templates put `host:port` in `host`. Both shapes are normalised into an
    `endpoint` attribute spelled exactly like nmap's port subject
    (`<host>:<port>/tcp`, IPv6 bracketed) so a vuln_candidate can be joined to the
    port_open / service_version facts for the same listener. Without that key the
    graph layer has nothing to attach a nuclei finding to.
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

__all__ = ["NucleiParseError", "parse_nuclei_json", "parse_run_timestamp"]


class NucleiParseError(Exception):
    """Raised when Nuclei JSON output cannot be safely or meaningfully parsed."""


_ID_NAMESPACE = "seekthreat.obs.v1"
_SCANNER = "nuclei"

_MAX_CONTENT_BYTES = 64 * 1024 * 1024
_MAX_ATTR_LEN = 512
_TRUNCATION_MARKER = "…[truncated]"
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")


# --------------------------------------------------------------------------- #
# Public entry points
# --------------------------------------------------------------------------- #


def parse_run_timestamp(raw: str) -> datetime:
    """Derive the run timestamp from the Nuclei JSON/NDJSON output.

    Scans the raw output for the latest timestamp recorded across all findings.
    If no timestamp is present or the output is empty, returns datetime.now(UTC).
    """
    _check_size(raw)
    records = _load_records(raw)
    timestamps: list[datetime] = []
    for rec in records:
        ts_str = rec.get("timestamp")
        if isinstance(ts_str, str) and ts_str.strip():
            parsed = _parse_iso_timestamp(ts_str.strip())
            if parsed is not None:
                timestamps.append(parsed)

    if timestamps:
        return max(timestamps)
    return datetime.now(UTC)


def parse_nuclei_json(artifact: RawArtifact, engagement_id: str) -> tuple[Observation, ...]:
    """Convert one captured Nuclei artifact into Observation objects.

    Pure function of (artifact, engagement_id): re-running this on the same
    artifact always produces byte-identical output in fixed order.
    """
    _check_size(artifact.content)
    records = _load_records(artifact.content)
    retrieved_at = artifact.captured_at

    observations: list[Observation] = []

    for record in records:
        template_id = record.get("template-id") or record.get("templateID") or "unknown"
        info = record.get("info") or {}
        if not isinstance(info, dict):
            info = {}

        # A record whose matcher did not fire is not a finding. nuclei only emits
        # these when asked to report match failures, but an absent key must stay
        # truthy-by-default: real findings carry "matcher-status": true.
        if record.get("matcher-status") is False:
            continue

        # Subject determination: matched-at > url > host > ip > unknown
        matched_at = record.get("matched-at") or record.get("matched") or ""
        url = record.get("url") or ""
        host = record.get("host") or ""
        ip = record.get("ip") or ""
        port = record.get("port") or ""
        scheme = record.get("scheme") or ""

        subject_candidate = matched_at or url or host or ip or "unknown"
        subject = _sanitize(str(subject_candidate))

        # Timestamp for this observation
        observed_at = retrieved_at
        ts_str = record.get("timestamp")
        if isinstance(ts_str, str) and ts_str.strip():
            parsed_ts = _parse_iso_timestamp(ts_str.strip())
            if parsed_ts is not None:
                observed_at = parsed_ts

        # Extract attributes
        attrs: dict[str, str] = {}
        attrs["template_id"] = _sanitize(str(template_id))

        name = info.get("name")
        if name:
            attrs["template_name"] = _sanitize(str(name))

        severity_raw = info.get("severity")
        if severity_raw:
            attrs["scanner_severity"] = _sanitize(str(severity_raw).lower())

        type_ = record.get("type")
        if type_:
            attrs["type"] = _sanitize(str(type_))

        if host:
            attrs["host"] = _sanitize(str(host))
        if matched_at:
            attrs["matched_at"] = _sanitize(str(matched_at))
        if ip:
            attrs["ip"] = _sanitize(str(ip))
        if url:
            attrs["url"] = _sanitize(str(url))
        if scheme:
            attrs["scheme"] = _sanitize(str(scheme).lower())
        if port:
            attrs["port"] = _sanitize(str(port))

        # Join key back to nmap's port facts. See module docstring.
        endpoint = _endpoint(
            host=str(host),
            ip=str(ip),
            port=str(port),
            url=str(url),
            record_type=str(record.get("type") or ""),
        )
        if endpoint:
            attrs["endpoint"] = _sanitize(endpoint)

        template_path = record.get("template-path") or record.get("template_path")
        if template_path:
            attrs["template_path"] = _sanitize(str(template_path))

        # Template tags decide whether a finding was even reachable under the
        # adapter's -etags policy, so they have to survive into the fact store.
        tags = info.get("tags")
        if tags:
            attrs["tags"] = _format_id_list(tags)

        desc = info.get("description")
        if desc:
            attrs["description"] = _sanitize(str(desc))

        matcher_name = record.get("matcher-name") or record.get("matcher_name")
        if matcher_name:
            attrs["matcher_name"] = _sanitize(str(matcher_name))

        extracted = record.get("extracted-results") or record.get("extracted_results")
        if extracted:
            if isinstance(extracted, list):
                attrs["extracted_results"] = _sanitize(", ".join(str(e) for e in extracted))
            else:
                attrs["extracted_results"] = _sanitize(str(extracted))

        extractor_name = record.get("extractor-name") or record.get("extractor_name")
        if extractor_name:
            attrs["extractor_name"] = _sanitize(str(extractor_name))

        curl_cmd = record.get("curl-command")
        if curl_cmd:
            attrs["curl_command"] = _sanitize(str(curl_cmd))

        # Classification fields (CVE, CWE, CVSS, EPSS)
        classification = info.get("classification")
        if isinstance(classification, dict):
            cve_val = classification.get("cve-id") or classification.get("cve_id")
            if cve_val:
                attrs["cve_ids"] = _format_id_list(cve_val)

            cwe_val = classification.get("cwe-id") or classification.get("cwe_id")
            if cwe_val:
                attrs["cwe_ids"] = _format_id_list(cwe_val)

            cvss_metrics = classification.get("cvss-metrics")
            if cvss_metrics:
                attrs["cvss_metrics"] = _sanitize(str(cvss_metrics))

            cvss_score = classification.get("cvss-score")
            if cvss_score is not None:
                attrs["cvss_score"] = _sanitize(str(cvss_score))

            epss_score = classification.get("epss-score")
            if epss_score is not None:
                attrs["epss_score"] = _sanitize(str(epss_score))

        # Confidence based on scanner severity / finding certainty
        confidence = _calculate_confidence(severity_raw)

        observations.append(
            _build_observation(
                engagement_id=engagement_id,
                artifact_id=artifact.artifact_id,
                kind=ObservationKind.VULN_CANDIDATE,
                subject=subject,
                attributes=attrs,
                observed_at=observed_at,
                retrieved_at=retrieved_at,
                confidence=confidence,
                note=f"Nuclei template {template_id}",
            )
        )

    # Sort deterministically for pure idempotent results
    observations.sort(
        key=lambda o: (o.subject, o.attributes.get("template_id", ""), o.observation_id)
    )
    return tuple(observations)


# --------------------------------------------------------------------------- #
# Parsing and validation helpers
# --------------------------------------------------------------------------- #


def _check_size(content: str) -> None:
    if len(content.encode("utf-8")) > _MAX_CONTENT_BYTES:
        raise NucleiParseError("Nuclei output exceeds maximum allowed size (64MB)")


def _load_records(raw: str) -> list[dict[str, Any]]:
    """Parse raw JSON Lines or JSON array into a list of record dictionaries."""
    stripped = raw.strip()
    if not stripped:
        return []

    # If formatted as a single JSON array: [ {...}, {...} ]
    if stripped.startswith("["):
        try:
            data = json.loads(stripped)
            if isinstance(data, list):
                return [item for item in data if isinstance(item, dict)]
            raise NucleiParseError("Top-level JSON is not a list")
        except json.JSONDecodeError as exc:
            raise NucleiParseError(f"Malformed Nuclei JSON array: {exc}") from exc

    # Otherwise parse as JSON Lines (one JSON object per non-empty line)
    records: list[dict[str, Any]] = []
    for line_idx, line in enumerate(raw.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise NucleiParseError(f"Malformed Nuclei JSONL at line {line_idx}: {exc}") from exc

        if isinstance(item, dict):
            records.append(item)

    return records


def _parse_iso_timestamp(ts: str) -> datetime | None:
    """Parse an ISO 8601 timestamp string into UTC-aware datetime."""
    # Standardize 'Z' suffix to '+00:00' for datetime.fromisoformat
    normalized = ts.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC)
    except (ValueError, TypeError):
        return None


def _format_id_list(value: Any) -> str:
    """Format single ID or list of IDs into comma-separated sanitized string."""
    if isinstance(value, list):
        return _sanitize(", ".join(str(v).strip() for v in value if v))
    return _sanitize(str(value).strip())


def _calculate_confidence(severity: Any) -> Confidence:
    """Map reported severity to confidence level for the raw candidate fact.

    Severity is the only signal nuclei gives about how sure it is. `matcher-name`
    used to be accepted here and never read: a named matcher is a label, not extra
    evidence, so it said nothing about certainty. Dropped rather than given
    invented meaning.
    """
    if not severity:
        return Confidence.LOW
    sev = str(severity).lower().strip()
    if sev in {"critical", "high"}:
        return Confidence.HIGH
    if sev in {"medium", "low"}:
        return Confidence.MEDIUM
    return Confidence.LOW


# nuclei types that describe a TCP listener. `dns` is UDP; `file`, `code`,
# `javascript` and `whois` have no endpoint on the scanned host at all.
_TCP_TYPES = frozenset({"http", "network", "ssl", "websocket", "headless", "tcp"})
_PORT_RE = re.compile(r"^[0-9]{1,5}$")
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._\-]*[A-Za-z0-9])?$")
_URL_PORT_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://(?:[^/@]*@)?(?:\[[^\]]+\]|[^:/?#]+):([0-9]{1,5})")


def _endpoint(*, host: str, ip: str, port: str, url: str, record_type: str) -> str:
    """Build the nmap-compatible `<host>:<port>/<proto>` join key, or "" if unknown.

    nmap's `_port_subject` is what every port_open / service_version observation is
    keyed by, so a vuln_candidate has to spell its listener the same way or nothing
    downstream can connect the two.

    Emitted only when a port is actually present in the output. A default derived
    from the scheme (80 for http, 443 for https) would be an inference, and every
    attribute here has to trace to something the scanner reported.
    """
    proto = "udp" if record_type == "dns" else "tcp"
    if record_type and record_type not in _TCP_TYPES and record_type != "dns":
        return ""

    host_part = host.strip()
    port_part = port.strip()

    # Network templates report `host` as "host:port"; HTTP templates report a bare
    # host with the port in its own field.
    if not port_part and host_part and ":" in host_part:
        head, _, tail = host_part.rpartition(":")
        if head and _PORT_RE.match(tail) and not _is_ipv6(host_part):
            host_part, port_part = head, tail

    if not port_part and url:
        match = _URL_PORT_RE.match(url.strip().lower())
        if match:
            port_part = match.group(1)

    if not host_part:
        host_part = ip.strip()
    if not host_part or not _PORT_RE.match(port_part):
        return ""
    if not 0 < int(port_part) < 65536:
        return ""

    host_part = host_part.strip("[]")
    if _is_ipv6(host_part):
        return f"[{ipaddress.ip_address(host_part).compressed}]:{int(port_part)}/{proto}"
    # Anything that is not a bare hostname or IPv4 literal (a URL left in `host` by a
    # hand-written fixture, say) would produce a join key nothing can match. Emit
    # nothing rather than something that looks like a key and is not one.
    if not _HOSTNAME_RE.match(host_part):
        return ""
    return f"{host_part}:{int(port_part)}/{proto}"


def _is_ipv6(value: str) -> bool:
    try:
        return ipaddress.ip_address(value.strip("[]")).version == 6
    except ValueError:
        return False


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
