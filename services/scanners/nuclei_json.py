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
"""

from __future__ import annotations

import hashlib
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

        # Subject determination: matched-at > host > ip > unknown
        matched_at = record.get("matched-at") or record.get("matched") or ""
        host = record.get("host") or ""
        ip = record.get("ip") or ""

        subject_candidate = matched_at or host or ip or "unknown"
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
        confidence = _calculate_confidence(severity_raw, matcher_name)

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


def _calculate_confidence(severity: Any, matcher_name: Any) -> Confidence:
    """Map reported severity to confidence level for the raw candidate fact."""
    if not severity:
        return Confidence.LOW
    sev = str(severity).lower().strip()
    if sev in {"critical", "high"}:
        return Confidence.HIGH
    if sev in {"medium", "low"}:
        return Confidence.MEDIUM
    return Confidence.LOW


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
