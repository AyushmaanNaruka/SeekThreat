"""Pure nmap XML parsing: turns one captured artifact into Observation objects.

Kept separate from `nmap_adapter.py` so the subprocess concern (invoking the tool) and
the parsing concern (interpreting its output) stay independently testable — this module
never touches a process or a clock.

Scope, deliberately narrow for this slice:
  - Emits HOST_UP, PORT_OPEN and SERVICE_VERSION only. Non-open ports are real facts too
    (nmap already tells us "22 is filtered"), but nothing consumes them until the graph
    engine's reachability rules exist, and the RawArtifact this parses is retained
    verbatim, so nothing is lost by deferring — re-parsing recovers them later without
    rescanning.
  - A service identified by method="table" (nmap's guess from the port number, not a
    fingerprint match) never produces SERVICE_VERSION. It is zero new evidence over the
    port number itself; treating it as evidence would let enrichment match CVEs against
    a guess.
  - No OS detection, no NSE script output. VULN_CANDIDATE observations belong to our own
    enrichment matching CPEs to CVEs, not to laundering a script's opinion.
  - No severity, no CVSS, no risk scoring. That is services.enrichment's job.

Every public entry point here must be a pure function of its arguments: no wall-clock
reads, no random ids, no iteration order that depends on dict/set internals. The same
XML string must always produce byte-identical Observation objects.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import UTC, datetime

from packages.schema.models.observation import Observation, ObservationKind, RawArtifact
from packages.schema.models.provenance import Confidence, Provenance, Source

__all__ = ["NmapParseError", "parse_nmap_xml", "parse_run_timestamp"]


class NmapParseError(Exception):
    """Raised when nmap XML cannot be safely or meaningfully parsed."""


_ID_NAMESPACE = "seekthreat.obs.v1"
_SCANNER = "nmap"

_MAX_CONTENT_BYTES = 64 * 1024 * 1024
_MAX_ATTR_LEN = 512
_TRUNCATION_MARKER = "…[truncated]"

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
_DOCTYPE_RE = re.compile(r"<!DOCTYPE\b", re.IGNORECASE)
_EXTERNAL_ID_RE = re.compile(r"\bSYSTEM\b|\bPUBLIC\b", re.IGNORECASE)

_HIGH_HOST_REASONS = {"syn-ack", "echo-reply", "reset", "arp-response", "localhost-response"}
_HIGH_PORT_REASONS = {"syn-ack", "udp-response"}
_ADDR_TYPE_ORDER = {"ipv4": 0, "ipv6": 1, "mac": 2}


# --------------------------------------------------------------------------- #
# Public entry points
# --------------------------------------------------------------------------- #


def parse_run_timestamp(raw: str) -> datetime:
    """When this nmap run produced its output, derived from the XML alone.

    Used by the adapter to stamp RawArtifact.captured_at before _parse ever runs, so
    that value — not the wall clock — becomes the single source every observation's
    timestamp derives from.
    """
    root = _parse_root(raw)
    return _run_timestamp(root)


def parse_nmap_xml(artifact: RawArtifact, engagement_id: str) -> tuple[Observation, ...]:
    """Convert one captured nmap XML artifact into Observation objects.

    Pure function of (artifact, engagement_id): every timestamp comes from
    artifact.captured_at or the XML itself, every id is content-derived, and hosts and
    ports are emitted in a fixed sort order. Re-running this on the same artifact always
    produces byte-identical output.
    """
    root = _parse_root(artifact.content)
    retrieved_at = artifact.captured_at

    observations: list[Observation] = []
    resolved_hosts = sorted(
        (
            (host, _resolve_host_address(host))
            for host in root.findall("host")
            if _host_state(host) == "up"
        ),
        key=lambda pair: pair[1].sort_key,
    )
    for host, addr in resolved_hosts:
        observed_at = _host_observed_at(host, fallback=retrieved_at)

        host_attrs = dict(addr.attrs)
        _fill_status_attrs(host_attrs, host)
        _fill_hostname_attrs(host_attrs, host)
        _fill_extraports_attrs(host_attrs, host)
        _fill_distance_attrs(host_attrs, host)

        confidence, note = _host_confidence_and_note(host)
        observations.append(
            _build_observation(
                engagement_id=engagement_id,
                artifact_id=artifact.artifact_id,
                kind=ObservationKind.HOST_UP,
                subject=addr.subject,
                attributes=host_attrs,
                observed_at=observed_at,
                retrieved_at=retrieved_at,
                confidence=confidence,
                note=note,
            )
        )

        ports_elem = host.find("ports")
        if ports_elem is None:
            continue

        open_ports = sorted(
            (p for p in ports_elem.findall("port") if _port_state(p) == "open"),
            key=_port_sort_key,
        )
        for port in open_ports:
            port_subject = _port_subject(addr, port)

            port_attrs: dict[str, str] = {}
            _fill_port_open_attrs(port_attrs, port)
            observations.append(
                _build_observation(
                    engagement_id=engagement_id,
                    artifact_id=artifact.artifact_id,
                    kind=ObservationKind.PORT_OPEN,
                    subject=port_subject,
                    attributes=port_attrs,
                    observed_at=observed_at,
                    retrieved_at=retrieved_at,
                    confidence=_port_confidence(port),
                )
            )

            service = port.find("service")
            if service is not None and service.get("method") == "probed":
                service_attrs: dict[str, str] = {}
                _fill_service_version_attrs(service_attrs, service)
                observations.append(
                    _build_observation(
                        engagement_id=engagement_id,
                        artifact_id=artifact.artifact_id,
                        kind=ObservationKind.SERVICE_VERSION,
                        subject=port_subject,
                        attributes=service_attrs,
                        observed_at=observed_at,
                        retrieved_at=retrieved_at,
                        confidence=_service_version_confidence(service),
                    )
                )

    return tuple(observations)


# --------------------------------------------------------------------------- #
# XML entry, guarded
# --------------------------------------------------------------------------- #


def _parse_root(content: str) -> ET.Element:
    _check_size(content)
    _guard_doctype(content)
    try:
        return ET.fromstring(content)
    except ET.ParseError as exc:
        raise NmapParseError(f"malformed nmap XML: {exc}") from exc


def _check_size(content: str) -> None:
    if len(content.encode("utf-8")) > _MAX_CONTENT_BYTES:
        raise NmapParseError("nmap XML exceeds the maximum allowed size")


def _guard_doctype(content: str) -> None:
    """Allow nmap's own `<!DOCTYPE nmaprun>`; reject anything that could define entities.

    nmap always emits a bare DOCTYPE with no internal subset and no external identifier,
    so this rejects only what nmap itself would never produce: a DOCTYPE with an internal
    subset (billion-laughs) or a SYSTEM/PUBLIC external identifier.
    """
    match = _DOCTYPE_RE.search(content)
    if match is None:
        return
    tail = content[match.end() :]
    bracket_idx = tail.find("[")
    gt_idx = tail.find(">")
    if bracket_idx != -1 and (gt_idx == -1 or bracket_idx < gt_idx):
        raise NmapParseError("DOCTYPE with an internal subset is not allowed")
    declaration = tail[:gt_idx] if gt_idx != -1 else tail
    if _EXTERNAL_ID_RE.search(declaration):
        raise NmapParseError("DOCTYPE with an external SYSTEM/PUBLIC identifier is not allowed")


# --------------------------------------------------------------------------- #
# Timestamps
# --------------------------------------------------------------------------- #


def _epoch(value: str | None) -> datetime | None:
    if not value or value == "0":
        return None
    try:
        return datetime.fromtimestamp(int(value), tz=UTC)
    except (ValueError, OverflowError, OSError) as exc:
        raise NmapParseError(f"invalid epoch timestamp {value!r}") from exc


def _run_timestamp(root: ET.Element) -> datetime:
    runstats = root.find("runstats")
    if runstats is not None:
        finished = runstats.find("finished")
        if finished is not None:
            finished_at = _epoch(finished.get("time"))
            if finished_at is not None:
                return finished_at

    start = _epoch(root.get("start"))
    if start is not None:
        return start

    end_times = [t for h in root.findall("host") if (t := _epoch(h.get("endtime"))) is not None]
    if end_times:
        return max(end_times)

    raise NmapParseError(
        "no timestamp found: runstats/finished@time, nmaprun@start and every host@endtime "
        "are all absent"
    )


def _host_observed_at(host: ET.Element, fallback: datetime) -> datetime:
    end = _epoch(host.get("endtime"))
    if end is not None:
        return end
    start = _epoch(host.get("starttime"))
    if start is not None:
        return start
    return fallback


# --------------------------------------------------------------------------- #
# Sanitization and attribute helpers
# --------------------------------------------------------------------------- #


def _sanitize(value: str) -> str:
    cleaned = _CONTROL_CHARS_RE.sub("", value)
    if len(cleaned) > _MAX_ATTR_LEN:
        cleaned = cleaned[:_MAX_ATTR_LEN] + _TRUNCATION_MARKER
    return cleaned


def _add(attrs: dict[str, str], key: str, value: str | None) -> None:
    """Set attrs[key] = sanitize(value), unless value is missing or empty."""
    if value:
        attrs[key] = _sanitize(value)


# --------------------------------------------------------------------------- #
# Host address resolution
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class _HostAddress:
    subject: str
    addr_type: str
    sort_key: tuple[int, bytes]
    attrs: dict[str, str]


def _parse_mac(raw_mac: str) -> bytes:
    try:
        parts = raw_mac.split(":")
        if len(parts) != 6:
            raise ValueError(f"expected 6 colon-separated octets, got {len(parts)}")
        return bytes(int(part, 16) for part in parts)
    except ValueError as exc:
        raise NmapParseError(f"invalid mac address {raw_mac!r}") from exc


def _resolve_host_address(host: ET.Element) -> _HostAddress:
    by_type: dict[str, ET.Element] = {}
    for addr in host.findall("address"):
        addr_type = addr.get("addrtype", "")
        by_type.setdefault(addr_type, addr)

    attrs: dict[str, str] = {}
    ipv4: ipaddress.IPv4Address | None = None
    ipv6: ipaddress.IPv6Address | None = None
    mac_bytes: bytes | None = None

    if "ipv4" in by_type:
        raw_ipv4 = by_type["ipv4"].get("addr", "")
        try:
            ipv4 = ipaddress.IPv4Address(raw_ipv4)
        except ValueError as exc:
            raise NmapParseError(f"invalid ipv4 address {raw_ipv4!r}") from exc
        _add(attrs, "ipv4", str(ipv4))
    if "ipv6" in by_type:
        raw_ipv6 = by_type["ipv6"].get("addr", "")
        try:
            ipv6 = ipaddress.IPv6Address(raw_ipv6)
        except ValueError as exc:
            raise NmapParseError(f"invalid ipv6 address {raw_ipv6!r}") from exc
        _add(attrs, "ipv6", ipv6.compressed)
    if "mac" in by_type:
        raw_mac = by_type["mac"].get("addr", "").lower()
        mac_bytes = _parse_mac(raw_mac)
        _add(attrs, "mac", raw_mac)
        _add(attrs, "mac_vendor", by_type["mac"].get("vendor"))

    if ipv4 is not None:
        subject, addr_type, packed = str(ipv4), "ipv4", ipv4.packed
    elif ipv6 is not None:
        subject, addr_type, packed = ipv6.compressed, "ipv6", ipv6.packed
    elif mac_bytes is not None:
        subject, addr_type, packed = f"mac:{attrs['mac']}", "mac", mac_bytes
    else:
        raise NmapParseError("host has no usable address: no ipv4, ipv6, or mac")

    attrs["address_type"] = addr_type
    sort_key = (_ADDR_TYPE_ORDER[addr_type], packed)
    return _HostAddress(subject=subject, addr_type=addr_type, sort_key=sort_key, attrs=attrs)


def _port_subject(addr: _HostAddress, port: ET.Element) -> str:
    host_part = f"[{addr.subject}]" if addr.addr_type == "ipv6" else addr.subject
    return f"{host_part}:{port.get('portid', '')}/{port.get('protocol', '')}"


# --------------------------------------------------------------------------- #
# Host-level attributes and confidence
# --------------------------------------------------------------------------- #


def _host_state(host: ET.Element) -> str | None:
    status = host.find("status")
    return status.get("state") if status is not None else None


def _fill_status_attrs(attrs: dict[str, str], host: ET.Element) -> None:
    status = host.find("status")
    if status is None:
        return
    _add(attrs, "status_reason", status.get("reason"))
    _add(attrs, "status_reason_ttl", status.get("reason_ttl"))


def _fill_hostname_attrs(attrs: dict[str, str], host: ET.Element) -> None:
    hostnames_elem = host.find("hostnames")
    if hostnames_elem is None:
        return
    entries = [
        (hn.get("name", ""), hn.get("type", ""))
        for hn in hostnames_elem.findall("hostname")
        if hn.get("name")
    ]
    if not entries:
        return
    user_entries = [name for name, kind in entries if kind == "user"]
    ptr_entries = [name for name, kind in entries if kind == "PTR"]
    if user_entries:
        primary = user_entries[0]
    elif ptr_entries:
        primary = ptr_entries[0]
    else:
        primary = entries[0][0]
    joined = ",".join(sorted(f"{name}|{kind}" for name, kind in entries))
    _add(attrs, "hostname", primary)
    _add(attrs, "hostnames", joined)


def _fill_extraports_attrs(attrs: dict[str, str], host: ET.Element) -> None:
    ports_elem = host.find("ports")
    if ports_elem is None:
        return
    for extraports in ports_elem.findall("extraports"):
        state, count = extraports.get("state"), extraports.get("count")
        if not state or not count:
            continue
        key = f"extraports_{state}"
        attrs[key] = str(int(attrs.get(key, "0")) + int(count))


def _fill_distance_attrs(attrs: dict[str, str], host: ET.Element) -> None:
    distance = host.find("distance")
    if distance is not None:
        _add(attrs, "distance_hops", distance.get("value"))


def _host_confidence_and_note(host: ET.Element) -> tuple[Confidence, str | None]:
    status = host.find("status")
    reason = status.get("reason") if status is not None else None
    if reason == "user-set":
        return Confidence.LOW, "host assumed up (-Pn); never probed"
    if reason in _HIGH_HOST_REASONS:
        return Confidence.HIGH, None
    return Confidence.MEDIUM, None


# --------------------------------------------------------------------------- #
# Port-level attributes and confidence
# --------------------------------------------------------------------------- #


def _port_state(port: ET.Element) -> str | None:
    state = port.find("state")
    return state.get("state") if state is not None else None


def _port_sort_key(port: ET.Element) -> tuple[str, int]:
    protocol = port.get("protocol", "")
    portid = int(port.get("portid") or 0)
    return (protocol, portid)


def _fill_port_open_attrs(attrs: dict[str, str], port: ET.Element) -> None:
    _add(attrs, "protocol", port.get("protocol"))
    _add(attrs, "port", port.get("portid"))
    state = port.find("state")
    if state is not None:
        _add(attrs, "state_reason", state.get("reason"))
        _add(attrs, "state_reason_ttl", state.get("reason_ttl"))
    service = port.find("service")
    if service is not None:
        _add(attrs, "service_name_guess", service.get("name"))
        _add(attrs, "service_method", service.get("method"))


def _port_confidence(port: ET.Element) -> Confidence:
    state = port.find("state")
    reason = state.get("reason") if state is not None else None
    return Confidence.HIGH if reason in _HIGH_PORT_REASONS else Confidence.MEDIUM


# --------------------------------------------------------------------------- #
# Service-version attributes and confidence
# --------------------------------------------------------------------------- #

_SERVICE_ATTR_MAP: tuple[tuple[str, str], ...] = (
    ("service_name", "name"),
    ("product", "product"),
    ("version", "version"),
    ("extrainfo", "extrainfo"),
    ("service_hostname", "hostname"),
    ("ostype", "ostype"),
    ("devicetype", "devicetype"),
    ("tunnel", "tunnel"),
    ("method", "method"),
    ("conf", "conf"),
)


def _fill_service_version_attrs(attrs: dict[str, str], service: ET.Element) -> None:
    for attr_key, xml_key in _SERVICE_ATTR_MAP:
        _add(attrs, attr_key, service.get(xml_key))

    cpes = sorted({cpe.text for cpe in service.findall("cpe") if cpe.text})
    if cpes:
        attrs["cpe"] = _sanitize(",".join(cpes))


def _service_version_confidence(service: ET.Element) -> Confidence:
    conf_raw = service.get("conf")
    try:
        conf = int(conf_raw) if conf_raw else None
    except ValueError:
        conf = None
    if conf is None:
        return Confidence.LOW
    if conf >= 9:
        return Confidence.HIGH if service.get("product") else Confidence.MEDIUM
    if conf >= 7:
        return Confidence.MEDIUM
    return Confidence.LOW


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
