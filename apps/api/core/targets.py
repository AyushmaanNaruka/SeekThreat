"""Turn free-form operator input into the scans that input asks for.

An operator types targets the way they would into any enterprise scanner: IPs,
CIDR blocks, IPv4 ranges, hostnames, ``host:port`` and http(s) URLs, separated
by commas, semicolons, whitespace or newlines. This module parses each entry
into a bare host (or a canonical CIDR block) plus the port and scheme it named,
and expands it into one planned scan per target the chosen scanner can take.

It decides nothing about authorization. Every planned target is still checked
by the allowlist gate (`apps/api/core/authorization.py`) as the exact string
the adapter will receive. URLs are split here, never in the gate, and the
scanner is never handed the original URL: adapters rebuild it from the bare
host and the validated ``port``/``scheme`` options (DECISIONS.md D-025, D-045),
so whatever host this parser extracts is the host that is both checked and
scanned.

No DNS resolution happens anywhere: a hostname is planned as a hostname.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import urlsplit

from packages.schema.models.engagement import is_valid_hostname

# One request never creates more scans than this. Larger inputs are refused
# outright rather than silently truncated, so coverage is never overstated.
MAX_SCANS_PER_BATCH = 256

# nmap scans a network block as one job, with host discovery. Bigger IPv4
# blocks are split into blocks of this size so a single job stays inside the
# scan timeout. nmap takes no CIDR for IPv6, so IPv6 blocks expand to hosts.
NMAP_MAX_IPV4_PREFIX = 22

# Refuse to enumerate anything bigger than this before even counting scans.
_MAX_EXPANDED_ADDRESSES = 1 << 16

_SPLIT_RE = re.compile(r"[\s,;]+")
_CIDR_RE = re.compile(r"[0-9a-fA-F:.]+/(?:0|[1-9][0-9]{0,2})", re.ASCII)
_PORT_RE = re.compile(r"[0-9]{1,5}", re.ASCII)
_IPV4_RANGE_RE = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3}|\d{1,3})", re.ASCII
)

Scanner = Literal["nmap", "nuclei", "nikto", "ssh-audit"]
SUPPORTED_SCANNERS: tuple[str, ...] = ("nmap", "nuclei", "nikto", "ssh-audit")

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class TargetPlanError(ValueError):
    """The input as a whole cannot be planned (too large, empty)."""


@dataclass(frozen=True)
class ParsedEntry:
    """One operator entry, reduced to what the gate and adapters understand."""

    raw: str
    host: str | None = None  # bare IP or hostname
    networks: tuple[IPNetwork, ...] = ()  # CIDR or range input
    port: str | None = None
    scheme: Literal["http", "https"] | None = None
    note: str | None = None


@dataclass(frozen=True)
class PlannedScan:
    input: str
    target: str
    options: dict[str, Any]
    kind: Literal["host", "network"]
    note: str | None = None


@dataclass(frozen=True)
class Rejection:
    input: str
    target: str | None
    reason: str


@dataclass
class TargetPlan:
    planned: list[PlannedScan] = field(default_factory=list)
    rejected: list[Rejection] = field(default_factory=list)


class _Reject(ValueError):
    pass


def split_entries(targets: list[str]) -> list[str]:
    """Split raw inputs on commas, semicolons and whitespace; drop empties."""
    out: list[str] = []
    for chunk in targets:
        out.extend(part for part in _SPLIT_RE.split(chunk) if part)
    return out


def _validate_port(port: str) -> str:
    if not _PORT_RE.fullmatch(port) or not 1 <= int(port) <= 65535:
        raise _Reject(f"invalid port {port!r}: must be 1-65535")
    return str(int(port))


def _validate_host(host: str) -> str:
    """Return the canonical bare host, or refuse anything that isn't one."""
    if "%" in host:
        raise _Reject("IPv6 scope ids ('%iface') are not accepted")
    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        pass
    if host.startswith("*."):
        raise _Reject(
            "a wildcard cannot be scanned directly (no DNS enumeration); "
            "enter the specific hostnames under it"
        )
    if not is_valid_hostname(host) or re.fullmatch(r"[0-9.]+", host):
        # An all-numeric name that is not an IP ("172.20.1.300") is a typo, and
        # nmap would read it as an address, not a hostname.
        raise _Reject("not a valid IP address, CIDR, range, hostname or URL")
    return host.lower()


def _parse_url(raw: str) -> ParsedEntry:
    if any(c in raw for c in "\\@") or any(ord(c) < 0x21 or ord(c) == 0x7F for c in raw):
        # userinfo and backslashes are where URL parsers disagree about the host.
        raise _Reject("URLs with credentials ('@') or backslashes are not accepted")
    parts = urlsplit(raw)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise _Reject(f"unsupported URL scheme {parts.scheme!r}: use http or https")
    if not parts.hostname:
        raise _Reject("URL has no host")
    try:
        port = parts.port
    except ValueError as exc:
        raise _Reject(f"invalid port in URL: {exc}") from exc
    host = _validate_host(parts.hostname)
    note = None
    if (parts.path not in ("", "/")) or parts.query or parts.fragment:
        note = "URL path/query ignored: the whole web root on this host:port is scanned"
    return ParsedEntry(
        raw=raw,
        host=host,
        port=_validate_port(str(port)) if port is not None else None,
        scheme=scheme,  # type: ignore[arg-type]
        note=note,
    )


def _parse_ipv4_range(raw: str, start_s: str, end_s: str) -> ParsedEntry:
    try:
        start = ipaddress.IPv4Address(start_s)
        if "." in end_s:
            end = ipaddress.IPv4Address(end_s)
        else:
            last = int(end_s)
            if last > 255 or (len(end_s) > 1 and end_s.startswith("0")):
                raise ValueError(end_s)
            end = ipaddress.IPv4Address(".".join(start_s.split(".")[:3] + [str(last)]))
    except ValueError as exc:
        raise _Reject("invalid IPv4 range") from exc
    if end < start:
        raise _Reject("range end is before its start")
    if int(end) - int(start) + 1 > _MAX_EXPANDED_ADDRESSES:
        raise _Reject(f"range is larger than {_MAX_EXPANDED_ADDRESSES} addresses")
    return ParsedEntry(raw=raw, networks=tuple(ipaddress.summarize_address_range(start, end)))


def parse_entry(raw: str) -> ParsedEntry:
    """Parse one entry. Raises `_Reject` with an operator-facing reason."""
    if "://" in raw:
        return _parse_url(raw)

    range_match = _IPV4_RANGE_RE.fullmatch(raw)
    if range_match:
        return _parse_ipv4_range(raw, range_match.group(1), range_match.group(2))

    if "/" in raw:
        if not _CIDR_RE.fullmatch(raw):
            raise _Reject("not a valid CIDR block (expected address/prefix, e.g. 10.0.0.0/24)")
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError as exc:
            raise _Reject(f"invalid CIDR block: {exc}") from exc
        if network.num_addresses > _MAX_EXPANDED_ADDRESSES and network.version == 6:
            raise _Reject(f"IPv6 block is larger than {_MAX_EXPANDED_ADDRESSES} addresses")
        note = None
        if network.compressed != raw.lower():
            note = f"normalized to {network.compressed}"
        return ParsedEntry(raw=raw, networks=(network,), note=note)

    bracketed = re.fullmatch(r"\[([^\]]+)\](?::(.*))?", raw)
    if bracketed:
        host = _validate_host(bracketed.group(1))
        port = bracketed.group(2)
        return ParsedEntry(raw=raw, host=host, port=_validate_port(port) if port else None)

    if raw.count(":") == 1:
        host_s, port_s = raw.split(":")
        return ParsedEntry(raw=raw, host=_validate_host(host_s), port=_validate_port(port_s))

    return ParsedEntry(raw=raw, host=_validate_host(raw))


def _scan_options(
    scanner: str, entry: ParsedEntry, base: dict[str, Any], *, network: bool
) -> dict[str, Any]:
    """Shared options plus what this entry itself named (its port and scheme win)."""
    opts = dict(base)
    if scanner == "nmap":
        if network:
            # -Pn on a block probes every port of every address, live or not.
            # Host discovery finds the live ones first.
            opts.pop("no_ping", None)
        if entry.port:
            opts["ports"] = entry.port
    elif scanner == "nuclei":
        opts["scheme"] = entry.scheme or opts.get("scheme", "http")
        if entry.port:
            opts["port"] = entry.port
    elif scanner == "nikto":
        scheme = entry.scheme or opts.get("scheme", "http")
        opts["scheme"] = scheme
        opts["port"] = entry.port or opts.get("port") or ("443" if scheme == "https" else "80")
    elif scanner == "ssh-audit":
        opts["port"] = entry.port or opts.get("port") or "22"
    return opts


def _hosts_of(network: IPNetwork) -> list[str]:
    if network.num_addresses == 1:
        return [network.network_address.compressed]
    return [h.compressed for h in network.hosts()]


def _nmap_blocks(network: IPNetwork) -> list[tuple[str, Literal["host", "network"]]]:
    if network.num_addresses == 1:
        return [(network.network_address.compressed, "host")]
    if network.version == 6:
        return [(h, "host") for h in _hosts_of(network)]
    if network.prefixlen < NMAP_MAX_IPV4_PREFIX:
        if 1 << (NMAP_MAX_IPV4_PREFIX - network.prefixlen) > MAX_SCANS_PER_BATCH:
            raise TargetPlanError(
                f"{network.compressed} splits into more than {MAX_SCANS_PER_BATCH} scans; "
                "use a narrower range"
            )
        return [(n.compressed, "network") for n in network.subnets(new_prefix=NMAP_MAX_IPV4_PREFIX)]
    return [(network.compressed, "network")]


def plan_targets(
    scanner: str, targets: list[str], base_options: dict[str, Any] | None = None
) -> TargetPlan:
    """Expand operator input into planned scans. Pure: no I/O, no DNS, no gate.

    Raises `TargetPlanError` when the input is empty or would plan more than
    `MAX_SCANS_PER_BATCH` scans.
    """
    if scanner not in SUPPORTED_SCANNERS:
        raise TargetPlanError(f"unsupported scanner {scanner!r}")
    entries = split_entries(targets)
    if not entries:
        raise TargetPlanError("no targets given")

    base = dict(base_options or {})
    plan = TargetPlan()
    seen: set[tuple[str, str]] = set()

    def add(
        entry: ParsedEntry, target: str, kind: Literal["host", "network"], note: str | None
    ) -> None:
        opts = _scan_options(scanner, entry, base, network=kind == "network")
        key = (target, json.dumps(opts, sort_keys=True, default=str))
        if key in seen:
            return
        seen.add(key)
        plan.planned.append(
            PlannedScan(input=entry.raw, target=target, options=opts, kind=kind, note=note)
        )
        if len(plan.planned) > MAX_SCANS_PER_BATCH:
            raise TargetPlanError(
                f"input expands to more than {MAX_SCANS_PER_BATCH} scans; "
                "split it into smaller batches or narrower ranges"
            )

    for raw in entries:
        try:
            entry = parse_entry(raw)
        except _Reject as exc:
            plan.rejected.append(Rejection(input=raw, target=None, reason=str(exc)))
            continue

        if entry.host is not None:
            add(entry, entry.host, "host", entry.note)
            continue

        for network in entry.networks:
            if scanner == "nmap":
                blocks = _nmap_blocks(network)
            else:
                total = sum(n.num_addresses for n in entry.networks)
                if total > _MAX_EXPANDED_ADDRESSES:
                    raise TargetPlanError(f"{raw!r} is too large to expand host by host")
                blocks = [(h, "host") for h in _hosts_of(network)]
            for target, kind in blocks:
                add(entry, target, kind, entry.note)

    return plan
