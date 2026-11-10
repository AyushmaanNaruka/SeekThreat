"""Deterministic asset identity resolution (Track 1, proposed in DECISIONS.md D-045).

Six scanners describe one host six ways: nmap keys it by address (`172.20.1.10`,
`[2001:db8::10]:443/tcp`, `mac:aa:bb:...`), nuclei and Nikto by whatever the operator
typed (`http://DVWA.lab.local./`), ssh-audit by its `<host>:<port>/tcp` target. This
module maps every observation to one canonical D-040 `asset_id`:

    host:<ipv4>            host:172.20.1.10
    host:<ipv6>            host:2001:db8::10      (compressed, unbracketed, lowercase)
    host:mac:<mac>         host:mac:aa:bb:cc:dd:ee:ff
    host:<hostname>        host:dvwa.lab.local    (lowercase, trailing dot removed)

How joins are made — only from evidence already in the observations, never from DNS:

1. **Canonicalisation.** Spelling differences are not identity differences: brackets,
   IPv6 zero-compression, case and a trailing FQDN dot are normalised away. This is
   string rewriting, not a join, and needs no evidence.
2. **`nmap_host_addresses`.** Addresses listed together in one nmap `HOST_UP`
   observation (`ipv4`, `ipv6`, `mac` attributes) are one host. Records are unioned
   across observations; a component resolves to its IPv4, else its IPv6, else its MAC
   (D-040 priority). A component holding two IPv4s (or, with no IPv4, two IPv6s or two
   MACs) is *conflicted* — e.g. one MAC seen with two IPv4s after a DHCP change — and
   then nothing in it is joined: every address stays `host:<itself>` and the conflict is
   recorded as an `Ambiguity`.
3. **`nmap_hostname`.** A hostname nmap lists for a host (`hostnames` attribute, `user`
   or `PTR`) points at that host. **`scanner_reported_ip`.** A nuclei/Nikto observation
   that names a hostname *and* reports the IP it connected to points that hostname at
   that IP. Hostname links are one-way (hostname -> host): a hostname can never glue two
   addresses together. If a hostname's links lead to more than one host it is ambiguous
   and stays `host:<hostname>`, with the conflict recorded.

PTR names are attacker-influenced (docs/02-architecture.md). They are accepted as join
evidence only because a PTR that claims a name another host also carries makes that name
ambiguous rather than re-pointing it; the evidence type is kept on the link so a reviewer
can see a join rests on PTR.

Every join carries the rule and the observation ids that justified it. No function here
resolves names or opens a socket.
"""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from collections.abc import Iterable
from enum import Enum
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict

from packages.schema.models.observation import Observation, ObservationKind

# Liberal on purpose: docker lab names carry underscores (`lab-dvwa-1.lab_dmz`), and a
# single label (`dvwa`) is a valid target. Lowercase only: callers canonicalise first.
_HOSTNAME_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_.\-]*[a-z0-9_])?$")
_MAC_RE = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")
_PORT_RE = re.compile(r"^[0-9]{1,5}$")
_SYNTHETIC_PREFIXES = ("asset-", "ast-")

# Scanners whose vuln/service observations may carry both a hostname (`host`) and the IP
# the scanner itself connected to (`ip`). The pairing is the scanner's own report.
_HOST_IP_SCANNERS = frozenset({"nuclei", "nikto"})


class AddressKind(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    MAC = "mac"
    HOSTNAME = "hostname"


# D-040 priority: IPv4 > IPv6 > MAC > hostname.
_PRIORITY = {AddressKind.IPV4: 0, AddressKind.IPV6: 1, AddressKind.MAC: 2, AddressKind.HOSTNAME: 3}


class HostRef(BaseModel):
    """One canonical way of naming a host."""

    model_config = ConfigDict(frozen=True)

    kind: AddressKind
    value: str

    @property
    def asset_id(self) -> str:
        if self.kind == AddressKind.MAC:
            return f"host:mac:{self.value}"
        return f"host:{self.value}"

    def sort_key(self) -> tuple[int, str]:
        return (_PRIORITY[self.kind], self.value)


class Endpoint(BaseModel):
    """A listener on a host: `<host>:<port>/<proto>` once canonicalised."""

    model_config = ConfigDict(frozen=True)

    host: HostRef
    port: int | None = None
    proto: str | None = None

    @property
    def service_key(self) -> str:
        """`<port>/<proto>`, or "" when the scanner reported no port."""
        if self.port is None:
            return ""
        return f"{self.port}/{self.proto or 'tcp'}"


class IdentityLink(BaseModel):
    """An alias joined to a canonical asset, and why."""

    model_config = ConfigDict(frozen=True)

    alias: str
    asset_id: str
    rule: str
    observation_ids: tuple[str, ...]


class Ambiguity(BaseModel):
    """An alias whose evidence points at more than one host. Left unjoined."""

    model_config = ConfigDict(frozen=True)

    alias: str
    candidates: tuple[str, ...]
    rule: str
    observation_ids: tuple[str, ...]


class Resolution(BaseModel):
    """Where one host reference landed."""

    model_config = ConfigDict(frozen=True)

    alias: str
    asset_id: str
    rule: str | None = None  # None: canonical form of the alias itself, no join made
    observation_ids: tuple[str, ...] = ()
    ambiguous: bool = False

    @property
    def joined(self) -> bool:
        return self.alias != self.asset_id


# --------------------------------------------------------------------------- #
# Canonicalisation (no evidence needed)
# --------------------------------------------------------------------------- #


def canonical_host(raw: str) -> HostRef | None:
    """Canonicalise one spelling of a host, or None if it names no usable host.

    Accepts an IPv4/IPv6 literal (bracketed or not), `mac:<mac>`, or a hostname. Pure
    string handling: never resolves anything.
    """
    value = raw.strip()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    if not value or value.lower() == "unknown":
        return None
    if value.lower().startswith("mac:"):
        mac = value[4:].lower().replace("-", ":")
        return HostRef(kind=AddressKind.MAC, value=mac) if _MAC_RE.fullmatch(mac) else None
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        if ip.version == 4:
            return HostRef(kind=AddressKind.IPV4, value=str(ip))
        return HostRef(kind=AddressKind.IPV6, value=ip.compressed)
    name = value.rstrip(".").lower()
    if name and _HOSTNAME_RE.fullmatch(name):
        return HostRef(kind=AddressKind.HOSTNAME, value=name)
    return None


def canonical_mac(raw: str) -> HostRef | None:
    return canonical_host(f"mac:{raw}") if raw else None


def parse_endpoint(raw: str) -> Endpoint | None:
    """Parse a URL, an nmap-style `<host>:<port>/<proto>`, `<host>:<port>`, or a bare host."""
    text = raw.strip()
    if not text:
        return None
    if "://" in text:
        parts = urlsplit(text)
        host = canonical_host(parts.hostname or "")
        if host is None:
            return None
        try:
            port = parts.port  # only an explicit port; never defaulted from the scheme
        except ValueError:
            port = None
        return Endpoint(host=host, port=port, proto="tcp" if port is not None else None)
    proto: str | None = None
    if "/" in text:
        text, proto = text.split("/", 1)
        proto = proto.lower() or None
    head, sep, tail = text.rpartition(":")
    bare = canonical_host(text)
    # "<host>:<port>". An unbracketed IPv6 literal also ends in ":<digits>", so a string
    # that is itself a valid address is a bare host unless a protocol suffix says otherwise.
    if sep and head and _PORT_RE.fullmatch(tail) and (proto is not None or bare is None):
        host = canonical_host(head)
        port = int(tail)
        if host is None or not 0 < port < 65536:
            return None
        return Endpoint(host=host, port=port, proto=proto or "tcp")
    if bare is None:
        return None
    return Endpoint(host=bare)


def endpoint_of(observation: Observation) -> Endpoint | None:
    """The host (and listener, if any) an observation is about."""
    if observation.kind == ObservationKind.HOST_UP:
        return parse_endpoint(observation.subject)
    raw = observation.attributes.get("endpoint") or observation.subject
    return parse_endpoint(raw)


def is_valid_asset_id(asset_id: str) -> bool:
    """True if `asset_id` is in canonical D-040 form (or a synthetic fixture prefix)."""
    if asset_id.startswith(_SYNTHETIC_PREFIXES):
        return True
    if not asset_id.startswith("host:"):
        return False
    ref = canonical_host(asset_id[len("host:") :])
    return ref is not None and ref.asset_id == asset_id


# --------------------------------------------------------------------------- #
# Evidence-based joining
# --------------------------------------------------------------------------- #


class _UnionFind:
    def __init__(self) -> None:
        self.parent: dict[HostRef, HostRef] = {}

    def add(self, ref: HostRef) -> None:
        self.parent.setdefault(ref, ref)

    def find(self, ref: HostRef) -> HostRef:
        root = ref
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[ref] != root:
            self.parent[ref], ref = root, self.parent[ref]
        return root

    def union(self, a: HostRef, b: HostRef) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            # Deterministic root regardless of insertion order.
            lo, hi = sorted((ra, rb), key=HostRef.sort_key)
            self.parent[hi] = lo


def _host_up_addresses(observation: Observation) -> list[HostRef]:
    attrs = observation.attributes
    refs: list[HostRef] = []
    subject = canonical_host(observation.subject)
    if subject is not None and subject.kind != AddressKind.HOSTNAME:
        refs.append(subject)
    for key in ("ipv4", "ipv6"):
        if attrs.get(key) and (ref := canonical_host(attrs[key])) is not None:
            refs.append(ref)
    if (ref := canonical_mac(attrs.get("mac", ""))) is not None:
        refs.append(ref)
    return sorted(set(refs), key=HostRef.sort_key)


def _host_up_hostnames(observation: Observation) -> list[tuple[HostRef, str]]:
    """(hostname, nmap type) pairs. Falls back to `hostname` when `hostnames` is absent."""
    attrs = observation.attributes
    kinds: dict[HostRef, set[str]] = defaultdict(set)
    raw = attrs.get("hostnames", "")
    entries = [e for e in raw.split(",") if e.strip()] if raw else []
    if not entries and attrs.get("hostname"):
        entries = [attrs["hostname"]]
    for entry in entries:
        name, _, kind = entry.partition("|")
        ref = canonical_host(name)
        if ref is not None and ref.kind == AddressKind.HOSTNAME:
            kinds[ref].add(kind.strip() or "unknown")
    return sorted(
        ((ref, "+".join(sorted(k))) for ref, k in kinds.items()),
        key=lambda item: item[0].sort_key(),
    )


class IdentityResolver:
    """Maps host references to canonical asset ids for one engagement's observations."""

    def __init__(self, observations: Iterable[Observation]) -> None:
        self._uf = _UnionFind()
        self._addr_evidence: dict[HostRef, set[str]] = defaultdict(set)
        # hostname -> {address -> (rule label, observation ids)}
        self._name_links: dict[HostRef, dict[HostRef, tuple[set[str], set[str]]]] = defaultdict(
            dict
        )
        for obs in sorted(observations, key=lambda o: o.observation_id):
            if obs.kind == ObservationKind.HOST_UP:
                self._ingest_host_up(obs)
            elif obs.scanner in _HOST_IP_SCANNERS:
                self._ingest_host_ip_pair(obs)
        self._components = self._build_components()
        self.ambiguities: list[Ambiguity] = []
        self._address_resolution: dict[HostRef, Resolution] = {}
        self._name_resolution: dict[HostRef, Resolution] = {}
        self._resolve_all()
        self.ambiguities.sort(key=lambda a: a.alias)

    # -- ingestion ---------------------------------------------------------- #

    def _ingest_host_up(self, obs: Observation) -> None:
        addresses = _host_up_addresses(obs)
        for ref in addresses:
            self._uf.add(ref)
            self._addr_evidence[ref].add(obs.observation_id)
        for other in addresses[1:]:
            self._uf.union(addresses[0], other)
        if not addresses:
            return
        primary = addresses[0]
        for name, nmap_type in _host_up_hostnames(obs):
            self._link_name(name, primary, f"nmap_hostname:{nmap_type}", obs.observation_id)

    def _ingest_host_ip_pair(self, obs: Observation) -> None:
        attrs = obs.attributes
        name = canonical_host(attrs.get("host", ""))
        ip = canonical_host(attrs.get("ip", ""))
        if name is None or ip is None:
            return
        if name.kind != AddressKind.HOSTNAME or ip.kind not in (AddressKind.IPV4, AddressKind.IPV6):
            return
        self._uf.add(ip)
        self._link_name(name, ip, "scanner_reported_ip", obs.observation_id)

    def _link_name(self, name: HostRef, address: HostRef, rule: str, obs_id: str) -> None:
        rules, obs_ids = self._name_links[name].setdefault(address, (set(), set()))
        rules.add(rule)
        obs_ids.add(obs_id)

    # -- resolution --------------------------------------------------------- #

    def _build_components(self) -> dict[HostRef, list[HostRef]]:
        comps: dict[HostRef, list[HostRef]] = defaultdict(list)
        for ref in self._uf.parent:
            comps[self._uf.find(ref)].append(ref)
        return {root: sorted(members, key=HostRef.sort_key) for root, members in comps.items()}

    def _resolve_all(self) -> None:
        for members in sorted(self._components.values(), key=lambda m: m[0].sort_key()):
            self._resolve_component(members)
        for name in sorted(self._name_links, key=HostRef.sort_key):
            self._resolve_name(name)

    def _resolve_component(self, members: list[HostRef]) -> None:
        evidence = tuple(sorted(set().union(*(self._addr_evidence[m] for m in members))))
        by_kind: dict[AddressKind, list[HostRef]] = defaultdict(list)
        for m in members:
            by_kind[m.kind].append(m)
        anchor_kind = next(
            (k for k in (AddressKind.IPV4, AddressKind.IPV6, AddressKind.MAC) if by_kind[k]),
            None,
        )
        if anchor_kind is None:
            return
        if len(by_kind[anchor_kind]) > 1:
            candidates = tuple(r.asset_id for r in by_kind[anchor_kind])
            for m in members:
                if m.kind != anchor_kind:
                    self.ambiguities.append(
                        Ambiguity(
                            alias=m.asset_id,
                            candidates=candidates,
                            rule="nmap_host_addresses",
                            observation_ids=evidence,
                        )
                    )
                self._address_resolution[m] = Resolution(
                    alias=m.asset_id, asset_id=m.asset_id, ambiguous=m.kind != anchor_kind
                )
            return
        anchor = by_kind[anchor_kind][0]
        for m in members:
            if m == anchor:
                self._address_resolution[m] = Resolution(alias=m.asset_id, asset_id=m.asset_id)
            else:
                self._address_resolution[m] = Resolution(
                    alias=m.asset_id,
                    asset_id=anchor.asset_id,
                    rule="nmap_host_addresses",
                    observation_ids=evidence,
                )

    def _resolve_address(self, ref: HostRef) -> Resolution:
        found = self._address_resolution.get(ref)
        if found is not None:
            return found
        return Resolution(alias=ref.asset_id, asset_id=ref.asset_id)

    def _resolve_name(self, name: HostRef) -> None:
        targets: dict[str, tuple[set[str], set[str]]] = {}
        for address, (rules, obs_ids) in self._name_links[name].items():
            res = self._resolve_address(address)
            t_rules, t_obs = targets.setdefault(res.asset_id, (set(), set()))
            t_rules.update(rules)
            t_obs.update(obs_ids)
            t_obs.update(res.observation_ids)
            if res.rule:
                t_rules.add(res.rule)
        all_obs = tuple(sorted(set().union(*(o for _, o in targets.values()))))
        if len(targets) == 1:
            asset_id, (rules, _) = next(iter(targets.items()))
            self._name_resolution[name] = Resolution(
                alias=name.asset_id,
                asset_id=asset_id,
                rule="+".join(sorted(rules)),
                observation_ids=all_obs,
            )
            return
        all_rules = sorted(set().union(*(r for r, _ in targets.values())))
        self.ambiguities.append(
            Ambiguity(
                alias=name.asset_id,
                candidates=tuple(sorted(targets)),
                rule="+".join(all_rules),
                observation_ids=all_obs,
            )
        )
        self._name_resolution[name] = Resolution(
            alias=name.asset_id, asset_id=name.asset_id, ambiguous=True
        )

    # -- public ------------------------------------------------------------- #

    def resolve(self, ref: HostRef) -> Resolution:
        """Canonical asset for one host reference. Unknown references map to themselves."""
        if ref.kind == AddressKind.HOSTNAME:
            found = self._name_resolution.get(ref)
            return found or Resolution(alias=ref.asset_id, asset_id=ref.asset_id)
        return self._resolve_address(ref)

    def resolve_observation(self, observation: Observation) -> Resolution | None:
        """Canonical asset for an observation, or None if it names no usable host."""
        endpoint = endpoint_of(observation)
        return None if endpoint is None else self.resolve(endpoint.host)

    @property
    def links(self) -> list[IdentityLink]:
        """Every join made, sorted by alias. Canonical self-mappings are not listed."""
        out = [
            IdentityLink(
                alias=r.alias,
                asset_id=r.asset_id,
                rule=r.rule or "",
                observation_ids=r.observation_ids,
            )
            for r in [*self._address_resolution.values(), *self._name_resolution.values()]
            if r.joined and r.rule
        ]
        return sorted(out, key=lambda link: link.alias)
