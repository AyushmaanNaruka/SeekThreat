"""The declared network model an attack graph is built against.

A scan run from one vantage point observes which services are *open*. It cannot
observe which hosts can reach which other hosts. In a real engagement that comes from
the network owner (firewall policy, segment diagrams), so it is declared, attributed
to a named person, and versioned by content hash, exactly like an authorization.

The graph engine never invents reachability: every lateral edge cites this declaration
(by `topology_id`) *and* an observed open service on the far side.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator, model_validator

from packages.schema.models._time import require_aware

_ZONE_NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}")


class Zone(BaseModel):
    """One network segment. Membership is by address, never by DNS name."""

    model_config = ConfigDict(frozen=True)

    name: str
    cidrs: tuple[str, ...]
    # The attacker is assumed to start with network access inside this zone
    # (e.g. the internet-facing DMZ the scanner sat in).
    attacker_entry: bool = False
    # Reaching anything in this zone is an attack-path goal.
    crown_jewel: bool = False
    description: str = ""

    @field_validator("name")
    @classmethod
    def _slug(cls, value: str) -> str:
        if not _ZONE_NAME.fullmatch(value):
            raise ValueError(f"zone name {value!r} must be a lowercase slug")
        return value

    @field_validator("cidrs")
    @classmethod
    def _valid_cidrs(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            raise ValueError("a zone needs at least one CIDR")
        return tuple(str(ipaddress.ip_network(c.strip(), strict=False)) for c in value)

    def contains(self, address: str) -> bool:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        return any(ip in ipaddress.ip_network(c) for c in self.cidrs)


class MultiHomedHost(BaseModel):
    """One machine with an address in more than one zone. Scanners see each address as a
    separate host; only this declaration says they are the same machine."""

    model_config = ConfigDict(frozen=True)

    name: str
    addresses: tuple[str, ...]

    @field_validator("addresses")
    @classmethod
    def _valid_addresses(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        canon = tuple(ipaddress.ip_address(a.strip()).compressed for a in value)
        if len(set(canon)) < 2:
            raise ValueError("a multi-homed host needs at least two distinct addresses")
        return canon


class ZoneFlow(BaseModel):
    """A declared allowed flow between zones (e.g. a firewall rule). Empty `ports` means
    every port."""

    model_config = ConfigDict(frozen=True)

    from_zone: str
    to_zone: str
    ports: tuple[int, ...] = ()
    description: str = ""

    @field_validator("ports")
    @classmethod
    def _valid_ports(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        for port in value:
            if not 0 < port < 65536:
                raise ValueError(f"port {port} out of range")
        return tuple(sorted(set(value)))


class NetworkTopology(BaseModel):
    """The declared network model for one engagement."""

    model_config = ConfigDict(frozen=True)

    engagement_id: str
    declared_by: str
    declared_at: datetime
    zones: tuple[Zone, ...]
    multi_homed_hosts: tuple[MultiHomedHost, ...] = ()
    flows: tuple[ZoneFlow, ...] = ()
    # Hosts in the same zone can reach each other's services (flat segment).
    intra_zone_reachable: bool = True
    source_note: str = Field(default="", description="Where this declaration came from")

    @field_validator("declared_by")
    @classmethod
    def _named(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("declared_by must name the person who declared this topology")
        return value.strip()

    @field_validator("declared_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        return require_aware(value)

    @model_validator(mode="after")
    def _consistent(self) -> NetworkTopology:
        names = [z.name for z in self.zones]
        if not names:
            raise ValueError("a topology needs at least one zone")
        if len(set(names)) != len(names):
            raise ValueError("zone names must be unique")
        if not any(z.attacker_entry for z in self.zones):
            raise ValueError("at least one zone must be marked attacker_entry")
        for flow in self.flows:
            for zone in (flow.from_zone, flow.to_zone):
                if zone not in names:
                    raise ValueError(f"flow references unknown zone {zone!r}")
        seen: dict[str, str] = {}
        for host in self.multi_homed_hosts:
            for address in host.addresses:
                if address in seen:
                    raise ValueError(
                        f"address {address} is declared on both {seen[address]!r} and {host.name!r}"
                    )
                seen[address] = host.name
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def topology_id(self) -> str:
        """Content hash of the declaration, so edges can cite the exact version used."""
        payload = self.model_dump(mode="json", exclude={"topology_id"})
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return f"topology:sha256:{digest[:24]}"

    def zones_of(self, address: str) -> tuple[str, ...]:
        """Names of every zone containing `address`, in declaration order."""
        return tuple(z.name for z in self.zones if z.contains(address))

    def zone(self, name: str) -> Zone:
        for z in self.zones:
            if z.name == name:
                return z
        raise KeyError(name)
