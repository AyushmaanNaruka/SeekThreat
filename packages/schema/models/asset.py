"""Assets and the services running on them."""

from __future__ import annotations

from pydantic import BaseModel, Field


class Service(BaseModel):
    """One network service on one asset."""

    port: int = Field(ge=1, le=65535)
    protocol: str = "tcp"
    name: str | None = None
    product: str | None = None
    version: str | None = None
    cpe: str | None = None


class Asset(BaseModel):
    """A host, service, or application discovered during a scan."""

    asset_id: str
    engagement_id: str
    hostname: str | None = None
    ip: str | None = None
    services: list[Service] = Field(default_factory=list)
    # Identity resolution: six scanners describe one host six ways.
    aliases: list[str] = Field(default_factory=list)
