# Phase 0 Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the SeekThreat repository ready to build in — typed schema, working authorization, and tests that mechanically enforce the project's two hard rules.

**Architecture:** `packages/schema` becomes Pydantic v2 models split by concern, with provenance and evidence made structurally non-optional so unattributed data cannot be constructed. Authorization target matching is fixed (it is currently broken) and moves into the schema alongside the `Authorization` type. Two architecture tests enforce the LLM firewall and the authorization choke point.

**Tech Stack:** Python 3.11+, Pydantic v2, pytest, ruff, mypy, Docker Compose.

**Spec:** `docs/02-architecture.md` (decisions logged as D-003 through D-009 in `DECISIONS.md`)

## Global Constraints

- Python `>=3.11`. Local interpreter is 3.12.10.
- Pydantic v2 (`>=2.9`) for every type crossing a boundary. No dataclasses in `packages/schema`.
- Every enriched field carries `Provenance` (source + confidence). No unattributed data.
- Every score renders its own explanation. No opaque numbers.
- Every `PathEdge` carries `rule_name` and non-empty `evidence`.
- The LLM never creates graph edges. `services/assistant` may import `packages.schema` only.
- No scan without an authorization record. Test targets come from `lab/` only.
- Third-party code lives in `vendor/` only, permissive licences only, with a `THIRD_PARTY.md` row in the same change.
- Never generate placeholder data that looks like a real measurement. No metric in this project has been measured.
- All datetimes are timezone-aware UTC. Naive datetimes are rejected at construction.
- Run everything from the repository root; `pytest` puts the root on `sys.path`.
- Branch: create `feat/phase-0-foundation` from `main` before Task 1.

---

### Task 1: Project tooling

**Files:**
- Create: `pyproject.toml`
- Create: `requirements.txt`
- Create: `requirements-dev.txt`
- Create: `tests/__init__.py`, `tests/unit/__init__.py`, `tests/architecture/__init__.py`
- Create: `tests/unit/test_smoke.py`
- Delete: `apps/api/requirements.txt`
- Modify: `apps/api/README.md`
- Modify: `THIRD_PARTY.md`

**Interfaces:**
- Consumes: nothing.
- Produces: a working `pytest` invocation from the repo root with the root on `sys.path`; `ruff check .` and `mypy` configured.

**Why root-level requirements rather than an installable package:** the codebase imports `packages.schema` and `services.scanners`, which requires the repository root on `sys.path`. Making the monorepo pip-installable would mean renaming those import paths. Instead `pytest` adds the root via its `pythonpath` setting, and dependencies live in plain requirements files. Boring and immediate.

- [ ] **Step 1: Create the branch**

```bash
git checkout -b feat/phase-0-foundation
```

- [ ] **Step 2: Write `pyproject.toml`**

Tool configuration only — no `[project]` table, no build backend, because this repo is not installed as a package.

```toml
[tool.pytest.ini_options]
pythonpath = ["."]
testpaths = ["tests"]
addopts = "-q --strict-markers"

[tool.ruff]
line-length = 100
target-version = "py311"

[tool.ruff.lint]
select = ["E", "F", "I", "UP", "B", "SIM"]

[tool.mypy]
python_version = "3.11"
strict = true
warn_unused_ignores = true
plugins = ["pydantic.mypy"]
mypy_path = "."
explicit_package_bases = true
namespace_packages = true

[[tool.mypy.overrides]]
module = ["networkx.*", "celery.*"]
ignore_missing_imports = true
```

- [ ] **Step 3: Write `requirements.txt`**

`networkx` and `pyyaml` are new dependencies, added by decisions D-003 and D-004. `vllm` is deliberately absent (D-006), as is `qdrant-client` (D-005).

```
fastapi>=0.115
uvicorn[standard]>=0.32
pydantic>=2.9
sqlalchemy>=2.0
alembic>=1.14
psycopg[binary]>=3.2
celery>=5.4
redis>=5.2
neo4j>=5.26
httpx>=0.28
networkx>=3.4
pyyaml>=6.0
```

- [ ] **Step 4: Write `requirements-dev.txt`**

```
-r requirements.txt
pytest>=8.3
pytest-asyncio>=0.24
ruff>=0.8
mypy>=1.13
types-PyYAML>=6.0
```

- [ ] **Step 5: Delete the old requirements file and update its README**

```bash
git rm apps/api/requirements.txt
```

In `apps/api/README.md`, append this section:

```markdown
## Dependencies

Dependencies live in the repository root: `requirements.txt` and `requirements-dev.txt`.
Install from the root, not from here.

    pip install -r requirements-dev.txt
```

- [ ] **Step 6: Verify the two new licences by opening them, then add register rows**

`THIRD_PARTY.md` requires a row for "a library that is central to a core subsystem." NetworkX is the graph substrate and PyYAML carries the rules. Both qualify. Rule 4 of the open source policy forbids guessing a licence.

```bash
pip download --no-deps --no-binary :all: networkx pyyaml -d /tmp/lic 2>/dev/null || true
python -c "import importlib.metadata as m; print('networkx:', m.metadata('networkx').get('License-Expression') or m.metadata('networkx').get('License'))"
python -c "import importlib.metadata as m; print('pyyaml:', m.metadata('PyYAML').get('License-Expression') or m.metadata('PyYAML').get('License'))"
```

Expected: NetworkX reports BSD-3-Clause, PyYAML reports MIT. Both are permissive and require no `vendor/` entry — we depend on them, we do not copy them. **If either reports something other than a permissive licence, stop and raise it before continuing.**

Add these two rows to the register table in `THIRD_PARTY.md`, below the Nmap row, filling in your own name and today's date in the last two columns:

```markdown
| NetworkX | BSD-3-Clause | Service | In-memory attack graph substrate (D-003) | | |
| PyYAML | MIT | Service | Rules-as-data loading for the path engine (D-004) | | |
```

- [ ] **Step 7: Create the test tree and a smoke test**

`tests/__init__.py`, `tests/unit/__init__.py` and `tests/architecture/__init__.py` are all empty files.

`tests/unit/test_smoke.py`:

```python
"""Proves the repository root is importable from tests."""

import packages.schema  # noqa: F401
import services.scanners  # noqa: F401


def test_repository_root_is_importable() -> None:
    assert packages.schema is not None
```

- [ ] **Step 8: Install and run**

```bash
pip install -r requirements-dev.txt
pytest tests/unit/test_smoke.py -v
```

Expected: PASS. If it fails with `ModuleNotFoundError`, the `pythonpath` setting in `pyproject.toml` is not being read — confirm you are running from the repository root.

- [ ] **Step 9: Run the linters**

```bash
ruff check .
```

Expected: clean, or only findings in files this plan replaces later.

- [ ] **Step 10: Commit**

```bash
git add pyproject.toml requirements.txt requirements-dev.txt tests THIRD_PARTY.md apps/api/README.md
git add -u
git commit -m "chore: add project tooling, test tree, and third-party rows for networkx and pyyaml"
```

---

### Task 2: Provenance primitives

**Files:**
- Create: `packages/schema/models/__init__.py` (empty)
- Create: `packages/schema/models/provenance.py`
- Test: `tests/unit/test_provenance.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `Source` (str Enum), `Confidence` (str Enum), `Provenance(source, confidence, retrieved_at, note=None)`, and the generic `Attributed[T](value, provenance)`. Every later task imports these.

This is the foundation of the "no unattributed data" invariant. `Attributed[T]` pairs a value with its provenance in one object, so a value without provenance is unrepresentable rather than merely discouraged.

- [ ] **Step 1: Write the failing test**

`tests/unit/test_provenance.py`:

```python
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from packages.schema.models.provenance import (
    Attributed,
    Confidence,
    Provenance,
    Source,
)

NOW = datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc)


def _prov() -> Provenance:
    return Provenance(source=Source.KEV, confidence=Confidence.HIGH, retrieved_at=NOW)


def test_provenance_rejects_naive_datetime() -> None:
    with pytest.raises(ValidationError, match="timezone-aware"):
        Provenance(
            source=Source.KEV,
            confidence=Confidence.HIGH,
            retrieved_at=datetime(2026, 9, 5, 12, 0),
        )


def test_provenance_is_frozen() -> None:
    p = _prov()
    with pytest.raises(ValidationError):
        p.source = Source.NVD


def test_attributed_requires_provenance() -> None:
    with pytest.raises(ValidationError):
        Attributed[str](value="9.8")


def test_attributed_carries_value_and_provenance() -> None:
    a = Attributed[float](value=9.8, provenance=_prov())
    assert a.value == 9.8
    assert a.provenance.source is Source.KEV


def test_derived_source_exists_and_is_labelled() -> None:
    assert Source.DERIVED.value == "derived"
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
pytest tests/unit/test_provenance.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'packages.schema.models'`

- [ ] **Step 3: Write the implementation**

Create empty `packages/schema/models/__init__.py`, then `packages/schema/models/provenance.py`:

```python
"""Provenance primitives.

Every enriched value in this system carries where it came from and how confident
we are. `Attributed[T]` pairs a value with its provenance so that an unattributed
value cannot be constructed.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict, field_validator


class Source(str, Enum):
    """Where a piece of data came from. Required on enriched fields."""

    CVE_ORG = "cve.org"
    VULNRICHMENT = "cisa.vulnrichment"
    KEV = "cisa.kev"
    EPSS = "first.epss"
    NVD = "nvd"
    EUVD = "enisa.euvd"
    OSV = "osv.dev"
    GHSA = "github.advisories"
    EXPLOITDB = "exploitdb"
    METASPLOIT = "metasploit"
    BRON = "bron"
    DERIVED = "derived"
    SCANNER = "scanner"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


def _require_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError("datetime must be timezone-aware")
    return value


class Provenance(BaseModel):
    """Attached to every enriched value. Non-optional by design."""

    model_config = ConfigDict(frozen=True)

    source: Source
    confidence: Confidence
    retrieved_at: datetime
    note: str | None = None

    @field_validator("retrieved_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        return _require_aware(value)


T = TypeVar("T")


class Attributed(BaseModel, Generic[T]):
    """A value and the provenance that justifies it, inseparably."""

    model_config = ConfigDict(frozen=True)

    value: T
    provenance: Provenance
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
pytest tests/unit/test_provenance.py -v
```

Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/schema/models tests/unit/test_provenance.py
git commit -m "feat: add Pydantic provenance primitives with Attributed[T]"
```

---

### Task 3: Authorization target matching

**Files:**
- Create: `packages/schema/models/engagement.py`
- Test: `tests/unit/test_authorization_matching.py`

**Interfaces:**
- Consumes: `_require_aware` behaviour from Task 2 (re-implemented locally as a validator).
- Produces: `target_matches(target: str, pattern: str) -> bool` and `Authorization(engagement_id, authorized_by, allowlist, granted_at, expires_at)` with `.permits(target: str) -> bool`. Task 4 adds `Engagement` to this same module; Task 9 imports `Authorization`.

**This fixes a live defect.** `services/scanners/base.py` currently implements `permits()` as `target in self.allowlist` — an exact string match. The allowlist in `.env.example` is `172.20.0.0/16`, so scanning `172.20.1.10` is rejected today. It fails closed, which is the safe direction, but authorization does not work.

**Security property to preserve:** matching never resolves DNS. A hostname is never compared against a CIDR by resolving it, because the resolution could change between the authorization being granted and the scan running. A hostname target only matches a hostname pattern.

- [ ] **Step 1: Write the failing test**

`tests/unit/test_authorization_matching.py`:

```python
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from packages.schema.models.engagement import Authorization, target_matches

NOW = datetime.now(timezone.utc)


def _auth(allowlist: list[str], expires_in: timedelta = timedelta(hours=1)) -> Authorization:
    return Authorization(
        engagement_id="eng-001",
        authorized_by="A. Named Human",
        allowlist=allowlist,
        granted_at=NOW,
        expires_at=NOW + expires_in,
    )


@pytest.mark.parametrize(
    ("target", "pattern", "expected"),
    [
        # The live defect: a host inside a CIDR must be permitted.
        ("172.20.1.10", "172.20.0.0/16", True),
        ("172.20.3.44", "172.20.0.0/16", True),
        ("10.0.0.5", "172.20.0.0/16", False),
        # A bare IP behaves as a single-host network.
        ("127.0.0.1", "127.0.0.1", True),
        ("127.0.0.2", "127.0.0.1", False),
        # Hostnames, case-insensitive.
        ("lab.local", "lab.local", True),
        ("LAB.LOCAL", "lab.local", True),
        ("other.local", "lab.local", False),
        # Wildcard subdomains match children, not the apex.
        ("web.lab.local", "*.lab.local", True),
        ("db.internal.lab.local", "*.lab.local", True),
        ("lab.local", "*.lab.local", False),
        ("evil.com", "*.lab.local", False),
        # No DNS resolution: a hostname never matches a CIDR.
        ("lab.local", "172.20.0.0/16", False),
        # An IP never matches a hostname pattern.
        ("172.20.1.10", "lab.local", False),
    ],
)
def test_target_matches(target: str, pattern: str, expected: bool) -> None:
    assert target_matches(target, pattern) is expected


def test_permits_accepts_target_in_any_allowlist_entry() -> None:
    auth = _auth(["10.0.0.0/8", "172.20.0.0/16"])
    assert auth.permits("172.20.1.10") is True


def test_permits_rejects_target_outside_allowlist() -> None:
    auth = _auth(["172.20.0.0/16"])
    assert auth.permits("8.8.8.8") is False


def test_expired_authorization_permits_nothing() -> None:
    auth = _auth(["172.20.0.0/16"], expires_in=timedelta(hours=-1))
    assert auth.permits("172.20.1.10") is False


def test_authorization_rejects_empty_allowlist() -> None:
    with pytest.raises(ValidationError):
        _auth([])


def test_authorization_rejects_anonymous_authorizer() -> None:
    with pytest.raises(ValidationError):
        Authorization(
            engagement_id="eng-001",
            authorized_by="   ",
            allowlist=["172.20.0.0/16"],
            granted_at=NOW,
            expires_at=NOW + timedelta(hours=1),
        )


def test_authorization_rejects_naive_datetimes() -> None:
    with pytest.raises(ValidationError, match="timezone-aware"):
        Authorization(
            engagement_id="eng-001",
            authorized_by="A. Named Human",
            allowlist=["172.20.0.0/16"],
            granted_at=datetime(2026, 9, 5, 12, 0),
            expires_at=datetime(2026, 9, 5, 13, 0),
        )
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
pytest tests/unit/test_authorization_matching.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'packages.schema.models.engagement'`

- [ ] **Step 3: Write the implementation**

`packages/schema/models/engagement.py`:

```python
"""Engagement and authorization.

No scan runs without an Authorization that permits its target. Matching never
resolves DNS: a name could resolve differently between the authorization being
granted and the scan running, so a hostname target only matches a hostname
pattern.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from fnmatch import fnmatch

from pydantic import BaseModel, ConfigDict, field_validator


def _require_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError("datetime must be timezone-aware")
    return value


def target_matches(target: str, pattern: str) -> bool:
    """Does `target` fall inside allowlist entry `pattern`?

    Patterns are either an IP address, a CIDR block, a hostname, or a
    `*.domain` wildcard matching subdomains but not the apex.
    """
    target = target.strip()
    pattern = pattern.strip()
    if not target or not pattern:
        return False

    try:
        network = ipaddress.ip_network(pattern, strict=False)
    except ValueError:
        network = None

    if network is not None:
        try:
            return ipaddress.ip_address(target) in network
        except ValueError:
            # A hostname is never resolved to compare against a network.
            return False

    # Pattern is a hostname. An IP target never matches one.
    try:
        ipaddress.ip_address(target)
    except ValueError:
        pass
    else:
        return False

    if pattern.startswith("*."):
        return fnmatch(target.lower(), pattern.lower())

    return target.lower() == pattern.lower()


class Authorization(BaseModel):
    """Proof that a scan is permitted. No scan runs without one."""

    model_config = ConfigDict(frozen=True)

    engagement_id: str
    authorized_by: str
    allowlist: list[str]
    granted_at: datetime
    expires_at: datetime

    @field_validator("granted_at", "expires_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        return _require_aware(value)

    @field_validator("allowlist")
    @classmethod
    def _allowlist_not_empty(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("allowlist must name at least one target")
        return value

    @field_validator("authorized_by")
    @classmethod
    def _authorizer_is_named(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("authorized_by must name a human, not be blank")
        return value

    def permits(self, target: str) -> bool:
        if datetime.now(timezone.utc) > self.expires_at:
            return False
        return any(target_matches(target, entry) for entry in self.allowlist)
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
pytest tests/unit/test_authorization_matching.py -v
```

Expected: 20 passed (14 parametrized cases plus 6 others).

- [ ] **Step 5: Commit**

```bash
git add packages/schema/models/engagement.py tests/unit/test_authorization_matching.py
git commit -m "fix: implement CIDR and wildcard matching for authorization allowlists

permits() previously used an exact string match, so a CIDR allowlist entry
such as 172.20.0.0/16 rejected every host inside it. Matching deliberately
never resolves DNS."
```

---

### Task 4: Engagement model and rewiring the scanner base

**Files:**
- Modify: `packages/schema/models/engagement.py`
- Modify: `services/scanners/base.py`
- Test: `tests/unit/test_engagement.py`

**Interfaces:**
- Consumes: `Authorization` from Task 3.
- Produces: `Engagement(engagement_id, name, authorization, created_at)`. `services.scanners.base` now imports `Authorization` and `ScanRequest` from the schema instead of defining `Authorization` itself. `ScanRequest(target, authorization, options)` becomes a Pydantic model.

- [ ] **Step 1: Write the failing test**

`tests/unit/test_engagement.py`:

```python
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from packages.schema.models.engagement import Authorization, Engagement, ScanRequest

NOW = datetime.now(timezone.utc)


def _auth() -> Authorization:
    return Authorization(
        engagement_id="eng-001",
        authorized_by="A. Named Human",
        allowlist=["172.20.0.0/16"],
        granted_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )


def test_engagement_carries_its_authorization() -> None:
    eng = Engagement(
        engagement_id="eng-001",
        name="Lab baseline",
        authorization=_auth(),
        created_at=NOW,
    )
    assert eng.authorization.permits("172.20.1.10") is True


def test_engagement_id_must_match_authorization() -> None:
    with pytest.raises(ValidationError, match="engagement_id"):
        Engagement(
            engagement_id="eng-002",
            name="Mismatched",
            authorization=_auth(),
            created_at=NOW,
        )


def test_scan_request_defaults_options_to_empty() -> None:
    req = ScanRequest(target="172.20.1.10", authorization=_auth())
    assert req.options == {}


def test_scanner_base_reuses_the_schema_authorization() -> None:
    from packages.schema.models.engagement import Authorization as SchemaAuthorization
    from services.scanners.base import Authorization as BaseAuthorization

    assert BaseAuthorization is SchemaAuthorization
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
pytest tests/unit/test_engagement.py -v
```

Expected: FAIL — `ImportError: cannot import name 'Engagement'`

- [ ] **Step 3: Add `Engagement` and `ScanRequest` to the schema**

Append to `packages/schema/models/engagement.py`:

```python
class Engagement(BaseModel):
    """A scoped piece of authorized work. Scopes every row downstream."""

    engagement_id: str
    name: str
    authorization: Authorization
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def _created_aware(cls, value: datetime) -> datetime:
        return _require_aware(value)

    @model_validator(mode="after")
    def _authorization_is_for_this_engagement(self) -> Engagement:
        if self.authorization.engagement_id != self.engagement_id:
            raise ValueError(
                "engagement_id must match the authorization's engagement_id "
                f"({self.engagement_id!r} != {self.authorization.engagement_id!r})"
            )
        return self


class ScanRequest(BaseModel):
    """One scan of one target, under one authorization."""

    target: str
    authorization: Authorization
    options: dict[str, Any] = Field(default_factory=dict)
```

`options` is `dict[str, Any]` rather than `dict[str, object]` deliberately: adapters
unpack values out of it (`*request.options.get("extra_args", [])`), and `object`
would make that a type error under the strict mypy settings from Task 1.

Update the imports at the top of the same file to:

```python
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
```

- [ ] **Step 4: Rewire `services/scanners/base.py`**

Replace the whole file with this. The local `Authorization` dataclass and the `ScanRequest` dataclass are deleted; both now come from the schema. `AuthorizationError` stays here because it is a scanner-layer concern.

```python
"""
Scanner adapter interface.

Every scanner integration implements ScannerAdapter. The contract:

  1. Adapters NEVER scan without an authorization record. Enforced here, not by callers.
  2. Adapters invoke tools as subprocesses or containers and parse their output.
     We do not vendor or link scanner source code.
  3. Adapters emit Observation objects from packages.schema. Raw tool output is
     preserved as a RawArtifact for provenance.
  4. Adapters do not enrich. Severity, EPSS and scoring belong to services.enrichment.

Adapters must be constructible with no arguments — tests/architecture discovers
every subclass by reflection and instantiates it to prove the authorization gate
holds.

See docs/01-open-source-policy.md before adding an adapter for a new tool.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from packages.schema.models.engagement import Authorization, ScanRequest
from packages.schema.models.observation import Observation

__all__ = [
    "Authorization",
    "AuthorizationError",
    "Observation",
    "ScanRequest",
    "ScannerAdapter",
]


class AuthorizationError(Exception):
    """Raised when a scan is attempted without valid authorization."""


class ScannerAdapter(ABC):
    """Base for all scanner integrations."""

    name: str
    version_command: list[str]

    def scan(self, request: ScanRequest) -> list[Observation]:
        """Entry point. Do not override — override _execute and _parse."""
        if not request.authorization.permits(request.target):
            raise AuthorizationError(
                f"No valid authorization for {request.target!r}. "
                f"Scans require an authorization record covering the target."
            )
        raw = self._execute(request)
        return self._parse(raw, request)

    @abstractmethod
    def _execute(self, request: ScanRequest) -> str:
        """Invoke the tool. Return its raw output."""

    @abstractmethod
    def _parse(self, raw: str, request: ScanRequest) -> list[Observation]:
        """Convert raw output into Observation objects. Preserve the raw artifact."""

    @abstractmethod
    def is_available(self) -> bool:
        """Is the tool installed and runnable?"""
```

The bare `-> list` returns are now `-> list[Observation]`. Under the strict mypy
settings from Task 1 an unparameterised generic is an error, so leaving them bare
would fail CI in Task 12.

- [ ] **Step 5: Annotate the nmap adapter to match**

`services/scanners/nmap_adapter.py` currently imports `from .base import ScannerAdapter, ScanRequest`, which still resolves because `base` re-exports `ScanRequest`. But its `_parse` signature has the same bare `list` return. Change the import line to:

```python
from .base import Observation, ScannerAdapter, ScanRequest
```

and change the `_parse` signature from `def _parse(self, raw: str, request: ScanRequest) -> list:` to:

```python
    def _parse(self, raw: str, request: ScanRequest) -> list[Observation]:
```

Leave the `raise NotImplementedError` body as it is — parsing nmap XML into schema
objects is September's Layer 1 work, not Phase 0.

- [ ] **Step 6: Run the tests to verify they pass**

```bash
pytest tests/unit -v
```

Expected: all pass, including the earlier tasks' tests.

- [ ] **Step 7: Commit**

```bash
git add packages/schema/models/engagement.py services/scanners/base.py tests/unit/test_engagement.py
git commit -m "feat: add Engagement model and move Authorization into packages/schema"
```

---

### Task 5: Observation and RawArtifact

**Files:**
- Create: `packages/schema/models/observation.py`
- Test: `tests/unit/test_observation.py`

**Interfaces:**
- Consumes: `Provenance`, `Source`, `Confidence` from Task 2.
- Produces: `RawArtifact(artifact_id, scanner, content, content_type, captured_at)`, `ObservationKind` enum, `Observation(observation_id, engagement_id, scanner, kind, subject, attributes, artifact_id, observed_at, provenance)`. Task 6's `Finding` references observations by id.

These are the keystone of the architecture: immutable, append-only facts from which everything downstream is derived. `frozen=True` makes immutability structural rather than a convention.

- [ ] **Step 1: Write the failing test**

`tests/unit/test_observation.py`:

```python
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from packages.schema.models.observation import Observation, ObservationKind, RawArtifact
from packages.schema.models.provenance import Confidence, Provenance, Source

NOW = datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc)


def _observation() -> Observation:
    return Observation(
        observation_id="obs-001",
        engagement_id="eng-001",
        scanner="nmap",
        kind=ObservationKind.SERVICE_VERSION,
        subject="172.20.1.10:80",
        attributes={"product": "apache", "version": "2.4.49"},
        artifact_id="art-001",
        observed_at=NOW,
        provenance=Provenance(
            source=Source.SCANNER, confidence=Confidence.HIGH, retrieved_at=NOW
        ),
    )


def test_observation_is_immutable() -> None:
    obs = _observation()
    with pytest.raises(ValidationError):
        obs.subject = "172.20.1.11:80"


def test_observation_carries_provenance_and_artifact() -> None:
    obs = _observation()
    assert obs.provenance.source is Source.SCANNER
    assert obs.artifact_id == "art-001"


def test_observation_requires_provenance() -> None:
    with pytest.raises(ValidationError):
        Observation(
            observation_id="obs-002",
            engagement_id="eng-001",
            scanner="nmap",
            kind=ObservationKind.PORT_OPEN,
            subject="172.20.1.10:22",
            attributes={},
            artifact_id="art-001",
            observed_at=NOW,
        )


def test_observation_rejects_naive_datetime() -> None:
    with pytest.raises(ValidationError, match="timezone-aware"):
        Observation(
            observation_id="obs-003",
            engagement_id="eng-001",
            scanner="nmap",
            kind=ObservationKind.HOST_UP,
            subject="172.20.1.10",
            attributes={},
            artifact_id="art-001",
            observed_at=datetime(2026, 9, 5, 12, 0),
            provenance=Provenance(
                source=Source.SCANNER, confidence=Confidence.HIGH, retrieved_at=NOW
            ),
        )


def test_raw_artifact_preserves_content_verbatim() -> None:
    xml = '<?xml version="1.0"?><nmaprun scanner="nmap"/>'
    art = RawArtifact(
        artifact_id="art-001",
        scanner="nmap",
        content=xml,
        content_type="application/xml",
        captured_at=NOW,
    )
    assert art.content == xml


def test_raw_artifact_is_immutable() -> None:
    art = RawArtifact(
        artifact_id="art-001",
        scanner="nmap",
        content="x",
        content_type="application/xml",
        captured_at=NOW,
    )
    with pytest.raises(ValidationError):
        art.content = "tampered"
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
pytest tests/unit/test_observation.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'packages.schema.models.observation'`

- [ ] **Step 3: Write the implementation**

`packages/schema/models/observation.py`:

```python
"""Immutable scan facts.

Observations are append-only and never mutated. Everything downstream — findings,
enrichment, the graph, paths, scores — is a view derived from them, which is what
makes the pipeline reproducible and every derived value traceable.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator

from packages.schema.models.provenance import Provenance


def _require_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError("datetime must be timezone-aware")
    return value


class RawArtifact(BaseModel):
    """Verbatim tool output, stored once and referenced by observations."""

    model_config = ConfigDict(frozen=True)

    artifact_id: str
    scanner: str
    content: str
    content_type: str
    captured_at: datetime

    @field_validator("captured_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        return _require_aware(value)


class ObservationKind(str, Enum):
    HOST_UP = "host_up"
    PORT_OPEN = "port_open"
    SERVICE_VERSION = "service_version"
    VULN_CANDIDATE = "vuln_candidate"
    REACHABILITY = "reachability"


class Observation(BaseModel):
    """One fact a scanner reported, at a point in time. Immutable."""

    model_config = ConfigDict(frozen=True)

    observation_id: str
    engagement_id: str
    scanner: str
    kind: ObservationKind
    subject: str
    attributes: dict[str, str] = Field(default_factory=dict)
    artifact_id: str
    observed_at: datetime
    provenance: Provenance

    @field_validator("observed_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        return _require_aware(value)
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
pytest tests/unit/test_observation.py -v
```

Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/schema/models/observation.py tests/unit/test_observation.py
git commit -m "feat: add immutable Observation and RawArtifact models"
```

---

### Task 6: Asset, Service, Finding, EnrichedFinding

**Files:**
- Create: `packages/schema/models/asset.py`
- Create: `packages/schema/models/finding.py`
- Test: `tests/unit/test_finding.py`

**Interfaces:**
- Consumes: `Attributed`, `Provenance` from Task 2.
- Produces: `Service(port, protocol, name, product, version, cpe)`, `Asset(asset_id, engagement_id, hostname, ip, services, aliases)`, `EnrichmentValue` type alias, `Finding(finding_id, engagement_id, asset_id, scanner, cve_ids, title, description, observation_ids, detected_at)`, `EnrichedFinding(finding, fields, ers)`. Task 7 supplies the `ers` type.

Two deliberate changes from the current `models.py`: `Asset.services` becomes `list[Service]` rather than untyped `list[dict]`, and `Finding.raw: str` becomes `observation_ids: list[str]` so a finding traces to the immutable facts that produced it rather than carrying a copy of them.

- [ ] **Step 1: Write the failing test**

`tests/unit/test_finding.py`:

```python
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from packages.schema.models.asset import Asset, Service
from packages.schema.models.finding import EnrichedFinding, Finding
from packages.schema.models.provenance import Attributed, Confidence, Provenance, Source

NOW = datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc)


def _prov(source: Source = Source.CVE_ORG) -> Provenance:
    return Provenance(source=source, confidence=Confidence.HIGH, retrieved_at=NOW)


def _finding() -> Finding:
    return Finding(
        finding_id="fnd-001",
        engagement_id="eng-001",
        asset_id="ast-001",
        scanner="nmap",
        cve_ids=["CVE-2021-41773"],
        title="Apache path traversal",
        description="Apache 2.4.49 path traversal",
        observation_ids=["obs-001"],
        detected_at=NOW,
    )


def test_service_is_typed_not_a_dict() -> None:
    svc = Service(port=80, name="http", product="apache", version="2.4.49")
    assert svc.protocol == "tcp"
    assert svc.port == 80


def test_service_rejects_out_of_range_port() -> None:
    with pytest.raises(ValidationError):
        Service(port=70000)


def test_asset_holds_typed_services() -> None:
    asset = Asset(
        asset_id="ast-001",
        engagement_id="eng-001",
        ip="172.20.1.10",
        services=[Service(port=80, name="http")],
    )
    assert asset.services[0].port == 80
    assert asset.aliases == []


def test_finding_traces_to_observations() -> None:
    assert _finding().observation_ids == ["obs-001"]


def test_finding_requires_at_least_one_observation() -> None:
    with pytest.raises(ValidationError, match="observation"):
        Finding(
            finding_id="fnd-002",
            engagement_id="eng-001",
            asset_id="ast-001",
            scanner="nmap",
            observation_ids=[],
            detected_at=NOW,
        )


def test_enriched_field_carries_value_and_provenance_together() -> None:
    enriched = EnrichedFinding(
        finding=_finding(),
        fields={
            "cvss_base": Attributed[float](value=7.5, provenance=_prov()),
            "kev_listed": Attributed[bool](value=True, provenance=_prov(Source.KEV)),
        },
    )
    assert enriched.fields["cvss_base"].value == 7.5
    assert enriched.fields["kev_listed"].provenance.source is Source.KEV


def test_enriched_finding_has_no_score_until_one_is_computed() -> None:
    enriched = EnrichedFinding(finding=_finding(), fields={})
    assert enriched.ers is None
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
pytest tests/unit/test_finding.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'packages.schema.models.asset'`

- [ ] **Step 3: Write `packages/schema/models/asset.py`**

```python
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
```

- [ ] **Step 4: Write `packages/schema/models/finding.py`**

```python
"""Findings, before and after enrichment.

`Finding` is what a scanner reported. `EnrichedFinding` is what multi-source
fusion made of it — and every fused field carries its own provenance, because
`Attributed` cannot be constructed without one.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field, field_validator

from packages.schema.models.provenance import Attributed

if TYPE_CHECKING:
    from packages.schema.models.scoring import ExposureRiskScore

# What an enrichment source can supply for a single field.
EnrichmentValue = str | float | int | bool | list[str] | None


def _require_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError("datetime must be timezone-aware")
    return value


class Finding(BaseModel):
    """One vulnerability on one asset, as reported by one scanner."""

    finding_id: str
    engagement_id: str
    asset_id: str
    scanner: str
    cve_ids: list[str] = Field(default_factory=list)
    title: str = ""
    description: str = ""
    observation_ids: list[str]
    detected_at: datetime

    @field_validator("observation_ids")
    @classmethod
    def _must_trace_to_observations(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("a finding must reference at least one observation")
        return value

    @field_validator("detected_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        return _require_aware(value)


class EnrichedFinding(BaseModel):
    """A finding plus fused, attributed intelligence about it."""

    finding: Finding
    fields: dict[str, Attributed[EnrichmentValue]] = Field(default_factory=dict)
    ers: ExposureRiskScore | None = None
```

- [ ] **Step 5: Run the test to verify it passes**

```bash
pytest tests/unit/test_finding.py -v
```

Expected: 7 passed. If Pydantic raises `PydanticUndefinedAnnotation` for `ExposureRiskScore`, that is expected until Task 7 — the final step of Task 7 rebuilds the model.

- [ ] **Step 6: Commit**

```bash
git add packages/schema/models/asset.py packages/schema/models/finding.py tests/unit/test_finding.py
git commit -m "feat: add typed Asset, Service, Finding and EnrichedFinding models"
```

---

### Task 7: Exposure Risk Score

**Files:**
- Create: `packages/schema/models/scoring.py`
- Modify: `packages/schema/models/finding.py` (rebuild the forward reference)
- Test: `tests/unit/test_scoring.py`

**Interfaces:**
- Consumes: `Provenance` from Task 2, `EnrichedFinding` from Task 6.
- Produces: `ScoreComponent(name, value, weight, explanation, provenance)` and `ExposureRiskScore(value, components)` with `.explain() -> str`.

**The design constraint made structural:** `ExposureRiskScore` validates that `value` equals the weighted sum of its components. A score that cannot explain itself cannot be constructed. This also enforces D-008's additive combination — there is no way to express a multiplied EPSS × CVSS score through this type.

- [ ] **Step 1: Write the failing test**

`tests/unit/test_scoring.py`:

```python
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from packages.schema.models.provenance import Confidence, Provenance, Source
from packages.schema.models.scoring import ExposureRiskScore, ScoreComponent

NOW = datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc)


def _component(name: str, value: float, weight: float, source: Source) -> ScoreComponent:
    return ScoreComponent(
        name=name,
        value=value,
        weight=weight,
        explanation=f"{name} contributed {value}",
        provenance=Provenance(source=source, confidence=Confidence.HIGH, retrieved_at=NOW),
    )


def _components() -> list[ScoreComponent]:
    return [
        _component("epss", 0.8, 0.5, Source.EPSS),
        _component("kev_listed", 1.0, 0.3, Source.KEV),
    ]


def test_score_equals_the_weighted_sum_of_its_components() -> None:
    score = ExposureRiskScore(value=0.7, components=_components())
    assert score.value == pytest.approx(0.7)


def test_score_inconsistent_with_its_components_is_rejected() -> None:
    with pytest.raises(ValidationError, match="weighted sum"):
        ExposureRiskScore(value=0.99, components=_components())


def test_score_must_have_components() -> None:
    with pytest.raises(ValidationError, match="component"):
        ExposureRiskScore(value=0.0, components=[])


def test_explain_names_every_component_with_its_source() -> None:
    text = ExposureRiskScore(value=0.7, components=_components()).explain()
    assert "epss" in text
    assert "kev_listed" in text
    assert "first.epss" in text
    assert "cisa.kev" in text
    assert "0.70" in text


def test_component_requires_an_explanation() -> None:
    with pytest.raises(ValidationError, match="explanation"):
        ScoreComponent(
            name="epss",
            value=0.8,
            weight=0.5,
            explanation="   ",
            provenance=Provenance(
                source=Source.EPSS, confidence=Confidence.HIGH, retrieved_at=NOW
            ),
        )


def test_enriched_finding_accepts_a_score() -> None:
    from packages.schema.models.finding import EnrichedFinding, Finding

    finding = Finding(
        finding_id="fnd-001",
        engagement_id="eng-001",
        asset_id="ast-001",
        scanner="nmap",
        observation_ids=["obs-001"],
        detected_at=NOW,
    )
    enriched = EnrichedFinding(
        finding=finding,
        fields={},
        ers=ExposureRiskScore(value=0.7, components=_components()),
    )
    assert enriched.ers is not None
    assert "epss" in enriched.ers.explain()
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
pytest tests/unit/test_scoring.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'packages.schema.models.scoring'`

- [ ] **Step 3: Write the implementation**

`packages/schema/models/scoring.py`:

```python
"""Exposure Risk Score.

Every score renders its own explanation. The model validates that `value` is the
weighted sum of its components, so a number that cannot account for itself cannot
be constructed.

Components combine ADDITIVELY (D-008). Never multiply EPSS by CVSS: the product
is not probability times severity, and FIRST is explicit that it means nothing.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from packages.schema.models.provenance import Provenance

_TOLERANCE = 1e-6


class ScoreComponent(BaseModel):
    """One input to the Exposure Risk Score, with its reasoning."""

    model_config = ConfigDict(frozen=True)

    name: str
    value: float
    weight: float
    explanation: str
    provenance: Provenance

    @field_validator("explanation")
    @classmethod
    def _explanation_is_present(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("every component needs an explanation; no opaque numbers")
        return value


class ExposureRiskScore(BaseModel):
    """Composite risk. Always able to explain itself."""

    model_config = ConfigDict(frozen=True)

    value: float
    components: list[ScoreComponent]

    @model_validator(mode="after")
    def _value_accounts_for_its_components(self) -> ExposureRiskScore:
        if not self.components:
            raise ValueError("a score needs at least one component to explain it")
        expected = sum(c.value * c.weight for c in self.components)
        if abs(self.value - expected) > _TOLERANCE:
            raise ValueError(
                f"value {self.value} is not the weighted sum of its components "
                f"({expected}); a score must account for itself"
            )
        return self

    def explain(self) -> str:
        lines = [f"Exposure Risk Score: {self.value:.2f}", ""]
        for c in self.components:
            lines.append(
                f"  {c.name}: {c.value:.2f} (weight {c.weight:.2f}) — {c.explanation}"
                f"  [{c.provenance.source.value}, {c.provenance.confidence.value}]"
            )
        return "\n".join(lines)
```

- [ ] **Step 4: Resolve the forward reference in `finding.py`**

Append to the end of `packages/schema/models/finding.py`:

```python
from packages.schema.models.scoring import ExposureRiskScore  # noqa: E402

EnrichedFinding.model_rebuild()
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
pytest tests/unit -v
```

Expected: all pass, including Task 6's tests.

- [ ] **Step 6: Commit**

```bash
git add packages/schema/models/scoring.py packages/schema/models/finding.py tests/unit/test_scoring.py
git commit -m "feat: add self-explaining ExposureRiskScore with additive components"
```

---

### Task 8: Graph types, and retiring the old models module

**Files:**
- Create: `packages/schema/models/graph.py`
- Create: `packages/schema/models/citation.py`
- Modify: `packages/schema/__init__.py`
- Delete: `packages/schema/models.py`
- Modify: `packages/schema/README.md`
- Test: `tests/unit/test_graph_models.py`

**Interfaces:**
- Consumes: nothing from earlier tasks except Pydantic.
- Produces: `Rule(name, description, preconditions, effect, citation)`, `PathEdge(from_node, to_node, rule_name, evidence, description)`, `AttackPath(path_id, edges, score, narration)`, `Chokepoint(finding_id, paths_broken, remediation, rank)`, `Citation(kind, ref_id, excerpt)`. `packages.schema` re-exports every model.

**The project's core rule made structural:** `PathEdge` rejects an empty `evidence` list and a blank `rule_name`. An edge without traceable provenance cannot be constructed, so "every edge traces to a scan fact and a named rule" stops being a convention.

`packages/schema/models.py` and `packages/schema/models/` cannot coexist — Python resolves the package over the module, and the old file would become dead but confusing. It is deleted here, once everything in it has a replacement.

- [ ] **Step 1: Write the failing test**

`tests/unit/test_graph_models.py`:

```python
import pytest
from pydantic import ValidationError

from packages.schema.models.citation import Citation
from packages.schema.models.graph import AttackPath, Chokepoint, PathEdge, Rule


def _edge() -> PathEdge:
    return PathEdge(
        from_node="internet",
        to_node="ast-001",
        rule_name="remote_code_execution_on_exposed_service",
        evidence=["fnd-001", "obs-001"],
        description="Apache 2.4.49 path traversal reachable from outside",
    )


def test_edge_requires_evidence() -> None:
    with pytest.raises(ValidationError, match="evidence"):
        PathEdge(
            from_node="internet",
            to_node="ast-001",
            rule_name="some_rule",
            evidence=[],
        )


def test_edge_requires_a_named_rule() -> None:
    with pytest.raises(ValidationError, match="rule_name"):
        PathEdge(
            from_node="internet",
            to_node="ast-001",
            rule_name="   ",
            evidence=["fnd-001"],
        )


def test_edge_is_immutable() -> None:
    with pytest.raises(ValidationError):
        _edge().rule_name = "something_else"


def test_attack_path_has_no_narration_by_default() -> None:
    path = AttackPath(path_id="path-1", edges=[_edge()])
    assert path.narration is None


def test_attack_path_requires_at_least_one_edge() -> None:
    with pytest.raises(ValidationError, match="edge"):
        AttackPath(path_id="path-1", edges=[])


def test_rule_is_data_and_can_cite_itself() -> None:
    rule = Rule(
        name="remote_code_execution_on_exposed_service",
        description="An exposed service with a known RCE grants code execution",
        preconditions=[{"kind": "service_version"}, {"kind": "vuln_candidate"}],
        effect="code_execution",
        citation="CAPEC-233",
    )
    assert rule.citation == "CAPEC-233"


def test_chokepoint_names_the_paths_it_breaks() -> None:
    cp = Chokepoint(
        finding_id="fnd-001",
        paths_broken=["path-1", "path-2"],
        remediation="Upgrade Apache to 2.4.51",
        rank=1,
    )
    assert len(cp.paths_broken) == 2


def test_citation_points_at_a_real_kind() -> None:
    c = Citation(kind="observation", ref_id="obs-001", excerpt="apache 2.4.49")
    assert c.kind == "observation"
    with pytest.raises(ValidationError):
        Citation(kind="vibes", ref_id="obs-001")


def test_schema_package_reexports_every_model() -> None:
    import packages.schema as schema

    for name in (
        "Asset",
        "AttackPath",
        "Attributed",
        "Authorization",
        "Chokepoint",
        "Citation",
        "Confidence",
        "Engagement",
        "EnrichedFinding",
        "ExposureRiskScore",
        "Finding",
        "Observation",
        "PathEdge",
        "Provenance",
        "RawArtifact",
        "Rule",
        "ScoreComponent",
        "Service",
        "Source",
    ):
        assert hasattr(schema, name), f"packages.schema does not export {name}"
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
pytest tests/unit/test_graph_models.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'packages.schema.models.graph'`

- [ ] **Step 3: Write `packages/schema/models/graph.py`**

```python
"""Rules, paths, and chokepoints.

CRITICAL: every edge carries the named rule that produced it and the evidence
supporting it. Both are validated here, so an edge without provenance cannot be
constructed. Edges are created by the deterministic rules engine only. The
language model never creates edges — it narrates paths that already exist.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Rule(BaseModel):
    """One named inference rule. Rules are data so they can be cited and extended."""

    model_config = ConfigDict(frozen=True)

    name: str
    description: str
    preconditions: list[dict[str, str]]
    effect: str
    citation: str | None = None


class PathEdge(BaseModel):
    """One step in an attack path, with the rule and evidence that produced it."""

    model_config = ConfigDict(frozen=True)

    from_node: str
    to_node: str
    rule_name: str
    evidence: list[str]
    description: str = ""

    @field_validator("rule_name")
    @classmethod
    def _rule_is_named(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("rule_name must name the rule that produced this edge")
        return value

    @field_validator("evidence")
    @classmethod
    def _evidence_is_present(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("evidence must cite at least one observation or finding")
        return value


class AttackPath(BaseModel):
    """A proven chain of steps. Narration is attached strictly downstream."""

    path_id: str
    edges: list[PathEdge]
    score: float = 0.0
    # Generated by the model from the proven path above. Never the reverse.
    narration: str | None = None

    @field_validator("edges")
    @classmethod
    def _has_edges(cls, value: list[PathEdge]) -> list[PathEdge]:
        if not value:
            raise ValueError("an attack path needs at least one edge")
        return value


class Chokepoint(BaseModel):
    """One fix that breaks many paths. Ranked by how many."""

    finding_id: str
    paths_broken: list[str] = Field(default_factory=list)
    remediation: str
    rank: int
```

- [ ] **Step 4: Write `packages/schema/models/citation.py`**

```python
"""Citations for assistant answers.

Every answer points at the observations, findings or paths it drew on.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

CitationKind = Literal["observation", "finding", "path", "source"]


class Citation(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: CitationKind
    ref_id: str
    excerpt: str | None = None
```

- [ ] **Step 5: Re-export everything from `packages/schema/__init__.py`**

```python
"""Shared data models. Everything crosses this boundary.

Two invariants:
  1. Every enriched field carries where it came from and how confident we are.
     No unattributed data anywhere in the system.
  2. Every score renders its own explanation. No opaque numbers.
"""

from packages.schema.models.asset import Asset, Service
from packages.schema.models.citation import Citation, CitationKind
from packages.schema.models.engagement import (
    Authorization,
    Engagement,
    ScanRequest,
    target_matches,
)
from packages.schema.models.finding import EnrichedFinding, EnrichmentValue, Finding
from packages.schema.models.graph import AttackPath, Chokepoint, PathEdge, Rule
from packages.schema.models.observation import Observation, ObservationKind, RawArtifact
from packages.schema.models.provenance import (
    Attributed,
    Confidence,
    Provenance,
    Source,
)
from packages.schema.models.scoring import ExposureRiskScore, ScoreComponent

__all__ = [
    "Asset",
    "AttackPath",
    "Attributed",
    "Authorization",
    "Chokepoint",
    "Citation",
    "CitationKind",
    "Confidence",
    "Engagement",
    "EnrichedFinding",
    "EnrichmentValue",
    "ExposureRiskScore",
    "Finding",
    "Observation",
    "ObservationKind",
    "PathEdge",
    "Provenance",
    "RawArtifact",
    "Rule",
    "ScanRequest",
    "ScoreComponent",
    "Service",
    "Source",
    "target_matches",
]
```

- [ ] **Step 6: Delete the superseded module**

```bash
git rm packages/schema/models.py
```

- [ ] **Step 7: Update the schema README**

In `packages/schema/README.md`, replace the "Invariants" section with:

```markdown
## Invariants

These are enforced by the models themselves, not by convention.

1. **Every enriched field carries `Provenance`.** `Attributed[T]` pairs a value with
   its provenance, so an unattributed value cannot be constructed.
2. **Every score explains itself.** `ExposureRiskScore` validates that its value is
   the weighted sum of its components, and every component needs an explanation.
   Components combine additively — never multiply EPSS by CVSS.
3. **Every `PathEdge` carries `rule_name` and non-empty `evidence`.** An edge without
   provenance is rejected at construction.
4. **Observations are immutable.** `Observation` and `RawArtifact` are frozen. Everything
   downstream is a derived view.
5. **All datetimes are timezone-aware.** Naive datetimes are rejected.

Breaking any of these breaks the project's core claim.

## Layout

Models are split by concern under `models/`: `provenance`, `engagement`, `observation`,
`asset`, `finding`, `scoring`, `graph`, `citation`. Import from `packages.schema` directly.
```

- [ ] **Step 8: Run the full suite**

```bash
pytest tests -v
ruff check .
```

Expected: all tests pass, ruff clean.

- [ ] **Step 9: Commit**

```bash
git add packages/schema tests/unit/test_graph_models.py
git add -u
git commit -m "feat: add graph and citation models, retire the dataclass models module

PathEdge rejects empty evidence and a blank rule_name, so an edge without
traceable provenance cannot be constructed."
```

---

### Task 9: Architecture test — the authorization gate

**Files:**
- Create: `tests/architecture/test_authorization_gate.py`

**Interfaces:**
- Consumes: `ScannerAdapter`, `AuthorizationError`, `ScanRequest` from Task 4; `Authorization` from Task 3.
- Produces: nothing importable. This is a guard.

Two properties, both parametrized over every `ScannerAdapter` subclass found by reflection, so a new adapter is covered the moment it exists. The second is the one that matters: it proves the gate runs *before* the tool is invoked, not beside it.

**Guarding against a false green:** an empty `parametrize` list produces zero tests and a green run. A separate test asserts that discovery actually found adapters.

- [ ] **Step 1: Write the test**

`tests/architecture/test_authorization_gate.py`:

```python
"""No scan runs without authorization, and the gate precedes tool invocation.

Parametrized over every ScannerAdapter subclass, so a new adapter is covered
without anyone remembering to add a test. Adapters must therefore be
constructible with no arguments — see services/scanners/base.py.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from datetime import datetime, timedelta, timezone

import pytest

import services.scanners as scanners_pkg
from packages.schema import Authorization, ScanRequest
from services.scanners.base import AuthorizationError, ScannerAdapter

NOW = datetime.now(timezone.utc)
UNAUTHORIZED_TARGET = "203.0.113.10"  # TEST-NET-3, never in an allowlist


def _all_subclasses(cls: type) -> set[type]:
    found = set(cls.__subclasses__())
    for sub in list(found):
        found |= _all_subclasses(sub)
    return found


def _concrete_adapters() -> list[type[ScannerAdapter]]:
    for module in pkgutil.walk_packages(
        scanners_pkg.__path__, scanners_pkg.__name__ + "."
    ):
        importlib.import_module(module.name)
    return sorted(
        (c for c in _all_subclasses(ScannerAdapter) if not inspect.isabstract(c)),
        key=lambda c: c.__name__,
    )


ADAPTERS = _concrete_adapters()


def _authorization() -> Authorization:
    return Authorization(
        engagement_id="eng-001",
        authorized_by="A. Named Human",
        allowlist=["172.20.0.0/16"],
        granted_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )


def test_adapter_discovery_found_something() -> None:
    """Without this, an empty parametrize list would pass silently."""
    assert ADAPTERS, "no ScannerAdapter subclasses discovered — the gate tests are vacuous"


@pytest.mark.parametrize("adapter_cls", ADAPTERS, ids=lambda c: c.__name__)
def test_adapter_rejects_unauthorized_target(adapter_cls: type[ScannerAdapter]) -> None:
    adapter = adapter_cls()
    request = ScanRequest(target=UNAUTHORIZED_TARGET, authorization=_authorization())
    with pytest.raises(AuthorizationError):
        adapter.scan(request)


@pytest.mark.parametrize("adapter_cls", ADAPTERS, ids=lambda c: c.__name__)
def test_gate_precedes_tool_invocation(
    adapter_cls: type[ScannerAdapter], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The tool must never run for an unauthorized target."""
    invocations: list[ScanRequest] = []

    def spy(self: ScannerAdapter, request: ScanRequest) -> str:
        invocations.append(request)
        return ""

    monkeypatch.setattr(adapter_cls, "_execute", spy, raising=True)

    adapter = adapter_cls()
    request = ScanRequest(target=UNAUTHORIZED_TARGET, authorization=_authorization())
    with pytest.raises(AuthorizationError):
        adapter.scan(request)

    assert invocations == [], f"{adapter_cls.__name__} invoked its tool before authorizing"


@pytest.mark.parametrize("adapter_cls", ADAPTERS, ids=lambda c: c.__name__)
def test_expired_authorization_blocks_an_allowlisted_target(
    adapter_cls: type[ScannerAdapter], monkeypatch: pytest.MonkeyPatch
) -> None:
    invocations: list[ScanRequest] = []

    def spy(self: ScannerAdapter, request: ScanRequest) -> str:
        invocations.append(request)
        return ""

    monkeypatch.setattr(adapter_cls, "_execute", spy, raising=True)

    expired = Authorization(
        engagement_id="eng-001",
        authorized_by="A. Named Human",
        allowlist=["172.20.0.0/16"],
        granted_at=NOW - timedelta(hours=2),
        expires_at=NOW - timedelta(hours=1),
    )
    adapter = adapter_cls()
    with pytest.raises(AuthorizationError):
        adapter.scan(ScanRequest(target="172.20.1.10", authorization=expired))

    assert invocations == []
```

- [ ] **Step 2: Run the test**

```bash
pytest tests/architecture/test_authorization_gate.py -v
```

Expected: PASS, with `NmapAdapter` appearing in the test ids. If `test_adapter_discovery_found_something` fails, the walk did not import `nmap_adapter` — check that `services/scanners/__init__.py` exists.

- [ ] **Step 3: Prove the test can fail**

Temporarily comment out the authorization check in `ScannerAdapter.scan` in `services/scanners/base.py`, then run:

```bash
pytest tests/architecture/test_authorization_gate.py -v
```

Expected: FAIL. **Restore the check immediately.** A guard that cannot fail is not a guard.

```bash
git diff services/scanners/base.py
```

Expected: empty output, confirming the check is restored.

- [ ] **Step 4: Commit**

```bash
git add tests/architecture/test_authorization_gate.py
git commit -m "test: enforce the authorization gate across every scanner adapter"
```

---

### Task 10: Architecture test — the LLM firewall

**Files:**
- Create: `services/assistant/__init__.py`
- Create: `services/assistant/README.md`
- Create: `tests/architecture/test_import_firewall.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `forbidden_imports_in(path: Path) -> list[str]`, importable by the test itself. `services/assistant` exists as an empty package.

The firewall is written *before* the assistant code, so the first line written under `services/assistant` is already constrained. `services/assistant` may import `packages.schema` and nothing else from this tree — it therefore cannot construct a graph edge, because it cannot reach the code that constructs edges.

**Guarding against a false green:** a broken checker that always returns `[]` would pass silently. A second test feeds it a known violation and asserts it is caught.

- [ ] **Step 1: Create the assistant package**

`services/assistant/__init__.py`:

```python
"""Retrieval, narration and citations.

This package may import `packages.schema` and NOTHING ELSE from this repository.
It receives AttackPath objects as data and returns text. It cannot construct a
graph edge because it cannot reach the code that constructs edges.

Enforced by tests/architecture/test_import_firewall.py.
"""
```

`services/assistant/README.md`:

```markdown
# services/assistant

Retrieval, narration, and citations. The only place a language model is called.

## The firewall

This package may import `packages.schema` and nothing else from this repository.
No `services.graph`, no `services.enrichment`, no `services.scanners`.

It receives proven `AttackPath` objects as data and returns text. It cannot create
an edge, because it cannot reach the code that creates edges. This is enforced by
`tests/architecture/test_import_firewall.py`, which fails CI on any violating import.

If you find yourself needing to import the graph builder here, the design is wrong.
The path should be passed in as an argument.

## Rules

1. The model narrates paths that already exist. It never infers them.
2. Every answer carries `Citation` objects pointing at observations, findings or paths.
3. When the data does not support an answer, say so. "I don't have that data" is a
   correct answer and the golden dataset grades for it.
```

- [ ] **Step 2: Write the test**

`tests/architecture/test_import_firewall.py`:

```python
"""The language model never creates graph edges.

services/assistant may import packages.schema and nothing else from this tree,
so it structurally cannot reach the code that constructs edges.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ASSISTANT = REPO_ROOT / "services" / "assistant"

FORBIDDEN_PREFIXES = (
    "services.graph",
    "services.enrichment",
    "services.scanners",
    "services.normalize",
    "apps.api",
)


def _absolute_module(node: ast.ImportFrom, module_path: Path) -> str:
    """Resolve a possibly-relative ImportFrom to a dotted module name."""
    if node.level == 0:
        return node.module or ""
    package_parts = module_path.relative_to(REPO_ROOT).parts[:-1]
    keep = len(package_parts) - (node.level - 1)
    base = list(package_parts[:keep]) if keep > 0 else []
    if node.module:
        base.append(node.module)
    return ".".join(base)


def forbidden_imports_in(path: Path) -> list[str]:
    """Return every forbidden module imported by the Python files under `path`."""
    violations: list[str] = []
    for py_file in sorted(path.rglob("*.py")):
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [_absolute_module(node, py_file)]
            else:
                continue
            for name in names:
                if any(
                    name == prefix or name.startswith(prefix + ".")
                    for prefix in FORBIDDEN_PREFIXES
                ):
                    rel = py_file.relative_to(REPO_ROOT)
                    violations.append(f"{rel}: imports {name}")
    return violations


def test_assistant_package_exists() -> None:
    """Without this, the firewall test would pass over an empty tree."""
    assert ASSISTANT.is_dir(), "services/assistant is missing; the firewall test is vacuous"
    assert (ASSISTANT / "__init__.py").exists()


def test_assistant_imports_nothing_it_should_not() -> None:
    violations = forbidden_imports_in(ASSISTANT)
    assert violations == [], (
        "services/assistant must not import graph, enrichment or scanner code — "
        "the model narrates proven paths, it never builds them.\n" + "\n".join(violations)
    )


def test_checker_detects_a_planted_violation(tmp_path: Path) -> None:
    """A checker that always returns [] would pass silently. Prove it bites."""
    offender = tmp_path / "bad.py"
    offender.write_text(
        "from services.graph.builder import build_graph\n"
        "import services.enrichment\n",
        encoding="utf-8",
    )
    violations = forbidden_imports_in(tmp_path)
    assert len(violations) == 2
    assert any("services.graph.builder" in v for v in violations)
    assert any("services.enrichment" in v for v in violations)


def test_checker_allows_the_schema(tmp_path: Path) -> None:
    good = tmp_path / "good.py"
    good.write_text(
        "from packages.schema import AttackPath, Citation\nimport packages.schema\n",
        encoding="utf-8",
    )
    assert forbidden_imports_in(tmp_path) == []
```

Note: `test_checker_detects_a_planted_violation` writes to `tmp_path`, which is outside `REPO_ROOT`, so `_absolute_module` is only exercised on absolute imports there. That is intentional — relative imports inside the real package are covered by the live scan.

- [ ] **Step 3: Run the test**

```bash
pytest tests/architecture/test_import_firewall.py -v
```

Expected: 4 passed.

- [ ] **Step 4: Prove the live check bites**

```bash
echo "from services.graph import builder" > services/assistant/_tmp_violation.py
pytest tests/architecture/test_import_firewall.py::test_assistant_imports_nothing_it_should_not -v
```

Expected: FAIL, naming `_tmp_violation.py`. Then remove it:

```bash
rm services/assistant/_tmp_violation.py
pytest tests/architecture/test_import_firewall.py -v
```

Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add services/assistant tests/architecture/test_import_firewall.py
git commit -m "test: enforce the LLM firewall before any assistant code is written

services/assistant may import packages.schema and nothing else, so it cannot
reach the code that constructs graph edges."
```

---

### Task 11: Docker Compose profiles

**Files:**
- Modify: `infra/docker-compose.yml`
- Modify: `.env.example`
- Modify: `HOW-THIS-REPO-WORKS.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: nothing.
- Produces: four compose profiles — `core`, `model`, `viz` in `infra/`, with `lab` remaining a separate file.

Nothing starts without a profile flag. On a 16 GB laptop this is the point: `docker compose up` with no flag must not launch a stack that will not fit. Neo4j gains explicit memory caps (D-003) and only runs under `viz`; it is not needed until the graph builder lands in November.

- [ ] **Step 1: Rewrite `infra/docker-compose.yml`**

```yaml
# SeekThreat development stack.
# Lab targets live in lab/docker-compose.yml — kept separate on purpose.
#
# NOTHING starts without a profile. On a 16 GB laptop the whole stack does not
# fit at once, so choosing what to run is deliberate. See docs/02-architecture.md.
#
#   docker compose -f infra/docker-compose.yml --profile core up -d
#   docker compose -f infra/docker-compose.yml --profile core --profile model up -d
#   docker compose -f infra/docker-compose.yml --profile viz up -d

services:
  postgres:
    profiles: ["core"]
    image: pgvector/pgvector:pg16
    environment:
      POSTGRES_USER: ${POSTGRES_USER:-seekthreat}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-changeme}
      POSTGRES_DB: ${POSTGRES_DB:-seekthreat}
    ports: ["5432:5432"]
    volumes: [pgdata:/var/lib/postgresql/data]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER:-seekthreat}"]
      interval: 10s
      retries: 5

  redis:
    profiles: ["core"]
    image: redis:7-alpine
    ports: ["6379:6379"]

  ollama:
    profiles: ["model"]
    image: ollama/ollama:latest
    ports: ["11434:11434"]
    volumes: [ollamadata:/root/.ollama]

  neo4j:
    # Read-only projection for visualization only (D-003). Not a source of truth.
    # Lands with the graph builder in November.
    profiles: ["viz"]
    image: neo4j:5-community
    environment:
      NEO4J_AUTH: neo4j/${NEO4J_PASSWORD:-changeme}
      NEO4J_server_memory_heap_initial__size: 512m
      NEO4J_server_memory_heap_max__size: 1G
      NEO4J_server_memory_pagecache__size: 512m
    ports: ["7474:7474", "7687:7687"]
    volumes: [neo4jdata:/data]

  # TODO: api and worker services join the core profile once apps/ is implemented.

volumes:
  pgdata:
  neo4jdata:
  ollamadata:
```

Two changes beyond profiles: the Postgres image becomes `pgvector/pgvector:pg16` because retrieval uses pgvector (D-005), and Neo4j gains memory caps so it cannot take a default page cache sized against total system RAM.

- [ ] **Step 2: Verify the compose file parses and respects profiles**

```bash
docker compose -f infra/docker-compose.yml config --services
```

Expected: an empty list or a warning — no services are active without a profile.

```bash
docker compose -f infra/docker-compose.yml --profile core config --services
```

Expected: `postgres` and `redis` only.

```bash
docker compose -f infra/docker-compose.yml --profile viz config --services
```

Expected: `neo4j` only.

- [ ] **Step 3: Update `.env.example`**

Replace the `# --- Model serving ---` block with this, dropping the stale `MODEL_NAME` default and noting the profile:

```
# --- Model serving (profile: model) ---
OLLAMA_HOST=http://localhost:11434
MODEL_NAME=foundation-sec-8b-reasoning
# Optional frontier fallback for comparison runs
ANTHROPIC_API_KEY=
```

And replace the `# --- Graph ---` block with:

```
# --- Graph projection (profile: viz, from November) ---
# Neo4j is a READ-ONLY projection for visualization. Never a source of truth.
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=changeme
```

- [ ] **Step 4: Update the getting-started commands in both READMEs**

In `README.md`, replace the `docker compose` lines in "Getting started" with:

```bash
cp .env.example .env
docker compose -f infra/docker-compose.yml --profile core up -d
docker compose -f lab/docker-compose.yml up -d        # the test network
```

In `HOW-THIS-REPO-WORKS.md`, replace the equivalent lines in "Getting started" with:

```bash
git clone <repo-url>
cd seekthreat
cp .env.example .env        # fill in your API keys
pip install -r requirements-dev.txt
docker compose -f infra/docker-compose.yml --profile core up -d
```

And add this paragraph immediately after that block:

```markdown
**Nothing starts without a profile.** The full stack does not fit in 16 GB, so you
choose what to run: `core` (Postgres, Redis), `model` (Ollama), `viz` (Neo4j, from
November). The lab is a separate file. See `docs/02-architecture.md`.
```

- [ ] **Step 5: Commit**

```bash
git add infra/docker-compose.yml .env.example README.md HOW-THIS-REPO-WORKS.md
git commit -m "chore: add compose profiles, cap neo4j memory, switch postgres to pgvector"
```

---

### Task 12: Continuous integration

**Files:**
- Create: `.github/workflows/ci.yml`
- Modify: `CONTRIBUTING.md`

**Interfaces:**
- Consumes: everything above.
- Produces: a CI job running ruff, mypy and pytest on every pull request.

The existing `third-party-check.yml` stays as it is. This adds a second workflow rather than modifying it, so the licence guard and the code guard fail independently and legibly.

- [ ] **Step 1: Write `.github/workflows/ci.yml`**

```yaml
name: ci

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
          cache: pip

      - name: Install dependencies
        run: pip install -r requirements-dev.txt

      - name: Lint
        run: ruff check .

      - name: Format check
        run: ruff format --check .

      - name: Types
        run: mypy packages services

      - name: Tests
        run: pytest tests -v

      - name: Architecture guards
        # Run these explicitly too, so a failure names the rule that broke.
        run: |
          echo "The LLM never creates graph edges; no scan without authorization."
          pytest tests/architecture -v
```

- [ ] **Step 2: Run every CI step locally before pushing**

```bash
ruff check .
ruff format --check .
mypy packages services
pytest tests -v
```

All four must pass. If `ruff format --check` fails, run `ruff format .` and review the diff before committing.

`mypy` runs `strict = true` (Task 1), so any remaining error will be a missing or imprecise annotation. Fix it with the real type — never with a blanket `# type: ignore`. The two known cases, bare `list` returns in `services/scanners/base.py` and `nmap_adapter.py`, are already annotated as `list[Observation]` in Task 4. If a third-party package has no stubs, add it to the `[[tool.mypy.overrides]]` block in `pyproject.toml` rather than silencing the call site.

- [ ] **Step 3: Add the CI expectations to `CONTRIBUTING.md`**

In the "Before you open a PR" checklist, replace the first three items with:

```markdown
- [ ] `ruff check .` and `ruff format --check .` pass
- [ ] `mypy packages services` passes
- [ ] `pytest tests` passes, including `tests/architecture`
- [ ] New logic in `services/graph` or `services/enrichment` has tests
```

And add this to "Things that will get a PR sent back":

```markdown
- Weakening or skipping a test in `tests/architecture/` instead of fixing the violation
```

- [ ] **Step 4: Commit and push the branch**

```bash
git add .github/workflows/ci.yml CONTRIBUTING.md
git commit -m "ci: run ruff, mypy and pytest on every pull request"
git push -u origin feat/phase-0-foundation
```

- [ ] **Step 5: Open the pull request**

```bash
gh pr create --title "Phase 0: foundation" --body "$(cat <<'EOF'
Implements the Phase 0 foundation from docs/02-architecture.md.

## What this does

- Project tooling: pyproject.toml, root requirements files, ruff, mypy, pytest
- packages/schema converted to Pydantic v2 and split by concern (D-009)
- **Fixes a live defect**: authorization allowlists used an exact string match, so a
  CIDR entry such as 172.20.0.0/16 rejected every host inside it
- Architecture tests enforcing the two hard rules mechanically
- Compose profiles, so nothing launches a stack that will not fit in 16 GB
- CI running ruff, mypy and pytest

## The invariants are now structural

- `Attributed[T]` — an unattributed value cannot be constructed
- `PathEdge` — an edge without `rule_name` and `evidence` cannot be constructed
- `ExposureRiskScore` — a score that is not the weighted sum of its explained
  components cannot be constructed
- `Observation` / `RawArtifact` — frozen; everything downstream is a derived view
- `tests/architecture/` — the LLM firewall and the authorization gate fail CI

## Decisions

D-003 through D-009 in DECISIONS.md.

## Not in this PR

Lab topology, ground_truth.yaml, and the eval harness — a separate plan, since they
depend on this schema landing first.
EOF
)"
```

- [ ] **Step 6: Confirm CI passes**

```bash
gh pr checks --watch
```

Expected: both `ci` and `third-party register check` green.

---

## What this plan deliberately does not cover

- **`docs/00-scope.md`** is still the placeholder stub. `docs/02-architecture.md` points at it. Writing it needs decisions about maturity targets that belong to the team, not to a plan.
- **The lab topology and `ground_truth.yaml`** — 8–12 hosts across three segments with real multi-hop chains. A separate plan; it depends on `Observation` existing.
- **The eval harness** — due in September per `evals/README.md`. A separate plan.
- **`tests/architecture/test_determinism.py`** — the purity guard from `docs/02-architecture.md` cannot be written before `build_graph` exists. It lands with the graph builder in November, and the architecture doc records it.
- **The API-layer authorization choke point** — `apps/api/core/authorization.py` lands with the `/scans` router in September's Layer 1 work. The adapter gate in `ScannerAdapter.scan` is enforced and tested here.
