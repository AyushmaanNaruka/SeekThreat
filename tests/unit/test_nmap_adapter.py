"""Unit and smoke tests for NmapAdapter."""

from __future__ import annotations

import subprocess
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from packages.schema.models.engagement import Authorization, ScanRequest
from services.scanners.nmap_adapter import DEFAULT_PORTS, NmapAdapter

NOW = datetime.now(UTC)


def _authorization(target: str = "127.0.0.1") -> Authorization:
    return Authorization(
        engagement_id="eng-nmap-unit-01",
        authorized_by="Security Engineer",
        allowlist=[target],
        granted_at=NOW - timedelta(minutes=5),
        expires_at=NOW + timedelta(hours=1),
    )


MINIMAL_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" start="1700000000" version="7.92">
<host><status state="up" reason="syn-ack"/><address addr="127.0.0.1" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="8000"><state state="open" reason="syn-ack"/><service name="http" method="table"/></port></ports>
</host>
<runstats><finished time="1700000010"/></runstats>
</nmaprun>
"""


def test_default_scan_uses_fast_default_ports() -> None:
    """Test 1: Default scan without explicit ports supplies fast default ports."""
    adapter = NmapAdapter()
    req = ScanRequest(target="127.0.0.1", authorization=_authorization(), options={})

    mock_res = MagicMock()
    mock_res.stdout = MINIMAL_XML

    with patch("subprocess.run", return_value=mock_res) as mock_run:
        adapter.scan(req)

        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "-sV" in cmd
        assert "-T4" in cmd
        assert "-p" in cmd
        p_index = cmd.index("-p")
        assert cmd[p_index + 1] == DEFAULT_PORTS
        assert cmd[-2:] == ["--", "127.0.0.1"]


def test_explicit_ports_are_preserved() -> None:
    """Test 2: Explicit ports option is preserved and not replaced by defaults."""
    adapter = NmapAdapter()
    req = ScanRequest(
        target="127.0.0.1",
        authorization=_authorization(),
        options={"ports": "8000,8080"},
    )

    mock_res = MagicMock()
    mock_res.stdout = MINIMAL_XML

    with patch("subprocess.run", return_value=mock_res) as mock_run:
        adapter.scan(req)

        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "-p" in cmd
        p_index = cmd.index("-p")
        assert cmd[p_index + 1] == "8000,8080"


def test_broad_explicit_scan_remains_possible() -> None:
    """Test 3: Broad explicit port scan like 1-1000 or -p- is passed through unmodified."""
    adapter = NmapAdapter()

    for broad_spec in ["1-1000", "-p-", "1-65535"]:
        req = ScanRequest(
            target="127.0.0.1",
            authorization=_authorization(),
            options={"ports": broad_spec},
        )

        mock_res = MagicMock()
        mock_res.stdout = MINIMAL_XML

        with patch("subprocess.run", return_value=mock_res) as mock_run:
            adapter.scan(req)

            mock_run.assert_called_once()
            cmd = mock_run.call_args[0][0]
            assert "-p" in cmd
            p_index = cmd.index("-p")
            assert cmd[p_index + 1] == broad_spec


def test_fast_option_uses_dash_f() -> None:
    """Test fast flag: options={'fast': True} uses -F instead of -p."""
    adapter = NmapAdapter()
    req = ScanRequest(
        target="127.0.0.1",
        authorization=_authorization(),
        options={"fast": True},
    )

    mock_res = MagicMock()
    mock_res.stdout = MINIMAL_XML

    with patch("subprocess.run", return_value=mock_res) as mock_run:
        adapter.scan(req)

        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "-F" in cmd
        assert "-p" not in cmd


def test_service_detection_toggle() -> None:
    """Test disabling service detection: options={'service_detection': False} omits -sV."""
    adapter = NmapAdapter()
    req = ScanRequest(
        target="127.0.0.1",
        authorization=_authorization(),
        options={"service_detection": False},
    )

    mock_res = MagicMock()
    mock_res.stdout = MINIMAL_XML

    with patch("subprocess.run", return_value=mock_res) as mock_run:
        adapter.scan(req)

        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "-sV" not in cmd
        assert "-T4" in cmd


def test_real_nmap_smoke_test_fast_ports() -> None:
    """Test 4: Real localhost smoke test against 127.0.0.1 executes quickly and parses output."""
    adapter = NmapAdapter()
    if not adapter.is_available():
        pytest.skip("Nmap binary is not installed in this environment.")

    req = ScanRequest(
        target="127.0.0.1",
        authorization=_authorization(),
        options={"ports": "80,443", "timeout": 30},
    )

    start_time = time.time()
    res = adapter.scan(req)
    duration = time.time() - start_time

    assert res.artifact.scanner == "nmap"
    assert res.artifact.content_type == "application/xml"
    assert res.artifact.content.startswith("<?xml") or "<nmaprun" in res.artifact.content
    assert duration < 20.0, f"Real Nmap smoke test took too long: {duration:.2f}s"
