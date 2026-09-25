"""Unit and command construction tests for NucleiAdapter."""

from __future__ import annotations

import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from packages.schema.models.engagement import Authorization, ScanRequest
from services.scanners.nuclei_adapter import NucleiAdapter

NOW = datetime.now(UTC)
FIXTURE_TEMPLATE = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "nuclei"
    / "test_http_detect.yaml"
)

MINIMAL_JSONL = (
    b'{"template-id":"test-http-detect"'
    b',"info":{"name":"Local HTTP Detection Test"'
    b',"author":["seekthreat"],"tags":[],"severity":"info"}'
    b',"type":"http","host":"http://127.0.0.1:8799"'
    b',"matched-at":"http://127.0.0.1:8799/"'
    b',"extracted-results":["200"]'
    b',"timestamp":"2026-09-22T10:00:00.000000Z"}\n'
)


def _authorization(target: str = "http://127.0.0.1:8799") -> Authorization:
    return Authorization(
        engagement_id="eng-nuclei-unit-01",
        authorized_by="Security Engineer",
        allowlist=["127.0.0.1", "127.0.0.1/32", "localhost", target],
        granted_at=NOW - timedelta(minutes=5),
        expires_at=NOW + timedelta(hours=1),
    )


def test_local_template_command_construction() -> None:
    """Test 1: Verify that a local template path produces the resolved path in the command."""
    adapter = NucleiAdapter()
    req = ScanRequest(
        target="http://127.0.0.1:8799",
        authorization=_authorization(),
        options={"template": str(FIXTURE_TEMPLATE)},
    )

    mock_res = MagicMock()
    mock_res.stdout = MINIMAL_JSONL

    with patch("subprocess.run", return_value=mock_res) as mock_run:
        adapter.scan(req)

        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "-u" in cmd
        assert cmd[cmd.index("-u") + 1] == "http://127.0.0.1:8799"
        assert "-jsonl" in cmd
        assert "-silent" in cmd
        assert "-duc" in cmd
        assert "-ni" in cmd
        assert "-no-stdin" in cmd
        assert "-t" in cmd
        assert cmd[cmd.index("-t") + 1] == str(FIXTURE_TEMPLATE.resolve())
        assert mock_run.call_args[1]["stdin"] == subprocess.DEVNULL


def test_nuclei_command_passes_no_stdin_and_closes_subprocess_stdin() -> None:
    """Regression test: -no-stdin flag and stdin=DEVNULL must both be set to prevent hangs."""
    import subprocess
    adapter = NucleiAdapter()
    req = ScanRequest(
        target="http://127.0.0.1:8799",
        authorization=_authorization(),
        options={"template": str(FIXTURE_TEMPLATE)},
    )

    mock_res = MagicMock()
    mock_res.stdout = MINIMAL_JSONL

    with patch("subprocess.run", return_value=mock_res) as mock_run:
        adapter.scan(req)

        mock_run.assert_called_once()
        cmd, kwargs = mock_run.call_args[0][0], mock_run.call_args[1]
        assert "-no-stdin" in cmd
        assert kwargs.get("stdin") == subprocess.DEVNULL


def test_relative_local_template_path_is_resolved() -> None:
    """Test 2: Relative local template path is resolved relative to repo root."""
    adapter = NucleiAdapter()
    req = ScanRequest(
        target="http://127.0.0.1:8799",
        authorization=_authorization(),
        options={"template": "tests/fixtures/nuclei/test_http_detect.yaml"},
    )

    mock_res = MagicMock()
    mock_res.stdout = MINIMAL_JSONL

    with patch("subprocess.run", return_value=mock_res) as mock_run:
        adapter.scan(req)

        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "-t" in cmd
        assert cmd[cmd.index("-t") + 1] == str(FIXTURE_TEMPLATE.resolve())


def test_templates_alias_option_is_supported() -> None:
    """Test 3: 'templates' option key is supported identically to 'template'."""
    adapter = NucleiAdapter()
    req = ScanRequest(
        target="http://127.0.0.1:8799",
        authorization=_authorization(),
        options={"templates": str(FIXTURE_TEMPLATE)},
    )

    mock_res = MagicMock()
    mock_res.stdout = MINIMAL_JSONL

    with patch("subprocess.run", return_value=mock_res) as mock_run:
        adapter.scan(req)

        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "-t" in cmd
        assert cmd[cmd.index("-t") + 1] == str(FIXTURE_TEMPLATE.resolve())


def test_tags_option_passes_tags_flag() -> None:
    """Test 4: tags option generates -tags flag."""
    adapter = NucleiAdapter()
    req = ScanRequest(
        target="http://127.0.0.1:8799",
        authorization=_authorization(),
        options={"tags": "cve,rce"},
    )

    mock_res = MagicMock()
    mock_res.stdout = MINIMAL_JSONL

    with patch("subprocess.run", return_value=mock_res) as mock_run:
        adapter.scan(req)

        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "-tags" in cmd
        assert cmd[cmd.index("-tags") + 1] == "cve,rce"


def test_missing_local_template_fails_cleanly() -> None:
    """Test 5: Missing template raises ValueError without hanging or network fetch."""
    adapter = NucleiAdapter()
    req = ScanRequest(
        target="http://127.0.0.1:8799",
        authorization=_authorization(),
        options={"template": "tests/fixtures/nuclei/nonexistent_template.yaml"},
    )

    with pytest.raises(ValueError, match="Nuclei template not found"):
        adapter.scan(req)


def test_successful_local_nuclei_execution_flow() -> None:
    """Test 6: Execution with local fixture parses output into Observations and RawArtifact."""
    adapter = NucleiAdapter()
    req = ScanRequest(
        target="http://127.0.0.1:8799",
        authorization=_authorization(),
        options={"template": str(FIXTURE_TEMPLATE)},
    )

    mock_res = MagicMock()
    mock_res.stdout = MINIMAL_JSONL

    with patch("subprocess.run", return_value=mock_res):
        res = adapter.scan(req)

        assert res.artifact.scanner == "nuclei"
        assert res.artifact.content_type == "application/x-ndjson"
        assert len(res.observations) == 1
        obs = res.observations[0]
        assert obs.attributes["template_id"] == "test-http-detect"
        assert obs.subject == "http://127.0.0.1:8799/"


def test_etags_exclude_destructive_checks_always_passed() -> None:
    """Exclude-tags flag is always passed to ensure non-destructive scanning."""
    adapter = NucleiAdapter()
    req = ScanRequest(
        target="http://127.0.0.1:8799",
        authorization=_authorization(),
        options={},
    )
    mock_res = MagicMock()
    mock_res.stdout = MINIMAL_JSONL
    with patch("subprocess.run", return_value=mock_res) as mock_run:
        adapter.scan(req)
        cmd = mock_run.call_args[0][0]
        assert "-etags" in cmd
        assert cmd[cmd.index("-etags") + 1] == "dos,intrusive,fuzz,bruteforce"


def test_unapproved_tags_rejected() -> None:
    """Tags outside the approved allowlist (e.g. dos, intrusive) raise ValueError."""
    adapter = NucleiAdapter()
    for bad_tag in ["dos", "intrusive", "bruteforce", "custom_exploit"]:
        req = ScanRequest(
            target="http://127.0.0.1:8799",
            authorization=_authorization(),
            options={"tags": bad_tag},
        )
        with pytest.raises(ValueError, match="not in approved tags allowlist"):
            adapter.scan(req)


def test_template_outside_allowed_directories_rejected() -> None:
    """Templates outside the approved repo template directories raise ValueError."""
    adapter = NucleiAdapter()
    for bad_template in ["../outside.yaml", "/etc/passwd", "services/graph/rules.yaml"]:
        req = ScanRequest(
            target="http://127.0.0.1:8799",
            authorization=_authorization(),
            options={"template": bad_template},
        )
        with pytest.raises(ValueError, match="outside allowed template directories"):
            adapter.scan(req)

