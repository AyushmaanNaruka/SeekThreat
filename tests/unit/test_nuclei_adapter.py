"""Unit and command construction tests for NucleiAdapter."""

from __future__ import annotations

import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from packages.schema.models.engagement import Authorization, ScanRequest
from services.scanners.base import ScannerTimeoutError, ScannerUnavailableError
from services.scanners.nuclei_adapter import NucleiAdapter

NOW = datetime.now(UTC)
FIXTURE_TEMPLATE = (
    Path(__file__).resolve().parents[1] / "fixtures" / "nuclei" / "test_http_detect.yaml"
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
        options={"tags": "cve,tech"},
    )

    mock_res = MagicMock()
    mock_res.stdout = MINIMAL_JSONL

    with patch("subprocess.run", return_value=mock_res) as mock_run:
        adapter.scan(req)

        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "-tags" in cmd
        assert cmd[cmd.index("-tags") + 1] == "cve,tech"


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
        excluded = cmd[cmd.index("-etags") + 1].split(",")
        for tag in ["dos", "intrusive", "fuzz", "bruteforce", "rce", "default-login"]:
            assert tag in excluded


def test_unapproved_tags_rejected() -> None:
    """Tags outside the approved allowlist (e.g. dos, intrusive) raise ValueError."""
    adapter = NucleiAdapter()
    for bad_tag in ["dos", "intrusive", "bruteforce", "custom_exploit", "rce", "default-login"]:
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


# --------------------------------------------------------------------------- #
# Target construction
#
# The authorization gate compares request.target as an exact string and refuses to
# parse a URL down to a host, deliberately — see the parser-differential cases in
# tests/unit/test_authorization_matching.py. nuclei's input model is URLs, so the
# adapter builds one by appending a validated scheme and port to the approved target.
# Appending cannot move the scan to a host the gate did not see; parsing could.
# --------------------------------------------------------------------------- #


def test_bare_host_target_with_port_option_builds_host_port() -> None:
    """The gate permits a bare IP, not a URL. The port comes from a validated option."""
    adapter = NucleiAdapter()
    req = ScanRequest(
        target="127.0.0.1",
        authorization=_authorization("127.0.0.1"),
        options={"template": str(FIXTURE_TEMPLATE), "port": 8799},
    )
    mock_res = MagicMock()
    mock_res.stdout = MINIMAL_JSONL
    with patch("subprocess.run", return_value=mock_res) as mock_run:
        adapter.scan(req)
        cmd = mock_run.call_args[0][0]
        assert cmd[cmd.index("-u") + 1] == "127.0.0.1:8799"


def test_scheme_option_prefixes_the_target() -> None:
    adapter = NucleiAdapter()
    req = ScanRequest(
        target="127.0.0.1",
        authorization=_authorization("127.0.0.1"),
        options={"template": str(FIXTURE_TEMPLATE), "port": 8799, "scheme": "https"},
    )
    mock_res = MagicMock()
    mock_res.stdout = MINIMAL_JSONL
    with patch("subprocess.run", return_value=mock_res) as mock_run:
        adapter.scan(req)
        cmd = mock_run.call_args[0][0]
        assert cmd[cmd.index("-u") + 1] == "https://127.0.0.1:8799"


def test_ipv6_target_is_bracketed() -> None:
    adapter = NucleiAdapter()
    req = ScanRequest(
        target="::1",
        authorization=_authorization("::1"),
        options={"template": str(FIXTURE_TEMPLATE), "port": 8799},
    )
    mock_res = MagicMock()
    mock_res.stdout = MINIMAL_JSONL
    with patch("subprocess.run", return_value=mock_res) as mock_run:
        adapter.scan(req)
        cmd = mock_run.call_args[0][0]
        assert cmd[cmd.index("-u") + 1] == "[::1]:8799"


def test_port_and_scheme_options_rejected_on_a_url_target() -> None:
    """Rewriting an allowlisted URL would build a target the gate never approved."""
    adapter = NucleiAdapter()
    for opts in ({"port": 9999}, {"scheme": "https"}):
        req = ScanRequest(
            target="http://127.0.0.1:8799",
            authorization=_authorization(),
            options={"template": str(FIXTURE_TEMPLATE), **opts},
        )
        with pytest.raises(ValueError, match="already a URL"):
            adapter.scan(req)


def test_invalid_port_and_scheme_options_rejected() -> None:
    adapter = NucleiAdapter()
    for port in [0, 65536, "80; rm -rf /", "-1", "http"]:
        req = ScanRequest(
            target="127.0.0.1",
            authorization=_authorization("127.0.0.1"),
            options={"template": str(FIXTURE_TEMPLATE), "port": port},
        )
        with pytest.raises(ValueError, match="port option must be"):
            adapter.scan(req)

    req = ScanRequest(
        target="127.0.0.1",
        authorization=_authorization("127.0.0.1"),
        options={"template": str(FIXTURE_TEMPLATE), "port": 8799, "scheme": "file"},
    )
    with pytest.raises(ValueError, match="scheme option must be"):
        adapter.scan(req)


def test_target_may_not_start_with_a_dash() -> None:
    """goflags would read it as a flag rather than a value."""
    adapter = NucleiAdapter()
    req = ScanRequest(
        target="-silent",
        authorization=Authorization(
            engagement_id="eng-nuclei-unit-01",
            authorized_by="Security Engineer",
            allowlist=["-silent"],
            granted_at=NOW - timedelta(minutes=5),
            expires_at=NOW + timedelta(hours=1),
        ),
        options={"template": str(FIXTURE_TEMPLATE)},
    )
    with pytest.raises(ValueError, match="may not start with"):
        adapter.scan(req)


# --------------------------------------------------------------------------- #
# Output-size and process-failure handling
# --------------------------------------------------------------------------- #


def test_omit_template_and_no_color_always_passed() -> None:
    """-ot drops the base64 template copy nuclei embeds in every record; -nc keeps
    ANSI escapes out of the stderr that lands in a scan row's error_message."""
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
        cmd = mock_run.call_args[0][0]
        assert "-ot" in cmd
        assert "-nc" in cmd
        # request/response evidence is kept unless explicitly omitted
        assert "-or" not in cmd


def test_omit_http_exchange_option_adds_omit_raw() -> None:
    adapter = NucleiAdapter()
    req = ScanRequest(
        target="http://127.0.0.1:8799",
        authorization=_authorization(),
        options={"template": str(FIXTURE_TEMPLATE), "omit_http_exchange": True},
    )
    mock_res = MagicMock()
    mock_res.stdout = MINIMAL_JSONL
    with patch("subprocess.run", return_value=mock_res) as mock_run:
        adapter.scan(req)
        assert "-or" in mock_run.call_args[0][0]


def test_nonzero_exit_raises_value_error_carrying_nucleis_reason() -> None:
    """nuclei exits 1 for "no templates provided" and 2 for a bad flag. The reason is
    only on stderr; CalledProcessError's own message carries just the exit code, and a
    retry repeats a configuration fault verbatim."""
    adapter = NucleiAdapter()
    req = ScanRequest(
        target="http://127.0.0.1:8799",
        authorization=_authorization(),
        options={"template": str(FIXTURE_TEMPLATE)},
    )
    exc = subprocess.CalledProcessError(
        returncode=1,
        cmd=["nuclei"],
        stderr=b"[FTL] Could not run nuclei: no templates provided for scan\n",
    )
    with (
        patch("subprocess.run", side_effect=exc),
        pytest.raises(ValueError, match="no templates provided for scan"),
    ):
        adapter.scan(req)


def test_timeout_raises_scanner_timeout_error_not_a_transient_failure() -> None:
    """A killed process loses its buffered findings, and the same budget times out
    again, so this must not be retried."""
    adapter = NucleiAdapter()
    req = ScanRequest(
        target="http://127.0.0.1:8799",
        authorization=_authorization(),
        options={"template": str(FIXTURE_TEMPLATE), "timeout": 5},
    )
    with (
        patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["nuclei"], timeout=5)),
        pytest.raises(ScannerTimeoutError, match="were discarded"),
    ):
        adapter.scan(req)


def test_missing_binary_raises_scanner_unavailable_error() -> None:
    adapter = NucleiAdapter()
    req = ScanRequest(
        target="http://127.0.0.1:8799",
        authorization=_authorization(),
        options={"template": str(FIXTURE_TEMPLATE)},
    )
    with (
        patch("subprocess.run", side_effect=FileNotFoundError("no such file")),
        pytest.raises(ScannerUnavailableError),
    ):
        adapter.scan(req)


def test_invalid_timeout_option_rejected_before_the_subprocess_starts() -> None:
    """options cross an HTTP and a Celery JSON boundary, so timeout arrives as
    whatever the client sent. subprocess.run raises TypeError deep in the call for
    some of these, which reads as a transient error and gets retried."""
    adapter = NucleiAdapter()
    for bad in ["30", None, True, 0, -5, 999_999]:
        req = ScanRequest(
            target="http://127.0.0.1:8799",
            authorization=_authorization(),
            options={"template": str(FIXTURE_TEMPLATE), "timeout": bad},
        )
        with pytest.raises(ValueError, match="timeout option must be"):
            adapter.scan(req)
