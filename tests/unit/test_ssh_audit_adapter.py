"""Unit and command construction tests for SshAuditAdapter."""

from __future__ import annotations

import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from packages.schema.models.engagement import Authorization, ScanRequest
from packages.schema.models.observation import ObservationKind, ScanResult
from services.scanners.base import (
    AuthorizationError,
    ScannerTimeoutError,
    ScannerUnavailableError,
)
from services.scanners.ssh_audit_adapter import SshAuditAdapter, _ssh_audit_host

NOW = datetime.now(UTC)
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "ssh_audit"
EXE = "/usr/bin/ssh-audit"

RESOLVE = "services.scanners.ssh_audit_adapter._resolve_ssh_audit_bin"


def _stdout(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def _authorization(*allowlist: str) -> Authorization:
    return Authorization(
        engagement_id="eng-ssh-audit-unit-01",
        authorized_by="Security Engineer",
        allowlist=list(allowlist) or ["172.20.2.50", "::1", "bastion.lab.local"],
        granted_at=NOW - timedelta(minutes=5),
        expires_at=NOW + timedelta(hours=1),
    )


def _request(target: str = "172.20.2.50", options: dict[str, object] | None = None) -> ScanRequest:
    return ScanRequest(target=target, authorization=_authorization(), options=options or {})


def _completed(
    stdout: bytes, returncode: int = 0, stderr: bytes = b""
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def _run(
    request: ScanRequest, result: subprocess.CompletedProcess[bytes] | None = None
) -> tuple[ScanResult, MagicMock]:
    """Scan with subprocess.run mocked; return (scan_result, mock_run)."""
    result = result or _completed(_stdout("openssh_8.3_ssh-audit-3.9.0.json"))
    with patch(RESOLVE, return_value=EXE), patch("subprocess.run", return_value=result) as run:
        return SshAuditAdapter().scan(request), run


# --------------------------------------------------------------------------- #
# Identity
# --------------------------------------------------------------------------- #


def test_adapter_identity_and_content_type() -> None:
    adapter = SshAuditAdapter()
    assert adapter.name == "ssh-audit"
    assert adapter.content_type == "application/json"


def test_is_available_follows_the_resolved_binary() -> None:
    with patch(RESOLVE, return_value=EXE):
        assert SshAuditAdapter().is_available() is True
    with patch(RESOLVE, return_value=None):
        assert SshAuditAdapter().is_available() is False


def test_version_command_uses_the_resolved_binary() -> None:
    with patch(RESOLVE, return_value=EXE):
        assert SshAuditAdapter().version_command == [EXE, "-h"]


def test_binary_resolution_prefers_the_configured_path_then_path_lookup(tmp_path: Path) -> None:
    from services.scanners import ssh_audit_adapter as mod

    fake = tmp_path / "ssh-audit"
    fake.write_text("")
    with patch("apps.api.core.config.settings") as settings:
        settings.ssh_audit_path = str(fake)
        assert mod._resolve_ssh_audit_bin() == str(fake)
        settings.ssh_audit_path = str(tmp_path / "missing")
        with patch("shutil.which", return_value="/found/ssh-audit"):
            assert mod._resolve_ssh_audit_bin() == "/found/ssh-audit"
    with patch("apps.api.core.config.settings", object()), patch("shutil.which", return_value=None):
        assert mod._resolve_ssh_audit_bin() is None  # a settings object without the field


# --------------------------------------------------------------------------- #
# Command construction
# --------------------------------------------------------------------------- #


def test_argv_is_fixed_and_the_host_comes_after_the_option_terminator() -> None:
    _, run = _run(_request())
    run.assert_called_once()
    cmd = run.call_args[0][0]
    assert cmd == [
        EXE,
        "-j",
        "--skip-rate-test",
        "-n",
        "-t",
        "10",
        "-p",
        "22",
        "--",
        "172.20.2.50",
    ]
    kwargs = run.call_args[1]
    assert kwargs["stdin"] == subprocess.DEVNULL
    assert kwargs["capture_output"] is True
    assert kwargs["timeout"] == 120
    assert kwargs["check"] is False
    assert "text" not in kwargs  # decoded explicitly


def test_port_and_timeout_options_are_validated_and_passed() -> None:
    _, run = _run(_request(options={"port": 2222, "timeout": 30}))
    cmd = run.call_args[0][0]
    assert cmd[cmd.index("-p") + 1] == "2222"
    assert cmd[cmd.index("-t") + 1] == "10"
    assert run.call_args[1]["timeout"] == 30


def test_ssh_audit_socket_timeout_never_exceeds_the_overall_budget() -> None:
    _, run = _run(_request(options={"timeout": 3}))
    cmd = run.call_args[0][0]
    assert cmd[cmd.index("-t") + 1] == "3"


def test_ipv6_literal_is_passed_unbracketed_after_the_terminator() -> None:
    _, run = _run(_request("::1", {"port": 2222}))
    cmd = run.call_args[0][0]
    assert cmd[-2:] == ["--", "::1"]
    assert cmd[cmd.index("-p") + 1] == "2222"


def test_hostname_target_is_accepted() -> None:
    _, run = _run(_request("bastion.lab.local"))
    assert run.call_args[0][0][-1] == "bastion.lab.local"


def test_caller_flags_are_not_forwarded() -> None:
    """ssh-audit has flags that read files (-T, -P), listen (-c) and attack (--dheat)."""
    options: dict[str, object] = {
        "extra_args": ["-T", "/etc/hosts", "--dheat", "10"],
        "args": ["-c"],
        "policy": "/etc/passwd",
        "flags": "-g 1:2:3",
    }
    _, run = _run(_request(options=options))
    cmd = run.call_args[0][0]
    for forbidden in ("-T", "--dheat", "-c", "-P", "-M", "-g", "--conn-rate-test", "--threads"):
        assert forbidden not in cmd
    assert len(cmd) == 10


# --------------------------------------------------------------------------- #
# Target and option validation
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "target",
    [
        "-x",
        "-T",
        "--dheat",
        "-p2222",
        "http://172.20.2.50",
        "ssh://172.20.2.50:22",
        "172.20.2.50:2222",
        "user@172.20.2.50",
        "172.20.2.50/32",
        "/etc/hosts",
        "../evil",
        "unix:///var/run/x.sock",
        "fe80::1%eth0",
        "[::1]",
        "[::1]:22",
        "evil.com#.lab.local",
        "bad host",
        "web..lab.local",
        "web-.lab.local",
        "172.20.2.50;id",
        "$(id)",
        "",
        "   ",
    ],
)
def test_target_must_be_a_bare_ip_or_strict_hostname(target: str) -> None:
    request = ScanRequest(target=target, authorization=_authorization(target or "x"))
    with pytest.raises(ValueError, match="ssh-audit target"):
        _ssh_audit_host(request)


def test_dash_target_never_reaches_the_subprocess() -> None:
    request = ScanRequest(target="-x", authorization=_authorization("-x"))
    with (
        patch(RESOLVE, return_value=EXE),
        patch("subprocess.run") as run,
        pytest.raises(ValueError, match="may not start with"),
    ):
        SshAuditAdapter().scan(request)
    run.assert_not_called()


@pytest.mark.parametrize("target", ["172.20.2.50", "::1", "2001:db8::10", "bastion.lab.local"])
def test_valid_targets_pass_through_unchanged(target: str) -> None:
    request = ScanRequest(target=target, authorization=_authorization(target))
    assert _ssh_audit_host(request) == target


@pytest.mark.parametrize("port", [0, 65536, -1, "80; rm -rf /", "-1", "ssh", True, 22.0, None, ""])
def test_invalid_port_option_is_rejected_before_the_subprocess(port: object) -> None:
    with (
        patch(RESOLVE, return_value=EXE),
        patch("subprocess.run") as run,
        pytest.raises(ValueError, match="port option must be"),
    ):
        SshAuditAdapter().scan(_request(options={"port": port}))
    run.assert_not_called()


@pytest.mark.parametrize("bad", ["30", None, True, 0, -5, 999_999, 1.5, float("inf"), float("nan")])
def test_invalid_timeout_option_is_rejected_before_the_subprocess(bad: object) -> None:
    with (
        patch(RESOLVE, return_value=EXE),
        patch("subprocess.run") as run,
        pytest.raises(ValueError, match="timeout option must be"),
    ):
        SshAuditAdapter().scan(_request(options={"timeout": bad}))
    run.assert_not_called()


# --------------------------------------------------------------------------- #
# Authorization
# --------------------------------------------------------------------------- #


def test_unauthorized_target_is_refused_and_the_tool_never_runs() -> None:
    request = ScanRequest(target="203.0.113.10", authorization=_authorization("172.20.2.50"))
    with (
        patch(RESOLVE, return_value=EXE),
        patch("subprocess.run") as run,
        pytest.raises(AuthorizationError),
    ):
        SshAuditAdapter().scan(request)
    run.assert_not_called()


def test_expired_authorization_is_refused() -> None:
    expired = Authorization(
        engagement_id="eng-ssh-audit-unit-01",
        authorized_by="Security Engineer",
        allowlist=["172.20.2.50"],
        granted_at=NOW - timedelta(hours=2),
        expires_at=NOW - timedelta(hours=1),
    )
    with (
        patch(RESOLVE, return_value=EXE),
        patch("subprocess.run") as run,
        pytest.raises(AuthorizationError),
    ):
        SshAuditAdapter().scan(ScanRequest(target="172.20.2.50", authorization=expired))
    run.assert_not_called()


# --------------------------------------------------------------------------- #
# Exit codes: findings are results, not errors
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("returncode", [0, 2, 3])
def test_good_warning_and_failure_exit_codes_are_all_results(returncode: int) -> None:
    result, _ = _run(
        _request(options={"port": 2222}),
        _completed(_stdout("openssh_8.3_ssh-audit-3.9.0.json"), returncode=returncode),
    )
    assert result.artifact.scanner == "ssh-audit"
    assert result.artifact.content_type == "application/json"
    kinds = {o.kind for o in result.observations}
    assert kinds == {ObservationKind.SERVICE_VERSION, ObservationKind.VULN_CANDIDATE}


def test_end_to_end_observations_join_the_bastion_endpoint() -> None:
    result, _ = _run(_request(options={"port": 2222}))
    assert {o.subject for o in result.observations} == {"172.20.2.50:2222/tcp"}
    assert {o.scanner for o in result.observations} == {"ssh-audit"}
    assert {o.engagement_id for o in result.observations} == {"eng-ssh-audit-unit-01"}
    assert {o.artifact_id for o in result.observations} == {result.artifact.artifact_id}
    assert result.artifact.content == _stdout("openssh_8.3_ssh-audit-3.9.0.json").decode()


def test_artifact_content_is_the_verbatim_stdout() -> None:
    raw = _stdout("openssh_8.3_ssh-audit-2.9.0.json")
    result, _ = _run(_request(options={"port": 2222}), _completed(raw, returncode=3))
    assert result.artifact.content == raw.decode("utf-8")
    assert len([o for o in result.observations if o.attributes.get("finding_type") == "cve"]) == 3


def test_connection_error_is_an_error_not_an_empty_result() -> None:
    refused = _completed(_stdout("connection_refused.txt"), returncode=1)
    with (
        patch(RESOLVE, return_value=EXE),
        patch("subprocess.run", return_value=refused),
        pytest.raises(ValueError, match=r"exited 1.*cannot connect to 172\.20\.2\.50 port 2223"),
    ):
        SshAuditAdapter().scan(_request(options={"port": 2223}))


@pytest.mark.parametrize(
    ("stdout", "returncode"),
    [(b"", 255), (b"", 0), (b"not json at all", 3), (b"[]", 0), (b'{"cves": []}', 2)],
)
def test_output_that_is_not_audit_json_is_an_error_whatever_the_exit_code(
    stdout: bytes, returncode: int
) -> None:
    with (
        patch(RESOLVE, return_value=EXE),
        patch("subprocess.run", return_value=_completed(stdout, returncode)),
        pytest.raises(ValueError, match="without producing audit JSON"),
    ):
        SshAuditAdapter().scan(_request())


def test_connection_error_message_has_ansi_escapes_stripped() -> None:
    ansi = _completed(b"\x1b[0;31m[exception] cannot connect to x port 22\x1b[0m\n", 1)
    with (
        patch(RESOLVE, return_value=EXE),
        patch("subprocess.run", return_value=ansi),
        pytest.raises(ValueError) as info,
    ):
        SshAuditAdapter().scan(_request())
    assert "\x1b" not in str(info.value)
    assert "cannot connect to x port 22" in str(info.value)


def test_stderr_is_logged_not_recorded(caplog: pytest.LogCaptureFixture) -> None:
    result = _completed(_stdout("openssh_8.3_ssh-audit-3.9.0.json"), 3, stderr=b"some warning\n")
    with caplog.at_level("WARNING"):
        scan, _ = _run(_request(options={"port": 2222}), result)
    assert "some warning" in caplog.text
    assert "some warning" not in scan.artifact.content


# --------------------------------------------------------------------------- #
# Process failures
# --------------------------------------------------------------------------- #


def test_timeout_raises_scanner_timeout_error() -> None:
    with (
        patch(RESOLVE, return_value=EXE),
        patch(
            "subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["ssh-audit"], timeout=5)
        ),
        pytest.raises(ScannerTimeoutError, match="not recorded"),
    ):
        SshAuditAdapter().scan(_request(options={"timeout": 5}))


def test_missing_binary_raises_scanner_unavailable_error() -> None:
    with (
        patch(RESOLVE, return_value=None),
        patch("subprocess.run", side_effect=FileNotFoundError("no such file")),
        pytest.raises(ScannerUnavailableError, match="not executable"),
    ):
        SshAuditAdapter().scan(_request())


def test_unstartable_binary_raises_scanner_unavailable_error() -> None:
    with (
        patch(RESOLVE, return_value=EXE),
        patch("subprocess.run", side_effect=PermissionError("denied")),
        pytest.raises(ScannerUnavailableError, match="could not start"),
    ):
        SshAuditAdapter().scan(_request())


def test_stdout_is_decoded_explicitly_with_replacement() -> None:
    """Invalid UTF-8 in the output must not raise and must not depend on the platform."""
    stdout = MagicMock()
    stdout.decode.return_value = _stdout("openssh_8.3_ssh-audit-3.9.0.json").decode()
    proc = MagicMock(returncode=3, stdout=stdout, stderr=b"")
    with patch(RESOLVE, return_value=EXE), patch("subprocess.run", return_value=proc):
        SshAuditAdapter().scan(_request(options={"port": 2222}))
    stdout.decode.assert_called_once_with("utf-8", errors="replace")
