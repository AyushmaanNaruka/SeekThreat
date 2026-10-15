"""Command construction, target hardening and failure mapping for NiktoAdapter."""

from __future__ import annotations

import logging
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from packages.schema.models.engagement import Authorization, ScanRequest
from packages.schema.models.observation import ObservationKind
from services.scanners import nikto_adapter
from services.scanners.base import (
    AuthorizationError,
    ScannerTimeoutError,
    ScannerUnavailableError,
)
from services.scanners.nikto_adapter import (
    EXCLUDED_TUNING,
    SAFE_PLUGINS,
    SAFE_TUNING,
    NiktoAdapter,
    _nikto_target_args,
)

NOW = datetime.now(UTC)
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "nikto"
REAL_OUTPUT = (FIXTURES / "httpd_2449.json").read_bytes()
# Plugins that upload, delete, guess credentials, enumerate, brute-force or send attack
# payloads. None may ever appear in the argv.
FORBIDDEN_PLUGINS = {
    "put_del_test",
    "auth",
    "dictionary",
    "apacheusers",
    "shellshock",
    "strutshock",
    "dishwasher",
    "ms10_070",
    "apache_expect_xss",
    "docker_registry",
    "drupal",
    "siebel",
    "domino",
}


def _authorization(*extra: str) -> Authorization:
    return Authorization(
        engagement_id="eng-nikto-unit-01",
        authorized_by="Security Engineer",
        allowlist=["172.20.1.10", "web.lab.local", "::1", *extra],
        granted_at=NOW - timedelta(minutes=5),
        expires_at=NOW + timedelta(hours=1),
    )


def _request(
    target: str = "172.20.1.10",
    options: dict[str, object] | None = None,
    *extra_allow: str,
) -> ScanRequest:
    return ScanRequest(
        target=target,
        authorization=_authorization(*extra_allow),
        options=options or {},
    )


def _ok(stdout: bytes = REAL_OUTPUT, stderr: bytes = b"") -> MagicMock:
    res = MagicMock()
    res.stdout = stdout
    res.stderr = stderr
    return res


def _run(request: ScanRequest, result: MagicMock | None = None) -> list[str]:
    with patch("subprocess.run", return_value=result or _ok()) as mock_run:
        NiktoAdapter().scan(request)
    mock_run.assert_called_once()
    cmd: list[str] = mock_run.call_args[0][0]
    return cmd


# --------------------------------------------------------------------------- #
# Identity and the authorization gate
# --------------------------------------------------------------------------- #


def test_adapter_identity_and_no_arg_construction() -> None:
    adapter = NiktoAdapter()
    assert adapter.name == "nikto"
    assert adapter.content_type == "application/json"
    assert adapter.version_command[-1] == "-Version"


def test_unauthorized_target_is_refused_before_the_tool_runs() -> None:
    with patch("subprocess.run") as mock_run, pytest.raises(AuthorizationError):
        NiktoAdapter().scan(_request("203.0.113.10"))
    mock_run.assert_not_called()


def test_full_scan_flow_produces_artifact_and_observations() -> None:
    with patch("subprocess.run", return_value=_ok()):
        res = NiktoAdapter().scan(_request())
    assert res.artifact.scanner == "nikto"
    assert res.artifact.content_type == "application/json"
    assert res.artifact.artifact_id.startswith("sha256:")
    assert len(res.observations) == 9
    assert {o.kind for o in res.observations} == {ObservationKind.VULN_CANDIDATE}
    assert {o.engagement_id for o in res.observations} == {"eng-nikto-unit-01"}


# --------------------------------------------------------------------------- #
# argv
# --------------------------------------------------------------------------- #


def test_exact_argv_for_a_bare_host() -> None:
    with patch.object(nikto_adapter, "_resolve_nikto_bin", return_value="/usr/bin/nikto"):
        cmd = _run(_request(options={"port": 8080, "scheme": "http"}))
    assert cmd == [
        "/usr/bin/nikto",
        "-host",
        "172.20.1.10",
        "-port",
        "8080",
        "-nossl",
        "-ask",
        "no",
        "-nointeractive",
        "-nolookup",
        "-Format",
        "json",
        "-o",
        "-",
        "-maxtime",
        "1800s",
        "-Tuning",
        "123abde",
        "-Plugins",
        ";".join(SAFE_PLUGINS),
    ]


def test_argv_is_the_same_fixed_shape_with_no_options() -> None:
    cmd = _run(_request())
    assert cmd[1:3] == ["-host", "172.20.1.10"]
    assert "-port" not in cmd and "-ssl" not in cmd and "-nossl" not in cmd
    for flag in ("-ask", "-nointeractive", "-Format", "-o", "-maxtime", "-Tuning", "-Plugins"):
        assert flag in cmd
    assert cmd[cmd.index("-ask") + 1] == "no"
    assert cmd[cmd.index("-Format") + 1] == "json"
    assert cmd[cmd.index("-o") + 1] == "-"


def test_tuning_is_an_include_list_that_excludes_destructive_categories() -> None:
    cmd = _run(_request())
    tuning = cmd[cmd.index("-Tuning") + 1]
    assert tuning == SAFE_TUNING
    assert not tuning.startswith("x"), "reverse tuning would include categories added later"
    for category in "069":  # file upload, denial of service, SQL injection
        assert category not in tuning
    assert not set(tuning) & EXCLUDED_TUNING
    assert {"0", "4", "5", "6", "7", "8", "9", "c"} == set(EXCLUDED_TUNING)


def test_plugins_are_an_include_list_without_active_plugins() -> None:
    cmd = _run(_request())
    plugins = cmd[cmd.index("-Plugins") + 1].split(";")
    assert plugins == list(SAFE_PLUGINS)
    assert not FORBIDDEN_PLUGINS & set(plugins)
    # without report_json nikto prints nothing on stdout at all
    assert "report_json" in plugins


def test_caller_options_cannot_inject_flags_or_widen_the_scan(
    caplog: pytest.LogCaptureFixture,
) -> None:
    baseline = _run(_request())
    hostile = {
        "extra_args": ["-host", "198.51.100.9"],
        "args": "-Tuning 69",
        "tuning": "69",
        "plugins": "put_del_test",
        "flags": ["-mutate", "5"],
    }
    with caplog.at_level(logging.WARNING):
        cmd = _run(_request(options=hostile))
    assert cmd == baseline
    assert cmd.count("-host") == 1
    assert "ignoring unsupported option" in caplog.text


def test_subprocess_gets_closed_stdin_and_a_watchdog_behind_maxtime() -> None:
    with patch("subprocess.run", return_value=_ok()) as mock_run:
        NiktoAdapter().scan(_request(options={"timeout": 120}))
    kwargs = mock_run.call_args[1]
    cmd = mock_run.call_args[0][0]
    assert kwargs["stdin"] == subprocess.DEVNULL
    assert kwargs["capture_output"] is True
    assert kwargs["check"] is True
    assert "text" not in kwargs and "shell" not in kwargs
    assert cmd[cmd.index("-maxtime") + 1] == "120s"
    assert kwargs["timeout"] == 120 + nikto_adapter.WATCHDOG_GRACE_SECONDS


def test_stdout_is_decoded_explicitly_without_newline_translation() -> None:
    raw = b'[{"host":"10.0.0.5","ip":"10.0.0.5","port":"80","banner":"","vulnerabilities":[]}]\r\n'
    with patch("subprocess.run", return_value=_ok(raw)):
        res = NiktoAdapter().scan(_request("172.20.1.10"))
    assert res.artifact.content == raw.decode("utf-8")
    assert "\r\n" in res.artifact.content


# --------------------------------------------------------------------------- #
# Target hardening (same rules as nuclei's _nuclei_target)
# --------------------------------------------------------------------------- #


def test_port_and_scheme_options_become_separate_flags() -> None:
    assert _nikto_target_args(_request(options={"port": 8443, "scheme": "https"})) == [
        "-host",
        "172.20.1.10",
        "-port",
        "8443",
        "-ssl",
    ]
    assert _nikto_target_args(_request(options={"port": "8080"}))[-2:] == ["-port", "8080"]


def test_hostname_target_is_accepted() -> None:
    assert _nikto_target_args(_request("web.lab.local")) == ["-host", "web.lab.local"]


def test_ipv6_target_is_passed_bare() -> None:
    assert _nikto_target_args(_request("::1", {"port": 80})) == ["-host", "::1", "-port", "80"]


@pytest.mark.parametrize("target", ["-Tuning", "-host", "--help", "-x"])
def test_target_may_not_start_with_a_dash(target: str) -> None:
    req = _request(target, None, target)
    with pytest.raises(ValueError, match="may not start with"):
        NiktoAdapter().scan(req)


@pytest.mark.parametrize(
    "target",
    [
        "evil.com/x.lab.local",
        "evil.com#.lab.local",
        "evil.com?.lab.local",
        "attacker@web.lab.local",
        "web.lab.local:8080",
        "172.20.1.10/admin",
        "172.20.1.10:80",
        "evil com.lab.local",
        "web..lab.local",
        "web-.lab.local",
        "172.20.1.10;id",
    ],
)
def test_bare_target_must_be_an_ip_or_a_strict_hostname(target: str) -> None:
    req = ScanRequest(
        target=target,
        authorization=Authorization(
            engagement_id="eng-nikto-unit-01",
            authorized_by="Security Engineer",
            allowlist=["*.lab.local", target],
            granted_at=NOW - timedelta(minutes=5),
            expires_at=NOW + timedelta(hours=1),
        ),
    )
    with pytest.raises(ValueError, match="not an IP address or a valid hostname"):
        _nikto_target_args(req)


@pytest.mark.parametrize(
    "target",
    [
        "http://evil.com/.lab.local",
        "http://evil.com#.lab.local",
        "https://web.lab.local",
    ],
)
def test_url_target_rejected_unless_exactly_allowlisted(target: str) -> None:
    req = ScanRequest(
        target=target,
        authorization=Authorization(
            engagement_id="eng-nikto-unit-01",
            authorized_by="Security Engineer",
            allowlist=["*.lab.local"],
            granted_at=NOW - timedelta(minutes=5),
            expires_at=NOW + timedelta(hours=1),
        ),
    )
    with pytest.raises(ValueError, match="URL target"):
        _nikto_target_args(req)


def test_exactly_allowlisted_url_target_is_passed_verbatim() -> None:
    url = "http://172.20.1.10:8080"
    assert _nikto_target_args(_request(url, None, url)) == ["-host", url]


def test_url_allowlist_match_is_case_sensitive() -> None:
    req = _request("HTTP://172.20.1.10:8080/Admin", None, "http://172.20.1.10:8080/admin")
    with pytest.raises(ValueError, match="URL target"):
        _nikto_target_args(req)


def test_port_and_scheme_options_rejected_on_a_url_target() -> None:
    url = "http://172.20.1.10:8080"
    for opts in ({"port": 9999}, {"scheme": "https"}):
        with pytest.raises(ValueError, match="already a URL"):
            _nikto_target_args(_request(url, opts, url))


@pytest.mark.parametrize("port", [0, 65536, "80; rm -rf /", "-1", "http", "", 1.5])
def test_invalid_port_option_rejected(port: object) -> None:
    with pytest.raises(ValueError, match="port option must be"):
        _nikto_target_args(_request(options={"port": port}))


@pytest.mark.parametrize("scheme", ["file", "ftp", "http://x", "", "https; id"])
def test_invalid_scheme_option_rejected(scheme: str) -> None:
    with pytest.raises(ValueError, match="scheme option must be"):
        _nikto_target_args(_request(options={"scheme": scheme}))


def test_rejected_target_never_starts_a_subprocess() -> None:
    with patch("subprocess.run") as mock_run, pytest.raises(ValueError):
        NiktoAdapter().scan(_request(options={"port": "99999"}))
    mock_run.assert_not_called()


# --------------------------------------------------------------------------- #
# Timeouts and process failures
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("bad", ["30", None, True, 0, -5, 999_999, 1.5, float("inf"), float("nan")])
def test_invalid_timeout_option_rejected_before_the_subprocess_starts(bad: object) -> None:
    with patch("subprocess.run") as mock_run, pytest.raises(ValueError, match="timeout option"):
        NiktoAdapter().scan(_request(options={"timeout": bad}))
    mock_run.assert_not_called()


def test_watchdog_timeout_raises_scanner_timeout_error() -> None:
    exc = subprocess.TimeoutExpired(cmd=["nikto"], timeout=5)
    with patch("subprocess.run", side_effect=exc), pytest.raises(ScannerTimeoutError, match="not"):
        NiktoAdapter().scan(_request(options={"timeout": 5}))


def test_nikto_own_maxtime_with_partial_report_is_a_timeout_not_a_result() -> None:
    """nikto stops itself at -maxtime and exits 0 with the findings so far."""
    stderr = b"+ ERROR: Host maximum execution time of 5 seconds reached\n"
    with (
        patch("subprocess.run", return_value=_ok(stderr=stderr)),
        pytest.raises(ScannerTimeoutError, match="partial output was not recorded"),
    ):
        NiktoAdapter().scan(_request(options={"timeout": 5}))


def test_missing_binary_raises_scanner_unavailable_error() -> None:
    with (
        patch("subprocess.run", side_effect=FileNotFoundError("no such file")),
        pytest.raises(ScannerUnavailableError),
    ):
        NiktoAdapter().scan(_request())


def test_os_error_raises_scanner_unavailable_error() -> None:
    with (
        patch("subprocess.run", side_effect=PermissionError("denied")),
        pytest.raises(ScannerUnavailableError, match="could not start"),
    ):
        NiktoAdapter().scan(_request())


def test_nonzero_exit_raises_value_error_carrying_stderr() -> None:
    exc = subprocess.CalledProcessError(
        returncode=2, cmd=["nikto"], stderr=b"+ ERROR: No host specified\n"
    )
    with patch("subprocess.run", side_effect=exc), pytest.raises(ValueError, match="No host"):
        NiktoAdapter().scan(_request())


def test_unreachable_target_logs_a_warning_and_yields_no_findings(
    caplog: pytest.LogCaptureFixture,
) -> None:
    raw = (FIXTURES / "unreachable.json").read_bytes()
    with patch("subprocess.run", return_value=_ok(raw)), caplog.at_level(logging.WARNING):
        res = NiktoAdapter().scan(_request())
    assert res.observations == ()
    assert "could not connect" in caplog.text


def test_garbage_output_surfaces_as_a_parse_error_at_capture() -> None:
    from services.scanners.nikto_json import NiktoParseError

    with (
        patch("subprocess.run", return_value=_ok(b"Segmentation fault")),
        pytest.raises(NiktoParseError),
    ):
        NiktoAdapter().scan(_request())


# --------------------------------------------------------------------------- #
# Binary resolution
# --------------------------------------------------------------------------- #


def test_binary_resolution_prefers_configured_path_then_nikto_then_nikto_pl(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "my-nikto"
    exe.write_text("#!/bin/sh\n")
    import apps.api.core.config as config

    monkeypatch.setattr(config, "settings", SimpleNamespace(nikto_path=str(exe)))
    assert nikto_adapter._resolve_nikto_bin() == str(exe)

    monkeypatch.setattr(config, "settings", SimpleNamespace(nikto_path=str(tmp_path / "gone")))
    with patch("shutil.which", side_effect=lambda n: "/x/nikto.pl" if n == "nikto.pl" else None):
        assert nikto_adapter._resolve_nikto_bin() == "/x/nikto.pl"
    with patch("shutil.which", side_effect=lambda n: f"/x/{n}"):
        assert nikto_adapter._resolve_nikto_bin() == "/x/nikto"


def test_binary_resolution_tolerates_a_settings_object_without_nikto_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import apps.api.core.config as config

    monkeypatch.setattr(config, "settings", SimpleNamespace())
    with patch("shutil.which", return_value=None):
        assert nikto_adapter._resolve_nikto_bin() is None
        assert NiktoAdapter().is_available() is False
    with patch("shutil.which", return_value="/usr/bin/nikto"):
        assert NiktoAdapter().is_available() is True


@pytest.mark.parametrize("target", ["::1%eth0", "::1%x,10.9.9.9", "::1%lo -Tuning 0"])
def test_scoped_ipv6_target_is_refused(target: str) -> None:
    # Defence in depth behind the gate: a scope id is free text that ipaddress accepts,
    # and nikto treats commas in -host as a host list (and a readable path as a host file).
    with pytest.raises(ValueError, match="scope"):
        _nikto_target_args(_request(target))
