import pytest
from typer.testing import CliRunner

from apl.cli import app
from apl.models import Finding, Severity
from apl.scan import exceeds_threshold, run_scan


def dirty_args(fix):
    return [
        "-c", str(fix / "configs/claude_desktop.json"),
        "-a", str(fix / "agents/release_notes_bot.yaml"),
        "-t", str(fix / "tools/claude_desktop_tools.json"),
    ]


def clean_args(fix):
    d = fix / "clean"
    return ["-c", str(d / "mcp.json"), "-a", str(d / "agent.yaml"), "-t", str(d / "tools.json")]


def scan(*args):
    return CliRunner().invoke(app, ["scan", *args])


@pytest.mark.parametrize("fail_on,code", [("none", 0), ("low", 1), ("medium", 1), ("high", 1)])
def test_exit_code_dirty(fix, fail_on, code):
    r = scan(*dirty_args(fix), "--fail-on", fail_on, "-f", "json")
    assert r.exit_code == code, r.output


@pytest.mark.parametrize("fail_on", ["none", "low", "medium", "high"])
def test_exit_code_clean_is_zero(fix, fail_on):
    assert scan(*clean_args(fix), "--fail-on", fail_on).exit_code == 0


def test_default_fail_on_is_none(fix):
    assert scan(*dirty_args(fix)).exit_code == 0


def test_out_file_written(fix, tmp_path):
    out = tmp_path / "r.json"
    r = scan(*dirty_args(fix), "-f", "json", "--out", str(out))
    assert r.exit_code == 0 and out.read_text(encoding="utf-8").strip()


def test_connect_refused(fix):
    r = scan(*clean_args(fix), "--connect")
    assert r.exit_code == 2 and "WARNING" in r.output


def test_parse_error_is_exit_2(fix):
    r = scan("-c", str(fix / "agents/invalid_extra_key.yaml"))
    assert r.exit_code == 2


def test_bad_format_rejected(fix):
    assert scan(*clean_args(fix), "-f", "xml").exit_code != 0


def _with(report, severity):
    f = Finding(id="X:1", rule_id="X", title="t", severity=severity, subject="s", fix="f",
                confidence=1, confidence_reason="r")
    report.result.findings = [f]
    return report


def test_threshold_boundaries(fix):
    rep = run_scan([fix / "clean/mcp.json"])
    assert not exceeds_threshold(_with(rep, Severity.MEDIUM), "high")
    assert exceeds_threshold(_with(rep, Severity.MEDIUM), "medium")
    assert exceeds_threshold(_with(rep, Severity.CRITICAL), "high")
    assert not exceeds_threshold(_with(rep, Severity.INFO), "low")
    assert not exceeds_threshold(_with(rep, Severity.CRITICAL), "none")
