"""apl scan says free text is not masked, on stderr and inside the report that travels."""

import json

import pytest
from typer.testing import CliRunner

from apl.cli import app
from apl.report.common import FREE_TEXT_LIMIT

NOTICE = "free-text fields are not masked: review before sharing"
FORMATS = ["md", "json", "sarif"]


def scan(fix, *extra):
    d = fix / "clean"
    args = ["scan", "-c", str(d / "mcp.json"), "-a", str(d / "agent.yaml")]
    return CliRunner().invoke(app, [*args, "-t", str(d / "tools.json"), *extra])


def test_wording_names_the_field():
    assert "justification text" in FREE_TEXT_LIMIT and "not masked" in FREE_TEXT_LIMIT


@pytest.mark.parametrize("fmt", FORMATS)
def test_scan_prints_the_same_line_as_inventory_on_stderr(fix, fmt):
    r = scan(fix, "--anonymise-names", "-f", fmt)
    assert r.exit_code == 0, r.output
    assert NOTICE in r.stderr and NOTICE not in r.stdout


def test_notice_comes_with_out_too(fix, tmp_path):
    r = scan(fix, "--anonymise-names", "--out", str(tmp_path / "r.md"))
    assert NOTICE in r.stderr


def test_no_notice_without_the_flag(fix):
    assert NOTICE not in scan(fix).stderr


def test_no_notice_when_the_scan_fails(fix, tmp_path):
    missing = tmp_path / "missing.json"
    r = CliRunner().invoke(app, ["scan", "-c", str(missing), "--anonymise-names"])
    assert r.exit_code == 2 and NOTICE not in r.stderr


def test_md_limits_section_says_so(fix, tmp_path):
    out = tmp_path / "r.md"
    scan(fix, "--anonymise-names", "--out", str(out))
    text = out.read_text(encoding="utf-8")
    limits = text[text.index("## Assumptions and limits") :]
    assert f"- {FREE_TEXT_LIMIT}" in limits


def test_json_limits_section_says_so(fix, tmp_path):
    out = tmp_path / "r.json"
    scan(fix, "--anonymise-names", "-f", "json", "--out", str(out))
    assert FREE_TEXT_LIMIT in json.loads(out.read_text(encoding="utf-8"))["limits"]["standing"]


def test_sarif_says_so_in_a_notification(fix, tmp_path):
    out = tmp_path / "r.sarif"
    scan(fix, "--anonymise-names", "-f", "sarif", "--out", str(out))
    run = json.loads(out.read_text(encoding="utf-8"))["runs"][0]
    notes = run["invocations"][0]["toolExecutionNotifications"]
    assert {"level": "note", "message": {"text": FREE_TEXT_LIMIT}} in notes


@pytest.mark.parametrize("fmt", FORMATS)
def test_no_limit_line_without_the_flag(fix, tmp_path, fmt):
    out = tmp_path / f"r.{fmt}"
    scan(fix, "-f", fmt, "--out", str(out))
    assert FREE_TEXT_LIMIT not in out.read_text(encoding="utf-8")


def test_justification_really_does_reach_a_report(tmp_path):
    """Pins why the limit exists: this free text prints as written."""
    config, tools, agent = tmp_path / "c.json", tmp_path / "t.json", tmp_path / "a.yaml"
    config.write_text(json.dumps({"mcpServers": {"fs": {"command": "c"}}}), encoding="utf-8")
    tools.write_text(json.dumps({"fs": {"tools": [{"name": "delete_file"}]}}), encoding="utf-8")
    agent.write_text(
        "name: a\npurpose: p\nservers:\n  - server: fs\n    required_capabilities: [read]\n"
        "    justification: Reads the payroll team drive\n",
        encoding="utf-8",
    )
    args = ["scan", "-c", str(config), "-t", str(tools), "-a", str(agent), "--anonymise-names"]
    assert "Reads the payroll team drive" in CliRunner().invoke(app, args).stdout
