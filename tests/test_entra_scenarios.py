"""End-to-end Entra scenarios over tests/fixtures/graph. One app per scenario, one server each."""

import json
from functools import partial

import pytest
from typer.testing import CliRunner

from apl.cli import app
from apl.collectors.entra import collect_mock
from apl.models import Severity
from apl.report import render
from apl.scan import run_scan


@pytest.fixture
def report(fix):
    d = fix / "entra"
    return run_scan(
        [d / "mcp.json"], tools=[d / "tools.json"], entra=partial(collect_mock, fix / "graph")
    )


def findings_for(report, server):
    return [f for f in report.result.findings if f.subject.startswith(f"{server}/")]


def apl001_ran(report, server):
    return any(e.rule_id == "APL-001" and e.subject == server for e in report.result.evaluated)


def test_over_scoped_mail_app(report):
    """Mail.ReadWrite is granted; every tool on the server only reads."""
    [f] = findings_for(report, "mail")
    assert f.rule_id == "APL-001" and f.status == "violation"
    assert f.severity is Severity.HIGH  # ReadWrite adds delete
    assert f.granted == ["Mail.ReadWrite"] and f.required == ["read"]
    assert f.confidence == 0.9 and "verified" in f.confidence_reason
    assert "(suggested mapping): Mail.Read." in f.fix
    assert all(m.label == "suggested mapping" for m in f.suggested_mappings)
    assert f.evidence[0].source == "entra-mock"
    assert f.evidence[0].pointer.startswith("/servicePrincipals/")


def test_mail_triage_demo_finding_is_pinned(report):
    """The README demo: exact id, severity, confidence and wording."""
    [f] = findings_for(report, "mail")
    assert f.id == "APL-001:d02e76c2cf43"
    assert (f.severity, f.confidence) == (Severity.HIGH, 0.9)
    assert f.confidence_reason == "credential kind verified"
    assert f.fix == (
        "Remove or narrow Mail.ReadWrite: no tool on 'mail' needs delete/write. "
        "Grant the least-privileged permission instead (suggested mapping): Mail.Read."
    )


def test_correctly_scoped_calendar_app(report):
    """Calendars.Read, granted by delegated consent, and read-only tools."""
    assert findings_for(report, "calendar") == []
    assert apl001_ran(report, "calendar")
    assert not [s for s in report.result.skips if s.subject.startswith("calendar/")]


def test_app_with_no_owner_is_reported_without_a_rule(report):
    """No rule covers ownership yet, so it must surface as a warning, not vanish."""
    warning = "files: Entra app orphan-files has no owner"
    assert warning in report.inventory.warnings
    assert findings_for(report, "files") == []  # its scope itself is fine
    assert apl001_ran(report, "files")
    assert warning in render(report, "md")
    assert warning in json.loads(render(report, "json"))["limits"]["parser_warnings"]


def test_owned_apps_do_not_warn(report):
    no_owner = [w for w in report.inventory.warnings if "no owner" in w]
    assert no_owner == ["files: Entra app orphan-files has no owner"]


def test_unknown_scope_is_skipped_with_a_reason(report):
    """`Contoso.Frobnicate` has no mapping; `Mail.Read` on the same app is still evaluated."""
    [s] = [s for s in report.result.skips if s.subject.startswith("custom/")]
    assert s.rule_id == "APL-001"
    assert s.subject == "custom/AZURE_CLIENT_ID/Contoso.Frobnicate"
    assert s.reason == "not evaluated: missing scope mapping"
    assert findings_for(report, "custom") == []
    assert apl001_ran(report, "custom")
    assert "Contoso.Frobnicate" in render(report, "md")


def test_expired_secret_is_reported(report):
    assert "mail: Entra app mail-triage has 1 expired credential(s)" in report.inventory.warnings


def test_mock_data_is_labelled_as_not_a_real_tenant(report):
    assert "not a real tenant" in render(report, "md")


def test_every_format_renders_the_finding(report):
    assert "Mail.ReadWrite" in render(report, "md")
    data = json.loads(render(report, "json"))
    assert data["summary"]["findings"] == 1 and data["summary"]["evaluated"] == 4
    sarif = json.loads(render(report, "sarif"))
    [result] = sarif["runs"][0]["results"]
    assert result["ruleId"] == "APL-001" and result["level"] == "error"
    location = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert location == "entra-mock"


def test_cli_fail_on_high_catches_the_over_scoped_app(fix):
    d = fix / "entra"
    args = ["scan", "-c", str(d / "mcp.json"), "-t", str(d / "tools.json")]
    mock = ["--entra-mock", str(fix / "graph")]
    assert CliRunner().invoke(app, [*args, *mock, "--fail-on", "high"]).exit_code == 1
    assert CliRunner().invoke(app, [*args, *mock]).exit_code == 0


def test_without_entra_apl001_is_skipped_not_passed(fix):
    d = fix / "entra"
    rep = run_scan([d / "mcp.json"], tools=[d / "tools.json"])
    assert rep.result.findings == []
    assert not any(e.rule_id == "APL-001" for e in rep.result.evaluated)
    reasons = {s.reason for s in rep.result.skips if s.rule_id == "APL-001"}
    assert reasons == {"not evaluated: missing granted scopes (run with --entra or --entra-mock)"}
