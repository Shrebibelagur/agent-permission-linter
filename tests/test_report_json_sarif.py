import json

from typer.testing import CliRunner

from apl.cli import app
from apl.report.json_report import SCHEMA_VERSION, render_json
from apl.report.sarif import render_sarif
from apl.scan import run_scan


def dirty(fix):
    return run_scan(
        [fix / "configs/claude_desktop.json"],
        fix / "agents/release_notes_bot.yaml",
        [fix / "tools/claude_desktop_tools.json"],
    )


def test_json_top_level_schema_is_stable(fix):
    data = json.loads(render_json(dirty(fix)))
    assert list(data) == [
        "schema_version", "tool", "generated_at", "agent", "summary",
        "findings", "not_evaluated", "servers", "limits",
    ]
    assert data["schema_version"] == SCHEMA_VERSION == "1.0"


def test_json_finding_and_skip_shape(fix):
    data = json.loads(render_json(dirty(fix)))
    f = data["findings"][0]
    assert set(f) >= {"id", "rule_id", "severity", "status", "subject", "fix", "confidence",
                      "confidence_reason", "suggested_mappings", "evidence"}
    assert data["summary"]["findings"] == len(data["findings"]) == 5
    assert all(s["reason"].startswith("not evaluated: missing ") for s in data["not_evaluated"])
    assert data["limits"]["low_confidence_tools"][0]["tool"] == "frobnicate"


def test_sarif_structure(fix):
    s = json.loads(render_sarif(dirty(fix)))
    assert s["version"] == "2.1.0" and s["$schema"].endswith("sarif-2.1.0.json")
    run = s["runs"][0]
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert {"APL-001", "APL-002", "APL-007", "APL-010"} <= set(rule_ids)
    results = run["results"]
    assert len(results) == 5
    for r in results:
        assert run["tool"]["driver"]["rules"][r["ruleIndex"]]["id"] == r["ruleId"]
        assert r["level"] in {"error", "warning", "note"}
        uri = r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert "\\" not in uri
        assert r["partialFingerprints"]["aplFindingId/v1"].startswith(r["ruleId"])
    levels = {
        r["locations"][0]["logicalLocations"][0]["fullyQualifiedName"]: r["level"]
        for r in results
    }
    assert levels["github/delete_repository"] == "error"
    assert levels["filesystem/write_file"] == "warning"
    assert levels["graph/frobnicate"] == "note"  # review_required
    notes = run["invocations"][0]["toolExecutionNotifications"]
    assert len(notes) == 6 and all("not evaluated" in n["message"]["text"] for n in notes)


def test_sarif_mappings_are_labelled(fix):
    run = json.loads(render_sarif(dirty(fix)))["runs"][0]
    maps = run["results"][0]["properties"]["suggestedMappings"]
    assert maps and all(m["label"] == "suggested mapping" for m in maps)


def test_cli_json_and_sarif_parse(fix):
    for fmt in ("json", "sarif"):
        r = CliRunner().invoke(app, [
            "scan", "-c", str(fix / "clean/mcp.json"), "-a", str(fix / "clean/agent.yaml"),
            "-t", str(fix / "clean/tools.json"), "-f", fmt,
        ])
        assert r.exit_code == 0, r.output
        json.loads(r.stdout)
