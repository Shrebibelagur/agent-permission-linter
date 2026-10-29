from apl.models import Finding, Severity
from apl.report.markdown import render_markdown
from apl.scan import run_scan


def dirty(fix):
    return run_scan(
        [fix / "configs/claude_desktop.json"],
        fix / "agents/release_notes_bot.yaml",
        [fix / "tools/claude_desktop_tools.json"],
    )


def test_sections_present(fix):
    md = render_markdown(dirty(fix))
    for heading in ("## Summary", "## Findings", "## Fixes", "## Not evaluated",
                    "## Assumptions and limits"):
        assert heading in md


def test_summary_counts_and_table(fix):
    md = render_markdown(dirty(fix))
    assert "| **total** | **4** | **1** |" in md
    assert "| ID | Severity | Status | Confidence | Tool / server | Title |" in md
    assert "`github/delete_repository`" in md and "| high | violation | 0.90 |" in md


def test_every_skip_listed_with_reason(fix):
    rep = dirty(fix)
    md = render_markdown(rep)
    assert rep.result.skips
    for s in rep.result.skips:
        assert s.reason in md


def test_limits_footer(fix):
    md = render_markdown(dirty(fix))
    footer = md.split("## Assumptions and limits", 1)[1]
    assert "`frobnicate`" in footer and "unclassified: review required" in footer
    assert "suggested mappings" in footer.lower()


def test_unverified_format_listed(fix):
    md = render_markdown(run_scan([fix / "configs/vscode_settings.json"]))
    assert "vscode-settings: not in current official client docs" in md


def test_findings_sorted_by_severity(fix):
    md = render_markdown(dirty(fix))
    table = md.split("## Findings", 1)[1].split("## Fixes", 1)[0]
    sev = [row.split("|")[2].strip() for row in table.splitlines() if row.startswith("| `")]
    order = ["critical", "high", "medium", "low", "info"]
    assert sev == sorted(sev, key=order.index)


def test_untrusted_text_escaped(fix):
    rep = run_scan([fix / "clean/mcp.json"])
    rep.result.findings = [
        Finding(id="X:1", rule_id="X", title="t", severity=Severity.LOW,
                subject="srv/evil|<script>`x`\n# heading", fix="f", confidence=1,
                confidence_reason="r")
    ]
    md = render_markdown(rep)
    assert "<script>" not in md and "\n# heading" not in md
    assert "evil\\|&lt;script>" in md


def test_leading_heading_or_quote_escaped(fix):
    from apl.report.markdown import _esc

    assert _esc("# x") == "\\# x" and _esc("> y") == "\\> y" and _esc("a -> b") == "a -> b"


def test_partial_evaluation_wording(fix):
    d = fix / "clean"
    md = render_markdown(run_scan([d / "mcp.json"], d / "agent.yaml", [d / "tools.json"]))
    sentence = "No findings among the 3 checks that ran (3 not evaluated)."
    findings = md.split("## Findings", 1)[1].split("## Fixes", 1)[0]
    assert sentence in findings
    assert "Checks: 3 evaluated, 3 not evaluated" in md
    assert "Nothing to fix among the checks that ran." in md
    assert "No findings." not in md and "Nothing to fix." not in md


def test_nothing_evaluated_wording(fix):
    # config only: no agent.yaml, no tools -> every rule skips
    md = render_markdown(run_scan([fix / "clean/mcp.json"]))
    summary = md.split("## Findings", 1)[0]
    findings = md.split("## Findings", 1)[1].split("## Fixes", 1)[0]
    assert "Nothing could be evaluated. See Not evaluated." in findings
    assert "Checks: 0 evaluated" in summary
    assert "No findings" not in md
    assert "Nothing to fix" not in md
    assert "| APL-007 | `agent` | not evaluated: missing agent.yaml |" in md


def test_singular_check_wording(fix):
    rep = run_scan([fix / "clean/mcp.json"])
    rep.result.ran("APL-002", "bot")
    md = render_markdown(rep)
    assert "No findings among the 1 check that ran (" in md
