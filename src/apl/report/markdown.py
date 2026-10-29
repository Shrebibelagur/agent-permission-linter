"""Markdown report. Untrusted strings (tool names, notes) are escaped; all text is redacted."""

from __future__ import annotations

from apl import __version__
from apl.redact import redact
from apl.report.common import collect_limits, display_path, summary_counts
from apl.scan import ScanReport


def _esc(s: object) -> str:
    """Make a string safe inside a table cell or inline text: no pipes, newlines or raw HTML."""
    text = str(s).replace("\r", " ").replace("\n", " ")
    for a, b in (("&", "&amp;"), ("<", "&lt;"), ("|", "\\|"), ("`", "'")):
        text = text.replace(a, b)
    return "\\" + text if text.startswith((">", "#")) else text


def _code(s: object) -> str:
    return f"`{_esc(s)}`"


def render_markdown(report: ScanReport) -> str:
    inv = report.inventory
    counts = summary_counts(report)
    findings = report.sorted_findings()
    limits = collect_limits(report)
    out: list[str] = ["# Agent Permission Linter report", ""]
    agent = _esc(inv.agent.name) if inv.agent else "none (no agent.yaml given)"
    out += [
        f"- **Agent:** {agent}",
        f"- **Generated:** {inv.generated_at.strftime('%Y-%m-%dT%H:%M:%SZ')}",
        f"- **apl version:** {__version__}",
        f"- **Servers scanned:** {len(inv.servers)}",
        "",
        "## Summary",
        "",
        "| Severity | Violations | Review required |",
        "|---|---:|---:|",
    ]
    for sev, n in counts["violations_by_severity"].items():
        out.append(f"| {sev} | {n} | {counts['review_required_by_severity'][sev]} |")
    n_viol = sum(counts["violations_by_severity"].values())
    n_rev = sum(counts["review_required_by_severity"].values())
    out += [
        f"| **total** | **{n_viol}** | **{n_rev}** |",
        "",
        f"Checks: {counts['evaluated']} evaluated, {counts['skipped']} not evaluated; "
        "see [Not evaluated](#not-evaluated).",
        "",
    ]
    if counts["message"]:
        out += [f"**{counts['message']}**", ""]
    out += ["## Findings", ""]
    if findings:
        out += [
            "| ID | Severity | Status | Confidence | Tool / server | Title |",
            "|---|---|---|---:|---|---|",
        ]
        for f in findings:
            out.append(
                f"| {_code(f.id)} | {f.severity.value} | {f.status} | {f.confidence:.2f} | "
                f"{_code(f.subject)} | {_esc(f.title)} |"
            )
    else:
        out.append(counts["message"])
    out += ["", "## Fixes", ""]
    if counts["outcome"] == "nothing_evaluated":
        out += ["No fixes can be suggested: nothing could be evaluated.", ""]
    elif counts["outcome"] == "no_findings":
        out += ["Nothing to fix among the checks that ran.", ""]
    for f in findings:
        out += [f"### {_esc(f.id)}: {_esc(f.subject)}", "", _esc(f.fix), ""]
        out.append(f"- Confidence {f.confidence:.2f}: {_esc(f.confidence_reason)}")
        if f.granted or f.required:
            out.append(
                f"- Granted: {_esc(', '.join(f.granted))}; required: {_esc(', '.join(f.required))}"
            )
        for e in f.evidence:
            where = _code(display_path(e.source)) + (f" {_code(e.pointer)}" if e.pointer else "")
            out.append(f"- Evidence: {where}" + (f": {_esc(e.note)}" if e.note else ""))
        for m in f.suggested_mappings:
            out.append(f"- {m.label.capitalize()}: [{_esc(m.id)} {_esc(m.title)}]({m.url})")
        out.append("")
    out += ["## Not evaluated", ""]
    if report.result.skips:
        out += ["| Rule | Subject | Reason |", "|---|---|---|"]
        for s in report.result.skips:
            out.append(f"| {s.rule_id} | {_code(s.subject)} | {_esc(s.reason)} |")
    else:
        out.append("Every rule was evaluated.")
    out += ["", "## Assumptions and limits", "", "**Unverified formats**", ""]
    if limits.unverified_formats:
        out += [
            f"- {_code(u.server)} in {_code(u.source)}: {_esc(u.detail)}"
            for u in limits.unverified_formats
        ]
    else:
        out.append("- None in this scan.")
    out += ["", "**Low-confidence classifications**", ""]
    if limits.low_confidence_tools:
        out += ["| Server | Tool | Confidence | Note |", "|---|---|---:|---|"]
        out += [
            f"| {_code(t.server)} | {_code(t.tool)} | {t.confidence:.2f} | {_esc(t.note)} |"
            for t in limits.low_confidence_tools
        ]
    else:
        out.append("- None in this scan.")
    if limits.parser_warnings:
        out += ["", "**Parser warnings**", ""]
        out += [f"- {_esc(w)}" for w in limits.parser_warnings]
    out += ["", "**Always true for this version**", ""]
    out += [f"- {_esc(s)}" for s in limits.standing]
    out.append("")
    return redact("\n".join(out))
