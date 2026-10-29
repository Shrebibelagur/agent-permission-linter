"""Data shared by all report formats: limits of this scan and display helpers."""

from __future__ import annotations

from pydantic import BaseModel, Field

from apl.models import Severity
from apl.rules.base import is_uncertain
from apl.scan import SEVERITY_ORDER, ScanReport

# Shown in every report. Kept short; details live in docs/ASSUMPTIONS.md.
STANDING_LIMITS = [
    "Offline analysis: tool lists come from saved tools/list files; no server was contacted.",
    "Client config formats are client conventions, not MCP spec (A1).",
    "Tool descriptions are never used to classify; annotations can only add capabilities (S5, S6).",
    "Framework references are suggested mappings, not compliance claims.",
    "Granted scopes (APL-001) need the Phase 3 Entra collector; offline runs skip it.",
]


class UnverifiedFormat(BaseModel):
    server: str
    source: str
    detail: str


class LowConfidenceTool(BaseModel):
    server: str
    tool: str
    confidence: float
    note: str


class Limits(BaseModel):
    unverified_formats: list[UnverifiedFormat] = Field(default_factory=list)
    low_confidence_tools: list[LowConfidenceTool] = Field(default_factory=list)
    parser_warnings: list[str] = Field(default_factory=list)
    standing: list[str] = Field(default_factory=lambda: list(STANDING_LIMITS))


def display_path(s: str) -> str:
    return s.replace("\\", "/")


def collect_limits(report: ScanReport) -> Limits:
    lim = Limits(parser_warnings=[display_path(w) for w in report.inventory.warnings])
    for srv in report.inventory.servers:
        src = display_path(srv.evidence.source)
        if srv.format_status == "unverified":
            lim.unverified_formats.append(
                UnverifiedFormat(
                    server=srv.name,
                    source=src,
                    detail=f"{srv.source_format}: not in current official client docs (A3)",
                )
            )
        if srv.auto_approve_pointer and srv.auto_approve_pointer.endswith("/alwaysAllow"):
            lim.unverified_formats.append(
                UnverifiedFormat(
                    server=srv.name,
                    source=src,
                    detail="alwaysAllow (Roo Code) auto-approve key: unverified (R7)",
                )
            )
        for t in srv.tools:
            if is_uncertain(t):
                note = "; ".join(t.classification_flags) or "low-confidence classification"
                lim.low_confidence_tools.append(
                    LowConfidenceTool(
                        server=srv.name,
                        tool=t.name,
                        confidence=t.classification_confidence,
                        note=note,
                    )
                )
    return lim


NOTHING_EVALUATED = "Nothing could be evaluated. See Not evaluated."


def outcome(report: ScanReport) -> tuple[str, str | None]:
    """("nothing_evaluated" | "no_findings" | "findings", sentence or None).

    Never claim "no findings" when nothing ran: an all-skipped scan is not a clean scan.
    """
    n = len(report.result.evaluated)
    m = len(report.result.skips)
    if report.result.findings:
        return "findings", None
    if n == 0:
        return "nothing_evaluated", NOTHING_EVALUATED
    checks = "check that ran" if n == 1 else "checks that ran"
    return "no_findings", f"No findings among the {n} {checks} ({m} not evaluated)."


def summary_counts(report: ScanReport) -> dict:
    sev = {s.value: 0 for s in sorted(Severity, key=lambda s: -SEVERITY_ORDER[s])}
    review = dict(sev)
    for f in report.result.findings:
        (review if f.status == "review_required" else sev)[f.severity.value] += 1
    kind, message = outcome(report)
    return {
        "findings": len(report.result.findings),
        "violations_by_severity": sev,
        "review_required_by_severity": review,
        "not_evaluated": len(report.result.skips),
        "evaluated": len(report.result.evaluated),
        "skipped": len(report.result.skips),
        "outcome": kind,
        "message": message,
    }
