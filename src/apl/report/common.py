"""Data shared by all report formats: limits of this scan and display helpers."""

from __future__ import annotations

from pydantic import BaseModel, Field

from apl import idmask
from apl.models import Evidence, Inventory, Severity
from apl.redact import REDACTED
from apl.rules.base import is_uncertain
from apl.scan import SEVERITY_ORDER, ScanReport

# Shown in every report. Kept short; details live in docs/ASSUMPTIONS.md.
STANDING_LIMITS = [
    "Offline analysis: tool lists come from saved tools/list files; no server was contacted.",
    "Client config formats are client conventions, not MCP spec (A1).",
    "Tool descriptions are never used to classify; annotations can only add capabilities (S5, S6).",
    "Framework references are suggested mappings, not compliance claims.",
    "Granted scopes (APL-001) need Entra data (--entra or --entra-mock); otherwise skipped.",
]
REAL_IDS_WARNING = "WARNING: this report contains real identifiers"
REAL_URLS_WARNING = "WARNING: this report contains full URLs"
FREE_TEXT_LIMIT = "Free-text fields (justification text) are not masked: review before sharing."
ENTRA_LIMITS = {
    "mock": "Entra data came from saved fixtures (--entra-mock), not a real tenant.",
    "live": "Entra data was read from Microsoft Graph during this scan (GET only).",
}


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


def _masked_evidence(e: Evidence) -> Evidence:
    return Evidence(
        source=idmask.mask_names(e.source),
        pointer=idmask.mask_names(e.pointer) if e.pointer else None,
        note=idmask.mask_names(e.note) if e.note else None,
    )


def anonymised(inv: Inventory) -> Inventory:
    """Names in the inventory, replaced before rendering: renderers escape text, and an escaped
    name (`R&amp;D`) no longer matches. Findings and skips are masked when they are made."""
    copy = inv.model_copy(deep=True)
    copy.warnings = [idmask.mask_names(w) for w in copy.warnings]
    if copy.agent:
        copy.agent.name = idmask.mask_names(copy.agent.name)
    for srv in copy.servers:
        srv.name = idmask.mask_names(srv.name)
        srv.evidence = _masked_evidence(srv.evidence)
    return copy


def _placeholder_args(args: list[str]) -> list[str]:
    """`[arg-1]`, `[arg-2]`, per server. A placeholder, not a pseudonym: an arg we did not
    recognise as a secret may still be one, and secrets are never hashed. A redacted arg stays
    as it is: it holds no value, and says one was removed."""
    out: list[str] = []
    count = 0
    for arg in args:
        if REDACTED in arg:
            out.append(arg)
        else:
            count += 1
            out.append(f"[arg-{count}]")
    return out


def inventory_data(inv: Inventory) -> dict:
    """The JSON-like inventory for `apl inventory`. Commands, args and urls go by field, as
    registering `npx` would replace that word everywhere. They become placeholders, not
    pseudonyms: a webhook url holds its secret in the path, and secrets are never hashed.
    N is the server's position, so `[cmd-2]` and `[url-2]` are the same server."""
    data = inv.model_dump(mode="json", exclude_none=True)
    if not idmask.anonymising_names():
        return data
    if "owner" in data.get("agent", {}):
        data["agent"]["owner"] = idmask.pseudonym("owner-name", data["agent"]["owner"])
    for index, srv in enumerate(data["servers"], start=1):
        if "command" in srv:
            srv["command"] = f"[cmd-{index}]"
        if "url" in srv:
            srv["url"] = f"[url-{index}]"
        srv["args"] = _placeholder_args(srv.get("args", []))
    return idmask.mask_names_obj(data)


def display_path(s: str) -> str:
    return s.replace("\\", "/")


def collect_limits(report: ScanReport) -> Limits:
    lim = Limits(parser_warnings=[display_path(w) for w in report.inventory.warnings])
    if report.inventory.entra_source:
        lim.standing.append(ENTRA_LIMITS[report.inventory.entra_source])
    if idmask.anonymising_names():
        lim.standing.append(FREE_TEXT_LIMIT)
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
