"""APL-010 no human approval gate on destructive or high-impact tools.

Evidence is the client's auto-approve list (`MCPServer.auto_approve`, ASSUMPTION R7). A tool on
that list runs without asking the user. It is flagged when it is high-impact:
  * delete or execute capability (destructiveHint=true already maps to delete), or
  * unclassified: it counts as high-impact until someone reviews it.
If agent.yaml declares `approval_gate: true` for the server, an auto-approved high-impact tool
contradicts that declaration and severity goes up one level.
"""

from __future__ import annotations

from apl.models import Capability, Evidence, Inventory, RuleResult, Severity, Tool
from apl.rules.base import LLM06, make_finding, skip

RULE_ID = "APL-010"
C = Capability
_HIGH_IMPACT = {C.DELETE, C.EXECUTE}
_BUMP = {Severity.MEDIUM: Severity.HIGH, Severity.HIGH: Severity.CRITICAL}


def _impact(t: Tool) -> tuple[Severity, float, str] | None:
    if t.capabilities & _HIGH_IMPACT:
        caps = "/".join(sorted(c.value for c in t.capabilities & _HIGH_IMPACT))
        return Severity.HIGH, t.classification_confidence, f"classified {caps}"
    if C.UNKNOWN in t.capabilities:
        return Severity.MEDIUM, 0.5, "unclassified: counted as high-impact until reviewed"
    return None


def check(inv: Inventory) -> RuleResult:
    res = RuleResult()
    gated = {p.server for p in inv.agent.servers if p.approval_gate} if inv.agent else set()
    for srv in inv.servers:
        if srv.auto_approve is None:
            res.skips.append(
                skip(RULE_ID, srv.name, "auto-approve list (no autoApprove/alwaysAllow in config)")
            )
            continue
        if not srv.auto_approve:
            continue  # every call asks the user
        if not srv.tools:
            res.skips.append(skip(RULE_ID, srv.name, "tool list"))
            continue
        approved = set(srv.auto_approve)
        for t in srv.tools:
            if t.name not in approved:
                continue
            impact = _impact(t)
            if impact is None:
                continue
            severity, conf, why = impact
            contradicted = srv.name in gated
            if contradicted:
                severity = _BUMP.get(severity, severity)
                why += "; contradicts approval_gate: true in agent.yaml"
            ev = Evidence(
                source=srv.evidence.source,
                pointer=srv.auto_approve_pointer,
                note=f"'{t.name}' is auto-approved",
            )
            res.findings.append(
                make_finding(
                    RULE_ID,
                    "High-impact tool runs without human approval",
                    severity,
                    f"{srv.name}/{t.name}",
                    granted=["auto-approved", *sorted(c.value for c in t.capabilities)],
                    required=["human approval for delete/execute/unclassified tools"],
                    evidence=[ev],
                    fix=(
                        f"Remove '{t.name}' from the auto-approve list for '{srv.name}' so each "
                        "call needs user confirmation."
                    ),
                    confidence=conf,
                    confidence_reason=f"auto-approve list is direct config evidence; {why}",
                    mappings=[LLM06],
                )
            )
    return res
