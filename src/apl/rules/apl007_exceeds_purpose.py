"""APL-007 tool capability exceeds declared purpose.

Declared purpose per server comes from agent.yaml: `required_capabilities` and/or
`required_tools`. A tool listed in `required_tools` is declared, so it is accepted. Any other tool
whose capabilities go beyond the declared set exceeds the purpose. If only `required_tools` is
given, the declared set is the union of what those tools can do.

Classifier confidence is respected: unclassified tools, or tools with confidence <= 0.5, never get
a hard "exceeds purpose" verdict. They get a `review_required` finding instead.
"""

from __future__ import annotations

from apl.models import Capability, Inventory, RuleResult, Severity, Tool
from apl.rules.base import LLM06, is_uncertain, make_finding, skip

RULE_ID = "APL-007"
C = Capability


def _severity(excess: set[Capability]) -> Severity:
    if excess & {C.DELETE, C.EXECUTE}:
        return Severity.HIGH
    if excess & {C.WRITE, C.NETWORK}:
        return Severity.MEDIUM
    return Severity.LOW


def _caps(caps: set[Capability]) -> list[str]:
    return sorted(c.value for c in caps)


def check(inv: Inventory) -> RuleResult:
    res = RuleResult()
    if inv.agent is None:
        res.skips.append(skip(RULE_ID, "agent", "agent.yaml"))
        return res
    purposes = {p.server: p for p in inv.agent.servers}
    for srv in inv.servers:
        purpose = purposes.get(srv.name)
        if purpose is None:
            res.skips.append(skip(RULE_ID, srv.name, "declared purpose in agent.yaml"))
            continue
        if not srv.tools:
            res.skips.append(skip(RULE_ID, srv.name, "tool list"))
            continue
        required_tools = set(purpose.required_tools or [])
        declared = set(purpose.required_capabilities)
        if not declared:
            if purpose.required_tools is None:
                res.skips.append(
                    skip(RULE_ID, srv.name, "agent.yaml required_tools or required_capabilities")
                )
                continue
            for t in srv.tools:
                if t.name in required_tools and not is_uncertain(t):
                    declared |= t.capabilities
        res.ran(RULE_ID, srv.name)
        for t in srv.tools:
            if t.name in required_tools:
                continue
            f = _check_tool(srv.name, t, declared, purpose.justification)
            if f:
                res.findings.append(f)
    return res


def _check_tool(server: str, t: Tool, declared: set[Capability], justification: str | None):
    excess = t.capabilities - declared - {C.UNKNOWN}
    subject = f"{server}/{t.name}"
    common = {
        "granted": _caps(t.capabilities),
        "required": _caps(declared),
        "mappings": [LLM06],
    }
    if is_uncertain(t):
        if not excess and C.UNKNOWN not in t.capabilities:
            return None  # even the widest plausible reading fits the purpose
        return make_finding(
            RULE_ID,
            "Review required: tool capability could not be established",
            Severity.LOW,
            subject,
            status="review_required",
            fix=(
                f"Check what '{t.name}' does. If '{server}' does not need it, remove or disable "
                "it. If it does, add it to required_tools in agent.yaml."
            ),
            confidence=t.classification_confidence,
            confidence_reason="unclassified or low-confidence tool name: "
            + "; ".join(t.classification_reasons[:3]),
            **common,
        )
    if not excess:
        return None
    why = "; ".join(t.classification_reasons[:3])
    return make_finding(
        RULE_ID,
        "Tool capability exceeds declared purpose",
        _severity(excess),
        subject,
        fix=(
            f"Disable or remove '{t.name}' ({'/'.join(_caps(excess))} not in the declared "
            f"purpose{': ' + justification if justification else ''}), or use a server build "
            "without it. If the agent really needs it, declare it in agent.yaml."
        ),
        confidence=t.classification_confidence,
        confidence_reason=f"classifier: {why}",
        **common,
    )
