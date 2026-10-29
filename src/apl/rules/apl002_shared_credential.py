"""APL-002 maker-mode / shared credential: one fixed token serves many invokers.

A credential in a static client config is the same for everyone who invokes that agent instance.
When agent.yaml says `invokers: multiple`, every invoker acts with that one identity, so their own
permissions are never checked. Per-invoker auth (an OAuth flow the client runs per user) leaves no
credential in the config, so it is not flagged.

Severity by kind: a person's own token (PAT, user refresh token) is maker-mode: every invoker
acts as that person (high). An app identity or API key is a shared identity (medium).
"""

from __future__ import annotations

from apl.models import CredentialKind, CredentialRef, Inventory, RuleResult, Severity
from apl.rules.base import ASI03, LLM06, kind_confidence, make_finding, skip

RULE_ID = "APL-002"
_PERSONAL = {CredentialKind.PAT, CredentialKind.USER_DELEGATED}


def _is_identifier_only(c: CredentialRef) -> bool:
    """A client/app ID kept for Entra linking (A9): an identifier, not a token."""
    return c.entra_app_id is not None and not c.inline_secret_detected


def check(inv: Inventory) -> RuleResult:
    res = RuleResult()
    if inv.agent is None:
        res.skips.append(skip(RULE_ID, "agent", "agent.yaml"))
        return res
    if inv.agent.invokers is None:
        res.skips.append(skip(RULE_ID, inv.agent.name, "agent.yaml invokers"))
        return res
    res.ran(RULE_ID, inv.agent.name)
    if inv.agent.invokers != "multiple":
        return res
    for srv in inv.servers:
        tokens = [c for c in srv.credentials if not _is_identifier_only(c)]
        if not tokens:
            continue
        personal = [c for c in tokens if c.kind in _PERSONAL]
        severity = Severity.HIGH if personal else Severity.MEDIUM
        basis = personal or tokens
        conf, why = min((kind_confidence(c.kind_source) for c in basis), key=lambda x: x[0])
        names = [c.env_var or c.header or "inline secret" for c in tokens]
        kinds = sorted({c.kind.value for c in tokens})
        title = (
            "Maker-mode: one person's token serves every invoker"
            if personal
            else "Shared credential: one fixed identity serves every invoker"
        )
        res.findings.append(
            make_finding(
                RULE_ID,
                title,
                severity,
                srv.name,
                granted=[f"fixed {k} credential" for k in kinds],
                required=["per-invoker identity (agent.yaml invokers: multiple)"],
                evidence=[c.evidence for c in tokens if c.evidence],
                fix=(
                    f"Replace {', '.join(names)} with per-invoker authorization (OAuth "
                    "delegated / on-behalf-of) so each call carries the invoker's identity, "
                    "or restrict the agent to a single owner."
                ),
                confidence=0.9 * conf,
                confidence_reason=f"{why}; static config credential is fixed per agent instance",
                mappings=[ASI03, LLM06],
            )
        )
    return res
