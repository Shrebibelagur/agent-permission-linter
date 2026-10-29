"""APL-001 over-scoped permission: a granted scope is broader than any tool on the server needs.

For each granted scope we take its *distinguishing* capabilities: what it adds over the
least-privileged variant. Example: `Files.ReadWrite.All` adds write+delete over `Files.Read.All`.
If no classified tool on the server needs any of them, the scope is over-scoped.

Inputs: `CredentialRef.granted_scopes`, which static configs do not contain (Phase 3 fills it),
and the server's classified tools. Missing either produces a visible skip.
Scope tables: docs/ASSUMPTIONS.md R2 (Graph) and R3 (GitHub).
"""

from __future__ import annotations

import re

from apl.models import Capability, Inventory, RuleResult, Severity
from apl.rules.base import ASI03, LLM06, is_uncertain, kind_confidence, make_finding, skip

RULE_ID = "APL-001"
C = Capability

# Graph: {resource}.{operation}[.{constraint}]. "ReadWrite" = read, create, update and delete.
_GRAPH = re.compile(r"^[A-Za-z]+\.(?P<op>[A-Za-z]+)(?:\.[A-Za-z]+)?$")
_GRAPH_OPS: dict[str, frozenset[Capability]] = {
    "Read": frozenset({C.READ}),
    "ReadBasic": frozenset({C.READ}),
    "ReadWrite": frozenset({C.WRITE, C.DELETE}),
    "Create": frozenset({C.WRITE}),
    "Manage": frozenset({C.WRITE, C.DELETE}),
    "Migrate": frozenset({C.WRITE}),
    "FullControl": frozenset({C.WRITE, C.DELETE}),
    "AccessAsUser": frozenset({C.WRITE, C.DELETE}),
}
# GitHub OAuth/PAT (classic) scopes.
_GITHUB: dict[str, frozenset[Capability]] = {
    "repo": frozenset({C.WRITE}),
    "public_repo": frozenset({C.WRITE}),
    "delete_repo": frozenset({C.DELETE}),
    "workflow": frozenset({C.WRITE, C.EXECUTE}),  # workflow files run code in CI
    "admin:org": frozenset({C.WRITE, C.DELETE}),
    "admin:repo_hook": frozenset({C.WRITE, C.DELETE}),
    "read:org": frozenset({C.READ}),
    "read:user": frozenset({C.READ}),
    "user": frozenset({C.WRITE}),
    "gist": frozenset({C.WRITE}),
    "write:packages": frozenset({C.WRITE}),
    "delete:packages": frozenset({C.DELETE}),
}


def scope_capabilities(scope: str) -> frozenset[Capability] | None:
    """Distinguishing capabilities of a scope, or None if we have no mapping for it."""
    if scope in _GITHUB:
        return _GITHUB[scope]
    m = _GRAPH.match(scope)
    if m:
        return _GRAPH_OPS.get(m.group("op"))
    return None


def check(inv: Inventory) -> RuleResult:
    res = RuleResult()
    for srv in inv.servers:
        creds = srv.credentials
        if not creds:
            continue  # nothing granted to over-scope
        if not srv.tools:
            res.skips.append(skip(RULE_ID, srv.name, "tool list"))
            continue
        scoped = [c for c in creds if c.granted_scopes is not None]
        if not scoped:
            res.skips.append(
                skip(RULE_ID, srv.name, "granted scopes (needs Phase 3 Entra collector)")
            )
            continue
        res.ran(RULE_ID, srv.name)
        needed = set().union(*(t.capabilities for t in srv.tools)) - {C.UNKNOWN}
        uncertain = [t.name for t in srv.tools if is_uncertain(t)]
        for cred in scoped:
            label = cred.env_var or cred.header or "credential"
            over: list[tuple[str, frozenset[Capability]]] = []
            for scope in cred.granted_scopes or []:
                caps = scope_capabilities(scope)
                if caps is None:
                    res.skips.append(
                        skip(RULE_ID, f"{srv.name}/{label}/{scope}", "scope mapping")
                    )
                elif not caps & needed:
                    over.append((scope, caps))
            if not over:
                continue
            excess = set().union(*(caps for _, caps in over))
            severity = Severity.HIGH if excess & {C.DELETE, C.EXECUTE} else Severity.MEDIUM
            conf, why = kind_confidence(cred.kind_source)
            conf *= 0.9
            status = "violation"
            if uncertain:
                status = "review_required"
                conf = min(conf, 0.4)
                why += f"; {len(uncertain)} unclassified/low-confidence tool(s) may need it"
            scopes = [s for s, _ in over]
            res.findings.append(
                make_finding(
                    RULE_ID,
                    "Granted scope broader than any tool needs",
                    severity,
                    f"{srv.name}/{label}",
                    granted=scopes,
                    required=sorted(c.value for c in needed) or ["(no classified tool)"],
                    evidence=[cred.evidence] if cred.evidence else [],
                    fix=(
                        f"Remove or narrow {', '.join(scopes)}: no tool on '{srv.name}' needs "
                        f"{'/'.join(sorted(c.value for c in excess))}. Grant the least-privileged "
                        "scope (e.g. a Read variant) instead."
                    ),
                    confidence=conf,
                    confidence_reason=why,
                    mappings=[LLM06, ASI03],
                    status=status,
                )
            )
    return res
