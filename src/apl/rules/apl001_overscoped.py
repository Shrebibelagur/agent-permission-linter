"""APL-001 over-scoped permission: a granted scope is broader than any tool on the server needs.

For each granted scope we take its *distinguishing* capabilities: what it adds over the
least-privileged variant. Example: `Files.ReadWrite.All` adds write+delete over `Files.Read.All`.
If no tool on the server needs any of them, the scope is over-scoped.

Tools count differently. A tool classified with confidence >= 0.6 gives a confident need. Anything
else gives only a possible need: a `search_mail(text)` that may write, or an unclassified tool,
which could need anything. A scope with a confident need gets no finding. One with only a possible
need is review_required, naming the tools. One with neither is a violation. A low-confidence tool
must never make a scope look justified: that let one `text` parameter hide a finding (E7).

Inputs: `CredentialRef.granted_scopes`, which static configs do not contain (the Entra collector
fills it), and the server's classified tools. Missing either produces a visible skip.
Scope tables: docs/ASSUMPTIONS.md R2 (Graph) and R3 (GitHub).
"""

from __future__ import annotations

import re

from apl.models import Capability, Finding, Inventory, RuleResult, Severity, Tool
from apl.rules.base import ASI03, LLM06, kind_confidence, make_finding, skip
from apl.scopemap import (
    LABEL,
    NO_DELETE,
    UNVERIFIED_CONFIDENCE,
    UNVERIFIED_DELETE,
    suggest_replacements,
)

RULE_ID = "APL-001"
C = Capability
CONFIDENT_NEED = 0.6  # the lowest confidence that may justify a scope; see the module docstring
REVIEW_CONFIDENCE = 0.4
MAX_NAMED_TOOLS = 5

# Graph: {resource}.{operation}[.{constraint}]. "ReadWrite" = read, create, update and delete,
# except permissions the docs show otherwise (scopemap.NO_DELETE).
_GRAPH = re.compile(r"^[A-Za-z]+\.(?P<op>[A-Za-z]+)(?:\.[A-Za-z]+)?$")
_GRAPH_OPS: dict[str, frozenset[Capability]] = {
    "Read": frozenset({C.READ}),
    "ReadBasic": frozenset({C.READ}),
    "ReadWrite": frozenset({C.WRITE, C.DELETE}),
    "Create": frozenset({C.WRITE}),
    "Send": frozenset({C.NETWORK}),
    "DeleteRestore": frozenset({C.DELETE}),
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
    if not m:
        return None
    caps = _GRAPH_OPS.get(m.group("op"))
    return caps - {C.DELETE} if caps and scope in NO_DELETE else caps


def _narrower(scopes: list[str], needed: set[Capability]) -> str:
    found = [s for scope in scopes for s in suggest_replacements(scope, needed)]
    if found:
        unique = ", ".join(dict.fromkeys(found))
        return f"Grant the least-privileged permission instead ({LABEL}): {unique}."
    return "Grant the least-privileged scope (e.g. a Read variant) instead."


def _is_confident(tool: Tool) -> bool:
    return C.UNKNOWN not in tool.capabilities and tool.classification_confidence >= CONFIDENT_NEED


def _may_need(tool: Tool, caps: frozenset[Capability]) -> bool:
    return C.UNKNOWN in tool.capabilities or bool(tool.capabilities & caps)


def _names(tools: list[str]) -> str:
    shown = ", ".join(tools[:MAX_NAMED_TOOLS])
    more = len(tools) - MAX_NAMED_TOOLS
    return f"{shown} and {more} more" if more > 0 else shown


def _finding(
    server: str,
    label: str,
    cred,
    over: list[tuple[str, frozenset[Capability]]],
    confident: set[Capability],
    low_tools: list[str] | None = None,
) -> Finding:
    """`low_tools` set = review_required: only those tools may need `over`."""
    excess = set().union(*(caps for _, caps in over))
    severity = Severity.HIGH if excess & {C.DELETE, C.EXECUTE} else Severity.MEDIUM
    conf, why = kind_confidence(cred.kind_source)
    conf *= 0.9
    deleters = {s for s, caps in over if C.DELETE in caps}
    if deleters and deleters <= UNVERIFIED_DELETE:  # R2: delete rests on unclear docs
        conf = min(conf, UNVERIFIED_CONFIDENCE)
        why += f"; delete unverified in Graph docs for {', '.join(sorted(deleters))}"
    scopes = [s for s, _ in over]
    wanted = "/".join(sorted(c.value for c in excess))
    narrow = _narrower(scopes, confident)
    fix = f"Remove or narrow {', '.join(scopes)}: no tool on '{server}' needs {wanted}. {narrow}"
    title = "Granted scope broader than any tool needs"
    subject = f"{server}/{label}"
    status = "violation"
    if low_tools:
        status = "review_required"
        subject += "/low-confidence"
        title = "Granted scope may be broader than any tool needs"
        conf = min(conf, REVIEW_CONFIDENCE)
        named = _names(low_tools)
        why += f"; only unclassified/low-confidence tool(s) may need it: {named}"
        fix = (
            f"Check whether {named} really needs {wanted}. If not, remove or narrow "
            f"{', '.join(scopes)}. {narrow}"
        )
    return make_finding(
        RULE_ID,
        title,
        severity,
        subject,
        granted=scopes,
        required=sorted(c.value for c in confident) or ["(no classified tool)"],
        evidence=[cred.evidence] if cred.evidence else [],
        fix=fix,
        confidence=conf,
        confidence_reason=why,
        mappings=[LLM06, ASI03],
        status=status,
    )


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
            why = (
                "granted scopes (no credential linked to an Entra app)"
                if inv.entra_source
                else "granted scopes (run with --entra or --entra-mock)"
            )
            res.skips.append(skip(RULE_ID, srv.name, why))
            continue
        res.ran(RULE_ID, srv.name)
        low = [t for t in srv.tools if not _is_confident(t)]
        confident = set().union(*(t.capabilities for t in srv.tools if _is_confident(t)))
        for cred in scoped:
            label = cred.env_var or cred.header or "credential"
            over: list[tuple[str, frozenset[Capability]]] = []
            possible: list[tuple[str, frozenset[Capability]]] = []
            low_tools: dict[str, None] = {}
            for scope in cred.granted_scopes or []:
                caps = scope_capabilities(scope)
                if caps is None:
                    res.skips.append(
                        skip(RULE_ID, f"{srv.name}/{label}/{scope}", "scope mapping")
                    )
                elif not caps & confident:
                    who = [t.name for t in low if _may_need(t, caps)]
                    (possible if who else over).append((scope, caps))
                    low_tools.update(dict.fromkeys(who))
            if over:
                res.findings.append(_finding(srv.name, label, cred, over, confident))
            if possible:
                res.findings.append(
                    _finding(srv.name, label, cred, possible, confident, list(low_tools))
                )
    return res
