"""APL-006 high-risk permission with no justification.

agent.yaml has an optional `justifications` mapping (permission -> reason). A high-risk Graph
permission (apl.highrisk) held by an app linked to a server needs an entry there. A blank reason
is no reason. The mapping is per agent, and an entry is an owner's statement that is not checked
against what the agent does. Severity is medium, or high when the same app has no owner (APL-004
applies): nobody is accountable for that grant. See ASSUMPTIONS R16.

A permission whose name could not be resolved might be high-risk, so it is a visible skip.
"""

from __future__ import annotations

from apl.highrisk import HighRisk, high_risk_grants
from apl.models import EntraApp, Evidence, Finding, Inventory, RuleResult, Severity
from apl.rules.base import ASI03, ENTRA_ORIGIN, NHI5, app_label, entra_targets, make_finding, skip

RULE_ID = "APL-006"
_UNRESOLVED = ("unresolved-app-role-", "unknown-resource-")


def _ownerless(app: EntraApp) -> bool:
    """Exactly APL-004's condition: owners not collected (None) is unknown, not ownerless."""
    return app.owner_ids == []


def _finding(server: str, app: EntraApp, entry: HighRisk, origin: str) -> Finding:
    held_as_role = entry.name in app.application_permissions
    pointer = (
        f"/servicePrincipals/{app.service_principal_id}/appRoleAssignments"
        if held_as_role
        else "/oauth2PermissionGrants"
    )
    form = "application" if held_as_role else "delegated"
    ownerless = _ownerless(app)
    why = "grant read directly from Graph; no reason in agent.yaml justifications"
    return make_finding(
        RULE_ID,
        "High-risk permission granted with no justification",
        Severity.HIGH if ownerless else Severity.MEDIUM,
        f"{server}/{entry.name}",
        granted=[f"{entry.name} ({form})"],
        required=["a justifications entry in agent.yaml"],
        evidence=[
            Evidence(
                source=origin,
                pointer=pointer,
                note=f"{app_label(app)}: {entry.why}. Reference: {entry.source}",
            )
        ],
        fix=(
            f"Remove {entry.name} from '{app.display_name or app.app_id}' if the agent does not "
            f"need it, or add '{entry.name}: <reason>' under justifications in agent.yaml."
        ),
        confidence=0.95,
        confidence_reason=f"{why}; app has no owner (APL-004)" if ownerless else why,
        mappings=[NHI5, ASI03],
    )


def check(inv: Inventory) -> RuleResult:
    res = RuleResult()
    if inv.agent is None:
        res.skips.append(skip(RULE_ID, "agent", "agent.yaml"))
        return res
    justified = {k.strip().lower() for k, v in inv.agent.justifications.items() if v.strip()}
    origin = ENTRA_ORIGIN.get(inv.entra_source or "", "entra")
    for srv in inv.servers:
        apps, skips = entra_targets(inv, srv, RULE_ID, "granted permissions")
        res.skips.extend(skips)
        if apps:
            res.ran(RULE_ID, srv.name)
        seen: set[str] = set()
        # A permission is reported once per server, so an ownerless app must be the one reported.
        for app in sorted(apps, key=lambda a: not _ownerless(a)):
            res.skips.extend(
                skip(RULE_ID, f"{srv.name}/{scope}", "permission name (unresolved in Graph)")
                for scope in app.granted_scopes()
                if scope.startswith(_UNRESOLVED)
            )
            for entry in high_risk_grants(app):
                if entry.name.lower() not in justified and entry.name not in seen:
                    seen.add(entry.name)
                    res.findings.append(_finding(srv.name, app, entry, origin))
    return res
