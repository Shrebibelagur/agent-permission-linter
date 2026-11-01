"""APL-004 no owner: an Entra app linked to a server has nobody accountable for it.

Owners are the union of the application's and the service principal's owners (G6). Zero owners is
medium, or high if the app holds a high-risk permission (apl.highrisk). When the app object is not
in this tenant (registered elsewhere, or a managed identity), only the service principal's owners
are visible, so absence proves less: the finding is review_required. See ASSUMPTIONS R13.
"""

from __future__ import annotations

from apl.highrisk import high_risk_grants
from apl.models import EntraApp, Evidence, Finding, Inventory, RuleResult, Severity
from apl.rules.base import ENTRA_ORIGIN, NHI1, app_label, entra_targets, make_finding, skip

RULE_ID = "APL-004"


def _evidence(app: EntraApp, origin: str) -> list[Evidence]:
    objects = []
    if app.application_object_id:
        objects.append(f"/applications/{app.application_object_id}/owners")
    if app.service_principal_id:
        objects.append(f"/servicePrincipals/{app.service_principal_id}/owners")
    return [Evidence(source=origin, pointer=p, note="Graph returned no owners") for p in objects]


def _finding(server: str, app: EntraApp, origin: str) -> Finding:
    risky = high_risk_grants(app)
    home_tenant = app.application_object_id is not None
    return make_finding(
        RULE_ID,
        "Entra app linked to this server has no owner",
        Severity.HIGH if risky else Severity.MEDIUM,
        f"{server}/{app_label(app)}",
        status="violation" if home_tenant else "review_required",
        granted=[e.name for e in risky],
        required=["at least one accountable owner"],
        evidence=_evidence(app, origin),
        fix=(
            f"Assign an owner to '{app.display_name or app.app_id}' in Entra, or remove the app "
            f"from '{server}' if nobody is responsible for it."
        ),
        confidence=0.95 if home_tenant else 0.6,
        confidence_reason=(
            "Graph owner lists read directly; none on the application or service principal"
            if home_tenant
            else "no application object in this tenant, so only service principal owners are seen"
        ),
        mappings=[NHI1],
    )


def check(inv: Inventory) -> RuleResult:
    res = RuleResult()
    origin = ENTRA_ORIGIN.get(inv.entra_source or "", "entra")
    for srv in inv.servers:
        apps, skips = entra_targets(inv, srv, RULE_ID, "owner data")
        res.skips.extend(skips)
        for app in apps:
            subject = f"{srv.name}/{app_label(app)}"
            if app.owner_ids is None:
                res.skips.append(skip(RULE_ID, subject, "owner data (Graph refused the request)"))
                continue
            res.ran(RULE_ID, subject)
            if not app.owner_ids:
                res.findings.append(_finding(srv.name, app, origin))
    return res
