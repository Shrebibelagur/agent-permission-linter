import json

import httpx
from builders import cred, inventory, server

from apl.collectors.entra import GraphClient, collect_entra
from apl.collectors.link import link_entra
from apl.highrisk import REFERENCE, high_risk_grants, lookup
from apl.models import AgentSpec, CredentialKind, EntraApp, ServerPurpose, Severity
from apl.rules.apl004_no_owner import check

APP_ID = "a1a1a1a1-0000-4000-8000-000000000001"
SECRET = "abc8Q~FAKEfakeFAKEfakeFAKEfakeFAKEfake00"  # noqa: S105


def app(**kw):
    fields = {
        "app_id": APP_ID,
        "display_name": "agent",
        "application_object_id": "obj1",
        "service_principal_id": "sp1",
        "service_principal_type": "Application",
        "owner_ids": [],
    }
    return EntraApp(**(fields | kw))


def linked(*apps):
    c = cred(kind=CredentialKind.SERVICE_PRINCIPAL, entra_app_id=APP_ID)
    inv = inventory(server("mail", creds=[c]))
    inv.servers[0].entra_apps = list(apps)
    inv.entra_source = "mock"
    return inv


def test_positive_ownerless_app_is_medium():
    (f,) = check(linked(app())).findings
    assert f.rule_id == "APL-004" and f.status == "violation"
    assert f.severity is Severity.MEDIUM
    assert f.subject == f"mail/agent ({APP_ID})"
    assert f.confidence == 0.95 and "read directly" in f.confidence_reason
    assert [e.pointer for e in f.evidence] == [
        "/applications/obj1/owners",
        "/servicePrincipals/sp1/owners",
    ]
    assert {m.id for m in f.suggested_mappings} == {"NHI1:2025"}
    assert all(m.label == "suggested mapping" for m in f.suggested_mappings)


def test_positive_high_risk_permission_raises_severity():
    (f,) = check(linked(app(application_permissions=["Mail.Send", "Calendars.Read"]))).findings
    assert f.severity is Severity.HIGH and f.granted == ["Mail.Send"]


def test_delegated_form_of_an_application_only_entry_stays_medium():
    a = app(delegated_all_principals=["Mail.Send"], delegated_per_user=["Files.ReadWrite.All"])
    assert check(linked(a)).findings[0].severity is Severity.MEDIUM


def test_delegated_entry_that_is_risky_in_both_forms_is_high():
    a = app(delegated_per_user=["Application.ReadWrite.All"])
    assert check(linked(a)).findings[0].severity is Severity.HIGH


def test_another_apis_scope_is_not_the_graph_permission():
    a = app(application_permissions=["Contoso API/Mail.Send"])
    assert check(linked(a)).findings[0].severity is Severity.MEDIUM


def test_service_principal_only_app_is_a_review():
    a = app(application_object_id=None, service_principal_type="ManagedIdentity")
    (f,) = check(linked(a)).findings
    assert f.status == "review_required" and f.confidence == 0.6
    assert "only service principal owners" in f.confidence_reason
    assert [e.pointer for e in f.evidence] == ["/servicePrincipals/sp1/owners"]


def test_negative_owned_app():
    res = check(linked(app(owner_ids=["u1"])))
    assert res.findings == [] and res.skips == []
    assert [e.subject for e in res.evaluated] == [f"mail/agent ({APP_ID})"]


def test_skip_owner_data_not_collected():
    res = check(linked(app(owner_ids=None)))
    assert res.findings == [] and res.evaluated == []
    assert [s.reason for s in res.skips] == [
        "not evaluated: missing owner data (Graph refused the request)"
    ]


def test_skip_without_entra():
    c = cred(kind=CredentialKind.SERVICE_PRINCIPAL, entra_app_id=APP_ID)
    res = check(inventory(server("mail", creds=[c])))
    assert [s.reason for s in res.skips] == [
        "not evaluated: missing owner data (run with --entra or --entra-mock)"
    ]


def test_skip_for_an_id_only_declared_in_agent_yaml():
    spec = AgentSpec(
        name="a", purpose="p", servers=[ServerPurpose(server="mail", entra_app_id=APP_ID)]
    )
    assert len(check(inventory(server("mail"), agent=spec)).skips) == 1


def test_skip_app_not_found_in_entra():
    c = cred(kind=CredentialKind.SERVICE_PRINCIPAL, entra_app_id="MISSING")
    inv = inventory(server("mail", creds=[c]))
    inv.entra_source = "mock"
    (s,) = check(inv).skips
    assert s.subject == "mail/missing"
    assert s.reason == "not evaluated: missing owner data (app not found in Entra)"


def test_skip_entra_kind_with_no_app_id():
    res = check(inventory(server("mail", creds=[cred(kind=CredentialKind.SERVICE_PRINCIPAL)])))
    assert [s.reason for s in res.skips] == [
        "not evaluated: missing owner data (no Entra app id for this server)"
    ]


def test_server_with_no_entra_link_is_out_of_scope():
    res = check(inventory(server("github", creds=[cred()]), server("local")))
    assert res.findings == [] and res.skips == [] and res.evaluated == []


def test_evidence_and_subject_are_redacted():
    dumped = json.dumps(
        check(linked(app(display_name=f"agent {SECRET}"))).model_dump(mode="json")
    )
    assert SECRET not in dumped and "agent" in dumped


def test_clean_fixture_has_no_findings_or_skips(clean_inventory):
    res = check(clean_inventory)
    assert res.findings == [] and res.skips == []


def tenant(app_owners, sp_owners):
    """`None` = Graph refuses that owners call."""

    def owners(value):
        return (403, {}) if value is None else (200, {"value": value})

    routes = {
        "/applications": (200, {"value": [{"id": "o", "appId": APP_ID}]}),
        "/servicePrincipals": (200, {"value": [{"id": "s", "appId": APP_ID}]}),
        "/oauth2PermissionGrants": (200, {"value": []}),
        "/applications/o/owners": owners(app_owners),
        "/servicePrincipals/s/owners": owners(sp_owners),
        "/servicePrincipals/s/appRoleAssignments": (200, {"value": []}),
    }

    def handler(request):
        status, body = routes[request.url.raw_path.decode().removeprefix("/v1.0")]
        return httpx.Response(status, json=body)

    return GraphClient(lambda: "t", httpx.MockTransport(handler), sleep=lambda s: None)


def owners_of(app_owners, sp_owners):
    return collect_entra(tenant(app_owners, sp_owners), [APP_ID]).apps[APP_ID].owner_ids


def test_collector_tells_zero_owners_from_not_collected():
    assert owners_of([], []) == []
    assert owners_of(None, None) is None
    assert owners_of([], None) is None  # no proof of zero: the other list was refused
    assert owners_of(None, [{"id": "u1"}]) == ["u1"]  # one readable owner settles it


def test_owners_refused_by_graph_reaches_the_skip():
    snap = collect_entra(tenant(None, None), [APP_ID])
    inv = inventory(server("mail", creds=[cred(entra_app_id=APP_ID)]))
    link_entra(inv, snap)
    res = check(inv)
    assert res.findings == [] and len(res.skips) == 1
    assert "no owner" not in " ".join(inv.warnings)


def test_high_risk_table_cites_the_reference_and_matches_exactly():
    entry = lookup("mail.send")
    assert entry.name == "Mail.Send" and entry.source == f"{REFERENCE}#mailsend"
    assert lookup("Contoso/Mail.Send") is None and lookup("Mail.Read") is None
    assert [e.name for e in high_risk_grants(app(application_permissions=["Mail.Send"]))] == [
        "Mail.Send"
    ]
