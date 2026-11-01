"""Finding ids: stable for a fact, different for a different linked app."""

import json

from builders import cred, inventory, server, tool

from apl.collectors.entra import EntraApp, EntraSnapshot
from apl.collectors.link import link_entra
from apl.models import AppRef, CredentialKind, Evidence, Severity
from apl.report import render
from apl.rules.apl001_overscoped import check as apl001
from apl.rules.base import make_finding
from apl.scan import ScanReport

APP_A = "a1a1a1a1-0000-4000-8000-000000000001"
APP_B = "b2b2b2b2-0000-4000-8000-000000000002"


def finding(app_id=None, subject="mail/AZURE_CLIENT_ID"):
    app = AppRef(app_id=app_id) if app_id else None
    return make_finding(
        "APL-001",
        "t",
        Severity.HIGH,
        subject,
        fix="f",
        confidence=1,
        confidence_reason="r",
        evidence=[Evidence(source="entra-mock", app=app)],
    )


def over_scoped(app_id):
    c = cred(env="AZURE_CLIENT_ID", kind=CredentialKind.SERVICE_PRINCIPAL, entra_app_id=app_id)
    inv = inventory(server("mail", tools=[tool("list_messages")], creds=[c]))
    app = EntraApp(
        app_id=app_id,
        display_name="same-name",
        service_principal_id="sp",
        owner_ids=["u"],
        application_permissions=["Mail.ReadWrite"],
    )
    link_entra(inv, EntraSnapshot(source="mock", apps={app_id: app}))
    return inv, apl001(inv).findings[0]


def test_same_server_and_variable_with_different_apps_get_different_ids():
    assert over_scoped(APP_A)[1].id != over_scoped(APP_B)[1].id


def test_id_is_stable_for_the_same_app():
    assert finding(APP_A).id == finding(APP_A).id
    assert finding(APP_A).id == finding(APP_A.upper()).id


def test_finding_with_no_linked_app_keeps_the_old_id_scheme():
    import hashlib

    expected = hashlib.sha256(b"APL-001|mail/AZURE_CLIENT_ID").hexdigest()[:12]
    assert finding().id == f"APL-001:{expected}"


def test_app_identity_never_reaches_output():
    inv, f = over_scoped(APP_A)
    assert f.evidence[0].app is None
    assert APP_A not in json.dumps(f.model_dump(mode="json"))
    report = ScanReport(inventory=inv, result=apl001(inv))
    for fmt in ("md", "json", "sarif"):
        assert APP_A not in render(report, fmt)
