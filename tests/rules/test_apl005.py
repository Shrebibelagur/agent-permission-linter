import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from builders import cred, inventory, server

from apl.collectors.entra import GraphClient, collect_entra
from apl.collectors.link import link_entra
from apl.models import CredentialExpiry, CredentialKind, EntraApp, Severity
from apl.rules.apl005_secret_hygiene import check

APP_ID = "a1a1a1a1-0000-4000-8000-000000000001"
NOW = datetime(2026, 11, 1, tzinfo=UTC)
PLANTED = "abc8Q~FAKEfakeFAKEfakeFAKEfakeFAKEfake00"


def secret(start_days_ago=30, lifetime=90, **kw):
    start = NOW - timedelta(days=start_days_ago)
    fields = {
        "kind": "password",
        "key_id": "k1",
        "start_date_time": start,
        "end_date_time": start + timedelta(days=lifetime),
        "pointer": "/applications/obj1/passwordCredentials",
    }
    return CredentialExpiry(**(fields | kw))


def linked(*credentials, **kw):
    app = EntraApp(
        app_id=APP_ID,
        display_name="agent",
        application_object_id="obj1",
        service_principal_type="Application",
        credentials=list(credentials),
        **kw,
    )
    c = cred(kind=CredentialKind.SERVICE_PRINCIPAL, entra_app_id=APP_ID)
    inv = inventory(server("mail", creds=[c]))
    inv.servers[0].entra_apps = [app]
    inv.entra_source = "mock"
    inv.generated_at = NOW
    return inv


def test_positive_expired_still_present_is_medium():
    (f,) = check(linked(secret(start_days_ago=100, lifetime=90))).findings
    assert f.rule_id == "APL-005" and f.status == "violation"
    assert f.severity is Severity.MEDIUM and f.title == "Expired credential still present"
    assert f.subject == "mail/agent (a1a1...0001)/password-k1"
    assert f.granted == ["password credential: expired 2026-10-22"]
    assert f.confidence == 0.95 and f.confidence_reason == "dates read directly from Graph"
    assert f.evidence[0].pointer == "/applications/obj1/passwordCredentials"
    assert {m.id for m in f.suggested_mappings} == {"NHI7:2025"}
    assert all(m.label == "suggested mapping" for m in f.suggested_mappings)


def test_positive_lifetime_over_180_days_is_low():
    (f,) = check(linked(secret(lifetime=181))).findings
    assert f.severity is Severity.LOW and "181 days" in f.granted[0]


def test_positive_no_expiry_is_medium_with_lower_confidence():
    (f,) = check(linked(secret(end_date_time=None))).findings
    assert f.severity is Severity.MEDIUM and f.title == "Credential has no expiry"
    assert f.confidence == 0.8 and "optional" in f.confidence_reason


def test_key_credentials_are_checked_too():
    (f,) = check(linked(secret(kind="key", lifetime=400))).findings
    assert "/key-k1" in f.subject


def test_expired_long_lived_credential_gives_one_finding():
    (f,) = check(linked(secret(start_days_ago=500, lifetime=400))).findings
    assert f.title == "Expired credential still present"


def test_each_bad_credential_gets_its_own_finding():
    res = check(linked(secret(key_id="a", lifetime=400), secret(key_id="b", end_date_time=None)))
    assert len({f.id for f in res.findings}) == 2


def test_credential_without_a_key_id_keeps_a_distinct_subject():
    res = check(linked(secret(key_id=None, lifetime=400), secret(key_id=None, lifetime=400)))
    assert len({f.subject for f in res.findings}) == 2


def test_negative_exactly_180_days_passes():
    res = check(linked(secret(lifetime=180)))
    assert res.findings == [] and res.skips == [] and len(res.evaluated) == 1


def test_negative_app_with_no_credentials():
    res = check(linked())
    assert res.findings == [] and res.skips == [] and len(res.evaluated) == 1


def test_naive_dates_are_read_as_utc():
    naive = secret(
        start_date_time=datetime(2026, 9, 1),
        end_date_time=datetime(2026, 10, 1),
    )
    assert check(linked(naive)).findings[0].title == "Expired credential still present"


def test_far_future_end_is_long_lived_not_a_crash():
    far = secret(end_date_time=datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC))
    assert check(linked(far)).findings[0].severity is Severity.LOW


def test_skip_unreadable_end_date_is_not_no_expiry():
    res = check(linked(secret(end_date_time=None, end_unreadable=True)))
    assert res.findings == []
    (s,) = res.skips
    assert s.reason == "not evaluated: missing credential end date (not a date in Graph)"


def test_skip_missing_start_date_when_lifetime_depends_on_it():
    res = check(linked(secret(start_date_time=None)))
    assert res.findings == []
    assert res.skips[0].reason == "not evaluated: missing credential start date, so no lifetime"


def test_missing_start_date_cannot_hide_an_expired_credential():
    res = check(linked(secret(start_date_time=None, end_date_time=NOW - timedelta(days=1))))
    assert len(res.findings) == 1 and res.skips == []


def test_skip_credential_lists_not_returned():
    res = check(linked(credentials_gap="credential lists absent from the Graph response"))
    assert res.findings == [] and res.evaluated == []
    assert res.skips[0].reason == (
        "not evaluated: missing credential data (credential lists absent from the Graph response)"
    )


def test_gap_keeps_the_findings_it_can_make():
    res = check(linked(secret(lifetime=400), credentials_gap="x"))
    assert len(res.findings) == 1 and len(res.skips) == 1


def test_skip_without_entra():
    c = cred(kind=CredentialKind.SERVICE_PRINCIPAL, entra_app_id=APP_ID)
    res = check(inventory(server("mail", creds=[c])))
    assert [s.reason for s in res.skips] == [
        "not evaluated: missing credential data (run with --entra or --entra-mock)"
    ]


def test_managed_identity_is_skipped_not_flagged():
    inv = linked(secret(end_date_time=None))
    inv.servers[0].entra_apps[0].service_principal_type = "ManagedIdentity"
    res = check(inv)
    assert res.findings == []
    assert "managed identity" in res.skips[0].reason


def test_clean_fixture_has_no_findings_or_skips(clean_inventory):
    res = check(clean_inventory)
    assert res.findings == [] and res.skips == []


def collected(app_obj, sp_obj=None):
    """One app through the real collector."""
    objects = {"/applications": [app_obj] if app_obj else [], "/servicePrincipals": [sp_obj or {}]}

    def handler(request):
        path = request.url.raw_path.decode().removeprefix("/v1.0")
        return httpx.Response(200, json={"value": objects.get(path, [])})

    client = GraphClient(lambda: "t", httpx.MockTransport(handler), sleep=lambda s: None)
    return collect_entra(client, [APP_ID]).apps[APP_ID]


APP = {"id": "o", "appId": APP_ID, "passwordCredentials": [], "keyCredentials": []}
SP = {"id": "s", "appId": APP_ID, "passwordCredentials": [], "keyCredentials": []}


def test_collector_keeps_start_and_end_and_points_at_the_object():
    pw = {
        "keyId": "k",
        "startDateTime": "2026-01-01T00:00:00Z",
        "endDateTime": "2026-02-01T00:00:00Z",
        "hint": "abc",
        "secretText": PLANTED,
    }
    app = collected(APP | {"passwordCredentials": [pw]}, SP)
    (c,) = app.credentials
    assert c.start_date_time.month == 1 and c.end_date_time.month == 2
    assert c.pointer == "/applications/o/passwordCredentials"
    assert app.credentials_gap is None
    assert PLANTED not in app.model_dump_json()


def test_collector_separates_null_end_from_unreadable_end():
    app = collected(
        APP | {"passwordCredentials": [{"keyId": "a", "endDateTime": None},
                                       {"keyId": "b", "endDateTime": "soon"}]},
        SP,
    )
    assert [c.end_unreadable for c in app.credentials] == [False, True]


@pytest.mark.parametrize(
    "app_obj,sp_obj,gap",
    [
        (APP, SP, None),
        ({"id": "o", "appId": APP_ID}, SP, "credential lists absent from the Graph response"),
        (None, SP, "application object is in another tenant"),
    ],
)
def test_collector_knows_when_the_list_is_incomplete(app_obj, sp_obj, gap):
    assert collected(app_obj, sp_obj).credentials_gap == gap


def test_no_secret_material_reaches_any_output():
    pw = {"keyId": "k", "endDateTime": f"not a date {PLANTED}", "secretText": PLANTED,
          "hint": PLANTED[:3], "key": PLANTED}
    snap_app = collected(APP | {"passwordCredentials": [pw, pw | {"endDateTime": None}]}, SP)
    inv = inventory(server("mail", creds=[cred(entra_app_id=APP_ID)]))
    inv.entra_source = "mock"
    inv.servers[0].entra_apps = [snap_app]
    inv.generated_at = NOW
    dumped = json.dumps(check(inv).model_dump(mode="json"))
    assert PLANTED not in dumped and "abc" not in dumped.replace("abc8", "")


def test_expired_warning_is_gone_after_linking():
    past = secret(start_days_ago=500, lifetime=100)
    app = EntraApp(app_id=APP_ID, service_principal_id="s", owner_ids=["u"], credentials=[past])
    from apl.collectors.entra import EntraSnapshot

    inv = inventory(server("mail", creds=[cred(entra_app_id=APP_ID)]))
    link_entra(inv, EntraSnapshot(source="mock", apps={APP_ID: app}))
    assert inv.warnings == []
    assert inv.servers[0].entra_apps == [app]
