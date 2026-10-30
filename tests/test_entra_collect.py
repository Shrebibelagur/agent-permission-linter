"""Graph paging, retry and collection, against responses shaped like the documented ones."""

from datetime import UTC, datetime, timedelta
from email.utils import format_datetime

import httpx
import pytest

from apl.collectors.entra import (
    GRAPH_APP_ID,
    MAX_ATTEMPTS,
    EntraError,
    GraphClient,
    ReadOnlyViolation,
    collect_entra,
)

BASE = "https://graph.microsoft.com/v1.0"
ACCESS = "fake-access-token-value"


def graph(routes, sleeps=None):
    """`routes`: path + query -> JSON body, or a list of (status, headers, body) replies."""
    calls = []

    def handler(request):
        key = request.url.raw_path.decode().removeprefix("/v1.0")
        calls.append(key)
        reply = routes[key]
        if isinstance(reply, list):
            status, headers, body = reply.pop(0)
            return httpx.Response(status, headers=headers, json=body)
        return httpx.Response(200, json=reply)

    sleep = (sleeps if sleeps is not None else []).append
    return GraphClient(lambda: ACCESS, httpx.MockTransport(handler), sleep=sleep), calls


def test_pagination_follows_nextlink_verbatim_until_absent():
    first, second = f"{BASE}/applications?$skiptoken=x", f"{BASE}/applications?$skiptoken=y"
    client, calls = graph(
        {
            "/applications": {"value": [{"id": "1"}], "@odata.nextLink": first},
            "/applications?$skiptoken=x": {"value": [], "@odata.nextLink": second},
            "/applications?$skiptoken=y": {"value": [{"id": "2"}]},
        }
    )
    assert [a["id"] for a in client.get_all("/applications")] == ["1", "2"]  # empty page continues
    assert len(calls) == 3


def test_hostile_nextlink_is_refused_before_the_token_leaves():
    client, calls = graph(
        {"/applications": {"value": [], "@odata.nextLink": "https://evil.example/steal"}}
    )
    with pytest.raises(ReadOnlyViolation):
        client.get_all("/applications")
    assert calls == ["/applications"]


def test_nextlink_loop_stops():
    link = f"{BASE}/applications"
    client, _ = graph({"/applications": {"value": [], "@odata.nextLink": link}})
    with pytest.raises(EntraError, match="did not terminate"):
        client.get_all("/applications")


def test_429_waits_for_retry_after_seconds():
    sleeps = []
    client, calls = graph(
        {"/x": [(429, {"Retry-After": "10"}, {}), (200, {}, {"value": [{"id": "1"}]})]}, sleeps
    )
    assert client.get_all("/x") == [{"id": "1"}]
    assert sleeps == [10.0] and len(calls) == 2


def test_retry_after_http_date():
    sleeps = []
    when = format_datetime(datetime.now(UTC) + timedelta(seconds=30), usegmt=True)
    client, _ = graph({"/x": [(503, {"Retry-After": when}, {}), (200, {}, {"value": []})]}, sleeps)
    client.get_all("/x")
    assert 25 < sleeps[0] <= 30


@pytest.mark.parametrize("status", [500, 502, 503, 504])
def test_5xx_without_header_backs_off_exponentially(status):
    sleeps = []
    client, _ = graph(
        {"/x": [(status, {}, {}), (status, {}, {}), (status, {}, {}), (200, {}, {"value": []})]},
        sleeps,
    )
    client.get_all("/x")
    assert sleeps == [1.0, 2.0, 4.0]


def test_malformed_retry_after_falls_back_to_backoff():
    sleeps = []
    client, _ = graph(
        {"/x": [(429, {"Retry-After": "soon"}, {}), (200, {}, {"value": []})]}, sleeps
    )
    client.get_all("/x")
    assert sleeps == [1.0]


def test_gives_up_after_bounded_attempts():
    sleeps = []
    client, calls = graph({"/x": [(429, {"Retry-After": "1"}, {})] * MAX_ATTEMPTS}, sleeps)
    with pytest.raises(EntraError, match="gave up"):
        client.get_all("/x")
    assert len(calls) == MAX_ATTEMPTS and len(sleeps) == MAX_ATTEMPTS - 1


def test_refuses_to_retry_early_when_retry_after_is_huge():
    sleeps = []
    client, calls = graph({"/x": [(429, {"Retry-After": "86400"}, {})]}, sleeps)
    with pytest.raises(EntraError, match="too long"):
        client.get_all("/x")
    assert sleeps == [] and len(calls) == 1


@pytest.mark.parametrize("status", [400, 401, 403, 404])
def test_client_errors_are_not_retried(status):
    client, calls = graph({"/x": [(status, {}, {})]})
    with pytest.raises(EntraError):
        client.get_all("/x")
    assert len(calls) == 1


def grant(client_id, resource, scope, consent="AllPrincipals"):
    return {"clientId": client_id, "consentType": consent, "resourceId": resource, "scope": scope}


def tenant():
    graph_sp = {
        "id": "sp-graph",
        "appId": GRAPH_APP_ID,
        "displayName": "Microsoft Graph",
        "appRoles": [{"id": "role-mail", "value": "Mail.ReadWrite"}],
    }
    other_api = {"id": "sp-api", "appId": "api-app", "displayName": "Contoso API", "appRoles": []}
    client_sp = {
        "id": "sp-client",
        "appId": "AAAA-Client",  # appId case differs from the link
        "displayName": "agent",
        "servicePrincipalType": "Application",
    }
    password = {
        "keyId": "k1",
        "endDateTime": "2030-01-01T00:00:00Z",
        "hint": "abc",
        "secretText": None,
    }
    key = {"keyId": "k2", "endDateTime": "2020-01-01T00:00:00Z", "key": "UFVCTElDS0VZ"}
    app = {
        "id": "obj-client",
        "appId": "aaaa-client",
        "displayName": "agent",
        "passwordCredentials": [password],
        "keyCredentials": [key],
    }
    return {
        "/applications": {"value": [app]},
        "/servicePrincipals": {"value": [graph_sp, other_api, client_sp]},
        "/oauth2PermissionGrants": {
            "value": [
                grant("sp-client", "sp-graph", "User.Read Calendars.Read"),
                grant("sp-client", "sp-graph", " Files.Read ", "Principal"),
                grant("sp-client", "sp-api", "Mail.ReadWrite"),
                grant("someone-else", "sp-graph", "Directory.ReadWrite.All"),
            ]
        },
        "/applications/obj-client/owners": {"value": [{"id": "u1"}]},
        "/servicePrincipals/sp-client/owners": {"value": [{"id": "u1"}, {"id": "u2"}]},
        "/servicePrincipals/sp-client/appRoleAssignments": {
            "value": [
                {"appRoleId": "role-mail", "resourceId": "sp-graph"},
                {"appRoleId": "role-gone", "resourceId": "sp-graph"},
                {"appRoleId": "role-x", "resourceId": "sp-graph", "deletedDateTime": "2026-01-01"},
            ]
        },
    }


def test_collect_links_ids_grants_and_owners():
    client, _ = graph(tenant())
    app = collect_entra(client, ["aaaa-client"]).apps["aaaa-client"]
    assert app.application_object_id == "obj-client" and app.service_principal_id == "sp-client"
    assert app.service_principal_type == "Application"
    assert app.owner_ids == ["u1", "u2"]  # union of application and service principal owners
    assert app.delegated_all_principals == [
        "Calendars.Read",
        "Contoso API/Mail.ReadWrite",  # another API's scope never reads as a Graph one
        "User.Read",
    ]
    assert app.delegated_per_user == ["Files.Read"]
    assert app.application_permissions == ["Mail.ReadWrite", "unresolved-app-role-role-gone"]
    assert "Directory.ReadWrite.All" not in app.granted_scopes()


def test_collect_keeps_expiry_and_no_credential_material():
    client, _ = graph(tenant())
    app = collect_entra(client, ["aaaa-client"]).apps["aaaa-client"]
    assert [(c.kind, c.key_id, c.end_date_time.year) for c in app.credentials] == [
        ("password", "k1", 2030),
        ("key", "k2", 2020),
    ]
    dumped = app.model_dump_json()
    assert "UFVCTElDS0VZ" not in dumped and "hint" not in dumped


def test_collect_only_fetches_relationships_for_requested_apps():
    client, calls = graph(tenant())
    assert collect_entra(client, ["no-such-app"]).apps == {}
    assert calls == ["/applications", "/servicePrincipals", "/oauth2PermissionGrants"]


def test_app_from_another_tenant_has_a_service_principal_only():
    routes = tenant()
    routes["/applications"] = {"value": []}
    client, calls = graph(routes)
    app = collect_entra(client, ["aaaa-client"]).apps["aaaa-client"]
    assert app.application_object_id is None and app.owner_ids == ["u1", "u2"]
    assert "/applications/obj-client/owners" not in calls


def test_display_name_is_redacted_on_ingest():
    planted = "abc8Q~FAKEfakeFAKEfakeFAKEfakeFAKEfake00"
    routes = tenant()
    routes["/applications"]["value"][0]["displayName"] = f"agent {planted}"
    client, _ = graph(routes)
    assert planted not in collect_entra(client, ["aaaa-client"]).model_dump_json()
