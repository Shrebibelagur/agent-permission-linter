"""Entra client: token flow, the read-only guard, and no credential in any error."""

import json
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import pytest

from apl.collectors.entra import (
    ClientCredentialsToken,
    EntraCredentials,
    EntraError,
    GetOnlyTransport,
    GraphClient,
    ReadOnlyViolation,
)

SECRET = "fake-client-secret-without-a-known-shape"  # noqa: S105
ACCESS = "fake-access-token-value"
CREDS = EntraCredentials("contoso.example", "app-id", SECRET)
SRC = Path(__file__).parents[1] / "src" / "apl"


def token_transport(seen, status=200, body=None):
    def handler(request):
        seen.append(request)
        ok = {"token_type": "Bearer", "expires_in": 3599, "access_token": ACCESS}
        return httpx.Response(status, json=body or ok)

    return httpx.MockTransport(handler)


def test_token_request_matches_the_documented_form():
    seen = []
    assert ClientCredentialsToken(CREDS, token_transport(seen))() == ACCESS
    req = seen[0]
    assert req.method == "POST"
    assert str(req.url) == "https://login.microsoftonline.com/contoso.example/oauth2/v2.0/token"
    assert req.headers["content-type"] == "application/x-www-form-urlencoded"
    assert parse_qs(req.content.decode()) == {
        "client_id": ["app-id"],
        "client_secret": [SECRET],
        "scope": ["https://graph.microsoft.com/.default"],
        "grant_type": ["client_credentials"],
    }


def test_token_is_cached_then_refreshed_near_expiry():
    seen, now = [], [0.0]
    token = ClientCredentialsToken(CREDS, token_transport(seen), clock=lambda: now[0])
    token(), token()
    assert len(seen) == 1
    now[0] = 3550.0  # inside the expiry margin
    token()
    assert len(seen) == 2


def test_token_failure_reports_code_but_not_description():
    body = {"error": "invalid_client", "error_description": f"AADSTS7000215: bad {SECRET}"}
    with pytest.raises(EntraError) as e:
        ClientCredentialsToken(CREDS, token_transport([], 401, body))()
    assert "HTTP 401 (invalid_client)" in str(e.value)
    assert SECRET not in str(e.value) and "AADSTS" not in str(e.value)
    assert e.value.__cause__ is None and e.value.__context__ is None


def test_token_failure_ignores_a_hostile_error_code():
    body = {"error": f"not a code {SECRET}"}
    with pytest.raises(EntraError) as e:
        ClientCredentialsToken(CREDS, token_transport([], 400, body))()
    assert str(e.value) == "token request failed: HTTP 400"


def test_network_error_does_not_chain_the_request():
    def boom(request):
        raise httpx.ConnectError(f"cannot reach {request.content!r}")

    with pytest.raises(EntraError) as e:
        ClientCredentialsToken(CREDS, httpx.MockTransport(boom))()
    assert str(e.value) == "token request failed: ConnectError"
    assert e.value.__suppress_context__


def test_secret_not_in_repr():
    assert SECRET not in repr(CREDS)
    assert SECRET not in repr(ClientCredentialsToken(CREDS))


def test_credentials_from_env_only_names_what_is_missing():
    with pytest.raises(EntraError) as e:
        EntraCredentials.from_env({"TENANT_ID": "t", "CLIENT_SECRET": SECRET})
    assert str(e.value) == "missing environment variable(s): CLIENT_ID"


def test_credentials_from_env():
    env = {"TENANT_ID": "t.example", "CLIENT_ID": "c", "CLIENT_SECRET": SECRET}
    assert EntraCredentials.from_env(env).client_secret == SECRET


@pytest.mark.parametrize("tenant", ["../evil", "a/b", "x?y=1", "a b", "@evil.example"])
def test_tenant_cannot_change_the_token_url(tenant):
    env = {"TENANT_ID": tenant, "CLIENT_ID": "c", "CLIENT_SECRET": SECRET}
    with pytest.raises(EntraError):
        EntraCredentials.from_env(env)


def client(seen):
    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={"value": []})

    return GraphClient(lambda: ACCESS, httpx.MockTransport(handler))


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
def test_guard_rejects_every_method_except_get(method):
    seen = []
    with pytest.raises(ReadOnlyViolation, match=method):
        client(seen)._http.request(method, "https://graph.microsoft.com/v1.0/applications")
    assert seen == []  # refused before anything reached the wire


def test_guard_allows_get():
    seen = []
    assert client(seen).get("https://graph.microsoft.com/v1.0/applications") == {"value": []}
    assert seen[0].headers["authorization"] == f"Bearer {ACCESS}"


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example/v1.0/applications",
        "https://graph.microsoft.com.evil.example/v1.0/applications",
        "http://graph.microsoft.com/v1.0/applications",
    ],
)
def test_guard_never_sends_the_token_off_graph(url):
    seen = []
    with pytest.raises(ReadOnlyViolation):
        client(seen).get(url)
    assert seen == []


def test_transport_is_the_guard_not_a_helper_method():
    assert isinstance(client([])._http._transport, GetOnlyTransport)


def test_no_azure_identity_sdk():
    text = "".join(p.read_text(encoding="utf-8") for p in SRC.rglob("*.py"))
    assert "azure.identity" not in text and "ClientSecretCredential" not in text
    assert "msal" not in text


def test_error_message_has_path_not_query():
    transport = httpx.MockTransport(lambda r: httpx.Response(403, json={"error": {}}))
    c = GraphClient(lambda: ACCESS, transport)
    with pytest.raises(EntraError) as e:
        c.get("https://graph.microsoft.com/v1.0/applications?$skiptoken=abc")
    assert str(e.value) == "Graph HTTP 403 for /v1.0/applications"
    assert json.dumps(str(e.value)).count("skiptoken") == 0
