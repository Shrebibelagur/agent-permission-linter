"""A planted fake client secret must not appear anywhere: output, files, errors or logs.

The shapeless secret matters most: `redact()` patterns cannot recognise it, so these tests would
pass by luck if they only planted a `8Q~` value.
"""

import json
import logging
import shutil
from urllib.parse import parse_qs

import httpx
import pytest
from typer.testing import CliRunner

import apl.collectors.entra as entra
from apl.cli import app
from apl.collectors.entra import FixtureTransport, collect_mock
from apl.redact import REDACTED, redact, remember_secret

SHAPELESS = "plain-fake-value-no-known-shape-1234"
ENTRA_SHAPED = "abc8Q~FAKEfakeFAKEfakeFAKEfakeFAKEfake00"
ACCESS = "opaque-fake-access-value-no-jwt-shape"
PLANTS = [SHAPELESS, ENTRA_SHAPED]
FORMATS = ["md", "json", "sarif"]


def plant(root, secret, *, in_names):
    """Put the secret where Graph could return it. `in_names` adds fields apl does copy."""
    apps_file = root / "applications.json"
    apps = json.loads(apps_file.read_text(encoding="utf-8"))
    pw = apps["value"][0]["passwordCredentials"][0]
    pw["secretText"], pw["hint"] = secret, secret[:3]
    apps["value"][0]["keyCredentials"] = [
        {"keyId": "k", "endDateTime": f"not a date {secret}", "key": secret}
    ]
    if in_names:
        apps["value"][0]["displayName"] = f"mail-triage {secret}"
        grants_file = root / "oauth2PermissionGrants.json"
        grants = json.loads(grants_file.read_text(encoding="utf-8"))
        grants["value"][0]["scope"] += f" Contoso.{secret}"
        grants_file.write_text(json.dumps(grants), encoding="utf-8")
    apps_file.write_text(json.dumps(apps), encoding="utf-8")


@pytest.fixture
def graph_dir(fix, tmp_path):
    root = tmp_path / "graph"
    shutil.copytree(fix / "graph", root)
    return root


class Tenant(httpx.BaseTransport):
    """Answers the token endpoint and Graph, and remembers what it was sent."""

    def __init__(self, root, token_reply=None, graph_reply=None):
        self.fixtures = FixtureTransport(root)
        self.token_reply = token_reply
        self.graph_reply = graph_reply
        self.requests = []

    def handle_request(self, request):
        self.requests.append(request)
        if request.url.host == "login.microsoftonline.com":
            request.read()
            return self.token_reply or httpx.Response(
                200, json={"token_type": "Bearer", "expires_in": 3599, "access_token": ACCESS}
            )
        return self.graph_reply or self.fixtures.handle_request(request)


def live(monkeypatch, tenant):
    monkeypatch.setattr(entra, "_live_transport", lambda: tenant)


def scan(fix, secret, *extra):
    d = fix / "entra"
    env = {"TENANT_ID": "contoso.example", "CLIENT_ID": "app", "CLIENT_SECRET": secret}
    args = ["scan", "-c", str(d / "mcp.json"), "-t", str(d / "tools.json"), *extra]
    return CliRunner().invoke(app, args, env=env)


def assert_clean(text, secret):
    assert secret not in text
    assert ACCESS not in text


@pytest.mark.parametrize("secret", PLANTS)
@pytest.mark.parametrize("fmt", FORMATS)
def test_live_scan_leaks_nothing(fix, graph_dir, tmp_path, monkeypatch, caplog, secret, fmt):
    caplog.set_level(logging.DEBUG)
    plant(graph_dir, secret, in_names=True)
    tenant = Tenant(graph_dir)
    live(monkeypatch, tenant)
    out = tmp_path / f"report.{fmt}"
    streamed = scan(fix, secret, "--entra", "-f", fmt)
    written = scan(fix, secret, "--entra", "-f", fmt, "--out", str(out))
    assert streamed.exit_code == 0 and written.exit_code == 0, streamed.output
    for text in (streamed.output, written.output, out.read_text(encoding="utf-8"), caplog.text):
        assert_clean(text, secret)
    assert "Mail.ReadWrite" in streamed.output  # the scan really ran
    if fmt != "md":
        json.loads(out.read_text(encoding="utf-8"))  # redaction must not break JSON


@pytest.mark.parametrize("secret", PLANTS)
def test_the_secret_was_really_in_play(fix, graph_dir, monkeypatch, secret):
    """Guards the tests above from passing because the secret never reached the code."""
    tenant = Tenant(graph_dir)
    live(monkeypatch, tenant)
    assert scan(fix, secret, "--entra").exit_code == 0
    token_request = tenant.requests[0]
    assert parse_qs(token_request.content.decode())["client_secret"] == [secret]
    graph_calls = [r for r in tenant.requests if r.url.host == "graph.microsoft.com"]
    assert graph_calls and {r.method for r in graph_calls} == {"GET"}
    assert all(r.headers["authorization"] == f"Bearer {ACCESS}" for r in graph_calls)
    assert all(secret not in str(r.url) and not r.content for r in graph_calls)


@pytest.mark.parametrize("secret", PLANTS)
def test_mock_scan_leaks_nothing(fix, graph_dir, secret):
    """No env secret is known here: this one rests on the fields never being copied."""
    plant(graph_dir, secret, in_names=False)
    r = scan(fix, "unused-in-mock-mode", "--entra-mock", str(graph_dir), "-f", "json")
    assert r.exit_code == 0, r.output
    assert_clean(r.output, secret)
    snapshot = collect_mock(graph_dir, [next(iter(_mail_id(fix)))])
    assert_clean(snapshot.model_dump_json(), secret)


def _mail_id(fix):
    config = json.loads((fix / "entra" / "mcp.json").read_text(encoding="utf-8"))
    return [config["mcpServers"]["mail"]["env"]["AZURE_CLIENT_ID"]]


def test_uncopied_fields_do_not_depend_on_the_exact_scrub(fix, graph_dir, monkeypatch):
    """Layers are independent: with exact-value scrubbing off, secretText etc. still stay out."""
    monkeypatch.setattr(entra, "remember_secret", lambda value: None)
    plant(graph_dir, SHAPELESS, in_names=False)
    live(monkeypatch, Tenant(graph_dir))
    r = scan(fix, SHAPELESS, "--entra", "-f", "json")
    assert r.exit_code == 0
    assert_clean(r.output, SHAPELESS)


@pytest.mark.parametrize("secret", PLANTS)
@pytest.mark.parametrize(
    "reply",
    [
        lambda s: {"token_reply": httpx.Response(401, json={"error_description": f"bad {s}"})},
        lambda s: {"token_reply": httpx.Response(200, text=f"not json {s}")},
        lambda s: {"graph_reply": httpx.Response(403, json={"error": {"message": s}})},
        lambda s: {"graph_reply": httpx.Response(200, text=f"not json {s}")},
    ],
    ids=["token-401", "token-garbage", "graph-403", "graph-garbage"],
)
def test_failures_leak_nothing(fix, graph_dir, monkeypatch, caplog, secret, reply):
    caplog.set_level(logging.DEBUG)
    live(monkeypatch, Tenant(graph_dir, **reply(secret)))
    r = scan(fix, secret, "--entra")
    assert r.exit_code == 2
    assert "error:" in r.output
    assert_clean(r.output + caplog.text, secret)


def test_token_failure_is_safe_without_the_exact_scrub(fix, graph_dir, monkeypatch):
    monkeypatch.setattr(entra, "remember_secret", lambda value: None)
    body = {"error": "invalid_client", "error_description": f"bad {SHAPELESS}"}
    live(monkeypatch, Tenant(graph_dir, token_reply=httpx.Response(401, json=body)))
    r = scan(fix, SHAPELESS, "--entra")
    assert r.exit_code == 2 and "invalid_client" in r.output
    assert_clean(r.output, SHAPELESS)


@pytest.mark.parametrize("status", [403, 404])
def test_graph_failure_body_is_never_echoed(fix, graph_dir, monkeypatch, status):
    """With the exact scrub off, only not reading the body keeps this out of the error."""
    monkeypatch.setattr(entra, "remember_secret", lambda value: None)
    reply = httpx.Response(status, json={"error": {"message": f"bad {SHAPELESS}"}})
    live(monkeypatch, Tenant(graph_dir, graph_reply=reply))
    r = scan(fix, SHAPELESS, "--entra")
    assert r.exit_code == 2 and f"Graph HTTP {status}" in r.output
    assert_clean(r.output, SHAPELESS)


def test_access_token_is_scrubbed_from_tenant_data(fix, graph_dir, monkeypatch):
    apps_file = graph_dir / "applications.json"
    apps = json.loads(apps_file.read_text(encoding="utf-8"))
    apps["value"][0]["displayName"] = f"mail-triage {ACCESS}"
    apps_file.write_text(json.dumps(apps), encoding="utf-8")
    live(monkeypatch, Tenant(graph_dir))
    r = scan(fix, SHAPELESS, "--entra")
    assert r.exit_code == 0
    assert "mail-triage" in r.output  # the name was reported, with the token scrubbed from it
    assert_clean(r.output, SHAPELESS)


def test_unexpected_crash_prints_no_locals(fix, graph_dir, monkeypatch):
    assert app.pretty_exceptions_show_locals is False

    def crash(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(entra, "collect_entra", crash)
    live(monkeypatch, Tenant(graph_dir))
    r = scan(fix, SHAPELESS, "--entra")
    assert isinstance(r.exception, RuntimeError)
    assert_clean(r.output, SHAPELESS)


def test_malformed_expiry_keeps_the_credential_without_a_date():
    obj = {"passwordCredentials": [{"keyId": "k", "endDateTime": "tomorrow-ish"}]}
    [c] = entra._expiries(obj)
    assert c.key_id == "k" and c.end_date_time is None


def test_remember_secret_scrubs_exact_values_only():
    remember_secret(SHAPELESS)
    remember_secret("short")  # too short to scrub safely
    assert redact(f"x {SHAPELESS} y short") == f"x {REDACTED} y short"
