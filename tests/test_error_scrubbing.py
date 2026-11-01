"""Exceptions, logs and CLI messages: identifiers and secrets go before anything is printed."""

import json
import logging
import traceback

import httpx
import pytest
from typer.testing import CliRunner

import apl.collectors.entra as entra
from apl.cli import UnexpectedError, app
from apl.collectors.entra import (
    ClientCredentialsToken,
    EntraCredentials,
    EntraError,
    GraphClient,
)
from apl.idmask import pseudonym, pseudonymise

TENANT = "11111111-2222-4333-8444-555555555555"
CLIENT = "66666666-7777-4888-9999-000000000000"
OBJECT = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
TOKEN_URL = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"
GRAPH_URL = f"https://graph.microsoft.com/v1.0/applications/{OBJECT}/owners"


def test_entra_error_is_scrubbed_when_it_is_made():
    message = str(EntraError(f"Graph HTTP 403 for /v1.0/applications/{OBJECT}/owners"))
    assert OBJECT not in message and pseudonym("app", OBJECT) in message


@pytest.mark.parametrize("status", [401, 403, 404])
def test_graph_failure_message_has_no_object_id(status):
    transport = httpx.MockTransport(lambda r: httpx.Response(status))
    client = GraphClient(lambda: "t", transport, sleep=lambda s: None)
    with pytest.raises(EntraError) as e:
        client.get(GRAPH_URL)
    assert OBJECT not in "".join(traceback.format_exception(e.value))


def test_invalid_next_link_does_not_escape_with_its_url():
    client = GraphClient(lambda: "t", httpx.MockTransport(lambda r: httpx.Response(200)))
    with pytest.raises(EntraError) as e:
        client.get(f"https://[bad/{OBJECT}")
    assert OBJECT not in str(e.value)


def test_token_failure_hides_the_endpoint():
    def fail(request):
        raise httpx.ConnectError(f"cannot reach {request.url}", request=request)

    creds = EntraCredentials(TENANT, CLIENT, "x" * 20)
    with pytest.raises(EntraError) as e:
        ClientCredentialsToken(creds, httpx.MockTransport(fail))()
    assert TENANT not in "".join(traceback.format_exception(e.value))


def test_httpx_request_log_is_scrubbed(caplog):
    caplog.set_level(logging.DEBUG)
    logging.getLogger("httpx").info('HTTP Request: POST %s "HTTP/1.1 200 OK"', TOKEN_URL)
    logging.getLogger("httpx").info("HTTP Request: GET %s", GRAPH_URL)
    assert TENANT not in caplog.text and OBJECT not in caplog.text
    assert pseudonym("tenant", TENANT) in caplog.text


def test_logged_exception_is_scrubbed(caplog):
    try:
        raise ValueError(f"boom {OBJECT}")
    except ValueError:
        logging.getLogger("anything").exception("failed on %s", OBJECT)
    assert OBJECT not in caplog.text and "ValueError" in caplog.text


def test_token_endpoint_with_a_domain_tenant_is_scrubbed():
    url = "https://login.microsoftonline.com/contoso.example/oauth2/v2.0/token"
    assert "contoso.example" not in pseudonymise(url)


def test_crash_keeps_its_type_name_and_loses_its_values(fix, monkeypatch):
    def crash(*a, **k):
        raise RuntimeError(f"boom {TOKEN_URL} {OBJECT}")

    monkeypatch.setattr("apl.scan.run_scan", crash)
    r = CliRunner().invoke(app, ["scan", "-c", str(fix / "clean/mcp.json")])
    assert isinstance(r.exception, UnexpectedError)
    text = "".join(traceback.format_exception(r.exception))
    assert "RuntimeError" in text and TENANT not in text and OBJECT not in text


def test_exit_codes_pass_through_the_guard(fix):
    r = CliRunner().invoke(app, ["scan", "-c", str(fix / "clean/mcp.json"), "--connect"])
    assert r.exit_code == 2 and r.exception is None or isinstance(r.exception, SystemExit)


def test_inventory_output_is_scrubbed(tmp_path):
    config = tmp_path / "mcp.json"
    server = {"command": "c", "env": {"AZURE_CLIENT_ID": CLIENT}}
    config.write_text(json.dumps({"mcpServers": {"s": server}}), encoding="utf-8")
    r = CliRunner().invoke(app, ["inventory", "-c", str(config)])
    assert r.exit_code == 0, r.output
    assert CLIENT not in r.output
    assert json.loads(r.stdout)["servers"][0]["credentials"]


def test_out_path_message_is_scrubbed(fix, tmp_path):
    out = tmp_path / f"{OBJECT}.md"
    r = CliRunner().invoke(app, ["scan", "-c", str(fix / "clean/mcp.json"), "--out", str(out)])
    assert r.exit_code == 0 and out.is_file() and OBJECT not in r.output


def test_no_salt_withholds_the_message_rather_than_printing_it(tmp_path, monkeypatch):
    config = tmp_path / "mcp.json"
    config.write_text(json.dumps({"mcpServers": {"s": {"command": "c"}}}), encoding="utf-8")
    monkeypatch.setenv("APL_ID_SALT", "short")
    monkeypatch.setattr(entra, "collect_mock", lambda *a: None)
    out = tmp_path / f"{OBJECT}.md"
    r = CliRunner().invoke(app, ["scan", "-c", str(config), "--out", str(out)])
    assert OBJECT not in r.output
