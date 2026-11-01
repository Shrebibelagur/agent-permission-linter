"""Four planted values against every way out: stdout, stderr, md, json, sarif, --out, logs and
tracebacks, in a mock scan, a live scan and simulated failures."""

import json
import logging
import os
import shutil
import subprocess
import sys
import traceback

import httpx
import pytest
from typer.testing import CliRunner

import apl.collectors.entra as entra
from apl.cli import app
from apl.collectors.entra import FixtureTransport

TENANT = "11111111-2222-4333-8444-555555555555"
CLIENT = "66666666-7777-4888-9999-000000000000"
OBJECT = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
SECRET = "plain-fake-value-no-known-shape-1234"  # noqa: S105
PLANTS = {"tenant": TENANT, "client": CLIENT, "object": OBJECT, "secret": SECRET}
MAIL_APP = "a1a1a1a1-0000-4000-8000-000000000001"
MAIL_OBJECT = "b1b1b1b1-0000-4000-8000-000000000001"
ENV = {"TENANT_ID": TENANT, "CLIENT_ID": CLIENT, "CLIENT_SECRET": SECRET}
FORMATS = ["md", "json", "sarif"]


def assert_clean(**surfaces):
    assert surfaces
    for surface, text in surfaces.items():
        for name, value in PLANTS.items():
            assert value.lower() not in text.lower(), f"{name} leaked in {surface}"


def replace_in(path, *pairs):
    text = path.read_text(encoding="utf-8")
    for old, new in pairs:
        text = text.replace(old, new)
    path.write_text(text, encoding="utf-8")


@pytest.fixture
def world(fix, tmp_path):
    """The agent's own app is the mail app, so its client id and object id are in Graph data.
    Its display name also carries every plant, as tenant-controlled free text."""
    graph = tmp_path / "graph"
    shutil.copytree(fix / "graph", graph)
    named = f'"mail-triage {TENANT} {CLIENT} {OBJECT} {SECRET}"'
    replace_in(
        graph / "applications.json",
        (MAIL_APP, CLIENT),
        (MAIL_OBJECT, OBJECT),
        ('"displayName": "mail-triage"', f'"displayName": {named}'),
        ('"secretText": null', f'"secretText": "{SECRET}"'),
    )
    replace_in(graph / "servicePrincipals.json", (MAIL_APP, CLIENT))
    shutil.move(
        graph / f"applications.{MAIL_OBJECT}.owners.json",
        graph / f"applications.{OBJECT}.owners.json",
    )
    config = tmp_path / "mcp.json"
    shutil.copy(fix / "entra/mcp.json", config)
    replace_in(config, (MAIL_APP, CLIENT))
    return {"graph": graph, "config": config, "tools": fix / "entra/tools.json", "tmp": tmp_path}


class Live(httpx.BaseTransport):
    """Token endpoint and Graph. `fail` may raise or answer for a request."""

    def __init__(self, root, fail=None):
        self.fixtures = FixtureTransport(root)
        self.fail = fail
        self.requests = []

    def handle_request(self, request):
        self.requests.append(request)
        if self.fail:
            reply = self.fail(request)
            if reply is not None:
                return reply
        if request.url.host == "login.microsoftonline.com":
            return httpx.Response(200, json={"expires_in": 3599, "access_token": "opaque-access"})
        return self.fixtures.handle_request(request)


def scan(world, *extra):
    args = ["scan", "-c", str(world["config"]), "-t", str(world["tools"]), *extra]
    return CliRunner().invoke(app, args, env=ENV)


def surfaces(result, caplog):
    out = {"stdout": result.stdout, "stderr": result.stderr, "logs": caplog.text}
    if result.exception is not None:
        out["traceback"] = "".join(traceback.format_exception(result.exception))
    return out


@pytest.fixture
def logs(caplog):
    caplog.set_level(logging.DEBUG)
    return caplog


@pytest.mark.parametrize("fmt", FORMATS)
def test_live_scan(world, monkeypatch, logs, fmt):
    transport = Live(world["graph"])
    monkeypatch.setattr(entra, "_live_transport", lambda: transport)
    out = world["tmp"] / f"report.{fmt}"
    streamed = scan(world, "--entra", "-f", fmt)
    written = scan(world, "--entra", "-f", fmt, "--out", str(out))
    assert streamed.exit_code == 0 and written.exit_code == 0, streamed.output
    assert_clean(
        **surfaces(streamed, logs),
        written_stdout=written.stdout,
        written_stderr=written.stderr,
        out_file=out.read_text(encoding="utf-8"),
    )
    assert "mail-triage" in streamed.stdout  # the scan really reported this app


def test_the_plants_were_really_in_play(world, monkeypatch):
    transport = Live(world["graph"])
    monkeypatch.setattr(entra, "_live_transport", lambda: transport)
    assert scan(world, "--entra").exit_code == 0
    token = transport.requests[0]
    token.read()
    assert TENANT in str(token.url) and SECRET in token.content.decode()
    assert CLIENT in token.content.decode()
    graph_urls = [str(r.url) for r in transport.requests[1:]]
    assert any(OBJECT in u for u in graph_urls)


@pytest.mark.parametrize("fmt", FORMATS)
def test_mock_scan(world, logs, tmp_path, fmt):
    """No env values in mock mode, so ids rest on the GUID guard. The secret was never copied."""
    replace_in(world["graph"] / "applications.json", (f" {SECRET}", ""))
    out = tmp_path / f"mock.{fmt}"
    args = ["--entra-mock", str(world["graph"]), "-f", fmt]
    streamed = scan(world, *args)
    written = scan(world, *args, "--out", str(out))
    assert streamed.exit_code == 0 and written.exit_code == 0, streamed.output
    assert_clean(**surfaces(streamed, logs), out_file=out.read_text(encoding="utf-8"))


def connect_error(request):
    raise httpx.ConnectError(f"All connection attempts failed: {request.url} {SECRET}")


def graph_timeout(request):
    if request.url.host == "graph.microsoft.com":
        raise httpx.ReadTimeout(f"timed out on {request.url}")


def graph_500_on_object(request):
    if OBJECT in str(request.url):
        return httpx.Response(500, headers={"Retry-After": "0"})


def not_an_httpx_error(request):
    raise RuntimeError(f"bug near {request.url} with {TENANT} {CLIENT} {OBJECT} {SECRET}")


def invalid_url(request):
    raise httpx.InvalidURL(f"bad url {request.url}")


@pytest.mark.parametrize(
    "fail", [connect_error, graph_timeout, graph_500_on_object, not_an_httpx_error, invalid_url]
)
def test_simulated_failure(world, monkeypatch, logs, fail):
    transport = Live(world["graph"], fail)
    monkeypatch.setattr(entra, "_live_transport", lambda: transport)
    out = world["tmp"] / "never.md"
    r = scan(world, "--entra", "--out", str(out))
    assert r.exit_code != 0  # it really failed
    assert transport.requests
    assert_clean(**surfaces(r, logs))
    assert not out.exists()


def test_graph_403_on_one_object_is_a_clean_skip(world, monkeypatch, logs):
    def refuse(request):
        if OBJECT in str(request.url):
            return httpx.Response(403)

    monkeypatch.setattr(entra, "_live_transport", lambda: Live(world["graph"], refuse))
    r = scan(world, "--entra")
    assert r.exit_code == 0
    assert_clean(**surfaces(r, logs))


def test_real_process_traceback(world):
    """CliRunner never reaches Typer's traceback printer. A real process does."""
    script = f"""
import sys
import httpx
import apl.collectors.entra as entra
from apl.cli import app


class Crash(httpx.BaseTransport):
    def handle_request(self, request):
        raise RuntimeError(f"bug near {{request.url}} {TENANT} {CLIENT} {OBJECT} {SECRET}")


entra._live_transport = Crash
sys.argv = ["apl", "scan", "-c", {str(world["config"])!r}, "--entra"]
app()
"""
    r = subprocess.run(  # noqa: S603
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env={**os.environ, **ENV},
        timeout=60,
    )
    assert r.returncode != 0
    assert "UnexpectedError" in r.stderr  # the crash really printed
    assert_clean(stdout=r.stdout, stderr=r.stderr)


def test_json_reports_stay_valid_after_scrubbing(world):
    r = scan(world, "--entra-mock", str(world["graph"]), "-f", "json")
    assert json.loads(r.stdout)["findings"]


def test_invalid_url_on_the_token_call_is_a_clean_error_not_a_crash(world, monkeypatch):
    monkeypatch.setattr(entra, "_live_transport", lambda: Live(world["graph"], invalid_url))
    r = scan(world, "--entra")
    assert r.exit_code == 2 and "token request failed: InvalidURL" in r.stderr
