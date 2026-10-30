"""`--entra-mock` runs the real client over fixtures; `--entra` needs env vars, says read-only."""

import socket

import httpx
import pytest
from typer.testing import CliRunner

from apl.cli import app
from apl.collectors.entra import EntraError, FixtureTransport, GraphClient, collect_mock

LINKED = {
    "a1a1a1a1-0000-4000-8000-000000000001": "mail-triage",
    "a2a2a2a2-0000-4000-8000-000000000002": "calendar-reader",
    "a3a3a3a3-0000-4000-8000-000000000003": "orphan-files",
    "a4a4a4a4-0000-4000-8000-000000000004": "custom-scope",
}


@pytest.fixture
def no_network(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("mock mode touched the network")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


def args(fix):
    d = fix / "entra"
    return ["scan", "-c", str(d / "mcp.json"), "-t", str(d / "tools.json")]


def test_fixtures_page_and_shape_like_graph(fix, no_network):
    snapshot = collect_mock(fix / "graph", LINKED)
    assert snapshot.source == "mock"
    assert {k: a.display_name for k, a in snapshot.apps.items()} == LINKED  # "unrelated" not read


def test_page_two_is_reached(fix):
    client = GraphClient(lambda: "mock", FixtureTransport(fix / "graph"))
    assert len(client.get_all("/applications")) == 5


def test_mock_transport_goes_through_the_guard(fix):
    client = GraphClient(lambda: "mock", FixtureTransport(fix / "graph"))
    with pytest.raises(EntraError):
        client._http.delete("https://graph.microsoft.com/v1.0/applications")


def test_unknown_path_is_a_404_not_a_file_read(fix):
    transport = FixtureTransport(fix / "graph")
    for path in ["/v1.0/..%5C..%5Csecrets", "/v1.0/nothing"]:
        req = httpx.Request("GET", f"https://graph.microsoft.com{path}")
        assert transport.handle_request(req).status_code == 404


def test_cli_mock_runs_without_network(fix, no_network, monkeypatch):
    for name in ("TENANT_ID", "CLIENT_ID", "CLIENT_SECRET"):
        monkeypatch.delenv(name, raising=False)
    r = CliRunner().invoke(app, [*args(fix), "--entra-mock", str(fix / "graph")])
    assert r.exit_code == 0, r.output
    assert "NOTICE" not in r.output


def test_cli_mock_missing_directory_is_exit_2(fix, tmp_path):
    r = CliRunner().invoke(app, [*args(fix), "--entra-mock", str(tmp_path / "nope")])
    assert r.exit_code == 2 and "not found" in r.output


def test_cli_mock_and_live_are_exclusive(fix):
    r = CliRunner().invoke(app, [*args(fix), "--entra", "--entra-mock", str(fix / "graph")])
    assert r.exit_code == 2 and "not both" in r.output


def test_cli_live_needs_env_and_prints_read_only_notice(fix, monkeypatch, no_network):
    monkeypatch.delenv("CLIENT_SECRET", raising=False)
    monkeypatch.setenv("TENANT_ID", "contoso.example")
    monkeypatch.setenv("CLIENT_ID", "client")
    r = CliRunner().invoke(app, [*args(fix), "--entra"])
    assert r.exit_code == 2
    assert "Read-only" in r.output and "CLIENT_SECRET" in r.output
