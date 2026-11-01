"""--anonymise-names: planted names against every output, and the things it must leave alone."""

import json
import logging
import shutil
import traceback

import httpx
import pytest
from typer.testing import CliRunner

import apl.collectors.entra as entra
from apl import idmask
from apl.cli import app
from apl.idmask import mask_names, pseudonym, register_name, set_anonymise_names

MAIL_OBJECT = "b1b1b1b1-0000-4000-8000-000000000001"
MAIL_APP = "a1a1a1a1-0000-4000-8000-000000000001"
# Long enough to be cut in subjects, and full of characters md and JSON escape.
APP_NAME = 'Contoso & Sons "Payroll" | Robot for the finance team in the northern region office'
SP_NAME = "Enterprise App Called Something Else"
CRED_NAME = "Secret For The Quarterly Close"
RESOURCE_NAME = "Fabrikam Ledger API"
SERVER = "payroll-bot"
ODD_SERVER = 'R&D "files"'
GHOST_SERVER = "server-only-in-agent-yaml"
PLANTS = [APP_NAME, SP_NAME, CRED_NAME, RESOURCE_NAME, SERVER, ODD_SERVER, GHOST_SERVER]
FRAGMENTS = ["Sons", "Payroll", "Robot", "northern region", "R&amp;D", "R&D", "Fabrikam"]
FORMATS = ["md", "json", "sarif"]


def assert_clean(**surfaces):
    assert surfaces
    for surface, text in surfaces.items():
        for value in [*PLANTS, *FRAGMENTS]:
            assert value not in text, f"{value!r} leaked in {surface}"
            assert json.dumps(value)[1:-1] not in text, f"{value!r} (escaped) in {surface}"


def rewrite(path, change):
    data = json.loads(path.read_text(encoding="utf-8"))
    change(data)
    path.write_text(json.dumps(data), encoding="utf-8")


@pytest.fixture
def world(fix, tmp_path):
    graph = tmp_path / "graph"
    shutil.copytree(fix / "graph", graph)

    def apps(data):
        data["value"][0]["displayName"] = APP_NAME
        data["value"][0]["passwordCredentials"][0]["displayName"] = CRED_NAME

    def sps(data):
        data["value"][1]["displayName"] = SP_NAME
        data["value"].append(
            {"id": "d9d9", "appId": "f9f9", "displayName": RESOURCE_NAME, "appRoles": []}
        )

    def grants(data):
        data["value"].append(
            {"clientId": "c1c1c1c1-0000-4000-8000-000000000001", "resourceId": "d9d9",
             "consentType": "Principal", "scope": "Ledger.Read"}
        )

    rewrite(graph / "applications.json", apps)
    rewrite(graph / "servicePrincipals.json", sps)
    rewrite(graph / "oauth2PermissionGrants.json", grants)

    def rename(data):
        table = data.get("mcpServers", data)
        table[SERVER] = table.pop("mail")
        table[ODD_SERVER] = table.pop("files")

    config, tools = tmp_path / "mcp.json", tmp_path / "tools.json"
    shutil.copy(fix / "entra/mcp.json", config)
    shutil.copy(fix / "entra/tools.json", tools)
    rewrite(config, rename)
    rewrite(tools, rename)
    agent = tmp_path / "agent.yaml"
    agent.write_text(
        f"name: demo\npurpose: p\nservers:\n  - server: {GHOST_SERVER}\n", encoding="utf-8"
    )
    return {"graph": graph, "config": config, "tools": tools, "agent": agent, "tmp": tmp_path}


def scan(world, *extra):
    args = ["scan", "-c", str(world["config"]), "-t", str(world["tools"])]
    args += ["-a", str(world["agent"]), "--entra-mock", str(world["graph"])]
    return CliRunner().invoke(app, [*args, *extra])


@pytest.mark.parametrize("fmt", FORMATS)
def test_no_name_in_any_output(world, caplog, fmt):
    caplog.set_level(logging.DEBUG)
    out = world["tmp"] / f"report.{fmt}"
    streamed = scan(world, "--anonymise-names", "-f", fmt)
    written = scan(world, "--anonymise-names", "-f", fmt, "--out", str(out))
    assert streamed.exit_code == 0 and written.exit_code == 0, streamed.output
    text = out.read_text(encoding="utf-8")
    assert_clean(
        stdout=streamed.stdout,
        stderr=streamed.stderr,
        written_stderr=written.stderr,
        out_file=text,
        logs=caplog.text,
    )
    assert "app-name-" in text and "server-name-" in text
    assert "sp-name-" in text  # the other API's name, inside a permission


@pytest.mark.parametrize("fmt", FORMATS)
def test_the_names_really_are_there_without_the_flag(world, fmt):
    r = scan(world, "-f", fmt, "--show-ids")
    assert r.exit_code == 0
    assert SERVER in r.stdout and json.dumps(GHOST_SERVER)[1:-1] in r.stderr
    assert "Robot" in r.stdout and "Fabrikam" in r.stdout


def test_off_by_default(world):
    r = scan(world, "-f", "json")
    assert SERVER in r.stdout and "server-name-" not in r.stdout


def test_titles_and_permissions_still_print(world):
    text = scan(world, "--anonymise-names", "-f", "json").stdout
    assert "Granted scope broader than any tool needs" in text
    assert "Mail.ReadWrite" in text and "Mail.Send" in text
    assert "Ledger.Read" in text


def test_finding_ids_do_not_depend_on_the_flag(world):
    def ids(*flags):
        report = json.loads(scan(world, "-f", "json", *flags).stdout)
        return sorted(f["id"] for f in report["findings"])

    assert ids() == ids("--anonymise-names") == ids("--anonymise-names", "--show-ids")


def test_works_with_show_ids(world):
    r = scan(world, "--anonymise-names", "--show-ids", "-f", "json")
    assert MAIL_APP in r.stdout
    assert_clean(stdout=r.stdout, stderr=r.stderr)


def test_same_name_same_pseudonym_and_the_salt_applies(monkeypatch):
    first = pseudonym("app-name", APP_NAME)
    assert first.startswith("app-name-") and first == pseudonym("app-name", APP_NAME)
    idmask.reset()
    monkeypatch.setenv(idmask.SALT_ENV, "another-salt-of-enough-length")
    assert pseudonym("app-name", APP_NAME) != first


def test_shortened_name_gives_the_full_names_pseudonym():
    set_anonymise_names(True)
    register_name("app-name", APP_NAME)
    register_name("app-name", APP_NAME[:60], full=APP_NAME)
    assert mask_names(APP_NAME[:60]) == pseudonym("app-name", APP_NAME)


@pytest.mark.parametrize(
    "text",
    ["Mail.ReadWrite", "mail-triage", "send_mail", "mail.contoso.example", "Mail", "email"],
)
def test_a_plain_word_server_name_leaves_other_words_alone(text):
    set_anonymise_names(True)
    register_name("server-name", "mail")
    assert mask_names(text) == text


@pytest.mark.parametrize(
    "text",
    ["mail", "mail/x", "'mail'", "on mail.", "mail: warning", "/mcpServers/mail/env", "`mail`"],
)
def test_a_plain_word_server_name_is_found_where_it_stands_alone(text):
    set_anonymise_names(True)
    register_name("server-name", "mail")
    assert "mail" not in mask_names(text).replace("server-name-", "")


def test_a_name_holding_an_id_goes_whole():
    set_anonymise_names(True)
    name = f"agent {MAIL_APP}"
    register_name("app-name", name)
    idmask.register("app", MAIL_APP)
    assert idmask.mask(f"see {name}.") == f"see {pseudonym('app-name', name)}."


def test_flag_does_not_outlive_the_command(world):
    scan(world, "--anonymise-names")
    register_name("server-name", SERVER)
    assert mask_names(SERVER) == SERVER


def test_inventory_takes_the_flag(world):
    args = ["inventory", "-c", str(world["config"]), "-a", str(world["agent"])]
    r = CliRunner().invoke(app, [*args, "--anonymise-names"])
    assert r.exit_code == 0, r.output
    assert json.loads(r.stdout)["servers"]
    assert_clean(stdout=r.stdout, stderr=r.stderr)


def test_crash_message_has_no_name(world, monkeypatch):
    def crash(*a, **k):
        raise RuntimeError(f"bug near {SERVER} and {GHOST_SERVER}")

    monkeypatch.setattr("apl.report.render", crash)
    r = scan(world, "--anonymise-names")
    assert r.exception is not None
    assert_clean(traceback="".join(traceback.format_exception(r.exception)), stderr=r.stderr)


def test_live_scan_too(world, monkeypatch):
    class Live(httpx.BaseTransport):
        def __init__(self):
            self.fixtures = entra.FixtureTransport(world["graph"])

        def handle_request(self, request):
            if request.url.host == "login.microsoftonline.com":
                return httpx.Response(200, json={"expires_in": 3599, "access_token": "opaque-x"})
            return self.fixtures.handle_request(request)

    monkeypatch.setattr(entra, "_live_transport", Live)
    env = {"TENANT_ID": "contoso.example", "CLIENT_ID": "client", "CLIENT_SECRET": "x" * 20}
    args = ["scan", "-c", str(world["config"]), "-t", str(world["tools"]), "--entra"]
    r = CliRunner().invoke(app, [*args, "--anonymise-names"], env=env)
    assert r.exit_code == 0, r.output
    assert_clean(stdout=r.stdout, stderr=r.stderr)
