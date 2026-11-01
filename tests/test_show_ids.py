"""--show-ids shows identifiers, warns, and can never show a secret."""

import json

import pytest
from typer.testing import CliRunner

from apl import idmask
from apl.cli import app
from apl.idmask import pseudonym

MAIL_APP = "a1a1a1a1-0000-4000-8000-000000000001"
SECRET = "plain-fake-value-no-known-shape-1234"  # noqa: S105


def scan(fix, *extra):
    d = fix / "entra"
    args = ["scan", "-c", str(d / "mcp.json"), "-t", str(d / "tools.json")]
    args += ["--entra-mock", str(fix / "graph"), *extra]
    return CliRunner().invoke(app, args)


def finding_ids(result):
    return sorted(f["id"] for f in json.loads(result.stdout)["findings"])


def test_off_by_default(fix):
    r = scan(fix, "-f", "json")
    assert MAIL_APP not in r.stdout and pseudonym("app", MAIL_APP) in r.stdout
    assert "--show-ids" not in r.stderr


def test_on_it_shows_ids_and_warns_on_stderr(fix):
    r = scan(fix, "-f", "json", "--show-ids")
    assert MAIL_APP in r.stdout and pseudonym("app", MAIL_APP) not in r.stdout
    assert "WARNING: --show-ids" in r.stderr and "Secrets stay redacted" in r.stderr
    assert "WARNING" not in r.stdout  # the report itself stays parseable


def test_warning_comes_even_with_nothing_to_show(fix):
    r = CliRunner().invoke(app, ["scan", "-c", str(fix / "clean/mcp.json"), "--show-ids"])
    assert "WARNING: --show-ids" in r.stderr


def test_finding_ids_do_not_depend_on_the_flag(fix):
    plain, shown = scan(fix, "-f", "json"), scan(fix, "-f", "json", "--show-ids")
    assert finding_ids(plain) == finding_ids(shown)


def test_flag_does_not_outlive_the_command(fix):
    scan(fix, "--show-ids")
    assert idmask.pseudonymise(MAIL_APP) != MAIL_APP
    assert MAIL_APP not in scan(fix, "-f", "json").stdout


@pytest.mark.parametrize("fmt", ["md", "json", "sarif"])
def test_secrets_stay_redacted(fix, tmp_path, fmt):
    """A secret in a fixture field apl copies: exact-value removal must still apply."""
    from apl.redact import remember_secret

    graph = tmp_path / "graph"
    import shutil

    shutil.copytree(fix / "graph", graph)
    path = graph / "applications.json"
    text = path.read_text(encoding="utf-8").replace('"mail-triage"', f'"mail-triage {SECRET}"')
    path.write_text(text, encoding="utf-8")
    remember_secret(SECRET)
    d = fix / "entra"
    args = ["scan", "-c", str(d / "mcp.json"), "-t", str(d / "tools.json")]
    out = tmp_path / "report"
    args += ["--entra-mock", str(graph), "--show-ids", "-f", fmt, "--out", str(out)]
    r = CliRunner().invoke(app, args)
    assert r.exit_code == 0, r.output
    written = out.read_text(encoding="utf-8")
    assert MAIL_APP in written  # the flag really was on
    assert SECRET not in written and SECRET not in r.output
    assert "[REDACTED]" in written


def test_inventory_takes_the_flag(tmp_path):
    config = tmp_path / "mcp.json"
    server = {"command": "c", "env": {"AZURE_CLIENT_ID": MAIL_APP}}
    config.write_text(json.dumps({"mcpServers": {"s": server}}), encoding="utf-8")
    r = CliRunner().invoke(app, ["inventory", "-c", str(config), "--show-ids"])
    assert MAIL_APP in r.stdout and "WARNING: --show-ids" in r.stderr
