"""--anonymise-names: the agent name in reports, and command, args and url in apl inventory."""

import json

import pytest
from typer.testing import CliRunner

from apl.cli import app
from apl.idmask import pseudonym
from apl.redact import REDACTED

AGENT = 'Payroll & "Finance" Copilot'
COMMAND = "C:/finance/bin/payroll-mcp.exe"
ARG = "--ledger=fabrikam-prod"
URL = "https://ledger.fabrikam.example/mcp"
SECRET = "ghp_FAKEfakeFAKEfakeFAKEfakeFAKEfake0000"  # noqa: S105
PLANTS = [AGENT, "Payroll", "Finance", COMMAND, "payroll-mcp", ARG, "fabrikam", URL]
FORMATS = ["md", "json", "sarif"]


def assert_clean(**surfaces):
    assert surfaces
    for surface, text in surfaces.items():
        for value in [*PLANTS, SECRET, json.dumps(AGENT)[1:-1]]:
            assert value not in text, f"{value!r} leaked in {surface}"


@pytest.fixture
def world(tmp_path):
    config = tmp_path / "mcp.json"
    servers = {
        "local": {"command": COMMAND, "args": [ARG, "-y", "--token", SECRET]},
        "remote": {"type": "http", "url": URL},
    }
    config.write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
    agent = tmp_path / "agent.yaml"
    agent.write_text(f"name: {json.dumps(AGENT)}\npurpose: p\n", encoding="utf-8")
    return config, agent, tmp_path


def run(*args):
    return CliRunner().invoke(app, [str(a) for a in args])


def inventory(world, *flags):
    config, agent, _ = world
    r = run("inventory", "-c", config, "-a", agent, *flags)
    assert r.exit_code == 0, r.output
    return r, json.loads(r.stdout)


@pytest.mark.parametrize("fmt", FORMATS)
def test_agent_name_is_gone_from_reports(world, fmt):
    config, agent, tmp = world
    out = tmp / f"r.{fmt}"
    streamed = run("scan", "-c", config, "-a", agent, "-f", fmt, "--anonymise-names")
    written = run("scan", "-c", config, "-a", agent, "-f", fmt, "--anonymise-names", "--out", out)
    assert streamed.exit_code == 0 and written.exit_code == 0, streamed.output
    assert_clean(
        stdout=streamed.stdout,
        stderr=streamed.stderr,
        written_stderr=written.stderr,
        out_file=out.read_text(encoding="utf-8"),
    )


def test_header_shows_the_pseudonym(world):
    config, agent, _ = world
    r = run("scan", "-c", config, "-a", agent, "--anonymise-names")
    assert f"- **Agent:** {pseudonym('agent-name', AGENT)}" in r.stdout


def test_json_agent_field_shows_the_pseudonym(world):
    config, agent, _ = world
    r = run("scan", "-c", config, "-a", agent, "-f", "json", "--anonymise-names")
    data = json.loads(r.stdout)
    assert data["agent"]["name"] == pseudonym("agent-name", AGENT)


def test_agent_name_prints_without_the_flag(world):
    config, agent, _ = world
    assert "Copilot" in run("scan", "-c", config, "-a", agent).stdout


def test_inventory_fields_are_pseudonyms(world):
    r, data = inventory(world, "--anonymise-names")
    assert_clean(stdout=r.stdout, stderr=r.stderr)
    local, remote = data["servers"]
    assert local["command"] == "[cmd-1]"
    assert local["args"] == ["[arg-1]", "[arg-2]", "[arg-3]", REDACTED]
    assert remote["url"] == "[url-2]"
    assert data["agent"]["name"] == pseudonym("agent-name", AGENT)


def test_inventory_prints_them_without_the_flag(world):
    _, data = inventory(world)
    assert data["servers"][0]["command"] == COMMAND
    assert data["servers"][1]["url"] == "https://ledger.fabrikam.example/[path-redacted]"


def test_redacted_args_stay_visible_and_are_never_hashed(world):
    r, data = inventory(world, "--anonymise-names")
    assert REDACTED in data["servers"][0]["args"]
    assert_clean(stdout=r.stdout)


def test_flag_value_form_of_a_redacted_arg_stays_whole(tmp_path):
    config = tmp_path / "mcp.json"
    server = {"command": "c", "args": ["--mode=fast", f"--token={SECRET}", "--region=eu"]}
    config.write_text(json.dumps({"mcpServers": {"s": server}}), encoding="utf-8")
    r = run("inventory", "-c", config, "--anonymise-names")
    args = json.loads(r.stdout)["servers"][0]["args"]
    assert args == ["[arg-1]", f"--token={REDACTED}", "[arg-2]"]


def test_placeholders_number_per_server_and_do_not_link_values(tmp_path):
    """The same value on two servers must not be recognisable, and an unknown secret leaves
    nothing derived from it in the output."""
    config = tmp_path / "mcp.json"
    servers = {
        "a": {"command": "c", "args": ["shared-unrecognised-value"]},
        "b": {"command": "c", "args": ["other", "shared-unrecognised-value"]},
    }
    config.write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
    r = run("inventory", "-c", config, "--anonymise-names")
    a, b = json.loads(r.stdout)["servers"]
    assert a["args"] == ["[arg-1]"] and b["args"] == ["[arg-1]", "[arg-2]"]
    assert "shared-unrecognised-value" not in r.stdout


def test_no_args_is_fine(tmp_path):
    config = tmp_path / "mcp.json"
    config.write_text(json.dumps({"mcpServers": {"s": {"command": "c"}}}), encoding="utf-8")
    assert json.loads(run("inventory", "-c", config, "--anonymise-names").stdout)["servers"]


def test_same_input_same_output_across_runs(world):
    first, second = inventory(world, "--anonymise-names"), inventory(world, "--anonymise-names")
    assert first[1]["servers"] == second[1]["servers"]


def test_inventory_with_show_ids_still_hides_these(world):
    r, _ = inventory(world, "--anonymise-names", "--show-ids")
    assert_clean(stdout=r.stdout)


def test_plain_command_word_is_not_replaced_elsewhere(tmp_path):
    """`npx` goes by field, so the word survives in the rest of the output."""
    config = tmp_path / "mcp.json"
    config.write_text(json.dumps({"mcpServers": {"npx": {"command": "npx"}}}), encoding="utf-8")
    r = run("inventory", "-c", config, "--anonymise-names")
    assert "[cmd-1]" in r.stdout
    assert pseudonym("server-name", "npx") in r.stdout


NOTICE = "free-text fields are not masked: review before sharing"


def test_inventory_notice_goes_to_stderr_under_the_flag(world):
    r, _ = inventory(world, "--anonymise-names")
    assert NOTICE in r.stderr and NOTICE not in r.stdout


def test_inventory_has_no_notice_without_the_flag(world):
    r, _ = inventory(world)
    assert NOTICE not in r.stderr


def test_notice_keeps_stdout_parseable_and_comes_with_show_ids(world):
    r, data = inventory(world, "--anonymise-names", "--show-ids")
    assert NOTICE in r.stderr and data["servers"]


def test_no_notice_when_the_inventory_fails(tmp_path):
    r = run("inventory", "-c", tmp_path / "missing.json", "--anonymise-names")
    assert r.exit_code != 0 and NOTICE not in r.stderr


def test_free_text_really_is_printed_as_written(tmp_path):
    """Pins the documented behaviour: if this changes, the docs and the notice must too."""
    config, agent = tmp_path / "mcp.json", tmp_path / "agent.yaml"
    server = {"command": "c", "env": {"FABRIKAM_API_KEY": "${KEY}"}}
    config.write_text(json.dumps({"mcpServers": {"s": server}}), encoding="utf-8")
    agent.write_text("name: a\npurpose: Helps the payroll team\n", encoding="utf-8")
    r = run("inventory", "-c", config, "-a", agent, "--anonymise-names")
    assert "Helps the payroll team" in r.stdout and "FABRIKAM_API_KEY" in r.stdout
