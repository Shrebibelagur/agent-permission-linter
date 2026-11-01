"""--anonymise-names: the agent owner, as a field and quoted in free text."""

import json

import pytest
from typer.testing import CliRunner

from apl.cli import app
from apl.idmask import pseudonym

OWNER = "priya.nair@fabrikam.example"
PLANTS = [OWNER, "priya", "fabrikam"]
FORMATS = ["md", "json", "sarif"]


def assert_clean(**surfaces):
    assert surfaces
    for surface, text in surfaces.items():
        for value in PLANTS:
            assert value not in text.lower(), f"{value!r} leaked in {surface}"


@pytest.fixture
def world(fix, tmp_path):
    """The owner is a field, and is quoted in a justification that APL-007 repeats in its fix."""
    config, tools = tmp_path / "mcp.json", tmp_path / "tools.json"
    config.write_text(json.dumps({"mcpServers": {"fs": {"command": "c"}}}), encoding="utf-8")
    tools.write_text(json.dumps({"fs": {"tools": [{"name": "delete_file"}]}}), encoding="utf-8")
    agent = tmp_path / "agent.yaml"
    agent.write_text(
        f"""name: a
purpose: p
owner: {OWNER}
servers:
  - server: fs
    required_capabilities: [read]
    justification: Read only, ask {OWNER}.
""",
        encoding="utf-8",
    )
    return config, tools, agent, tmp_path


def scan(world, *extra):
    config, tools, agent, _ = world
    args = ["scan", "-c", config, "-t", tools, "-a", agent, *extra]
    return CliRunner().invoke(app, [str(a) for a in args])


def test_owner_reaches_a_report_without_the_flag(world):
    assert OWNER in scan(world).stdout  # guards the leak tests below


@pytest.mark.parametrize("fmt", FORMATS)
def test_no_owner_in_any_report_output(world, fmt):
    out = world[3] / f"r.{fmt}"
    streamed = scan(world, "--anonymise-names", "-f", fmt)
    written = scan(world, "--anonymise-names", "-f", fmt, "--out", out)
    assert streamed.exit_code == 0 and written.exit_code == 0, streamed.output
    text = out.read_text(encoding="utf-8")
    assert_clean(
        stdout=streamed.stdout,
        stderr=streamed.stderr,
        written_stderr=written.stderr,
        out_file=text,
    )
    assert pseudonym("owner-name", OWNER) in text


def test_inventory_field_is_a_pseudonym(world):
    config, _, agent, _ = world
    args = ["inventory", "-c", str(config), "-a", str(agent), "--anonymise-names"]
    r = CliRunner().invoke(app, args)
    assert r.exit_code == 0, r.output
    assert_clean(stdout=r.stdout, stderr=r.stderr)
    assert json.loads(r.stdout)["agent"]["owner"] == pseudonym("owner-name", OWNER)


def test_inventory_prints_the_owner_without_the_flag(world):
    config, _, agent, _ = world
    r = CliRunner().invoke(app, ["inventory", "-c", str(config), "-a", str(agent)])
    assert json.loads(r.stdout)["agent"]["owner"] == OWNER


def test_no_owner_set_is_fine(tmp_path):
    config, agent = tmp_path / "mcp.json", tmp_path / "agent.yaml"
    config.write_text(json.dumps({"mcpServers": {"fs": {"command": "c"}}}), encoding="utf-8")
    agent.write_text("name: a\npurpose: p\n", encoding="utf-8")
    args = ["inventory", "-c", str(config), "-a", str(agent), "--anonymise-names"]
    r = CliRunner().invoke(app, args)
    assert r.exit_code == 0 and "owner" not in json.loads(r.stdout)["agent"]
