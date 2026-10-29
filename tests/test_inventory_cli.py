import json

import pytest
from typer.testing import CliRunner

from apl.cli import app
from apl.inventory import build_inventory
from apl.models import Capability
from apl.parsers.agent_spec import load_agent_spec
from apl.parsers.mcp_config import ConfigParseError


def test_agent_spec_loads(fix):
    spec = load_agent_spec(fix / "agents/release_notes_bot.yaml")
    assert spec.name == "release-notes-bot"
    gh = next(s for s in spec.servers if s.server == "github")
    assert gh.required_capabilities == {Capability.READ, Capability.WRITE}
    assert gh.approval_gate


def test_agent_spec_strict(fix):
    with pytest.raises(ConfigParseError, match="unexpected_key"):
        load_agent_spec(fix / "agents/invalid_extra_key.yaml")


def test_inventory_end_to_end(fix):
    inv = build_inventory(
        [fix / "configs/claude_desktop.json"],
        fix / "agents/release_notes_bot.yaml",
        [fix / "tools/claude_desktop_tools.json"],
    )
    gh = next(s for s in inv.servers if s.name == "github")
    assert gh.tools_source == "fixture"
    assert Capability.DELETE in gh.granted_capabilities()  # exceeds declared read+write
    assert any("prompt injection" in w for w in inv.warnings)
    fs = next(s for s in inv.servers if s.name == "filesystem")
    assert Capability.WRITE in fs.granted_capabilities()


def test_inventory_warns_on_undeclared_server(fix):
    inv = build_inventory(
        [fix / "configs/vscode_mcp.json"], fix / "agents/release_notes_bot.yaml", None
    )
    assert any("no declared purpose" in w for w in inv.warnings)
    assert any("not present in config" in w for w in inv.warnings)


def test_cli_inventory_output_redacted(fix):
    r = CliRunner().invoke(
        app,
        [
            "inventory",
            "-c",
            str(fix / "configs/claude_desktop.json"),
            "-t",
            str(fix / "tools/claude_desktop_tools.json"),
        ],
    )
    assert r.exit_code == 0, r.output
    assert "ghp_FAKE" not in r.output and "8Q~FAKE" not in r.output
    data = json.loads(r.stdout[r.stdout.index("{") :])
    assert len(data["servers"]) == 3


def test_cli_connect_refused(fix):
    r = CliRunner().invoke(
        app, ["inventory", "-c", str(fix / "configs/claude_desktop.json"), "--connect"]
    )
    assert r.exit_code == 2
    assert "WARNING" in r.output
