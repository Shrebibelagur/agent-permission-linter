"""No full Entra id may reach any output: every id in the Graph fixtures is a planted GUID."""

import json
import re
import shutil
from functools import partial

import pytest
from typer.testing import CliRunner

from apl.cli import app
from apl.collectors.entra import collect_mock
from apl.redact import mask_id, mask_ids
from apl.report import RENDERERS, render
from apl.scan import run_scan

GUID = re.compile(r"(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
PLANTED_APP = "9f8e7d6c-5b4a-4321-8fed-cba987654321"
PLANTED_OBJECT = "1a2b3c4d-5e6f-4a0b-9c8d-7e6f5a4b3c2d"
PLANTED_KEY = "ABCDEF12-3456-4789-ABCD-EF1234567890"  # upper case: Graph ids are not case-bound


def plant(root):
    """A real app in the tenant, under planted ids: one no-owner, expired, high-risk case."""
    path = root / "applications.json"
    text = path.read_text(encoding="utf-8")
    text = text.replace("a1a1a1a1-0000-4000-8000-000000000001", PLANTED_APP)
    text = text.replace("b1b1b1b1-0000-4000-8000-000000000001", PLANTED_OBJECT)
    text = text.replace("f1f1f1f1-0000-4000-8000-000000000001", PLANTED_KEY)
    path.write_text(text, encoding="utf-8")
    shutil.move(
        root / "applications.b1b1b1b1-0000-4000-8000-000000000001.owners.json",
        root / f"applications.{PLANTED_OBJECT}.owners.json",
    )
    (root / f"applications.{PLANTED_OBJECT}.owners.json").write_text(
        json.dumps({"value": []}), encoding="utf-8"
    )
    sps = root / "servicePrincipals.json"
    sps.write_text(
        sps.read_text(encoding="utf-8").replace(
            "a1a1a1a1-0000-4000-8000-000000000001", PLANTED_APP
        ),
        encoding="utf-8",
    )


def unknown_app_config(root):
    path = root / "mcp.json"
    server = {"command": "c", "env": {"AZURE_CLIENT_ID": PLANTED_APP}}
    path.write_text(json.dumps({"mcpServers": {"s": server}}), encoding="utf-8")
    return path


@pytest.fixture
def graph_dir(fix, tmp_path):
    root = tmp_path / "graph"
    shutil.copytree(fix / "graph", root)
    plant(root)
    return root


@pytest.fixture
def config(fix, tmp_path):
    path = tmp_path / "mcp.json"
    text = (fix / "entra/mcp.json").read_text(encoding="utf-8")
    path.write_text(text.replace("a1a1a1a1-0000-4000-8000-000000000001", PLANTED_APP), "utf-8")
    return path


@pytest.fixture
def report(fix, graph_dir, config):
    collect = partial(collect_mock, graph_dir)
    return run_scan([config], fix / "entra/agent.yaml", [fix / "entra/tools.json"], entra=collect)


@pytest.mark.parametrize("fmt", sorted(RENDERERS))
def test_no_full_id_in_any_format(report, fmt):
    text = render(report, fmt)
    assert "mail-triage" in text  # the planted app really was reported
    assert mask_id(PLANTED_APP) in text
    assert GUID.findall(text) == []


def test_all_planted_ids_are_in_the_evidence_before_rendering(report):
    """Guards the test above: the ids must reach the findings for masking to mean anything."""
    raw = json.dumps(report.result.model_dump(mode="json"))
    assert PLANTED_OBJECT in raw or PLANTED_APP in raw
    assert any(GUID.search(e.pointer or "") for f in report.result.findings for e in f.evidence)


@pytest.mark.parametrize("fmt", sorted(RENDERERS))
def test_app_not_found_warning_is_masked(fix, tmp_path, fmt):
    collect = partial(collect_mock, fix / "graph")
    text = render(run_scan([unknown_app_config(tmp_path)], entra=collect), fmt)
    assert PLANTED_APP not in text and mask_id(PLANTED_APP) in text


def test_cli_stderr_is_masked(fix, tmp_path):
    config = unknown_app_config(tmp_path)
    r = CliRunner().invoke(app, ["scan", "-c", str(config), "--entra-mock", str(fix / "graph")])
    assert r.exit_code == 0
    assert GUID.findall(r.output) == []


def test_mask_ids_keeps_the_rest_and_can_run_twice():
    once = mask_ids(f"/applications/{PLANTED_OBJECT}/owners and {PLANTED_KEY}")
    assert once == "/applications/1a2b...3c2d/owners and ABCD...7890"
    assert mask_ids(once) == once
    assert mask_ids("APL-001:d02e76c2cf43 1.2.3") == "APL-001:d02e76c2cf43 1.2.3"
