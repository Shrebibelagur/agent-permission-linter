"""One subject format for anything about a linked app: server / app name (masked id)."""

import re
from functools import partial

import pytest

from apl.collectors.entra import collect_mock
from apl.report import render
from apl.scan import run_scan

FORMAT = re.compile(r"^[\w-]+ / [\w-]+ \([0-9a-f]{4}\.\.\.[0-9a-f]{4}\)( / \S+)*$")
LINKED_RULES = {"APL-001", "APL-004", "APL-005", "APL-006"}


@pytest.fixture
def report(fix):
    d = fix / "entra"
    collect = partial(collect_mock, fix / "graph")
    return run_scan([d / "mcp.json"], d / "agent.yaml", [d / "tools.json"], entra=collect)


def test_every_linked_finding_uses_the_format(report):
    subjects = [f.subject for f in report.result.findings if f.rule_id in LINKED_RULES]
    assert {f.rule_id for f in report.result.findings} == LINKED_RULES
    assert [s for s in subjects if not FORMAT.match(s)] == []


def test_apl001_gets_the_format_from_its_evidence(report):
    [f] = [f for f in report.result.findings if f.rule_id == "APL-001"]
    assert f.subject == "mail / mail-triage (a1a1...0001) / AZURE_CLIENT_ID"


def test_sarif_still_finds_the_server_location(report):
    assert "mail-triage (a1a1...0001)" in render(report, "sarif")
