import pytest
from builders import inventory, server, tool

from apl.models import AgentSpec, ServerPurpose, Severity
from apl.parsers.mcp_config import parse_config_dict
from apl.rules import run_rules
from apl.rules.apl010_no_approval_gate import check

TOOLS = [tool("get_file_contents"), tool("delete_repository"), tool("frobnicate")]


def srv(approve, tools=TOOLS):
    return server(tools=tools, auto_approve=approve, auto_approve_pointer="/mcpServers/github/x")


def test_positive_destructive_tool_auto_approved():
    (f,) = check(inventory(srv(["delete_repository", "get_file_contents"]))).findings
    assert f.rule_id == "APL-010" and f.status == "violation" and f.severity is Severity.HIGH
    assert f.subject == "github/delete_repository"
    assert f.evidence[0].pointer == "/mcpServers/github/x"
    assert [m.id for m in f.suggested_mappings] == ["LLM06:2025"]
    assert f.suggested_mappings[0].label == "suggested mapping"


def test_unclassified_tool_counts_as_high_impact():
    (f,) = check(inventory(srv(["frobnicate"]))).findings
    assert f.severity is Severity.MEDIUM and f.confidence == 0.5
    assert "until reviewed" in f.confidence_reason


def test_declared_gate_contradicted_raises_severity():
    agent = AgentSpec(name="b", purpose="p",
                      servers=[ServerPurpose(server="github", approval_gate=True)])
    (f,) = check(inventory(srv(["delete_repository"]), agent=agent)).findings
    assert f.severity is Severity.CRITICAL and "approval_gate" in f.confidence_reason


def test_negative_only_read_tools_or_empty_list():
    assert check(inventory(srv(["get_file_contents"]))).findings == []
    res = check(inventory(srv([])))
    assert res.findings == [] and res.skips == []


def test_skip_missing_auto_approve_list():
    res = check(inventory(server(tools=TOOLS)))
    assert res.findings == []
    assert res.skips[0].reason == (
        "not evaluated: missing auto-approve list (no autoApprove/alwaysAllow in config)"
    )


def test_skip_missing_tool_list():
    res = check(inventory(srv(["delete_repository"], tools=[])))
    assert res.skips[0].reason == "not evaluated: missing tool list"


@pytest.mark.parametrize("key", ["autoApprove", "alwaysAllow"])
def test_parser_reads_auto_approve(key):
    servers, _ = parse_config_dict({"mcpServers": {"a": {"command": "x", key: ["t1"]}}}, "c")
    assert servers[0].auto_approve == ["t1"]
    assert servers[0].auto_approve_pointer == f"/mcpServers/a/{key}"


def test_parser_absent_and_non_list():
    servers, _ = parse_config_dict({"mcpServers": {"a": {"command": "x"}}}, "c")
    assert servers[0].auto_approve is None
    servers, warns = parse_config_dict(
        {"mcpServers": {"a": {"command": "x", "autoApprove": True}}}, "c"
    )
    assert servers[0].auto_approve is None and any("not a list" in w for w in warns)


def test_clean_fixture_has_no_findings(clean_inventory):
    res = check(clean_inventory)
    assert res.findings == []
    assert {s.subject for s in res.skips} == {"docs", "tickets"}  # VS Code has no auto-approve


def test_all_rules_on_clean_fixture(clean_inventory):
    res = run_rules(clean_inventory)
    assert res.findings == []
    assert all(s.reason.startswith("not evaluated: missing ") for s in res.skips)
