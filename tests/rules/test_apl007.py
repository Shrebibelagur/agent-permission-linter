from builders import inventory, server, tool

from apl.inventory import build_inventory
from apl.models import AgentSpec, Capability, ServerPurpose, Severity
from apl.rules.apl007_exceeds_purpose import check


def agent(**purpose):
    return AgentSpec(name="bot", purpose="p", servers=[ServerPurpose(server="github", **purpose)])


def run(tools, **purpose):
    return check(inventory(server(tools=tools), agent=agent(**purpose)))


def test_positive_tool_exceeds_declared_capabilities():
    res = run([tool("get_file_contents"), tool("delete_repository")],
              required_capabilities={Capability.READ})
    (f,) = res.findings
    assert f.rule_id == "APL-007" and f.status == "violation" and f.severity is Severity.HIGH
    assert f.subject == "github/delete_repository"
    assert f.granted == ["delete"] and f.required == ["read"]
    assert f.confidence == 0.7 and "classifier" in f.confidence_reason
    assert [m.id for m in f.suggested_mappings] == ["LLM06:2025"]
    assert f.suggested_mappings[0].label == "suggested mapping"


def test_required_tools_only_defines_purpose():
    res = run([tool("get_file_contents"), tool("create_issue"), tool("push_files")],
              required_tools=["get_file_contents", "create_issue"])
    assert res.findings == []  # push_files is write, already covered by create_issue
    res = run([tool("get_file_contents"), tool("delete_branch")],
              required_tools=["get_file_contents"])
    assert [f.subject for f in res.findings] == ["github/delete_branch"]


def test_negative_listed_tool_is_declared_even_if_powerful():
    res = run([tool("get_file_contents"), tool("delete_repository")],
              required_capabilities={Capability.READ}, required_tools=["delete_repository"])
    assert res.findings == [] and res.skips == []


def test_unclassified_tool_is_review_not_violation():
    (f,) = run([tool("frobnicate")], required_capabilities={Capability.READ}).findings
    assert f.status == "review_required" and f.severity is Severity.LOW
    assert f.confidence == 0.0 and "Review required" in f.title


def test_low_confidence_tool_is_review_not_violation():
    # manage_files: ambiguous verb, confidence 0.5 -> widest set exceeds read, but no hard verdict
    (f,) = run([tool("manage_files")], required_capabilities={Capability.READ}).findings
    assert f.status == "review_required"


def test_low_confidence_tool_within_purpose_is_fine():
    caps = {Capability.READ, Capability.WRITE}
    assert run([tool("sync")], required_capabilities=caps).findings == []


def test_skip_missing_declared_purpose():
    res = check(inventory(server("other", tools=[tool("x_get")]), agent=agent()))
    assert res.skips[0].reason == "not evaluated: missing declared purpose in agent.yaml"


def test_skip_missing_required_fields():
    res = run([tool("get_x")])
    expected = "not evaluated: missing agent.yaml required_tools or required_capabilities"
    assert res.skips[0].reason == expected and res.findings == []


def test_skip_missing_tool_list_and_agent():
    res = check(inventory(server(), agent=agent(required_capabilities={Capability.READ})))
    assert res.skips[0].reason == "not evaluated: missing tool list"
    assert check(inventory(server())).skips[0].reason == "not evaluated: missing agent.yaml"


def test_dirty_fixture(fix):
    inv = build_inventory(
        [fix / "configs/claude_desktop.json"],
        fix / "agents/release_notes_bot.yaml",
        [fix / "tools/claude_desktop_tools.json"],
    )
    res = check(inv)
    hard = {f.subject for f in res.findings if f.status == "violation"}
    review = {f.subject for f in res.findings if f.status == "review_required"}
    assert hard == {
        "github/delete_repository",
        "filesystem/write_file",
        "filesystem/move_file",
        "graph/runGraphQuery",
    }
    assert review == {"graph/frobnicate"}


def test_clean_fixture_has_no_findings(clean_inventory):
    res = check(clean_inventory)
    assert res.findings == [] and res.skips == []
