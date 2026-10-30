"""Classifier report on HELD-OUT set #3 (tests/fixtures/tool_corpus_holdout3.yaml).

The first corpus with parameter names, so the first that exercises schema signals. Reports each
split twice, name only and name+schema, plus the false-alarm block. Report only: NO floor. Never
tune the classifier against this file or edit its labels to fit.

Run `pytest -s tests/test_classifier_holdout3.py` to see the report.
"""

from datetime import UTC, datetime

from corpus_report import FIXTURES, HOLDOUT, MAIN, load, name_only, report

from apl.classifier import CONFLICT_FLAG, classify_tool
from apl.models import (
    AgentSpec,
    Capability,
    Evidence,
    Inventory,
    MCPServer,
    ServerPurpose,
    Tool,
)
from apl.parsers.tools_list import _load
from apl.rules.apl007_exceeds_purpose import check as apl007

HOLDOUT2 = FIXTURES / "tool_corpus_holdout2.yaml"
HOLDOUT3 = FIXTURES / "tool_corpus_holdout3.yaml"
BLOCK_HEADER = "# read tools with generic parameter names"


def with_schema(entry: dict) -> Tool:
    """A real tools/list payload through the real parser: object schema, string properties."""
    properties = {p: {"type": "string"} for p in entry["params"]}
    tool = {"name": entry["name"], "inputSchema": {"type": "object", "properties": properties}}
    return _load({"tools": [tool]})["*"][0]


def generic_block() -> list[dict]:
    """The block is marked only by a comment, which YAML drops, so read it from the raw text."""
    lines = HOLDOUT3.read_text(encoding="utf-8").splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith(BLOCK_HEADER))
    end = next(i for i, line in enumerate(lines) if i > start and line.startswith("#"))
    block = [line for line in lines[start:end] if "name:" in line]
    names = {line.split("name:")[1].split(",")[0].strip() for line in block}
    return [e for e in load(HOLDOUT3) if e["name"] in names]


def apl007_on_read_only_purpose(tool: Tool) -> str:
    purpose = ServerPurpose(server="s", required_capabilities={Capability.READ})
    agent = AgentSpec(name="a", purpose="p", servers=[purpose])
    srv = MCPServer(name="s", tools=[tool], evidence=Evidence(source="c"))
    inv = Inventory(agent=agent, servers=[srv], generated_at=datetime.now(UTC))
    findings = apl007(inv).findings
    return f"{findings[0].status} ({findings[0].severity.value})" if findings else "no finding"


def test_holdout3_shape():
    entries = load(HOLDOUT3)
    names = [e["name"] for e in entries]
    assert entries and len(names) == len(set(names))
    for e in entries:
        {Capability(c) for c in e["expected"]}  # every label is a known capability
        assert isinstance(e["params"], list)
    assert len(generic_block()) == 6


def test_holdout3_report():
    entries = load(HOLDOUT3)
    report("HELD-OUT #3, name only", entries)
    report("HELD-OUT #3, name+schema", entries, with_schema)
    earlier = {e["name"] for path in (MAIN, HOLDOUT, HOLDOUT2) for e in load(path)}
    overlap = sorted(e["name"] for e in entries if e["name"] in earlier)
    print(f"\nalso in an earlier corpus ({len(overlap)}): {overlap or 'none'}")


def test_holdout3_false_alarm_report():
    block = generic_block()
    print(f"\nFALSE ALARMS, read tools with generic parameter names ({len(block)} tools)")
    for title, build in (("name only", name_only), ("name+schema", with_schema)):
        alarms = 0
        print(f"  {title}:")
        for e in block:
            tool = classify_tool(build(e))
            extra = sorted(c.value for c in tool.capabilities - {Capability.READ})
            alarm = bool(tool.capabilities - {Capability.READ, Capability.UNKNOWN})
            alarms += alarm
            conflict = " [conflict]" if CONFLICT_FLAG in tool.classification_flags else ""
            verdict = apl007_on_read_only_purpose(tool)
            print(
                f"    {e['name']}{e['params']}: extra {extra}, "
                f"confidence {tool.classification_confidence:.1f}{conflict}, APL-007: {verdict}"
            )
        print(f"  {title} false-alarm rate: {alarms}/{len(block)} = {alarms / len(block):.0%}")
