"""Markdown snapshot tests for the clean and dirty fixtures.

To update after an intended change: APL_UPDATE_SNAPSHOTS=1 pytest tests/test_report_snapshots.py
then review the diff of tests/snapshots/*.md before committing.
"""

import os
from datetime import UTC, datetime
from functools import partial
from pathlib import Path

import pytest

from apl.collectors.entra import collect_mock
from apl.report.markdown import render_markdown
from apl.scan import run_scan

ROOT = Path(__file__).resolve().parent.parent
SNAPSHOTS = Path(__file__).parent / "snapshots"
FIXED_TIME = datetime(2026, 1, 1, tzinfo=UTC)
F = Path("tests/fixtures")  # relative on purpose: paths appear in the report
CASES = {
    "clean": ([F / "clean/mcp.json"], F / "clean/agent.yaml", [F / "clean/tools.json"]),
    "dirty": (
        [F / "configs/claude_desktop.json"],
        F / "agents/release_notes_bot.yaml",
        [F / "tools/claude_desktop_tools.json"],
    ),
    "entra": ([F / "entra/mcp.json"], F / "entra/agent.yaml", [F / "entra/tools.json"]),
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_markdown_snapshot(name, monkeypatch):
    monkeypatch.chdir(ROOT)
    configs, agent, tools = CASES[name]
    entra = partial(collect_mock, F / "graph") if name == "entra" else None
    report = run_scan(configs, agent, tools, entra=entra, now=FIXED_TIME)
    actual = render_markdown(report)
    path = SNAPSHOTS / f"{name}.md"
    if os.environ.get("APL_UPDATE_SNAPSHOTS") == "1":
        path.parent.mkdir(exist_ok=True)
        path.write_text(actual, encoding="utf-8", newline="\n")
    expected = path.read_text(encoding="utf-8").replace("\r\n", "\n")
    assert actual == expected, f"snapshot {name}.md differs; see module docstring to update"
