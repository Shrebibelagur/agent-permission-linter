"""Shared bucketing for the classifier corpus tests.

Each tool lands in exactly one bucket:

  exact   - predicted set == label
  missing - at least one labelled capability is not predicted (DANGEROUS: the linter would
            understate what the tool can do, even if it predicts something riskier)
  extra   - every labelled capability is predicted, plus more (NOISY: false alarms only)
  unclassified - classifier returned {unknown} with a review flag. Not silent, so it is kept out
            of "missing"; the report also prints "missing + unclassified" as the stricter view.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import yaml

from apl.classifier import classify_tool
from apl.models import Capability, Tool

FIXTURES = Path(__file__).parent / "fixtures"
MAIN = FIXTURES / "tool_corpus.yaml"
HOLDOUT = FIXTURES / "tool_corpus_holdout.yaml"
BUCKETS = ("exact", "missing", "extra", "unclassified")


def load(path: Path) -> list[dict]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def bucket(expected: set[Capability], got: set[Capability]) -> str:
    if got == expected:
        return "exact"
    if got == {Capability.UNKNOWN}:
        return "unclassified"
    if not expected <= got:
        return "missing"
    return "extra"


def name_only(entry: dict) -> Tool:
    return Tool(name=entry["name"])


def report(
    title: str, entries: list[dict], build: Callable[[dict], Tool] = name_only
) -> dict[str, list[str]]:
    """Classify, print a report naming every miss, and return {bucket: [names]}."""
    out: dict[str, list[str]] = {b: [] for b in BUCKETS}
    lines = []
    for e in entries:
        expected = {Capability(c) for c in e["expected"]}
        got = classify_tool(build(e)).capabilities
        b = bucket(expected, got)
        out[b].append(e["name"])
        if b != "exact":
            amb = " [ambiguous]" if e.get("ambiguous") else ""
            missing = sorted(c.value for c in expected - got)
            extra = sorted(c.value for c in got - expected)
            diff = f"  missing {missing}" if missing else ""
            diff += f"  extra {extra}" if extra else ""
            exp_s, got_s = sorted(c.value for c in expected), sorted(c.value for c in got)
            if b == "unclassified":
                diff = ""
            lines.append(f"  {b.upper():12} {e['name']}{amb}: expected {exp_s} got {got_s}{diff}")
    n = len(entries)
    print(f"\n{title} ({n} names)")
    for b in BUCKETS:
        print(f"  {b:12}: {len(out[b]):2}/{n} = {len(out[b]) / n:.0%}")
    strict = len(out["missing"]) + len(out["unclassified"])
    print(f"  {'(missing + unclassified)':12}: {strict}/{n}")
    print("  misses:\n" + ("\n".join(lines) or "    none"))
    return out
