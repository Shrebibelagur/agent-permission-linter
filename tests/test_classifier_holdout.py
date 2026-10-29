"""Classifier report on the HELD-OUT corpus (tests/fixtures/tool_corpus_holdout.yaml).

Same buckets as test_classifier_corpus.py (exact / under / over), imported so the definitions
cannot drift. Report only: there is deliberately NO accuracy floor yet. Never tune the classifier
against this file or edit its labels to fit.

Run `pytest -s tests/test_classifier_holdout.py` to see the report.
"""

from pathlib import Path

import yaml
from test_classifier_corpus import CORPUS, _bucket

from apl.classifier import classify_tool
from apl.models import Capability, Tool

HOLDOUT = Path(__file__).parent / "fixtures" / "tool_corpus_holdout.yaml"


def _load(path: Path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_holdout_shape():
    holdout = _load(HOLDOUT)
    names = [e["name"] for e in holdout]
    assert holdout and len(names) == len(set(names))
    for e in holdout:
        {Capability(c) for c in e["expected"]}  # every label is a known capability


def test_holdout_report():
    holdout = _load(HOLDOUT)
    main = {e["name"]: set(e["expected"]) for e in _load(CORPUS)}
    buckets: dict[str, list[str]] = {"exact": [], "under": [], "over": []}
    lines = []
    for e in holdout:
        expected = {Capability(c) for c in e["expected"]}
        got = classify_tool(Tool(name=e["name"])).capabilities
        b = _bucket(expected, got)
        buckets[b].append(e["name"])
        if b != "exact":
            amb = " [ambiguous]" if e.get("ambiguous") else ""
            exp_s, got_s = sorted(c.value for c in expected), sorted(c.value for c in got)
            missing = sorted(c.value for c in expected - got)
            extra = sorted(c.value for c in got - expected)
            diff = f"  missing {missing}" if missing else ""
            diff += f"  extra {extra}" if extra else ""
            lines.append(
                f"  {b.upper():5} {e['name']}{amb}: expected {exp_s} got {got_s}{diff}"
            )
    n = len(holdout)
    print(f"\nHELD-OUT corpus ({n} names)")
    for b in ("exact", "under", "over"):
        print(f"{b:5}: {len(buckets[b]):2}/{n} = {len(buckets[b]) / n:.0%}")
    print("misses:\n" + ("\n".join(lines) or "  none"))
    overlap = sorted(set(main) & {e["name"] for e in holdout})
    print(f"also in main corpus ({len(overlap)}): {overlap}")
    conflicts = [
        e["name"] for e in holdout if e["name"] in main and set(e["expected"]) != main[e["name"]]
    ]
    print(f"label differs from main corpus: {conflicts or 'none'}")
