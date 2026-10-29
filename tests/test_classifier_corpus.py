"""Classifier accuracy against a hand-labelled tool-name corpus.

Run `pytest -s tests/test_classifier_corpus.py` to see the report. The floors below are regression
guards set at the measured baseline, not targets.
"""

from pathlib import Path

import yaml

from apl.classifier import classify_tool
from apl.models import CAPABILITY_RISK, Capability, Tool

CORPUS = Path(__file__).parent / "fixtures" / "tool_corpus.yaml"
EXACT_FLOOR = 0.75
MAX_RISK_UNDERESTIMATES = 5


def _max_risk(caps: set[Capability]) -> int:
    return max((CAPABILITY_RISK[c] for c in caps), default=0)


def _load():
    return yaml.safe_load(CORPUS.read_text(encoding="utf-8"))


def test_corpus_shape():
    corpus = _load()
    assert 30 <= len(corpus) <= 50
    names = [e["name"] for e in corpus]
    assert len(names) == len(set(names))
    for required in ("run_query", "manage_files", "sync"):
        assert required in names


def test_classifier_accuracy_report():
    corpus = _load()
    exact = 0
    under: list[str] = []
    lines = []
    for e in corpus:
        expected = {Capability(c) for c in e["expected"]}
        got = classify_tool(Tool(name=e["name"])).capabilities
        exact += got == expected
        tag = ""
        if _max_risk(got) < _max_risk(expected):
            under.append(e["name"])
            tag = "  <-- RISK UNDERESTIMATED"
        elif not expected <= got:
            tag = "  (missing a capability, but higher risk predicted)"
        if got != expected:
            amb = " [ambiguous]" if e.get("ambiguous") else ""
            exp_s, got_s = sorted(c.value for c in expected), sorted(c.value for c in got)
            lines.append(f"  {e['name']}{amb}: expected {exp_s} got {got_s}{tag}")
    acc = exact / len(corpus)
    print(f"\nclassifier exact-match accuracy: {exact}/{len(corpus)} = {acc:.0%}")
    print(f"risk underestimated: {len(under)} {under}")
    print("mismatches:\n" + "\n".join(lines))
    assert acc >= EXACT_FLOOR
    assert len(under) <= MAX_RISK_UNDERESTIMATES
