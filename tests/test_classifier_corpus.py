"""Classifier accuracy against a hand-labelled tool-name corpus.

Run `pytest -s tests/test_classifier_corpus.py` to see the report. Each tool lands in one bucket:

  exact - predicted set == label
  under - predicted max risk < labelled max risk (DANGEROUS: the linter would understate power)
  over  - any other mismatch: extra capabilities, or a missing one outranked by a riskier
          prediction (e.g. archive labelled write, predicted delete)

Risk order is models.CAPABILITY_RISK. The floors are regression guards set at the measured
baseline. Do not edit corpus labels to make this pass.
"""

from pathlib import Path

import yaml

from apl.classifier import classify_tool
from apl.models import CAPABILITY_RISK, Capability, Tool

CORPUS = Path(__file__).parent / "fixtures" / "tool_corpus.yaml"
# under-classified cases must never increase. 1 = download_file after its relabel to
# [network, read, write]: a newly visible gap, not a classifier regression.
MAX_UNDER = 1
MIN_EXACT = 42  # 43 after Step B (was 36); 42 after the download_file relabel


def _max_risk(caps: set[Capability]) -> int:
    return max((CAPABILITY_RISK[c] for c in caps), default=0)


def _load():
    return yaml.safe_load(CORPUS.read_text(encoding="utf-8"))


def _bucket(expected: set[Capability], got: set[Capability]) -> str:
    if got == expected:
        return "exact"
    if _max_risk(got) < _max_risk(expected):
        return "under"
    return "over"


def test_corpus_shape():
    corpus = _load()
    assert 30 <= len(corpus) <= 50
    names = [e["name"] for e in corpus]
    assert len(names) == len(set(names))
    for required in ("run_query", "manage_files", "sync"):
        assert required in names


def test_bucket_definitions():
    R, W, D = Capability.READ, Capability.WRITE, Capability.DELETE
    assert _bucket({R}, {R}) == "exact"
    assert _bucket({D}, {R, W}) == "under"
    assert _bucket({W}, {R, W}) == "over"
    assert _bucket({W}, {D}) == "over"


def test_classifier_accuracy_report():
    corpus = _load()
    buckets: dict[str, list[str]] = {"exact": [], "under": [], "over": []}
    lines = []
    for e in corpus:
        expected = {Capability(c) for c in e["expected"]}
        got = classify_tool(Tool(name=e["name"])).capabilities
        b = _bucket(expected, got)
        buckets[b].append(e["name"])
        if b != "exact":
            amb = " [ambiguous]" if e.get("ambiguous") else ""
            exp_s, got_s = sorted(c.value for c in expected), sorted(c.value for c in got)
            lines.append(f"  {b.upper():5} {e['name']}{amb}: expected {exp_s} got {got_s}")
    n = len(corpus)
    print()
    for b in ("exact", "under", "over"):
        print(f"{b:5}: {len(buckets[b]):2}/{n} = {len(buckets[b]) / n:.0%}")
    print("mismatches:\n" + "\n".join(lines))
    assert len(buckets["under"]) <= MAX_UNDER, f"under-classified: {buckets['under']}"
    assert len(buckets["exact"]) >= MIN_EXACT
