"""Classifier report on HELD-OUT set #2 (tests/fixtures/tool_corpus_holdout2.yaml).

Buckets: see corpus_report.py (exact / missing / extra / unclassified, plus the stricter
missing + unclassified view). Report only: NO floor yet. Now a DEVELOPMENT set: its misses were
seen before classifier v2 (docs/ASSUMPTIONS.md E5), so it does not measure accuracy. Still never
tune against this file or edit its labels to fit. Names that also appear in an earlier corpus are
listed, because they are not independent.

Run `pytest -s tests/test_classifier_holdout2.py` to see the report.
"""

from corpus_report import FIXTURES, HOLDOUT, MAIN, load, report

from apl.models import Capability

HOLDOUT2 = FIXTURES / "tool_corpus_holdout2.yaml"


def test_holdout2_shape():
    entries = load(HOLDOUT2)
    names = [e["name"] for e in entries]
    assert entries and len(names) == len(set(names))
    for e in entries:
        {Capability(c) for c in e["expected"]}  # every label is a known capability


def test_holdout2_report():
    entries = load(HOLDOUT2)
    report("HELD-OUT #2", entries)
    earlier = {e["name"] for e in load(MAIN)} | {e["name"] for e in load(HOLDOUT)}
    overlap = sorted(e["name"] for e in entries if e["name"] in earlier)
    print(f"\nalso in main or held-out #1 ({len(overlap)}): {overlap or 'none'}")
