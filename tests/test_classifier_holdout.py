"""Classifier report on the HELD-OUT corpus (tests/fixtures/tool_corpus_holdout.yaml).

Buckets: see corpus_report.py. Never tune the classifier against this file or edit its labels
to fit. Also reports the held-out names that do NOT appear in the main corpus separately,
because only those are truly unseen.

Run `pytest -s tests/test_classifier_holdout.py` to see the report.
"""

from corpus_report import HOLDOUT, MAIN, load, report

from apl.models import Capability

# Regression guard: missing-any-capability cases must never increase.
# 12 before classifier pass 2; tightened to the post-pass-2 result (2026-10-29).
MAX_MISSING = 3


def test_holdout_shape():
    holdout = load(HOLDOUT)
    names = [e["name"] for e in holdout]
    assert holdout and len(names) == len(set(names))
    for e in holdout:
        {Capability(c) for c in e["expected"]}  # every label is a known capability


def test_holdout_report():
    holdout = load(HOLDOUT)
    main = {e["name"]: set(e["expected"]) for e in load(MAIN)}
    out = report("HELD-OUT corpus", holdout)
    unseen = [e for e in holdout if e["name"] not in main]
    report("HELD-OUT, not in main corpus", unseen)
    overlap = sorted(e["name"] for e in holdout if e["name"] in main)
    print(f"\nalso in main corpus ({len(overlap)}): {overlap}")
    conflicts = [
        e["name"] for e in holdout if e["name"] in main and set(e["expected"]) != main[e["name"]]
    ]
    print(f"label differs from main corpus: {conflicts or 'none'}")
    assert len(out["missing"]) <= MAX_MISSING, f"missing-any: {out['missing']}"
