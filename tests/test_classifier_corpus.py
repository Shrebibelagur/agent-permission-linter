"""Classifier accuracy against the main hand-labelled corpus. Buckets: see corpus_report.py.

Run `pytest -s tests/test_classifier_corpus.py` to see the report. Do not edit corpus labels to
make this pass.
"""

from corpus_report import MAIN, bucket, load, report

from apl.models import Capability

# Regression guard: missing-any-capability cases must never increase.
# Baseline 2026-10-29, measured after the download_file relabel, before classifier pass 2.
MAX_MISSING = 2


def test_corpus_shape():
    corpus = load(MAIN)
    assert 30 <= len(corpus) <= 50
    names = [e["name"] for e in corpus]
    assert len(names) == len(set(names))
    for required in ("run_query", "manage_files", "sync"):
        assert required in names


def test_bucket_definitions():
    R, W, D = Capability.READ, Capability.WRITE, Capability.DELETE
    assert bucket({R}, {R}) == "exact"
    assert bucket({D}, {R, W}) == "missing"
    assert bucket({W}, {D}) == "missing"  # riskier prediction still misses write
    assert bucket({W}, {R, W}) == "extra"


def test_classifier_accuracy_report():
    out = report("MAIN corpus", load(MAIN))
    assert len(out["missing"]) <= MAX_MISSING, f"missing-any: {out['missing']}"
