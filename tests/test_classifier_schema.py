"""Name + inputSchema combination. Every schema here is synthetic."""

import pytest

from apl.classifier import CONFLICT_FLAG, SCHEMA_ONLY_FLAG, UNCLASSIFIED_FLAG, classify_tool
from apl.models import Capability as C
from apl.models import Tool, ToolAnnotations
from apl.rules.base import LOW_CONFIDENCE, is_uncertain


def t(name, *parameters, **ann):
    tool = Tool(
        name=name,
        parameters=list(parameters),
        annotations=ToolAnnotations(**ann) if ann else None,
    )
    return classify_tool(tool)


def test_no_schema_behaves_as_before():
    r = t("get_issue")
    assert r.capabilities == {C.READ} and r.classification_confidence == 0.7
    assert r.classification_flags == []


def test_agreement_raises_confidence():
    r = t("run_shell_command", "command")
    assert r.capabilities == {C.EXECUTE}
    assert r.classification_confidence == pytest.approx(0.8)
    assert "schema agrees with the name" in r.classification_reasons


def test_weak_read_agrees_with_a_read_name():
    assert t("get_issue", "id").classification_confidence == pytest.approx(0.8)


def test_weak_read_is_neutral_on_a_write_name():
    r = t("update_issue", "id")
    assert r.capabilities == {C.WRITE} and r.classification_flags == []
    assert r.classification_confidence == 0.7


def test_agreement_is_capped():
    r = t("get_issue", "id", readOnlyHint=True)
    assert r.classification_confidence == pytest.approx(0.95)


def test_agreement_cannot_lift_an_uncertain_tool():
    r = t("manage_files", "path")
    assert r.classification_confidence == 0.5 and is_uncertain(r)


def test_conflict_takes_widest_set_lowers_confidence_and_flags():
    r = t("get_status", "command")
    assert r.capabilities == {C.READ, C.EXECUTE}
    assert r.classification_confidence == 0.6
    assert r.classification_flags == [CONFLICT_FLAG]
    assert any("CONFLICT" in x for x in r.classification_reasons)


def test_conflict_lowers_annotated_confidence_too():
    assert t("get_status", "command", readOnlyHint=True).classification_confidence == 0.6


def test_conflict_cannot_be_used_to_dodge_a_verdict():
    """A server must not turn a violation into a review by adding a `content` parameter."""
    r = t("delete_repository", "content")
    assert r.capabilities == {C.DELETE, C.WRITE}
    assert r.classification_confidence > LOW_CONFIDENCE and not is_uncertain(r)


def test_schema_classifies_an_unknown_name_upward_but_stays_uncertain():
    r = t("frobnicate", "command")
    assert r.capabilities == {C.UNKNOWN, C.EXECUTE}
    assert r.classification_flags == [SCHEMA_ONLY_FLAG]
    assert r.classification_confidence == 0.5 and is_uncertain(r)


def test_read_only_schema_cannot_classify_an_unknown_name():
    r = t("frobnicate", "id", "limit")
    assert r.capabilities == {C.UNKNOWN}
    assert r.classification_flags == [UNCLASSIFIED_FLAG]
    assert r.classification_confidence == 0.0


def test_schema_never_removes_a_capability():
    assert t("delete_repository", "id").capabilities == {C.DELETE}
