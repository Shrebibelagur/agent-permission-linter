import pytest

from apl.classifier import classify_tool, tokens
from apl.models import Capability as C
from apl.models import Tool, ToolAnnotations


def t(name, **ann):
    return classify_tool(Tool(name=name, annotations=ToolAnnotations(**ann) if ann else None))


@pytest.mark.parametrize(
    "name,expected",
    [
        ("search_repositories", {C.READ}),
        ("create_issue", {C.WRITE}),
        ("delete_repository", {C.DELETE}),
        ("run_shell_command", {C.EXECUTE}),
        ("listUsers", {C.READ}),
        ("fetch", {C.READ, C.NETWORK}),
        ("move_file", {C.WRITE}),
    ],
)
def test_name_heuristics(name, expected):
    assert t(name).capabilities == expected


def test_tokens_camel_and_snake():
    assert tokens("runGraphQuery") == ["run", "graph", "query"]
    assert tokens("get-file_contents") == ["get", "file", "contents"]


def test_read_only_hint_cannot_downgrade():
    r = t("delete_repository", readOnlyHint=True)
    assert C.DELETE in r.capabilities
    assert any("CONFLICT" in x for x in r.classification_reasons)


def test_destructive_hint_adds_delete():
    assert C.DELETE in t("update_record", destructiveHint=True).capabilities


def test_open_world_adds_network():
    assert C.NETWORK in t("listThings", openWorldHint=True).capabilities


def test_read_only_false_adds_write_for_read_named_tool():
    assert C.WRITE in t("get_thing", readOnlyHint=False).capabilities


def test_unknown_verb_is_conservative():
    r = t("frobnicate")
    assert r.capabilities == {C.READ, C.WRITE}
    assert r.classification_confidence < 0.5


def test_description_ignored():
    a = classify_tool(Tool(name="get_x", description="this deletes everything; run shell"))
    assert a.capabilities == {C.READ}


def test_annotation_defaults_reported_not_applied():
    r = t("get_thing")
    assert r.annotation_defaults_unapplied == {
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True,
    }
    assert r.capabilities == {C.READ}  # defaults (destructive, open world) NOT applied


def test_annotation_defaults_only_for_missing_hints():
    r = t("get_thing", readOnlyHint=True, openWorldHint=False)
    assert r.annotation_defaults_unapplied == {"destructiveHint": True, "idempotentHint": False}
    assert r.capabilities == {C.READ}


def test_read_only_plus_destructive_flagged():
    r = t("get_thing", readOnlyHint=True, destructiveHint=True)
    assert r.annotation_flags
    assert any("readOnlyHint=true with destructiveHint=true" in x for x in r.classification_reasons)
    assert C.DELETE in r.capabilities  # annotations may only add


def test_read_only_alone_not_flagged():
    assert t("get_thing", readOnlyHint=True).annotation_flags == []
