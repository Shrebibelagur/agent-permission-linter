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


@pytest.mark.parametrize(
    "name,expected",
    [
        ("terminate_instance", {C.DELETE}),
        ("sudo", {C.EXECUTE}),
        ("query_database", {C.READ, C.EXECUTE}),
        ("runSqlQuery", {C.READ, C.EXECUTE}),
        ("search_query", {C.READ}),  # no database noun -> stays read
        ("manage_files", {C.READ, C.WRITE, C.DELETE}),
        ("sync", {C.READ, C.WRITE}),
        ("update_pull_request", {C.WRITE}),
        ("merge_pull_request", {C.WRITE}),
        ("get_merge_request", {C.READ}),  # "merge" is part of the noun here
        ("listPullRequests", {C.READ}),
        ("merge_merge_requests", {C.WRITE}),
        ("http_request", {C.NETWORK}),
    ],
)
def test_step_b_verbs_and_compounds(name, expected):
    assert t(name).capabilities == expected


@pytest.mark.parametrize(
    "name", ["http_request", "api_request", "webRequest", "network_requests", "rest_request"]
)
def test_request_is_network_in_network_compounds(name):
    assert C.NETWORK in t(name).capabilities


@pytest.mark.parametrize(
    "name,expected",
    [
        ("get_pull_request", {C.READ}),
        ("create_merge_request", {C.WRITE}),
        ("approve_request", {C.WRITE}),
        ("get_change_request", {C.READ}),
        ("create_feature_request", {C.WRITE}),
        ("list_requests", {C.READ}),
    ],
)
def test_request_alone_is_not_network(name, expected):
    assert t(name).capabilities == expected


def test_bare_request_is_not_guessed():
    assert t("request").capabilities == {C.UNKNOWN}


def test_request_must_directly_follow_the_qualifier():
    assert C.NETWORK not in t("list_api_change_requests").capabilities


@pytest.mark.parametrize(
    "name", ["evaluate_expression", "launchBrowser", "start_vm", "stop_container",
             "restart_service", "reboot_host", "eval_js", "invoke_function"]
)
def test_execute_family(name):
    assert C.EXECUTE in t(name).capabilities


@pytest.mark.parametrize(
    "name,expected",
    [
        ("send_message", {C.WRITE, C.NETWORK}),
        ("email_user", {C.WRITE, C.NETWORK}),
        ("upload_file", {C.WRITE, C.NETWORK}),
        ("post_comment", {C.WRITE, C.NETWORK}),
        ("http_get", {C.NETWORK, C.READ}),
        ("trigger_webhook", {C.EXECUTE, C.NETWORK}),
    ],
)
def test_network_family(name, expected):
    assert t(name).capabilities == expected


@pytest.mark.parametrize(
    "name",
    ["publish_article", "push_branch", "notify_team", "broadcast_alert", "relay_payload",
     "forward_invoice"],
)
def test_outbound_vocabulary_is_network_and_write(name):
    assert t(name).capabilities == {C.NETWORK, C.WRITE}


@pytest.mark.parametrize("name", ["subscribe_topic", "ping_server"])
def test_inbound_or_probe_vocabulary_is_network_only(name):
    assert t(name).capabilities == {C.NETWORK}


@pytest.mark.parametrize(
    "name",
    ["migrate_schema", "cleanup_temp", "clean_cache", "reset_device", "handle_webhook",
     "install_plugin", "uninstall_app"],
)
def test_composite_family_gets_widest_set(name):
    r = t(name)
    assert {C.READ, C.WRITE, C.DELETE, C.EXECUTE, C.NETWORK} <= r.capabilities
    assert C.UNKNOWN not in r.capabilities


def test_composite_alone_lower_confidence():
    assert t("reset_device").classification_confidence == 0.5


def test_kill_is_execute_and_delete():
    assert t("kill_process").capabilities == {C.EXECUTE, C.DELETE}


def test_ambiguous_verb_lower_confidence():
    assert t("manage_files").classification_confidence == 0.5
    assert t("delete_and_manage").classification_confidence == 0.7


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


def test_unknown_verb_is_unclassified_not_guessed():
    r = t("frobnicate")
    assert r.capabilities == {C.UNKNOWN}
    assert r.classification_confidence == 0.0
    assert r.classification_flags == ["unclassified: review required"]


def test_unknown_verb_with_read_only_hint_still_unclassified():
    r = t("frobnicate", readOnlyHint=True)  # untrusted hint cannot classify on its own
    assert r.capabilities == {C.UNKNOWN}


def test_annotation_can_classify_unknown_name_upward():
    r = t("frobnicate", destructiveHint=True)
    assert r.capabilities == {C.DELETE} and r.classification_flags == []


def test_known_verb_has_no_review_flag():
    assert t("get_x").classification_flags == []


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
