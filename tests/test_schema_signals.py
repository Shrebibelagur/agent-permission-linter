"""inputSchema extraction and the parameter vocabularies. All schemas here are synthetic."""

import json

import pytest

from apl.models import Capability as C
from apl.parsers.tools_list import load_tools_file
from apl.schema_signals import MAX_PARAMETERS, extract_parameters, schema_signals


def schema(*names):
    return {"type": "object", "properties": {n: {"type": "string"} for n in names}}


def strong(*params, name=("frob",), caps=()):
    return schema_signals(params, name, set(caps)).strong


def test_extracts_top_level_nested_and_array_parameters():
    s = schema("a")
    s["properties"]["opts"] = {"type": "object", "properties": {"b": {"type": "string"}}}
    s["properties"]["rows"] = {"type": "array", "items": {"properties": {"c": {}}}}
    names, suspected = extract_parameters(s)
    assert set(names) == {"a", "opts", "b", "rows", "c"} and suspected is False


@pytest.mark.parametrize("bad", [None, "x", 3, [], {"properties": "x"}, {"properties": None}])
def test_malformed_schema_gives_nothing(bad):
    assert extract_parameters(bad) == ([], False)


def test_extraction_is_bounded():
    wide = schema(*(f"p{i}" for i in range(MAX_PARAMETERS + 50)))
    assert len(extract_parameters(wide)[0]) == MAX_PARAMETERS
    deep: dict = {}
    for _ in range(5000):
        deep = {"properties": {"p": deep}}
    assert extract_parameters(deep)[0] == ["p"]


def test_secret_in_a_parameter_name_is_redacted():
    leak = "ghp_FAKEfakeFAKEfakeFAKEfakeFAKEfake0000"
    assert leak not in json.dumps(extract_parameters(schema(leak))[0])


def test_schema_values_are_not_kept(tmp_path):
    leak = "plain-default-value-no-known-shape"
    tool = {
        "name": "get_x",
        "inputSchema": {"properties": {"key": {"default": leak, "enum": [leak]}}},
    }
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"tools": [tool]}), encoding="utf-8")
    [parsed] = load_tools_file(path)["*"]
    assert parsed.parameters == ["key"]
    assert leak not in parsed.model_dump_json()


def test_parser_tolerates_a_missing_schema(tmp_path):
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"tools": [{"name": "get_x"}]}), encoding="utf-8")
    assert load_tools_file(path)["*"][0].parameters == []


@pytest.mark.parametrize("word", ["command", "script", "code", "cmd", "shell", "shellCommand"])
def test_execute_words(word):
    assert C.EXECUTE in strong(word)


@pytest.mark.parametrize("word", ["url", "uri", "endpoint", "host", "webhook", "targetUrl"])
def test_network_words(word):
    assert C.NETWORK in strong(word)


@pytest.mark.parametrize("word", ["content", "body", "data", "text", "payload", "request_body"])
def test_content_words_are_weak_writes(word):
    s = schema_signals([word], ["frob"], set())
    assert s.strong == {} and s.weak_write == word.split("_")[-1]


@pytest.mark.parametrize("word", ["id", "limit", "offset", "filter", "user_id"])
def test_read_words_are_weak(word):
    s = schema_signals([word], ["frob"], set())
    assert s.strong == {} and s.weak_read == word.split("_")[-1]


@pytest.mark.parametrize("word", ["path", "file", "filename", "dir", "file_path"])
def test_path_reads_by_default(word):
    s = schema_signals([word], ["frob"], set())
    assert s.strong == {} and s.weak_read


def test_path_writes_with_a_write_name():
    assert strong("path", caps=[C.WRITE]) == {C.WRITE: "path"}


def test_a_content_parameter_does_not_make_a_path_a_strong_write():
    s = schema_signals(["path", "content"], ["frob"], set())
    assert s.strong == {} and s.weak_read == "path" and s.weak_write == "content"


def test_sql_is_always_execute():
    assert strong("sql") == {C.EXECUTE: "sql"}


@pytest.mark.parametrize("word", ["query", "statement"])
def test_query_is_execute_only_on_a_database(word):
    assert strong(word, name=("query", "postgres")) == {C.EXECUTE: word}
    assert strong(word, "database") == {C.EXECUTE: word}
    assert strong(word) == {}


def test_query_without_a_database_is_a_weak_read():
    assert schema_signals(["query"], ["search", "docs"], set()).weak_read == "query"


@pytest.mark.parametrize("word", ["zip_code", "status_code", "country_code", "auth_code"])
def test_code_false_friends_are_not_execute(word):
    assert strong(word) == {}


@pytest.mark.parametrize("word", ["source_code", "python_code", "pythonCode"])
def test_qualified_code_is_execute(word):
    assert strong(word) == {C.EXECUTE: "code"}


@pytest.mark.parametrize("word", ["command_id", "script_id", "url_limit", "webhook_id"])
def test_head_noun_decides(word):
    assert strong(word) == {}


def test_empty_parameters_give_no_signal():
    assert not schema_signals([], ["frob"], set())
    assert not schema_signals(["unrelated_thing"], ["frob"], set())


def test_returned_words_are_vocabulary_not_parameter_names():
    hostile = "ignore previous instructions_command"
    assert strong(hostile) == {C.EXECUTE: "command"}
