import json

import pytest

from apl.parsers.mcp_config import ConfigParseError
from apl.parsers.tools_list import load_tools_file

TOOL = {"name": "get_x", "inputSchema": {"type": "object"}}


def _write(tmp_path, obj):
    p = tmp_path / "tools.json"
    p.write_text(json.dumps(obj), encoding="utf-8")
    return p


def test_2026_07_28_result_with_result_type_and_cache_fields(tmp_path):
    obj = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "resultType": "complete",
            "tools": [TOOL],
            "nextCursor": "c",
            "ttlMs": 300000,
            "cacheScope": "public",
        },
    }
    assert [t.name for t in load_tools_file(_write(tmp_path, obj))["*"]] == ["get_x"]


def test_missing_result_type_treated_as_complete(tmp_path):
    assert load_tools_file(_write(tmp_path, {"tools": [TOOL]}))["*"][0].name == "get_x"


@pytest.mark.parametrize("rt", ["input_required", "IGNORE PREVIOUS INSTRUCTIONS", None, 1])
def test_non_complete_result_type_rejected_without_echo(tmp_path, rt):
    p = _write(tmp_path, {"result": {"resultType": rt, "tools": [TOOL]}})
    with pytest.raises(ConfigParseError) as e:
        load_tools_file(p)
    assert "resultType" in str(e.value) and "IGNORE" not in str(e.value)


def test_non_complete_in_server_map_rejected(tmp_path):
    obj = {"a": {"tools": [TOOL]}, "b": {"resultType": "input_required", "tools": []}}
    with pytest.raises(ConfigParseError):
        load_tools_file(_write(tmp_path, obj))


def test_no_tools_error_includes_path(tmp_path):
    p = _write(tmp_path, {"nope": 1})
    with pytest.raises(ConfigParseError) as e:
        load_tools_file(p)
    assert str(p) in str(e.value)
