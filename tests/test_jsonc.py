import pytest

from apl.parsers.jsonc import JSONCError, loads_jsonc, strip_jsonc
from apl.parsers.mcp_config import ConfigParseError, parse_config_file

FAKE = "ghp_FAKEfakeFAKEfakeFAKEfakeFAKEfake0000"


def test_strict_json_is_not_flagged_as_jsonc():
    assert loads_jsonc('{"a": 1}') == ({"a": 1}, False)


def test_line_and_block_comments_and_trailing_commas():
    text = """{
      // line comment
      "servers": {
        /* block
           comment */
        "x": {"type": "stdio", "command": "node", "args": ["a", "b",],},
      },
    }"""
    data, used = loads_jsonc(text)
    assert used is True
    assert data == {"servers": {"x": {"type": "stdio", "command": "node", "args": ["a", "b"]}}}


def test_comment_markers_and_commas_inside_strings_preserved():
    text = '{"u": "https://a.example/x//y", "s": "/* no */", "c": ",}", "q": "a\\"//b",}'
    data, _ = loads_jsonc(text)
    assert data == {"u": "https://a.example/x//y", "s": "/* no */", "c": ",}", "q": 'a"//b'}


def test_trailing_comma_before_comment():
    data, _ = loads_jsonc('{"a": [1, 2, // last\n]}')
    assert data == {"a": [1, 2]}


def test_stripping_preserves_line_numbers():
    text = '{\n/* a\nb */\n"a": 1\n}'
    stripped, _ = strip_jsonc(text)
    assert stripped.count("\n") == text.count("\n")


@pytest.mark.parametrize(
    "text",
    [
        '{"env": {"T": "' + FAKE + '"}',  # unclosed object
        '{"env": {"T": "' + FAKE + "}}",  # unterminated string
        '{"env": {"T": "' + FAKE + '"}} /* unterminated',
        '{"env": {"T": ' + FAKE + "}}",  # bare token
    ],
)
def test_errors_carry_position_only(text):
    with pytest.raises(JSONCError) as e:
        loads_jsonc(text)
    assert FAKE not in str(e.value) and "ghp_" not in str(e.value)
    assert e.value.lineno >= 1


def test_vscode_jsonc_file_parses(tmp_path):
    p = tmp_path / "mcp.json"
    p.write_text(
        "{\n  // workspace servers\n  \"servers\": {\n"
        '    "gh": {"type": "stdio", "command": "npx", "env": {"GITHUB_TOKEN": "${input:gh}"},},\n'
        '  },\n  "inputs": [],\n}\n',
        encoding="utf-8",
    )
    servers, warns = parse_config_file(p)
    assert [s.name for s in servers] == ["gh"]
    assert servers[0].credentials[0].env_var == "input:gh"
    assert not any("JSONC" in w for w in warns)


def test_jsonc_in_mcpservers_file_warns(tmp_path):
    p = tmp_path / "claude_desktop_config.json"
    p.write_text('{"mcpServers": {"a": {"command": "x"}}, // c\n}', encoding="utf-8")
    servers, warns = parse_config_file(p)
    assert servers and any("strict JSON" in w for w in warns)


def test_invalid_jsonc_file_error_has_no_content(tmp_path):
    p = tmp_path / "mcp.json"
    p.write_text('{\n // c\n "servers": {"x": {"env": {"T": "' + FAKE + '"}}', encoding="utf-8")
    with pytest.raises(ConfigParseError) as e:
        parse_config_file(p)
    msg = str(e.value)
    assert "ghp_" not in msg and "line" in msg
