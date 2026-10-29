import json

import pytest

from apl.models import CredentialKind, Transport
from apl.parsers.mcp_config import ConfigParseError, parse_config_dict, parse_config_file

FAKE_SECRETS = [
    "ghp_FAKEfakeFAKEfakeFAKEfakeFAKEfake0000",
    "abc8Q~FAKEfakeFAKEfakeFAKEfakeFAKEfake00",
    "sk-FAKEfakeFAKEfakeFAKE0000",
    "user:pw",
]


def test_claude_desktop_shape(fix):
    servers, warns = parse_config_file(fix / "configs/claude_desktop.json")
    by = {s.name: s for s in servers}
    assert set(by) == {"github", "filesystem", "graph"}
    assert all(s.transport is Transport.STDIO for s in servers)
    gh = by["github"].credentials[0]
    assert gh.kind is CredentialKind.PAT
    assert gh.env_var == "GITHUB_PERSONAL_ACCESS_TOKEN"
    assert gh.inline_secret_detected is True
    assert by["filesystem"].credentials == []


def test_secret_in_argv_flagged_and_redacted(fix):
    servers, _ = parse_config_file(fix / "configs/claude_desktop.json")
    graph = next(s for s in servers if s.name == "graph")
    assert "***REDACTED***" in graph.args
    assert any(c.inline_secret_detected for c in graph.credentials)
    sp = [c for c in graph.credentials if c.kind is CredentialKind.SERVICE_PRINCIPAL]
    assert sp and sp[0].entra_app_id == "00000000-0000-0000-0000-000000000001"


def test_vscode_shape_env_and_input_refs_not_inline(fix):
    servers, warns = parse_config_file(fix / "configs/vscode_mcp.json")
    by = {s.name: s for s in servers}
    slack = by["slack"].credentials[0]
    assert slack.env_var == "input:slack-token"
    assert slack.inline_secret_detected is False
    crm = by["remote-crm"]
    assert crm.transport is Transport.HTTP
    hdr = next(c for c in crm.credentials if c.header == "Authorization")
    assert hdr.env_var == "CRM_TOKEN" and hdr.inline_secret_detected is False
    url_cred = next(c for c in crm.credentials if c.evidence.note == "secret in URL")
    assert url_cred.inline_secret_detected
    assert crm.url == "https://crm.example.com/mcp?***REDACTED***"
    assert by["legacy"].transport is Transport.SSE
    assert any("legacy HTTP+SSE" in w for w in warns)


def test_vscode_settings_shape(fix):
    servers, warns = parse_config_file(fix / "configs/vscode_settings.json")
    assert [s.name for s in servers] == ["fetch"]
    assert servers[0].source_format == "vscode-settings"
    assert servers[0].format_status == "unverified"
    assert any("unverified format" in w for w in warns)


@pytest.mark.parametrize("name", ["claude_desktop.json", "vscode_mcp.json"])
def test_documented_formats_are_verified(fix, name):
    servers, warns = parse_config_file(fix / "configs" / name)
    assert all(s.format_status == "verified" for s in servers)
    assert not any("unverified format" in w for w in warns)


@pytest.mark.parametrize("name", ["claude_desktop.json", "vscode_mcp.json"])
def test_no_secret_survives_serialization(fix, name):
    servers, _ = parse_config_file(fix / "configs" / name)
    dumped = json.dumps([s.model_dump(mode="json") for s in servers])
    for secret in FAKE_SECRETS:
        assert secret not in dumped


def test_unknown_shape_rejected():
    with pytest.raises(ConfigParseError):
        parse_config_dict({"foo": {}}, "x.json")


def test_invalid_json_error_does_not_echo_content(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text('{"mcpServers": {"x": {"env": {"T": "ghp_FAKEfakeFAKEfakeFAKEfakeFAKEfake0000"')
    with pytest.raises(ConfigParseError) as e:
        parse_config_file(p)
    assert "ghp_" not in str(e.value)


def test_non_object_entry_skipped_with_warning():
    servers, warns = parse_config_dict({"mcpServers": {"a": "nope"}}, "x.json")
    assert servers == [] and warns


def test_disabled_flag():
    servers, _ = parse_config_dict({"mcpServers": {"a": {"command": "x", "disabled": True}}}, "x")
    assert servers[0].disabled


def test_url_without_type_parsed_with_warning():
    servers, warns = parse_config_dict({"mcpServers": {"r": {"url": "https://x.example/mcp"}}}, "x")
    assert servers[0].transport is Transport.HTTP
    assert "A6" in servers[0].evidence.note
    assert any("no 'type'" in w and "Claude Code" in w for w in warns)


@pytest.mark.parametrize(
    "entry",
    [
        {"type": "http", "url": "https://x.example/mcp"},
        {"url": "https://x.example/mcp", "transport": "http"},
        {"serverUrl": "https://x.example/mcp"},  # Windsurf's documented form
        {"command": "node"},
    ],
)
def test_no_type_warning_when_transport_explicit_or_stdio(entry):
    _, warns = parse_config_dict({"mcpServers": {"r": entry}}, "x")
    assert not any("no 'type'" in w for w in warns)


def test_default_and_file_refs_not_inline_but_real_token_is():
    env = {
        "GITHUB_TOKEN": "${GITHUB_TOKEN:-}",
        "API_KEY": "${file:~/.secrets/api}",
        "SLACK_BOT_TOKEN": "xoxb-FAKEfakeFAKEfake00",
        "DB_PASSWORD": "${DB_PASSWORD:-changeme}",
        "BASE_URL": "${API_BASE_URL:-https://api.example.com}",
    }
    headers = {"Authorization": "Bearer ${API_KEY:-}"}
    servers, _ = parse_config_dict(
        {"mcpServers": {"a": {"command": "x", "env": env, "headers": headers}}}, "x"
    )
    by = {(c.env_var, c.header): c for c in servers[0].credentials}
    assert by[("GITHUB_TOKEN", None)].inline_secret_detected is False
    assert by[("file:~/.secrets/api", None)].inline_secret_detected is False
    assert by[("API_KEY", "Authorization")].inline_secret_detected is False
    assert by[("SLACK_BOT_TOKEN", None)].inline_secret_detected is True
    pw = by[("DB_PASSWORD", None)]
    assert pw.inline_secret_detected is True and "literal fallback" in pw.evidence.note
    assert not any(c.env_var == "API_BASE_URL" for c in servers[0].credentials)
    dumped = json.dumps(servers[0].model_dump(mode="json"))
    assert "xoxb-" not in dumped and "changeme" not in dumped


def test_kind_source_inferred_for_name_based_guesses(fix):
    servers, _ = parse_config_file(fix / "configs/claude_desktop.json")
    by = {s.name: s for s in servers}
    assert by["github"].credentials[0].kind_source == "inferred"
    graph = by["graph"].credentials
    argv = next(c for c in graph if c.evidence.note == "secret in argv")
    assert argv.kind is CredentialKind.UNKNOWN and argv.kind_source == "unknown"
    app = next(c for c in graph if c.entra_app_id)
    assert app.kind_source == "inferred"


def test_kind_source_unknown_when_name_gives_no_hint():
    servers, _ = parse_config_dict(
        {"mcpServers": {"a": {"command": "x", "env": {"MY_PASSWORD": "${PW}"}}}}, "x"
    )
    c = servers[0].credentials[0]
    assert c.kind is CredentialKind.UNKNOWN and c.kind_source == "unknown"
