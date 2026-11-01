"""Random-looking tokens in command and args are redacted by default. A heuristic: the tests pin
what it catches, what it leaves alone, and its known misses."""

import json

import pytest
from typer.testing import CliRunner

from apl.cli import app
from apl.inventory import build_inventory
from apl.parsers.mcp_config import parse_config_file
from apl.redact import REDACTED, redact_random_tokens

TOKEN = "qT7vZ2mK9xLw4RbN8sYc3Hd6"  # noqa: S105


def write_config(path, command="c", args=()):
    server = {"command": command, "args": list(args)}
    path.write_text(json.dumps({"mcpServers": {"s": server}}), encoding="utf-8")
    return path


def inventory(path, *flags):
    r = CliRunner().invoke(app, ["inventory", "-c", str(path), *flags])
    assert r.exit_code == 0, r.output
    return r, json.loads(r.stdout)["servers"][0]


@pytest.mark.parametrize(
    "token",
    [
        TOKEN,
        "aB3dE5gH7jK9mN1pQ3sT5vX7",
        "Zm9vYmFyQmF6MTIzNDU2Nzg5MEFiQ2Rl",
        "x7Kp2-Qm9Rt_4Ws8Yb3Nf6Hj",
    ],
)
def test_random_tokens_are_redacted(token):
    assert redact_random_tokens(token) == REDACTED


@pytest.mark.parametrize(
    "text",
    [
        "C:/tools/agents/a-long-benign-directory-name/run.exe",
        "/usr/local/share/my-organisation-tools/bin/server",
        "C:/Program Files/Microsoft Visual Studio/2022/Community/Common7/IDE/devenv.exe",
        "server-1.24.3-alpha.20261101",
        "1.2.3-beta.4+build.20261101123456",
        "MicrosoftGraphServer2025Preview",
        "modelcontextprotocol-server-filesystem",
        "@modelcontextprotocol/server-github",
        "a1a1a1a1-0000-4000-8000-000000000001",
        "A1A1A1A1-0000-4000-8000-000000000001",
        "AZURE_CLIENT_ID_FOR_THE_PRODUCTION_TENANT",
        "--some-very-long-command-line-option-name",
        "${MY_VERY_LONG_ENVIRONMENT_VARIABLE_NAME_2}",
    ],
)
def test_benign_values_are_left_alone(text):
    assert redact_random_tokens(text) == text


def test_only_the_token_goes():
    assert redact_random_tokens(f"--client={TOKEN}") == f"--client={REDACTED}"
    assert redact_random_tokens(f"C:/keys/{TOKEN}/run.exe") == f"C:/keys/{REDACTED}/run.exe"


def test_nineteen_characters_are_below_the_floor():
    assert redact_random_tokens(TOKEN[:19]) == TOKEN[:19]
    assert redact_random_tokens(TOKEN[:20]) == REDACTED


def test_low_entropy_secret_is_a_known_miss():
    miss = "aaaaaaaaaaBBBBBBBBBB1111111111"
    assert redact_random_tokens(miss) == miss


def test_single_case_hex_is_a_known_miss():
    miss = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b"
    assert redact_random_tokens(miss) == miss


def test_random_looking_build_id_is_a_known_over_redaction():
    assert redact_random_tokens("build-7Fq2Lx9Zt4Wm8Rk3Pn6V") == REDACTED


def test_arg_token_is_redacted_in_inventory(tmp_path):
    path = write_config(tmp_path / "c.json", args=[f"--client={TOKEN}", TOKEN, "--region=eu"])
    r, server = inventory(path)
    assert TOKEN not in r.stdout + r.stderr
    assert server["args"] == [f"--client={REDACTED}", REDACTED, "--region=eu"]


def test_command_token_is_redacted_in_inventory(tmp_path):
    path = write_config(tmp_path / "c.json", command=f"C:/keys/{TOKEN}/run.exe")
    r, server = inventory(path)
    assert TOKEN not in r.stdout and server["command"] == f"C:/keys/{REDACTED}/run.exe"


def test_no_flag_brings_a_token_back(tmp_path):
    path = write_config(tmp_path / "c.json", args=[TOKEN])
    for flag in ("--show-ids", "--show-urls"):
        assert TOKEN not in inventory(path, flag)[0].stdout


def test_benign_config_is_unchanged(tmp_path):
    command = "C:/tools/agents/a-long-benign-directory-name/run.exe"
    version = "server-1.24.3-alpha.20261101"
    path = write_config(tmp_path / "c.json", command=command, args=[version])
    _, server = inventory(path)
    assert server["command"] == command and server["args"] == [version]


def test_a_guess_does_not_count_as_an_inline_secret(tmp_path):
    """APL-002 cites inline secrets as fact. This is a guess, so it must not create a finding."""
    path = write_config(tmp_path / "c.json", args=[TOKEN])
    servers, _ = parse_config_file(path)
    assert servers[0].credentials == []


def test_stored_value_is_already_gone(tmp_path):
    inv = build_inventory([write_config(tmp_path / "c.json", args=[TOKEN])])
    assert TOKEN not in inv.servers[0].model_dump_json()
