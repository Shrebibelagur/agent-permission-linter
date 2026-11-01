"""URLs print as scheme://host/[path-redacted] by default, wherever they stand."""

import json

import pytest
from typer.testing import CliRunner

from apl import idmask
from apl.cli import app
from apl.redact import REDACTED, remember_secret, scrub, shorten_urls

PATH_SECRET = "Xy9fAkEsEcReTpAtHsEgMeNt1234"  # noqa: S105
HOOK = f"https://hooks.example.test/services/T0FAKE/B0FAKE/{PATH_SECRET}"
SHORT = "https://hooks.example.test/[path-redacted]"
FORMATS = ["md", "json", "sarif"]


def assert_clean(**surfaces):
    assert surfaces
    for surface, text in surfaces.items():
        for value in (HOOK, PATH_SECRET, "T0FAKE"):
            assert value not in text, f"{value!r} leaked in {surface}"


def run(*args):
    return CliRunner().invoke(app, [str(a) for a in args])


@pytest.fixture
def world(tmp_path):
    """The url as a field, an arg, a warning (a server only agent.yaml names), and in a
    justification that APL-007 repeats in reports."""
    config, tools, agent = tmp_path / "c.json", tmp_path / "t.json", tmp_path / "a.yaml"
    servers = {
        "fs": {"command": "c", "args": ["mcp-remote", HOOK]},
        "hook": {"type": "http", "url": HOOK},
    }
    config.write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
    tools.write_text(json.dumps({"fs": {"tools": [{"name": "delete_file"}]}}), encoding="utf-8")
    agent.write_text(
        f"""name: a
purpose: p
servers:
  - server: fs
    required_capabilities: [read]
    justification: Reports to {HOOK} daily.
  - server: {HOOK}
    required_capabilities: [read]
""",
        encoding="utf-8",
    )
    return config, tools, agent, tmp_path


def scan(world, *extra):
    config, tools, agent, _ = world
    return run("scan", "-c", config, "-t", tools, "-a", agent, *extra)


def inventory(world, *extra):
    return run("inventory", "-c", world[0], "-a", world[2], *extra)


@pytest.mark.parametrize("fmt", FORMATS)
def test_no_report_output_holds_the_path(world, fmt):
    out = world[3] / f"r.{fmt}"
    streamed = scan(world, "-f", fmt)
    written = scan(world, "-f", fmt, "--out", out)
    assert streamed.exit_code == 0 and written.exit_code == 0, streamed.output
    text = out.read_text(encoding="utf-8")
    assert_clean(
        stdout=streamed.stdout,
        stderr=streamed.stderr,
        written_stderr=written.stderr,
        out_file=text,
    )
    assert SHORT in text


def test_the_url_reaches_reports_with_the_flag(world):
    r = scan(world, "--show-urls")
    assert HOOK in r.stdout and HOOK in r.stderr  # guards the test above: fix text and a warning


def test_inventory_field_and_arg_are_short(world):
    r = inventory(world)
    assert r.exit_code == 0, r.output
    assert_clean(stdout=r.stdout, stderr=r.stderr)
    fs, hook = json.loads(r.stdout)["servers"]
    assert hook["url"] == SHORT and fs["args"] == ["mcp-remote", SHORT]


def test_show_urls_prints_the_path_and_warns_on_stderr(world):
    r = inventory(world, "--show-urls")
    assert json.loads(r.stdout)["servers"][1]["url"] == HOOK
    assert "WARNING: --show-urls" in r.stderr and "WARNING" not in r.stdout


def test_show_urls_warns_on_scan_too(world):
    assert "WARNING: --show-urls" in scan(world, "--show-urls").stderr


def test_no_warning_without_the_flag(world):
    assert "--show-urls" not in scan(world).stderr


def test_show_urls_keeps_userinfo_and_query_out(tmp_path):
    config = tmp_path / "c.json"
    url = f"https://user:hunter2-pw@hooks.example.test/x?sig={PATH_SECRET}"
    server = {"type": "http", "url": url}
    config.write_text(json.dumps({"mcpServers": {"h": server}}), encoding="utf-8")
    r = run("inventory", "-c", config, "--show-urls")
    assert "hunter2-pw" not in r.stdout and PATH_SECRET not in r.stdout
    assert f"https://hooks.example.test/x?{REDACTED}" in r.stdout


def test_show_urls_never_shows_a_secret(world):
    remember_secret(PATH_SECRET)
    r = inventory(world, "--show-urls")
    assert PATH_SECRET not in r.stdout and REDACTED in r.stdout


def test_flag_does_not_outlive_the_command(world):
    inventory(world, "--show-urls")
    assert shorten_urls(HOOK) == SHORT


def test_a_name_that_is_a_url_goes_whole_under_anonymise_names():
    """Names first: a shortened url would no longer match the name, and its host would print."""
    idmask.set_anonymise_names(True)
    idmask.register_name("server-name", HOOK)
    assert scrub(f"see {HOOK}") == f"see {idmask.pseudonym('server-name', HOOK)}"


@pytest.mark.parametrize(
    "url,short",
    [
        (HOOK, SHORT),
        ("https://a.example", "https://a.example/[path-redacted]"),
        ("https://a.example:8443/x", "https://a.example:8443/[path-redacted]"),
        ("wss://a.example/socket", "wss://a.example/[path-redacted]"),
        ("postgres://me:pw@db.example/prod", "postgres://db.example/[path-redacted]"),
        ("https://u:p@a.example/x?y=1#z", "https://a.example/[path-redacted]"),
    ],
)
def test_shapes(url, short):
    assert shorten_urls(url) == short


def test_can_run_twice_and_stops_at_the_end_of_the_url():
    once = shorten_urls(f"see {HOOK} and `{HOOK}` then ({HOOK})")
    assert once == f"see {SHORT} and `{SHORT}` then ({SHORT})"
    assert shorten_urls(once) == once


@pytest.mark.parametrize(
    "url",
    [
        "https://learn.microsoft.com/en-us/graph/permissions-reference#mailsend",
        "https://owasp.org/www-project-non-human-identities-top-10/2025/7-long-lived-secrets/",
        "https://genai.owasp.org/llmrisk/llm062025-excessive-agency/",
        "https://json.schemastore.org/sarif-2.1.0.json",
        "file:///C:/config/mcp.json",
    ],
)
def test_our_own_references_are_left_alone(url):
    assert shorten_urls(url) == url


@pytest.mark.parametrize(
    "url,host",
    [
        (f"https://learn.microsoft.com@evil.test/{PATH_SECRET}", "evil.test"),
        (f"https://learn.microsoft.com.evil.test/{PATH_SECRET}", "learn.microsoft.com.evil.test"),
        (f"https://evil.test/learn.microsoft.com/{PATH_SECRET}", "evil.test"),
        (f"https://user@learn.microsoft.com/{PATH_SECRET}", "learn.microsoft.com"),
    ],
)
def test_a_lookalike_of_a_trusted_host_is_still_shortened(url, host):
    assert shorten_urls(url) == f"https://{host}/[path-redacted]"
