"""--anonymise-names: a webhook url holds its secret in the path, where nothing recognises it.
Commands and urls become placeholders, so nothing derived from them can print."""

import json

import pytest
from typer.testing import CliRunner

from apl.cli import app

PATH_SECRET = "Xy9fAkEsEcReTpAtHsEgMeNt1234"  # noqa: S105
URL = f"https://hooks.fabrikam.example/services/T0FAKE/B0FAKE/{PATH_SECRET}"
COMMAND = f"C:/fabrikam/{PATH_SECRET}/run.exe"
PLANTS = [URL, COMMAND, PATH_SECRET, "fabrikam", "T0FAKE", "hooks."]
FORMATS = ["md", "json", "sarif"]


def assert_clean(**surfaces):
    assert surfaces
    for surface, text in surfaces.items():
        for value in PLANTS:
            assert value not in text, f"{value!r} leaked in {surface}"


def run(*args):
    return CliRunner().invoke(app, [str(a) for a in args])


def write_config(path, url=URL, command=COMMAND):
    servers = {"local": {"command": command}, "hook": {"type": "http", "url": url}}
    path.write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
    return path


@pytest.fixture
def config(tmp_path):
    return write_config(tmp_path / "mcp.json")


def test_redaction_alone_does_not_catch_this_url(config):
    """Why placeholders are needed: recognising secrets does not find this one."""
    r = run("inventory", "-c", config, "--show-urls")
    assert PATH_SECRET in r.stdout


def test_inventory_shows_placeholders(config):
    r = run("inventory", "-c", config, "--anonymise-names")
    assert r.exit_code == 0, r.output
    assert_clean(stdout=r.stdout, stderr=r.stderr)
    local, hook = json.loads(r.stdout)["servers"]
    assert local["command"] == "[cmd-1]" and hook["url"] == "[url-2]"


def test_nothing_derived_from_the_value_prints(tmp_path):
    """Different urls and commands give the very same output, so no hash of them can be in it."""
    one = write_config(tmp_path / "one.json")
    two = write_config(tmp_path / "two.json", "https://a.example/other", "other.exe")

    def servers(path):
        data = json.loads(run("inventory", "-c", path, "--anonymise-names").stdout)["servers"]
        for srv in data:
            srv.pop("evidence")  # the config file's own path
        return data

    assert servers(one) == servers(two)


def test_same_value_on_two_servers_cannot_be_matched(tmp_path):
    path = tmp_path / "mcp.json"
    servers = {name: {"type": "http", "url": URL} for name in ("a", "b")}
    path.write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
    a, b = json.loads(run("inventory", "-c", path, "--anonymise-names").stdout)["servers"]
    assert (a["url"], b["url"]) == ("[url-1]", "[url-2]")


def test_show_ids_does_not_bring_them_back(config):
    r = run("inventory", "-c", config, "--anonymise-names", "--show-ids")
    assert_clean(stdout=r.stdout)


def test_show_urls_does_not_bring_them_back(config):
    r = run("inventory", "-c", config, "--anonymise-names", "--show-urls")
    assert_clean(stdout=r.stdout)


@pytest.mark.parametrize("fmt", FORMATS)
def test_no_report_output_holds_them(config, tmp_path, fmt):
    out = tmp_path / f"r.{fmt}"
    streamed = run("scan", "-c", config, "-f", fmt, "--anonymise-names")
    written = run("scan", "-c", config, "-f", fmt, "--anonymise-names", "--out", out)
    assert streamed.exit_code == 0 and written.exit_code == 0, streamed.output
    assert_clean(
        stdout=streamed.stdout,
        stderr=streamed.stderr,
        written_stderr=written.stderr,
        out_file=out.read_text(encoding="utf-8"),
    )
