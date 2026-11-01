"""A report with full URLs says so itself, as the stderr warning does not travel with it."""

import json

import pytest
from typer.testing import CliRunner

from apl.cli import app
from apl.report.common import REAL_IDS_WARNING, REAL_URLS_WARNING

FORMATS = ["md", "json", "sarif"]


def scan(fix, *extra):
    args = ["scan", "-c", str(fix / "safe_output/mcp.json"), *extra]
    return CliRunner().invoke(app, args)


def written(fix, tmp_path, fmt, *flags):
    out = tmp_path / f"report.{fmt}"
    r = scan(fix, "-f", fmt, "--out", str(out), *flags)
    assert r.exit_code == 0, r.output
    return out.read_text(encoding="utf-8")


def test_wording():
    assert REAL_URLS_WARNING == "WARNING: this report contains full URLs"


def test_md_file_opens_with_the_warning(fix, tmp_path):
    text = written(fix, tmp_path, "md", "--show-urls")
    assert text.splitlines()[0] == f"**{REAL_URLS_WARNING}**"


def test_json_file_has_the_top_level_key(fix, tmp_path):
    data = json.loads(written(fix, tmp_path, "json", "--show-urls"))
    assert data["contains_real_urls"] is True


def test_sarif_file_has_a_note_and_a_property(fix, tmp_path):
    run = json.loads(written(fix, tmp_path, "sarif", "--show-urls"))["runs"][0]
    first = run["invocations"][0]["toolExecutionNotifications"][0]
    assert first == {"level": "warning", "message": {"text": REAL_URLS_WARNING}}
    assert run["properties"]["containsRealUrls"] is True


@pytest.mark.parametrize("fmt", FORMATS)
def test_no_marker_without_the_flag(fix, tmp_path, fmt):
    text = written(fix, tmp_path, fmt)
    assert REAL_URLS_WARNING not in text
    assert "contains_real_urls" not in text and "containsRealUrls" not in text


@pytest.mark.parametrize("fmt", FORMATS)
def test_show_ids_alone_does_not_claim_urls(fix, tmp_path, fmt):
    text = written(fix, tmp_path, fmt, "--show-ids")
    assert REAL_URLS_WARNING not in text and "contains_real_urls" not in text


@pytest.mark.parametrize("fmt", FORMATS)
def test_stdout_redirect_is_marked_too(fix, fmt):
    r = scan(fix, "-f", fmt, "--show-urls")
    assert REAL_URLS_WARNING in r.stdout or '"contains_real_urls": true' in r.stdout


def test_both_flags_give_both_markers(fix, tmp_path):
    text = written(fix, tmp_path, "md", "--show-ids", "--show-urls")
    assert text.splitlines()[0] == f"**{REAL_IDS_WARNING}**"
    assert text.splitlines()[2] == f"**{REAL_URLS_WARNING}**"
    data = json.loads(written(fix, tmp_path, "json", "--show-ids", "--show-urls"))
    assert data["contains_real_ids"] is True and data["contains_real_urls"] is True


def test_marked_json_keeps_the_pinned_keys_first(fix, tmp_path):
    data = json.loads(written(fix, tmp_path, "json", "--show-urls"))
    assert list(data)[0] == "schema_version" and list(data)[-1] == "contains_real_urls"
