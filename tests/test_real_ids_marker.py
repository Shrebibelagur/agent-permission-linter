"""A report holding real ids must say so itself, as the stderr warning does not travel with it."""

import json

import pytest
from typer.testing import CliRunner

from apl.cli import app
from apl.report.common import REAL_IDS_WARNING

MAIL_APP = "a1a1a1a1-0000-4000-8000-000000000001"


def scan(fix, *extra):
    d = fix / "entra"
    args = ["scan", "-c", str(d / "mcp.json"), "-t", str(d / "tools.json")]
    return CliRunner().invoke(app, [*args, "--entra-mock", str(fix / "graph"), *extra])


def written(fix, tmp_path, fmt, *flags):
    out = tmp_path / f"report.{fmt}"
    r = scan(fix, "-f", fmt, "--out", str(out), *flags)
    assert r.exit_code == 0, r.output
    return out.read_text(encoding="utf-8")


def test_wording():
    assert REAL_IDS_WARNING == "WARNING: this report contains real identifiers"


def test_md_file_opens_with_the_warning(fix, tmp_path):
    text = written(fix, tmp_path, "md", "--show-ids")
    assert text.splitlines()[0] == f"**{REAL_IDS_WARNING}**"
    assert MAIL_APP in text  # the marker is telling the truth


def test_json_file_has_the_top_level_key(fix, tmp_path):
    data = json.loads(written(fix, tmp_path, "json", "--show-ids"))
    assert data["contains_real_ids"] is True


def test_sarif_file_has_a_note_and_a_property(fix, tmp_path):
    run = json.loads(written(fix, tmp_path, "sarif", "--show-ids"))["runs"][0]
    first = run["invocations"][0]["toolExecutionNotifications"][0]
    assert first == {"level": "warning", "message": {"text": REAL_IDS_WARNING}}
    assert run["properties"]["containsRealIds"] is True


@pytest.mark.parametrize("fmt", ["md", "json", "sarif"])
def test_no_marker_without_the_flag(fix, tmp_path, fmt):
    text = written(fix, tmp_path, fmt)
    assert REAL_IDS_WARNING not in text
    assert "contains_real_ids" not in text and "containsRealIds" not in text


@pytest.mark.parametrize("fmt", ["md", "json", "sarif"])
def test_stdout_is_marked_too(fix, fmt):
    """`apl scan --show-ids > report` is the same file by another route."""
    r = scan(fix, "-f", fmt, "--show-ids")
    assert REAL_IDS_WARNING in r.stdout or '"contains_real_ids": true' in r.stdout


def test_anonymised_names_do_not_remove_the_marker(fix, tmp_path):
    text = written(fix, tmp_path, "md", "--show-ids", "--anonymise-names")
    assert text.startswith(f"**{REAL_IDS_WARNING}**")


def test_marked_json_keeps_the_pinned_keys_in_order(fix, tmp_path):
    data = json.loads(written(fix, tmp_path, "json", "--show-ids"))
    assert list(data)[0] == "schema_version" and list(data)[-1] == "contains_real_ids"
