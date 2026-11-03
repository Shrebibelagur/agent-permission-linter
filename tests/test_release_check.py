"""tools/release_check.py: the GUID scan flags unknown ids by line and skips fixtures."""

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("release_check", ROOT / "tools/release_check.py")
rc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rc)

# Invented, and built from parts so this file itself holds no GUID for the scan to find.
UNKNOWN = "-".join(["5d1f9c3e", "7a42", "4b8e", "9c61", "2f0d8e4a7b13"])


def test_unknown_guid_is_flagged_by_line():
    text = f"first\nclient = '{UNKNOWN}'\nthird\n"
    assert rc.guid_hits("src/apl/x.py", text) == [2]


def test_case_does_not_matter():
    assert rc.guid_hits("docs/x.md", UNKNOWN.upper()) == [1]


def test_allowed_guids_pass():
    text = "\n".join(rc.ALLOWED_GUIDS)
    assert rc.guid_hits("tests/test_x.py", text) == []


def test_fixture_pattern_is_allowed():
    assert "a1a1a1a1-0000-4000-8000-000000000001" in rc.ALLOWED_GUIDS
    assert "b2b2b2b2-0000-4000-8000-000000000002" in rc.ALLOWED_GUIDS


def test_fixtures_are_not_checked():
    assert rc.guid_hits("tests/fixtures/graph/applications.json", UNKNOWN) == []
    assert rc.guid_hits("tests\\fixtures\\graph\\applications.json", UNKNOWN) == []


def test_an_allowed_guid_does_not_hide_an_unknown_one_on_the_same_line():
    line = f"00000003-0000-0000-c000-000000000000 {UNKNOWN}"
    assert rc.guid_hits("README.md", line) == [1]


def test_the_repo_has_no_unknown_guid():
    assert rc.check_guids() == []


def test_required_files_are_present():
    assert rc.check_files() == []
