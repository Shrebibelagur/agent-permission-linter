"""The README flag table must keep listing what --anonymise-names leaves visible (R20)."""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STILL_PRINTS = [
    "finding titles",
    "permission names",
    "custom ones",
    "tool names",
    "contain a server name",
    "environment variable and header names",
    "`justification`",
    "config file paths",
    "`purpose`",
    "`env_keys`",
]


def test_readme_row_lists_what_still_prints():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    [row] = [ln for ln in readme.splitlines() if ln.startswith("| `--anonymise-names`")]
    assert [item for item in STILL_PRINTS if item not in row] == []


def test_r20_covers_the_same_list():
    docs = (ROOT / "docs/ASSUMPTIONS.md").read_text(encoding="utf-8")
    r20 = docs[docs.index("**R20 [HEURISTIC]") :]
    r20 = r20[: r20.index("- **R7 [CLIENT]")].lower()
    for item in ("tool names", "custom permission names", "contain a server name"):
        assert item in r20


def test_env_example_holds_no_salt_value():
    lines = (ROOT / ".env.example").read_text(encoding="utf-8").splitlines()
    assert "APL_ID_SALT=" in lines
