""".gitleaks.toml allowlists only the planted test values, and nothing wider.

The scanning tests run real gitleaks in a temp directory with this repo's config, and are
skipped if gitleaks (8.25 or later) is not installed. The config-shape and stale-entry tests
need no gitleaks and always run.
"""

import importlib.util
import re
import secrets
import shutil
import string
import subprocess
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("release_check", ROOT / "tools/release_check.py")
rc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rc)

CONFIG = tomllib.loads(rc.GITLEAKS_CONFIG.read_text(encoding="utf-8"))
ALLOWLISTS = CONFIG.get("allowlists", [])
# (rule, value) for every allowlisted value: each regex is ^<escaped exact value>$.
PLANTED = [
    (rule, re.sub(r"\\(.)", r"\1", rx[1:-1]))
    for a in ALLOWLISTS
    for rule in a["targetRules"]
    for rx in a["regexes"]
]

EXE = shutil.which("gitleaks")
needs_gitleaks = pytest.mark.skipif(
    EXE is None or (rc.gitleaks_version(EXE) or (0,)) < rc.MIN_GITLEAKS,
    reason="gitleaks 8.25 or later not installed",
)


def fresh_github_token() -> str:
    """A realistic-format GitHub PAT made up now: no planted marker, never a real token."""
    alphabet = string.ascii_letters + string.digits
    return "ghp_" + "".join(secrets.choice(alphabet) for _ in range(36))


def scan(root: Path, files: dict[str, str]) -> set[tuple[str, str]]:
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8")
    code, leaks = rc.run_gitleaks(EXE, "dir", root)
    assert code in (0, 1), f"gitleaks failed to run (exit {code})"
    return {(x["RuleID"], x["File"]) for x in leaks}


def assignment(value: str) -> str:
    return f'api_key = "{value}"\n'


# --- (a) and (b): anything not planted is still found, wherever it is --------------------------


@needs_gitleaks
def test_a_fresh_token_under_src_is_flagged(tmp_path):
    found = scan(tmp_path, {"src/apl/leak.py": assignment(fresh_github_token())})
    assert ("github-pat", "src/apl/leak.py") in found


@needs_gitleaks
def test_a_fresh_token_under_tests_is_flagged(tmp_path):
    found = scan(tmp_path, {"tests/test_leak.py": assignment(fresh_github_token())})
    assert ("github-pat", "tests/test_leak.py") in found


@needs_gitleaks
@pytest.mark.parametrize("rule,value", PLANTED, ids=[v[:8] for _, v in PLANTED])
def test_a_planted_value_outside_tests_is_flagged(tmp_path, rule, value):
    found = scan(tmp_path, {"src/apl/leak.py": assignment(value), "README.md": assignment(value)})
    assert {(rule, "src/apl/leak.py"), (rule, "README.md")} <= found


@needs_gitleaks
@pytest.mark.parametrize("rule,value", PLANTED, ids=[v[:8] for _, v in PLANTED])
def test_a_planted_value_under_tests_is_allowed(tmp_path, rule, value):
    """The control: proves the scans above would pass if the allowlist were too wide."""
    assert scan(tmp_path, {"tests/test_plant.py": assignment(value)}) == set()


# --- (c) and shape: every entry is narrow and still used ---------------------------------------


def test_every_allowlisted_value_still_appears_under_tests():
    git = shutil.which("git")
    tracked = subprocess.run(  # noqa: S603
        [git, "ls-files", "-z", "tests"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.split("\0")
    text = "\n".join(
        (ROOT / p).read_text(encoding="utf-8", errors="replace") for p in tracked if p
    )
    stale = [value for _, value in PLANTED if value not in text]
    assert stale == [], "allowlisted values no longer in tests/: remove their entries"


def test_there_are_allowlists_and_each_is_narrow():
    assert ALLOWLISTS, "no [[allowlists]] in .gitleaks.toml"
    for a in ALLOWLISTS:
        assert a.get("targetRules"), f"rule-wide ignore: {a.get('description')}"
        assert a.get("condition") == "AND", f"path or value alone would match: {a}"
        assert a.get("paths") == ["^tests/"], f"path must be exactly ^tests/: {a}"
        assert a.get("regexTarget") == "secret"
        assert a.get("regexes"), f"path-wide ignore: {a.get('description')}"
        for rx in a["regexes"]:
            assert rx.startswith("^") and rx.endswith("$"), f"not anchored: {rx}"
            assert re.fullmatch(r"(?:\\.|[^\\.*+?()\[\]{}|^$])*", rx[1:-1]), f"not exact: {rx}"
        assert not {"stopwords", "commits"} & a.keys()


def test_no_global_allowlist_or_rule_overrides():
    assert CONFIG.get("extend", {}).get("useDefault") is True
    assert "allowlist" not in CONFIG, "the old global [allowlist] table is not allowed"
    assert "rules" not in CONFIG, "default rules must not be replaced or disabled"
    assert not CONFIG.get("extend", {}).get("disabledRules")
