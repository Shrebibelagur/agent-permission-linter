"""The guard harness in tools/mutation: entries stay current, and its isolation holds. The harness
itself is not run here: it takes minutes, and is not part of the default pytest run."""

import importlib
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools/mutation"))
guards = importlib.import_module("guards")
mutants = importlib.import_module("mutants")

Mutant = mutants.Mutant
GUID = re.compile(r"(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
REAL_VARS = {"TENANT_ID": "real-tenant", "CLIENT_ID": "real-client", "CLIENT_SECRET": "real-secret"}


def test_every_entry_still_applies():
    assert guards.stale() == []


@pytest.mark.parametrize("mutant", mutants.MUTANTS, ids=lambda m: m.name)
def test_entry_really_changes_a_source_file(mutant):
    assert mutant.file.startswith("src/apl/")
    assert guards.apply(guards.source(ROOT, mutant), mutant) != guards.source(ROOT, mutant)


def test_names_are_unique():
    names = [m.name for m in mutants.MUTANTS]
    assert len(names) == len(set(names))


def test_a_changed_line_is_reported_as_stale(tmp_path, monkeypatch):
    target = tmp_path / "x.py"
    target.write_text("current\n", encoding="utf-8")
    entry = Mutant("gone", "x.py", "old text", "new text")
    monkeypatch.setattr(guards, "MUTANTS", (entry,))
    assert guards.stale(tmp_path) == ["gone"]


def test_recorded_guard_count_is_current():
    docs = (ROOT / "docs/ASSUMPTIONS.md").read_text(encoding="utf-8")
    assert f"**Guard count: {len(mutants.MUTANTS)}.**" in docs


def test_entries_hold_no_real_values():
    for mutant in mutants.MUTANTS:
        text = f"{mutant.old}{mutant.new}{mutant.also}"
        assert not GUID.search(text), mutant.name
        assert "8Q~" not in text and "ghp_" not in text and "eyJ" not in text, mutant.name


def test_stale_check_is_excluded_from_harness_runs():
    """Inside a broken copy it would fail every time, and every guard would look caught."""
    assert f"--ignore={guards.STALE_CHECK}" in guards.pytest_command()
    assert (ROOT / guards.STALE_CHECK).is_file()


def test_real_credentials_do_not_reach_the_tests(tmp_path, monkeypatch):
    for name, value in REAL_VARS.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("APL_ID_SALT", "a-real-salt-value-from-the-shell")
    env = guards.isolated_env(tmp_path)
    assert not set(REAL_VARS) & set(env)
    assert env["APL_ID_SALT"] == guards.FAKE_SALT
    assert "real" not in guards.FAKE_SALT


@pytest.mark.parametrize("name", guards.HOME_VARS)
def test_every_home_points_into_the_copy(tmp_path, name):
    assert Path(guards.isolated_env(tmp_path)[name]) == tmp_path / "home"


def test_copy_is_refused_inside_the_repo():
    with pytest.raises(guards.HarnessError):
        guards.make_copy(ROOT / "tools/mutation/work")


def test_a_surviving_guard_is_reported_as_surviving(tmp_path):
    (tmp_path / "x.py").write_text("guard = True\n", encoding="utf-8")
    entry = Mutant("off", "x.py", "guard = True", "guard = False")
    assert guards.run_guard(tmp_path, entry, lambda: (0, [])) is None


def test_a_caught_guard_names_the_test_and_the_file_is_restored(tmp_path):
    target = tmp_path / "x.py"
    target.write_text("guard = True\n", encoding="utf-8")
    entry = Mutant("off", "x.py", "guard = True", "guard = False")
    seen = []

    def runner():
        seen.append(target.read_text(encoding="utf-8"))
        return 1, ["FAILED tests/test_x.py::test_y - AssertionError"]

    assert guards.run_guard(tmp_path, entry, runner) == "tests/test_x.py::test_y"
    assert seen == ["guard = False\n"]
    assert target.read_text(encoding="utf-8") == "guard = True\n"


def test_the_file_is_restored_if_the_run_blows_up(tmp_path):
    target = tmp_path / "x.py"
    target.write_text("guard = True\n", encoding="utf-8")
    entry = Mutant("off", "x.py", "guard = True", "guard = False")

    def runner():
        raise TimeoutError

    with pytest.raises(TimeoutError):
        guards.run_guard(tmp_path, entry, runner)
    assert target.read_text(encoding="utf-8") == "guard = True\n"


def test_a_salt_file_in_the_isolated_home_fails_the_run(tmp_path):
    (tmp_path / "home/apl").mkdir(parents=True)
    (tmp_path / "home/apl/id_salt").write_text("x", encoding="utf-8")
    with pytest.raises(guards.HarnessError, match="escaped"):
        guards.check_isolation(tmp_path, guards.fingerprint())


def test_a_changed_repo_fails_the_run(tmp_path):
    (tmp_path / "home").mkdir()
    with pytest.raises(guards.HarnessError, match="repo changed"):
        guards.check_isolation(tmp_path, "not-the-real-fingerprint")


def test_harness_is_outside_the_default_pytest_run():
    config = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'testpaths = ["tests"]' in config
    assert not list((ROOT / "tools").rglob("test_*.py"))
