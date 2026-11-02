"""Break each output guard on purpose and confirm a test fails. See README.md here.

    python tools/mutation/guards.py list
    python tools/mutation/guards.py run [--only TEXT]

Works on a throwaway copy, in a process with an allowlisted environment and its own home, so it
cannot touch this repo, read real credentials, or create a real salt file. Each of those is
checked after the run, and a breach fails it.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

from mutants import MUTANTS, Mutant

ROOT = Path(__file__).resolve().parents[2]
COPIED_DIRS = ("src", "tests", "docs", "tools")
COPIED_FILES = ("pyproject.toml", "README.md", ".env.example")
# Reads the real source to check entries, so inside a mutated copy it would fail every time and
# make every guard look caught.
STALE_CHECK = "tests/test_mutation_entries.py"
FAKE_SALT = "mutation-harness-fake-salt-0000"
PASSED_ENV = ("PATH", "PATHEXT", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC")
HOME_VARS = ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME")
TIMEOUT = 280

Runner = Callable[[], tuple[int, list[str]]]


class HarnessError(RuntimeError):
    """The harness could not run safely. Not the same as a guard surviving."""


def isolated_env(base: Path) -> dict[str, str]:
    """An allowlist, not a copy: real tenant, client and salt values must not get in. Home and
    temp sit beside the copy, not in it, as tests check that the salt is outside the repo."""
    env = {name: os.environ[name] for name in PASSED_ENV if name in os.environ}
    for name in HOME_VARS:
        env[name] = str(base / "home")
    env |= {
        "TEMP": str(base / "tmp"),
        "TMP": str(base / "tmp"),
        "TMPDIR": str(base / "tmp"),
        "APL_ID_SALT": FAKE_SALT,
        "PYTHONPATH": str(base / "copy" / "src"),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    return env


def make_copy(base: Path) -> None:
    if base.resolve().is_relative_to(ROOT):
        raise HarnessError("the throwaway copy must be outside the repo")
    work = base / "copy"
    ignore = shutil.ignore_patterns("__pycache__", ".pytest_cache", ".ruff_cache")
    for name in COPIED_DIRS:
        shutil.copytree(ROOT / name, work / name, ignore=ignore)
    for name in COPIED_FILES:
        shutil.copy(ROOT / name, work / name)
    (base / "home").mkdir()
    (base / "tmp").mkdir()


def pytest_command() -> list[str]:
    return [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "-x",
        "--no-header",
        "-p",
        "no:cacheprovider",
        f"--ignore={STALE_CHECK}",
    ]


def run_tests(base: Path) -> tuple[int, list[str]]:
    result = subprocess.run(  # noqa: S603
        pytest_command(),
        cwd=base / "copy",
        env=isolated_env(base),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=TIMEOUT,
    )
    lines = result.stdout.splitlines()
    return result.returncode, [ln for ln in lines if ln.startswith(("FAILED", "ERROR"))]


def source(root: Path, mutant: Mutant) -> str:
    return (root / mutant.file).read_text(encoding="utf-8").replace("\r\n", "\n")


def stale(root: Path = ROOT) -> list[str]:
    """Entries whose target text is gone, which would otherwise silently test nothing."""
    out = []
    for mutant in MUTANTS:
        text = source(root, mutant)
        if any(old not in text for old, _ in ((mutant.old, mutant.new), *mutant.also)):
            out.append(mutant.name)
    return out


def apply(text: str, mutant: Mutant) -> str:
    out = text.replace(mutant.old, mutant.new, 1)
    for old, new in mutant.also:
        out = out.replace(old, new, 1)
    return out


def run_guard(work: Path, mutant: Mutant, runner: Runner) -> str | None:
    """The first failing test, or None if the guard survived. The file is always restored."""
    path = work / mutant.file
    original = path.read_bytes()
    path.write_text(apply(source(work, mutant), mutant), encoding="utf-8", newline="\n")
    try:
        code, failed = runner()
    finally:
        path.write_bytes(original)
    if code == 0:
        return None
    return failed[0].split(" - ")[0].split(" ", 1)[-1] if failed else f"pytest exit {code}"


def fingerprint() -> str:
    """Every file the harness could touch in the real repo."""
    digest = hashlib.sha256()
    for name in COPIED_DIRS:
        for path in sorted((ROOT / name).rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts:
                digest.update(str(path).encode())
                digest.update(path.read_bytes())
    return digest.hexdigest()


def check_isolation(base: Path, before: str) -> None:
    created = [p for p in (base / "home").rglob("*") if p.is_file()]
    if created:
        raise HarnessError(f"{len(created)} file(s) written to the isolated home: a test escaped")
    if fingerprint() != before:
        raise HarnessError("the real repo changed during the run")


def check_imports(base: Path) -> None:
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", "import apl; print(apl.__file__)"],
        cwd=base / "copy",
        env=isolated_env(base),
        capture_output=True,
        text=True,
        timeout=60,
    )
    if not Path(result.stdout.strip()).is_relative_to(base / "copy"):
        raise HarnessError("tests would import the real package, not the copy")


def run_all(chosen: list[Mutant]) -> int:
    gone = stale()
    if gone:
        raise HarnessError(f"stale entries, fix them first: {gone}")
    before = fingerprint()
    with tempfile.TemporaryDirectory(prefix="apl-mutation-", ignore_cleanup_errors=True) as tmp:
        base = Path(tmp).resolve()
        make_copy(base)
        check_imports(base)
        code, failed = run_tests(base)
        if code != 0:
            raise HarnessError(f"tests must pass before anything is broken: {failed[:3]}")
        print(f"baseline passes; breaking {len(chosen)} guard(s)", flush=True)
        survived = []
        for mutant in chosen:
            caught_by = run_guard(base / "copy", mutant, lambda: run_tests(base))
            if caught_by is None:
                survived.append(mutant.name)
                print(f"SURVIVED  {mutant.name}", flush=True)
            else:
                print(f"caught    {mutant.name:42} {caught_by[:60]}", flush=True)
        check_isolation(base, before)
    print(f"{len(chosen) - len(survived)}/{len(chosen)} caught; survived: {survived}")
    return 1 if survived else 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Break each guard and confirm a test fails.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="print every guard")
    run = sub.add_parser("run", help="break every guard in a throwaway copy")
    run.add_argument("--only", help="run only guards whose name contains this text")
    args = parser.parse_args()
    if args.command == "list":
        for mutant in MUTANTS:
            print(f"{mutant.name:42} {mutant.file}")
        print(f"{len(MUTANTS)} guards")
        return 0
    chosen = [m for m in MUTANTS if not args.only or args.only in m.name]
    if not chosen:
        print(f"no guard name contains {args.only!r}")
        return 2
    try:
        return run_all(chosen)
    except HarnessError as e:
        print(f"harness error: {e}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
