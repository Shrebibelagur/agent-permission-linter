"""Release check: run before tagging. Exits 0 only if every check passes.

    python tools/release_check.py

Checks, in order:
  1. LICENSE and the release docs exist and are not empty.
  2. No GUID in a tracked file outside tests/fixtures/, except the allowlist below.
  3. gitleaks over the whole git history with .gitleaks.toml, if gitleaks is installed (skipped,
     not failed, if not). The config allowlists only the planted test values, under tests/.
  4. pytest.
  5. ruff check.

Never prints a matched value: GUID hits are reported as path:line, and gitleaks runs with
--redact and is reported as rule, path, line and commit only.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess  # noqa: S404 - fixed argument lists, no shell
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

REQUIRED_FILES = (
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "CHANGELOG.md",
    "docs/THREAT_MODEL.md",
    "docs/ASSUMPTIONS.md",
    ".gitleaks.toml",
)
LICENSE_MARKERS = ("Apache License", "Version 2.0, January 2004")

FIXTURES = "tests/fixtures/"
GUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)

# Every GUID allowed outside tests/fixtures/, with the reason. Lower case. Add new ones only
# if they are invented or publicly documented, never one copied from a tenant.
ALLOWED_GUIDS = {
    # Public, documented by Microsoft.
    "00000003-0000-0000-c000-000000000000": "Microsoft Graph appId (G9)",
    "e2a3a72e-5f79-4c64-b1b1-878b674786c9": "Graph Mail.ReadWrite app role id (G5)",
    "00000000-0000-0000-0000-000000000000": "all-zero app role id: no specific role (G5)",
    # Invented test values: repeated or sequential digits.
    "00000000-0000-0000-0000-000000000001": "fake entra_app_id",
    "11111111-2222-4333-8444-555555555555": "planted fake tenant id",
    "66666666-7777-4888-9999-000000000000": "planted fake client id",
    "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee": "planted fake object id",
    "1a2b3c4d-5e6f-4a0b-9c8d-7e6f5a4b3c2d": "invented id for masking tests",
    "9f8e7d6c-5b4a-4321-8fed-cba987654321": "invented id for masking tests",
    "abcdef12-3456-4789-abcd-ef1234567890": "invented id for masking tests",
    # The fixture pattern: a1a1a1a1-0000-4000-8000-000000000001 and so on.
    **{
        f"{p * 4}-0000-4000-8000-{p[1]:0>12}": "fixture-pattern fake id"
        for p in ("a1", "a2", "a3", "a4", "a6", "a7", "a8", "a9", "b1", "b2", "c1", "f1")
    },
}


def guid_hits(path: str, text: str) -> list[int]:
    """Line numbers in `text` holding a GUID that is not allowed. Fixtures are not checked."""
    if path.replace("\\", "/").startswith(FIXTURES):
        return []
    return [
        i
        for i, line in enumerate(text.splitlines(), 1)
        if any(m.lower() not in ALLOWED_GUIDS for m in GUID.findall(line))
    ]


def check_files() -> list[str]:
    errors = []
    for rel in REQUIRED_FILES:
        p = ROOT / rel
        if not p.is_file() or not p.read_text(encoding="utf-8").strip():
            errors.append(f"missing or empty: {rel}")
    lic = ROOT / "LICENSE"
    if lic.is_file():
        text = lic.read_text(encoding="utf-8")
        errors += [f"LICENSE lacks '{m}'" for m in LICENSE_MARKERS if m not in text]
    return errors


def _run(args: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(args, cwd=ROOT, text=True, encoding="utf-8", errors="replace", **kw)  # noqa: S603


def check_guids() -> list[str]:
    git = shutil.which("git")
    if not git:
        return ["git not found"]
    r = _run([git, "ls-files", "-z"], capture_output=True)
    if r.returncode != 0:
        return ["git ls-files failed"]
    errors = []
    for rel in filter(None, r.stdout.split("\0")):
        p = ROOT / rel
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError):
            continue  # binary or deleted in the working tree
        errors += [f"GUID not on the allowlist: {rel}:{n}" for n in guid_hits(rel, text)]
    return errors


GITLEAKS_CONFIG = ROOT / ".gitleaks.toml"
MIN_GITLEAKS = (8, 25, 0)  # first version with [[allowlists]] and targetRules


def gitleaks_version(exe: str) -> tuple[int, ...] | None:
    r = _run([exe, "version"], capture_output=True)
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", r.stdout)
    return tuple(int(x) for x in m.groups()) if r.returncode == 0 and m else None


def run_gitleaks(exe: str, mode: str, cwd: Path) -> tuple[int, list[dict]]:
    """Run `gitleaks <mode> .` in `cwd` with this repo's config. Paths come back relative to
    `cwd`, which the config's `^tests/` conditions rely on. Exit 0 = clean, 1 = findings."""
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "gitleaks.json"
        r = subprocess.run(  # noqa: S603
            [exe, mode, ".", "--config", str(GITLEAKS_CONFIG), "--redact", "--no-banner",
             "--log-level", "error", "--report-format", "json", "--report-path", str(report),
             "--exit-code", "1"],
            cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        leaks = json.loads(report.read_text(encoding="utf-8") or "[]") if report.is_file() else []
    return r.returncode, leaks


def check_gitleaks() -> tuple[list[str], str]:
    exe = shutil.which("gitleaks")
    if not exe:
        return [], "SKIPPED (gitleaks not installed; install it to scan history)"
    if not GITLEAKS_CONFIG.is_file():
        return ["missing .gitleaks.toml"], ""
    version = gitleaks_version(exe)
    if version is None or version < MIN_GITLEAKS:
        need = ".".join(map(str, MIN_GITLEAKS))
        return [f"gitleaks {need} or later is needed for .gitleaks.toml"], ""
    code, leaks = run_gitleaks(exe, "git", ROOT)
    if code == 0:
        return [], "0 findings in git history (with .gitleaks.toml)"
    if code != 1:
        return [f"gitleaks failed to run (exit {code})"], ""
    return [
        f"gitleaks {x.get('RuleID')}: {x.get('File')}:{x.get('StartLine')} "
        f"(commit {str(x.get('Commit', ''))[:8]})"
        for x in leaks
    ] or ["gitleaks reported leaks"], ""


def check_command(args: list[str]) -> list[str]:
    r = _run(args, capture_output=True)
    tail = "\n".join((r.stdout + r.stderr).strip().splitlines()[-15:])
    print("    " + tail.replace("\n", "\n    "))
    return [] if r.returncode == 0 else [f"{args[2]} exited {r.returncode}"]


def main() -> int:
    failed = 0

    def report(name: str, errors: list[str], ok: str = "ok") -> None:
        nonlocal failed
        status = "FAIL" if errors else "SKIP" if ok.startswith("SKIPPED") else "PASS"
        print(f"[{status}] {name}" + ("" if errors else f": {ok}"))
        for e in errors:
            print(f"    {e}")
        failed += bool(errors)

    report("license and docs", check_files(), f"{len(REQUIRED_FILES)} files present")
    allowed = f"none beyond the {len(ALLOWED_GUIDS)} allowed"
    report("GUIDs outside fixtures", check_guids(), allowed)
    leaks, note = check_gitleaks()
    report("gitleaks history scan", leaks, note)
    print("[....] pytest")
    report("pytest", check_command([sys.executable, "-m", "pytest", "-q"]))
    print("[....] ruff")
    report("ruff", check_command([sys.executable, "-m", "ruff", "check", "."]))

    print(f"\nrelease check: {'FAILED, ' + str(failed) + ' check(s)' if failed else 'all passed'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
