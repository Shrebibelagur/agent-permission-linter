"""The README report excerpt must match the dirty snapshot, line for line."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_readme_excerpt_matches_dirty_snapshot():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    snapshot = (ROOT / "tests/snapshots/dirty.md").read_text(encoding="utf-8")
    snap_lines = set(snapshot.replace("\r\n", "\n").splitlines())
    m = re.search(r"```markdown\n(.*?)```", readme.replace("\r\n", "\n"), re.S)
    assert m, "README is missing the ```markdown report excerpt"
    excerpt = [ln for ln in m.group(1).splitlines() if ln.strip()]
    missing = [ln for ln in excerpt if ln not in snap_lines]
    assert not missing, f"README excerpt lines not in snapshot: {missing}"
