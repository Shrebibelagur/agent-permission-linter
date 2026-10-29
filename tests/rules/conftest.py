import pytest

from apl.inventory import build_inventory


@pytest.fixture
def clean_inventory(fix):
    """The clean fixture set: a well-scoped agent that should yield few or no findings."""
    d = fix / "clean"
    return build_inventory([d / "mcp.json"], d / "agent.yaml", [d / "tools.json"])
