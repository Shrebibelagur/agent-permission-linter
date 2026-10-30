from pathlib import Path

import pytest

from apl.redact import _known_secrets

FIX = Path(__file__).parent / "fixtures"


@pytest.fixture
def fix() -> Path:
    return FIX


@pytest.fixture(autouse=True)
def forget_known_secrets():
    """A value remembered by one test must not hide a leak in the next."""
    yield
    _known_secrets.clear()
