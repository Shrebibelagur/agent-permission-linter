from pathlib import Path

import pytest

from apl import idmask
from apl.redact import _known_secrets

FIX = Path(__file__).parent / "fixtures"


@pytest.fixture
def fix() -> Path:
    return FIX


@pytest.fixture(autouse=True)
def forget_known_secrets(monkeypatch):
    """A value remembered by one test must not hide a leak in the next. A fixed salt keeps ids
    and snapshots stable, and keeps tests away from the real salt file."""
    monkeypatch.setenv(idmask.SALT_ENV, "fixed-test-salt-not-a-real-one")
    yield
    _known_secrets.clear()
    idmask.reset()
