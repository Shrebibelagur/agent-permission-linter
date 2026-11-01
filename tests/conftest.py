import os
from pathlib import Path

import pytest

from apl import idmask
from apl.redact import _known_secrets

FIX = Path(__file__).parent / "fixtures"
TEST_SALT = "fixed-test-salt-not-a-real-one"  # keeps finding ids and snapshots stable


@pytest.fixture
def fix() -> Path:
    return FIX


def pytest_configure():
    """For the whole session, not per test: pytest formats failures after fixtures are undone, and
    a log record holding a GUID then asks for a salt. That must never reach the real salt file."""
    os.environ[idmask.SALT_ENV] = TEST_SALT


@pytest.fixture(autouse=True)
def forget_known_secrets():
    """A value remembered by one test must not hide a leak in the next."""
    yield
    _known_secrets.clear()
    idmask.reset()
