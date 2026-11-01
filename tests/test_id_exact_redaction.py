"""Secrets become [REDACTED]; tenant and client ids are masked even inside free text."""

import pytest

from apl import idmask
from apl.collectors.entra import EntraCredentials
from apl.idmask import pseudonym
from apl.redact import REDACTED, redact, remember_secret

TENANT = "11111111-2222-4333-8444-555555555555"
CLIENT = "66666666-7777-4888-9999-000000000000"
SECRET = "plain-fake-value-no-known-shape-1234"  # noqa: S105


@pytest.fixture
def creds():
    return EntraCredentials.from_env(
        {"TENANT_ID": TENANT, "CLIENT_ID": CLIENT, "CLIENT_SECRET": SECRET}
    )


def test_marker_is_the_agreed_one():
    assert REDACTED == "[REDACTED]"


def test_secret_is_removed_not_hashed(creds):
    out = redact(f"value {SECRET} here")
    assert out == "value [REDACTED] here"
    assert pseudonym("id", SECRET) not in out


def test_tenant_and_client_are_masked_in_free_text(creds):
    out = redact(f"tenant {TENANT}, client {CLIENT.upper()}, in a sentence")
    assert out == (
        f"tenant {pseudonym('tenant', TENANT)}, client {pseudonym('app', CLIENT)}, in a sentence"
    )


def test_tenant_domain_is_masked_too():
    EntraCredentials.from_env(
        {"TENANT_ID": "contoso.example", "CLIENT_ID": CLIENT, "CLIENT_SECRET": SECRET}
    )
    assert "contoso.example" not in redact("https://x/contoso.example/y")


def test_a_secret_holding_an_id_goes_whole(creds):
    remember_secret(f"prefix-{TENANT}-suffix")
    assert redact(f"a prefix-{TENANT}-suffix b") == "a [REDACTED] b"


def test_short_client_id_cannot_eat_ordinary_words():
    EntraCredentials.from_env(
        {"TENANT_ID": "contoso.example", "CLIENT_ID": "app", "CLIENT_SECRET": SECRET}
    )
    assert redact("the application") == "the application"


def test_show_ids_leaves_ids_and_still_removes_secrets(creds):
    idmask.set_show_ids(True)
    assert redact(f"{TENANT} {SECRET}") == f"{TENANT} [REDACTED]"
