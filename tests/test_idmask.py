"""Pseudonyms: format, determinism, keying and where the salt lives."""

import os
import re
from pathlib import Path

import pytest

from apl import idmask
from apl.idmask import SaltError, pseudonym, pseudonymise, salt_path
from apl.redact import _known_secrets, redact

GUID = "9f8e7d6c-5b4a-4321-8fed-cba987654321"
ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def config_dir(tmp_path, monkeypatch):
    """The real salt file path logic, in a temp dir."""
    monkeypatch.delenv(idmask.SALT_ENV)
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    return tmp_path


@pytest.mark.parametrize("kind", ["app", "tenant", "sp", "cred"])
def test_format(kind):
    assert re.fullmatch(rf"{kind}-[0-9a-f]{{6}}", pseudonym(kind, GUID))


def test_same_input_same_output_whatever_the_case():
    assert pseudonym("app", GUID) == pseudonym("app", GUID) == pseudonym("app", GUID.upper())


def test_kind_is_part_of_the_value():
    assert pseudonym("app", GUID)[4:] != pseudonym("sp", GUID)[3:]


def test_unknown_kind_is_refused():
    with pytest.raises(ValueError):
        pseudonym("user", GUID)


def test_a_different_salt_gives_a_different_pseudonym(monkeypatch):
    first = pseudonym("app", GUID)
    idmask.reset()
    monkeypatch.setenv(idmask.SALT_ENV, "another-salt-of-enough-length")
    assert pseudonym("app", GUID) != first


def test_salt_file_is_created_once_and_reused(config_dir):
    first = pseudonym("app", GUID)
    path = salt_path()
    assert path.is_file() and path.parent == config_dir / "apl"
    stored = path.read_text(encoding="utf-8")
    idmask.reset()
    assert pseudonym("app", GUID) == first
    assert path.read_text(encoding="utf-8") == stored


def test_salt_file_is_never_in_the_repo(config_dir):
    pseudonym("app", GUID)
    assert not salt_path().is_relative_to(ROOT)
    assert not [p for p in ROOT.glob("*") if "salt" in p.name]


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes")
def test_salt_file_is_private(config_dir):
    pseudonym("app", GUID)
    assert salt_path().stat().st_mode & 0o077 == 0


def test_env_salt_wins_and_creates_no_file(config_dir, monkeypatch):
    monkeypatch.setenv(idmask.SALT_ENV, "set-in-the-environment-16")
    pseudonym("app", GUID)
    assert not salt_path().exists()


def test_short_salt_fails_closed(monkeypatch):
    monkeypatch.setenv(idmask.SALT_ENV, "short")
    with pytest.raises(SaltError):
        pseudonym("app", GUID)


def test_unwritable_salt_location_fails_closed(config_dir, monkeypatch):
    (config_dir / "apl").write_text("a file where the directory should be", encoding="utf-8")
    with pytest.raises(SaltError):
        pseudonym("app", GUID)


def test_salt_is_scrubbed_like_a_secret(monkeypatch):
    salt = "a-distinctive-salt-value-1234"
    monkeypatch.setenv(idmask.SALT_ENV, salt)
    idmask.reset()
    pseudonym("app", GUID)
    assert salt in _known_secrets
    assert salt not in redact(f"x {salt} y")


def test_no_salt_is_needed_without_an_identifier(config_dir):
    assert pseudonymise("github/delete_repository") == "github/delete_repository"
    assert not salt_path().exists()


def test_registered_kind_is_kept_in_free_text():
    idmask.register("tenant", GUID)
    assert pseudonymise(f"in {GUID.upper()}.") == f"in {pseudonym('tenant', GUID)}."


def test_graph_paths_know_their_kind_and_any_segment():
    assert pseudonymise("/servicePrincipals/sp1/owners") == (
        f"/servicePrincipals/{pseudonym('sp', 'sp1')}/owners"
    )
    assert pseudonymise("/applications?$skiptoken=x") == "/applications?$skiptoken=x"
