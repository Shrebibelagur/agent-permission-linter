"""`apl --version` prints the package version and exits 0."""

from typer.testing import CliRunner

from apl import __version__
from apl.cli import app


def test_version_flag():
    r = CliRunner().invoke(app, ["--version"])
    assert r.exit_code == 0, r.output
    assert r.output.strip() == f"apl {__version__}"
