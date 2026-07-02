"""Shared pytest fixtures for the TATS test suite."""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

# Make the project root importable when pytest is invoked from anywhere.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

EXAMPLES_DIR = PROJECT_ROOT / "examples"


@pytest.fixture(scope="session")
def burp_fixture_xml() -> Path:
    """Return the path to ``examples/fixture.xml`` (regenerate if missing)."""
    p = EXAMPLES_DIR / "fixture.xml"
    if not p.is_file():
        # Lazy-generate so a fresh checkout still has fixtures to work with.
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "make_fixture", EXAMPLES_DIR / "make_fixture.py")
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        sys.argv = ["make_fixture", str(p)]
        spec.loader.exec_module(mod)
    return p


@pytest.fixture
def burp_fixture_xml_copy(tmp_path, burp_fixture_xml) -> Path:
    """A throwaway copy of ``examples/fixture.xml`` in ``tmp_path``."""
    dest = tmp_path / "fixture.xml"
    shutil.copy(burp_fixture_xml, dest)
    return dest


@pytest.fixture
def empty_db_path(tmp_path) -> Path:
    return tmp_path / "tokens.db"


@pytest.fixture(scope="session")
def mitm_available() -> bool:
    try:
        import mitmproxy.io  # noqa: F401
        return True
    except ImportError:
        return False


@pytest.fixture
def mitm_fixture(tmp_path, mitm_available) -> Path:
    """A throwaway copy of ``examples/fixture.mitm`` in ``tmp_path``.

    Skipped when the ``mitmproxy`` package is not importable.
    """
    if not mitm_available:
        pytest.skip("mitmproxy not installed (pip install mitmproxy)")
    src = EXAMPLES_DIR / "fixture.mitm"
    if not src.is_file():
        # Lazy-generate the fixture if it isn't on disk yet.
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "make_mitm_fixture", EXAMPLES_DIR / "make_mitm_fixture.py")
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        sys.argv = ["make_mitm_fixture", str(src)]
        spec.loader.exec_module(mod)
    dest = tmp_path / "fixture.mitm"
    shutil.copy(src, dest)
    return dest
