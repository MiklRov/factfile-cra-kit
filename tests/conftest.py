"""
Shared pytest configuration for the cra-kit test suite.

The code is the `cra_kit` package (pyproject.toml); the scripts in the
repository root are thin wrappers that keep `python3 build.py` working from
a clone. Tests import the package (`from cra_kit.risk_report import
cross_check`). The repository root is put on sys.path here so that works
without `pip install -e .` as well.

No test in this suite may make a real network call. vuln_scan.py is the
only module that talks to the network (OSV.dev); every test that touches
it must monkeypatch `vuln_scan.urllib.request.urlopen`. A safety net
fixture below (`no_network`, autouse) fails fast if something forgets.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

CRA_KIT_DIR = Path(__file__).resolve().parent.parent
if str(CRA_KIT_DIR) not in sys.path:
    sys.path.insert(0, str(CRA_KIT_DIR))

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Safety net: fail loudly if a test reaches real urllib.request.urlopen.

    Individual vuln_scan tests monkeypatch `vuln_scan.urllib.request.urlopen`
    directly with their own fake, which shadows this one for the duration of
    that test. Any test that does NOT patch it and yet ends up calling
    urlopen for real gets a clear error instead of a silent, slow network
    round-trip.
    """

    def _blocked(*args, **kwargs):
        raise AssertionError(
            "a test attempted a real network call via urllib.request.urlopen() "
            "— mock it via vuln_scan.urllib.request.urlopen instead"
        )

    import urllib.request

    monkeypatch.setattr(urllib.request, "urlopen", _blocked)
