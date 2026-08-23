"""
Shared pytest configuration for the cra-kit test suite.

cra-kit's modules are standalone scripts, not an installable package (see
README.md: "run as `python3 script.py`", no setup.py). They
import each other with plain top-level imports, e.g. build.py does
`from risk_report import cross_check, render`. To let tests do the same
thing (`import validate`, `from risk_report import cross_check`, ...),
cra-kit/ itself must be on sys.path — this file puts it there before any
test module is collected.

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
