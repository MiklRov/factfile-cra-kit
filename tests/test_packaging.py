"""
Tests for the packaging (P0.5): every console script and every root wrapper
must point at a real `main`, the version has one source, and the stylesheet
build.py needs ships inside the package.

These run against the source tree, not an installed wheel; CI additionally
installs the package into a clean environment and runs each command.
"""

from __future__ import annotations

import importlib
import re
import subprocess
import sys
import tomllib

from conftest import CRA_KIT_DIR

import cra_kit

PYPROJECT = tomllib.loads((CRA_KIT_DIR / "pyproject.toml").read_text(encoding="utf-8"))
SCRIPTS = PYPROJECT["project"]["scripts"]


def test_the_five_tools_are_console_scripts():
    targets = {v.split(":")[0].split(".")[-1] for v in SCRIPTS.values()}
    assert targets == {"build", "sbom_gen", "vuln_scan", "validate", "license_enrich"}


def test_every_console_script_points_at_a_callable_main():
    for name, target in SCRIPTS.items():
        module, _, func = target.partition(":")
        assert callable(getattr(importlib.import_module(module), func)), name


def test_every_root_wrapper_points_at_a_callable_main():
    wrappers = sorted(CRA_KIT_DIR.glob("*.py"))
    assert wrappers, "no root wrappers found"
    for w in wrappers:
        m = re.search(r"^from (cra_kit\.\w+) import main$", w.read_text(encoding="utf-8"), re.M)
        assert m, f"{w.name} is not a wrapper around cra_kit"
        assert callable(importlib.import_module(m.group(1)).main), w.name


def test_root_wrapper_runs_from_a_clone():
    r = subprocess.run(
        [sys.executable, str(CRA_KIT_DIR / "build.py"), "--help"],
        capture_output=True, text=True, cwd=CRA_KIT_DIR,
    )
    assert r.returncode == 0, r.stderr
    assert "--config-dir" in r.stdout


def test_version_has_one_source():
    from cra_kit import license_enrich, sbom_gen, vuln_scan
    assert PYPROJECT["tool"]["setuptools"]["dynamic"]["version"] == {"attr": "cra_kit.__version__"}
    for mod in (sbom_gen, vuln_scan, license_enrich):
        assert mod.TOOL_VERSION == cra_kit.__version__


def test_the_stylesheet_ships_with_the_package():
    assert "doc.css" in PYPROJECT["tool"]["setuptools"]["package-data"]["cra_kit"]
    assert (CRA_KIT_DIR / "cra_kit" / "doc.css").is_file()
