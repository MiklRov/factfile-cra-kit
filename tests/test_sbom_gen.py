"""
Tests for sbom_gen.py — the E-SBOM-01 / W-SBOM-02 / W-SBOM-03 checks and the
--allow-empty escape hatch. E-SBOM-02 (declared-only PyPI) was a hard
failure until P0 and is now a warning plus a known-unknowns entry; the
--declared-only flag is still accepted and has no effect (defect #1: an
empty SBOM used to be written silently with exit code 0; defect #2:
root-only static parsing of a multi-module project used to be the reason the
SBOM came out empty in the first place; defect #3: a PyPI component set
built only from requirements.txt looked like a complete, valid SBOM while
silently omitting the real, running dependency closure — see
the real 27-vs-111 incident this closes).

generate() is exercised directly (not main()/argv) — same pattern as
build.py's tests: a plain function that returns an exit code and can be
asserted against with tmp_path/capsys.
"""

from __future__ import annotations

import json

from conftest import FIXTURES_DIR

from cra_kit.sbom_gen import generate

MULTI_MODULE_DIR = FIXTURES_DIR / "gradle_multi_module"
NO_MANIFEST_DIR = FIXTURES_DIR / "no_manifest"
PIP_FREEZE_BASIC_DIR = FIXTURES_DIR / "pip_freeze_basic"
PIP_FREEZE_DECLARED_ONLY_DIR = FIXTURES_DIR / "pip_freeze_declared_only"


# --------------------------------------------------------------------------
# E-SBOM-01 — refuse to write an empty SBOM
# --------------------------------------------------------------------------

def test_empty_sbom_refuses_to_write_and_exits_nonzero(tmp_path, capsys):
    out = tmp_path / "sbom.cdx.json"
    rc = generate(
        NO_MANIFEST_DIR, "X", "1.0.0", None, include_dev=False, out=out,
    )
    err = capsys.readouterr().err

    assert rc != 0
    assert "E-SBOM-01" in err
    # the message must name what was actually checked and where, not a
    # generic template
    assert "composer.lock" in err
    assert "package-lock.json" in err
    assert "build.gradle" in err
    assert "requirements.txt" in err
    assert str(NO_MANIFEST_DIR) in err

    # the file must genuinely not exist on disk, not just "rc != 0"
    assert not out.exists()


def test_allow_empty_suppresses_the_check_and_writes_the_file(tmp_path):
    out = tmp_path / "sbom.cdx.json"
    rc = generate(
        NO_MANIFEST_DIR, "X", "1.0.0", None, include_dev=False, out=out,
        allow_empty=True,
    )
    assert rc == 0
    assert out.exists()
    bom = json.loads(out.read_text(encoding="utf-8"))
    assert bom["components"] == []


# --------------------------------------------------------------------------
# W-SBOM-02 — static-only Gradle parsing warning
# --------------------------------------------------------------------------

def test_static_only_gradle_parse_warns_but_still_writes(tmp_path, capsys):
    out = tmp_path / "sbom.cdx.json"
    rc = generate(
        MULTI_MODULE_DIR, "X", "1.0.0", None, include_dev=False, out=out,
    )
    err = capsys.readouterr().err

    assert rc == 0  # a warning, not a failure
    assert out.exists()
    assert "W-SBOM-02" in err
    assert "--gradle-tree" in err


# --------------------------------------------------------------------------
# end-to-end multi-module Gradle run
# --------------------------------------------------------------------------

def test_multi_module_root_produces_nonempty_sbom_with_module_tags(tmp_path):
    out = tmp_path / "sbom.cdx.json"
    rc = generate(
        MULTI_MODULE_DIR, "FixtureApp", "1.0.0", None, include_dev=False,
        out=out,
    )
    assert rc == 0
    bom = json.loads(out.read_text(encoding="utf-8"))
    comps = bom["components"]

    assert len(comps) > 0

    for c in comps:
        module_props = [p for p in c["properties"] if p["name"] == "cra:module"]
        assert module_props, f"component {c['purl']} missing cra:module"
        assert module_props[0]["value"]

    # no in-repo module name leaked in as if it were an external package
    for c in comps:
        assert "mod-a" not in c["purl"]
        assert "mod-b" not in c["purl"]
        assert "mod-c" not in c["purl"]


# --------------------------------------------------------------------------
# E-SBOM-02 — PyPI components must be resolved (--pip-freeze), not just
# declared (requirements.txt alone), unless --declared-only is explicit
# --------------------------------------------------------------------------

def test_declared_only_pypi_warns_and_records_a_known_unknown(tmp_path, capsys):
    # PIP_FREEZE_DECLARED_ONLY_DIR has only a requirements.txt, no gradle,
    # no --pip-freeze passed. This used to be the hard failure E-SBOM-02;
    # since P0 it writes the SBOM, warns, and records the gap in the SBOM
    # itself, so the technical file states it instead of not existing.
    out = tmp_path / "sbom.cdx.json"
    rc = generate(
        PIP_FREEZE_DECLARED_ONLY_DIR, "X", "1.0.0", None, include_dev=False,
        out=out,
    )
    err = capsys.readouterr().err

    assert rc == 0
    assert out.exists()
    assert "E-SBOM-02" not in err
    assert "W-SBOM-03" in err
    assert "pip freeze" in err
    assert "--pip-freeze" in err

    from cra_kit.sbom_coverage import from_bom
    bom = json.loads(out.read_text(encoding="utf-8"))
    unknowns = from_bom(bom)
    pypi = [u for u in unknowns if u["ecosystem"] == "pypi"]
    assert len(pypi) == 1
    assert pypi[0]["status"] == "partial"
    assert "--pip-freeze" in pypi[0]["fix"]
    assert bom["compositions"][0]["aggregate"] == "incomplete"


def test_pip_freeze_flag_satisfies_the_check_and_no_warning_fires(tmp_path, capsys):
    out = tmp_path / "sbom.cdx.json"
    rc = generate(
        PIP_FREEZE_BASIC_DIR, "X", "1.0.0", None, include_dev=False,
        out=out,
        pip_freeze=PIP_FREEZE_BASIC_DIR / "freeze.txt",
    )
    err = capsys.readouterr().err

    assert rc == 0
    assert out.exists()
    assert "E-SBOM-02" not in err
    assert "W-SBOM-03" not in err

    bom = json.loads(out.read_text(encoding="utf-8"))
    names = {c["name"] for c in bom["components"]}
    # 4 packages in freeze.txt, none double-counted against requirements.txt
    assert names == {"certifi", "click", "requests", "urllib3"}
    for c in bom["components"]:
        props = {p["name"]: p["value"] for p in c["properties"]}
        assert props["cra:pypi-source"] == "resolved"
    direct = {c["name"]: dict(
        (p["name"], p["value"]) for p in c["properties"]
    )["cra:direct"] for c in bom["components"]}
    assert direct["requests"] == "true"
    assert direct["click"] == "true"
    assert direct["certifi"] == "false"
    assert direct["urllib3"] == "false"


def test_declared_only_flag_is_still_accepted_and_still_writes(tmp_path, capsys):
    out = tmp_path / "sbom.cdx.json"
    rc = generate(
        PIP_FREEZE_DECLARED_ONLY_DIR, "X", "1.0.0", None, include_dev=False,
        out=out,
        declared_only=True,
    )
    err = capsys.readouterr().err

    assert rc == 0  # downgraded to a warning, not a failure
    assert out.exists()
    assert "E-SBOM-02" not in err
    assert "W-SBOM-03" in err
    assert "--pip-freeze" in err

    bom = json.loads(out.read_text(encoding="utf-8"))
    names = {c["name"] for c in bom["components"]}
    assert names == {"requests"}
    props = {p["name"]: p["value"] for p in bom["components"][0]["properties"]}
    assert props["cra:pypi-source"] == "declared"


def test_no_pypi_components_at_all_does_not_trigger_the_pypi_check(tmp_path):
    # A pure-Gradle project (multi-module fixture, no requirements.txt
    # anywhere) has zero PyPI components — E-SBOM-02 must not fire for a
    # project that simply isn't Python.
    out = tmp_path / "sbom.cdx.json"
    rc = generate(
        MULTI_MODULE_DIR, "X", "1.0.0", None, include_dev=False, out=out,
    )
    assert rc == 0
    assert out.exists()
