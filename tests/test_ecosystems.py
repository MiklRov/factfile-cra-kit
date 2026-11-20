"""
Tests for ecosystems.py's Gradle handling — multi-module discovery and the
version-catalog / BOM-managed-version convention.

Regression scope: a root-only static parse of a multi-module Android project
used to see no `dependencies {}` block in the root build.gradle.kts and
silently return []. `discover_gradle_modules()` + `parse_gradle()` now walk
settings.gradle.kts, parse every declared module's own build file, and merge
the results — this is what turns sbom_gen.py's root-directory invocation from
a silent empty SBOM into real coverage (see tests/test_sbom_gen.py for the
end-to-end version of that same fix).
"""

from __future__ import annotations

from conftest import FIXTURES_DIR

from cra_kit.ecosystems import discover_gradle_modules, parse_gradle, parse_pip_freeze, parse_pypi

MULTI_MODULE_DIR = FIXTURES_DIR / "gradle_multi_module"
BOM_MANAGED_DIR = FIXTURES_DIR / "gradle_bom_managed"
PIP_FREEZE_BASIC_DIR = FIXTURES_DIR / "pip_freeze_basic"
PIP_FREEZE_UNKNOWN_DIR = FIXTURES_DIR / "pip_freeze_unknown"
PIP_FREEZE_BOM_DIR = FIXTURES_DIR / "pip_freeze_bom"


def _prop(comp: dict, name: str) -> str | None:
    for p in comp["properties"]:
        if p["name"] == name:
            return p["value"]
    return None


# --------------------------------------------------------------------------
# discover_gradle_modules
# --------------------------------------------------------------------------

def test_discover_modules_handles_single_and_multi_arg_include():
    modules = discover_gradle_modules(MULTI_MODULE_DIR)
    names = {name for name, _ in modules}
    # settings.gradle.kts declares `include(":mod-a", ":mod-b")` (multi-arg,
    # one call) and `include(":mod-c")` (single-arg, separate call) — both
    # forms must be picked up.
    assert names == {"mod-a", "mod-b", "mod-c"}


def test_discover_modules_maps_colon_path_to_directory():
    modules = dict(discover_gradle_modules(MULTI_MODULE_DIR))
    assert modules["mod-a"] == MULTI_MODULE_DIR / "mod-a"
    assert modules["mod-b"] == MULTI_MODULE_DIR / "mod-b"


def test_discover_modules_empty_when_no_settings_file():
    # mod-a itself has no settings.gradle(.kts) — it's a leaf module, not a
    # multi-module root.
    assert discover_gradle_modules(MULTI_MODULE_DIR / "mod-a") == []


# --------------------------------------------------------------------------
# parse_gradle — multi-module discovery + merge
# --------------------------------------------------------------------------

def test_multi_module_root_yields_components_from_every_module():
    comps = parse_gradle(MULTI_MODULE_DIR)
    # mod-c is declared in settings.gradle.kts but has no directory on disk —
    # discovery must skip it gracefully rather than crashing.
    assert comps, "root-only static parsing must not silently return zero components"
    names = {c["name"] for c in comps}
    assert "androidx.core:core-ktx" in names  # from mod-a
    assert "com.squareup.okhttp3:okhttp" in names  # from mod-b


def test_multi_module_components_tagged_with_owning_module():
    comps = {c["name"]: c for c in parse_gradle(MULTI_MODULE_DIR)}
    assert _prop(comps["androidx.core:core-ktx"], "cra:module") == "mod-a"
    assert _prop(comps["com.squareup.okhttp3:okhttp"], "cra:module") == "mod-b"


def test_inter_module_project_dependency_does_not_leak_as_external_component():
    # mod-a declares `implementation(project(":mod-b"))` — that is not a
    # third-party package and must never surface as pkg:maven/mod-b/...
    comps = parse_gradle(MULTI_MODULE_DIR)
    assert not any(c["purl"].startswith("pkg:maven/mod-a/") for c in comps)
    assert not any(c["purl"].startswith("pkg:maven/mod-b/") for c in comps)
    # exactly the two real external dependencies, nothing named after a module
    assert len(comps) == 2


def test_single_module_dir_without_settings_falls_back_to_direct_parse():
    # Calling parse_gradle directly on a leaf module (no settings.gradle.kts
    # there) must behave exactly as single-module parsing always has: only
    # that module's own dependencies, none of its sibling's.
    comps = parse_gradle(MULTI_MODULE_DIR / "mod-a")
    names = {c["name"] for c in comps}
    assert names == {"androidx.core:core-ktx"}


# --------------------------------------------------------------------------
# version-catalog / BOM-managed version convention
# --------------------------------------------------------------------------

def test_bom_managed_dependency_version_is_literally_unspecified():
    comps = {c["name"]: c for c in parse_gradle(BOM_MANAGED_DIR / "module")}
    ui = comps["androidx.compose.ui:ui"]
    # compose-ui has no version.ref in the catalog — its version is decided
    # by the compose-bom platform at Gradle resolution time, which static
    # parsing cannot see. The existing convention (ecosystems.py: `purl_ver =
    # version or "unspecified"`) must report this honestly, not guess.
    assert ui["version"] == "unspecified"
    assert _prop(ui, "cra:version-managed-by-bom") == "true"
    assert "androidx.compose:compose-bom:2024.12.01" in (_prop(ui, "cra:bom") or "")


def test_bom_itself_keeps_its_explicit_version():
    comps = {c["name"]: c for c in parse_gradle(BOM_MANAGED_DIR / "module")}
    bom = comps["androidx.compose:compose-bom"]
    assert bom["version"] == "2024.12.01"


# --------------------------------------------------------------------------
# parse_pip_freeze — resolved-environment PyPI coverage
#
# Regression scope: requirements.txt is hand-maintained and only ever shows
# top-level packages someone chose to declare — a real incident (2026-08-20,
# on a real backend) found 27 declared vs 111 actually resolved and running in
# production, including security-critical packages (cryptography, PyJWT,
# redis, sentry-sdk) invisible to a requirements.txt-only scan. See
# test_sbom_gen.py for the E-SBOM-02/W-SBOM-03
# checks built on top of this parser.
# --------------------------------------------------------------------------

def test_pip_freeze_cross_referenced_against_requirements_tags_direct_and_transitive():
    comps = {
        c["name"]: c
        for c in parse_pip_freeze(
            PIP_FREEZE_BASIC_DIR / "freeze.txt",
            requirements_paths=[PIP_FREEZE_BASIC_DIR / "requirements.txt"],
        )
    }
    # freeze.txt has 4 packages; requirements.txt names 2 of them (requests, click)
    assert set(comps) == {"certifi", "click", "requests", "urllib3"}
    assert _prop(comps["requests"], "cra:direct") == "true"
    assert _prop(comps["click"], "cra:direct") == "true"
    # found only in the freeze file, not declared anywhere — genuinely transitive
    assert _prop(comps["certifi"], "cra:direct") == "false"
    assert _prop(comps["urllib3"], "cra:direct") == "false"


def test_pip_freeze_components_tagged_resolved_not_declared():
    comps = parse_pip_freeze(
        PIP_FREEZE_BASIC_DIR / "freeze.txt",
        requirements_paths=[PIP_FREEZE_BASIC_DIR / "requirements.txt"],
    )
    assert comps  # sanity: fixture actually produced components
    for c in comps:
        assert _prop(c, "cra:ecosystem") == "pypi"
        assert _prop(c, "cra:pypi-source") == "resolved"


def test_pip_freeze_no_double_counting_when_requirements_also_parsed_separately():
    # parse_pypi(requirements.txt) and parse_pip_freeze(freeze.txt, ...) each
    # return their own component lists — sbom_gen.py's _pypi_components()
    # helper is responsible for calling only one of them per run. This test
    # just pins down that a name declared in both files is not itself
    # duplicated *within* the freeze-derived list.
    freeze_comps = parse_pip_freeze(
        PIP_FREEZE_BASIC_DIR / "freeze.txt",
        requirements_paths=[PIP_FREEZE_BASIC_DIR / "requirements.txt"],
    )
    names = [c["name"] for c in freeze_comps]
    assert len(names) == len(set(names))
    assert names.count("requests") == 1


def test_pip_freeze_without_any_requirements_file_marks_direct_unknown():
    # No requirements.txt exists anywhere near this fixture — the freeze file
    # alone cannot say what is top-level vs transitive, so cra:direct must be
    # an honest "unknown", not a silent guess in either direction.
    comps = parse_pip_freeze(PIP_FREEZE_UNKNOWN_DIR / "freeze.txt")
    assert comps
    for c in comps:
        assert _prop(c, "cra:direct") == "unknown"


def test_pip_freeze_missing_requirements_path_also_marks_unknown():
    # Same as above, but explicitly passing a requirements_paths list whose
    # entries don't exist on disk — must behave identically to passing None,
    # not silently treat "the file doesn't exist" as "nothing is direct".
    comps = parse_pip_freeze(
        PIP_FREEZE_UNKNOWN_DIR / "freeze.txt",
        requirements_paths=[PIP_FREEZE_UNKNOWN_DIR / "requirements.txt"],
    )
    assert comps
    for c in comps:
        assert _prop(c, "cra:direct") == "unknown"


def test_pip_freeze_handles_utf8_bom_and_crlf():
    # Real pip-freeze capture (docker exec ... pip freeze, piped through a
    # Windows shell) came back UTF-8 with a BOM and CRLF line endings. The
    # BOM must not leak into the first package's name.
    comps = {
        c["name"]: c
        for c in parse_pip_freeze(PIP_FREEZE_BOM_DIR / "freeze_with_bom.txt")
    }
    assert set(comps) == {"package-one", "package-two"}
    assert "﻿package-one" not in comps
    assert comps["package-one"]["version"] == "1.0.0"
    assert comps["package-two"]["version"] == "2.5.1"


def test_pip_freeze_purl_and_version_from_flat_freeze_line():
    comps = {c["name"]: c for c in parse_pip_freeze(PIP_FREEZE_UNKNOWN_DIR / "freeze.txt")}
    assert comps["flask"]["version"] == "3.0.2"
    assert comps["flask"]["purl"] == "pkg:pypi/flask@3.0.2"


def test_parse_pypi_tags_declared_source():
    # parse_pypi (declared-only, requirements.txt) must be distinguishable
    # from parse_pip_freeze (resolved) via cra:pypi-source, so a reader of
    # the final SBOM can tell which PyPI components were confirmed against a
    # real resolved environment versus just declared.
    comps = parse_pypi(PIP_FREEZE_BASIC_DIR / "requirements.txt")
    assert comps
    for c in comps:
        assert _prop(c, "cra:pypi-source") == "declared"
