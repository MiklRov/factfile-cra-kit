"""
Tests for license_enrich.py — a port of an earlier internal collect_licenses.py
into cra-kit's SBOM-first pipeline (see the module docstring for the full
rationale). No test in this file makes a real network call: any test that
exercises the network-shaped paths (Gradle POM fetch, PyPI metadata) either
passes network_enabled=False / offline=True, or monkeypatches the seam
function directly (`license_enrich.fetch_pom_network` /
`license_enrich.fetch_pypi_metadata`) rather than `urllib.request.urlopen`
itself. The `no_network` autouse fixture in conftest.py fails loudly if
anything slips through unpatched.

The six fixture POMs under tests/fixtures/license_enrich/gradle-cache/ each
demonstrate exactly one outcome:
  - com.example.direct:direct-apache   -> own POM, Apache-2.0, matched directly
  - com.example.child:child-lib        -> no <licenses>, has <parent> ->
                                           com.example.parent:parent-pom (MIT)
  - com.example.proprietary:weird-license -> raw text found, no SPDX mapping
                                              (mirrors the real "Play Core SDK
                                              Terms of Service" case)
  - com.example.missing:not-in-cache   -> no POM anywhere -> genuinely nothing
  - com.example.dual:dual-lib          -> two <license> entries (MIT + Apache-2.0),
                                           both recorded, not collapsed
  - com.example.nolicense:no-license-lib -> POM read successfully, no
                                             <licenses>, no <parent> -> a real,
                                             confirmed "no license" (distinct
                                             from "we couldn't find a POM")

Network-shaped scenarios (POM fetched over the network, parent-walk
triggered after a network fetch, the .jar/.aar archive fallback) are tested
by monkeypatching `fetch_pom_network` and, for the archive path, building a
throwaway zip under tmp_path -- see the bottom of this file.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from factfile_cra_kit import license_enrich

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "license_enrich"
GRADLE_CACHE = FIXTURES_DIR / "gradle-cache"


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def mk_gradle_component(group: str, artifact: str, version: str) -> dict:
    purl = f"pkg:maven/{group}/{artifact}@{version}"
    return {
        "bom-ref": purl,
        "type": "library",
        "name": f"{group}:{artifact}",
        "version": version,
        "purl": purl,
        "scope": "required",
        "properties": [
            {"name": "cra:ecosystem", "value": "gradle"},
            {"name": "cra:direct", "value": "true"},
            {"name": "cra:dev", "value": "false"},
        ],
    }


def license_ids(comp: dict) -> list[str | None]:
    return [entry.get("license", {}).get("id") for entry in comp.get("licenses", [])]


def license_names(comp: dict) -> list[str | None]:
    return [entry.get("license", {}).get("name") for entry in comp.get("licenses", [])]


def prop(comp: dict, name: str) -> str | None:
    for p in comp.get("properties", []):
        if p["name"] == name:
            return p["value"]
    return None


# --------------------------------------------------------------------------
# 1. direct POM, Apache-2.0-ish string -> resolved SPDX, pom:gradle-cache
# --------------------------------------------------------------------------

def test_direct_pom_license_resolves_to_spdx():
    comp = mk_gradle_component("com.example.direct", "direct-apache", "1.0.0")
    license_enrich.enrich_gradle_component(comp, GRADLE_CACHE, cache_available=True)

    assert license_ids(comp) == ["Apache-2.0"]
    assert prop(comp, "cra:license-source") == "pom:gradle-cache"
    assert prop(comp, "cra:license-status") == "resolved"
    assert prop(comp, "cra:license-note") is None


# --------------------------------------------------------------------------
# 2. no <licenses> block, has <parent> which DOES -> one level of recursion
# --------------------------------------------------------------------------

def test_parent_pom_recursion_resolves_license():
    comp = mk_gradle_component("com.example.child", "child-lib", "2.0.0")
    license_enrich.enrich_gradle_component(comp, GRADLE_CACHE, cache_available=True)

    assert license_ids(comp) == ["MIT"]
    assert prop(comp, "cra:license-source") == "pom:parent"
    assert prop(comp, "cra:license-status") == "resolved"


# --------------------------------------------------------------------------
# 3. raw license string found, no SPDX mapping -> preserved verbatim, NOT
#    collapsed into "no license data" (case 4 must be distinguishably different)
# --------------------------------------------------------------------------

def test_unmatched_raw_license_preserved_verbatim():
    comp = mk_gradle_component("com.example.proprietary", "weird-license", "1.0.0")
    license_enrich.enrich_gradle_component(comp, GRADLE_CACHE, cache_available=True)

    assert license_ids(comp) == [None]
    assert license_names(comp) == ["Play Core Software Development Kit Terms of Service"]
    assert prop(comp, "cra:license-source") == "pom:gradle-cache"
    assert prop(comp, "cra:license-status") == "unmatched"
    # the component DOES carry license data -- this must not look like case 4
    assert comp.get("licenses")


# --------------------------------------------------------------------------
# 4. genuinely no POM anywhere (cache + network both exhausted, no archive
#    to fall back to either) -> unknown:not-determined, explicitly different
#    from both 3 (unmatched) and "declared-empty" (a POM WAS read and had
#    nothing) -- see the tests further down for that last distinction.
# --------------------------------------------------------------------------

def test_missing_pom_yields_unknown_not_determined():
    comp = mk_gradle_component("com.example.missing", "not-in-cache", "3.0.0")
    # network_enabled=False: this component genuinely isn't in the fixture
    # cache, and this test is specifically about the cache-exhausted case,
    # not the network-fetch path (covered separately below).
    license_enrich.enrich_gradle_component(comp, GRADLE_CACHE, cache_available=True,
                                            network_enabled=False)

    assert "licenses" not in comp
    assert prop(comp, "cra:license-source") == "unknown:not-determined"
    assert prop(comp, "cra:license-status") == "none"
    assert "pom-not-in-cache" in prop(comp, "cra:license-note")


def test_case_3_and_case_4_are_distinguishable():
    """The whole point of the three-state design: a raw-text-found-but-
    unmatched component must never look the same as a nothing-found one."""
    unmatched = mk_gradle_component("com.example.proprietary", "weird-license", "1.0.0")
    none_found = mk_gradle_component("com.example.missing", "not-in-cache", "3.0.0")
    license_enrich.enrich_gradle_component(unmatched, GRADLE_CACHE, cache_available=True)
    license_enrich.enrich_gradle_component(none_found, GRADLE_CACHE, cache_available=True,
                                            network_enabled=False)

    assert prop(unmatched, "cra:license-status") != prop(none_found, "cra:license-status")
    assert prop(unmatched, "cra:license-source") != prop(none_found, "cra:license-source")
    assert bool(unmatched.get("licenses")) is True
    assert bool(none_found.get("licenses")) is False


# --------------------------------------------------------------------------
# 6. a POM IS read successfully (no <licenses>, no <parent>) -> a real,
#    confirmed "no license", distinguishable from "we never found a POM"
#    (test 4 above) even though both end up with cra:license-status=none.
#    This is the core of the behavioral fix: not-declared vs not-determined.
# --------------------------------------------------------------------------

def test_pom_read_successfully_with_no_license_is_none_not_declared():
    comp = mk_gradle_component("com.example.nolicense", "no-license-lib", "1.0.0")
    license_enrich.enrich_gradle_component(comp, GRADLE_CACHE, cache_available=True,
                                            network_enabled=False)

    assert "licenses" not in comp
    assert prop(comp, "cra:license-source") == "none:not-declared"
    assert prop(comp, "cra:license-status") == "none"


def test_not_declared_and_not_determined_are_distinguishable():
    declared_empty = mk_gradle_component("com.example.nolicense", "no-license-lib", "1.0.0")
    truly_missing = mk_gradle_component("com.example.missing", "not-in-cache", "3.0.0")
    license_enrich.enrich_gradle_component(declared_empty, GRADLE_CACHE, cache_available=True,
                                            network_enabled=False)
    license_enrich.enrich_gradle_component(truly_missing, GRADLE_CACHE, cache_available=True,
                                            network_enabled=False)

    # both are cra:license-status=none (neither has a `licenses` field) --
    # that part is legitimately the same. The source must not be.
    assert prop(declared_empty, "cra:license-status") == "none"
    assert prop(truly_missing, "cra:license-status") == "none"
    assert prop(declared_empty, "cra:license-source") == "none:not-declared"
    assert prop(truly_missing, "cra:license-source") == "unknown:not-determined"
    assert prop(declared_empty, "cra:license-source") != prop(truly_missing, "cra:license-source")


# --------------------------------------------------------------------------
# 5. dual license -> both recorded, not collapsed into one
# --------------------------------------------------------------------------

def test_dual_license_both_recorded():
    comp = mk_gradle_component("com.example.dual", "dual-lib", "1.0.0")
    license_enrich.enrich_gradle_component(comp, GRADLE_CACHE, cache_available=True)

    assert set(license_ids(comp)) == {"MIT", "Apache-2.0"}
    assert len(comp["licenses"]) == 2
    assert prop(comp, "cra:license-status") == "resolved"


# --------------------------------------------------------------------------
# normalize_spdx table sanity (ported verbatim from collect_licenses.py)
# --------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("The Apache Software License, Version 2.0", "Apache-2.0"),
    ("MIT License", "MIT"),
    ("Android Software Development Kit License", "LicenseRef-android-sdk"),
    ("GNU AFFERO GPL 3.0", "AGPL-3.0-or-later"),
])
def test_normalize_spdx_known_strings(raw, expected):
    spdx, matched = license_enrich.normalize_spdx(raw)
    assert matched is True
    assert spdx == expected


def test_normalize_spdx_never_invents_an_id():
    spdx, matched = license_enrich.normalize_spdx("Some Totally Novel License Text")
    assert spdx is None
    assert matched is False


# --------------------------------------------------------------------------
# gradle cache dir missing entirely -> every component becomes 'none',
# never silently treated as resolved
# --------------------------------------------------------------------------

def test_gradle_cache_dir_missing_marks_none_not_crash():
    comp = mk_gradle_component("com.example.direct", "direct-apache", "1.0.0")
    license_enrich.enrich_gradle_component(comp, Path("/does/not/exist"), cache_available=False)

    assert "licenses" not in comp
    # cache dir missing entirely -- this is a config error, not a confirmed
    # "no license", so it must be unknown:not-determined, not none:not-declared.
    assert prop(comp, "cra:license-source") == "unknown:not-determined"
    assert "cache dir not found" in prop(comp, "cra:license-note")


# --------------------------------------------------------------------------
# re-run idempotency: enriching an already-enriched component must not
# accumulate duplicate cra:license-* properties
# --------------------------------------------------------------------------

def test_rerun_is_idempotent_no_duplicate_properties():
    comp = mk_gradle_component("com.example.direct", "direct-apache", "1.0.0")
    license_enrich.enrich_gradle_component(comp, GRADLE_CACHE, cache_available=True)
    license_enrich.enrich_gradle_component(comp, GRADLE_CACHE, cache_available=True)

    license_props = [p for p in comp["properties"] if p["name"].startswith("cra:license-")]
    names = [p["name"] for p in license_props]
    assert len(names) == len(set(names))
    assert license_ids(comp) == ["Apache-2.0"]


# --------------------------------------------------------------------------
# PyPI side: offline mode -> 'none', never a real network call
# --------------------------------------------------------------------------

def test_pypi_offline_mode_yields_none_no_network(monkeypatch):
    def fail_if_called(*args, **kwargs):
        raise AssertionError("fetch_pypi_metadata must not be called with --offline-python")

    monkeypatch.setattr(license_enrich, "fetch_pypi_metadata", fail_if_called)

    comp = {
        "bom-ref": "pkg:pypi/somepkg@1.0.0",
        "type": "library",
        "name": "somepkg",
        "version": "1.0.0",
        "purl": "pkg:pypi/somepkg@1.0.0",
        "properties": [
            {"name": "cra:ecosystem", "value": "pypi"},
            {"name": "cra:direct", "value": "true"},
            {"name": "cra:dev", "value": "false"},
        ],
    }
    license_enrich.enrich_pypi_component(comp, offline=True)

    assert "licenses" not in comp
    # PyPI was never actually consulted (--offline-python) -- a data gap,
    # not a confirmed absence of a license.
    assert prop(comp, "cra:license-source") == "unknown:not-determined"
    assert "offline mode" in prop(comp, "cra:license-note")


def test_pypi_online_mode_resolves_via_classifier(monkeypatch):
    def fake_fetch(name, version, pinned, timeout=10):
        return {
            "resolved_version": version,
            "license_field": None,
            "license_expression": None,
            "classifiers": ["License :: OSI Approved :: MIT License"],
            "error": None,
        }

    monkeypatch.setattr(license_enrich, "fetch_pypi_metadata", fake_fetch)

    comp = {
        "bom-ref": "pkg:pypi/somepkg@1.0.0",
        "type": "library",
        "name": "somepkg",
        "version": "1.0.0",
        "purl": "pkg:pypi/somepkg@1.0.0",
        "properties": [
            {"name": "cra:ecosystem", "value": "pypi"},
            {"name": "cra:direct", "value": "true"},
            {"name": "cra:dev", "value": "false"},
        ],
    }
    license_enrich.enrich_pypi_component(comp, offline=False)

    assert license_ids(comp) == ["MIT"]
    assert prop(comp, "cra:license-source") == "pypi:metadata"
    assert prop(comp, "cra:license-status") == "resolved"


def test_pypi_metadata_present_but_empty_is_none_not_declared(monkeypatch):
    """PyPI WAS reached successfully and simply has no License field or
    classifier -- a real, confirmed absence, distinct from offline mode or a
    fetch error (both of which are unknown:not-determined, tested above)."""
    def fake_fetch(name, version, pinned, timeout=10):
        return {
            "resolved_version": version,
            "license_field": None,
            "license_expression": None,
            "classifiers": [],
            "error": None,
        }

    monkeypatch.setattr(license_enrich, "fetch_pypi_metadata", fake_fetch)

    comp = {
        "bom-ref": "pkg:pypi/somepkg@1.0.0",
        "type": "library",
        "name": "somepkg",
        "version": "1.0.0",
        "purl": "pkg:pypi/somepkg@1.0.0",
        "properties": [
            {"name": "cra:ecosystem", "value": "pypi"},
            {"name": "cra:direct", "value": "true"},
            {"name": "cra:dev", "value": "false"},
        ],
    }
    license_enrich.enrich_pypi_component(comp, offline=False)

    assert "licenses" not in comp
    assert prop(comp, "cra:license-source") == "none:not-declared"
    assert prop(comp, "cra:license-status") == "none"


def test_pypi_fetch_error_is_unknown_not_determined(monkeypatch):
    def fake_fetch(name, version, pinned, timeout=10):
        return {"resolved_version": None, "license_field": None, "license_expression": None,
                "classifiers": [], "error": "HTTP 404"}

    monkeypatch.setattr(license_enrich, "fetch_pypi_metadata", fake_fetch)

    comp = {
        "bom-ref": "pkg:pypi/somepkg@1.0.0",
        "type": "library",
        "name": "somepkg",
        "version": "1.0.0",
        "purl": "pkg:pypi/somepkg@1.0.0",
        "properties": [
            {"name": "cra:ecosystem", "value": "pypi"},
            {"name": "cra:direct", "value": "true"},
            {"name": "cra:dev", "value": "false"},
        ],
    }
    license_enrich.enrich_pypi_component(comp, offline=False)

    assert "licenses" not in comp
    assert prop(comp, "cra:license-source") == "unknown:not-determined"


# --------------------------------------------------------------------------
# Gradle network POM fetch (fix #1) -- --offline is OFF by default, so a
# component missing from the local cache is fetched over the network.
# Every test here monkeypatches license_enrich.fetch_pom_network directly
# (the same pattern the PyPI tests above use for fetch_pypi_metadata) so
# nothing ever reaches real urllib.
# --------------------------------------------------------------------------

def test_network_fetch_resolves_when_not_in_local_cache(monkeypatch, tmp_path):
    def fake_fetch(fetch_cache_root, group, artifact, version, timeout=10):
        dest = fetch_cache_root / group / artifact / version / f"{artifact}-{version}.pom"
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(
            "<project><licenses><license>"
            "<name>Apache License, Version 2.0</name>"
            "<url>http://www.apache.org/licenses/LICENSE-2.0.txt</url>"
            "</license></licenses></project>",
            encoding="utf-8",
        )
        return dest, None

    monkeypatch.setattr(license_enrich, "fetch_pom_network", fake_fetch)

    comp = mk_gradle_component("com.example.networkonly", "not-cached-anywhere", "5.0.0")
    license_enrich.enrich_gradle_component(comp, GRADLE_CACHE, cache_available=True,
                                            network_enabled=True, maven_fetch_cache=tmp_path)

    assert license_ids(comp) == ["Apache-2.0"]
    assert prop(comp, "cra:license-source") == "pom:fetched"
    assert prop(comp, "cra:license-status") == "resolved"


def test_offline_flag_disables_network_fetch(monkeypatch):
    def fail_if_called(*args, **kwargs):
        raise AssertionError("fetch_pom_network must not be called when network_enabled=False (--offline)")

    monkeypatch.setattr(license_enrich, "fetch_pom_network", fail_if_called)

    comp = mk_gradle_component("com.example.missing", "not-in-cache", "3.0.0")
    license_enrich.enrich_gradle_component(comp, GRADLE_CACHE, cache_available=True,
                                            network_enabled=False)

    assert prop(comp, "cra:license-source") == "unknown:not-determined"


def test_network_fetch_failure_falls_through_to_unknown_not_determined(monkeypatch):
    monkeypatch.setattr(license_enrich, "fetch_pom_network",
                         lambda *a, **k: (None, "HTTP 404 for both repos"))

    comp = mk_gradle_component("com.example.missing", "not-in-cache", "3.0.0")
    license_enrich.enrich_gradle_component(comp, GRADLE_CACHE, cache_available=True,
                                            network_enabled=True, maven_fetch_cache=Path("unused"))

    assert "licenses" not in comp
    assert prop(comp, "cra:license-source") == "unknown:not-determined"
    assert "network-fetch-failed" in prop(comp, "cra:license-note")


def test_parent_walk_triggers_after_child_pom_was_network_fetched(monkeypatch, tmp_path):
    """The gap the diagnosis specifically flagged: parent-POM walking must
    not be wired only to the local-cache-read path. Here the CHILD's POM is
    only reachable via a (mocked) network fetch; its parent
    (com.example.parent:parent-pom:9.0.0, MIT) is the real fixture POM
    already used by test_parent_pom_recursion_resolves_license, sitting in
    the local cache."""
    def fake_fetch(fetch_cache_root, group, artifact, version, timeout=10):
        if (group, artifact, version) != ("com.example.networkchild", "child-needs-parent", "1.0.0"):
            return None, f"not mocked for {group}:{artifact}:{version}"
        dest = fetch_cache_root / group / artifact / version / f"{artifact}-{version}.pom"
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(
            "<project><parent>"
            "<groupId>com.example.parent</groupId>"
            "<artifactId>parent-pom</artifactId>"
            "<version>9.0.0</version>"
            "</parent></project>",
            encoding="utf-8",
        )
        return dest, None

    monkeypatch.setattr(license_enrich, "fetch_pom_network", fake_fetch)

    comp = mk_gradle_component("com.example.networkchild", "child-needs-parent", "1.0.0")
    license_enrich.enrich_gradle_component(comp, GRADLE_CACHE, cache_available=True,
                                            network_enabled=True, maven_fetch_cache=tmp_path)

    assert license_ids(comp) == ["MIT"]
    assert prop(comp, "cra:license-source") == "pom:parent"
    assert prop(comp, "cra:license-status") == "resolved"


# --------------------------------------------------------------------------
# Archive fallback (fix #2) -- only reached when cache + network both come
# up empty. Builds a throwaway .aar (a zip file) under tmp_path; no static
# binary fixtures needed.
# --------------------------------------------------------------------------

def test_archive_fallback_finds_bundle_license_in_manifest(tmp_path, monkeypatch):
    monkeypatch.setattr(license_enrich, "fetch_pom_network",
                         lambda *a, **k: (None, "simulated 404"))

    cache_root = tmp_path / "gradle-cache"
    hash_dir = cache_root / "com.example.archived" / "manifest-license" / "1.0.0" / "abc123"
    hash_dir.mkdir(parents=True)
    aar_path = hash_dir / "manifest-license-1.0.0.aar"
    with zipfile.ZipFile(aar_path, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nBundle-License: Apache-2.0\n")

    comp = mk_gradle_component("com.example.archived", "manifest-license", "1.0.0")
    license_enrich.enrich_gradle_component(comp, cache_root, cache_available=True,
                                            network_enabled=True,
                                            maven_fetch_cache=tmp_path / "fetch-cache")

    assert license_ids(comp) == ["Apache-2.0"]
    assert prop(comp, "cra:license-source") == "archive:manifest"
    assert prop(comp, "cra:license-status") == "resolved"


def test_archive_fallback_finds_embedded_pom(tmp_path, monkeypatch):
    monkeypatch.setattr(license_enrich, "fetch_pom_network",
                         lambda *a, **k: (None, "simulated 404"))

    cache_root = tmp_path / "gradle-cache"
    hash_dir = cache_root / "com.example.archived" / "embedded-pom" / "1.0.0" / "def456"
    hash_dir.mkdir(parents=True)
    jar_path = hash_dir / "embedded-pom-1.0.0.jar"
    with zipfile.ZipFile(jar_path, "w") as zf:
        zf.writestr(
            "META-INF/maven/com.example.archived/embedded-pom/pom.xml",
            "<project><licenses><license><name>MIT License</name></license></licenses></project>",
        )

    comp = mk_gradle_component("com.example.archived", "embedded-pom", "1.0.0")
    license_enrich.enrich_gradle_component(comp, cache_root, cache_available=True,
                                            network_enabled=True,
                                            maven_fetch_cache=tmp_path / "fetch-cache")

    assert license_ids(comp) == ["MIT"]
    assert prop(comp, "cra:license-source") == "archive:manifest"
    assert prop(comp, "cra:license-status") == "resolved"


def test_archive_present_but_empty_still_unknown_not_determined(tmp_path, monkeypatch):
    """An archive that opens fine but has neither an embedded POM license
    nor a Bundle-License header is NOT good enough evidence to call it
    none:not-declared -- most jars carry no license metadata at all even
    when the artifact is genuinely licensed."""
    monkeypatch.setattr(license_enrich, "fetch_pom_network",
                         lambda *a, **k: (None, "simulated 404"))

    cache_root = tmp_path / "gradle-cache"
    hash_dir = cache_root / "com.example.archived" / "no-clues" / "1.0.0" / "ghi789"
    hash_dir.mkdir(parents=True)
    jar_path = hash_dir / "no-clues-1.0.0.jar"
    with zipfile.ZipFile(jar_path, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")

    comp = mk_gradle_component("com.example.archived", "no-clues", "1.0.0")
    license_enrich.enrich_gradle_component(comp, cache_root, cache_available=True,
                                            network_enabled=True,
                                            maven_fetch_cache=tmp_path / "fetch-cache")

    assert "licenses" not in comp
    assert prop(comp, "cra:license-source") == "unknown:not-determined"


def test_no_pom_no_archive_anywhere_is_unknown_not_determined(tmp_path, monkeypatch):
    """The true end state: cache miss, network miss, and there isn't even a
    local .jar/.aar to open (mirrors the real 6 "not-in-cache" components
    from the diagnosis before the network fetch closed them)."""
    monkeypatch.setattr(license_enrich, "fetch_pom_network",
                         lambda *a, **k: (None, "simulated 404"))

    cache_root = tmp_path / "gradle-cache"
    cache_root.mkdir()

    comp = mk_gradle_component("com.example.nowhere", "truly-missing", "1.0.0")
    license_enrich.enrich_gradle_component(comp, cache_root, cache_available=True,
                                            network_enabled=True,
                                            maven_fetch_cache=tmp_path / "fetch-cache")

    assert "licenses" not in comp
    assert prop(comp, "cra:license-source") == "unknown:not-determined"
    assert prop(comp, "cra:license-status") == "none"


# --------------------------------------------------------------------------
# resolve_from_archive() unit tests -- direct, without going through
# enrich_gradle_component()
# --------------------------------------------------------------------------

def test_resolve_from_archive_unfolds_wrapped_manifest_header(tmp_path):
    """MANIFEST.MF wraps long header values onto continuation lines starting
    with a single space (the JAR spec's 72-byte line limit)."""
    aar_path = tmp_path / "wrapped.aar"
    with zipfile.ZipFile(aar_path, "w") as zf:
        zf.writestr(
            "META-INF/MANIFEST.MF",
            "Manifest-Version: 1.0\nBundle-License: Eclipse Public Li\n cense 2.0\n",
        )

    res = license_enrich.resolve_from_archive(aar_path)
    assert res["outcome"] == "found"
    assert res["licenses"][0]["name"] == "Eclipse Public License 2.0"


def test_resolve_from_archive_bad_zip_is_not_found(tmp_path):
    corrupt = tmp_path / "corrupt.aar"
    corrupt.write_bytes(b"not a zip file at all")

    res = license_enrich.resolve_from_archive(corrupt)
    assert res["outcome"] == "not-found"
    assert "could not open" in res["note"]


# --------------------------------------------------------------------------
# full enrich_bom() pass over a small in-memory SBOM
# --------------------------------------------------------------------------

def test_enrich_bom_leaves_non_gradle_non_pypi_components_untouched():
    bom = {
        "components": [
            mk_gradle_component("com.example.direct", "direct-apache", "1.0.0"),
            {
                "bom-ref": "pkg:npm/foo@1.2.3",
                "type": "library",
                "name": "foo",
                "version": "1.2.3",
                "purl": "pkg:npm/foo@1.2.3",
                "licenses": [{"license": {"id": "MIT"}}],
                "properties": [
                    {"name": "cra:ecosystem", "value": "npm"},
                    {"name": "cra:direct", "value": "true"},
                    {"name": "cra:dev", "value": "false"},
                ],
            },
        ]
    }
    counts = license_enrich.enrich_bom(bom, GRADLE_CACHE, offline_python=True)

    npm_comp = bom["components"][1]
    assert npm_comp["licenses"] == [{"license": {"id": "MIT"}}]
    assert all(not p["name"].startswith("cra:license-") for p in npm_comp["properties"])

    gradle_comp = bom["components"][0]
    assert license_ids(gradle_comp) == ["Apache-2.0"]
    assert counts["gradle"] == 1
    assert counts["python"] == 0
