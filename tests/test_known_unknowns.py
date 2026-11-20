"""
Tests for P0: the optional Syft path, per-ecosystem gaps instead of a global
hard failure, and the known-unknowns record (coverage.py, syft_scan.py, and
their wiring in sbom_gen.py and build.py).

No test runs a real Syft. Every Syft call goes through a fake runner that
returns canned CycloneDX, so the suite needs neither Syft nor Docker.

The fixture tests/fixtures/polyglot/ is the acceptance case from the brief:
a Gradle project with a Dockerfile and a Go service in a subdirectory. It
also carries a node_modules/ directory that detection must ignore.
"""

from __future__ import annotations

import json
import shutil
import subprocess

import pytest

from conftest import FIXTURES_DIR

from cra_kit import sbom_coverage as coverage
from cra_kit import syft_scan
from cra_kit.build import build, known_unknowns_section
from cra_kit.sbom_gen import generate

POLYGLOT = FIXTURES_DIR / "polyglot"
HAPPY_DIR = FIXTURES_DIR / "build_happy"
NO_MANIFEST_DIR = FIXTURES_DIR / "no_manifest"


# --------------------------------------------------------------------------
# a fake Syft
# --------------------------------------------------------------------------

def _cdx(components):
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": components}


DIR_SCAN = _cdx([
    {"type": "library", "name": "github.com/google/uuid", "version": "v1.6.0",
     "purl": "pkg:golang/github.com/google/uuid@v1.6.0",
     "licenses": [{"license": {"id": "BSD-3-Clause"}}],
     "properties": [{"name": "syft:package:foundBy", "value": "go-module-file-cataloger"}]},
    # also found by our own Gradle parser: must be dropped (ours wins)
    {"type": "library", "group": "com.squareup.okhttp3", "name": "okhttp",
     "version": "4.12.0", "purl": "pkg:maven/com.squareup.okhttp3/okhttp@4.12.0"},
    # a test-only dependency Syft does not know to exclude: same ecosystem
    # as ours, so it must be dropped too
    {"type": "library", "group": "junit", "name": "junit", "version": "4.13.2",
     "purl": "pkg:maven/junit/junit@4.13.2"},
    # the scanned source itself is not a package
    {"type": "file", "name": "/src/go.mod"},
])

IMAGE_SCAN = _cdx([
    {"type": "library", "name": "libc6", "version": "2.36-9",
     "purl": "pkg:deb/debian/libc6@2.36-9?arch=amd64&distro=debian-12"},
    # same group:name@version as ours, with a qualifier ours does not have
    {"type": "library", "group": "com.squareup.okhttp3", "name": "okhttp",
     "version": "4.12.0", "purl": "pkg:maven/com.squareup.okhttp3/okhttp@4.12.0?type=jar"},
    {"type": "operating-system", "name": "debian", "version": "12"},
])


class FakeSyft:
    def __init__(self, fail_on: str | None = None):
        self.calls: list[tuple[list[str], dict]] = []
        self.fail_on = fail_on

    def __call__(self, cmd, **kw):
        self.calls.append((cmd, kw))
        source = cmd[2]
        if self.fail_on and source.startswith(self.fail_on):
            return subprocess.CompletedProcess(cmd, 1, "", "boom: cannot read source\n")
        doc = DIR_SCAN if source.startswith("dir:") else IMAGE_SCAN
        return subprocess.CompletedProcess(cmd, 0, json.dumps(doc), "")


def _gen(tmp_path, **kw):
    out = tmp_path / "sbom.cdx.json"
    rc = generate(POLYGLOT, "Poly", "1.0.0", None, include_dev=False, out=out, **kw)
    bom = json.loads(out.read_text(encoding="utf-8")) if out.exists() else None
    return rc, bom


def _props(c):
    return {p["name"]: p["value"] for p in c.get("properties", [])}


def _by_eco(unknowns):
    return {u["ecosystem"]: u for u in unknowns}


# --------------------------------------------------------------------------
# acceptance: no Syft
# --------------------------------------------------------------------------

def test_without_syft_go_and_container_are_named_as_known_unknowns(tmp_path, capsys):
    rc, bom = _gen(tmp_path)
    err = capsys.readouterr().err

    assert rc == 0, err
    unknowns = _by_eco(coverage.from_bom(bom))

    assert unknowns["go"]["status"] == "unresolved"
    assert unknowns["go"]["evidence"] == ["service/go.mod"]
    assert "Syft" in unknowns["go"]["reason"]

    cont = unknowns["container"]
    assert cont["status"] == "unresolved"
    assert cont["evidence"] == ["Dockerfile"]
    assert cont["base_images"] == ["golang:1.23-bookworm", "eclipse-temurin:21-jre"]
    assert "docker save" in cont["fix"]

    # Gradle came from static parsing only: present, but partial
    assert unknowns["gradle"]["status"] == "partial"
    # node_modules/ is never treated as the product's own npm usage
    assert "npm" not in unknowns

    assert bom["compositions"] == [
        {"aggregate": "incomplete", "assemblies": ["pkg:generic/Poly@1.0.0"]}
    ]
    for c in bom["components"]:
        assert _props(c)["cra:generator"] == "cra-kit"

    assert "W-SBOM-04" in err
    assert "service/go.mod" in err


def test_without_syft_the_technical_file_prints_the_section(tmp_path):
    _, _ = _gen(tmp_path)
    out_dir = tmp_path / "out"
    rc = build(cfg_dir=HAPPY_DIR, sbom_path=tmp_path / "sbom.cdx.json",
               out_dir=out_dir, pdf=False)
    assert rc == 0
    text = (out_dir / "technical_file.md").read_text(encoding="utf-8")

    assert "## 8.3 Known unknowns" in text
    assert "| go | unresolved | `service/go.mod` |" in text
    assert "Built on `golang:1.23-bookworm`, `eclipse-temurin:21-jre`" in text
    assert "Coverage is incomplete" in text
    assert "Coverage exceeds the statutory minimum" not in text


# --------------------------------------------------------------------------
# acceptance: with Syft
# --------------------------------------------------------------------------

def test_with_syft_go_is_in_the_sbom_tagged_syft(tmp_path):
    fake = FakeSyft()
    rc, bom = _gen(tmp_path, syft="syft", syft_runner=fake)
    assert rc == 0

    by_purl = {c["purl"]: c for c in bom["components"]}
    uuid = by_purl["pkg:golang/github.com/google/uuid@v1.6.0"]
    p = _props(uuid)
    assert p["cra:generator"] == "syft"
    assert p["cra:ecosystem"] == "go"
    assert p["cra:direct"] == "unknown"
    assert p["cra:syft-source"] == "dir"
    assert not any(k.startswith("syft:") for k in p)
    assert uuid["licenses"] == [{"license": {"id": "BSD-3-Clause"}}]

    # ours kept, Syft's duplicate dropped, Syft's test-only extra dropped
    okhttp = by_purl["pkg:maven/com.squareup.okhttp3/okhttp@4.12.0"]
    assert _props(okhttp)["cra:generator"] == "cra-kit"
    assert "pkg:maven/junit/junit@4.13.2" not in by_purl
    assert not any(c.get("type") == "file" for c in bom["components"])

    unknowns = _by_eco(coverage.from_bom(bom))
    assert "go" not in unknowns
    assert "container" in unknowns  # no image given: still a known unknown

    tools = [t["name"] for t in bom["metadata"]["tools"]["components"]]
    assert "syft" in tools


def test_syft_runs_offline_without_update_check(tmp_path):
    fake = FakeSyft()
    _gen(tmp_path, syft="syft", syft_runner=fake)
    cmd, kw = fake.calls[0]
    assert cmd[:2] == ["syft", "scan"]
    assert cmd[2] == f"dir:{POLYGLOT}"
    assert ["-o", "cyclonedx-json"] == cmd[3:5]
    assert kw["env"]["SYFT_CHECK_FOR_APP_UPDATE"] == "false"


def test_with_an_image_archive_the_container_is_resolved(tmp_path):
    archive = tmp_path / "image.tar"
    archive.write_bytes(b"not really a tar; the fake runner never reads it")
    fake = FakeSyft()
    rc, bom = _gen(tmp_path, syft="syft", syft_image=str(archive), syft_runner=fake)
    assert rc == 0

    assert fake.calls[1][0][2] == f"docker-archive:{archive}"
    by_purl = {c["purl"]: c for c in bom["components"] if c.get("purl")}
    libc = by_purl["pkg:deb/debian/libc6@2.36-9?arch=amd64&distro=debian-12"]
    assert _props(libc)["cra:ecosystem"] == "os:deb"
    assert _props(libc)["cra:syft-source"] == "image"
    # the qualified okhttp purl from the image is the same component as ours
    assert "pkg:maven/com.squareup.okhttp3/okhttp@4.12.0?type=jar" not in by_purl
    assert not any(c.get("type") == "operating-system" for c in bom["components"])

    unknowns = _by_eco(coverage.from_bom(bom))
    assert "container" not in unknowns
    assert "go" not in unknowns


def test_a_failing_syft_is_a_known_unknown_not_a_failure(tmp_path, capsys):
    rc, bom = _gen(tmp_path, syft="syft", syft_runner=FakeSyft(fail_on="dir:"))
    assert rc == 0
    go = _by_eco(coverage.from_bom(bom))["go"]
    assert go["reason"].startswith("Syft failed: syft exited 1")
    assert "boom" in go["reason"]


def test_syft_output_that_is_not_cyclonedx_is_rejected(tmp_path):
    def runner(cmd, **kw):
        return subprocess.CompletedProcess(cmd, 0, '{"artifacts": []}', "")
    rc, bom = _gen(tmp_path, syft="syft", syft_runner=runner)
    assert rc == 0
    assert "not a CycloneDX document" in _by_eco(coverage.from_bom(bom))["go"]["reason"]


def test_image_without_syft_binary_stays_unknown(tmp_path):
    archive = tmp_path / "image.tar"
    archive.write_bytes(b"x")
    rc, bom = _gen(tmp_path, syft_image=str(archive))
    assert rc == 0
    cont = _by_eco(coverage.from_bom(bom))["container"]
    assert "no Syft binary" in cont["reason"]


# --------------------------------------------------------------------------
# the hard failures that stay
# --------------------------------------------------------------------------

def test_empty_sbom_is_still_a_hard_failure_and_names_what_was_detected(tmp_path, capsys):
    root = tmp_path / "repo"
    shutil.copytree(NO_MANIFEST_DIR, root)
    (root / "go.mod").write_text("module x\n\ngo 1.23\n", encoding="utf-8")
    out = tmp_path / "sbom.cdx.json"

    rc = generate(root, "X", "1.0.0", None, include_dev=False, out=out)
    err = capsys.readouterr().err

    assert rc != 0
    assert "E-SBOM-01" in err
    assert "detected but not resolved: go (go.mod)" in err
    assert not out.exists()


# --------------------------------------------------------------------------
# image sources stay local
# --------------------------------------------------------------------------

def test_registry_images_are_refused():
    with pytest.raises(syft_scan.SyftError, match="registry"):
        syft_scan.image_source("registry:python:3.12-slim")


def test_a_bare_image_reference_is_refused():
    with pytest.raises(syft_scan.SyftError, match="not a local image archive"):
        syft_scan.image_source("python:3.12-slim")


def test_explicit_local_schemes_pass_through():
    assert syft_scan.image_source("docker:myapp:1.0") == "docker:myapp:1.0"
    assert syft_scan.image_source("oci-archive:/x/img.tar") == "oci-archive:/x/img.tar"


def test_local_paths_map_to_archive_or_layout(tmp_path):
    tar = tmp_path / "img.tar"
    tar.write_bytes(b"x")
    layout = tmp_path / "layout"
    layout.mkdir()
    assert syft_scan.image_source(str(tar)) == f"docker-archive:{tar}"
    assert syft_scan.image_source(str(layout)) == f"oci-dir:{layout}"


def test_windows_drive_letter_is_not_a_scheme():
    with pytest.raises(syft_scan.SyftError, match="not a local image archive"):
        syft_scan.image_source("Z:\\nowhere\\img.tar")


# --------------------------------------------------------------------------
# detection and Dockerfile parsing
# --------------------------------------------------------------------------

def test_detect_skips_vendored_and_build_directories():
    found = coverage.detect(POLYGLOT)
    assert found == {
        "container": ["Dockerfile"],
        "go": ["service/go.mod"],
        "gradle": ["build.gradle.kts"],
    }


def test_base_images_handles_flags_aliases_scratch_and_continuations(tmp_path):
    assert coverage.base_images(POLYGLOT / "Dockerfile") == [
        "golang:1.23-bookworm", "eclipse-temurin:21-jre",
    ]
    df = tmp_path / "Dockerfile"
    df.write_text("ARG TAG=3.12\nFROM python:${TAG}-slim\n", encoding="utf-8")
    assert coverage.base_images(df) == ["python:${TAG}-slim"]


def test_merge_keys_on_group_name_version_per_ecosystem():
    ours = [{"purl": "pkg:pypi/requests@2.32.0", "name": "requests"}]
    img = [
        syft_scan.normalise({"name": "Requests", "version": "2.32.0",
                             "purl": "pkg:pypi/Requests@2.32.0"}, "image"),
        syft_scan.normalise({"name": "requests", "version": "2.32.0",
                             "purl": "pkg:npm/requests@2.32.0"}, "image"),
    ]
    merged = syft_scan.merge(ours, [], img)
    purls = [c["purl"] for c in merged]
    assert purls == ["pkg:pypi/requests@2.32.0", "pkg:npm/requests@2.32.0"]


# --------------------------------------------------------------------------
# section 8.3 for SBOMs from elsewhere
# --------------------------------------------------------------------------

def test_section_without_a_record_says_so():
    text = known_unknowns_section(coverage.from_bom({"metadata": {}}))
    assert "no machine-readable coverage record" in text
    assert "not evidence that coverage is complete" in text


def test_section_with_an_empty_record_says_none():
    bom = {"metadata": {"properties": coverage.to_properties([])}}
    assert coverage.from_bom(bom) == []
    assert "None. Every ecosystem detected" in known_unknowns_section([])


def test_section_escapes_pipes():
    text = known_unknowns_section([{
        "ecosystem": "x", "status": "unresolved", "evidence": ["a"],
        "reason": "a | b", "fix": "c",
    }])
    assert "a \\| b" in text
