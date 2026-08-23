"""
Tests for validate.py — the integrity check for the Annex I requirements
matrix. This is Priority 1: the product's differentiator ("we refuse to
close a requirement with no evidence") lives entirely in
`check_requirement()`, so every error/warning code gets a fixture that
triggers exactly it, plus a happy-path fixture that triggers none.

Also covers the newest, least-tested logic: customer_attestation handling
(missing provenance -> E006, unknown verification -> E004,
verification="contradicted" -> E007 hard fail, verification="unverified"
-> W104 warning-only), and external_lookup handling — the tool's own
external fact-gathering held to the same discipline (missing provenance ->
E008, unknown source_reliability -> E004, verification="contradicted" ->
E009 hard fail, source_reliability="scrape" with verification not
"corroborated" -> W105 warning-only).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest
import yaml

import validate
from validate import Finding, check_requirement


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def base_req(**overrides) -> dict:
    """A minimal requirement that on its own trips zero findings."""
    req = {
        "id": "EI-01",
        "status": "met",
        "applicability": "applicable",
        "owner": "Alice",
        "rationale": "",
        "evidence": [{"type": "test_report", "ref": "tests/foo.py::test_bar"}],
    }
    req.update(overrides)
    return req


_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(text: str) -> str:
    return _ANSI.sub("", text)


def codes(findings: list[Finding]) -> list[str]:
    return [f.code for f in findings]


def check(req: dict, seen: set[str] | None = None) -> list[Finding]:
    return check_requirement(req, seen if seen is not None else set())


def run_main(monkeypatch, capsys, tmp_path: Path, matrix: dict, extra_args=None):
    """Write `matrix` to a temp YAML file and invoke validate.main() against
    it, the same way the CLI does. Returns (returncode, stdout)."""
    p = tmp_path / "annex_i.yaml"
    p.write_text(yaml.dump(matrix), encoding="utf-8")
    argv = ["validate.py", str(p)] + (extra_args or [])
    monkeypatch.setattr(sys, "argv", argv)
    rc = validate.main()
    out = capsys.readouterr().out
    return rc, out


def minimal_matrix(reqs: list[dict], *, product="X", assessor="Y") -> dict:
    return {
        "meta": {"product": product, "assessor": assessor},
        "part_i": reqs,
        "part_ii": [],
    }


# --------------------------------------------------------------------------
# happy path — the equally-important other half of the contract
# --------------------------------------------------------------------------

def test_happy_path_zero_findings():
    req = base_req()
    findings = check(req)
    assert findings == []


def test_happy_path_full_matrix_main_zero_errors_and_warnings(monkeypatch, capsys, tmp_path):
    matrix = minimal_matrix([
        base_req(id="EI-01"),
        base_req(id="EI-02", status="not_applicable", applicability="not_applicable",
                  rationale="does not apply to this deployment model", evidence=[]),
    ])
    rc, out = run_main(monkeypatch, capsys, tmp_path, matrix)
    out = strip_ansi(out)
    assert rc == 0
    m = re.search(r"Errors:\s+(\d+)", out)
    assert m and m.group(1) == "0"
    m = re.search(r"Warnings:\s+(\d+)", out)
    assert m and m.group(1) == "0"
    assert "All requirements are closed and backed by evidence." in out


# --------------------------------------------------------------------------
# E001 — status met, no evidence
# --------------------------------------------------------------------------

def test_e001_met_without_evidence():
    req = base_req(evidence=[])
    found = check(req)
    assert codes(found) == ["E001"]


def test_e001_not_triggered_when_evidence_present():
    req = base_req()
    assert "E001" not in codes(check(req))


# --------------------------------------------------------------------------
# E002 — not_applicable without rationale
# --------------------------------------------------------------------------

def test_e002_not_applicable_without_rationale():
    req = base_req(
        status="not_applicable", applicability="not_applicable",
        rationale="", evidence=[],
    )
    assert codes(check(req)) == ["E002"]


def test_e002_not_triggered_with_rationale():
    req = base_req(
        status="not_applicable", applicability="not_applicable",
        rationale="hardware feature not present in this product", evidence=[],
    )
    assert "E002" not in codes(check(req))


# --------------------------------------------------------------------------
# E003 — applicability/status contradiction, both directions
# --------------------------------------------------------------------------

def test_e003_applicable_but_status_not_applicable():
    req = base_req(applicability="applicable", status="not_applicable", evidence=[])
    assert codes(check(req)) == ["E003"]


def test_e003_not_applicable_but_status_in_progress():
    req = base_req(
        applicability="not_applicable", status="in_progress",
        rationale="justified", evidence=[],
    )
    assert codes(check(req)) == ["E003"]


def test_e003_not_triggered_when_consistent():
    req = base_req(applicability="applicable", status="met")
    assert "E003" not in codes(check(req))


# --------------------------------------------------------------------------
# E004 — unknown status / applicability / evidence shape / verification
# --------------------------------------------------------------------------

def test_e004_unknown_status():
    req = base_req(status="halfway_there")
    assert codes(check(req)) == ["E004"]


def test_e004_unknown_applicability():
    req = base_req(applicability="sometimes")
    assert codes(check(req)) == ["E004"]


def test_e004_evidence_not_an_object():
    req = base_req(evidence=["just a string"])
    found = check(req)
    assert codes(found) == ["E004"]
    assert "not an object" in found[0].message


def test_e004_evidence_empty_ref():
    req = base_req(evidence=[{"type": "test_report", "ref": ""}])
    found = check(req)
    assert codes(found) == ["E004"]
    assert "empty ref" in found[0].message


def test_e004_evidence_unknown_type():
    req = base_req(evidence=[{"type": "vibes", "ref": "somewhere"}])
    found = check(req)
    assert codes(found) == ["E004"]
    assert "unknown type" in found[0].message


def test_e004_attestation_unknown_verification():
    req = base_req(evidence=[{
        "type": "customer_attestation", "ref": "thread-1",
        "attested_by": "Bob", "attested_at": "2026-08-01", "thread": "t-1",
        "verification": "probably_fine",
    }])
    found = check(req)
    assert codes(found) == ["E004"]
    assert "unknown verification status" in found[0].message


# --------------------------------------------------------------------------
# E005 — duplicate identifier
# --------------------------------------------------------------------------

def test_e005_duplicate_identifier():
    seen: set[str] = set()
    first = check(base_req(id="EI-09"), seen)
    second = check(base_req(id="EI-09"), seen)
    assert "E005" not in codes(first)
    assert codes(second) == ["E005"]


# --------------------------------------------------------------------------
# customer_attestation: E006 / E007 / W104 — the newest, least-tested logic
# --------------------------------------------------------------------------

def test_e006_attestation_missing_all_provenance():
    req = base_req(evidence=[{"type": "customer_attestation", "ref": "thread-1"}])
    found = check(req)
    # missing provenance fires E006; verification defaults to "unverified" -> W104 too
    assert "E006" in codes(found)
    e006 = next(f for f in found if f.code == "E006")
    assert "attested_by" in e006.message
    assert "attested_at" in e006.message
    assert "thread" in e006.message


def test_e006_attestation_missing_one_provenance_field():
    req = base_req(evidence=[{
        "type": "customer_attestation", "ref": "thread-1",
        "attested_by": "Bob", "attested_at": "2026-08-01",
        # "thread" missing
        "verification": "corroborated",
    }])
    found = check(req)
    assert "E006" in codes(found)
    e006 = next(f for f in found if f.code == "E006")
    assert "thread" in e006.message
    assert "attested_by" not in e006.message
    assert "attested_at" not in e006.message


def test_e006_not_triggered_with_full_provenance():
    req = base_req(evidence=[{
        "type": "customer_attestation", "ref": "thread-1",
        "attested_by": "Bob", "attested_at": "2026-08-01", "thread": "t-1",
        "verification": "corroborated",
    }])
    assert "E006" not in codes(check(req))


def test_e007_contradicted_attestation_is_hard_fail_code():
    req = base_req(evidence=[{
        "type": "customer_attestation", "ref": "thread-1",
        "attested_by": "Bob", "attested_at": "2026-08-01", "thread": "t-1",
        "verification": "contradicted",
    }])
    found = check(req)
    assert codes(found) == ["E007"]
    assert found[0].is_error


def test_w104_unverified_attestation_is_warning_not_fail():
    req = base_req(evidence=[{
        "type": "customer_attestation", "ref": "thread-1",
        "attested_by": "Bob", "attested_at": "2026-08-01", "thread": "t-1",
        "verification": "unverified",
    }])
    found = check(req)
    assert codes(found) == ["W104"]
    assert not found[0].is_error


def test_w104_unverified_is_default_when_verification_omitted():
    req = base_req(evidence=[{
        "type": "customer_attestation", "ref": "thread-1",
        "attested_by": "Bob", "attested_at": "2026-08-01", "thread": "t-1",
    }])
    assert codes(check(req)) == ["W104"]


def test_e007_fails_the_build_w104_does_not(monkeypatch, capsys, tmp_path):
    contradicted = base_req(id="EI-01", evidence=[{
        "type": "customer_attestation", "ref": "thread-1",
        "attested_by": "Bob", "attested_at": "2026-08-01", "thread": "t-1",
        "verification": "contradicted",
    }])
    rc, out = run_main(monkeypatch, capsys, tmp_path, minimal_matrix([contradicted]))
    assert rc == 1
    assert "E007" in out

    unverified = base_req(id="EI-01", evidence=[{
        "type": "customer_attestation", "ref": "thread-1",
        "attested_by": "Bob", "attested_at": "2026-08-01", "thread": "t-1",
        "verification": "unverified",
    }])
    rc, out = run_main(monkeypatch, capsys, tmp_path, minimal_matrix([unverified]))
    assert rc == 0
    assert "W104" in out


# --------------------------------------------------------------------------
# external_lookup: E008 / E004 / E009 / W105 — the tool's own external
# fact-gathering, held to the same provenance discipline as
# customer_attestation (see the motivating incident: two consecutive Google
# Play scrapes, one a mismatched app, one months-stale, neither caught by
# the tooling — a human caught both by comparing against a screenshot).
# --------------------------------------------------------------------------

def test_external_lookup_happy_path_official_api_corroborated():
    req = base_req(evidence=[{
        "type": "external_lookup", "ref": "itunes-lookup-1",
        "source": "itunes.apple.com/lookup", "source_reliability": "official_api",
        "retrieved_at": "2026-08-20", "verification": "corroborated",
    }])
    assert check(req) == []


def test_e008_external_lookup_missing_all_provenance():
    req = base_req(evidence=[{"type": "external_lookup", "ref": "lookup-1"}])
    found = check(req)
    assert "E008" in codes(found)
    e008 = next(f for f in found if f.code == "E008")
    assert "source" in e008.message
    assert "source_reliability" in e008.message
    assert "retrieved_at" in e008.message


def test_e008_external_lookup_missing_source_only():
    req = base_req(evidence=[{
        "type": "external_lookup", "ref": "lookup-1",
        "source_reliability": "official_api", "retrieved_at": "2026-08-20",
        "verification": "corroborated",
    }])
    found = check(req)
    assert codes(found) == ["E008"]
    assert "source" in found[0].message
    assert "source_reliability" not in found[0].message
    assert "retrieved_at" not in found[0].message


def test_e008_external_lookup_missing_source_reliability_only():
    req = base_req(evidence=[{
        "type": "external_lookup", "ref": "lookup-1",
        "source": "example.com/privacy", "retrieved_at": "2026-08-20",
        "verification": "corroborated",
    }])
    found = check(req)
    assert codes(found) == ["E008"]
    assert "source_reliability" in found[0].message


def test_e008_external_lookup_missing_retrieved_at_only():
    req = base_req(evidence=[{
        "type": "external_lookup", "ref": "lookup-1",
        "source": "example.com/privacy", "source_reliability": "direct_fetch",
        "verification": "corroborated",
    }])
    found = check(req)
    assert codes(found) == ["E008"]
    assert "retrieved_at" in found[0].message


def test_e004_external_lookup_unknown_source_reliability():
    req = base_req(evidence=[{
        "type": "external_lookup", "ref": "lookup-1",
        "source": "Google Play store listing (fetched)", "source_reliability": "vibes",
        "retrieved_at": "2026-08-20", "verification": "unverified",
    }])
    found = check(req)
    assert "E004" in codes(found)
    e004 = next(f for f in found if f.code == "E004")
    assert "source_reliability" in e004.message


def test_w105_scrape_unverified_warns():
    req = base_req(evidence=[{
        "type": "external_lookup", "ref": "lookup-1",
        "source": "Google Play store listing (fetched)", "source_reliability": "scrape",
        "retrieved_at": "2026-08-20", "verification": "unverified",
    }])
    found = check(req)
    assert codes(found) == ["W105"]
    assert not found[0].is_error


def test_w105_not_triggered_when_scrape_is_corroborated():
    req = base_req(evidence=[{
        "type": "external_lookup", "ref": "lookup-1",
        "source": "Google Play store listing (fetched)", "source_reliability": "scrape",
        "retrieved_at": "2026-08-20", "verification": "corroborated",
    }])
    assert "W105" not in codes(check(req))


def test_w105_not_triggered_for_official_api_unverified():
    # the warning is specific to the scrape tier, not "any unverified lookup"
    req = base_req(evidence=[{
        "type": "external_lookup", "ref": "lookup-1",
        "source": "itunes.apple.com/lookup", "source_reliability": "official_api",
        "retrieved_at": "2026-08-20", "verification": "unverified",
    }])
    assert "W105" not in codes(check(req))


def test_e009_contradicted_external_lookup_is_hard_fail_code():
    req = base_req(evidence=[{
        "type": "external_lookup", "ref": "lookup-1",
        "source": "itunes.apple.com/lookup", "source_reliability": "official_api",
        "retrieved_at": "2026-08-20", "verification": "contradicted",
    }])
    found = check(req)
    assert codes(found) == ["E009"]
    assert found[0].is_error


def test_e009_fails_the_build_w105_does_not(monkeypatch, capsys, tmp_path):
    contradicted = base_req(id="EI-01", evidence=[{
        "type": "external_lookup", "ref": "lookup-1",
        "source": "play.google.com listing (fetched)", "source_reliability": "scrape",
        "retrieved_at": "2026-08-20", "verification": "contradicted",
    }])
    rc, out = run_main(monkeypatch, capsys, tmp_path, minimal_matrix([contradicted]))
    assert rc == 1
    assert "E009" in out

    scraped_unverified = base_req(id="EI-01", evidence=[{
        "type": "external_lookup", "ref": "lookup-1",
        "source": "play.google.com listing (fetched)", "source_reliability": "scrape",
        "retrieved_at": "2026-08-20", "verification": "unverified",
    }])
    rc, out = run_main(monkeypatch, capsys, tmp_path, minimal_matrix([scraped_unverified]))
    assert rc == 0
    assert "W105" in out


# --------------------------------------------------------------------------
# W101 — not started
# --------------------------------------------------------------------------

def test_w101_not_started():
    req = base_req(status="not_started", evidence=[])
    assert codes(check(req)) == ["W101"]


# --------------------------------------------------------------------------
# W102 — no owner (per-requirement, and at meta level for the assessor)
# --------------------------------------------------------------------------

def test_w102_no_owner():
    req = base_req(owner=None)
    assert codes(check(req)) == ["W102"]


def test_w102_meta_assessor_missing(monkeypatch, capsys, tmp_path):
    matrix = minimal_matrix([base_req()], assessor=None)
    rc, out = run_main(monkeypatch, capsys, tmp_path, matrix)
    assert "W102" in out
    assert "assessor is not set" in out


# --------------------------------------------------------------------------
# W103 — evidence exists but status is not yet met
# --------------------------------------------------------------------------

def test_w103_evidence_but_in_progress():
    req = base_req(status="in_progress")
    assert codes(check(req)) == ["W103"]


def test_w103_evidence_but_not_started():
    req = base_req(status="not_started")
    found = check(req)
    assert set(codes(found)) == {"W101", "W103"}


# --------------------------------------------------------------------------
# E006 at meta level — product metadata incomplete
# --------------------------------------------------------------------------

def test_e006_meta_product_missing(monkeypatch, capsys, tmp_path):
    matrix = minimal_matrix([base_req()], product=None)
    rc, out = run_main(monkeypatch, capsys, tmp_path, matrix)
    assert rc == 1
    assert "E006" in out
    assert "product is not set" in out


# --------------------------------------------------------------------------
# --strict promotes warnings to a failing build
# --------------------------------------------------------------------------

def test_strict_mode_fails_on_warnings_only(monkeypatch, capsys, tmp_path):
    matrix = minimal_matrix([base_req(status="not_started", evidence=[])])
    rc, _ = run_main(monkeypatch, capsys, tmp_path, matrix)
    assert rc == 0  # warnings alone don't fail a normal run
    rc, out = run_main(monkeypatch, capsys, tmp_path, matrix, extra_args=["--strict"])
    assert rc == 1
    assert "Strict mode" in out
