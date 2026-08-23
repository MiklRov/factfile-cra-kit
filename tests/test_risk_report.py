"""
Tests for risk_report.py — cross_check() is the other half of cra-kit's
"refuse to assemble from contradictory data" claim: it links risks.yaml to
annex_i.yaml in BOTH directions. This file explicitly covers both directions
(E101 = risk points at a requirement that doesn't exist; W201 = an
applicable requirement has zero risks pointing at it), every other cross_check
code (E102-E105), and a fully-consistent happy path with zero problems.
"""

from __future__ import annotations

import pytest

from risk_report import cross_check


# --------------------------------------------------------------------------
# helpers — minimal risks.yaml / annex_i.yaml shaped dicts
# --------------------------------------------------------------------------

def matrix_doc(req_ids: list[str], applicable_ids: list[str] | None = None) -> dict:
    applicable_ids = applicable_ids if applicable_ids is not None else req_ids
    return {
        "part_i": [
            {
                "id": rid,
                "title": f"Requirement {rid}",
                "applicability": "applicable" if rid in applicable_ids else "not_applicable",
            }
            for rid in req_ids
        ],
        "part_ii": [],
    }


def base_risk(**overrides) -> dict:
    risk = {
        "id": "R-01",
        "title": "Something bad",
        "annex_i": ["EI-01"],
        "likelihood": 3,
        "impact": 3,
        "residual_likelihood": 3,
        "residual_impact": 3,
        "treatment": "accept",
        "treatment_note": "acceptable given compensating controls elsewhere",
    }
    risk.update(overrides)
    return risk


def risks_doc(*risks: dict) -> dict:
    return {"risks": list(risks)}


def error_codes(problems: list[str]) -> set[str]:
    return {p.split()[0] for p in problems}


# --------------------------------------------------------------------------
# happy path
# --------------------------------------------------------------------------

def test_happy_path_zero_problems():
    matrix = matrix_doc(["EI-01"])
    risks = risks_doc(base_risk())
    assert cross_check(risks, matrix) == []


# --------------------------------------------------------------------------
# E101 — risk references a nonexistent requirement (direction 1)
# --------------------------------------------------------------------------

def test_e101_risk_points_at_nonexistent_requirement():
    matrix = matrix_doc(["EI-01"])
    risks = risks_doc(base_risk(annex_i=["EI-99-DOES-NOT-EXIST"]))
    problems = cross_check(risks, matrix)
    assert "E101" in error_codes(problems)
    assert any("EI-99-DOES-NOT-EXIST" in p for p in problems)


# --------------------------------------------------------------------------
# W201 — an applicable requirement has zero risks covering it (direction 2)
# --------------------------------------------------------------------------

def test_w201_applicable_requirement_with_no_risk():
    matrix = matrix_doc(["EI-01", "EI-02"], applicable_ids=["EI-01", "EI-02"])
    risks = risks_doc(base_risk(annex_i=["EI-01"]))  # EI-02 is never referenced
    problems = cross_check(risks, matrix)
    assert "W201" in error_codes(problems)
    assert any("EI-02" in p for p in problems)
    assert not any("EI-01" in p and "W201" in p for p in problems)


def test_w201_not_triggered_for_not_applicable_requirement():
    # EI-02 is not_applicable, so its lack of risk coverage is not a gap
    matrix = matrix_doc(["EI-01", "EI-02"], applicable_ids=["EI-01"])
    risks = risks_doc(base_risk(annex_i=["EI-01"]))
    problems = cross_check(risks, matrix)
    assert "W201" not in error_codes(problems)


def test_both_directions_together_in_one_document():
    """The two halves of the bidirectional check are independent: a risk
    pointing at a bogus id (E101) and a separate uncovered applicable
    requirement (W201) must BOTH be reported from the same cross_check call,
    proving neither direction masks the other."""
    matrix = matrix_doc(["EI-01", "EI-02"], applicable_ids=["EI-01", "EI-02"])
    risks = risks_doc(base_risk(id="R-01", annex_i=["EI-97-GHOST"]))
    problems = cross_check(risks, matrix)
    codes = error_codes(problems)
    assert "E101" in codes  # R-01 -> EI-97-GHOST doesn't exist
    assert "W201" in codes  # EI-01 AND EI-02 both uncovered
    assert sum(1 for p in problems if p.startswith("W201")) == 2


# --------------------------------------------------------------------------
# E102 — risk not mapped to any requirement
# --------------------------------------------------------------------------

def test_e102_risk_with_no_annex_i_mapping():
    matrix = matrix_doc(["EI-01"])
    risks = risks_doc(base_risk(annex_i=[]))
    problems = cross_check(risks, matrix)
    assert "E102" in error_codes(problems)


# --------------------------------------------------------------------------
# E103 — rating fields outside 1..5, or unknown treatment
# --------------------------------------------------------------------------

@pytest.mark.parametrize("field", ["likelihood", "impact", "residual_likelihood", "residual_impact"])
def test_e103_rating_out_of_range(field):
    matrix = matrix_doc(["EI-01"])
    risks = risks_doc(base_risk(**{field: 6}))
    problems = cross_check(risks, matrix)
    assert "E103" in error_codes(problems)

def test_e103_string_rating_does_not_crash_the_comparison():
    # Regression test: a non-int rating value used to reach the
    # residual-vs-inherent arithmetic (`likelihood * impact`) unguarded,
    # which either raised TypeError (string * string) or silently produced
    # a repeated-string garbage value (string * int) instead of failing
    # cleanly with E103. cross_check must now report E103 and simply skip
    # the E104 comparison for this risk, not crash and not fabricate a result.
    matrix = matrix_doc(["EI-01"])
    risks = risks_doc(base_risk(likelihood="high"))
    problems = cross_check(risks, matrix)  # must not raise
    assert "E103" in error_codes(problems)
    assert "E104" not in error_codes(problems)


def test_e103_unknown_treatment():
    matrix = matrix_doc(["EI-01"])
    risks = risks_doc(base_risk(treatment="ignore_it"))
    problems = cross_check(risks, matrix)
    assert "E103" in error_codes(problems)
    assert any("unknown treatment" in p for p in problems)


# --------------------------------------------------------------------------
# E104 — residual rating lower than inherent, but no control stated
# --------------------------------------------------------------------------

def test_e104_residual_lower_without_controls():
    matrix = matrix_doc(["EI-01"])
    risks = risks_doc(base_risk(
        likelihood=4, impact=4, residual_likelihood=2, residual_impact=2,
        existing_controls=[],
    ))
    problems = cross_check(risks, matrix)
    assert "E104" in error_codes(problems)


def test_e104_not_triggered_with_controls_stated():
    matrix = matrix_doc(["EI-01"])
    risks = risks_doc(base_risk(
        likelihood=4, impact=4, residual_likelihood=2, residual_impact=2,
        existing_controls=["rate limiting on the login endpoint"],
    ))
    problems = cross_check(risks, matrix)
    assert "E104" not in error_codes(problems)


def test_e104_not_triggered_when_residual_equals_inherent():
    matrix = matrix_doc(["EI-01"])
    risks = risks_doc(base_risk(
        likelihood=3, impact=3, residual_likelihood=3, residual_impact=3,
        existing_controls=[],
    ))
    problems = cross_check(risks, matrix)
    assert "E104" not in error_codes(problems)


# --------------------------------------------------------------------------
# E105 — risk accepted without a rationale
# --------------------------------------------------------------------------

def test_e105_accepted_without_note():
    matrix = matrix_doc(["EI-01"])
    risks = risks_doc(base_risk(treatment="accept", treatment_note=""))
    problems = cross_check(risks, matrix)
    assert "E105" in error_codes(problems)


def test_e105_not_triggered_with_note():
    matrix = matrix_doc(["EI-01"])
    risks = risks_doc(base_risk(treatment="accept", treatment_note="documented business reason"))
    problems = cross_check(risks, matrix)
    assert "E105" not in error_codes(problems)


def test_e105_not_triggered_for_non_accept_treatment():
    matrix = matrix_doc(["EI-01"])
    risks = risks_doc(base_risk(treatment="mitigate", treatment_note=""))
    problems = cross_check(risks, matrix)
    assert "E105" not in error_codes(problems)
