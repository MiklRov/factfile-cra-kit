"""
Tests for build.py — Priority 4, end to end.

Two things matter most here:
  1. A fully consistent, minimal fixture set produces a technical_file.md
     with every Annex VII section header present.
  2. Self-contradictory input (a risk pointing at a requirement id that
     doesn't exist) makes build.py's own integrity gate refuse to write
     ANY output and return a non-zero exit code. This is the literal
     headline claim on the kit's own README: "the tool refuses to
     assemble a document from inconsistent data."

Both fixture sets live under tests/fixtures/build_happy/ and
tests/fixtures/build_contradictory/ — small, hand-built, not a full
worked example.
"""

from __future__ import annotations

from pathlib import Path

from conftest import FIXTURES_DIR

from factfile_cra_kit.build import build, ANNEX_VII_TITLES

HAPPY_DIR = FIXTURES_DIR / "build_happy"
CONTRADICTORY_DIR = FIXTURES_DIR / "build_contradictory"


def test_happy_path_produces_technical_file_with_all_sections(tmp_path):
    out_dir = tmp_path / "out"
    rc = build(
        cfg_dir=HAPPY_DIR,
        sbom_path=HAPPY_DIR / "sbom.cdx.json",
        out_dir=out_dir,
        pdf=False,
    )
    assert rc == 0

    tech_md = out_dir / "technical_file.md"
    doc_md = out_dir / "declaration_of_conformity.md"
    assert tech_md.is_file()
    assert doc_md.is_file()

    text = tech_md.read_text(encoding="utf-8")
    # every one of the eight Annex VII section titles must appear as a
    # top-level heading somewhere in the assembled document
    for num, title in ANNEX_VII_TITLES.items():
        assert f"# {num}. {title}" in text, f"missing section {num} ({title!r})"

    decl_text = doc_md.read_text(encoding="utf-8")
    assert "EU Declaration of Conformity" in decl_text


def test_contradictory_input_refuses_to_build(tmp_path, capsys):
    out_dir = tmp_path / "out"
    rc = build(
        cfg_dir=CONTRADICTORY_DIR,
        sbom_path=CONTRADICTORY_DIR / "sbom.cdx.json",
        out_dir=out_dir,
        pdf=False,
    )
    out = capsys.readouterr().out

    assert rc != 0
    assert "E101" in out
    assert "Build stopped" in out

    # the integrity gate must refuse BEFORE writing anything, not produce a
    # partial or contradictory document
    assert not out_dir.exists() or not any(out_dir.iterdir())
    assert not (out_dir / "technical_file.md").exists()
    assert not (out_dir / "declaration_of_conformity.md").exists()


def test_contradictory_risks_file_alone_is_caught_by_cross_check():
    """Sanity check that the fixture actually is contradictory (isolates a
    fixture-authoring mistake from a build.py regression)."""
    import yaml
    from factfile_cra_kit.risk_report import cross_check

    risks = yaml.safe_load((CONTRADICTORY_DIR / "risks.yaml").read_text(encoding="utf-8"))
    matrix = yaml.safe_load((CONTRADICTORY_DIR / "annex_i.yaml").read_text(encoding="utf-8"))
    problems = cross_check(risks, matrix)
    assert any(p.startswith("E101") for p in problems)
