#!/usr/bin/env python3
"""
Build the Annex VII technical file and the Annex V declaration of conformity
for Regulation (EU) 2024/2847.

Input is four files, each with its own area of responsibility:
  product.yaml     sections 1, 2, 4, 5, 6 and the declaration data
  annex_i.yaml     the essential requirements matrix
  risks.yaml       the risk assessment, section 3
  sbom.cdx.json    section 8

A fifth file is optional:
  reporting.yaml   Article 14 reporting runbook, appendix A — not an Annex VII
                   section, so its absence only warns, never blocks the build.

The build refuses to run if the integrity checks fail. A document assembled
from inconsistent data is worse than no document at all.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

import yaml

import sbom_coverage as coverage
from risk_report import cross_check, render as render_risks
from reporting_report import check_readiness, render as render_reporting

RESET, RED, YEL, GRN, DIM = "\033[0m", "\033[31m", "\033[33m", "\033[32m", "\033[2m"

ANNEX_VII_TITLES = {
    1: "General description of the product",
    2: "Design, development and production",
    3: "Cybersecurity risk assessment",
    4: "Support period",
    5: "Applied standards and specifications",
    6: "Test reports",
    7: "EU Declaration of Conformity",
    8: "Software bill of materials",
}
# Appendix A (Article 14 reporting runbook) is supplementary material, not
# enumerated by Annex VII. Its title lives in reporting_report.APPENDIX_TITLE,
# deliberately kept out of this dict so nothing here is ever mistaken for one
# of the eight required sections, and their numbering never shifts.


def load_yaml(p: Path) -> dict:
    return yaml.safe_load(p.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------
# section renderers
# --------------------------------------------------------------------------

def s1(d: dict) -> str:
    s = d["section_1"]
    o = [f"# 1. {ANNEX_VII_TITLES[1]}\n"]
    o.append(f"**Product:** {s['product_name']}  ")
    o.append(f"**Version:** {s['product_version']}  ")
    o.append(f"**Type:** {s['product_type']}  ")
    o.append(f"**Licence:** {s['license']}\n")
    o.append("## 1.1 Intended purpose\n")
    o.append(s["intended_purpose"].strip() + "\n")
    o.append("## 1.2 Intended users\n")
    o.append(s["intended_users"].strip() + "\n")
    o.append("## 1.3 Reasonably foreseeable misuse\n")
    o.append(s["reasonably_foreseeable_misuse"].strip() + "\n")
    o.append("## 1.4 Note on scope\n")
    o.append(s["scope_note"].strip() + "\n")
    o.append("## 1.5 Versions affecting conformity\n")
    o.append(s["versions_affecting_compliance"].strip() + "\n")
    o.append("## 1.6 Information to the user (Annex II)\n")
    o.append("| Item | Value |")
    o.append("|---|---|")
    labels = {
        "manufacturer_contact": "Manufacturer contact",
        "single_point_of_contact": "Single point of contact",
        "product_identification": "Product identification",
        "intended_purpose_short": "Intended purpose",
        "known_limitations": "Known limitations",
        "support_period_end": "End of support period",
        "security_update_information": "Security update information",
        "vulnerability_reporting": "Vulnerability reporting",
        "secure_configuration_guidance": "Secure configuration guidance",
    }
    for k, label in labels.items():
        v = " ".join(str(s["annex_ii_user_information"].get(k, "")).split())
        o.append(f"| {label} | {v} |")
    o.append("")
    return "\n".join(o)


def s2(d: dict) -> str:
    s = d["section_2"]
    o = [f"# 2. {ANNEX_VII_TITLES[2]}\n"]
    o.append("## 2.1 Architecture\n")
    o.append(s["architecture"].strip() + "\n")
    o.append("## 2.2 Component integration\n")
    o.append(s["component_integration"].strip() + "\n")
    o.append("## 2.3 Security-relevant subsystems\n")
    o.append("| Subsystem | Location | Description |")
    o.append("|---|---|---|")
    for x in s["security_relevant_subsystems"]:
        note = " ".join(x["note"].split())
        o.append(f"| {x['name']} | `{x['ref']}` | {note} |")
    o.append("")
    o.append("## 2.4 Production and monitoring\n")
    o.append(s["production_and_monitoring"].strip() + "\n")
    o.append("## 2.5 Vulnerability handling processes (Annex I, Part II)\n")
    o.append("| Process | Status | Note |")
    o.append("|---|---|---|")
    proc_labels = {
        "sbom": "SBOM",
        "coordinated_disclosure_policy": "Coordinated vulnerability disclosure policy",
        "reporting_channel": "Vulnerability reporting channel",
        "security_advisories": "Publication of security advisories",
        "update_distribution": "Update distribution",
    }
    for k, label in proc_labels.items():
        v = s["vulnerability_handling_processes"].get(k, {})
        note = " ".join(str(v.get("note", "")).split())
        o.append(f"| {label} | {v.get('status','—')} | {note} |")
    o.append("")
    return "\n".join(o)


def s4(d: dict) -> str:
    s = d["section_4"]
    o = [f"# 4. {ANNEX_VII_TITLES[4]}\n"]
    o.append(f"**Support period:** {s['support_period_years']} years  ")
    o.append(f"**End date:** {s['end_date']}  ")
    o.append(
        f"**Availability of issued updates:** no less than "
        f"{s['security_update_availability_years']} years\n"
    )
    o.append("## 4.1 Rationale\n")
    o.append(s["rationale"].strip() + "\n")
    o.append("## 4.2 Factors considered (Article 13(8))\n")
    o.append("| Factor | Assessment |")
    o.append("|---|---|")
    for f in s["factors_considered"]:
        o.append(f"| {f['factor']} | {' '.join(f['assessment'].split())} |")
    o.append("")
    o.append("## 4.3 End-of-support notification\n")
    o.append(s["end_of_support_notification"].strip() + "\n")
    return "\n".join(o)


def s5(d: dict) -> str:
    s = d["section_5"]
    o = [f"# 5. {ANNEX_VII_TITLES[5]}\n"]
    o.append("## 5.1 Harmonised standards\n")
    if s["harmonised_standards_applied"]:
        for x in s["harmonised_standards_applied"]:
            o.append(f"- {x}")
    else:
        o.append("None applied.\n")
    o.append("\n" + s["harmonised_standards_note"].strip() + "\n")
    o.append("## 5.2 Other means applied\n")
    o.append("| Means | Role |")
    o.append("|---|---|")
    for x in s["other_means_used"]:
        o.append(f"| {x['name']} | {' '.join(x['note'].split())} |")
    o.append("")
    return "\n".join(o)


def s6(d: dict) -> str:
    s = d["section_6"]
    o = [f"# 6. {ANNEX_VII_TITLES[6]}\n"]
    o.append(s["summary"].strip() + "\n")
    o.append("## 6.1 Automated tests\n")
    o.append("| Suite | Files | Note |")
    o.append("|---|---|---|")
    for t in s["automated_tests"]:
        o.append(f"| {t['suite']} | {t['files']} | {t['note']} |")
    o.append("")
    o.append("## 6.2 Tests mapped to essential requirements\n")
    o.append(s["security_relevant_tests"]["note"].strip() + "\n")
    o.append("| Test suite | Requirements |")
    o.append("|---|---|")
    for t in s["security_relevant_tests"]["items"]:
        o.append(f"| {t['name']} | {', '.join(t['covers'])} |")
    o.append("")
    o.append("## 6.3 Static analysis\n")
    o.append("| Tool | Configuration | Note |")
    o.append("|---|---|---|")
    for t in s["static_analysis"]:
        lvl = f" (level {t['level']})" if "level" in t else ""
        o.append(f"| {t['tool']}{lvl} | `{t['config']}` | {t.get('note','')} |")
    o.append("")
    o.append("## 6.4 Evidence gaps\n")
    for g in s["gaps"]:
        o.append(f"- {g}")
    o.append("")
    return "\n".join(o)


def s8(sbom: dict) -> str:
    comps = sbom["components"]
    by_eco: dict[str, int] = {}
    direct = 0
    lic: dict[str, int] = {}
    for c in comps:
        props = {p["name"]: p["value"] for p in c.get("properties", [])}
        eco = props.get("cra:ecosystem", "?")
        by_eco[eco] = by_eco.get(eco, 0) + 1
        if props.get("cra:direct") == "true":
            direct += 1
        for l in c.get("licenses", []):
            name = l.get("license", {}).get("id") or l.get("expression") or "?"
            lic[name] = lic.get(name, 0) + 1

    o = [f"# 8. {ANNEX_VII_TITLES[8]}\n"]
    o.append(
        "Requirement: Annex I, Part II, point 1 — a software bill of materials in "
        "a commonly used machine-readable format covering at the very least "
        "the top-level dependencies of the product.\n"
    )
    o.append(f"**Format:** CycloneDX {sbom['specVersion']}  ")
    o.append(f"**Serial number:** `{sbom.get('serialNumber', '—')}`  ")
    o.append(f"**Generated:** {sbom['metadata']['timestamp']}  ")
    o.append(f"**File:** `sbom.cdx.json`\n")
    o.append("## 8.1 Composition\n")
    o.append(f"- Total components: **{len(comps)}**")
    for eco, n in sorted(by_eco.items()):
        o.append(f"  - {eco}: {n}")
    o.append(f"- Direct dependencies: **{direct}**")
    o.append(f"- Without a stated licence: **{sum(1 for c in comps if not c.get('licenses'))}**")
    o.append("")
    unknowns = coverage.from_bom(sbom)
    if unknowns:
        o.append(
            "Coverage is incomplete: the ecosystems listed in 8.3 were found in "
            "the source but are missing from this SBOM, or present only in "
            "part. Build-time dependencies that are not shipped with the "
            "product are excluded.\n"
        )
    else:
        o.append(
            "Coverage exceeds the statutory minimum: the full dependency tree of the "
            "shipped product is included, not only the top level. Build-time "
            "dependencies that are not shipped with the product are excluded.\n"
        )
    o.append("## 8.2 Licence distribution\n")
    o.append("| Licence | Components |")
    o.append("|---|---|")
    for name, n in sorted(lic.items(), key=lambda kv: -kv[1])[:12]:
        o.append(f"| {name} | {n} |")
    o.append("")
    o.append(known_unknowns_section(unknowns))
    o.append(
        "> The SBOM is not subject to mandatory publication. It is retained as "
        "part of the technical documentation and made available to the market "
        "surveillance authority upon reasoned request.\n"
    )
    return "\n".join(o)


def _cell(v) -> str:
    return " ".join(str(v).split()).replace("|", "\\|")


def known_unknowns_section(unknowns: list[dict] | None) -> str:
    """8.3 — what the SBOM does not cover, stated rather than left for the
    reader to discover. `unknowns` is None when the SBOM carries no coverage
    record at all (produced by another tool, or by an older cra-kit)."""
    o = ["## 8.3 Known unknowns\n"]
    if unknowns is None:
        o.append(
            "This SBOM carries no machine-readable coverage record: it was not "
            "produced by `sbom_gen.py`, or by a version that predates the "
            "record. Gaps in coverage, if any, are not stated here, and the "
            "absence of this record is not evidence that coverage is "
            "complete.\n"
        )
        return "\n".join(o)
    if not unknowns:
        o.append(
            "None. Every ecosystem detected in the source was resolved into "
            "components, and none was resolved only in part.\n"
        )
        return "\n".join(o)
    o.append(
        "Detected in the source, but not resolved into components (or only "
        "in part). Each entry names what is missing, why, and what resolves "
        "it.\n"
    )
    o.append("| Ecosystem | Status | Found in | Why | How to resolve |")
    o.append("|---|---|---|---|---|")
    for e in unknowns:
        ev = e.get("evidence") or []
        where = ", ".join(f"`{x}`" for x in ev[:4])
        if len(ev) > 4:
            where += f" (+{len(ev) - 4} more)"
        why = e.get("reason", "")
        if e.get("base_images"):
            imgs = ", ".join(f"`{i}`" for i in e["base_images"])
            why += f". Built on {imgs}; the image contents are not enumerated"
        o.append(
            f"| {_cell(e.get('ecosystem', '?'))} | {_cell(e.get('status', '?'))} "
            f"| {where or '—'} | {_cell(why)} | {_cell(e.get('fix', ''))} |"
        )
    o.append("")
    return "\n".join(o)


def doc(d: dict) -> str:
    x = d["declaration"]
    o = ["# EU Declaration of Conformity\n"]
    o.append(
        "Drawn up in accordance with Annex V to Regulation (EU) 2024/2847.\n"
    )
    rows = [
        ("1. Product identification", x["product_identification"]),
        ("2. Name of the manufacturer", x["manufacturer_name"]),
        ("2. Address of the manufacturer", x["manufacturer_address"]),
        ("3. Statement of sole responsibility", x["sole_responsibility_statement"]),
        ("4. Object of the declaration", x["object_of_declaration"]),
        ("5. Statement of conformity", x["conformity_statement"]),
    ]
    o.append("| Item | Content |")
    o.append("|---|---|")
    for k, v in rows:
        o.append(f"| **{k}** | {' '.join(str(v).split())} |")
    o.append("")
    o.append("## 6. References to standards\n")
    if x["standards_referenced"]:
        for s in x["standards_referenced"]:
            o.append(f"- {s}")
    else:
        o.append("None.\n")
    o.append("\n" + x["standards_note"].strip() + "\n")
    o.append("## 7. Notified body\n")
    o.append("Not involved.\n")
    o.append("\n" + x["notified_body_note"].strip() + "\n")
    o.append(f"**Conformity assessment procedure:** {x['conformity_assessment_module']}\n")
    o.append("## 8. Signature\n")
    o.append(f"Place of issue: {x['place_of_issue']}  ")
    o.append(f"Date of issue: {x['date_of_issue']}  ")
    o.append(f"Signed for and on behalf of: {x['signatory_name']}, {x['signatory_function']}\n")
    o.append("\nSignature: ______________________\n")
    return "\n".join(o)


# --------------------------------------------------------------------------
# assembly
# --------------------------------------------------------------------------

PRODUCT_YAML_KEYS = {
    "section_1", "section_2", "section_4", "section_5", "section_6", "declaration", "meta",
}


def build(cfg_dir: Path, sbom_path: Path, out_dir: Path, pdf: bool) -> int:
    product = load_yaml(cfg_dir / "product.yaml")
    matrix = load_yaml(cfg_dir / "annex_i.yaml")
    risks = load_yaml(cfg_dir / "risks.yaml")
    sbom = json.loads(sbom_path.read_text(encoding="utf-8"))

    # A tool that refuses to build on contradictory data cannot also silently
    # drop data it doesn't recognize — that's the same failure mode by
    # omission instead of by contradiction.
    for key in sorted(set(product) - PRODUCT_YAML_KEYS):
        print(
            f"{YEL}  W202  product.yaml has an unrecognized top-level key "
            f"'{key}' — it is not read by any section and will not appear "
            f"anywhere in the built document.{RESET}"
        )

    reporting_path = cfg_dir / "reporting.yaml"
    reporting = load_yaml(reporting_path) if reporting_path.exists() else None

    print(f"{DIM}  checking integrity...{RESET}")
    problems = cross_check(risks, matrix)
    errors = [p for p in problems if p.startswith("E")]
    warnings = [p for p in problems if p.startswith("W")]
    for p in errors:
        print(f"{RED}  {p}{RESET}")
    for p in warnings:
        print(f"{YEL}  {p}{RESET}")
    if errors:
        print(f"\n{RED}  Build stopped: the input data is inconsistent.{RESET}")
        return 1
    print(f"{GRN}  integrity ok{RESET}")

    # reporting.yaml is optional and never blocks the build: a missing or
    # incomplete Article 14 runbook is a completeness gap, not a
    # contradiction in the technical file itself.
    if reporting is None:
        print(
            f"{YEL}  W300  {reporting_path.name} not found — appendix A (Article 14 "
            f"reporting runbook) is omitted. Not required by Annex VII, but recommended "
            f"ahead of the 11 September 2026 deadline.{RESET}"
        )
    else:
        for p in check_readiness(reporting):
            print(f"{YEL}  {p}{RESET}")

    out_dir.mkdir(parents=True, exist_ok=True)

    head = [
        "---",
        f'title: "Technical documentation — {product["section_1"]["product_name"]} '
        f'{product["section_1"]["product_version"]}"',
        'subtitle: "Annex VII to Regulation (EU) 2024/2847"',
        f'date: "{product["meta"]["compiled_at"]}"',
        "lang: en",
        "---",
        "",
        "> **" + " ".join(product["meta"]["disclaimer"].split()) + "**",
        "",
        "\\newpage",
        "",
    ]

    parts = [
        "\n".join(head),
        s1(product), "\n\\newpage\n",
        s2(product), "\n\\newpage\n",
        render_risks(risks, matrix), "\n\\newpage\n",
        s4(product), "\n\\newpage\n",
        s5(product), "\n\\newpage\n",
        s6(product), "\n\\newpage\n",
        f"# 7. {ANNEX_VII_TITLES[7]}\n\nSee the separate document "
        "`declaration_of_conformity.md`, which forms an integral part "
        "of this documentation.\n",
        "\n\\newpage\n",
        s8(sbom),
    ]
    if reporting is not None:
        parts += ["\n\\newpage\n", render_reporting(reporting)]
    tech = "\n".join(parts)

    tech_md = out_dir / "technical_file.md"
    doc_md = out_dir / "declaration_of_conformity.md"
    # newline="\n": the same bytes on every OS, so the worked example
    # rebuilds byte-for-byte on Windows too
    tech_md.write_text(tech, encoding="utf-8", newline="\n")
    doc_md.write_text(doc(product), encoding="utf-8", newline="\n")

    print(f"\n  Technical file:  {tech_md}  ({len(tech.splitlines())} lines)")
    print(f"  Declaration:        {doc_md}")

    if pdf:
        for src in (tech_md, doc_md):
            dst = src.with_suffix(".pdf")
            cmd = [
                "pandoc", str(src), "-o", str(dst),
                "--toc", "--toc-depth=2",
                "-V", "papersize=a4",
                "-V", "geometry:margin=2.2cm",
                "-V", "fontsize=10pt",
                "-V", "linkcolor=blue",
                "--pdf-engine=xelatex",
                "-V", "mainfont=DejaVu Serif",
                "-V", "monofont=DejaVu Sans Mono",
            ]
            r = subprocess.run(cmd, capture_output=True, text=True)
            if r.returncode == 0:
                print(f"  PDF:               {dst}")
            else:
                print(f"{YEL}  PDF not produced ({src.name}): "
                      f"{r.stderr.strip().splitlines()[-1] if r.stderr.strip() else '?'}{RESET}")

        # HTML for open publication: a single self-contained file with no external
        # resources and no cookies, so the page can be published as-is.
        for src in (tech_md, doc_md):
            dst = src.with_suffix(".html")
            cmd = [
                "pandoc", str(src), "-o", str(dst),
                "--standalone", "--embed-resources",
                "--toc", "--toc-depth=2",
                "--metadata", "lang=en",
                "-c", str(Path(__file__).parent / "doc.css"),
            ]
            r = subprocess.run(cmd, capture_output=True, text=True)
            if r.returncode == 0:
                print(f"  HTML:              {dst}")
            else:
                print(f"{YEL}  HTML not produced ({src.name}){RESET}")
    return 0


def main() -> int:
    here = Path(__file__).parent
    ap = argparse.ArgumentParser(description="Build the Annex VII technical file")
    ap.add_argument("--config-dir", type=Path, default=here)
    ap.add_argument("--sbom", type=Path, required=True)
    ap.add_argument("-o", "--out", type=Path, required=True)
    ap.add_argument("--pdf", action="store_true")
    args = ap.parse_args()
    return build(args.config_dir, args.sbom, args.out, args.pdf)


if __name__ == "__main__":
    raise SystemExit(main())
