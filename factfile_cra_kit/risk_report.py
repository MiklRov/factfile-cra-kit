#!/usr/bin/env python3
"""
Cross-check the risk assessment against the requirements matrix.

Does two things that neither document does on its own:
  1. Verifies that every applicable Annex I requirement is covered by at least
     one identified risk. A requirement with no risk means it was either not
     analysed, or the analysis is incomplete.
  2. Verifies that every risk references requirements that actually exist.

Also renders section 3 of the technical file as Markdown.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

RESET, RED, YEL, GRN, DIM, BOLD = (
    "\033[0m", "\033[31m", "\033[33m", "\033[32m", "\033[2m", "\033[1m"
)

STRIDE_RU = {
    "spoofing": "spoofing",
    "tampering": "tampering",
    "repudiation": "repudiation",
    "information_disclosure": "information disclosure",
    "denial_of_service": "denial of service",
    "elevation_of_privilege": "elevation of privilege",
}

TREATMENT_RU = {
    "mitigate": "mitigate",
    "accept": "accept",
    "transfer": "transfer",
    "avoid": "avoid",
}


def level(score: int) -> tuple[str, str]:
    if score >= 15:
        return "critical", RED
    if score >= 10:
        return "high", RED
    if score >= 5:
        return "medium", YEL
    return "low", GRN


def load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def cross_check(risks_doc: dict, matrix_doc: dict) -> list[str]:
    problems: list[str] = []

    req_ids: set[str] = set()
    applicable: set[str] = set()
    for section in ("part_i", "part_ii"):
        for r in matrix_doc.get(section) or []:
            rid = r["id"]
            req_ids.add(rid)
            if r.get("applicability") == "applicable":
                applicable.add(rid)

    covered: set[str] = set()
    for risk in risks_doc.get("risks") or []:
        for rid in risk.get("annex_i") or []:
            if rid not in req_ids:
                problems.append(
                    f"E101  {risk['id']}: reference to a non-existent requirement {rid}"
                )
            covered.add(rid)
        if not risk.get("annex_i"):
            problems.append(
                f"E102  {risk['id']}: risk is not mapped to any requirement"
            )
        ratings_valid = True
        for f in ("likelihood", "impact", "residual_likelihood", "residual_impact"):
            v = risk.get(f)
            if not isinstance(v, int) or not 1 <= v <= 5:
                problems.append(f"E103  {risk['id']}: field {f} outside the range 1..5")
                ratings_valid = False
        if risk.get("treatment") not in TREATMENT_RU:
            problems.append(
                f"E103  {risk['id']}: unknown treatment {risk.get('treatment')!r}"
            )
        # a reduction in risk must be backed by controls. Only meaningful once
        # the four rating fields are confirmed numeric above — E103 already
        # flags a bad value, so this must not also crash (or, worse, silently
        # multiply strings) on data already known to be invalid.
        if ratings_valid:
            base = risk.get("likelihood", 0) * risk.get("impact", 0)
            res = risk.get("residual_likelihood", 0) * risk.get("residual_impact", 0)
            if res < base and not risk.get("existing_controls"):
                problems.append(
                    f"E104  {risk['id']}: residual rating is lower than inherent, "
                    "but no control is stated"
                )
        if risk.get("treatment") == "accept" and not risk.get("treatment_note"):
            problems.append(
                f"E105  {risk['id']}: risk accepted without a rationale"
            )

    for rid in sorted(applicable - covered):
        problems.append(
            f"W201  requirement {rid} is not covered by any risk — the analysis is incomplete"
        )

    return problems


def render(risks_doc: dict, matrix_doc: dict) -> str:
    meta = risks_doc["meta"]
    sysd = risks_doc["system"]
    out: list[str] = []
    a = out.append

    a(f"# 3. Cybersecurity risk assessment\n")
    a(f"**Product:** {meta['product']} {meta['product_version']}  ")
    a(f"**Assessment date:** {meta['assessed_at']}  ")
    a(f"**Method:** {meta['methodology']}\n")
    a("> This section is drawn up pursuant to Article 13(2) and point 3 of "
      "Annex VII to Regulation (EU) 2024/2847.\n")

    a("## 3.1 Limitations of the assessment\n")
    for lim in meta.get("limitations", []):
        a(f"- {lim}")
    a("")

    a("## 3.2 System description\n")
    a(sysd["description"].strip() + "\n")

    a("### Entry points\n")
    a("| Ref | Entry point | Location |")
    a("|---|---|---|")
    for ep in sysd["entry_points"]:
        a(f"| {ep['id']} | {ep['name']} | `{ep['ref']}` |")
    a("")

    a("### Assets\n")
    a("| Ref | Asset | Properties | Note |")
    a("|---|---|---|---|")
    for asset in sysd["assets"]:
        cia = ", ".join(
            {"confidentiality": "C", "integrity": "I", "availability": "A"}[c]
            for c in asset["cia"]
        )
        a(f"| {asset['id']} | {asset['name']} | {cia} | {asset.get('note','')} |")
    a("\nC — confidentiality, I — integrity, A — availability\n")

    a("### Trust boundaries\n")
    for tb in sysd["trust_boundaries"]:
        a(f"- **{tb['id']}** — {tb['name']}")
    a("")

    a("## 3.3 Identified risks\n")
    risks = sorted(
        risks_doc["risks"],
        key=lambda r: -(r["likelihood"] * r["impact"]),
    )
    a("| Ref | Risk | STRIDE | Inherent | Residual | Treatment | Requirements |")
    a("|---|---|---|---|---|---|---|")
    for r in risks:
        base = r["likelihood"] * r["impact"]
        res = r["residual_likelihood"] * r["residual_impact"]
        bl, _ = level(base)
        rl, _ = level(res)
        stride = ", ".join(STRIDE_RU.get(s, s) for s in r["stride"])
        reqs = ", ".join(r["annex_i"])
        a(f"| {r['id']} | {r['title']} | {stride} | {base} ({bl}) | "
          f"{res} ({rl}) | {TREATMENT_RU[r['treatment']]} | {reqs} |")
    a("")

    a("## 3.4 Risk detail\n")
    for r in risks:
        base = r["likelihood"] * r["impact"]
        res = r["residual_likelihood"] * r["residual_impact"]
        a(f"### {r['id']} — {r['title']}\n")
        if r.get("deployment_dependent"):
            a("*This risk depends on deployment configuration.*\n")
        a(r["description"].strip() + "\n")
        a(f"- **Trust boundary:** {r['boundary']}")
        a(f"- **Affected assets:** {', '.join(r['assets'])}")
        a(f"- **Inherent rating:** likelihood {r['likelihood']} x "
          f"impact {r['impact']} = **{base}** ({level(base)[0]})")
        a(f"- **Residual rating:** likelihood {r['residual_likelihood']} x "
          f"impact {r['residual_impact']} = **{res}** ({level(res)[0]})")
        a(f"- **Treatment:** {TREATMENT_RU[r['treatment']]}")
        a("")
        if r.get("existing_controls"):
            a("**Existing controls:**\n")
            for c in r["existing_controls"]:
                a(f"- {c}")
            a("")
        if r.get("control_refs"):
            a("**Evidence in code:**\n")
            for c in r["control_refs"]:
                a(f"- `{c}`")
            a("")
        if r.get("treatment_note"):
            a(f"**Rationale:** {r['treatment_note'].strip()}\n")
        a(f"**Covers requirements:** {', '.join(r['annex_i'])}\n")

    a("## 3.5 Annex I requirement coverage\n")
    cov: dict[str, list[str]] = {}
    for r in risks_doc["risks"]:
        for rid in r.get("annex_i") or []:
            cov.setdefault(rid, []).append(r["id"])
    a("| Requirement | Title | Risks |")
    a("|---|---|---|")
    for section in ("part_i", "part_ii"):
        for req in matrix_doc.get(section) or []:
            rid = req["id"]
            lst = ", ".join(sorted(cov.get(rid, []))) or "—"
            a(f"| {rid} | {req['title']} | {lst} |")
    a("")
    return "\n".join(out)


def main() -> int:
    here = Path(__file__).parent
    ap = argparse.ArgumentParser(description="Cross-check risks against the requirements matrix")
    ap.add_argument("--risks", type=Path, default=here / "risks.yaml")
    ap.add_argument("--matrix", type=Path, default=here / "annex_i.yaml")
    ap.add_argument("-o", "--out", type=Path, default=None,
                    help="where to write section 3 as Markdown")
    args = ap.parse_args()

    risks_doc = load(args.risks)
    matrix_doc = load(args.matrix)

    problems = cross_check(risks_doc, matrix_doc)
    errors = [p for p in problems if p.startswith("E")]
    warnings = [p for p in problems if p.startswith("W")]

    for p in errors:
        print(f"{RED}  {p}{RESET}")
    for p in warnings:
        print(f"{YEL}  {p}{RESET}")

    risks = risks_doc["risks"]
    buckets: dict[str, int] = {}
    for r in risks:
        lv, _ = level(r["likelihood"] * r["impact"])
        buckets[lv] = buckets.get(lv, 0) + 1

    print(f"\n  Risks identified: {len(risks)}")
    for lv in ("critical", "high", "medium", "low"):
        if lv in buckets:
            print(f"    {lv:<14} {buckets[lv]}")
    dep = sum(1 for r in risks if r.get("deployment_dependent"))
    print(f"  Deployment-dependent: {dep}")
    accepted = sum(1 for r in risks if r["treatment"] == "accept")
    print(f"  Accepted without mitigation:     {accepted}")
    print(f"  {RED}Errors:{RESET} {len(errors)}   {YEL}Warnings:{RESET} {len(warnings)}")

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(render(risks_doc, matrix_doc), encoding="utf-8")
        print(f"\n  Section 3 written: {args.out}")

    if errors:
        print(f"\n{RED}  Risk assessment failed the integrity check.{RESET}")
        return 1
    print(f"\n{GRN}  Integrity check passed.{RESET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
