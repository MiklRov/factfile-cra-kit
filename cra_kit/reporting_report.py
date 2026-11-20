#!/usr/bin/env python3
"""
Render the Article 14 vulnerability and incident reporting runbook.

This is not an Annex VII section — Annex VII does not require it. It is
supplementary, operational-readiness material: cra-kit assembles evidence of
conformity, and being ready to meet the Article 14 clock (in force from
11 September 2026) is a separate, live obligation that has nothing to do with
harmonised standards and everything to do with having a runbook before an
event happens.

Also checks the runbook for completeness — an unfilled filer, an
unidentified CSIRT contact, an unreviewed template. These are never hard
failures: a missing or incomplete runbook does not make the rest of the
technical file self-contradictory the way a risk-assessment gap does, so it
is reported as a warning, not an error. The build proceeds either way.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

RESET, RED, YEL, GRN, DIM = "\033[0m", "\033[31m", "\033[33m", "\033[32m", "\033[2m"

APPENDIX_TITLE = "Article 14 vulnerability and incident reporting runbook"

# A value still carrying one of these markers has not actually been filled
# in — same convention as the "<to be completed by the manufacturer>"
# placeholders used throughout product.yaml.
def _is_placeholder(value) -> bool:
    return not isinstance(value, str) or not value.strip() or value.strip().startswith("<")


def load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def check_readiness(doc: dict) -> list[str]:
    """Completeness check. Everything here is a warning (W3xx) — a runbook
    gap is incomplete work, not a data contradiction, and must not block
    the build."""
    problems: list[str] = []

    filer = doc.get("filer") or {}
    if _is_placeholder((filer.get("primary") or {}).get("name")):
        problems.append("W301  no named filer identified — filer.primary.name is a placeholder")
    if _is_placeholder((filer.get("deputy") or {}).get("name")):
        problems.append("W302  no deputy filer identified — filer.deputy.name is a placeholder")

    csirt = doc.get("csirt_contact") or {}
    identified = (csirt.get("identified_csirt") or {})
    if csirt.get("status") != "identified" or _is_placeholder(identified.get("csirt_name")):
        problems.append(
            "W303  CSIRT contact not identified — csirt_contact.identified_csirt is a placeholder"
        )

    checklist = doc.get("readiness_checklist") or {}
    if not checklist.get("templates_reviewed"):
        problems.append("W304  readiness_checklist.templates_reviewed is false — templates not yet reviewed")
    if not checklist.get("tabletop_completed"):
        problems.append("W305  readiness_checklist.tabletop_completed is false — no walkthrough has been run")

    # a contradictory pair: a date recorded without the box checked, or the
    # box checked with no date to show for it
    completed = bool(checklist.get("tabletop_completed"))
    has_date = bool(checklist.get("tabletop_date"))
    if completed != has_date:
        problems.append(
            "W306  tabletop_completed and tabletop_date disagree — "
            f"completed={completed!r}, date={checklist.get('tabletop_date')!r}"
        )

    return problems


def _check(flag: bool) -> str:
    return "[x]" if flag else "[ ]"


def render(doc: dict) -> str:
    out: list[str] = []
    a = out.append

    a(f"# Appendix A. {APPENDIX_TITLE}\n")
    a(
        "> This appendix is not one of the eight sections Annex VII requires. It is "
        "supplementary material cra-kit provides as a practical addition: a runbook for "
        "the Article 14 reporting obligation, which took effect on "
        f"{doc['meta'].get('applies_from', '11 September 2026')} and runs on a much "
        "shorter clock than anything else in this pack. It does not detect vulnerabilities "
        "or incidents, does not decide whether the 24-hour clock has started, and does not "
        "submit anything to ENISA or a CSIRT — that judgment is the manufacturer's alone, "
        "made by a human, at the time.\n"
    )

    a("## A.1 The two triggers\n")
    a(
        "The 24-hour clock starts only on the manufacturer's actual knowledge that "
        "exploitation of a vulnerability, or a severe incident, is real and is affecting "
        "**this product**. A CVE existing in the SBOM, a scanner finding, an unconfirmed "
        "report, or exploitation confirmed in a different product does **not** start it.\n"
    )
    for key in ("exploited_vulnerability", "severe_incident"):
        t = doc["triggers"][key]
        a(f"### {t['name']} ({t['legal_basis']})\n")
        a("**Starts the clock when:**\n")
        a(t["clock_starts_when"].strip() + "\n")
        a("**Does NOT start the clock:**\n")
        for x in t.get("clock_does_NOT_start_when", []):
            a(f"- {x}")
        a("")

    a("## A.2 Deadlines\n")
    a("| Trigger | Stage | Deadline | Legal basis |")
    a("|---|---|---|---|")
    stage_labels = {
        "early_warning": "24h early warning",
        "full_notification": "72h full notification",
        "final_report": "Final report",
    }
    for key in ("exploited_vulnerability", "severe_incident"):
        t = doc["triggers"][key]
        for stage_key, label in stage_labels.items():
            s = t["stages"][stage_key]
            a(f"| {t['name']} | {label} | {s['deadline']} | {s['legal_basis']} |")
    a("")
    a(
        "The final report deadline differs by trigger: for an exploited vulnerability it "
        "is **14 days after a corrective or mitigating measure becomes available** — "
        "anchored to the fix, which may land well outside 14 days from first awareness. "
        "For a severe incident it is **one month after the 72-hour notification**, on a "
        "fixed clock that is not tied to any fix at all.\n"
    )

    a("## A.3 Operators, self-hosters and other third-party deployments\n")
    a(doc["operator_and_self_hoster_note"].strip() + "\n")

    a("## A.4 Named filer and deputy\n")
    a("| Role | Name | Contact |")
    a("|---|---|---|")
    filer = doc["filer"]
    a(f"| {filer['primary'].get('role','—')} (primary) | {filer['primary'].get('name','—')} | {filer['primary'].get('contact','—')} |")
    a(f"| {filer['deputy'].get('role','—')} (deputy) | {filer['deputy'].get('name','—')} | {filer['deputy'].get('contact','—')} |")
    a("")
    a(filer["deputy"]["note"].strip() + "\n")

    a("## A.5 Identifying the relevant CSIRT\n")
    csirt = doc["csirt_contact"]
    a(f"**Status:** {csirt.get('status', 'not_identified')}\n")
    if csirt.get("status") != "identified":
        a(
            "> **Not yet identified.** This is a field the manufacturer must resolve — "
            "cra-kit does not invent a CSIRT contact, since a wrong or fabricated one is "
            "worse than an honestly blank one.\n"
        )
    a(csirt["process_note"].strip() + "\n")
    ic = csirt.get("identified_csirt") or {}
    a("| Field | Value |")
    a("|---|---|")
    a(f"| Country | {ic.get('country','—')} |")
    a(f"| CSIRT | {ic.get('csirt_name','—')} |")
    a(f"| Contact | {ic.get('contact','—')} |")
    a("")
    a(csirt["enisa_platform_note"].strip() + "\n")

    a("## A.6 Draft notification templates\n")
    a(
        "Bracketed fields (`[LIKE THIS]`) mark facts that can only be known at the time of "
        "a real event and must never be filled in ahead of one.\n"
    )
    template_labels = [
        ("early_warning_24h", "24-hour early warning"),
        ("full_notification_72h", "72-hour full notification"),
        ("final_report_vulnerability", "Final report — exploited vulnerability"),
        ("final_report_incident", "Final report — severe incident"),
    ]
    for tkey, label in template_labels:
        a(f"### {label}\n")
        a("```markdown")
        a(doc["templates"][tkey].rstrip("\n"))
        a("```\n")

    a("## A.7 Readiness checklist\n")
    checklist = doc["readiness_checklist"]
    rows = [
        ("named_filer_identified", "Named filer identified"),
        ("deputy_identified", "Deputy filer identified"),
        ("csirt_contact_identified", "CSIRT contact identified"),
        ("templates_reviewed", "Templates reviewed"),
        ("tabletop_completed", "One tabletop walkthrough completed"),
    ]
    for key, label in rows:
        a(f"- {_check(bool(checklist.get(key)))} {label}")
    date = checklist.get("tabletop_date") or "not recorded"
    a(f"- Tabletop date: {date}")
    a("")
    a(checklist["note"].strip() + "\n")

    return "\n".join(out)


def main() -> int:
    here = Path(__file__).parent
    ap = argparse.ArgumentParser(description="Render the Article 14 reporting runbook appendix")
    ap.add_argument("--reporting", type=Path, default=here / "reporting.yaml")
    ap.add_argument("-o", "--out", type=Path, default=None,
                    help="where to write the appendix as Markdown")
    args = ap.parse_args()

    if not args.reporting.exists():
        print(f"{YEL}  W300  {args.reporting} not found — the Article 14 runbook is not yet "
              f"configured{RESET}")
        return 0

    doc = load(args.reporting)
    problems = check_readiness(doc)
    for p in problems:
        print(f"{YEL}  {p}{RESET}")

    print(f"\n  Readiness gaps: {len(problems)}")
    if problems:
        print(f"{YEL}  The runbook is incomplete. This is a warning, not a build failure.{RESET}")
    else:
        print(f"{GRN}  Runbook is fully filled in.{RESET}")

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(render(doc), encoding="utf-8")
        print(f"\n  Appendix written: {args.out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
