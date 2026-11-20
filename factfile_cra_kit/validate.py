#!/usr/bin/env python3
"""
Integrity check for the CRA essential requirements matrix.

The point of this tool: do not let a requirement be closed with the word
"met" without evidence, and do not let one be declared not applicable
without a justification. That is what separates a conformity matrix from
a checklist.

Problem codes:
  E001  status is met but there is no evidence at all
  E002  applicability = not_applicable without a rationale
  E003  status not_applicable while applicability = applicable (or vice versa)
  E004  evidence without a ref, or with an unknown type
  E005  duplicate requirement identifier
  E006  product metadata is incomplete, or an attestation lacks provenance
  E007  a customer attestation contradicts what was found in the build
  E008  an external lookup lacks provenance (source, reliability, or retrieval time)
  E009  an external lookup contradicts what was found in the build
  W101  requirement not started
  W102  no owner assigned
  W103  evidence exists but the status is not yet met
  W104  a customer attestation has not been checked against the artefacts
  W105  a scraped external lookup has not been independently corroborated
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("PyYAML is required: pip install pyyaml --break-system-packages", file=sys.stderr)
    raise SystemExit(2)

VALID_STATUS = {"not_started", "in_progress", "met", "not_met", "not_applicable"}
VALID_APPLICABILITY = {"applicable", "not_applicable", "conditional"}
VALID_EVIDENCE_TYPES = {
    "design_doc", "test_report", "code_ref", "config", "sbom",
    "process_doc", "third_party", "screenshot", "policy",
    # A manufacturer's attestation: something the customer stated in writing.
    # Deliberately kept apart from the other types — it is an assertion, not a
    # verified fact, and the two must not be blended in a document that goes
    # to a market surveillance authority.
    "customer_attestation",
    # A fact cra-kit itself pulled from an external source at build time (an
    # API lookup, a direct fetch of a known page, a scrape). Kept apart from
    # the other types for the same reason as customer_attestation: this is
    # the tool's own claim about the outside world, not a verified fact, and
    # it must not read as more authoritative than it is just because a tool
    # produced it instead of a person.
    "external_lookup",
}

# An attestation must carry provenance: who said it, when, and where it is
# recorded. Without those, the assertion cannot be checked and does not
# qualify as evidence.
ATTESTATION_REQUIRED = ("attested_by", "attested_at", "thread")

# An external lookup must carry provenance too: what was actually queried,
# how reliable that kind of source is, and when it was retrieved (stale or
# mismatched results are only catchable if you know when the fetch happened).
EXTERNAL_LOOKUP_REQUIRED = ("source", "source_reliability", "retrieved_at")

# Ordered worst-to-best is not required by the code, but keep this reading as
# a trust ladder: a documented API you query directly, a first-party URL you
# fetch directly, and a page scrape of something never designed to be read
# by a machine — the least trustworthy of the three, since neither its
# content nor its availability is guaranteed stable.
VALID_SOURCE_RELIABILITY = {"official_api", "direct_fetch", "scrape"}

VALID_VERIFICATION = {"unverified", "corroborated", "contradicted"}

RESET, RED, YEL, GRN, DIM = "\033[0m", "\033[31m", "\033[33m", "\033[32m", "\033[2m"


class Finding:
    __slots__ = ("code", "req_id", "message")

    def __init__(self, code: str, req_id: str, message: str):
        self.code, self.req_id, self.message = code, req_id, message

    @property
    def is_error(self) -> bool:
        return self.code.startswith("E")


def check_requirement(req: dict, seen: set[str]) -> list[Finding]:
    out: list[Finding] = []
    rid = req.get("id", "<no id>")

    if rid in seen:
        out.append(Finding("E005", rid, "duplicate identifier"))
    seen.add(rid)

    status = req.get("status")
    applicability = req.get("applicability")
    evidence = req.get("evidence") or []

    if status not in VALID_STATUS:
        out.append(Finding("E004", rid, f"unknown status: {status!r}"))
    if applicability not in VALID_APPLICABILITY:
        out.append(Finding("E004", rid, f"unknown applicability: {applicability!r}"))

    # the key check: a requirement cannot be closed without evidence
    if status == "met" and not evidence:
        out.append(
            Finding("E001", rid, "status is met but no evidence is attached — not permitted")
        )

    # cannot be declared not applicable without a rationale
    if applicability == "not_applicable" and not (req.get("rationale") or "").strip():
        out.append(
            Finding(
                "E002", rid,
                "declared not applicable without a rationale — the authority will ask why",
            )
        )

    # status and applicability must not contradict each other
    if applicability == "applicable" and status == "not_applicable":
        out.append(Finding("E003", rid, "applicable, but status is not_applicable"))
    if applicability == "not_applicable" and status not in {"not_applicable", None}:
        out.append(
            Finding("E003", rid, f"not applicable, but status is {status!r}")
        )

    for i, ev in enumerate(evidence):
        if not isinstance(ev, dict):
            out.append(Finding("E004", rid, f"evidence #{i+1}: not an object"))
            continue
        if not (ev.get("ref") or "").strip():
            out.append(Finding("E004", rid, f"evidence #{i+1}: empty ref"))
        etype = ev.get("type")
        if etype not in VALID_EVIDENCE_TYPES:
            out.append(
                Finding("E004", rid, f"evidence #{i+1}: unknown type {etype!r}")
            )

        if etype == "customer_attestation":
            missing = [f for f in ATTESTATION_REQUIRED if not (ev.get(f) or "")]
            if missing:
                out.append(Finding(
                    "E006", rid,
                    f"evidence #{i+1}: customer attestation without provenance "
                    f"({', '.join(missing)}) — not verifiable"
                ))
            verification = ev.get("verification", "unverified")
            if verification not in VALID_VERIFICATION:
                out.append(Finding(
                    "E004", rid,
                    f"evidence #{i+1}: unknown verification status "
                    f"{verification!r}"
                ))
            if verification == "contradicted":
                out.append(Finding(
                    "E007", rid,
                    f"evidence #{i+1}: the attestation contradicts what was found "
                    "in the build — must be resolved before the document is issued"
                ))
            elif verification == "unverified":
                out.append(Finding(
                    "W104", rid,
                    f"evidence #{i+1}: customer attestation has not been checked "
                    "against the artefacts"
                ))

        elif etype == "external_lookup":
            missing = [f for f in EXTERNAL_LOOKUP_REQUIRED if not (ev.get(f) or "")]
            if missing:
                out.append(Finding(
                    "E008", rid,
                    f"evidence #{i+1}: external lookup without provenance "
                    f"({', '.join(missing)}) — not verifiable"
                ))
            reliability = ev.get("source_reliability")
            if reliability and reliability not in VALID_SOURCE_RELIABILITY:
                out.append(Finding(
                    "E004", rid,
                    f"evidence #{i+1}: unknown source_reliability {reliability!r}"
                ))
            verification = ev.get("verification", "unverified")
            if verification not in VALID_VERIFICATION:
                out.append(Finding(
                    "E004", rid,
                    f"evidence #{i+1}: unknown verification status "
                    f"{verification!r}"
                ))
            elif verification == "contradicted":
                out.append(Finding(
                    "E009", rid,
                    f"evidence #{i+1}: the external lookup contradicts what was "
                    "found in the build — re-check the query before the document "
                    "is issued"
                ))
            elif reliability == "scrape" and verification != "corroborated":
                out.append(Finding(
                    "W105", rid,
                    f"evidence #{i+1}: a scraped (low-reliability) source has not "
                    "been independently corroborated — do not treat this "
                    "requirement as settled until it is"
                ))

    if status == "not_started":
        out.append(Finding("W101", rid, "not started"))
    if not req.get("owner"):
        out.append(Finding("W102", rid, "no owner assigned"))
    if evidence and status in {"not_started", "in_progress"}:
        out.append(
            Finding("W103", rid, "evidence exists but the status is not yet met")
        )

    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate the CRA requirements matrix")
    ap.add_argument("matrix", type=Path, nargs="?",
                    default=Path(__file__).parent / "annex_i.yaml")
    ap.add_argument("--strict", action="store_true",
                    help="treat warnings as errors")
    ap.add_argument("--quiet", action="store_true", help="summary only")
    args = ap.parse_args()

    data = yaml.safe_load(args.matrix.read_text(encoding="utf-8"))
    findings: list[Finding] = []

    meta = data.get("meta") or {}
    if not meta.get("product"):
        findings.append(Finding("E006", "meta", "product is not set"))
    if not meta.get("assessor"):
        findings.append(Finding("W102", "meta", "assessor is not set"))

    seen: set[str] = set()
    total = 0
    by_status: dict[str, int] = {}
    for section in ("part_i", "part_ii"):
        for req in data.get(section) or []:
            total += 1
            st = req.get("status", "?")
            by_status[st] = by_status.get(st, 0) + 1
            findings.extend(check_requirement(req, seen))

    errors = [f for f in findings if f.is_error]
    warnings = [f for f in findings if not f.is_error]

    if not args.quiet:
        for f in errors:
            print(f"{RED}  {f.code}{RESET}  {f.req_id:<8} {f.message}")
        for f in warnings:
            print(f"{YEL}  {f.code}{RESET}  {f.req_id:<8} {DIM}{f.message}{RESET}")

    print(f"\n  Requirements:    {total}")
    for st, n in sorted(by_status.items()):
        print(f"    {st:<16} {n}")
    met = by_status.get("met", 0) + by_status.get("not_applicable", 0)
    pct = (met / total * 100) if total else 0
    print(f"  Closed:          {met}/{total}  ({pct:.0f}%)")
    print(f"  {RED}Errors:{RESET}          {len(errors)}")
    print(f"  {YEL}Warnings:{RESET}        {len(warnings)}")

    if errors:
        print(f"\n{RED}  Matrix not ready: integrity errors present.{RESET}")
        return 1
    if args.strict and warnings:
        print(f"\n{YEL}  Strict mode: warnings are treated as errors.{RESET}")
        return 1
    if met < total:
        print(f"\n{YEL}  Integrity is fine, but the work is not finished.{RESET}")
        return 0
    print(f"\n{GRN}  All requirements are closed and backed by evidence.{RESET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
