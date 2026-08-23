#!/usr/bin/env python3
"""
Match SBOM components against known vulnerabilities via OSV.dev.

This is the layer sbom_gen.py deliberately does not build: sbom_gen.py
produces an inventory of what is in the product; this script checks that
inventory against a public vulnerability database and reports what is
already known about each component's exact version.

IMPORTANT — read before treating the output as a finding:
A known vulnerability existing against a component's version is not the
same as that vulnerability being exploited, or even exploitable, in this
specific product. This script performs identifier matching (purl + version
against OSV.dev records) — nothing more. Whether a match is a real exposure
(is the vulnerable code path reachable, is the vulnerable functionality
used, is there a compensating control) is a human judgement call that this
tool does not make. See the disclaimer at the top of vuln_report.md, and do
not strip it when repackaging the output.

Data source: OSV.dev (https://osv.dev), the Open Source Vulnerability
database run by Google/OpenSSF. Public, free, no API key. Two endpoints:
  - POST /v1/querybatch  — cheap: purl in, list of vulnerability IDs out
  - GET  /v1/vulns/{id}  — full record for one ID (summary, aliases incl.
    CVE, severity, references)
Endpoint shapes were confirmed against https://google.github.io/osv.dev/
and by live test calls against api.osv.dev while building this script
(2026-08). Notable, non-obvious behaviour found by testing rather than by
reading the docs:
  - No auth header of any kind is required or accepted.
  - A component with no known vulnerabilities comes back as `{}` (no
    "vulns" key) — not an empty list, not an error.
  - If ANY purl in a /v1/querybatch request is not a well-formed "pkg:..."
    string, the WHOLE batch fails with HTTP 400 — one bad purl takes every
    other query in that batch down with it. Malformed purls are therefore
    filtered out and reported as failures *before* a batch is sent, never
    mixed into a live request.
  - A syntactically valid purl whose *type* OSV does not recognise (e.g.
    "pkg:gradle/...", which OSV has no ecosystem for) does not error either
    — it silently comes back the same as "no known vulnerabilities". This
    is indistinguishable from a clean result unless you already know which
    purl types OSV understands, which is what KNOWN_PURL_TYPES below is
    for. cra-kit's own SBOM output never emits "pkg:gradle/..." purls (see
    gradle_tree.py / ecosystems.py — Gradle deps get "pkg:maven/..." purls,
    tagged cra:ecosystem=gradle only as a provenance label), so this case
    is a defensive fallback for purl types cra-kit does not produce today,
    not something the current pipeline is expected to hit.

Skips dev-only components by default (cra:dev=true) — matching sbom_gen.py's
own default, though its own default output should not contain any.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

TOOL_NAME = "cra-kit-vuln-scan"
TOOL_VERSION = "0.1.0"

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"

REQUEST_TIMEOUT = 20  # seconds, per HTTP request — a request either answers
                       # in reasonable time or it is treated as failed; the
                       # script must never hang waiting on the network.
MAX_RETRIES = 4
BACKOFF_BASE = 1.5  # seconds; exponential: 1.5, 3, 6, 12
BATCH_SIZE = 500  # purls per /v1/querybatch call. OSV's own pagination is
                   # keyed to vulnerability counts (>1000 per package,
                   # >3000 per batch), not to query counts, and no request
                   # size limit is documented; 500 keeps a single HTTP call
                   # comfortably sized and cheap to retry as a unit.
DETAIL_THROTTLE = 0.05  # seconds between individual /v1/vulns/{id} calls —
                         # courtesy pacing; OSV documents no rate limit but
                         # publishes no allowance either.

RESET, RED, YEL, GRN, DIM, BOLD = (
    "\033[0m", "\033[31m", "\033[33m", "\033[32m", "\033[2m", "\033[1m"
)

# purl types cra-kit's own generators (sbom_gen.py, ecosystems.py,
# gradle_tree.py) are known to emit, mapped to the OSV ecosystem name each
# corresponds to (per https://ossf.github.io/osv-schema/#ecosystems). This
# table is NOT used to build the OSV query — OSV resolves a purl directly,
# confirmed by live testing (see module docstring) — it exists only so an
# empty OSV result for a purl *type* we don't recognise can be reported as
# "uncertain" rather than silently accepted as "clean". A few common types
# cra-kit does not currently emit are included for forward compatibility.
KNOWN_PURL_TYPES = {
    "composer": "Packagist",
    "npm": "npm",
    "maven": "Maven",
    "pypi": "PyPI",
    "golang": "Go",
    "cargo": "crates.io",
    "gem": "RubyGems",
    "nuget": "NuGet",
}

_SEVERITY_RANK = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MODERATE": 2,
    "MEDIUM": 2,
    "LOW": 1,
    "NEGLIGIBLE": 1,
}


# --------------------------------------------------------------------------
# HTTP, with retry/backoff and a hard timeout — never hang forever
# --------------------------------------------------------------------------

class OSVError(Exception):
    """A query to OSV.dev could not be completed."""


def _do_request(req: urllib.request.Request) -> dict:
    last_err: OSVError | None = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")[:300]
            if e.code == 429 or e.code >= 500:
                # rate-limited or a server-side hiccup: worth a retry
                last_err = OSVError(f"HTTP {e.code}: {body}")
            else:
                # a 4xx other than 429 means the request itself is bad
                # (malformed purl, unknown id, ...) — retrying identical
                # input will not change the outcome
                raise OSVError(f"HTTP {e.code}: {body}") from e
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            last_err = OSVError(f"network error: {e}")
        except json.JSONDecodeError as e:
            last_err = OSVError(f"malformed JSON in response: {e}")
        if attempt < MAX_RETRIES:
            time.sleep(BACKOFF_BASE * (2 ** (attempt - 1)))
    assert last_err is not None
    raise last_err


def osv_post(url: str, payload: dict) -> dict:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json"},
    )
    return _do_request(req)


def osv_get(url: str) -> dict:
    req = urllib.request.Request(url, method="GET")
    return _do_request(req)


# --------------------------------------------------------------------------
# SBOM parsing
# --------------------------------------------------------------------------

def load_sbom(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def purl_type(purl: str) -> str | None:
    """"pkg:composer/foo/bar@1.0" -> "composer". None if not well-formed."""
    if not purl or not purl.startswith("pkg:"):
        return None
    rest = purl[len("pkg:"):]
    if not rest:
        return None
    return rest.split("/", 1)[0] or None


def is_wellformed_purl(purl: str | None) -> bool:
    return bool(purl_type(purl))


def extract_components(bom: dict, include_dev: bool) -> tuple[list[dict], int]:
    """Normalise SBOM components into the shape this script works with.
    Returns (components, dev_skipped_count).
    """
    out: list[dict] = []
    dev_skipped = 0
    for c in bom.get("components", []) or []:
        props = {p["name"]: p["value"] for p in c.get("properties", []) or []}
        is_dev = props.get("cra:dev") == "true"
        if is_dev and not include_dev:
            dev_skipped += 1
            continue
        out.append({
            "purl": c.get("purl"),
            "name": c.get("name"),
            "version": c.get("version"),
            "ecosystem": props.get("cra:ecosystem", "?"),
            "direct": props.get("cra:direct") == "true",
            "dev": is_dev,
        })
    return out, dev_skipped


def chunked(items: list, n: int):
    for i in range(0, len(items), n):
        yield items[i:i + n]


# --------------------------------------------------------------------------
# OSV querying
# --------------------------------------------------------------------------

def query_vuln_ids(
    components: list[dict],
) -> tuple[dict[str, list[str]], list[dict], list[str]]:
    """For each component, ask OSV which vulnerability IDs apply.

    Returns:
      ids_by_purl     -- purl -> [OSV id, ...] for purls with >=1 finding
      failures        -- components whose lookup could not be trusted, each
                          with a "reason" (malformed purl / network error /
                          unsupported ecosystem)
      truncated_purls -- purls where OSV indicated more results existed
                          than were returned (next_page_token present);
                          rare in practice, surfaced rather than silently
                          dropped
    """
    ids_by_purl: dict[str, list[str]] = {}
    failures: list[dict] = []
    truncated_purls: list[str] = []

    queryable: list[dict] = []
    for c in components:
        if not is_wellformed_purl(c["purl"]):
            failures.append({**c, "reason": "missing or malformed purl — cannot query OSV"})
            continue
        queryable.append(c)

    for chunk in chunked(queryable, BATCH_SIZE):
        payload = {"queries": [{"package": {"purl": c["purl"]}} for c in chunk]}
        try:
            resp = osv_post(OSV_QUERYBATCH_URL, payload)
        except OSVError as e:
            for c in chunk:
                failures.append({**c, "reason": f"OSV batch query failed: {e}"})
            continue

        results = resp.get("results") or []
        if len(results) != len(chunk):
            # shape didn't match what we sent — treat the whole chunk as
            # unreliable rather than guessing at an alignment
            for c in chunk:
                failures.append({
                    **c,
                    "reason": (
                        f"OSV returned {len(results)} results for a batch of "
                        f"{len(chunk)} queries — response could not be matched "
                        "back to components"
                    ),
                })
            continue

        for c, result in zip(chunk, results):
            if result.get("next_page_token"):
                truncated_purls.append(c["purl"])
            vulns = result.get("vulns") or []
            ids = [v["id"] for v in vulns if v.get("id")]
            if ids:
                ids_by_purl[c["purl"]] = ids
                continue
            ptype = purl_type(c["purl"])
            if ptype not in KNOWN_PURL_TYPES:
                failures.append({
                    **c,
                    "reason": (
                        f"unsupported ecosystem: purl type '{ptype}' is not in "
                        "cra-kit's list of OSV-recognised types (composer, npm, "
                        "maven, pypi, and a few not yet emitted by this kit) — "
                        "OSV returned no findings, but for an unrecognised type "
                        "that could mean 'no known vulnerabilities' or it could "
                        "mean 'OSV does not understand this package type'. "
                        "Treat as unknown, not as clean."
                    ),
                })
            # else: recognised type, genuinely no findings — not a failure

    return ids_by_purl, failures, truncated_purls


def fetch_vuln_details(ids: set[str]) -> tuple[dict[str, dict], list[str]]:
    """GET the full record for each unique vulnerability ID.

    Returns (detail_by_id, ids_whose_detail_fetch_failed). A failed detail
    fetch does not remove the finding — the component still shows the
    vulnerability ID, just without summary/severity/references, and the ID
    is listed separately so the gap is visible rather than silently absent.
    """
    details: dict[str, dict] = {}
    failed: list[str] = []
    for i, vid in enumerate(sorted(ids)):
        try:
            details[vid] = osv_get(OSV_VULN_URL.format(id=vid))
        except OSVError as e:
            failed.append(vid)
            print(f"  ! could not fetch details for {vid}: {e}", file=sys.stderr)
        if i + 1 < len(ids):
            time.sleep(DETAIL_THROTTLE)
    return details, failed


# --------------------------------------------------------------------------
# severity — best effort, never invented
# --------------------------------------------------------------------------

def extract_severity(detail: dict) -> dict | None:
    """Pull a severity rating out of an OSV vulnerability record.

    Prefers a qualitative rating the source database already computed
    (GHSA's LOW/MODERATE/HIGH/CRITICAL, Ubuntu's negligible/low/medium/
    high/critical, ...) over a raw CVSS vector string. Turning a CVSS
    vector into a base score requires applying the CVSS formula; that is
    not implemented here, so a bare vector is reported verbatim rather than
    converted into a number this script did not verify. Returns None if the
    record carries no severity information of either kind at all.
    """
    ds = detail.get("database_specific") or {}
    label = ds.get("severity")
    label = label.strip() if isinstance(label, str) and label.strip() else None

    cvss: dict | None = None
    if label is None:
        for sev in detail.get("severity") or []:
            score = sev.get("score")
            sev_type = sev.get("type", "")
            if not isinstance(score, str) or not score.strip():
                continue
            if score.strip().upper() in _SEVERITY_RANK:
                # some sources (e.g. Ubuntu) put the qualitative word
                # directly in the score field
                label = score.strip()
                break
            if cvss is None:
                cvss = {"type": sev_type, "vector": score.strip()}

    if label is None and cvss is None:
        return None
    rank = _SEVERITY_RANK.get(label.upper(), 0) if label else 0
    out: dict = {"label": label, "rank": rank}
    if cvss:
        out["cvss"] = cvss
    return out


# --------------------------------------------------------------------------
# assembly
# --------------------------------------------------------------------------

def build_finding_record(vid: str, detail: dict | None) -> dict:
    if detail is None:
        return {
            "id": vid,
            "aliases": [],
            "summary": None,
            "severity": None,
            "published": None,
            "references": [],
            "details_unavailable": True,
        }
    summary = detail.get("summary") or None
    if not summary and detail.get("details"):
        summary = detail["details"].strip().splitlines()[0][:300]
    return {
        "id": vid,
        "aliases": detail.get("aliases") or [],
        "summary": summary,
        "severity": extract_severity(detail),
        "published": detail.get("published"),
        "references": [
            r["url"] for r in (detail.get("references") or []) if r.get("url")
        ],
    }


def component_max_severity_rank(entry: dict) -> int:
    ranks = [
        v["severity"]["rank"] for v in entry["vulnerabilities"] if v.get("severity")
    ]
    return max(ranks) if ranks else -1


def cve_or_id(vuln: dict) -> str:
    for alias in vuln.get("aliases") or []:
        if alias.startswith("CVE-"):
            return alias
    return vuln["id"]


def build_component_entry(c: dict, vuln_ids: list[str], details: dict[str, dict]) -> dict:
    records = [build_finding_record(vid, details.get(vid)) for vid in vuln_ids]
    records.sort(key=lambda r: -(r["severity"]["rank"] if r.get("severity") else -1))
    return {
        "purl": c["purl"],
        "name": c["name"],
        "version": c["version"],
        "ecosystem": c["ecosystem"],
        "direct": c["direct"],
        "vulnerabilities": records,
    }


# --------------------------------------------------------------------------
# Markdown report
# --------------------------------------------------------------------------

DISCLAIMER = """> **What this report is, and is not.** Four terms are used
> below with specific, deliberately narrow meanings — do not read any of
> them as a stronger claim than stated:
>
> - **Known vulnerability match** — the component's name and version fall
>   inside a version range OSV.dev records against a public advisory. A
>   string/range match, nothing more.
> - **Potentially affected** — the match is uncertain: the advisory's
>   version range is ambiguous, the package may be backported or repackaged
>   under the same version string, or the reported version could not be
>   fully confirmed. Treat with extra care before acting on it either way.
> - **Not assessed for exploitability** — this tool does not determine
>   whether the vulnerable code path is reachable in this product, whether
>   the vulnerable functionality is used, whether a compensating control
>   exists, or whether the vulnerability is being actively exploited
>   anywhere. That assessment is the manufacturer's to make, using
>   `risks.yaml` / `risk_report.py`, not this script's.
> - **No match found** — OSV.dev's database held no record against this
>   purl and version at scan time. This is **not** a statement that the
>   component or product is secure. It means nothing matched a public
>   database on this date; unknown, unreported, or not-yet-published
>   vulnerabilities are invisible to this method by construction.
>
> This distinction is not a courtesy — it tracks the legal line drawn by the
> Regulation itself. Article 14 of Regulation (EU) 2024/2847 and Commission
> guidance (C(2026) 5252) tie the 24-hour/72-hour reporting clock to *actual
> knowledge of active exploitation of a vulnerability in the manufacturer's
> own product* — not to the mere existence of a CVE against a component
> version. A known vulnerability match below does not, by itself, start
> that clock."""


def _fmt_severity(sev: dict | None) -> str:
    if sev is None:
        return "unrated"
    if sev.get("label"):
        return sev["label"]
    if sev.get("cvss"):
        return f"CVSS present, not scored ({sev['cvss']['vector']})"
    return "unrated"


def render_report(
    product_name: str,
    product_version: str,
    source_sbom: Path,
    total_scanned: int,
    dev_skipped: int,
    entries: list[dict],
    failures: list[dict],
    detail_fetch_failed: list[str],
    truncated_purls: list[str],
    generated_at: str,
) -> str:
    out: list[str] = []
    a = out.append

    a("# Known-vulnerability matches\n")
    a(f"**Product:** {product_name} {product_version}  ")
    a(f"**Source SBOM:** `{source_sbom}`  ")
    a(f"**Generated:** {generated_at}  ")
    a(f"**Data source:** OSV.dev (https://osv.dev)\n")

    a(DISCLAIMER + "\n")

    direct_n = sum(1 for e in entries if e["direct"])
    transitive_n = len(entries) - direct_n
    a("## Summary\n")
    a("| Metric | Count |")
    a("|---|---|")
    a(f"| Components scanned | {total_scanned} |")
    a(f"| Components with >=1 known vulnerability | {len(entries)} |")
    a(f"| &nbsp;&nbsp;— direct dependencies | {direct_n} |")
    a(f"| &nbsp;&nbsp;— transitive dependencies | {transitive_n} |")
    a(f"| Components with a failed or uncertain lookup | {len(failures)} |")
    if dev_skipped:
        a(f"| Dev-only components skipped (cra:dev=true) | {dev_skipped} |")
    a("")

    a("## Known vulnerability matches, by severity\n")
    a("Every row here is a **known vulnerability match** as defined above — "
      "a version match against a public advisory, not an assessed finding. "
      "Sorted by highest severity first (unrated last), direct dependencies "
      "before transitive ones within the same severity. \"Vulnerability "
      "ID(s)\" prefers a CVE alias where OSV records one; the OSV-native ID "
      "always exists and is shown when no CVE alias is known.\n")
    if entries:
        ranked = sorted(
            entries,
            key=lambda e: (-component_max_severity_rank(e), not e["direct"], e["name"] or ""),
        )
        a("| Component | Version | Direct? | Vulnerability ID(s) | Severity | Summary |")
        a("|---|---|---|---|---|---|")
        for e in ranked:
            ids = ", ".join(cve_or_id(v) for v in e["vulnerabilities"])
            worst = max(
                e["vulnerabilities"],
                key=lambda v: v["severity"]["rank"] if v.get("severity") else -1,
            )
            sev_text = _fmt_severity(worst.get("severity"))
            summary = (worst.get("summary") or "").replace("|", "\\|").replace("\n", " ")
            if len(summary) > 140:
                summary = summary[:137] + "..."
            direct_text = "yes" if e["direct"] else "no"
            a(f"| {e['name']} | {e['version']} | {direct_text} | {ids} | {sev_text} | {summary} |")
        a("")
    else:
        a("No components with a known vulnerability match were found in "
          "OSV.dev at scan time. **This is not a statement that the product "
          "is secure** — see \"No match found\" in the definitions above.\n")

    a("## Lookup failures — do not read as \"clean\"\n")
    a("A component in this section was **not** successfully checked against "
      "OSV.dev. It is not equivalent to \"no known vulnerabilities\" — it "
      "means the check itself did not complete, for the reason stated.\n")
    if failures:
        a("| Component | Version | purl | Reason |")
        a("|---|---|---|---|")
        for f in failures:
            reason = (f.get("reason") or "").replace("|", "\\|")
            a(f"| {f.get('name') or '?'} | {f.get('version') or '?'} | "
              f"`{f.get('purl') or '?'}` | {reason} |")
        a("")
    else:
        a("None. Every component with a well-formed purl was successfully queried.\n")

    if detail_fetch_failed:
        a("### Vulnerability records that could not be fully fetched\n")
        a("The IDs below were found by the batch lookup (so the component IS "
          "affected by something) but fetching the full record — summary, "
          "aliases, severity — failed. They still appear in `vulns.json` "
          "with `\"details_unavailable\": true` and no severity, so they do "
          "not silently disappear, but they are also not fully described "
          "here.\n")
        for vid in detail_fetch_failed:
            a(f"- `{vid}`")
        a("")

    if truncated_purls:
        a("### Truncated results\n")
        a("OSV indicated more vulnerability IDs exist than were returned for "
          "the components below (pagination token present, not followed). "
          "Their listed findings here are a subset.\n")
        for p in truncated_purls:
            a(f"- `{p}`")
        a("")

    a("---\n")
    a(f"*Generated by `{TOOL_NAME}` {TOOL_VERSION}. Matching only — see the "
      "disclaimer above before treating any row as a confirmed issue.*")
    return "\n".join(out)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(
        description=(
            "Match an existing CycloneDX SBOM (from sbom_gen.py) against "
            "OSV.dev's known-vulnerability database"
        )
    )
    ap.add_argument("--sbom", required=True, type=Path, help="path to sbom.cdx.json")
    ap.add_argument("-o", "--out", type=Path, default=Path("out"),
                     help="output directory (writes vulns.json + vuln_report.md)")
    ap.add_argument(
        "--include-dev", action="store_true",
        help="also query dev-only components (cra:dev=true) — off by default, "
        "matching sbom_gen.py; the default SBOM should not contain any",
    )
    args = ap.parse_args()

    if not args.sbom.is_file():
        print(f"no such file: {args.sbom}", file=sys.stderr)
        return 1

    try:
        bom = load_sbom(args.sbom)
    except (json.JSONDecodeError, OSError) as e:
        print(f"could not read SBOM: {e}", file=sys.stderr)
        return 1

    meta_component = (bom.get("metadata") or {}).get("component") or {}
    product_name = meta_component.get("name", "?")
    product_version = meta_component.get("version", "?")

    components, dev_skipped = extract_components(bom, args.include_dev)
    print(f"  Components to check: {len(components)}"
          + (f"  (dev-only skipped: {dev_skipped})" if dev_skipped else ""))

    print("  Querying OSV.dev (batch)...")
    ids_by_purl, failures, truncated_purls = query_vuln_ids(components)

    all_ids: set[str] = set()
    for ids in ids_by_purl.values():
        all_ids.update(ids)
    print(f"  Components with findings: {len(ids_by_purl)}  "
          f"(unique vulnerability IDs: {len(all_ids)})")

    print(f"  Fetching {len(all_ids)} vulnerability record(s)...")
    details, detail_fetch_failed = fetch_vuln_details(all_ids)

    by_purl = {c["purl"]: c for c in components}
    entries = [
        build_component_entry(by_purl[purl], ids, details)
        for purl, ids in sorted(ids_by_purl.items())
    ]

    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    direct_n = sum(1 for e in entries if e["direct"])
    transitive_n = len(entries) - direct_n

    vulns_doc = {
        "meta": {
            "tool": f"{TOOL_NAME} {TOOL_VERSION}",
            "generated_at": now,
            "source_sbom": str(args.sbom),
            "product": {"name": product_name, "version": product_version},
            "osv_api": "https://api.osv.dev",
            "totals": {
                "components_scanned": len(components),
                "components_with_findings": len(entries),
                "components_direct_with_findings": direct_n,
                "components_transitive_with_findings": transitive_n,
                "components_lookup_failed": len(failures),
                "unique_vulnerability_ids": len(all_ids),
            },
            "detail_fetch_failures": detail_fetch_failed,
            "truncated_results": truncated_purls,
        },
        "findings": entries,
        "lookup_failures": [
            {
                "purl": f.get("purl"),
                "name": f.get("name"),
                "version": f.get("version"),
                "ecosystem": f.get("ecosystem"),
                "direct": f.get("direct"),
                "reason": f.get("reason"),
            }
            for f in failures
        ],
    }

    args.out.mkdir(parents=True, exist_ok=True)
    vulns_path = args.out / "vulns.json"
    vulns_path.write_text(
        json.dumps(vulns_doc, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    report_path = args.out / "vuln_report.md"
    report_path.write_text(
        render_report(
            product_name, product_version, args.sbom,
            len(components), dev_skipped, entries, failures,
            detail_fetch_failed, truncated_purls, now,
        ),
        encoding="utf-8",
    )

    print(f"\n  vulns.json written:      {vulns_path}")
    print(f"  vuln_report.md written:  {report_path}")
    print(f"\n  Total components scanned:        {len(components)}")
    print(f"  Components with >=1 finding:     {len(entries)}  "
          f"(direct: {direct_n}, transitive: {transitive_n})")
    fail_color = YEL if failures else GRN
    print(f"  {fail_color}Lookup failures:{RESET}                 {len(failures)}")
    if detail_fetch_failed:
        print(f"  {YEL}Detail fetch failures:{RESET}           {len(detail_fetch_failed)}")
    if truncated_purls:
        print(f"  {YEL}Truncated results:{RESET}               {len(truncated_purls)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
