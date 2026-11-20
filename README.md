# cra-kit

Tooling to assemble the Annex VII technical file required by Regulation (EU) 2024/2847 — the Cyber Resilience Act.

It builds a complete pack from a product's source code plus structured data: an SBOM, an essential requirements matrix, a risk assessment, the technical file and the declaration of conformity.

**What separates this from a checklist:** the tool refuses to assemble a document from inconsistent data. A requirement cannot be closed without evidence, a risk cannot be declared reduced without naming a control, and a requirement cannot be declared not applicable without a justification.

---

## Prerequisites

Python 3.12 or newer, and the packages in `requirements-dev.txt`.

`--pdf` additionally needs **pandoc** and a LaTeX engine (`xelatex`). Without them the
build still produces Markdown — omit `--pdf` and nothing is lost but the typesetting.

---

## Quick start

```bash
pip install -r requirements-dev.txt

# Bring your own SBOM — any CycloneDX document works, from ORT, syft, cdxgen or
# this kit's own generator. Then:
python3 build.py --config-dir . --sbom your-sbom.cdx.json -o out
```

The four YAML files in the repository root are **templates**: the requirements matrix
carries all twenty-one essential requirements with empty evidence, and the rest carry one
worked example of each structure. The first build succeeds and prints a warning for
everything still unfilled — that list is the work.

If you already run a dependency scanner in CI, keep it. This kit is the layer above:
what it adds is the Annex VII document itself — the requirements matrix with evidence,
the risk assessment, the declaration and the Article 14 runbook.

---

## Why

The Regulation is in force. The duty to report actively exploited vulnerabilities has applied since 11 September 2026. The full set of obligations applies from 11 December 2027: technical documentation, conformity assessment, CE marking, and a support period of at least five years.

At the same time, **no harmonised standard supporting the Regulation has been cited in the Official Journal.** Standardisation request M/606 was accepted by CEN, CENELEC and ETSI on 3 April 2025, and amended by Commission Implementing Decision C(2026) 7861 of 10 November 2026. The first two standards of the series were published by CEN-CENELEC on 18 November 2026 — EN 40000-1-1, vocabulary, and EN 40000-1-2, principles, product risk management and lifecycle activities — with more than thirty in development.

Publication by the standards bodies is not citation in the Official Journal, and only citation confers the presumption of conformity. Those two are also the vocabulary and the principles rather than the operative parts: vulnerability handling and the generic security requirements are still in ballot. So the presumption of conformity remains unavailable to everyone, and conformity still has to be substantiated directly — through the risk assessment and evidence.

That is exactly what this kit does.

---

## Contents

| File | Purpose |
|---|---|
| `sbom_gen.py` | SBOM generator (CycloneDX 1.6) across four ecosystems |
| `ecosystems.py` | Parsers for Gradle (Kotlin/Android, including multi-module projects) and PyPI. Composer and npm are parsed in `sbom_gen.py` |
| `gradle_tree.py` | Parser for a Gradle-resolved dependency tree |
| `vuln_scan.py` | Matches an SBOM's components against OSV.dev's known-vulnerability database |
| `license_enrich.py` | Resolves licenses for an SBOM's Gradle/Maven and Python components — offline Gradle-cache POM walk, optional PyPI metadata lookup — and writes them back onto the SBOM |
| `annex_i.yaml` | Matrix of 21 essential requirements: 13 from Part I, 8 from Part II |
| `validate.py` | Integrity check for the matrix |
| `risks.yaml` | Risk assessment: assets, trust boundaries, threats, controls |
| `risk_report.py` | Cross-check of risks against the matrix; renders section 3 |
| `product.yaml` | Data for sections 1, 2, 4, 5, 6 and the declaration |
| `reporting.yaml` | Article 14 reporting runbook: triggers, deadlines, filer, CSIRT contact, templates, readiness checklist |
| `reporting_report.py` | Completeness check of the runbook; renders it as appendix A |
| `build.py` | Assembles the technical file and declaration into Markdown, PDF, HTML |
| `doc.css` | HTML styling: one file, no external resources, no cookies |

---

## Usage

```bash
# 1. SBOM from the product repository
python3 sbom_gen.py /path/to/product \
    --name "MyProduct" --version "1.2.3" \
    --supplier "Acme Sp. z o.o." \
    -o out/sbom.cdx.json

# 1a. Android: a fully resolved tree instead of just the top level
#     first, on the build machine:
#     ./gradlew :app:dependencies --configuration prodReleaseRuntimeClasspath > deps.txt
python3 sbom_gen.py /path/to/app \
    --name "MyApp" --version "1.2.39" \
    --gradle-tree deps.txt \
    --gradle-configuration prodReleaseRuntimeClasspath \
    -o out/sbom.cdx.json

# 1a'. Or point at a multi-module Gradle project's repo root directly — every
#      module declared in settings.gradle.kts is discovered and parsed on its
#      own (static, top-level only; prefer 1a above when a resolved tree is
#      available). A genuinely dependency-free target needs --allow-empty,
#      otherwise a zero-component result is refused (E-SBOM-01) rather than
#      silently written.
python3 sbom_gen.py /path/to/multi-module-project \
    --name "MyApp" --version "1.2.39" \
    -o out/sbom.cdx.json

# 1a''. Python: a fully resolved environment instead of just requirements.txt
#       first, inside the real target environment/container:
#       pip freeze > freeze.txt
python3 sbom_gen.py /path/to/backend \
    --name "MyBackend" --version "4.2.0" \
    --pip-freeze freeze.txt \
    -o out/sbom.cdx.json

# 1b. Match the SBOM against known vulnerabilities (OSV.dev)
python3 vuln_scan.py --sbom out/sbom.cdx.json -o out/

# 1c. Resolve licenses for the SBOM's Gradle/Maven + Python components
#     (offline Gradle-cache POM walk; writes a new file, never overwrites
#     the input unless --in-place is passed)
python3 license_enrich.py --sbom out/sbom.cdx.json \
    --gradle-cache ~/.gradle/caches/modules-2/files-2.1 \
    -o out/sbom.enriched.cdx.json

# 2. Validate the requirements matrix
python3 validate.py annex_i.yaml

# 3. Cross-check risks against requirements
python3 risk_report.py -o out/section3.md

# 3a. Check the Article 14 reporting runbook for completeness (optional)
python3 reporting_report.py -o out/appendix_a.md

# 4. Build the pack
python3 build.py --sbom out/sbom.cdx.json -o out --pdf
```

See **Prerequisites** above.

---

## Testing

```bash
pip install -r requirements-dev.txt
pytest
```

The unit tests use small, hand-built fixtures under `tests/fixtures/` rather than captured production data, so the suite runs in under a second and carries nothing product-specific.

**Mocked-network-only: no test in this suite makes a live call to OSV.dev, PyPI, or a Maven repository.** Every `vuln_scan.py` test monkeypatches `urllib.request.urlopen` (or the `osv_post` seam directly above it); `license_enrich.py` tests that exercise the network-shaped Gradle POM fetch or PyPI lookup monkeypatch the seam functions directly (`fetch_pom_network`, `fetch_pypi_metadata`) instead. An autouse fixture in `tests/conftest.py` fails any test that reaches the real `urlopen` unpatched. The whole suite runs in well under a second, which is itself a signal nothing is hitting the network.

---

## What is checked

The build stops on any of these errors:

| Code | Check |
|---|---|
| `E001` | A requirement is closed with no evidence at all |
| `E002` | A requirement is declared not applicable without a justification |
| `E003` | Contradiction between applicability and status |
| `E004` | Invalid evidence type, or an empty reference |
| `E101` | A risk references a requirement that does not exist |
| `E102` | A risk is not mapped to any requirement |
| `E103` | A rating falls outside the 1..5 range |
| `E104` | Residual risk is below inherent, but no control is stated |
| `E105` | A risk is accepted without a rationale |
| `W201` | A requirement is not covered by any risk — the analysis is incomplete |
| `W300` | `reporting.yaml` is missing — appendix A is omitted, never a build failure |
| `W301`–`W306` | The Article 14 runbook is present but incomplete: no named filer, no deputy, no CSIRT contact, templates unreviewed, no tabletop walkthrough, or the tabletop fields contradict each other |

None of the `W3xx` codes stop the build: an unfilled runbook is a completeness gap, not a contradiction in the technical file itself — it just means the manufacturer is not yet ready to meet the Article 14 clock, which is worth knowing but not worth blocking the rest of the pack over.

`W201` is not a formality. On its first run against a real codebase it found seven requirements that had not been analysed at all: reviewing the code did not surface the process obligations, which relate not to the product but to maintaining it.

---

## Scope and limits

**The tool does not establish conformity.** It helps assemble documentation and check it for internal consistency. The conformity decision is taken by the manufacturer, under their sole responsibility.

**It does not replace:**

- penetration testing or dynamic testing
- legal advice
- assessment by a notified body, where the product is an important product of class I or II under Annex III, or a critical product under Annex IV
- a determination of exploitability — `vuln_scan.py` matches identifiers (purl + version) against OSV.dev, nothing more; whether a matched vulnerability is reachable, whether the vulnerable code path is actually used, and whether it triggers any regulatory reporting duty are judgement calls made by the manufacturer, not by this tool. See "On vulnerability matching" below.
- a live Article 14 reporting pipeline — `reporting.yaml` produces a runbook and draft templates, not a detector, and not a decision about whether the 24-hour clock has started. See "On Article 14 reporting" below.

**Static analysis has limits.** It sees structure, configuration and the set of dependencies. It does not see the behaviour of a running system.

**This is not a scanner.** It does not compete with ORT, syft, cdxgen or any other dependency analyser — they do that job well, and this kit consumes their output. What it does is assemble and check the document those tools do not produce.

---

## Where you will get stuck

Running the tools takes minutes. Filling the four YAML files takes days, and that is not a
defect in the tooling.

`sbom_gen.py`, `license_enrich.py`, `vuln_scan.py` and `build.py` are mechanical: give them
a resolved dependency tree and they produce an SBOM, licence data, vulnerability matches
and a formatted document. Nothing in that chain requires a decision.

`annex_i.yaml`, `risks.yaml`, `product.yaml` and `reporting.yaml` are the opposite. Every
line in them is a judgement: whether an essential requirement is met, what counts as
evidence for it, which risks the product actually carries, what justifies the support
period claimed under Article 13(8). The tool deliberately refuses to guess at any of it — a
requirement cannot be closed without evidence, a risk cannot be lowered without a named
control, and inconsistent data stops the build rather than producing a confident-looking
document.

[`examples/worked-example/`](examples/worked-example/) is what a filled-in one looks like —
a real released product, 31 pages, 278 components, seven of twenty-one requirements closed
and the other fourteen named rather than hidden.

If you would rather someone did that part and put their name on it, that is what we do:
**[factfile.eu](https://factfile.eu)**. The tools stay free either way.

---

## On the SBOM

- The Regulation requires a "commonly used machine-readable format" covering **at the very least the top-level dependencies**. A full transitive tree is not mandatory, but nor is it prohibited — this kit builds the full tree where the input allows it.
- **No format is prescribed.** The implementing act under Article 13(24) that would set one had not been adopted as of November 2026, and Article 13(24) is discretionary — it says the Commission *may* specify the format, with no deadline. Do not treat CycloneDX or SPDX as legally mandatory: the whole of the EU-level specification is the phrase "commonly used and machine-readable format" in Annex I, Part II, point 1. ENISA's Technical Advisory for Software Bill of Materials (v1.10, 22 October 2026) is non-binding and prescribes no format or version either. The only authority naming versions is national — Germany's BSI TR-03183-2, which requires CycloneDX 1.6 or later, or SPDX 3.0.1 or later — and it carries no EU-wide force under the Regulation.
- **The SBOM does not have to be published.** It is retained as part of the technical documentation and made available to the market surveillance authority upon reasoned request.
- Build-time dependencies that are not shipped are excluded: the SBOM describes the product, not the development environment.
- For Gradle projects, prefer `--gradle-tree`. Static parsing of `build.gradle.kts` misses transitive dependencies and cannot resolve versions managed by a platform BOM.
- **Gradle multi-module projects are discovered automatically.** Point `sbom_gen.py` at the repository root and, if a `settings.gradle.kts` / `settings.gradle` is found there, every `include(...)`-declared module's own `build.gradle.kts` is parsed and merged — not just the root file, which in a multi-module project typically only declares plugins and has no `dependencies {}` block of its own. Each component carries a `cra:module` property naming the module it was declared in. Inter-module dependencies (`implementation(project(":other-module"))`) are not third-party components and never appear in the output; `other-module`'s own external dependencies still do, tagged with its name. If the same `group:name@version` is declared by more than one module, it is written once with `cra:module` listing all of them; if two modules genuinely pin different versions of the same `group:name`, both are kept as separate components rather than one being silently dropped.
- **`sbom_gen.py` refuses to write an empty SBOM (error `E-SBOM-01`).** If zero components are found, the run exits non-zero and prints exactly which manifest/lockfile paths were checked and where — an empty file that looks complete (valid CycloneDX, zero components, no warning) is the most dangerous failure mode in the kit: it silently passes as "done" when it usually means the tool was pointed at the wrong directory. Pass `--allow-empty` to write the file anyway, for the genuine case of a dependency-free module.
- **Warning `W-SBOM-02`** fires (without failing the run) when every component in the SBOM is direct — i.e. it came from static parsing of `build.gradle.kts` file(s) rather than a Gradle-resolved tree, so no transitive dependency is present at all. It names the exact `gradlew :<module>:dependencies --configuration <config> > deps.txt` command and the matching `--gradle-tree` / `--gradle-configuration` flags to get full coverage instead.
- **Python: `--pip-freeze` is the PyPI counterpart to `--gradle-tree`, and resolving a Python component set is a mandatory step, not an optional enhancement.** `requirements.txt` is hand-maintained and only ever shows the top-level packages someone chose to pin — a real incident found 27 declared packages against 111 actually resolved and running inside the production container, including security-critical packages (`cryptography`, `PyJWT`, `redis`, `sentry-sdk`) that were completely invisible to a `requirements.txt`-only scan and would have shipped as an SBOM gap in exactly the place Annex I Part II's SBOM requirement exists to close. Because of that, **`sbom_gen.py` treats a declared-only Python component set as a hard failure, `E-SBOM-02`, the same severity class as the empty-SBOM check `E-SBOM-01` — not a softer warning.** It fires whenever any PyPI component came only from static parsing of `requirements.txt` and no `--pip-freeze` was given; the run exits non-zero and no file is written. The fix it names is concrete: on the real target environment/container, run
  ```bash
  pip freeze > freeze.txt
  ```
  then re-run with `--pip-freeze freeze.txt`. `pip freeze` output is a flat list with no tree structure, so `sbom_gen.py` cross-references it against `requirements.txt` (root `requirements.txt` plus every `--pypi` extra) to tell direct from transitive: a package named in a requirements file is tagged `cra:direct=true`, everything else found only in the freeze file is `cra:direct=false` — genuine transitive information, not a guess. When no requirements file is available at all, `cra:direct` is tagged `"unknown"` rather than silently defaulting either way. Every PyPI component also carries `cra:pypi-source`: `"resolved"` when it came from `--pip-freeze`, `"declared"` when it came from `requirements.txt` parsing alone — so a reader of the finished technical file can tell which Python components were confirmed against a real resolved environment versus just declared. When both `--pypi requirements.txt` and `--pip-freeze` are given, the freeze file is authoritative for the component list itself (it reflects what actually runs); the requirements file is used only to inform `cra:direct` tagging, never parsed into a second, duplicate set of components.
  For the genuine case where only a declared scan is available or intended, pass `--declared-only` — this is the explicit, visible admission mirroring `--allow-empty`: it downgrades the check to warning `W-SBOM-03` (same wording, same fix command) and the run still writes the file and exits zero.

---

## Which components belong in the SBOM

A technical file describes one artefact placed on the market, so the SBOM has to describe
that artefact and nothing else. That is narrower than it sounds, and the two common
approaches miss it in opposite directions.

Measured on a released Android application:

| How the components were determined | Distinct libraries |
|---|---|
| Parsing the build files statically | 43 |
| Resolved graph of the shipped release configuration | **242** |
| Union of every resolvable configuration in the project | 381 |

Static parsing misses transitive dependencies and reports the versions the manifests name
rather than the versions that were resolved — ten of the 242 differed.

Taking the union of every configuration adds 139 libraries that are in no shipped binary:
36 test frameworks, 19 annotation processors, debug tooling, and internals of the Android
Gradle Plugin. It also yields 658 entries once differing versions are counted separately,
because the same library resolves differently in different configurations — leaving no
correct answer to "which version is in the product".

Reproduce it on your own project with Gradle alone, no tooling required:

```bash
./gradlew :app:dependencies                                              # every configuration
./gradlew :app:dependencies --configuration prodReleaseRuntimeClasspath  # one release
```

This kit builds from one named configuration: the one the shipped binary came from.

---

## On vulnerability matching

`sbom_gen.py` builds an inventory of what is in the product. It does not check that inventory against a vulnerability database — that is a separate step, `vuln_scan.py`, added on top of the SBOM rather than folded into generation, so the SBOM stays a static description of what shipped and the vulnerability match stays a query result that is only accurate as of the moment it was run.

```bash
python3 vuln_scan.py --sbom out/sbom.cdx.json -o out/
```

- Queries [OSV.dev](https://osv.dev) — Google/OpenSSF's open, free, public vulnerability database. No API key, no auth header, nothing to configure.
- For each component's `purl`, a batch lookup returns the OSV IDs that apply; full records (summary, aliases — this is where a `CVE-XXXX-XXXXX` id usually lives, since OSV and CVE are separate namespaces — severity where the source database rated it, references) are then fetched per unique ID.
- Writes `vulns.json` (structured, one entry per affected component) and `vuln_report.md` (a summary table, a findings table sorted by severity, and — importantly — a table of components whose lookup itself failed or was inconclusive, so a network error or an unrecognised package type is never silently reported as "clean").
- **What it does not do:** it does not determine whether a matched vulnerability is exploitable in this product, it does not compute a numeric CVSS score from a raw CVSS vector (a source database's own qualitative rating — GHSA's LOW/MODERATE/HIGH/CRITICAL and similar — is used when present; a bare CVSS vector is reported verbatim, not scored), and a match does not by itself constitute a reportable incident under Article 14. `vuln_report.md` carries this disclaimer at the top and it should not be stripped when the report is repackaged elsewhere.
- Coverage matches what `sbom_gen.py` emits today (composer, npm, maven, pypi purls) — OSV resolves the `purl` field directly for these, confirmed by live testing against `api.osv.dev`. A purl type OSV does not recognise is reported as an inconclusive lookup, not silently treated as vulnerability-free.

---

## On license enrichment

`sbom_gen.py` records a component's *declared* license only where the ecosystem's own lockfile already states one — composer and npm. Gradle/Maven and Python components come out of SBOM generation with no `licenses` field at all; resolving those is a separate step.

```bash
python3 license_enrich.py --sbom out/sbom.cdx.json \
    --gradle-cache ~/.gradle/caches/modules-2/files-2.1 \
    -o out/sbom.enriched.cdx.json

# strictly local, no network call for the Gradle side
python3 license_enrich.py --sbom out/sbom.cdx.json --offline
```

- **Gradle/Maven: three sources, tried in order, each one only consulted when the previous came up empty for a component.**
  1. **Local Gradle module cache** (`~/.gradle/caches/modules-2/files-2.1`) — populated by the normal build that produced the product, so it is already there. When a component's own POM has no `<licenses>` block but does have a `<parent>`, the parent POM is walked recursively (capped at 3 hops).
  2. **Network POM fetch — on by default.** A large share of components have only a downloaded `.aar`/`.jar` in the local cache with no adjacent `.pom`: Gradle resolved them via Gradle Module Metadata (a `.module` file elsewhere in the cache, which this tool does not parse), not a direct POM download. The POM still exists on the origin repository, so it is fetched (XML metadata only — **never** a `.jar`/`.aar`) and cached to disk under `--maven-fetch-cache` (default: `<sbom-dir>/maven-fetch-cache`) so a re-run never re-fetches. `androidx.*` / `com.google.android.*` / `com.android.*` groups are routed to Google's Maven repo (`dl.google.com/dl/android/maven2/`) first; everything else to Maven Central (`repo1.maven.org/maven2/`) first — either way, the other repository is tried as a fallback before giving up. **Pass `--offline` to disable this and stay strictly local** — the same shape as `--offline-python` on the Python side. On a real 129-component Android SBOM, 84 components resolved straight from the local cache and a further 45 needed this network fetch (44 directly, 1 — `com.google.guava:listenablefuture` — via a parent hop reached only after its own POM was fetched over the network, confirming parent-walk isn't wired only to the local-cache path).
  3. **Archive fallback, last resort** — only reached when *neither* the cache nor the network produced a POM. Opens the component's own cached `.jar`/`.aar` (local cache only; this step never downloads an artifact) as a zip and looks for an embedded `META-INF/maven/**/pom.xml` (parsed the same way as a regular POM), then a `Bundle-License` header in `META-INF/MANIFEST.MF` (the OSGi convention). On the same real SBOM, running with `--offline` (no network at all) still resolved 2 of the 45 network-only cases this way — `com.google.code.gson:gson` and `com.google.errorprone:error_prone_annotations` — purely from their locally-cached jars.
- **Python: PyPI JSON API** (metadata only, no package download), skippable with `--offline-python`.
- **Three `cra:license-status` outcomes, never collapsed into two.** A raw license string that was found but does not map to a known SPDX id (`licenses: [{"license": {"name": "<raw text>"}}]`, `cra:license-status=unmatched`) is not the same fact as nothing being found at all (no `licenses` key, `cra:license-status=none`) — a real, specific, non-SPDX license (e.g. Google Play Core's "Play Core Software Development Kit Terms of Service") needs to read as exactly that in the technical file, not as "unknown". A matched license gets `licenses: [{"license": {"id": "<spdx>"}}]`, `cra:license-status=resolved`; a dual/multi-license POM keeps every license entry rather than picking one (`cra:license-status=partial` when only some of them matched an SPDX id).
- **Six `cra:license-source` values — the fix for a real failure mode.** An earlier version of this tool wrote a single flat `none` for every "nothing found" component, which reads to a customer exactly like "you have a legal problem" — indistinguishable from a component that was actually checked and confirmed to declare no license. The six values below are never collapsed:

  | Value | Meaning |
  |---|---|
  | `pom:gradle-cache` | found directly on the component's own POM in the local Gradle cache |
  | `pom:parent` | found by walking up to a parent POM (one or more `<parent>` hops, from either the local cache or the network) |
  | `pom:fetched` | the component's own POM was not in any local cache; found after a network fetch |
  | `archive:manifest` | found by opening the component's own `.jar`/`.aar` (embedded `pom.xml` or a `Bundle-License` manifest header) |
  | `none:not-declared` | a real, findable source (a POM, a POM reached via a fully-walked parent chain, or an archive) **was read successfully**, and it genuinely declares no license — a fact about the component |
  | `unknown:not-determined` | no source could be found or read at all — missing from the cache, not fetchable over the network, no usable archive, a parse error, `--offline` with nothing local, or PyPI metadata absent/errored/`--offline-python` — a gap in *our* data, never a statement about the component |

  The distinction between the last two is the entire point of this design: a report showing "45 components, unknown license" reads as a legal red flag, when the underlying truth on a real SBOM was closer to "0 components confirmed license-less; we simply couldn't determine some of them, and after the network fetch and archive fallback, usually very few." `license_enrich.py`'s summary output reports these as two separate counts (`confirmed no license declared` vs `could not be determined`) rather than one bucket, and any downstream report built from the enriched SBOM should preserve that split rather than merging it back into "unknown".
- **Never invents an SPDX id.** The raw-string → SPDX table only maps strings actually observed in the wild; anything it does not recognise is left as raw text with an empty `spdx`/`id` field rather than guessed.
- Writes a new file by default (`<name>.enriched.cdx.json`, next to the input) — pass `--in-place` to overwrite `--sbom` directly. Re-running on an already-enriched SBOM is safe: it replaces its own `cra:license-*` properties rather than accumulating duplicates.

---

## On Article 14 reporting

Article 14 requires manufacturers to report actively exploited vulnerabilities and severe incidents to ENISA and the relevant national CSIRT on a strict clock — 24-hour early warning, 72-hour full notification, and a final report (14 days after a fix is available, for a vulnerability; one month after the 72-hour notification, for an incident). This obligation has applied since 11 September 2026.

`reporting.yaml` + `reporting_report.py` produce **appendix A** of the technical file: a runbook, not a live pipeline. It states the two triggers precisely enough that a CVE sitting in the SBOM is not mistaken for the clock having started, lays out the deadline stages for each, and holds a named filer, a deputy, the process for identifying the applicable CSIRT, and four draft notification templates with bracketed placeholders for facts only knowable at the time of a real event.

**What it does not do:**

- It does not detect an actively exploited vulnerability or a severe incident — no scanner, no feed, no monitoring.
- It does not decide when the 24-hour clock starts. Whether exploitation is real and is happening in this specific product is a judgement call made by a human, at the time — never inferred from a CVE identifier or a dependency's status.
- It does not identify which CSIRT is the manufacturer's coordinator, or invent a contact for one. That depends on facts only the manufacturer has, and cra-kit will not fabricate regulatory contact information.
- It does not submit anything to ENISA or a CSIRT. The templates are drafts to fill in and send by hand, not an integration with the Article 16 single reporting platform.

`reporting.yaml` is optional. A build with no runbook at all still succeeds — `build.py` prints a `W300` warning and omits appendix A, the same "warn, don't block" treatment `risk_report.py` gives an incomplete risk assessment.

---

## Example

**[`examples/worked-example/`](examples/worked-example/)** — the pack for a real released
product: a household inventory tracker shipped as an Android client, an iOS client and the
backend both require. The four YAML files, the SBOM they were built against, and the
output. The manufacturer and the product identifiers are anonymised; the component set, the
evidence, the gaps and the warnings are the real ones.

Rebuild it from the repository root:

```bash
python3 build.py --config-dir examples/worked-example \
                 --sbom examples/worked-example/sbom.cdx.json \
                 -o out --pdf
```

31 pages, 278 components, **7 of the 21 essential requirements met, 4 in progress, 10 not
met.** Every one of the fourteen that are not closed carries a named gap. The build prints
five `W3xx` warnings because the Article 14 runbook has no named filer and no completed
walkthrough — which is the product's true state, so it is what the document says.

**The declaration of conformity refuses to be signed.** Field 5, the statement of
conformity, holds what `build.py` writes when the requirements matrix does not support one:
*"NOT ISSUED… A declaration of conformity issued against this evidence would be false."*
The document that carries legal weight is the one the tool is least willing to fake.

Two further findings are the kind a questionnaire does not produce: the SBOM's licence data
is determined for 4 of 278 components, and `pymupdf 1.27.2.3` is AGPL-3.0-or-later inside a
network-facing backend serving proprietary clients. Both are named in the technical file
itself rather than left for a reader to find.
[`examples/worked-example/README.md`](examples/worked-example/README.md) walks through them.

A worked example with twenty-one green rows would demonstrate nothing but a willingness to
fill in twenty-one rows. Partway through is where every manufacturer reading this is.

Two small fixture sets show the mechanics in isolation:
`tests/fixtures/build_happy/` is a minimal valid set that builds, and
`tests/fixtures/build_contradictory/` is what the integrity check rejects, and why.

---

## Licence

MIT. See `LICENSE`.

Security issues: see `SECURITY.md` — reports go to security@factfile.eu.
