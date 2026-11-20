# Worked example

The Annex VII pack for a real released product, built by `cra-kit` from the sources in this
folder. Nothing here is illustrative — it is the output of the tool on a real input,
including the parts that came out unflattering.

**The product and the manufacturer are anonymised.** The legal name, the registered
address, the business-register entry, the tax identification number, the store identifiers
and the hostnames are replaced with placeholders, and hosts use the reserved `.invalid`
domain so they can never resolve. Everything else is unchanged: the component set, the
evidence, the risk assessment, the gaps and the warnings are the real ones.

## Rebuild it

From the repository root:

```bash
python3 build.py --config-dir examples/worked-example \
                 --sbom examples/worked-example/sbom.cdx.json \
                 -o out --pdf
```

Omit `--pdf` if pandoc and xelatex are not installed; nothing is lost but the typesetting.

## What is in this folder

| Input | |
|---|---|
| `product.yaml` | Product description, manufacturer, intended use, support period, Article 13(8) justification |
| `annex_i.yaml` | The 21 essential requirements, each with a status, evidence and — where not met — a named gap |
| `risks.yaml` | Risk assessment: threats, controls, residual risk |
| `reporting.yaml` | Article 14 reporting runbook (appendix A) |
| `sbom.cdx.json` | CycloneDX 1.6, 278 components |

| Output | |
|---|---|
| `technical_file.md` / `.html` / `.pdf` | The technical file, 31 pages |
| `declaration_of_conformity.md` / `.html` / `.pdf` | The declaration, 2 pages |

## The product

A household inventory and expiry tracker: an Android client, an iOS client and the backend
service both require, distributed through the App Store and Google Play. One three-part
product under the Regulation, which is why every component in the SBOM carries a `cra:part`
property — 242 Maven, 32 PyPI, 4 Swift.

## The declaration refuses to be signed

Read `declaration_of_conformity.md` first. Field 5, the statement of conformity, does not
contain a statement of conformity. It contains this:

> NOT ISSUED. This declaration is a draft and must not be signed in its present state.
> Several essential requirements relating to vulnerability handling are recorded as not met
> in the requirements matrix, and the gaps in section 6 are open. A declaration of
> conformity issued against this evidence would be false.

That text is not boilerplate and it was not written by hand for this example. It is what
`build.py` produces when the requirements matrix it was given does not support a
declaration. The document that carries legal weight is the one the tool is least willing to
fake.

## What the build reports

The integrity check passes. The build then prints five warnings, `W301`–`W305`, and they
are not oversights:

```
W301  no named filer identified — filer.primary.name is a placeholder
W302  no deputy filer identified — filer.deputy.name is a placeholder
W303  CSIRT contact not identified — csirt_contact.identified_csirt is a placeholder
W304  readiness_checklist.templates_reviewed is false
W305  readiness_checklist.tabletop_completed is false
```

The Article 14 runbook exists, states both triggers and all the deadline stages, and holds
four draft notifications — but no human has been named as the filer and no walkthrough has
been run. That is the true state of this product's readiness, so that is what the document
says. `build.py` warns and continues rather than blocking, and the unfilled fields appear
in the finished file as unfilled fields.

## What the requirements matrix says

Of the 21 essential requirements: **7 met, 4 in progress, 10 not met.** Every one of the
fourteen that are not closed carries a named gap rather than an empty cell or an optimistic
status.

Two findings worth reading, because they are the kind a questionnaire does not produce:

- **The SBOM's licence data is incomplete** — of 278 components, 4 carry a determined
  licence. The requirement is still marked `met`, because the Regulation requires a
  machine-readable bill of materials covering at least the top-level dependencies and this
  one covers the full resolved tree; but the gap is named in the evidence itself and again
  in section 6, rather than being left for a reader to discover.
- **`pymupdf 1.27.2.3` is AGPL-3.0-or-later**, a direct dependency of a network-facing
  backend that serves proprietary clients. The network clause is engaged by exactly this
  deployment shape. The technical file records that the licence consequences have not been
  assessed and that replacement is planned — in its own words, because "a bill of materials
  that lists the component without naming the consequence would be a bill of materials that
  hides the finding."

## Why publish an example with fourteen open requirements

Because that is what a technical file looks like partway through, and partway through is
where every manufacturer reading this actually is. A worked example showing twenty-one
green rows would demonstrate nothing except that the author was willing to fill in
twenty-one rows.

The tool's claim is narrow and this folder is the evidence for it: it will assemble,
cross-check and format the document, and it will not let an unsupported claim through. The
judgements — whether a requirement is met, what counts as evidence, what justifies the
support period — stay with the manufacturer. Here they are, written down, including the
ones that read badly.
