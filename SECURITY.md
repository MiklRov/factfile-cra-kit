# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities to **security@factfile.eu**.

Please include enough detail to reproduce the issue: the affected version or commit,
the input that triggers it, and what you observed. A proof of concept helps but is not
required.

Do not open a public issue for a suspected vulnerability. Use the address above, or
GitHub's private security advisory form on this repository.

## What to expect

| | |
|---|---|
| Acknowledgement of your report | within 3 working days |
| Initial assessment | within 10 working days |
| Fix or a stated plan | within 90 days of the initial assessment |

If a report is valid and you would like to be named, you will be credited in the
advisory. If you would rather not be, say so and you will not be.

This project is maintained by one person. These are the periods actually intended to be
met, not aspirational ones — if a deadline is going to slip, you will be told rather
than left waiting.

## Scope

In scope: the tooling in this repository — SBOM generation, dependency resolution,
vulnerability matching, validation and document assembly.

Out of scope: the content of any technical documentation produced with these tools. A
document that states something incorrect about a product is a data problem in that
product's input files, not a vulnerability in the tooling. Report those as ordinary
issues.

Also out of scope: findings from automated scanners submitted without a working
reproduction.

## Disclosure

Fixed vulnerabilities are published as GitHub security advisories with a CVE requested
where one is warranted, and are listed in the release notes for the version that
contains the fix.

We ask for coordinated disclosure: give us the periods above before publishing. If a
vulnerability is being actively exploited, say so in the first message and the clock
changes — that case is handled immediately.
