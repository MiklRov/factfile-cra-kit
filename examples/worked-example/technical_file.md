---
title: "Technical documentation — Sample Product iOS 1.0.15 (build 9) / Android 1.2.39 (versionCode 79)"
subtitle: "Annex VII to Regulation (EU) 2024/2847"
date: "2026-08-21"
lang: en
---

> **This technical file was assembled by the manufacturer using cra-kit. It is not legal advice and it does not constitute a conformity assessment by a third party. Where a requirement could not be substantiated from the code, the build or a public record, it is recorded as not met or as unconfirmed rather than assumed. Section 6 lists the gaps explicitly.**

\newpage

# 1. General description of the product

**Product:** Sample Product  
**Version:** iOS 1.0.15 (build 9) / Android 1.2.39 (versionCode 79)  
**Type:** Product with digital elements — two mobile applications and the backend service they require  
**Licence:** Proprietary. Free to install, with in-app purchases.

## 1.1 Intended purpose

The product keeps track of food a household already owns and of when it expires. A user photographs a shop receipt; the product extracts the items and files them into named storage locations (fridge, freezer, pantry, medicine cabinet), then reminds the user before something expires. It also maintains a shopping list, a weekly menu and a medication course tracker. The stated aim is to reduce household food waste.

## 1.2 Intended users

Consumers, in a household setting. Multiple people may share one household. The product is sold directly to end users through Apple's App Store and Google Play; it is not deployed or self-hosted by anyone other than the manufacturer, and there is no on-premises or reseller distribution.

## 1.3 Reasonably foreseeable misuse

Two uses are foreseeable and were not designed for. First, the medication course tracker invites use as a clinical adherence tool; it is not one, it makes no clinical claim, and a missed or late reminder must not be relied upon for medication that matters. Second, the receipt scanner accepts any photograph, so users may submit documents that are not receipts — including documents containing payment card numbers or identifiers — which are then transmitted to external processing services named in section 2. The product does not detect or refuse such input.

## 1.4 Note on scope

The product boundary covers three parts: the iOS application, the Android application and the backend service at api.example.invalid.
The backend is inside the boundary because the applications cannot perform their core functions without it. Receipt extraction, the item inventory, medication schedules and reminder times are all resolved server-side; an application without the backend shows a login screen and nothing else. Its dependencies are therefore part of the bill of materials in section 8.
Four external services are outside the boundary and are not part of this product, but they receive user content and are documented in section 2 as external interfaces: Google Gemini and OpenAI (receipt and voice processing), Telegram (authentication and notification delivery) and Sentry (error reports).
The two applications share one backend, one account system and one token format, but they are separate binaries with separate release cycles and separate identifiers. Where a statement in this file is true of only one platform, it says so.

## 1.5 Versions affecting conformity

This file covers iOS 1.0.15, build 9 (placed on the market 1 July 2026, current version published 19 August 2026) and Android 1.2.39, versionCode 79 (current version published 18 August 2026).

Both version identifiers were confirmed against the live store records rather than taken from the repository: the iOS entry against the App Store catalogue, the Android entry against the production track in the Google Play Console. The resolved dependency trees in section 8 were taken from these versions.

The composition of the released iOS 1.0.15 is established from the continuous integration run that produced it, not from a lock file: the repository does not commit Package.resolved. That recovery route expires with the log and is recorded as a gap in section 6.

## 1.6 Information to the user (Annex II)

| Item | Value |
|---|---|
| Manufacturer contact | <manufacturer name> — redacted in this published example. The real file carries the full legal name, the registered address, the national business-register entry and the tax identification number, and the address must match the developer record in both stores. |
| Single point of contact | <to be completed — a stable address for cybersecurity matters, e.g. security@example.invalid. No such address exists today; see section 6.> |
| Product identification | iOS: bundle identifier <ios bundle id>, version 1.0.15 (build 9), App Store ID <app store id>. Android: application identifier <android application id>, version 1.2.39 (versionCode 79), published under the product name. The Android application identifier retains the product's original working name and cannot be changed for a published application; the iOS bundle identifier contains a typographic error in the vendor segment from an earlier company name which likewise cannot be changed. Both are recorded here as they are; the identifiers themselves are redacted in this published example. |
| Intended purpose | Household food inventory and expiry tracking with receipt scanning. |
| Known limitations | The product requires network access and the manufacturer's backend. Receipt and voice processing depend on third-party services; if those are unavailable, the corresponding features do not work. Reminder delivery on Android degrades to an inexact schedule when the exact-alarm permission is not granted. |
| End of support period | 2031-07-01 |
| Security update information | Security updates are delivered as ordinary application updates through the App Store and Google Play, and as server-side changes for the backend. Updates are free of charge. |
| Vulnerability reporting | <to be completed — no published vulnerability reporting channel exists today. See VH-05 and VH-06 in the requirements matrix and the gap list in section 6.> |
| Secure configuration guidance | The product has no user-configurable security settings beyond the platform permissions it requests. Default configuration is the secure configuration; there is nothing for the user to harden. |


\newpage

# 2. Design, development and production

## 2.1 Architecture

Two mobile clients and one backend. The iOS client is written in Swift with SwiftUI (deployment target iOS 16.0); the Android client is written in Kotlin with Jetpack Compose (minimum SDK 26, target SDK 35). Both talk to a single HTTPS API at https://api.example.invalid/api/v1/ and hold no primary data locally: the inventory, medication courses and reminder schedule live server-side.
Authentication is by an opaque token carried in the X-Mobile-Token header. On iOS the token is obtained through Google Sign-In or Sign in with Apple; on Android through Google Sign-In. Telegram is additionally used as an authentication channel per the published privacy policy.
The backend is a Python service. It performs receipt and voice processing by calling external services rather than locally.

Terms under which the external recipients hold this data

Because user content leaves the product boundary at these interfaces, the terms under which the recipients hold it form part of the assessment rather than a commercial footnote. Both providers are used on their paid tiers, evidenced by the billed model identifiers named in services/ai/config.py.

Training. Neither provider uses this data to train models on the paid tier by default. OpenAI's documentation states that "data sent to the OpenAI API is not used to train or improve OpenAI models (unless you explicitly opt in to share data with us)". Google's states that for a billing-enabled project "prompts and responses within logs are not used for product improvement or development". Neither opt-in has been taken.

Retention, which is a separate question and is not zero. OpenAI retains abuse-monitoring logs containing prompts and responses "for up to 30 days". Google retains logs "for a default maximum period of 55 days", configurable down to 7, 14 or 28. So a receipt image submitted today exists outside the manufacturer's control for weeks after the user has forgotten it, and continues to exist there if the user deletes their account in the meantime.

Zero-data-retention controls exist at both providers and are not in use here. OpenAI's require prior approval and additional terms; Google's are available for paid services, with the caveat that certain features retain data regardless. Reducing the Google log window from 55 days to 7 is a configuration change and is the cheapest available reduction of this exposure.

Sources: OpenAI, Data controls in the OpenAI platform; Google, Gemini API Data Logging and Sharing, and Zero data retention in the Gemini Developer API. Retrieved 21 August 2026.

## 2.2 Component integration

The bill of materials in section 8 lists 278 components across the three parts: 4 Swift packages in the iOS client, 242 Maven artefacts in the Android client and 32 Python distributions in the backend.
The iOS figures come from the resolved package graph recorded by the release build; the Android figures from a resolved Gradle dependency tree (configuration prodReleaseRuntimeClasspath), not from parsing build files. The distinction matters: on the Android side, parsing the build files alone yields 43 components against 242 actually resolved.
Eight Android components are proprietary Google Play Services artefacts distributed under the Android Software Development Kit licence rather than an open-source licence. One backend component, pymupdf 1.27.2.3, is licensed AGPL-3.0-or-later; see section 6.

## 2.3 Security-relevant subsystems

| Subsystem | Location | Description |
|---|---|---|
| Authentication and token handling | `data/api/ApiClient.kt · core-design/.../auth/FamilyTokenStore.kt · ios/App/Networking/TokenStore.swift` | Identity through Google Sign-In and Sign in with Apple; an opaque token in the X-Mobile-Token header. The token is bound to the API host by an HTTP interceptor so it cannot leak to another host on a redirect. It is stored unencrypted in the application sandbox. |
| HTTP transport | `data/api/ApiClient.kt · ios/App/Networking/APIClient.swift` | HTTPS only; cleartext traffic is not enabled. No certificate pinning; at target SDK 35 the platform default excludes user-installed certificate authorities. |
| Request logging | `data/api/ApiClient.kt:35` | The HTTP logging interceptor is instantiated only in debug builds and at a level that excludes headers, so authentication material is never written to the system log in a release build. |
| Local storage | `android/app/src/main/AndroidManifest.xml` | allowBackup=false, so the token store cannot be extracted through platform backup. No database is used on the client; primary data lives server-side. |
| Reminder delivery | `reminders/ReminderScheduler.kt · reminders/ReminderAlarmReceiver.kt · reminders/BootReceiver.kt` | Scheduled locally through AlarmManager. The receiver that fires a reminder is not exported; the boot receiver is exported only because the platform requires it to receive BOOT_COMPLETED. Pending intents are immutable. |
| External processing | `services/ai/config.py · backend services/receipts/, services/voice/` | Receipt images and voice recordings are transmitted for processing. Google Gemini is the primary provider (models/gemini-3.6-flash, with models/gemini-3.1-flash-lite as the cheap reserve); OpenAI (gpt-4o-mini and gpt-4o-mini-transcribe) is a cross-provider fallback that fires only during a full Gemini outage and is disabled when no key is configured. Both are used on their paid, billed tiers, which is what determines how the providers treat the data — see 2.6. Telegram carries notifications and one authentication path; Sentry receives error reports. These are the points at which user content leaves the product boundary. |

## 2.4 Production and monitoring

Both applications are built and released by GitHub Actions. The iOS release workflow (ios_deploy.yml) runs on every push touching the iOS sources, resolves Swift packages, signs with a distribution certificate held in repository secrets and uploads to TestFlight.
Neither workflow pins its toolchain: both request the latest stable Xcode. Two builds two days apart in August 2026 used Xcode 16.2 and Xcode 26.6 respectively. The released 1.0.15 was produced by Xcode 26.6. This is recorded as a finding in section 6.
Runtime errors are reported to Sentry.

## 2.5 Vulnerability handling processes (Annex I, Part II)

| Process | Status | Note |
|---|---|---|
| SBOM | met | A machine-readable bill of materials covering all three parts of the product is maintained and is included as section 8. It is generated from resolved build output, not from manifests. Licence data is incomplete: of 278 components, 4 carry a determined licence. Determination for the Maven and PyPI components is a known gap; see section 6. |
| Coordinated vulnerability disclosure policy | not_met | No coordinated vulnerability disclosure policy is published. Neither repository contains a SECURITY.md, and no .well-known/security.txt is served. This is a genuine gap, not an unconfirmed one. |
| Vulnerability reporting channel | not_met | There is no dedicated address for reporting vulnerabilities. The published privacy policy gives a general support address; the Google Play listing gives a personal mailbox. Neither is a security contact. |
| Publication of security advisories | not_met | No security advisories have been published, and there is no channel through which they would be. No vulnerability has been reported to the manufacturer to date. |
| Update distribution | met | Updates are free of charge and are delivered through the platform update mechanisms, which verify package signatures. Users may disable automatic updates at the platform level. Security fixes are not separable from feature releases: a user receives them as part of the next application version. |


\newpage

# 3. Cybersecurity risk assessment

**Product:** Sample Product iOS 1.0.15 / Android 1.2.39  
**Assessment date:** 2026-08-21  
**Method:** STRIDE across trust boundaries; risk rating = likelihood x impact, each 1-5

> This section is drawn up pursuant to Article 13(2) and point 3 of Annex VII to Regulation (EU) 2024/2847.

## 3.1 Limitations of the assessment

- no dynamic testing and no penetration testing
- no assessment of the backend's own infrastructure, hosting or server-side data handling
- no assessment of the external processing services; they are treated as opaque recipients
- the assessment was performed by the manufacturer on its own product and has not been reviewed by a third party

## 3.2 System description

A household food inventory and expiry tracking product consisting of two mobile applications (iOS, Swift and SwiftUI; Android, Kotlin and Jetpack Compose) and the backend service at api.example.invalid that both require. The applications hold no primary data: inventory, medication courses and reminder schedules are resolved server-side. Receipt and voice processing are performed by external services called from the backend. Distribution is through the App Store and Google Play to consumers; there is no self-hosted deployment.

### Entry points

| Ref | Entry point | Location |
|---|---|---|
| EP-1 | Mobile application UI (iOS) | `ios/App/App.swift, AppRouter.swift` |
| EP-2 | Mobile application UI (Android) | `android/app/src/main/AndroidManifest.xml — exported launcher activity` |
| EP-3 | HTTPS API | `https://api.example.invalid/api/v1/` |
| EP-4 | Android boot receiver (exported, BOOT_COMPLETED and MY_PACKAGE_REPLACED) | `reminders/BootReceiver.kt` |
| EP-5 | Camera, photo library, microphone and speech recognition | `ios/App/Info.plist usage descriptions; Android media permissions` |
| EP-6 | Telegram, used for notification delivery and as an authentication channel | `https://example.invalid/privacy` |

### Assets

| Ref | Asset | Properties | Note |
|---|---|---|---|
| A-1 | Receipt images and any other photograph the user submits | C | May contain payment card numbers, addresses or identity documents the product did not ask for |
| A-2 | Voice recordings | C |  |
| A-3 | Medication course data | C, I | Health-adjacent personal data |
| A-4 | Authentication token (X-Mobile-Token) | C | Bearer-equivalent; possession grants account access |
| A-5 | Account and household data — email, name, user and place identifiers, inventory | C, I |  |
| A-6 | Signing identity and store credentials | C, I | Apple distribution certificate and App Store Connect key, held in CI secrets |
| A-7 | Integrity of the released binary and the record of what it contains | I |  |

C — confidentiality, I — integrity, A — availability

### Trust boundaries

- **TB-1** — User device to application
- **TB-2** — Application to backend
- **TB-3** — Backend to external AI processors
- **TB-4** — Backend to Telegram
- **TB-5** — Application and backend to Sentry
- **TB-6** — Build and release pipeline to published artefact
- **TB-7** — Manufacturer to the outside world

## 3.3 Identified risks

| Ref | Risk | STRIDE | Inherent | Residual | Treatment | Requirements |
|---|---|---|---|---|---|---|
| R-01 | Unrelated sensitive documents forwarded to external processors through the receipt scanner | information disclosure | 16 (critical) | 12 (high) | mitigate | EI-07, EI-05 |
| R-03 | The composition of a released version is not recorded | tampering, repudiation | 15 (critical) | 9 (medium) | mitigate | VH-01, EI-06, EI-01 |
| R-05 | A vulnerability report has nowhere to arrive | repudiation | 12 (high) | 12 (high) | accept | VH-05, VH-06 |
| R-07 | AGPL-3.0 component in a network-facing backend serving proprietary clients | repudiation | 12 (high) | 12 (high) | accept | VH-01 |
| R-08 | No function survives loss of the backend or of a third-party processor | denial of service | 12 (high) | 9 (medium) | accept | EI-08 |
| R-16 | No security testing, so vulnerabilities are found by others or not at all | information disclosure, elevation of privilege | 12 (high) | 12 (high) | accept | VH-03, EI-01 |
| R-04 | Build toolchain is not pinned | tampering | 10 (high) | 10 (high) | accept | EI-06 |
| R-11 | No one is designated to file an Article 14 report | repudiation | 10 (high) | 10 (high) | accept | VH-02 |
| R-12 | Signing certificate export password held in plaintext in the release workflow | spoofing, tampering | 10 (high) | 8 (medium) | mitigate | EI-04, EI-06 |
| R-17 | The only update channel is controlled by two third parties | denial of service | 10 (high) | 8 (medium) | mitigate | VH-07, EI-03 |
| R-06 | Users cannot learn that an update contained a security fix | repudiation | 9 (medium) | 6 (medium) | mitigate | VH-04, VH-08 |
| R-14 | Security-relevant events are neither recorded nor surfaced | repudiation | 9 (medium) | 9 (medium) | accept | EI-12, EI-04 |
| R-15 | Data at the external processors is outside both the deletion and the export path | information disclosure | 9 (medium) | 4 (low) | mitigate | EI-13 |
| R-02 | Authentication token stored unencrypted on the device | information disclosure, spoofing | 8 (medium) | 8 (medium) | mitigate | EI-05, EI-04, EI-11 |
| R-09 | Release build without shrinking or obfuscation | information disclosure | 8 (medium) | 8 (medium) | accept | EI-11, EI-10 |
| R-13 | Public contact for the product is a personal mailbox | repudiation | 6 (medium) | 6 (medium) | accept | VH-06 |
| R-18 | Secure defaults are inherited from the platform rather than asserted by the product | tampering, information disclosure | 6 (medium) | 4 (low) | mitigate | EI-02, EI-09 |

## 3.4 Risk detail

### R-01 — Unrelated sensitive documents forwarded to external processors through the receipt scanner

The receipt scanner accepts any photograph and forwards it for processing. A user photographing a bank statement, an identity document or a payment card transmits that image to Google Gemini or OpenAI. The product performs no inspection, no redaction and no refusal. This is the intended flow working exactly as designed on unintended input.

- **Trust boundary:** TB-3
- **Affected assets:** A-1
- **Inherent rating:** likelihood 4 x impact 4 = **16** (critical)
- **Residual rating:** likelihood 4 x impact 3 = **12** (high)
- **Treatment:** mitigate

**Existing controls:**

- The processing is disclosed in the published privacy policy
- Transmission is over HTTPS
- Both providers are used on paid tiers, where per their published terms the data is not used to train models by default and neither opt-in has been taken
- Retention at the providers is bounded rather than indefinite: up to 30 days at OpenAI, a default maximum of 55 days at Google

**Evidence in code:**

- `https://example.invalid/privacy`
- `services/ai/config.py — billed model identifiers`
- `product.yaml section_2.external_processing_terms`

**Rationale:** The likelihood is unchanged: nothing stops a user photographing the wrong document, because the product does not look at what it is sending. What the paid tiers change is the consequence — the image is not absorbed into a training set and it ages out of the providers' logs within weeks. That is a genuine reduction in impact and it is why the residual rating moves, but the requirement in EI-07 is about not sending the data in the first place, and it remains unmet.
Cheapest available further reduction, in order: set the Google log window to 7 days instead of the default 55, which is a configuration change; then a warning at the point of capture; then on-device detection of card-number patterns before upload.

**Covers requirements:** EI-07, EI-05

### R-03 — The composition of a released version is not recorded

The Swift package lock file is not committed. Package versions are resolved afresh on each build machine, so two builds of the same version number may contain different dependency versions. When an advisory lands on a dependency, the manufacturer cannot state from its own records whether a released version is affected.

- **Trust boundary:** TB-6
- **Affected assets:** A-7
- **Inherent rating:** likelihood 5 x impact 3 = **15** (critical)
- **Residual rating:** likelihood 3 x impact 3 = **9** (medium)
- **Treatment:** mitigate

**Existing controls:**

- The release pipeline logs the resolved package graph, so composition is recoverable while the log exists

**Evidence in code:**

- `.github/workflows/ios_deploy.yml — step 'Resolve Swift Package dependencies'`

**Rationale:** Recovery from CI logs worked for 1.0.15 and is recorded in the SBOM, but logs expire. Planned: commit the lock file and publish it as a build artefact on every release.

**Covers requirements:** VH-01, EI-06, EI-01

### R-05 — A vulnerability report has nowhere to arrive

No coordinated disclosure policy is published, no SECURITY.md exists in either repository and no security contact address is served. A researcher who finds a flaw either writes to a general support mailbox, publishes without contact, or does nothing. The manufacturer would learn of the flaw last.

- **Trust boundary:** TB-7
- **Affected assets:** A-5, A-7
- **Inherent rating:** likelihood 3 x impact 4 = **12** (high)
- **Residual rating:** likelihood 3 x impact 4 = **12** (high)
- **Treatment:** accept

**Rationale:** Planned and cheap: a SECURITY.md in both repositories, a .well-known/security.txt on example.invalid, and one stable address that outlives any individual.

**Covers requirements:** VH-05, VH-06

### R-07 — AGPL-3.0 component in a network-facing backend serving proprietary clients

pymupdf 1.27.2.3 is a direct dependency of the backend and is licensed AGPL-3.0-or-later. The network clause of that licence is engaged by exactly this deployment shape: users interact with the software over a network. The licence consequences for the proprietary applications and the backend have not been assessed.

- **Trust boundary:** TB-2
- **Affected assets:** A-7
- **Inherent rating:** likelihood 4 x impact 3 = **12** (high)
- **Residual rating:** likelihood 4 x impact 3 = **12** (high)
- **Treatment:** accept

**Evidence in code:**

- `requirements.txt — pymupdf==1.27.2.3`
- `services/receipts/pdf_render.py — the only usage site`

**Rationale:** Replacement with a permissively licensed renderer is planned; the usage is confined to one module of about sixty lines with three call sites, so the change is contained. Recorded here because a bill of materials that lists the component without naming the consequence would be a bill of materials that hides the finding.

**Covers requirements:** VH-01

### R-08 — No function survives loss of the backend or of a third-party processor

The applications store no primary data locally. If the backend is unavailable the product shows a login screen; if Gemini or OpenAI is unavailable, receipt and voice capture fail. Medication reminders are scheduled from a server-resolved queue, so an outage spanning the daily refresh silently stops reminders the user is relying on.

- **Trust boundary:** TB-3
- **Affected assets:** A-5, A-3
- **Inherent rating:** likelihood 3 x impact 4 = **12** (high)
- **Residual rating:** likelihood 3 x impact 3 = **9** (medium)
- **Treatment:** accept

**Existing controls:**

- Android re-arms alarms after reboot and re-schedules from a cached daily queue

**Evidence in code:**

- `reminders/ReminderScheduler.kt, reminders/BootReceiver.kt`

**Rationale:** No offline mode, no degraded read-only view and no user-visible signal that reminders have stopped. The last point is the one that matters most, because a silent failure of a medication reminder is worse than a visible one.

**Covers requirements:** EI-08

### R-16 — No security testing, so vulnerabilities are found by others or not at all

No penetration test, no external assessment and no recurring security review has been performed on either client or the backend. Functional tests and linters do not look for security defects. A vulnerability in the product would therefore be discovered by a user, a researcher or an attacker before it was discovered by the manufacturer — and, per R-05, the first two have no way to report it.

- **Trust boundary:** TB-2
- **Affected assets:** A-5, A-4, A-1
- **Inherent rating:** likelihood 3 x impact 4 = **12** (high)
- **Residual rating:** likelihood 3 x impact 4 = **12** (high)
- **Treatment:** accept

**Existing controls:**

- Component versions are matched against the OSV database, which covers known defects in dependencies but nothing in the product's own code
- Android lint runs in the release build

**Evidence in code:**

- `vuln_scan.py against sbom.cdx.json`

**Rationale:** Accepted for now and named as the largest single blind spot in this assessment. Dependency scanning covers borrowed code; nothing covers the code written here. A first external assessment is the highest-value item on the roadmap.

**Covers requirements:** VH-03, EI-01

### R-04 — Build toolchain is not pinned

Both release workflows request the latest stable Xcode rather than a fixed version. Two builds two days apart in August 2026 used Xcode 16.2 and Xcode 26.6. The production process described in the technical file therefore does not describe a reproducible build, and a compiler change between releases is invisible in the release record.

- **Trust boundary:** TB-6
- **Affected assets:** A-7
- **Inherent rating:** likelihood 5 x impact 2 = **10** (high)
- **Residual rating:** likelihood 5 x impact 2 = **10** (high)
- **Treatment:** accept

**Rationale:** Planned: pin an explicit Xcode version in both workflows and raise it by deliberate commit.

**Covers requirements:** EI-06

### R-11 — No one is designated to file an Article 14 report

Article 14 has applied since 11 September 2026 and allows twenty-four hours for an early warning. No filer and no deputy are designated, the relevant CSIRT has not been identified, no account exists on the Single Reporting Platform, and there is no recorded criterion or owner for deciding that exploitation is real. The clock would start retroactively with nothing to show when.

- **Trust boundary:** TB-7
- **Affected assets:** A-5
- **Inherent rating:** likelihood 2 x impact 5 = **10** (high)
- **Residual rating:** likelihood 2 x impact 5 = **10** (high)
- **Treatment:** accept

**Evidence in code:**

- `reporting.yaml — the runbook exists but its fields are unfilled`

**Rationale:** Low likelihood, severe consequence, and cheap to fix: naming two people and identifying one CSIRT closes most of it. Nothing here requires engineering work.

**Covers requirements:** VH-02

### R-12 — Signing certificate export password held in plaintext in the release workflow

The iOS release workflow imports the distribution certificate using a password written literally into the workflow file. The certificate itself comes from a repository secret, so the password alone grants nothing, but it removes the second factor: anyone obtaining the encrypted certificate also has what unlocks it.

- **Trust boundary:** TB-6
- **Affected assets:** A-6
- **Inherent rating:** likelihood 2 x impact 5 = **10** (high)
- **Residual rating:** likelihood 2 x impact 4 = **8** (medium)
- **Treatment:** mitigate

**Existing controls:**

- The certificate is stored as a repository secret, not in the repository
- The keychain created during the build is temporary and scoped to the runner

**Evidence in code:**

- `.github/workflows/ios_deploy.yml — step 'Install Apple Certificate'`

**Rationale:** Planned: move the export password into a repository secret. One line.

**Covers requirements:** EI-04, EI-06

### R-17 — The only update channel is controlled by two third parties

Security updates reach users solely through the App Store and Google Play. If either listing is suspended — for a policy breach, an expired agreement, a broken privacy-policy link, or a developer-account problem — the manufacturer loses the ability to ship a security fix to that platform's users entirely, and has no side channel to reach them. Suspension does not require any fault in the software itself: a policy change, an expired developer agreement or an account issue is enough.

- **Trust boundary:** TB-7
- **Affected assets:** A-7, A-5
- **Inherent rating:** likelihood 2 x impact 5 = **10** (high)
- **Residual rating:** likelihood 2 x impact 4 = **8** (medium)
- **Treatment:** mitigate

**Existing controls:**

- Both platforms verify package signatures and support automatic update, so a shipped fix reaches users quickly
- Backend fixes reach all users without any store involvement

**Evidence in code:**

- `.github/workflows/ios_deploy.yml`

**Rationale:** The backend path gives partial coverage: a server-side mitigation can be deployed without the stores. Client-side fixes have no alternative route. Keeping both listings in good standing is therefore a security control, not only a commercial matter.

**Covers requirements:** VH-07, EI-03

### R-06 — Users cannot learn that an update contained a security fix

No advisory accompanies any release. A user cannot tell whether a given version fixed something that affects them, and therefore cannot judge the urgency of updating or take any compensating action.

- **Trust boundary:** TB-7
- **Affected assets:** A-5
- **Inherent rating:** likelihood 3 x impact 3 = **9** (medium)
- **Residual rating:** likelihood 3 x impact 2 = **6** (medium)
- **Treatment:** mitigate

**Existing controls:**

- Platform automatic update, where the user has left it enabled, delivers fixes without the user needing to decide

**Rationale:** Automatic update reduces impact but does not satisfy the disclosure requirement, which is separate.

**Covers requirements:** VH-04, VH-08

### R-14 — Security-relevant events are neither recorded nor surfaced

Authentication failures, sign-in from a new device, household membership changes and data access are not recorded as security events and are never shown to the user. An account accessed with a stolen token leaves no trace the user could see, and the manufacturer has no record from which to reconstruct what happened after an incident.

- **Trust boundary:** TB-2
- **Affected assets:** A-5, A-4
- **Inherent rating:** likelihood 3 x impact 3 = **9** (medium)
- **Residual rating:** likelihood 3 x impact 3 = **9** (medium)
- **Treatment:** accept

**Existing controls:**

- Sentry receives runtime errors, which is unrelated to security event recording but would capture some anomalous failures

**Rationale:** This is the requirement with the largest gap between what exists and what Annex I asks for, and closing it is backend work rather than a configuration change.

**Covers requirements:** EI-12, EI-04

### R-15 — Data at the external processors is outside both the deletion and the export path

Deletion and export are both implemented for data the manufacturer holds: an export endpoint returns the caller's own data in machine-readable and human-readable form, and an account deletion endpoint exists which the manufacturer attests has been verified end to end. Two things remain open.
The deletion verification is the manufacturer's own and has not been audited by anyone else. And data already transmitted to Google Gemini, OpenAI or Sentry sits outside both paths: it is neither exported to the user nor removed when the account is deleted. That tail is bounded rather than open-ended — the providers' published retention windows are 30 and 55 days — but during those weeks a user who has deleted their account still has a copy of their receipt sitting somewhere they were never told about in those terms.

- **Trust boundary:** TB-2
- **Affected assets:** A-1, A-2, A-3, A-5
- **Inherent rating:** likelihood 3 x impact 3 = **9** (medium)
- **Residual rating:** likelihood 2 x impact 2 = **4** (low)
- **Treatment:** mitigate

**Existing controls:**

- GET /profile/export returns the caller's own data as JSON and HTML, scoped to the user and excluding credentials and other users' rows
- DELETE /profile exists and is reachable from the client
- The manufacturer attests that end-to-end deletion has been verified and the verification recorded

**Evidence in code:**

- `api/routers/profile.py:693`
- `data/api/MedicineApiService.kt`
- `annex_i.yaml EI-13 — customer attestation, 21 August 2026, unverified`

**Rationale:** What the manufacturer holds is covered, and the export path was verified in code rather than taken on trust. The residual risk is now almost entirely about the external processors: a user who deletes their account has no assurance about the copy of their receipt image that Gemini or OpenAI received. Closing it does not require a negotiation: the retention windows are published, the Google one is configurable down to 7 days, and stating both in the privacy policy would turn an unknown into a disclosed limit.

**Covers requirements:** EI-13

### R-02 — Authentication token stored unencrypted on the device

The token is written to a DataStore preferences file in plaintext. Anyone able to read the application's sandbox — a rooted or jailbroken device, a forensic image, a malicious application exploiting a platform flaw — obtains a credential that grants full account access, and there is no server-side signal that it was taken.

- **Trust boundary:** TB-1
- **Affected assets:** A-4, A-5
- **Inherent rating:** likelihood 2 x impact 4 = **8** (medium)
- **Residual rating:** likelihood 2 x impact 4 = **8** (medium)
- **Treatment:** mitigate

**Existing controls:**

- Platform application sandbox
- allowBackup=false prevents extraction through platform backup
- The token is bound to the API host by the HTTP interceptor, so it cannot leak on a redirect

**Evidence in code:**

- `android/app/src/main/AndroidManifest.xml`
- `core-design/src/main/java/com/example/coredesign/auth/FamilyTokenStore.kt`
- `data/api/ApiClient.kt`

**Rationale:** The sandbox and the backup setting cover the ordinary case. They do not cover a compromised device. The platform keystore is not used, and no server-side token binding or revocation on anomaly exists.

**Covers requirements:** EI-05, EI-04, EI-11

### R-09 — Release build without shrinking or obfuscation

The Android release build sets isMinifyEnabled = false. Class names, endpoint paths, request models and the token header name are readable directly from the package, which lowers the effort required to explore the API surface.

- **Trust boundary:** TB-1
- **Affected assets:** A-7, A-5
- **Inherent rating:** likelihood 4 x impact 2 = **8** (medium)
- **Residual rating:** likelihood 4 x impact 2 = **8** (medium)
- **Treatment:** accept

**Existing controls:**

- The API enforces authorisation server-side; readability of the client does not confer access

**Evidence in code:**

- `android/app/build.gradle.kts`

**Rationale:** Accepted with justification: obfuscation is not a security control, and treating it as one would be security through obscurity. It is recorded because it affects the effort side of the equation, not because its absence is a defect.

**Covers requirements:** EI-11, EI-10

### R-13 — Public contact for the product is a personal mailbox

The contact published in the store listing is an individual's personal address rather than a role address belonging to the manufacturer. It does not survive a change of person, is not monitored as a security channel, and does not satisfy the requirement for a contact point at which the manufacturer can be reached about vulnerabilities.

- **Trust boundary:** TB-7
- **Affected assets:** A-5
- **Inherent rating:** likelihood 3 x impact 2 = **6** (medium)
- **Residual rating:** likelihood 3 x impact 2 = **6** (medium)
- **Treatment:** accept

**Rationale:** Planned together with R-05: one role address, published in both stores, in the policy and in SECURITY.md.

**Covers requirements:** VH-06

### R-18 — Secure defaults are inherited from the platform rather than asserted by the product

Several protections in this assessment are platform behaviour, not product code: user certificate authorities are excluded because the Android target SDK is 35, transport is protected because the platform enforces it, and the application sandbox isolates the token store. A change of target SDK, a platform policy change, or running on an older or modified system weakens these without any change to the product, and nothing in the product would detect or report it.

- **Trust boundary:** TB-1
- **Affected assets:** A-4, A-5
- **Inherent rating:** likelihood 2 x impact 3 = **6** (medium)
- **Residual rating:** likelihood 2 x impact 2 = **4** (low)
- **Treatment:** mitigate

**Existing controls:**

- Target SDK 35 and minimum SDK 26 on Android; deployment target iOS 16 on the client
- allowBackup=false is an explicit product setting rather than an inherited default
- The API base URL is HTTPS in code, independent of platform policy

**Evidence in code:**

- `android/app/build.gradle.kts`
- `android/app/src/main/AndroidManifest.xml`
- `data/api/ApiClient.kt`

**Rationale:** Recorded so the technical file does not present platform behaviour as product design. No certificate pinning and no runtime integrity check is implemented; the mitigation is that the few settings that are the product's own are set explicitly rather than left to default.

**Covers requirements:** EI-02, EI-09

## 3.5 Annex I requirement coverage

| Requirement | Title | Risks |
|---|---|---|
| EI-01 | No known exploitable vulnerabilities | R-03, R-16 |
| EI-02 | Secure by default configuration | R-18 |
| EI-03 | Vulnerabilities addressed through security updates | R-17 |
| EI-04 | Protection from unauthorised access | R-02, R-12, R-14 |
| EI-05 | Confidentiality of data | R-01, R-02 |
| EI-06 | Integrity of data | R-03, R-04, R-12 |
| EI-07 | Data minimisation | R-01 |
| EI-08 | Availability of essential functions | R-08 |
| EI-09 | No adverse effect on availability of other devices or networks | R-18 |
| EI-10 | Limitation of attack surface | R-09 |
| EI-11 | Mitigation of the impact of exploitation | R-02, R-09 |
| EI-12 | Recording and monitoring of security-relevant activity | R-14 |
| EI-13 | Data deletion and portability | R-15 |
| VH-01 | Identification of components and the SBOM | R-03, R-07 |
| VH-02 | Addressing vulnerabilities without delay | R-11 |
| VH-03 | Regular security testing and review | R-16 |
| VH-04 | Public disclosure of fixed vulnerabilities | R-06 |
| VH-05 | Coordinated vulnerability disclosure policy | R-05 |
| VH-06 | Channel for receiving vulnerability reports | R-05, R-13 |
| VH-07 | Secure distribution of updates | R-17 |
| VH-08 | Timely, free-of-charge updates with a security advisory | R-06 |


\newpage

# 4. Support period

**Support period:** 5 years  
**End date:** 2031-07-01  
**Availability of issued updates:** no less than 5 years

## 4.1 Rationale

Five years from the date the product was first placed on the market, 1 July 2026. The Regulation sets five years as the floor unless the expected product lifetime is shorter; the manufacturer does not consider it shorter. A household inventory application is used for as long as the household keeps using it, and no shorter service life is claimed.
The binding practical constraint is the mobile platform, not the product: the iOS client targets iOS 16 and above and the Android client API 26 and above, and both platform vendors withdraw support for older releases on their own schedule. The manufacturer commits to the five-year period for the product as released; users running an operating system version that has itself left support may be unable to receive updates for reasons outside the manufacturer's control, and this is stated in the user information.

## 4.2 Factors considered (Article 13(8))

| Factor | Assessment |
|---|---|
| The statutory floor | Article 13(8) sets five years unless the expected product lifetime is shorter. The manufacturer does not consider it shorter and claims no shorter service life. |
| Mobile platform support | The binding practical constraint. The clients target iOS 16 and API 26 upward; both platform vendors withdraw support for older releases on their own schedule, which the manufacturer does not control. |
| Runtime and framework support | Swift, Kotlin and Python major versions, and the Compose and SwiftUI framework generations in use, each have their own support horizon shorter than five years. |
| Dependence on a manufacturer-operated backend | The applications do not function without it, so the support commitment is also a commitment to keep a service running for five years, not only to ship patches. |
| Dependence on third-party processors | Two core features depend on Google Gemini and OpenAI. Their availability, pricing and terms are outside the manufacturer's control for the whole period. |
| Commercial expectation | The product is sold with in-app purchases including subscription tiers, which creates a user expectation of continued service independent of the Regulation. |
| Size of the manufacturer | A sole proprietorship. A five-year commitment is a real constraint rather than a formality, and is stated deliberately rather than by default. |

## 4.3 End-of-support notification

<to be completed — the product does not currently notify users when support ends, and no mechanism to do so exists. The support period is stated in the user information but is not surfaced in the applications themselves.>


\newpage

# 5. Applied standards and specifications

## 5.1 Harmonised standards

None applied.


None. As at August 2026 there is no harmonised standard supporting Regulation (EU) 2024/2847 cited in the Official Journal. Standardisation request M/606 was accepted by CEN, CENELEC and ETSI on 3 April 2025 and the work is ongoing. The presumption of conformity is therefore unavailable, and conformity is substantiated directly through the risk assessment in section 3 and the evidence recorded against each essential requirement.

## 5.2 Other means applied

| Means | Role |
|---|---|
| STRIDE | A threat identification method, applied across the trust boundaries in section 3. |
| Resolved-build bill of materials | Components enumerated from resolved build output for all three parts of the product rather than from manifests, and matched against the OSV vulnerability database. |
| Integrity checks on the evidence itself | A requirement cannot be recorded as met without attached evidence, a risk cannot be shown as reduced without a named control, and the document does not build if the data contradicts itself. |


\newpage

# 6. Test reports

No penetration test and no external security assessment has been performed on this product. No third party has reviewed this technical file. What follows is the manufacturer's own testing, and the gaps are listed in full rather than summarised.

## 6.1 Automated tests

| Suite | Files | Note |
|---|---|---|
| pytest (backend) | None | Functional test suite for the Python backend, with coverage measurement. Not security-specific. |
| iOS compile check | None | An unsigned simulator build run on demand in continuous integration. There is no automated test suite for the iOS client. |
| Android | 0 | No automated test suite exists for the Android client. |

## 6.2 Tests mapped to essential requirements

The following were verified by direct inspection of the code and the build output during preparation of this file, on 20 August 2026. They are inspections, not executed tests, and are recorded as such.

| Test suite | Requirements |
|---|---|
| Authentication token attached only to the API host — data/api/ApiClient.kt:19 | EI-04, EI-05 |
| HTTP request logging compiled into debug builds only, headers excluded — data/api/ApiClient.kt:35 | EI-05 |
| Platform backup of application data disabled — AndroidManifest.xml, allowBackup=false | EI-02, EI-05 |
| Pending intents immutable — reminders/ReminderNotifier.kt | EI-06 |
| Alarm receiver not exported; boot receiver exported only as the platform requires — AndroidManifest.xml | EI-10 |
| Notification permission re-checked at posting time, not at scheduling time — reminders/ReminderNotifier.kt | EI-02 |
| No cleartext HTTP; API base URL is HTTPS on both clients | EI-05 |
| Account deletion endpoint present and reachable from the client — DELETE /profile | EI-13 |
| Data export scoped to the caller and excluding credentials and other users' rows — api/routers/profile.py:693 | EI-13, EI-05 |

## 6.3 Static analysis

| Tool | Configuration | Note |
|---|---|---|
| Android lint (level None) | `lintVitalAnalyzeRelease` | Runs as part of the release build. Correctness and API-usage checks, not a security scanner. |
| ruff (level None) | `.ruff.toml` | Style and correctness linting for the Python backend. |
| OSV matching (level None) | `vuln_scan.py against sbom.cdx.json` | Component versions matched against the OSV database. Results are identifier matches requiring assessment, not confirmed exposure. The pass is incomplete across the Maven and PyPI components. |

## 6.4 Evidence gaps

- No coordinated vulnerability disclosure policy is published, and no security contact address exists. This blocks VH-05 and VH-06.
- The Swift package lock file is not committed to the repository, so the exact composition of a released version is recoverable only from continuous integration logs, which expire. The composition of 1.0.15 was recovered this way and is recorded, but the practice is not sustainable.
- Neither release workflow pins its build toolchain. Two builds two days apart used different major Xcode versions. The production process is therefore not reproducible as described.
- Licence determination is incomplete: of 278 components, 4 have a determined licence. The Maven and PyPI components are not yet resolved.
- One backend component, pymupdf 1.27.2.3, is licensed AGPL-3.0-or-later and is a direct dependency of a network-facing service that serves proprietary clients. The licence consequences have not been assessed and replacement is planned.
- No penetration test or external security assessment has been performed.
- The applications do not notify users when the support period ends.


\newpage

# 7. EU Declaration of Conformity

See the separate document `declaration_of_conformity.md`, which forms an integral part of this documentation.


\newpage

# 8. Software bill of materials

Requirement: Annex I, Part II, point 1 — a software bill of materials in a commonly used machine-readable format covering at the very least the top-level dependencies of the product.

**Format:** CycloneDX 1.6  
**Serial number:** `urn:uuid:1e8dd6cd-7eed-5a50-97a3-45afdfb2de3e`  
**Generated:** 2026-08-21T00:20:00Z  
**File:** `sbom.cdx.json`

## 8.1 Composition

- Total components: **278**
  - gradle: 242
  - pypi: 32
  - swiftpm: 4
- Direct dependencies: **77**
- Without a stated licence: **274**

Coverage exceeds the statutory minimum: the full dependency tree of the shipped product is included, not only the top level. Build-time dependencies that are not shipped with the product are excluded.

## 8.2 Licence distribution

| Licence | Components |
|---|---|
| Apache-2.0 | 4 |

## 8.3 Known unknowns

This SBOM carries no machine-readable coverage record: it was not produced by `sbom_gen.py`, or by a version that predates the record. Gaps in coverage, if any, are not stated here, and the absence of this record is not evidence that coverage is complete.

> The SBOM is not subject to mandatory publication. It is retained as part of the technical documentation and made available to the market surveillance authority upon reasoned request.


\newpage

# Appendix A. Article 14 vulnerability and incident reporting runbook

> This appendix is not one of the eight sections Annex VII requires. It is supplementary material cra-kit provides as a practical addition: a runbook for the Article 14 reporting obligation, which took effect on 2026-09-11 and runs on a much shorter clock than anything else in this pack. It does not detect vulnerabilities or incidents, does not decide whether the 24-hour clock has started, and does not submit anything to ENISA or a CSIRT — that judgment is the manufacturer's alone, made by a human, at the time.

## A.1 The two triggers

The 24-hour clock starts only on the manufacturer's actual knowledge that exploitation of a vulnerability, or a severe incident, is real and is affecting **this product**. A CVE existing in the SBOM, a scanner finding, an unconfirmed report, or exploitation confirmed in a different product does **not** start it.

### Actively exploited vulnerability (Article 14(1)-(2))

**Starts the clock when:**

The manufacturer has actual knowledge, with reasonable certainty, that a vulnerability in ITS OWN product with digital elements is being actively exploited — not that it merely could be. "Becoming aware" is the trigger; a suspicion, a scan result, or an unconfirmed report is not.

**Does NOT start the clock:**

- A CVE identifier exists for a component in the SBOM, with no evidence it is being exploited in this product.
- A vulnerability scanner, SAST tool, or software-composition-analysis run flags a known CVE in a dependency.
- A security researcher discloses a vulnerability, including under coordinated disclosure, before exploitation is confirmed.
- The same CVE is confirmed exploited in a DIFFERENT product or a different vendor's build — exploitation is assessed per product, not per component.
- A component maintainer's advisory describes exploitation of the component in the abstract, with no evidence that this product's specific integration is affected and is being exploited.
- An internal red-team or pentest finding demonstrates a theoretical exploit path with no evidence it has been used against a real deployment.

### Severe incident affecting the product's security (Article 14(3)-(4))

**Starts the clock when:**

The manufacturer becomes aware of an incident that has an actual negative impact on the security of ITS OWN product with digital elements — for example, it compromises the product's ability to protect the confidentiality, integrity or availability of data or functions, or it has resulted in the execution of malicious code through the product. This is about the product's own security, not about whatever happened inside a customer's environment. See `operator_and_self_hoster_note` below.

**Does NOT start the clock:**

- A customer reports an operational outage or a misconfiguration at their own installation, with no indication the product itself is compromised.
- A general industry breach or incident is reported that does not implicate this product.
- An internal security test or audit turns up a finding with no actual incident having occurred.
- A single customer's credentials are stolen or misused through no fault of the product (e.g. phishing, credential reuse) — that is an incident at the installation, not in the product.

## A.2 Deadlines

| Trigger | Stage | Deadline | Legal basis |
|---|---|---|---|
| Actively exploited vulnerability | 24h early warning | without undue delay, and in any event within 24 hours of the manufacturer becoming aware | Article 14(2)(a) |
| Actively exploited vulnerability | 72h full notification | without undue delay, and in any event within 72 hours of the manufacturer becoming aware | Article 14(2)(b) |
| Actively exploited vulnerability | Final report | no later than 14 days after a corrective or mitigating measure becomes available | Article 14(2)(c) |
| Severe incident affecting the product's security | 24h early warning | without undue delay, and in any event within 24 hours of the manufacturer becoming aware | Article 14(4)(a) |
| Severe incident affecting the product's security | 72h full notification | without undue delay, and in any event within 72 hours of the manufacturer becoming aware | Article 14(4)(b) |
| Severe incident affecting the product's security | Final report | within one month of the submission of the 72-hour notification | Article 14(4)(c) |

The final report deadline differs by trigger: for an exploited vulnerability it is **14 days after a corrective or mitigating measure becomes available** — anchored to the fix, which may land well outside 14 days from first awareness. For a severe incident it is **one month after the 72-hour notification**, on a fixed clock that is not tied to any fix at all.

## A.3 Operators, self-hosters and other third-party deployments

This product has no operators, deployers or self-hosters. It is distributed to consumers through the App Store and Google Play and runs against a backend the manufacturer operates itself. There is therefore no third party who would notice exploitation before the manufacturer does, and no third party the manufacturer could ask. The corollary is uncomfortable: the manufacturer's only realistic route to learning that its product is being exploited in the field is its own monitoring, which is described in EI-12 as absent, or a report through a channel described in VH-06 as absent.

## A.4 Named filer and deputy

| Role | Name | Contact |
|---|---|---|
| Manufacturer (primary) | <to be completed> | <to be completed> |
| Deputy (deputy) | <to be completed> | <to be completed> |

A deputy exists so the 24-hour clock survives one person being on leave, unreachable, or asleep. Both the primary and the deputy should be able to file a notification alone, without waiting for the other.

## A.5 Identifying the relevant CSIRT

**Status:** not_identified

> **Not yet identified.** This is a field the manufacturer must resolve — cra-kit does not invent a CSIRT contact, since a wrong or fabricated one is worse than an honestly blank one.

cra-kit cannot determine this for you: which CSIRT is "the coordinator" depends on facts only the manufacturer has (place of main establishment; where the product's users are concentrated) and on each Member State's own designation. Consult ENISA's published list of national CSIRTs and single points of contact, confirm which one applies to your situation, and record the outcome below. Do not guess, and do not leave this blank until an actual event — confirming it in advance is exactly what the 24-hour clock does not leave time to do.

| Field | Value |
|---|---|
| Country | <to be completed — Poland> |
| CSIRT | <to be completed> |
| Contact | <to be completed> |

Notifications go simultaneously to ENISA via the Article 16 single reporting platform. Where that platform is not yet operational for a given Member State or trigger type, use the interim channel your national CSIRT coordinator publishes.

## A.6 Draft notification templates

Bracketed fields (`[LIKE THIS]`) mark facts that can only be known at the time of a real event and must never be filled in ahead of one.

### 24-hour early warning

```markdown
# Article 14(2)(a) / 14(4)(a) — 24-hour early warning

Submitted via: [ENISA single reporting platform (Article 16) / national CSIRT interim channel — delete as applicable]

**To:** [NAME OF CSIRT DESIGNATED AS COORDINATOR], simultaneously to ENISA
**From:** [MANUFACTURER NAME] — filed by [FILER NAME], [FILER ROLE]
**Date/time of this notification:** [DATE, TIME, TIMEZONE]
**Date/time the manufacturer became aware:** [DATE, TIME, TIMEZONE]
**Trigger type:** [ actively exploited vulnerability | severe incident — choose ONE; file separately if both apply ]

**Product:** [PRODUCT NAME]
**Affected versions:** [AFFECTED VERSIONS]

**Member States concerned, where known at this stage:** [MEMBER STATES, or "not yet known"]

**Basis for concluding this notification is required:**
[ONE TO TWO SENTENCES: what confirmed, with reasonable certainty, that exploitation is
actively happening in THIS product / that this is a severe incident affecting THIS
product's own security. Not a CVE score. Not a scanner finding. Not a report about a
different product.]

This is an early warning under Article 14(2)(a) [or 14(4)(a)]. A full notification
will follow within 72 hours of the awareness time stated above, per Article 14(2)(b)
[or 14(4)(b)].

Filed by: [FILER NAME], [FILER ROLE], [FILER CONTACT]
```

### 72-hour full notification

```markdown
# Article 14(2)(b) / 14(4)(b) — 72-hour full notification

**To:** [CSIRT COORDINATOR], simultaneously to ENISA
**Reference:** early warning of [DATE/TIME]
**Trigger type:** [ actively exploited vulnerability | severe incident ]

**Product:** [PRODUCT NAME]
**Affected versions:** [AFFECTED VERSIONS]

**General information about the vulnerability/incident:**
[WHAT IT IS AND HOW IT MANIFESTS]

**Severity and impact, as currently assessed:**
[SEVERITY / CVSS IF APPLICABLE / OBSERVED OR LIKELY IMPACT]

**Indicators of compromise, if available (incident only):**
[IOCs, or "none identified at this stage"]

**Suspected cause / threat type, if known at this stage (incident only):**
[SUSPECTED CAUSE, or "under investigation"]

**Corrective or mitigating measures taken or planned:**
[MEASURES — e.g. patch in progress, workaround published, affected feature disabled]

**Cross-border relevance, if known:**
[MEMBER STATES / MARKETS AFFECTED, or "not yet known"]

This notification is submitted under Article 14(2)(b) [or 14(4)(b)], within 72 hours
of the manufacturer becoming aware. A final report will follow:
[14 days after a corrective or mitigating measure becomes available (vulnerability) |
within one month of this notification (incident)].

Filed by: [FILER NAME], [FILER ROLE], [FILER CONTACT]
```

### Final report — exploited vulnerability

```markdown
# Article 14(2)(c) — final report: actively exploited vulnerability

**To:** [CSIRT COORDINATOR], simultaneously to ENISA
**Reference:** early warning of [DATE], full notification of [DATE]

**Product:** [PRODUCT NAME]
**Affected versions:** [AFFECTED VERSIONS]

**Description of the vulnerability:**
[FULL DESCRIPTION]

**Severity and impact:**
[FINAL SEVERITY ASSESSMENT AND IMPACT]

**Information about the malicious actor, where available:**
[WHAT IS KNOWN, or "not attributed"]

**Security update or other corrective/mitigating measure made available:**
[VERSION / PATCH / ADVISORY LINK]

**Date the corrective or mitigating measure became available:** [DATE]
(This report is due no later than 14 days after that date — Article 14(2)(c). It is
anchored to the fix, not to the date of the 72-hour notification.)

Filed by: [FILER NAME], [FILER ROLE], [FILER CONTACT]
```

### Final report — severe incident

```markdown
# Article 14(4)(c) — final report: severe incident

**To:** [CSIRT COORDINATOR], simultaneously to ENISA
**Reference:** early warning of [DATE], full notification of [DATE]

**Product:** [PRODUCT NAME]
**Affected versions / installations:** [AFFECTED VERSIONS]

**Detailed description of the incident:**
[FULL DESCRIPTION]

**Severity and impact:**
[FINAL SEVERITY ASSESSMENT AND IMPACT]

**Threat type or root cause:**
[ROOT CAUSE]

**Mitigation measures taken or ongoing:**
[MEASURES]

**Cross-border impact, if any:**
[MEMBER STATES / MARKETS AFFECTED, or "none identified"]

This report is due within one month of the submission of the 72-hour notification
(submitted [DATE]) — Article 14(4)(c). It is NOT tied to the availability of a fix:
file it on the one-month clock regardless of remediation status.

Filed by: [FILER NAME], [FILER ROLE], [FILER CONTACT]
```

## A.7 Readiness checklist

- [ ] Named filer identified
- [ ] Deputy filer identified
- [ ] CSIRT contact identified
- [ ] Templates reviewed
- [ ] One tabletop walkthrough completed
- Tabletop date: not recorded

Nothing in this checklist is ticked. Article 14 has applied since 11 September 2026 and this product has been on the market since 1 July 2026. The gap is recorded as risk R-11. None of the remaining items requires engineering work: they require two names and one phone call.
