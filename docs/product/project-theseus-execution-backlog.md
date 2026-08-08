# Project Theseus — Execution Backlog and Next Steps

**Status:** Draft backlog for migration into the future private organization  
**Owner:** Adam Gell  
**Priority model:** P0 blocks the first sellable workflow; P1 blocks pilot readiness; P2 follows customer proof

---

## 1. Backlog principles

1. The first sellable workflow is the organizing constraint.
2. Organization and repository ownership work is a prerequisite, not administrative decoration.
3. Final public naming must not block engineering.
4. Asset Continuity is foundational but must not delay the first stored-evidence pull.
5. Agent jobs follow stored-session retrieval.
6. Fleet intelligence follows trustworthy single-device evidence.
7. Every implementation issue must name its user-visible or operational outcome.
8. Cross-repository contracts require explicit owners and compatibility tests.
9. Commercial-only work must not accidentally land in public CMTrace Open.
10. General local-investigation improvements may still be selectively imported from CMTrace Open.

---

# 2. Priority definitions

## P0 — Program and first commercial proof

Required to create organization-owned repositories and demonstrate remote stored evidence inside the desktop.

## P1 — Production-shaped design-partner readiness

Required for real enterprise authentication, agent jobs, lifecycle identity, supportability, and paid pilot delivery.

## P2 — Repeatability and product expansion

Required for scalable commercial packaging, fleet intelligence, integrations, managed service, and guarded actions.

## P3 — Research or optional future work

Ideas that may be valuable but should not distract from validated product demand.

---

# 3. P0 decision queue

These decisions should be resolved first because they alter repository or product identity.

## D0.1 — GitHub organization name

**Outcome:** A durable source-ownership namespace exists.

Decision criteria:

- independent of the final first product name where possible;
- available on GitHub;
- acceptable as a future company or studio identity;
- not tied to `CMTrace`, `Intune`, `Entra`, or Project Theseus;
- supports future products if the company expands;
- domain and basic trademark risk reviewed before public use.

Deliverable:

- accepted organization name;
- owner/recovery plan;
- creation date;
- private repository defaults.

## D0.2 — Initial stable internal product ID

**Outcome:** Installer, update, configuration, and protocol identity do not depend on the eventual display name.

Candidate shape:

```text
com.adamgell.endpoint-evidence
```

or organization-neutral UUID-backed identifiers where platform conventions require them.

Must decide before:

- customer preview installer identity;
- auto-update channel;
- stable service registration;
- externally distributed configuration profiles.

## D0.3 — Private repository count at bootstrap

Recommended decision:

```text
theseus-desktop
theseus-platform
```

Defer separate release/docs repos until the split creates real permission or lifecycle value.

## D0.4 — Public `cmtraceopen-web` disposition

Choose one after private migration:

- archive as historical public snapshot;
- make private where operationally possible;
- retain a minimal historical README and disable issues/PRs;
- no promise of ongoing feature development.

The decision must record the final public commit/tag.

## D0.5 — Commercial licensing approach for preview

Temporary options:

- evaluation/design-partner agreement with no embedded technical license enforcement;
- signed license file;
- organization entitlement from the private platform;
- manual customer allowlist.

Recommendation for first design partner:

- contractual entitlement plus a simple signed configuration/entitlement;
- do not build a complex billing/licensing service before product proof.

---

# 4. M1 backlog — Organization and private repository bootstrap

## EPIC M1-A — Create commercial GitHub organization

### Issue M1-A1 — Create organization and owner recovery

Acceptance criteria:

- organization exists;
- Adam is owner;
- recovery and MFA documented;
- default repository visibility is private;
- base member permission is restricted;
- initial teams exist.

### Issue M1-A2 — Configure organization security defaults

Acceptance criteria:

- secret scanning/push protection configured where available;
- dependency alerts enabled;
- Actions policy constrained;
- package visibility defaults private;
- audit access confirmed;
- private security contact established.

### Issue M1-A3 — Create organization resource inventory

Track:

- repositories;
- packages;
- Actions environments;
- signing identities;
- cloud subscriptions;
- service principals;
- domains;
- release storage;
- telemetry/support integrations.

## EPIC M1-B — Bootstrap private desktop repository

### Issue M1-B1 — Mirror CMTrace Open history and tags

Acceptance criteria:

- full history present;
- tags present;
- default branch matches intended baseline;
- commit authorship intact;
- clone/build smoke test passes.

### Issue M1-B2 — Record upstream baseline and intake policy

Files:

- `UPSTREAM.md`;
- `upstream/baseline.json`;
- `upstream/intake-policy.md`;
- integration log directory.

### Issue M1-B3 — Preserve licensing and generate third-party notices

Acceptance criteria:

- MIT license retained for inherited code;
- third-party inventory generated;
- commercial additions have an explicit license/ownership statement;
- release packaging includes required notices.

### Issue M1-B4 — Add repository protections and CI

Acceptance criteria:

- protected `main`;
- PR required;
- required check/test/lint/build gates;
- CODEOWNERS;
- release environment protected;
- commercial artifacts cannot publish from untrusted PRs.

## EPIC M1-C — Bootstrap private platform repository

### Issue M1-C1 — Mirror platform history and tags

Same history/provenance requirements as desktop.

### Issue M1-C2 — Record historical public source baseline

Files:

- `HISTORICAL-SOURCE.md`;
- license inventory;
- final public source commit/tag;
- private continuation date.

### Issue M1-C3 — Redirect desktop dependency/submodule

Acceptance criteria:

- platform references private desktop source;
- CI can authenticate securely without leaking credentials;
- developer bootstrap documentation covers access;
- public CMTrace Open is not accidentally bundled where commercial desktop is intended.

### Issue M1-C4 — Move package, container, and deployment namespaces

Inventory and redirect:

- GHCR images;
- release artifacts;
- Terraform image references;
- download URLs;
- update manifests;
- package names;
- Azure resource naming;
- deployment scripts.

### Issue M1-C5 — Establish protected preview deployment

Acceptance criteria:

- private preview image produced;
- private preview environment deploys;
- secrets externalized;
- rollback documented;
- no public production endpoint exposed unintentionally.

---

# 5. M2 backlog — Product shell and independent identity

## EPIC M2-A — Product manifest and capability boundary

### Issue M2-A1 — Define product manifest schema

Fields:

- stable product ID;
- internal program name;
- display name;
- edition/channel;
- publisher generation;
- update endpoint;
- support endpoint;
- capability flags;
- privacy/telemetry policy.

### Issue M2-A2 — Replace scattered product branding with manifest access

Focus on high-conflict surfaces:

- window title;
- menus;
- About dialog;
- installer metadata;
- application paths;
- update UI;
- support links;
- screenshots/release assets.

Do not rename internal parser crates without a technical reason.

### Issue M2-A3 — Add commercial capability registry

Initial capabilities:

```text
localInvestigation
serverProfiles
remoteDevices
remoteSessions
bundleDownload
assetHistory
collectionJobs
fleetIntelligence
```

Only implemented capabilities should be advertised.

## EPIC M2-B — Independent install and runtime identity

### Issue M2-B1 — Windows application and installer identity

Acceptance criteria:

- independent executable/product name;
- stable MSI upgrade strategy;
- independent registry/config paths;
- side-by-side test with CMTrace Open;
- uninstall isolation;
- publisher shown as Adam Gell.

### Issue M2-B2 — Agent service identity

Acceptance criteria:

- independent service name/display name;
- independent install/data/log paths;
- recovery behavior;
- upgrade path;
- no collision with old public agent ancestry.

### Issue M2-B3 — macOS/Linux identity

- bundle/package IDs;
- app data paths;
- signing/notarization path;
- side-by-side behavior where supported.

## EPIC M2-C — Founder-signed preview release

### Issue M2-C1 — Signing generation manifest

Record generation 1 publisher as Adam Gell.

### Issue M2-C2 — Protected desktop signing workflow

### Issue M2-C3 — Protected agent signing workflow

### Issue M2-C4 — Component release manifest and compatibility skeleton

### Issue M2-C5 — Internal preview smoke test

Required:

- install;
- launch;
- local investigation;
- agent install/start;
- server deploy;
- uninstall/rollback;
- signature verification.

---

# 6. M3 backlog — Stored remote evidence vertical slice

## EPIC M3-A — Platform session bundle retrieval

Existing ancestry item: `cmtraceopen-web#159` should be migrated or recreated privately.

### Issue M3-A1 — Define bundle-download API contract

Route:

```text
GET /v1/sessions/{session_id}/bundle
```

Specify:

- authentication/role;
- response headers;
- filename;
- checksum;
- content length;
- range/resume position;
- errors;
- audit;
- capability/version identifier.

### Issue M3-A2 — Extend storage abstraction for streamed reads

Backends:

- local filesystem;
- Azure Blob;
- test/memory backend where useful.

### Issue M3-A3 — Implement route with safe metadata resolution

Never accept caller-supplied storage keys.

### Issue M3-A4 — Add access audit and metrics

Audit:

- operator;
- asset/device/session;
- result;
- bytes;
- correlation ID;
- no evidence content.

### Issue M3-A5 — Add authorization, expiry, mismatch, and streaming tests

## EPIC M3-B — Desktop server-client foundation

Existing ancestry items: `cmtraceopen#534` and `#535` should be migrated or recreated privately.

### Issue M3-B1 — Server profile model and persistence

### Issue M3-B2 — URL/TLS policy

Rules:

- HTTPS by default;
- local loopback HTTP only in bounded development modes;
- no embedded credentials;
- no invalid-certificate toggle in persisted production settings;
- explicit timeouts and proxy behavior.

### Issue M3-B3 — API DTO fixtures

Mirror current wire shapes without conflating them with parser-domain entries.

### Issue M3-B4 — Typed error envelope

Include:

- unreachable;
- TLS;
- unauthorized;
- forbidden;
- rate-limited;
- expired/missing;
- protocol mismatch;
- malformed response;
- cancellation;
- integrity;
- local I/O.

### Issue M3-B5 — HTTP transport and in-memory lab authorization

Do not persist lab bearer tokens in profile JSON.

## EPIC M3-C — Remote browser UX

### Issue M3-C1 — Server selector and connection test

### Issue M3-C2 — Remote device list

### Issue M3-C3 — Session list and detail

### Issue M3-C4 — Clear distinction between server, cache, and local evidence

## EPIC M3-D — Download and local handoff

### Issue M3-D1 — App-managed cache design

- partial suffix;
- atomic finalization;
- retention metadata;
- collision handling;
- cache provenance.

### Issue M3-D2 — Streaming download and progress events

### Issue M3-D3 — Cancellation and partial cleanup

### Issue M3-D4 — SHA-256 verification

### Issue M3-D5 — Open downloaded bundle through existing pipeline

No second parser or evidence-workspace implementation.

## EPIC M3-E — End-to-end product proof

### Issue M3-E1 — Create repeatable demo environment

### Issue M3-E2 — Seed real synthetic device/session evidence

### Issue M3-E3 — Automate vertical-slice e2e test

### Issue M3-E4 — Record demonstration and operator script

Exit sequence:

```text
server → device → session → download → verify → desktop workspace
```

---

# 7. M4 backlog — Production authentication and product-pipe telemetry

## EPIC M4-A — Desktop Entra authentication

### Issue M4-A1 — Define dedicated desktop app registration

### Issue M4-A2 — Authorization code + PKCE

### Issue M4-A3 — Secure token storage and refresh

### Issue M4-A4 — Sign-out/account switch/tenant display

### Issue M4-A5 — Conditional Access and interaction-required UX

## EPIC M4-B — Connection-health model

### Issue M4-B1 — Define health state DTO

### Issue M4-B2 — Reachability and latency

### Issue M4-B3 — Account, role, and token health

### Issue M4-B4 — Last successful query and pull

### Issue M4-B5 — Agent last-seen and selected-device status

### Issue M4-B6 — Last sanitized error and correlation ID

## EPIC M4-C — Compatibility

### Issue M4-C1 — Protocol generation and capability endpoint

### Issue M4-C2 — Desktop/server compatibility matrix

### Issue M4-C3 — Agent/server compatibility matrix

### Issue M4-C4 — Unsupported-version fail-closed UX

### Issue M4-C5 — Upgrade-order integration tests

---

# 8. M5 backlog — Agent lifecycle and collection jobs

## EPIC M5-A — Agent identity and lifecycle

### Issue M5-A1 — Bootstrap-stage architecture

### Issue M5-A2 — Registration and certificate renewal

### Issue M5-A3 — Capability advertisement

### Issue M5-A4 — Heartbeat and health

### Issue M5-A5 — Signed configuration

### Issue M5-A6 — Upgrade and rollback

### Issue M5-A7 — Retirement and revocation

## EPIC M5-B — Collection profile model

### Issue M5-B1 — Profile schema and versioning

### Issue M5-B2 — Resource limits and privilege declaration

### Issue M5-B3 — Redaction and privacy declaration

### Issue M5-B4 — Profile signing/integrity

### Issue M5-B5 — Default Intune/Autopilot evidence profile

## EPIC M5-C — Job orchestration

### Issue M5-C1 — Job state machine

### Issue M5-C2 — Server API and persistence

### Issue M5-C3 — Agent polling/receipt and execution

### Issue M5-C4 — Timeout/cancellation/retry

### Issue M5-C5 — Result-to-evidence-session linkage

### Issue M5-C6 — Desktop request/status/open workflow

### Issue M5-C7 — On-demand collection e2e test

---

# 9. M6 backlog — Asset Continuity and evidence chain

## EPIC M6-A — Identity architecture

### Issue M6-A1 — Asset Continuity ADR

### Issue M6-A2 — Asset/Incarnation/OS/Registration schema

### Issue M6-A3 — Management alias model

### Issue M6-A4 — Identity decision ledger

### Issue M6-A5 — Migration from existing flat device records

## EPIC M6-B — Hardware identity profile

### Issue M6-B1 — Initial claim inventory

### Issue M6-B2 — Normalization and placeholder rules

### Issue M6-B3 — Fleet prevalence detection

### Issue M6-B4 — Tenant-scoped token/key design

### Issue M6-B5 — TPM-backed identity research and prototype

### Issue M6-B6 — Privacy/export policy

## EPIC M6-C — Match engine

### Issue M6-C1 — Explainable scoring model

### Issue M6-C2 — Conflict and concurrent-registration protection

### Issue M6-C3 — High/medium/low/contradictory decision bands

### Issue M6-C4 — Adversarial identity fixture corpus

### Issue M6-C5 — Operator attach/split/unlink/undo API

### Issue M6-C6 — Planned repair continuity claim

## EPIC M6-D — Evidence chain of custody

### Issue M6-D1 — Evidence manifest schema

### Issue M6-D2 — Agent signing key and manifest signature

### Issue M6-D3 — Server receipt

### Issue M6-D4 — Manifest sequence/previous-hash policy

### Issue M6-D5 — Independent verification command

### Issue M6-D6 — Association changes without evidence mutation

## EPIC M6-E — Desktop lifecycle UX

### Issue M6-E1 — Asset identity card

### Issue M6-E2 — Incarnation/OS timeline

### Issue M6-E3 — Match reason and claim comparison

### Issue M6-E4 — Manual continuity review

### Issue M6-E5 — Audit and undo history

---

# 10. M7 backlog — Design-partner pilot

## EPIC M7-A — Security and operational readiness

- threat model;
- data classification;
- secrets inventory;
- audit validation;
- backup/restore rehearsal;
- disaster-recovery rehearsal;
- upgrade/rollback rehearsal;
- support bundles;
- incident playbooks.

## EPIC M7-B — Customer deployment

- readiness questionnaire;
- reference Azure deployment;
- Entra registration;
- PKI/agent identity;
- Intune deployment;
- cohort and assignment;
- firewall/proxy;
- retention/storage;
- removal plan.

## EPIC M7-C — Commercial package

- design-partner agreement;
- paid scope;
- pricing hypothesis;
- support boundaries;
- acceptable use;
- release lifecycle;
- feedback process;
- case-study permission.

## EPIC M7-D — Pilot measurement

- time to evidence;
- pull success;
- collection latency;
- remote-control avoidance;
- operator repeat usage;
- support effort;
- storage growth;
- investigation outcomes.

---

# 11. Recommended first PR sequence

This sequence is intentionally small and reviewable.

## Desktop

1. **chore: establish commercial downstream baseline**
2. **feat(product): add commercial product manifest**
3. **build: establish independent preview application identity**
4. **feat(server-client): add profiles, DTOs, URL policy, and typed errors**
5. **feat(server-client): add connection test and lab authorization seam**
6. **feat(remote): add device and session browser shell**
7. **feat(remote): stream and verify session bundle into cache**
8. **feat(remote): open cached server bundle in existing investigation pipeline**
9. **feat(connectivity): add local product-pipe health strip**
10. **feat(auth): add production Entra desktop sign-in**

## Platform

1. **chore: establish private platform baseline**
2. **build: redirect platform dependencies and package namespaces**
3. **feat(protocol): add capability and compatibility metadata**
4. **feat(api): add authenticated streamed session-bundle download**
5. **feat(audit): record session-bundle access**
6. **test(e2e): exercise device-to-desktop stored-evidence path**
7. **feat(agent): add heartbeat and capability report**
8. **feat(jobs): add collection-job state machine**
9. **feat(agent): execute approved collection profile**
10. **test(e2e): request, collect, upload, and open evidence**

Do not combine desktop rebranding, Entra auth, bundle download, asset continuity, and collection jobs into one PR.

---

# 12. Definition of ready for an implementation issue

An issue is ready when it includes:

- user or operator outcome;
- repository and component owner;
- dependencies;
- explicit in-scope behavior;
- explicit out-of-scope behavior;
- security/privacy considerations;
- API/schema impact;
- acceptance criteria;
- validation commands or test classes;
- migration/compatibility impact where relevant.

---

# 13. Definition of done for a product slice

A slice is done when:

1. Production code and tests are merged.
2. Failure behavior is visible and actionable.
3. Security/privacy requirements are tested, not merely documented.
4. Compatibility impact is recorded.
5. Required documentation and runbooks are updated.
6. Release notes identify customer/operator impact.
7. A real end-to-end demonstration passes.
8. No temporary credential or unsafe debug bypass is required.
9. Local-only desktop behavior remains functional where applicable.
10. Operational support can distinguish product failure from customer-environment failure.

---

# 14. Work explicitly deferred from the first commercial proof

- final public product name;
- company signing certificate;
- multi-tenant SaaS;
- MSP partner plane;
- generalized fleet search;
- complete Asset Continuity UI;
- live endpoint tailing;
- arbitrary remote shell;
- broad remediation catalog;
- complex billing infrastructure;
- marketplace listings;
- perfect plugin architecture;
- complete internal codebase renaming.

---

# 15. Immediate next actions

1. Approve the charter, roadmap, repository skeleton, and this backlog as the temporary program source of truth.
2. Begin organization-name exploration.
3. Create the organization.
4. Create and secure `theseus-desktop` and `theseus-platform`.
5. Mirror histories and record baselines.
6. Recreate the M1 and M3 epics in the private repositories.
7. Establish independent internal preview build identity.
8. Start the two parallel P0 implementation tracks:
   - platform streamed session-bundle retrieval;
   - desktop typed server-client foundation.
9. Join those tracks through the smallest device/session/download/open UI.
10. Demonstrate the first commercial product outcome before expanding the roadmap.
