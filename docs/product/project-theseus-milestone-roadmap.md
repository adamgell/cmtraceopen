# Project Theseus — Milestone Roadmap

**Status:** Draft for execution  
**Owner:** Adam Gell  
**Planning style:** Gate-based, not date-based  
**Internal codename:** Project Theseus

---

## How to use this roadmap

This roadmap is organized around **proof gates**, not calendar promises.

A milestone is complete only when its exit criteria are demonstrated. Documentation or partial implementation alone does not satisfy a product gate unless the milestone explicitly concerns planning or governance.

The milestone order is intentional:

```text
M0 Direction and ownership
  ↓
M1 Private repository and build independence
  ↓
M2 Commercial shell and release identity
  ↓
M3 Stored remote evidence vertical slice
  ↓
M4 Production authentication and compatibility
  ↓
M5 Long-lived agent and collection jobs
  ↓
M6 Asset continuity and evidence chain
  ↓
M7 Design-partner pilot readiness
  ↓
M8 Paid supported preview
  ↓
M9 Fleet intelligence and guarded actions
```

Some workstreams can proceed in parallel, but no later milestone may claim readiness while depending on an unproven earlier gate.

---

# M0 — Direction, ownership, and program lock

## Outcome

Project Theseus has a durable charter, accepted source boundary, startup identity stack, and decision-governance model.

## Accepted direction

- CMTrace Open remains public and MIT licensed.
- The commercial desktop is a private organization-owned downstream.
- The agent/server/web platform is private commercial IP.
- Commercial work has no default contribution-back obligation.
- Internal program name is Project Theseus.
- Startup binaries are signed by Adam Gell.
- All new commercial repositories are organization owned.
- The public product name remains open.
- The first sellable workflow is stored remote evidence opened in the desktop.

## Deliverables

- [x] Enterprise platform product memory.
- [x] Open-core repository boundary.
- [x] Commercial repository and signing decision.
- [x] Startup identity stack.
- [x] Naming brief.
- [x] Program charter.
- [x] Milestone roadmap.
- [ ] Organization naming decision.
- [ ] Employment/IP and outside-business review completed and recorded privately.
- [ ] Initial third-party licensing inventory assigned.

## Exit gate

M0 is complete when:

1. Adam approves the program charter and roadmap.
2. A GitHub organization identity is selected.
3. There is no unresolved disagreement about public versus private repository boundaries.
4. The first two private repository names can be created without implying a final public brand.

## Commercial proof

No commercial proof is required at M0. The purpose is to prevent avoidable ownership and architecture mistakes before code migration.

---

# M1 — Organization-owned private repositories

## Outcome

The commercial desktop and platform build independently from organization-owned private repositories while preserving complete ancestry, license notices, tags, and provenance.

## Scope

### Desktop repository

Create:

```text
<organization>/theseus-desktop
```

Requirements:

- private repository;
- full CMTrace Open Git history and tags;
- `origin` points to commercial repository;
- `upstream` points to `adamgell/cmtraceopen`;
- exact source baseline recorded;
- branch protections and CODEOWNERS established;
- private Actions environments and release permissions;
- inherited MIT notices preserved;
- commercial additions clearly licensed and owned.

### Platform repository

Create:

```text
<organization>/theseus-platform
```

Requirements:

- private repository;
- full `cmtraceopen-web` Git history and tags;
- exact source baseline recorded;
- active agent/server/web/infra work moves here;
- commercial platform points to the private commercial desktop rather than the public submodule;
- package, GHCR, Actions, Terraform, secrets, and deployment references are migrated or explicitly staged for migration.

## Deliverables

- [ ] GitHub organization created or selected.
- [ ] Organization owner recovery and MFA model established.
- [ ] Desktop private repository created.
- [ ] Platform private repository created.
- [ ] Full branches/tags mirrored.
- [ ] `UPSTREAM.md` in desktop.
- [ ] Upstream baseline JSON in desktop.
- [ ] Historical-source/baseline record in platform.
- [ ] Third-party notices baseline generated.
- [ ] Default branch protection.
- [ ] Required review rules.
- [ ] Secret scanning and dependency alerts.
- [ ] Private vulnerability-reporting route.
- [ ] Initial Actions environments: `preview`, `release`.
- [ ] Adam Gell signing authority documented.
- [ ] Public repositories contain transition/archive notes as appropriate.

## Validation

- Fresh desktop clone builds and tests from the private repository.
- Fresh platform clone builds and tests from the private repository.
- Platform dependency/submodule resolves only to authorized private sources where intended.
- No release secret exists in repository contents or unprotected Actions variables.
- License and attribution files survive the move.

## Exit gate

M1 is complete when a clean machine can clone both private repositories, build the current product ancestry, and identify exactly which public commits each repository originated from.

## Deferred

- Final public brand.
- Final company signer.
- Customer licensing enforcement.
- Product-wide internal renaming.

---

# M2 — Commercial shell and independent release identity

## Outcome

The private desktop and platform present as Project Theseus internally, no longer collide operationally with CMTrace Open, and can produce founder-signed preview artifacts through independent channels.

## Scope

### Product manifest

Introduce a central commercial product manifest or equivalent configuration seam for:

- product ID;
- display name placeholder;
- edition;
- application and service names;
- support links;
- update endpoints;
- telemetry policy;
- capability registration;
- branding assets;
- release channel.

The implementation must avoid scattering commercial names throughout parser and investigation code.

### Independent identities

Establish independent:

- Windows installer product/upgrade strategy;
- executable and service names;
- application bundle identifiers;
- macOS bundle identity and notarization path;
- Linux package names;
- configuration and cache directories;
- update channel and release manifest;
- protocol product identifier;
- website/support placeholders;
- package/container names.

### Signing

- binaries signed by Adam Gell;
- timestamping enabled;
- signing restricted to protected release workflow;
- machine-readable publisher generation recorded;
- preview release notes clearly identify publisher.

## Deliverables

- [ ] Product-manifest ADR.
- [ ] Brand-neutral shell implementation.
- [ ] Temporary internal display name approved for noncustomer builds.
- [ ] Independent installer identity.
- [ ] Independent app data/config paths.
- [ ] Independent update manifest and preview channel.
- [ ] Independent agent service identity.
- [ ] Independent container/package namespaces.
- [ ] Signed desktop preview artifact.
- [ ] Signed agent preview artifact.
- [ ] Platform image provenance/attestation recorded.
- [ ] Release manifest includes signer generation and component compatibility.

## Validation

- CMTrace Open and the commercial desktop can be installed side by side where supported.
- Uninstalling either product does not remove the other's data or registration.
- The commercial desktop does not check the CMTrace Open update channel.
- Founder-signed artifacts validate after download.
- Preview release cannot accidentally publish to public CMTrace Open channels.

## Exit gate

M2 is complete when the private repositories can issue an independently identified, founder-signed internal preview without operationally masquerading as CMTrace Open.

---

# M3 — Stored remote evidence vertical slice

## Outcome

An operator can select a remote device/session in the commercial desktop, securely download its canonical stored bundle from the private platform, verify the bundle, and open it in the existing investigation experience.

This is the first sellable product proof.

## Server/platform scope

- operator-authenticated session-bundle download route;
- streamed response from local and Azure object storage;
- safe filename and content disposition;
- SHA-256 integrity metadata over exact streamed bytes;
- clean missing, expired, unauthorized, forbidden, rate-limited, cancelled, and server-error behavior;
- audit record for access and result;
- correlation ID;
- no caller-controlled storage key or path;
- compatibility/capability metadata.

## Desktop scope

- persisted server profiles without persisted bearer tokens;
- safe URL normalization and fail-closed TLS;
- anonymous/lab mode for development;
- typed API DTOs and error taxonomy;
- connection test;
- device list;
- session list;
- file list where useful;
- streaming bundle download to partial file;
- disk-space preflight;
- cancellation and cleanup;
- hash verification;
- atomic finalization into app-managed cache;
- open through existing evidence/bundle inspection pipeline;
- distinguish local, cached-server, and current-server state.

## UX scope

- server selector;
- connection state;
- remote devices entry point;
- session browser;
- `Open in Desktop` action;
- visible download progress;
- actionable sanitized failures;
- local file opening remains available regardless of server state.

## Test matrix

- server local-FS download;
- server Azure Blob download;
- authorized operator;
- unauthorized/no token;
- forbidden role;
- expired/retention-removed object;
- object/session mismatch;
- interrupted download;
- integrity mismatch;
- cache collision;
- low disk space;
- desktop cancellation;
- unsupported server capability;
- local-only startup with network unavailable;
- Lite/community build remains independent where applicable.

## Deliverables

- [ ] Platform download contract.
- [ ] Desktop server-client foundation.
- [ ] Minimal remote browser.
- [ ] Bundle cache and integrity verifier.
- [ ] Existing workspace handoff.
- [ ] Vertical-slice end-to-end test.
- [ ] Demonstration script and fixture environment.
- [ ] Preview release notes.

## Exit gate

M3 is complete only when a real desktop build opens a real stored platform session end to end without manual file transfer.

Required demonstration:

```text
Select server
→ verify connection
→ select device
→ select session
→ download bundle
→ verify integrity
→ open in existing investigation workspace
```

## Commercial proof

The workflow can be demonstrated to an endpoint engineer without explaining internal architecture first. The engineer can understand the operational value within the demonstration itself.

---

# M4 — Production authentication, telemetry, and compatibility

## Outcome

The stored-evidence workflow is production-shaped for a self-hosted enterprise preview.

## Authentication

- dedicated desktop Entra public-client registration;
- authorization code with PKCE;
- system-browser sign-in;
- secure token cache appropriate to each supported platform;
- silent refresh where supported;
- sign-out and account switching;
- account, role, tenant, and token-expiry visibility;
- Conditional Access and interaction-required states surfaced clearly;
- no plaintext tokens in profile/config files or logs.

## Connectivity telemetry

Display locally:

- server reachability;
- round-trip latency;
- signed-in account;
- effective role;
- token health;
- last successful query;
- last successful pull;
- selected device last seen;
- active operation state;
- last sanitized error;
- desktop/server protocol compatibility.

## Compatibility

- protocol version and capability negotiation;
- client min/max supported server generation;
- server min/max supported agent generation;
- explicit unsupported-version errors;
- documented compatibility matrix;
- upgrade order documented;
- no silent use of incompatible response shapes.

## Operational hardening

- enterprise proxy behavior validated;
- TLS and certificate errors fail closed;
- bounded retry with jitter for idempotent reads;
- rate-limit retry hints;
- cache retention and manual clear;
- support correlation IDs;
- support bundle for desktop connectivity.

## Deliverables

- [ ] Desktop Entra registration runbook.
- [ ] Production authentication implementation.
- [ ] Connectivity health strip.
- [ ] Protocol-capability document.
- [ ] Compatibility test suite.
- [ ] Upgrade-order runbook.
- [ ] Desktop self-diagnostics export.

## Exit gate

M4 is complete when an enterprise operator can sign in, retrieve evidence, diagnose connection failures, and understand version incompatibility without needing developer tooling.

---

# M5 — Long-lived agent and collection jobs

## Outcome

The agent can remain installed across the device lifecycle and respond to approved server-mediated collection requests safely and transparently.

## Agent lifecycle scope

- bootstrap-stage design;
- managed-agent enrollment;
- durable registration and certificate lifecycle;
- agent capability advertisement;
- heartbeat and health;
- signed/versioned configuration;
- bounded local evidence ring;
- durable upload queue;
- upgrade and rollback;
- certificate renewal and revocation;
- retirement/final collection flow;
- self-diagnostics.

## Collection-job model

Job states:

```text
requested
→ authorized
→ queued
→ acknowledged
→ collecting
→ packaging
→ uploading
→ ingested
→ completed
```

Terminal alternatives:

```text
cancelled
expired
timedOut
rejected
collectionFailed
uploadFailed
integrityFailed
```

Every job records:

- requester;
- authorization decision;
- target registration/asset;
- collection profile and version;
- creation and expiry;
- agent acknowledgement;
- status transitions;
- resulting session;
- audit and correlation IDs;
- sanitized failure reason.

## Collection profiles

Profiles must be:

- approved and versioned;
- bounded by file count, size, runtime, and source scope;
- clear about required privilege;
- explicit about redaction policy;
- signed or integrity protected;
- safe to retry or explicitly marked nonrepeatable;
- represented in the evidence manifest.

## Desktop experience

- request approved collection;
- display job status;
- cancel where safe;
- refresh automatically or intentionally;
- open resulting evidence;
- show why a job failed or expired;
- no direct desktop-to-agent socket.

## Deliverables

- [ ] Agent lifecycle ADR.
- [ ] Collection-job protocol.
- [ ] Collection-profile schema.
- [ ] Platform job API and storage.
- [ ] Agent job receiver/executor.
- [ ] Desktop job UI.
- [ ] End-to-end on-demand collection test.
- [ ] Agent update/rollback test.
- [ ] Retirement workflow draft.

## Exit gate

M5 is complete when an operator requests a bounded collection from the desktop, the agent completes it through the server-mediated path, and the resulting evidence opens in the desktop with complete job and provenance records.

---

# M6 — Asset continuity and evidence chain

## Outcome

Project Theseus maintains one explainable logical asset history across wipes, reenrollment, routine repairs, and motherboard/TPM replacement without flattening distinct technical identities.

## Data model

- Asset;
- Hardware Incarnation;
- OS Instance;
- Agent Registration;
- Management Alias;
- Hardware Identity Observation/Profile;
- Identity Claim;
- Identity Match Candidate;
- Identity Decision;
- Evidence Session;
- Evidence Manifest;
- Server Receipt.

## Hardware identity

Initial claim categories:

- TPM-backed product identity/attestation anchor;
- SMBIOS system UUID;
- system/chassis/baseboard/BIOS serials;
- firmware asset tag;
- manufacturer/model;
- disk and adapter context;
- customer-provided asset/CMDB ID;
- management aliases as weak contextual links.

Controls:

- tenant-scoped tokens;
- placeholder rejection;
- fleet-prevalence downgrade;
- source and quality metadata;
- conflict detection;
- no globally comparable raw fingerprint in ordinary telemetry.

## Matching decisions

- high-confidence automatic attach;
- medium-confidence operator suggestion;
- low-confidence new asset candidate;
- contradictory quarantine;
- reversible attach, unlink, split, replacement, duplicate-registration decisions;
- planned repair continuity claim.

## Evidence chain

Agent-signed manifest:

- registration and OS instance;
- collection reason/profile/version;
- sequence and times;
- files, sizes, hashes;
- previous manifest hash where used;
- signature.

Server receipt:

- authenticated registration/certificate;
- receipt time;
- resolved asset/incarnation/OS instance;
- identity-decision reference;
- stored-object hash;
- audit event.

Association changes never rewrite original manifests or receipts.

## Desktop experience

- asset identity card;
- incarnation and OS history;
- wipe transition;
- repair transition;
- changed/unchanged claim comparison;
- confidence and reason codes;
- manual attach/split/unlink/undo;
- ticket/reference field;
- complete audit history.

## Validation scenarios

1. Normal reinstall with same hardware.
2. Intune/Entra deletion and reenrollment.
3. Disk replacement.
4. NIC replacement/dock changes.
5. Bad or duplicated motherboard serials.
6. Placeholder SMBIOS UUID.
7. Motherboard/TPM replacement with planned claim.
8. Motherboard/TPM replacement without claim.
9. Two concurrently active devices sharing weak identifiers.
10. Incorrect manual link followed by undo/split.
11. Tenant migration.
12. Evidence collected before and after identity correction.

## Deliverables

- [ ] Asset Continuity ADR.
- [ ] Identity claim inventory and normalization rules.
- [ ] Data migrations.
- [ ] Match engine and reason codes.
- [ ] Identity-decision ledger.
- [ ] Repair claim flow.
- [ ] Signed manifest and server receipt.
- [ ] Desktop history and review UI.
- [ ] Adversarial identity test corpus.

## Exit gate

M6 is complete when the validation scenarios preserve correct provenance and produce understandable, reversible asset-history decisions.

---

# M7 — Design-partner pilot readiness

## Outcome

The product can be deployed into a bounded real customer environment with defined support, security, success metrics, and rollback.

## Pilot package

- architecture/readiness workshop;
- customer responsibilities;
- Azure/self-host deployment path;
- Entra application setup;
- PKI/agent identity;
- Intune agent deployment;
- pilot device cohort;
- data classification and retention;
- firewall/proxy requirements;
- backup and restore;
- upgrade/rollback;
- operator onboarding;
- support and escalation path;
- end-of-pilot exit/removal plan.

## Security and operations

- threat model reviewed;
- secrets inventory;
- dependency and vulnerability handling;
- secure defaults;
- audit verification;
- backup/restore rehearsal;
- disaster-recovery rehearsal;
- health monitoring and alerting;
- agent and server support bundles;
- customer evidence-access policy;
- incident-response contacts.

## Success metrics

At minimum:

- successful agent enrollment rate;
- agent last-seen reliability;
- collection-to-ingest success rate;
- median collection-to-desktop-open time;
- failed pull rate and root causes;
- avoided manual log transfer;
- avoided remote-control sessions;
- investigation completion time before/after;
- operator repeat usage;
- support hours per environment;
- storage growth per endpoint/session.

## Commercial readiness

- design-partner agreement;
- paid scope and price;
- support boundaries;
- data-processing terms as applicable;
- product disclaimer and acceptable use;
- release/support lifecycle;
- feedback and case-study permission process.

## Exit gate

M7 is complete when the product can be installed, operated, supported, upgraded, backed up, and removed through documented procedures, and a qualified design partner has agreed to a bounded paid pilot.

---

# M8 — Paid supported preview

## Outcome

Project Theseus is a repeatable paid product offer rather than a one-off engineering engagement.

## Product package

- supported self-hosted preview release;
- founder-signed desktop and agent;
- supported server/platform image;
- compatibility matrix;
- release notes and security notices;
- installation and operations documentation;
- defined support response targets;
- customer licensing/subscription mechanism;
- upgrade entitlement and support period.

## Repeatability requirements

- deployment does not require source editing;
- tenant/environment configuration is parameterized;
- customer-specific secrets are externalized;
- upgrades are tested from the previous supported preview;
- support bundle captures enough evidence to diagnose the product pipe;
- customer onboarding has a standard checklist;
- pricing and support scope can be quoted consistently.

## Commercial proof

- at least one paying deployment completes the pilot;
- a second qualified customer can be onboarded without redesigning the product;
- measured customer value supports recurring pricing;
- support burden and infrastructure costs are understood;
- product feedback produces a prioritized roadmap rather than uncontrolled custom work.

## Exit gate

M8 is complete when the product can be sold and delivered twice through substantially the same deployment, support, and release process.

---

# M9 — Fleet intelligence and guarded actions

## Outcome

The platform extends from single-device investigations to evidence-backed fleet operations without becoming a generic RMM or SIEM.

## Fleet intelligence

- repeated failure clustering;
- cohort and rollout comparison;
- change-point detection around app/policy/agent versions;
- incident blast-radius estimation;
- fleet evidence coverage;
- before/after outcome comparison;
- saved organization investigations;
- ITSM/ticket linkage.

## Guarded actions

Possible approved catalog:

- request evidence profile;
- trigger MDM sync;
- restart a known service;
- retry a bounded workflow;
- clear a narrowly defined cache;
- run a signed approved remediation with pre/post evidence.

Required controls:

- role and authorization;
- explicit target set;
- bounded runtime/output;
- signed/versioned action definition;
- cancellation and timeout;
- audit;
- pre/post evidence;
- no arbitrary command shell.

## Exit gate

M9 is complete when a fleet-level insight or approved action creates measurable operational value while preserving the product's evidence-first, controlled-diagnostics boundary.

---

# Cross-milestone workstreams

These run throughout the program.

## Security

- threat modeling;
- secret handling;
- dependency review;
- authentication and authorization;
- audit and tamper evidence;
- release provenance;
- vulnerability response.

## Privacy

- data minimization;
- collection transparency;
- redaction;
- customer retention policy;
- user-sensitive evidence controls;
- export safety.

## Quality

- synthetic fixtures;
- adversarial identity tests;
- protocol compatibility tests;
- platform integration tests;
- cross-platform desktop builds;
- performance and capacity tests;
- reproducible release checks.

## Commercial discovery

- customer interviews;
- workflow measurement;
- pricing tests;
- design-partner qualification;
- objection tracking;
- support-cost tracking.

## Upstream intake

- periodic CMTrace Open review;
- security/correctness triage;
- controlled desktop integration;
- no default commercial-platform contribution back.

---

# Milestone dependency summary

| Milestone | Hard dependencies | Can begin partially before dependency closes? |
|---|---|---|
| M0 | None | N/A |
| M1 | M0 ownership direction | Yes, local preparation only |
| M2 | M1 repositories | Product-manifest design can begin |
| M3 | M1; enough M2 identity to avoid collisions | Server/desktop components can proceed in parallel |
| M4 | M3 vertical slice | Auth design and protocol metadata can begin earlier |
| M5 | M3 platform/desktop pipe; M4 compatibility principles | Agent job protocol can be drafted earlier |
| M6 | M1 schema ownership; M5 registration concepts | Identity ADR and fixtures can begin earlier |
| M7 | M3–M6 feature subset selected for pilot | Customer discovery can begin immediately |
| M8 | Successful M7 pilot | Packaging hypotheses can begin earlier |
| M9 | Trustworthy evidence and lifecycle model | Research only before M6/M8 |

---

# Immediate next-step queue

## Do now

1. Approve this roadmap as the execution baseline.
2. Decide the GitHub organization name.
3. Create the organization with owner recovery and MFA.
4. Create the two private repositories.
5. Mirror histories and tags.
6. Record baselines and license inventory.
7. Establish branch protection, environments, and signing authority.
8. Move/continue stored-bundle and desktop-server-client work in the private repositories.

## Do immediately after repository creation

1. Add product manifest and independent identities.
2. Redirect the platform to the private desktop.
3. Define component and protocol versioning.
4. Create M3 issue epics in the private repositories.
5. Build the smallest lab-mode vertical slice.
6. Create a repeatable demo environment.

## Do not let block M3

- final public product name;
- perfect multi-tenant architecture;
- generalized search;
- complete Asset Continuity implementation;
- managed SaaS;
- fleet actions;
- complete plugin architecture.

---

# Controlling product gate

Until M3 is complete, the program should judge work against one question:

> **Does this help a remote endpoint's stored evidence appear safely and usefully inside the commercial desktop investigation experience?**

If not, the work must either be a prerequisite, a security obligation, or explicitly deferred.
