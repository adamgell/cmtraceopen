# Product Memory — Enterprise Endpoint Evidence Platform

**Status:** Canonical product-direction memory  
**Captured:** 2026-08-08  
**Owner:** Adam Gell  
**Open-source upstream:** `adamgell/cmtraceopen`  
**Platform/server work:** `adamgell/cmtraceopen-web`  
**Commercial product name:** Not yet selected

---

## Why this document exists

This document preserves the product strategy, architecture direction, commercial model, identity model, and development priorities discussed on 2026-08-08.

It is deliberately broader than a feature specification. It records the product thesis and the reasons behind it so future implementation choices do not accidentally reduce the product to a generic log viewer, a generic log warehouse, or a collection of disconnected agent registrations.

The direction can be summarized in one sentence:

> Build a commercial downstream product from CMTrace Open that gives endpoint engineers remote endpoint evidence inside a rich desktop investigation experience, with an agent that accompanies a managed device from its earliest practical provisioning stage until retirement.

---

# 1. Product thesis

## 1.1 The real product

The server is not the product by itself. The agent is not merely a log uploader. The desktop is not merely a local file viewer.

The complete product is:

> **A permanent endpoint evidence layer, with the desktop application as the investigation cockpit.**

The agent lives with the machine throughout its managed life. It quietly preserves the evidence needed to understand what happened. The server provides identity, transport, policy, retention, fleet coordination, audit, and operational trust. The desktop turns the evidence into an investigation an endpoint engineer can actually work.

The commercial wedge is:

> **Remote endpoint evidence appearing inside the existing desktop investigation experience.**

This is more specific and more valuable than claiming to be a generic enterprise log platform.

## 1.2 North-star language

Candidate product statement:

> The product is an endpoint evidence and investigation platform. Its agent accompanies managed devices from provisioning through retirement, its server preserves and coordinates their evidence, and its desktop gives endpoint engineers a complete investigation experience for remote devices.

Candidate commercial promise:

> Every managed endpoint has a history. The product makes that history available when troubleshooting begins.

Useful internal metaphor:

- **Agent:** flight recorder
- **Server:** evidence plane and control plane
- **Desktop:** investigation cockpit

## 1.3 Installed first, removed last

The agent should be installed at the earliest practical managed trust boundary and remain present until the endpoint's management identity is intentionally retired.

It may not literally be the first process installed on a new Windows machine because Windows and the management channel must exist first. The product goal is still clear:

- install during pre-provisioning or as one of the first required managed applications;
- preserve enrollment and provisioning evidence as early as possible;
- remain through normal operations, incidents, repairs, migrations, and upgrades;
- perform a final bounded collection before retirement when policy allows;
- revoke the agent identity and uninstall cleanly near the end of the machine lifecycle.

---

# 2. Product boundaries

## 2.1 What this product should be

The product should be an:

> **Endpoint evidence, investigation, and controlled-diagnostics platform for managed-device operations.**

Initial specialization should remain strongly focused on:

- Microsoft Intune;
- Windows Autopilot and Device Preparation;
- Enrollment Status Page;
- Win32 and Microsoft Store application deployment;
- scripts and remediations;
- compliance and configuration policy evidence;
- Entra registration and device identity;
- Windows event logs and deployment logs;
- ConfigMgr/SCCM evidence where supported;
- eventually, macOS and other managed endpoint evidence.

## 2.2 What it should not become

Do not let the product drift into being:

- a generic SIEM;
- a general-purpose log warehouse;
- an EDR replacement;
- a full MDM replacement;
- a generic RMM;
- a remote desktop product;
- an arbitrary remote shell;
- an employee-surveillance platform.

Those categories bring different buyers, competitors, security expectations, and engineering burdens. The differentiated value is trustworthy endpoint evidence and specialized investigation.

---

# 3. Open-source upstream and commercial downstream

## 3.1 The desired model

CMTrace Open remains the public open-source upstream.

A separate commercial downstream product should be created from the current CMTrace Open codebase, renamed, branded independently, and developed as a potentially sellable product. The commercial product should continue accepting selected improvements from CMTrace Open over time.

The relationship should be:

```text
Public upstream: CMTrace Open
  ├── parser improvements
  ├── local investigation workspaces
  ├── performance and accessibility
  ├── common bug and security fixes
  └── community contributions
             │
             │ reviewed upstream integrations
             ▼
Commercial downstream product
  ├── independent product name and trademarks
  ├── server-connected desktop mode
  ├── enterprise agent lifecycle
  ├── asset continuity and chain of evidence
  ├── commercial packaging and support
  ├── enterprise release train
  ├── proprietary or source-available modules as decided
  └── managed/self-hosted commercial offerings
```

## 3.2 Do not treat this as only a GitHub fork

The commercial product should be a **downstream product repository**, not merely a public GitHub fork with a different logo.

Preferred setup:

1. Create a separate company or product GitHub organization.
2. Create an independent private repository initialized from the full CMTrace Open Git history.
3. Configure remotes locally as:

```text
origin    = commercial downstream repository
upstream  = adamgell/cmtraceopen
```

4. Record the exact CMTrace Open commit used as the commercial baseline.
5. Preserve upstream history and required license notices.
6. Integrate upstream changes through reviewed pull requests rather than automatically merging every upstream commit.

This preserves traceability while allowing the commercial product to diverge safely.

## 3.3 Legal baseline

CMTrace Open is currently MIT licensed. The MIT license permits use, modification, distribution, sublicensing, and sale, provided the copyright and license notice are retained in copies or substantial portions.

Implications:

- Adam can sell a renamed product derived from the current code.
- Existing MIT-licensed portions remain subject to the MIT notice.
- Proprietary commercial code can be added around or alongside MIT components.
- A commercial binary can contain MIT code without requiring the entire commercial product to be open sourced.
- Existing third-party contributions remain MIT licensed; their copyright is not erased by creating a commercial downstream.
- The commercial product needs a third-party notices and attribution process.
- A future dual-license strategy for upstream contributions requires explicit contributor governance and should be reviewed by qualified counsel.

The current CMTrace Open disclaimer also makes clear that the name refers descriptively to compatibility and does not grant Microsoft trademark rights. A new commercial product should have a distinct name that does not depend on Microsoft's `CMTrace` mark.

## 3.4 Contribution governance before commercialization

Before accepting major new contributions intended to flow into a commercial downstream, decide on one of these models:

- continue MIT-only contributions and consume them under MIT;
- Developer Certificate of Origin, with contributions remaining MIT;
- Contributor License Agreement granting sufficient additional rights for dual licensing;
- company-owned core with carefully separated community components.

Do not retroactively assume ownership of contributor copyrights.

## 3.5 Upstream integration policy

Not every CMTrace Open change should enter the commercial product immediately.

Use a controlled process:

1. Track the last integrated upstream commit in a machine-readable file.
2. Review upstream commits since that point.
3. Classify them:
   - security fix;
   - parser correctness;
   - shared UI improvement;
   - dependency or build update;
   - community-only feature;
   - incompatible architecture change;
   - irrelevant development tooling.
4. Integrate selected changes into a dedicated branch.
5. Run commercial compatibility and regression gates.
6. Resolve branding and configuration conflicts through maintained downstream overlays.
7. Merge only after the commercial release train is green.

Preferred integration cadence:

- urgent security fixes: immediately;
- normal upstream maintenance: weekly or biweekly;
- major upstream features: planned release integration;
- never merge upstream `main` directly into commercial production without review.

## 3.6 Keep divergence intentional

The commercial downstream should avoid gratuitously rewriting shared upstream code. Excessive changes to core parser and local-workspace files will make every upstream integration expensive.

Prefer these seams:

- shared parser crates with stable contracts;
- product configuration and branding manifests;
- capability interfaces;
- enterprise-only modules and routes;
- separate commercial shell/navigation where necessary;
- adapters around upstream components instead of edits throughout them;
- database and protocol contracts versioned independently from visual branding.

When a bug or generally useful improvement is found in shared code, fix it upstream first when practical, then integrate it downstream.

---

# 4. Commercial product architecture

## 4.1 Three surfaces, one evidence plane

```text
                    ┌──────────────────────────────┐
                    │ API server / evidence plane  │
                    │ ingest · query · identity ·  │
                    │ jobs · audit · retention     │
                    └───────────┬──────────────────┘
             mTLS / outbound    │     operator auth
             upload + jobs      │     query + download
                    │           │
         ┌──────────▼────┐  ┌───▼─────────────────────┐
         │ Endpoint agent │  │ Commercial desktop      │
         │ lifecycle      │  │ investigation cockpit  │
         │ evidence layer │  │ local + remote evidence│
         └───────────────┘  └─────────────────────────┘

                         ┌───────────────────────────┐
                         │ Web console               │
                         │ fleet/admin/browse        │
                         └───────────────────────────┘
```

Default network architecture:

> **Desktop → Server ← Agent**

Do not make direct desktop-to-agent connections the default. Direct inbound access creates firewall, NAT, mTLS, lateral-movement, endpoint-security, and support problems. Live and on-demand activity should remain server mediated.

## 4.2 Current foundation that should be reused

Existing platform work is canonical, not disposable:

- chunked resumable ingest;
- parse-on-ingest;
- keyset query APIs;
- Entra operator authentication and RBAC;
- mTLS device identity;
- CRL and application-gateway modes;
- SQLite/Postgres and local/Azure storage;
- Prometheus metrics and audit;
- retention and rate limiting;
- agent queue, uploader, scheduler, collectors, and redaction;
- Intune deployment and MSI/signing design;
- Azure deployment module;
- day-two, pilot, disaster-recovery, and publishing workflows;
- rich CMTrace Open local workspaces and parsers.

The missing bridge is getting remote evidence into the desktop's existing investigation environment.

---

# 5. First sellable workflow

The first complete product slice is:

1. An operator configures or selects a server.
2. The operator authenticates.
3. The desktop shows connection health.
4. The operator browses devices and evidence sessions.
5. The operator selects a stored session.
6. The desktop downloads the canonical bundle through the server.
7. The desktop validates integrity.
8. The bundle opens through the existing local evidence pipeline and specialized workspaces.

Commercial outcome:

> An endpoint engineer retrieves and analyzes remote Intune or Autopilot evidence without remote-controlling the user device, asking the user to upload logs, or manually moving diagnostic archives between tools.

This workflow should be proven before live collection jobs, fleet search, remote actions, or generalized dashboards.

Linked implementation work at capture time:

- `adamgell/cmtraceopen-web#159` — authenticated session-artifact download contract;
- `adamgell/cmtraceopen#534` — desktop server-mode epic;
- `adamgell/cmtraceopen#535` — connection profiles and typed server-client foundation.

---

# 6. Endpoint lifecycle vision

## 6.1 Lifecycle stages

| Stage | Agent role | Desktop outcome |
|---|---|---|
| Bootstrap | Start protected local evidence storage and preserve earliest practical context | Show whether agent coverage began before, during, or after enrollment |
| Provisioning | Capture Autopilot, ESP, enrollment, IME, applications, identity, certificates, and policy evidence | Open one provisioning attempt as one investigation |
| Steady state | Maintain low-cost health, change signals, and bounded rolling evidence | Show current health, important transitions, and last known state |
| Incident | Preserve pre-incident context and execute approved collection jobs | Pull fresh evidence into the relevant workspace |
| Repair | Record before-and-after evidence around controlled changes | Compare failing and repaired states |
| Upgrade/migration | Capture feature update, tenant, join, app, and policy transitions | Explain exactly what changed |
| Retirement | Final bounded collection, identity revocation, and clean uninstall | Preserve a final read-only lifecycle record |

## 6.2 Two-stage agent concept

### Bootstrap component

A small, dependable bootstrap capability should:

- start a local evidence ring early;
- record bootstrap/enrollment timestamps;
- preserve installation failures and retries;
- discover initial identity observations;
- work offline;
- hand state to the full agent;
- avoid depending on complete enterprise configuration.

### Managed agent

The full agent should:

- establish mTLS identity;
- register the current agent and OS instance;
- receive signed/versioned configuration;
- upload queued evidence;
- execute approved collection jobs;
- maintain bounded rolling evidence;
- report health and capabilities;
- update and roll back through a controlled channel.

---

# 7. Asset continuity: one device history without one fragile identifier

## 7.1 The problem

A device cannot be permanently identified by:

- Entra device ID;
- Intune managed-device ID;
- Autopilot registration ID;
- hostname;
- Windows installation identity;
- agent registration;
- serial number alone;
- one all-or-nothing custom hardware hash.

Wipes create new management and operating-system identities. Some manufacturers provide missing, placeholder, or duplicated serial/UUID values. Hardware repairs can replace the motherboard, TPM, disk, or other components. A single composite hash changes completely even when one repair occurred and cannot explain which signal changed.

## 7.2 Canonical model

The permanent product identity should be a server-generated logical **Asset**.

```text
Asset
  ├── Hardware incarnation 1
  │     ├── OS instance 1
  │     │     ├── Agent registration A
  │     │     ├── Management aliases
  │     │     └── Evidence sessions
  │     └── OS instance 2 after wipe
  │           ├── Agent registration B
  │           ├── New management aliases
  │           └── Evidence sessions
  └── Hardware incarnation 2 after motherboard/TPM repair
        └── OS instance 3
              ├── Agent registration C
              ├── New management aliases
              └── Evidence sessions
```

Definitions:

- **Asset:** the organization's continuing concept of the machine.
- **Hardware incarnation:** one core hardware identity epoch.
- **OS instance:** one Windows installation or managed operating-system life.
- **Agent registration:** one agent key/certificate lifecycle.
- **Management alias:** a time-bounded external ID such as Intune or Entra.
- **Evidence session:** one scheduled, event-triggered, provisioning, retirement, or operator-requested capture.

A wipe normally creates a new OS instance and agent registration under the same hardware incarnation and asset.

A motherboard or TPM replacement normally creates a new hardware incarnation. It can still be linked to the same logical asset through strong evidence or an audited continuity decision.

## 7.3 Hardware identity profile, not hardware primary key

Build a versioned **Hardware Identity Profile** containing individually typed identity claims.

Possible claim types:

### Strong

- TPM-backed product key or attested hardware anchor;
- tenant-scoped token derived from an approved TPM identity anchor;
- valid, fleet-unique SMBIOS system UUID;
- organization-assigned CMDB or asset identifier.

### Medium

- system serial number;
- chassis serial;
- baseboard serial;
- BIOS serial;
- firmware asset tag;
- manufacturer and model tuple;
- OEM service identifier.

### Weak/contextual

- disk serial;
- permanent physical adapter identity;
- CPU characteristics;
- memory identifiers;
- hostname;
- current user;
- Windows installation date;
- MachineGuid;
- Entra and Intune IDs.

The profile may have an integrity digest, but matching must operate on individual claims so the system can explain what matched and what changed.

## 7.4 Claim quality and fleet prevalence

Every identity claim should have:

- claim type;
- normalized tenant-scoped token;
- source;
- quality;
- validity;
- first/last observed times;
- fleet prevalence;
- optional encrypted display value.

Known placeholder values receive zero identity weight. Examples include all-zero UUIDs, all-`F` values, `To Be Filled By O.E.M.`, `Default string`, and other vendor defaults.

Fleet prevalence must be dynamic. If a supposedly unique value appears on hundreds of devices in one tenant, classify it as non-identifying even if it is not in a static placeholder list.

## 7.5 Tenant-scoped matching tokens

Avoid globally comparable hardware fingerprints.

Conceptual token:

```text
HMAC-SHA256(
  tenant_identity_key,
  claim_type || NUL || normalized_value
)
```

This allows matching inside one customer deployment while reducing cross-customer tracking and raw-identifier exposure.

Raw TPM anchors, full hardware profiles, serials, and hardware hashes must not appear in ordinary logs, metrics, screenshots, or default exports.

## 7.6 Explainable matching

The matching engine should return:

- candidate asset;
- confidence band;
- matched claims;
- conflicting claims;
- missing/degraded claims;
- contextual signals;
- reason codes;
- whether automatic linkage is allowed.

Decision bands:

- **High confidence:** automatically attach the new OS/registration or hardware incarnation to the asset.
- **Medium confidence:** suggest linkage for operator confirmation.
- **Low confidence:** create a new asset candidate.
- **Contradictory:** quarantine for explicit review.

Illustrative explanation:

> Linked to asset A-1042 because the trusted TPM anchor, fleet-unique SMBIOS UUID, and system serial matched. Disk serial changed. A new Windows installation was observed 41 minutes after the prior instance stopped reporting.

## 7.7 Hard matching rules

1. Never auto-link based only on serial number.
2. Never auto-link based only on hostname, user, MAC, Entra ID, or Intune ID.
3. Never use placeholder or fleet-duplicated values as positive identity evidence.
4. Never destroy original identity observations after a link.
5. Never silently join two concurrently active registrations using weak evidence.
6. Never override conflicting trusted TPM and unique SMBIOS anchors solely because a serial matches.
7. Every manual decision must be reversible and audited.
8. Hardware identity change and organizational asset continuity are separate facts.
9. Matching must be tenant scoped.
10. The desktop must explain every automatic or manual continuity decision.

## 7.8 Repair continuity

For planned motherboard or TPM replacement, support a signed, short-lived **repair continuity claim**.

The claim can include:

- asset ID;
- change/service ticket;
- expected repair window;
- operator or provider;
- allowed identity discontinuity;
- expiration;
- single-use nonce.

After repair, a new agent presents the claim and the server creates a new hardware incarnation attached to the existing asset. The system does not pretend the hardware stayed the same; it records that the organization considers the new incarnation a continuation of the asset.

For unplanned repair, the server presents possible previous assets and an operator performs an audited **Attach incarnation to asset** action.

Use `link`, `attach`, `split`, and `unlink` semantics rather than destructive database `merge` semantics.

---

# 8. Chain of identity and chain of evidence

Two separate chains must be preserved.

## 8.1 Identity continuity

This chain answers:

> Which asset, hardware incarnation, OS instance, agent registration, and management aliases produced the evidence?

It is maintained by the asset-continuity graph and immutable identity decisions.

## 8.2 Evidence chain of custody

This chain answers:

> What was collected, by which authenticated agent, when, under which collection profile, and has it changed?

Each evidence bundle should contain a signed manifest with at least:

- manifest schema version;
- agent registration ID;
- hardware observation/profile ID;
- OS instance ID;
- capture reason;
- collection profile ID and version;
- sequence number;
- start and completion times;
- previous manifest hash where chaining is appropriate;
- file list, sizes, and SHA-256 hashes;
- manifest signature.

The server should append an immutable receipt with:

- received time;
- authenticated registration/certificate;
- resolved asset and incarnation;
- identity decision reference;
- stored object hash;
- audit event and correlation ID.

If an operator later changes asset association, the original bundle and receipt are not rewritten. A new identity-association event is added.

This distinction is essential:

- original provenance remains immutable;
- current organizational association can evolve;
- every association change remains attributable and reversible.

---

# 9. Desktop product vision

The commercial desktop must remain a genuine investigator's tool, not become a thin wrapper around the web console.

## 9.1 Device workspace

A device/asset workspace should show:

- logical asset identity;
- current hardware incarnation;
- current OS instance;
- current agent registration and health;
- management aliases;
- enrollment history;
- evidence sessions;
- important change timeline;
- collection jobs;
- local cache status;
- retention/expiry state;
- identity-continuity decisions.

## 9.2 Investigation workspace

An investigation can be associated with:

- one asset;
- one hardware incarnation or OS instance;
- one or more evidence sessions;
- ticket or incident reference;
- notes and findings;
- local and server artifacts;
- baseline and follow-up captures;
- exportable handoff package.

The product's unit of work becomes an **endpoint investigation**, not just an open file.

## 9.3 Evidence timeline

The timeline should eventually correlate:

- agent activity;
- collection jobs;
- Intune logs;
- Autopilot and ESP events;
- application deployment;
- identity and `dsregcmd` state;
- policy/configuration evidence;
- Windows events;
- server ingest events;
- remediation boundaries;
- follow-up evidence.

Every interpreted finding must lead back to exact source evidence and provenance.

## 9.4 Local and remote evidence together

An operator should be able to combine in one investigation:

- a server-collected session;
- a manually supplied diagnostics archive;
- local logs dropped into the desktop;
- exported reports;
- later follow-up collections.

The source must remain visually explicit.

## 9.5 Case export

A future case package should include:

- investigation summary;
- asset/incarnation/OS identity;
- evidence coverage and gaps;
- findings and confidence;
- relevant timeline;
- sanitized excerpts;
- artifact hashes;
- collection and access audit;
- recommended next evidence request.

---

# 10. Agent capability roadmap

## Level 1 — Reliable evidence delivery

- durable local queue;
- bounded scheduled collections;
- server-mediated upload;
- configuration sync;
- heartbeat and health;
- bundle retention;
- desktop retrieval;
- protocol/capability negotiation.

## Level 2 — On-demand collection

- operator requests an approved profile;
- server creates a job;
- agent receives the job through outbound communication or polling;
- agent collects and uploads through the normal pipe;
- desktop shows queued/running/uploading/completed/failed;
- completed evidence opens in the existing workspace.

## Level 3 — Event-triggered evidence

Potential triggers:

- Autopilot or ESP failure;
- repeated IME enforcement failure;
- application install failure;
- enrollment/certificate failure;
- loss of management or PRT state;
- feature-update rollback;
- compliance transition;
- remediation failure;
- agent queue or upload failure;
- repeated agent/service crash.

Triggers must be bounded, policy-driven, transparent, and privacy reviewed. Do not indiscriminately upload every log line forever.

## Level 4 — Before-and-after investigations

```text
Baseline evidence
→ controlled change or remediation
→ follow-up evidence
→ compare
```

Use cases:

- application reinstall;
- policy assignment;
- certificate renewal;
- Entra join repair;
- feature update;
- approved remediation.

## Level 5 — Fleet intelligence

After single-device evidence is trustworthy:

- cluster repeated failures;
- identify cohorts affected by one app/policy/version;
- detect failure onset after a change;
- compare enrollment and deployment outcomes;
- surface likely incident blast radius;
- provide evidence-backed fleet patterns rather than generic log search.

## Level 6 — Guarded endpoint actions

Future actions should come from an approved, versioned catalog. Examples may include:

- collect an evidence profile;
- restart a known service;
- trigger MDM sync;
- retry a bounded workflow;
- clear a narrowly defined cache;
- execute an approved signed remediation with pre/post evidence.

Do not add an arbitrary remote shell. Every action needs authorization, audit, timeout, output limits, versioning, cancellation, and before/after evidence.

---

# 11. Connectivity telemetry

Connectivity telemetry describes the health of the product's own evidence pipe, not endpoint-user surveillance.

The desktop should show locally:

- server reachability and round-trip latency;
- signed-in account and role;
- token expiration/refresh state;
- last successful query;
- last successful artifact pull;
- selected agent last-seen;
- active job and download state;
- last sanitized error;
- client/server/agent protocol compatibility.

Initial telemetry should remain local UI state. Automatic upload of desktop health can be considered later as explicit opt-in or enterprise policy.

---

# 12. Commercial model

## 12.1 Initial buyer

Best early customer profile:

- hundreds to several thousand managed Windows endpoints;
- Intune and Entra;
- meaningful Autopilot, ESP, application, compliance, configuration, or identity failures;
- centralized endpoint engineering/EUC team;
- remote/distributed workforce;
- current investigations frequently require remote control or manual diagnostics handling;
- ability to self-host in Azure or containers.

Likely champion:

- senior Intune engineer;
- endpoint architect;
- EUC operations lead;
- escalation engineer;
- MSP modern-workplace lead.

## 12.2 Community/upstream value

CMTrace Open should remain a genuinely useful open-source product:

- local log viewer;
- local workspaces and diagnostics;
- manual evidence import;
- core parser improvements;
- community bug/security fixes;
- air-gapped/local workflows.

Do not reduce upstream to an unusable demo merely to force commercial conversion.

## 12.3 What customers pay for

Customers should pay for enterprise operational assurance and lifecycle workflows, such as:

- supported agent deployment;
- signed and tested enterprise releases;
- server-connected commercial desktop;
- on-demand collection;
- longitudinal asset history;
- RBAC, audit, retention, and policy controls;
- compatibility guarantees;
- upgrade/rollback tooling;
- architecture validation;
- support response commitments;
- managed Azure operation later;
- fleet intelligence and integrations later.

## 12.4 First revenue offer

Start with a paid **Enterprise Diagnostics Design-Partner Pilot**.

Possible scope:

- readiness and architecture workshop;
- self-hosted/Azure deployment;
- Entra registration and RBAC;
- PKI and agent identity;
- Intune agent deployment;
- pilot cohort;
- retention and storage policy;
- operational handoff;
- direct pilot support;
- success-metrics report;
- structured product feedback.

Initial pricing hypotheses should be tested rather than published prematurely.

## 12.5 Recurring offers

Potential progression:

1. supported self-hosted subscription;
2. enterprise release channel and LTS;
3. managed Azure deployment;
4. MSP/partner deployments;
5. advanced fleet intelligence and integrations.

Do not build multi-tenant SaaS operations before the self-hosted workflow and customer value are proven.

---

# 13. Development sequence

## A. Commercial downstream foundation

- choose product/company name;
- establish company/product GitHub organization;
- create independent private downstream repository from current upstream history;
- record baseline upstream commit;
- preserve MIT notices and generate third-party notices;
- implement product/branding configuration seams;
- establish upstream-integration workflow;
- define commercial release/versioning policy;
- separate credentials, signing identities, download domains, telemetry endpoints, and update channels from CMTrace Open.

## B. Remote evidence vertical slice

Parallel work:

### Server

- authenticated canonical bundle download;
- streaming from local and Azure storage;
- integrity metadata;
- audit;
- expired/missing semantics;
- authorization and object-mismatch tests.

### Desktop

- connection profiles;
- safe URL and TLS policy;
- typed DTOs and errors;
- server connectivity test;
- device/session browser;
- download, hash validation, atomic cache finalization;
- open through existing local evidence pipeline.

## C. Production authentication

- dedicated desktop public-client Entra registration;
- authorization code with PKCE;
- system browser;
- secure token storage and refresh;
- sign-out/account switching;
- role and expiration telemetry.

## D. Agent/job maturity

- heartbeat and capabilities;
- job abstraction;
- collection profile versioning;
- on-demand collection;
- download/job cancellation;
- agent update/rollback;
- self-diagnostics support bundle.

## E. Asset continuity and evidence chain

Before long-lived fleet pilots:

- Asset/HardwareIncarnation/OSInstance/AgentRegistration model;
- hardware identity profile and claim quality;
- matching engine and reason codes;
- external aliases;
- repair continuity workflow;
- immutable identity-decision ledger;
- signed evidence manifests and server receipts;
- desktop identity history and link/split/undo UI.

## F. Pilot hardening

- threat model;
- privacy and data classification;
- cache retention and disk-space checks;
- proxy behavior;
- protocol compatibility matrix;
- backup/restore and DR rehearsal;
- upgrades and rollback;
- support runbooks;
- legal/customer terms;
- design-partner pilot.

---

# 14. Product and engineering invariants

1. The commercial product is a downstream product, not merely a renamed public fork.
2. CMTrace Open remains the open-source upstream and adoption engine.
3. The first sellable workflow is remote evidence opened inside the desktop investigation experience.
4. Local-only investigation remains valuable and must not depend on server availability.
5. Desktop-to-agent communication is server mediated by default.
6. A logical asset is not the same as an Entra, Intune, OS, agent, serial, TPM, or hardware-hash identity.
7. Hardware profiles are matching evidence, not canonical primary keys.
8. Wipes create new OS instances, not automatically new assets.
9. Motherboard/TPM repairs create new hardware incarnations that may continue the same asset.
10. Identity decisions are explainable, reversible, and audited.
11. Evidence provenance is immutable even when identity association changes.
12. Findings must retain source provenance and confidence.
13. The agent should collect bounded, purpose-specific evidence rather than indiscriminate surveillance data.
14. No arbitrary remote shell.
15. Shared fixes should flow upstream when practical to reduce commercial divergence.
16. Upstream integrations into the commercial product are reviewed and tested, never blind.
17. The commercial differentiator is lifecycle evidence and specialized investigation, not generic log storage.

---

# 15. Decisions still needed

## Product/company

- commercial product name;
- company/legal entity and ownership;
- trademark search and registrations;
- domain names;
- public vs private timing;
- commercial license and customer terms;
- contribution agreement strategy.

## Repository structure

- exact downstream repository and organization;
- mono-repo vs coordinated desktop/server/agent repositories;
- whether shared parser crates are vendored, subtree-integrated, or package-versioned;
- upstream-integration cadence and ownership;
- product branding/config overlay design.

## Commercial packaging

- self-hosted subscription tiers;
- endpoint/capacity/support pricing metric;
- design-partner pilot price;
- which modules remain MIT, source-available, or proprietary;
- managed-hosting timeline.

## Identity

- initial identity claim inventory;
- TPM enrollment and attestation design;
- tenant identity-key custody and rotation;
- automatic-match thresholds;
- repair claim workflow;
- encrypted display-value policy;
- identity-decision retention.

## Agent lifecycle

- earliest supported install stage;
- bootstrap-to-managed-agent handoff;
- local evidence-ring limits;
- update/rollback strategy;
- retirement collection and revocation;
- customer-configurable event triggers.

---

# 16. Immediate next actions

1. Select a temporary internal commercial codename so engineering can begin without committing to public branding.
2. Create the independent private commercial downstream repository from the current CMTrace Open history.
3. Record the upstream baseline commit and add `UPSTREAM.md` plus an integration ledger.
4. Create an ADR for the upstream/downstream commercial model.
5. Create an ADR for Asset → Hardware incarnation → OS instance → Agent registration → Evidence session.
6. Implement the authenticated bundle-download server prerequisite.
7. Implement the desktop typed server-client foundation.
8. Complete the lab-mode end-to-end evidence pull.
9. Demonstrate one stored remote Intune/Autopilot session opening inside the commercial desktop.
10. Use that demo to recruit the first paid design partner.

---

# Closing memory

The commercial opportunity is not selling a renamed log viewer.

It is selling a durable endpoint evidence and investigation system built from the strengths of CMTrace Open:

- an agent present across the managed device lifecycle;
- an evidence plane that preserves identity, provenance, policy, and history;
- a desktop investigation cockpit that understands endpoint-management evidence;
- an open-source upstream that continues improving the local diagnostic foundation;
- a commercial downstream that turns those capabilities into a supported enterprise product.

The decisive first milestone remains simple and concrete:

> **Select a remote device, retrieve its evidence through the server, and open it inside the desktop investigation experience.**
