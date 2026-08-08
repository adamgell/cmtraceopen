# Project Theseus — Program Charter

**Status:** Draft for execution  
**Program owner:** Adam Gell  
**Internal codename:** Project Theseus  
**Binary publisher during startup:** Adam Gell  
**Repository owner:** New organization, name not yet selected  
**Public product name:** Still under exploration

---

## 1. Mission

Project Theseus will turn the proven local investigation capabilities of CMTrace Open into a private commercial endpoint evidence and investigation platform.

The product will place remote endpoint evidence inside a rich desktop investigation experience while an endpoint agent accompanies the device from the earliest practical managed provisioning point through retirement.

The program succeeds when an endpoint engineer can select a remote asset, retrieve trustworthy evidence through the private platform, open that evidence in the commercial desktop, understand how the evidence relates to the asset's lifecycle, and act with materially less manual collection, remote-control activity, and uncertainty.

---

## 2. Product thesis

The complete product is:

> **A permanent endpoint evidence layer, with the desktop application as the investigation cockpit.**

The three principal surfaces are:

- **Agent — flight recorder:** collects bounded, policy-driven evidence; maintains a durable queue; establishes device identity; executes approved collection jobs; reports health and capabilities.
- **Platform — evidence and control plane:** authenticates agents and operators; ingests, stores, retrieves, and audits evidence; maintains asset continuity; schedules jobs; enforces retention and organizational policy.
- **Desktop — investigation cockpit:** combines local and remote evidence; shows device history; runs specialized endpoint-management analysis; preserves provenance; supports investigations, comparison, and handoff.

The commercial wedge is:

> **Remote endpoint evidence appearing inside the existing desktop investigation experience.**

---

## 3. Accepted business and repository model

Project Theseus uses a traditional open-core model.

### Public open-source product

`adamgell/cmtraceopen` remains public and MIT licensed.

It continues as a genuinely useful local investigation product and may receive:

- parser and normalization improvements;
- evidence reducers and findings;
- local diagnostic workspaces;
- local evidence-bundle analysis;
- performance, accessibility, dependency, correctness, and security improvements.

### Private commercial desktop

A new organization-owned private repository will be initialized from the complete CMTrace Open Git history.

It will:

- use an independent commercial product identity;
- selectively accept reviewed CMTrace Open improvements;
- add server connectivity, remote evidence, lifecycle history, organization-aware investigations, commercial release channels, and paid product capabilities;
- have no default obligation to contribute commercial changes back to CMTrace Open.

### Private commercial platform

A new organization-owned private repository will be initialized from the complete `cmtraceopen-web` Git history.

It will contain the private commercial:

- agent;
- API server;
- web console;
- storage and infrastructure;
- deployment and signing workflows;
- asset continuity;
- collection jobs;
- fleet operations;
- enterprise governance and operational tooling.

There is no ongoing public `cmtraceopen-web` contribution surface and no default contribution-back relationship.

---

## 4. Startup identity stack

```text
Internal program:  Project Theseus
Binary publisher:  Adam Gell
Repository owner:  New organization
Public product:    Still under exploration
```

These identities are intentionally separate.

Project Theseus is temporary internal language. It must not become a permanent protocol, database, tenant, installer, or public brand identity.

Binaries distributed during startup and design-partner activity will be digitally signed as `Adam Gell`. A later company-signing transition will be a controlled release event rather than a product-identity change.

---

## 5. Initial architecture boundary

Default communication path:

```text
Commercial Desktop → Private Platform ← Endpoint Agent
```

The product will not default to direct desktop-to-agent connections.

Server-mediated communication avoids inbound endpoint firewall requirements, direct operator-to-endpoint trust, NAT traversal, lateral-movement concerns, and inconsistent connection behavior.

The first architecture slice uses stored evidence. On-demand and live activity follow only after stored-session retrieval is reliable.

---

## 6. Canonical device and evidence model

A permanent device history cannot be keyed to Entra ID, Intune ID, hostname, serial number, one agent certificate, or one all-or-nothing hardware hash.

Project Theseus will use the following hierarchy:

```text
Asset
  ├── Hardware Incarnation
  │     ├── OS Instance
  │     │     ├── Agent Registration
  │     │     ├── Management Aliases
  │     │     └── Evidence Sessions
  │     └── OS Instance after wipe
  └── Hardware Incarnation after repair
        └── OS Instance
```

Core rules:

1. The server-generated **Asset ID** is the permanent logical product identity.
2. Hardware observations are explainable matching claims, not the Asset primary key.
3. Wipes normally create a new OS Instance, not a new Asset.
4. Motherboard or TPM replacement normally creates a new Hardware Incarnation.
5. A new Hardware Incarnation may continue the same Asset through strong evidence or an audited operator decision.
6. Entra, Intune, Autopilot, ConfigMgr, hostname, and other external identifiers are time-bounded aliases.
7. Identity decisions are explainable, reversible, and audited.
8. Evidence provenance remains immutable if asset association changes later.

The evidence chain and identity-continuity chain are distinct but linked.

---

## 7. Program workstreams

### W1 — Organization, ownership, and legal readiness

Purpose:

- establish the organization-owned commercial source boundary;
- separate startup activity from personal repository ownership;
- preserve licensing and attribution obligations;
- prepare future company ownership and signing transition.

Outputs:

- GitHub organization;
- repository ownership and team model;
- contribution and third-party notice policy;
- startup signing policy;
- commercial IP and employment-policy review;
- future company signer migration plan.

### W2 — Commercial desktop downstream

Purpose:

- create a private, independently named descendant of CMTrace Open;
- preserve selective upstream intake without allowing upstream structure to dominate the commercial product.

Outputs:

- private desktop repository with complete history;
- product manifest and brand-neutral shell;
- independent package IDs, update channels, signing, installer identity, and release metadata;
- upstream baseline and integration ledger;
- commercial-only capability registration.

### W3 — Private platform continuation

Purpose:

- move the agent/server/web/infra ancestry into an organization-owned private commercial platform;
- establish a production-shaped foundation for design partners.

Outputs:

- private platform repository with complete history;
- redirected packages, registries, Actions, environments, cloud resources, secrets, deployment tooling, and documentation;
- private desktop integration;
- supported development and preview deployment path.

### W4 — Remote stored-evidence vertical slice

Purpose:

- prove the first sellable workflow.

Outputs:

- operator-authenticated bundle download;
- typed desktop server client;
- server profile and connection health;
- device and session browser;
- streaming download, integrity validation, atomic cache finalization;
- open through existing local bundle and workspace pipeline.

### W5 — Authentication, protocol, and compatibility

Purpose:

- make the desktop/agent/platform relationship supportable over multiple releases.

Outputs:

- dedicated desktop Entra public-client registration;
- authorization-code + PKCE flow;
- secure token lifecycle;
- explicit protocol and capability negotiation;
- supported-version matrix;
- safe failure behavior for version skew;
- correlation IDs and operator-facing error taxonomy.

### W6 — Agent lifecycle and collection jobs

Purpose:

- evolve the agent from scheduled uploader into a long-lived evidence service.

Outputs:

- early bootstrap design;
- managed agent enrollment;
- health and capabilities;
- signed/versioned configuration;
- approved collection profiles;
- on-demand collection jobs;
- cancellation, timeout, retry, and result states;
- update, rollback, revocation, and retirement workflows.

### W7 — Asset continuity and chain of evidence

Purpose:

- create a trustworthy lifecycle record across wipes, reenrollment, repairs, and identity changes.

Outputs:

- Asset/Hardware Incarnation/OS Instance/Agent Registration schema;
- hardware identity profile and tenant-scoped claims;
- match scoring and reason codes;
- manual attach/split/unlink/undo decisions;
- planned repair continuity claims;
- signed evidence manifests;
- immutable server receipts and identity-decision ledger;
- desktop identity-history experience.

### W8 — Enterprise operations and security

Purpose:

- make customer deployments supportable and defensible.

Outputs:

- threat model;
- data classification and privacy policy;
- audit and retention controls;
- backup, restore, and disaster-recovery validation;
- upgrade and rollback procedures;
- support bundle and self-diagnostics;
- operational dashboards and alerts;
- secure release and artifact provenance.

### W9 — Design-partner and commercial readiness

Purpose:

- convert engineering capability into a paid, measurable customer outcome.

Outputs:

- design-partner offer and qualification criteria;
- architecture/readiness workshop;
- pilot deployment checklist;
- success metrics;
- customer support process;
- pricing hypotheses;
- commercial terms and licensing;
- case study and feedback process.

### W10 — Fleet intelligence and guarded actions

Purpose:

- extend the platform after single-device evidence and lifecycle identity are trustworthy.

Outputs:

- incident clustering;
- cohort analysis;
- deployment-change correlation;
- before/after comparisons;
- approved action catalog with authorization and pre/post evidence;
- no arbitrary remote shell.

---

## 8. Product scope and non-goals

### First commercial scope

- stored remote evidence retrieval;
- commercial desktop investigation;
- private agent/server/web platform;
- visible connectivity health;
- self-hosted deployment first;
- Intune/Autopilot/endpoint-management evidence specialization.

### Deferred until prior gates are proven

- live endpoint tailing;
- generalized fleet search;
- multi-tenant SaaS;
- managed hosting;
- broad endpoint remediation;
- MSP cross-customer management;
- fleet intelligence;
- arbitrary endpoint scripting.

### Permanent non-goals unless explicitly reversed

- covert user surveillance;
- arbitrary remote shell;
- replacement for Intune/MDM;
- replacement for EDR/SIEM;
- direct peer-to-peer operator access as the normal architecture.

---

## 9. Decision governance

### Decision classes

- **Product decision:** customer promise, packaging, public/open boundary, pricing, naming.
- **Architecture decision:** identity model, protocol, storage, security boundary, release compatibility.
- **Operational decision:** hosting, support, signing, release, backup, incident response.
- **Implementation decision:** module design, libraries, UI structure, test strategy.

### Recording requirement

Product, architecture, and operational decisions must be recorded in durable Markdown before they become difficult to reverse.

Each accepted decision should include:

- context;
- decision;
- alternatives considered;
- consequences;
- migration or rollback notes;
- owner;
- decision date.

### Change control

A decision is not immutable, but superseding it must be explicit. New decisions should name the prior document or rule they replace.

---

## 10. Development and review principles

1. Build vertical slices that create customer-visible outcomes.
2. Preserve local-only behavior and startup independence.
3. Keep commercial capability around shared upstream components rather than scattered through them.
4. Treat protocols, identity, evidence manifests, and database migrations as long-lived contracts.
5. Use fail-closed security defaults.
6. Preserve provenance and confidence; never improve certainty merely for a cleaner UI.
7. Keep agent collections bounded, transparent, versioned, and policy controlled.
8. Avoid building future scale abstractions before the first remote evidence workflow works end to end.
9. Prefer upstream intake through reviewed PRs and explicit baselines.
10. Every release must identify desktop/server/agent/protocol compatibility.
11. Every distributed binary must be signed and timestamped.
12. Every customer-impacting operation must produce actionable, sanitized diagnostics.

---

## 11. Program success measures

### Product proof

- An operator can retrieve and open stored remote evidence without leaving the desktop.
- The desktop shows why a pull failed without requiring server-log access.
- Local analysis remains functional when the platform is unavailable.
- Evidence integrity and provenance can be verified.

### Operational proof

- Agent, server, and desktop versions have explicit compatibility.
- A preview deployment can be upgraded and rolled back safely.
- Backup and restore are rehearsed.
- Signing and release provenance are reproducible.

### Commercial proof

- At least one design partner pays for deployment and support.
- The customer can measure reduced time to evidence or avoided remote-control effort.
- Product usage continues after the initial pilot novelty period.
- Support effort is understood and does not exceed the value of the engagement.

### Identity proof

- A wipe is represented as a new OS Instance under the correct Asset.
- A routine hardware change does not incorrectly create a new Asset.
- A motherboard/TPM replacement creates a new Hardware Incarnation without losing asset history.
- Operators can understand and reverse continuity decisions.

---

## 12. Primary risks

| Risk | Consequence | Program response |
|---|---|---|
| Excessive downstream divergence | Upstream intake becomes prohibitively expensive | Product manifests, capability seams, shared crates, reviewed intake ledger |
| Overbuilding before a sellable workflow | Long development without market proof | Stored remote evidence vertical slice remains first milestone |
| Weak asset identity | Incorrectly merged or fragmented device history | Multi-claim continuity model, confidence bands, audited manual decisions |
| Agent becomes surveillance-like | Customer trust and legal risk | Bounded purpose-specific collection, transparency, policy, privacy defaults |
| Private platform security defect | High customer and reputation impact | Threat model, least privilege, mTLS, RBAC, audit, signed releases, staged pilots |
| Founder signing transition | Customer allowlist and reputation disruption | Stable product identity, signing generations, documented migration |
| Commercial work tied to personal namespace | Operational and ownership risk | Organization-owned repositories and resources from inception |
| Open-core boundary confuses users | Community distrust or weak conversion | Useful public product; clear local vs managed-lifecycle distinction |
| Support burden exceeds revenue | Unsustainable product | Paid pilots, bounded scope, support instrumentation, operational runbooks |

---

## 13. Immediate program order

1. Choose the GitHub organization identity.
2. Create organization-owned private desktop and platform repositories.
3. Record source baselines and preserve full Git history and tags.
4. Establish product manifest, repository protections, signing, release, and upstream-intake skeletons.
5. Repoint the platform to the private commercial desktop.
6. Complete authenticated stored-bundle download.
7. Complete desktop connection profiles and typed API foundation.
8. Build the device → session → download → open vertical slice.
9. Add connection-health visibility.
10. Add production desktop authentication and compatibility negotiation.
11. Prepare the first self-hosted design-partner deployment.
12. Begin Asset Continuity and signed evidence-chain work after the stored-evidence slice is stable.

---

## 14. Controlling statement

> Project Theseus is the private commercial program that turns CMTrace Open's local investigation engine into a managed endpoint evidence platform. CMTrace Open remains public. The commercial desktop selectively accepts upstream improvements. The private agent/server/web platform remains commercial IP. Startup binaries are signed by Adam Gell, while organization-owned repositories establish the long-term product ownership boundary.
