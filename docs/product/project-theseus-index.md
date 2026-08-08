# Project Theseus — Planning Index

**Status:** Temporary program source of truth pending migration to organization-owned private repositories  
**Owner:** Adam Gell  
**Internal program:** Project Theseus

---

## Canonical identity stack

```text
Internal program:  Project Theseus
Binary publisher:  Adam Gell
Repository owner:  New organization
Public product:    Still under exploration
```

---

# Read in this order

## 1. Product memory

[`enterprise-platform-product-memory.md`](./enterprise-platform-product-memory.md)

The complete product thesis and long-range memory:

- commercial endpoint evidence platform;
- agent as flight recorder;
- platform as evidence/control plane;
- desktop as investigation cockpit;
- installed early and removed near retirement;
- asset continuity;
- evidence chain;
- desktop and agent roadmap;
- commercial model.

## 2. Open-core boundary

[`open-core-repository-boundary.md`](./open-core-repository-boundary.md)

Controlling source boundary:

- CMTrace Open remains public and MIT licensed;
- commercial desktop is a private downstream;
- agent/server/web platform is private commercial IP;
- commercial work has no default contribution-back obligation.

## 3. Repository ownership and signing

[`commercial-repository-and-signing-decision.md`](./commercial-repository-and-signing-decision.md)

Accepted Option B:

- all new commercial repositories live under a dedicated organization;
- binaries are initially signed by Adam Gell;
- later company signing is a controlled publisher-generation transition.

## 4. Startup identity stack

[`startup-identity-stack.md`](./startup-identity-stack.md)

Defines the relationship between Project Theseus, Adam Gell as publisher, the new organization, and the unresolved public product name.

## 5. Naming brief

[`commercial-product-naming-brief.md`](./commercial-product-naming-brief.md)

Internal codename rationale and public-brand exploration criteria.

## 6. Program charter

[`project-theseus-program-charter.md`](./project-theseus-program-charter.md)

Defines:

- mission;
- workstreams;
- product scope and non-goals;
- governance;
- success measures;
- primary risks;
- immediate program order.

## 7. Milestone roadmap

[`project-theseus-milestone-roadmap.md`](./project-theseus-milestone-roadmap.md)

Gate-based milestone sequence:

```text
M0 Direction and ownership
M1 Private repository and build independence
M2 Commercial shell and release identity
M3 Stored remote evidence vertical slice
M4 Production authentication and compatibility
M5 Long-lived agent and collection jobs
M6 Asset continuity and evidence chain
M7 Design-partner pilot readiness
M8 Paid supported preview
M9 Fleet intelligence and guarded actions
```

## 8. Repository skeleton

[`project-theseus-repository-skeleton.md`](./project-theseus-repository-skeleton.md)

Copy-ready bootstrap structure for:

- GitHub organization;
- `theseus-desktop`;
- `theseus-platform`;
- branch protections;
- Actions environments;
- secrets;
- CI;
- release manifests;
- upstream intake;
- issue hierarchy;
- security and documentation.

## 9. Execution backlog

[`project-theseus-execution-backlog.md`](./project-theseus-execution-backlog.md)

Detailed P0/P1/P2 backlog with:

- decisions;
- epics;
- implementation issues;
- acceptance criteria;
- first ordered desktop and platform PR sequences;
- definitions of ready and done;
- immediate next actions.

---

# Current accepted milestone status

| Milestone | Status | Notes |
|---|---|---|
| M0 — Direction and ownership | In progress | Core decisions accepted; organization name and private creation remain |
| M1 — Private repositories | Not started | Skeleton ready; blocked on organization name/creation |
| M2 — Commercial shell | Not started | Product-manifest and identity plan drafted |
| M3 — Stored remote evidence | Partially scoped | Existing public ancestry issues must move into private repos |
| M4 — Production auth/compatibility | Planned | Entra desktop and telemetry direction accepted |
| M5 — Agent/jobs | Planned | Follows stored-session vertical slice |
| M6 — Asset continuity/evidence chain | Architecture drafted | Detailed implementation follows initial remote evidence proof |
| M7 — Design-partner readiness | Planned | Customer discovery may begin earlier |
| M8 — Paid preview | Planned | Depends on repeatable pilot |
| M9 — Fleet intelligence/actions | Deferred | Evidence-first boundaries retained |

---

# Current blockers

## Blocking M1

- organization/company namespace not selected;
- organization not created;
- private repositories not created.

## Not blocking M1–M3

- final public product name;
- final company/legal entity name if organization uses a durable studio/company placeholder;
- company-owned code-signing certificate;
- multi-tenant SaaS design;
- fleet intelligence;
- complete asset-continuity implementation.

---

# First execution objective

Until the stored-evidence vertical slice is complete, all work should be evaluated against:

> **Does this help a remote endpoint's stored evidence appear safely and usefully inside the commercial desktop investigation experience?**

The required product demonstration is:

```text
Select server
→ authenticate or use bounded lab mode
→ select device
→ select stored session
→ stream bundle
→ verify integrity
→ open in the desktop investigation experience
```

---

# Migration into the new organization

When the organization exists:

1. Copy the accepted product and program documents into the private documentation source of truth.
2. Recreate the milestone and epic hierarchy in private repositories.
3. Preserve links back to this temporary planning PR for ancestry.
4. Mark this public planning location as historical if sensitive commercial detail should stop evolving here.
5. Continue implementation planning privately.
6. Keep only deliberately public CMTrace Open roadmap material in the public upstream.

---

# Controlling statement

> CMTrace Open remains the public local investigation engine. Project Theseus is the private commercial program that adds remote evidence, the long-lived agent, asset continuity, chain of custody, organization controls, and supported endpoint lifecycle operations.
