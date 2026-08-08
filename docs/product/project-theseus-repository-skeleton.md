# Project Theseus — Commercial Repository Skeleton

**Status:** Copy-ready bootstrap specification  
**Owner:** Adam Gell  
**Repository owner:** New GitHub organization, name not yet selected  
**Internal codename:** Project Theseus  
**Startup binary publisher:** Adam Gell

---

## 1. Purpose

This document defines the minimum organization and repository skeleton required to begin private commercial development without waiting for the final public product name.

Temporary names use `theseus`, but permanent application, protocol, installer, database, and customer identities must remain brand-neutral or be explicitly migration-safe.

---

# 2. Initial organization structure

Minimum viable structure:

```text
<organization>/theseus-desktop    private
<organization>/theseus-platform   private
```

Optional repositories to add only when separation is operationally useful:

```text
<organization>/theseus-release    private
<organization>/theseus-docs       private
<organization>/theseus-infra      private, only if infra ownership warrants separation
```

Do not create extra repositories merely to appear enterprise-ready. Start with desktop and platform; split release/docs/infra when ownership, permissions, release cadence, or customer access justifies it.

---

# 3. Organization bootstrap

## 3.1 Ownership and recovery

Required:

- at least two organization owners or a documented recovery path;
- phishing-resistant MFA for owners where available;
- recovery codes stored outside ordinary development systems;
- no shared user accounts;
- organization ownership not dependent on a single unmanaged email address;
- scoped teams rather than direct collaborator sprawl.

Initial teams:

```text
owners
maintainers
release-managers
security
read-only-advisors   optional
```

Adam may initially hold all operational roles, but the role model should exist before additional people are added.

## 3.2 Organization settings

Enable or configure:

- dependency graph;
- Dependabot alerts;
- Dependabot security updates where appropriate;
- secret scanning and push protection where available;
- private vulnerability reporting or a private security contact route;
- Actions policy restricted to approved actions and pinned revisions where practical;
- package and container visibility defaults set to private;
- member repository creation restricted to owners initially;
- default repository visibility set to private;
- base permissions set to none or read, not write;
- audit-log retention/export plan.

## 3.3 External integrations

Inventory before connection:

- signing provider and timestamp service;
- cloud subscription and service principal;
- container registry;
- package registry;
- domain/DNS provider;
- release-download storage/CDN;
- error tracking and telemetry;
- code-quality/review tools;
- customer support and ticket system later.

Each integration should have:

- owner;
- purpose;
- credential type;
- repository/environment access;
- rotation procedure;
- removal procedure.

---

# 4. Repository ancestry and migration

## 4.1 Desktop ancestry

Source:

```text
adamgell/cmtraceopen
```

Target:

```text
<organization>/theseus-desktop
```

Requirements:

- preserve full Git history;
- preserve tags;
- preserve current release ancestry;
- preserve MIT license and third-party notices;
- preserve commit authorship;
- configure `origin` as the private commercial repository;
- configure `upstream` as `adamgell/cmtraceopen` in developer setup documentation;
- record exact initial upstream commit and tag state.

## 4.2 Platform ancestry

Source:

```text
adamgell/cmtraceopen-web
```

Target:

```text
<organization>/theseus-platform
```

Requirements:

- preserve full Git history and tags;
- preserve existing license/attribution obligations;
- record the final public-source baseline;
- move active platform work to the private repository;
- redirect the desktop submodule/dependency to the private desktop repository;
- migrate GHCR/image references, deployment modules, Actions secrets, and release workflows to organization-owned resources.

The platform is not treated as an ongoing public upstream after migration.

---

# 5. Desktop repository skeleton

Suggested initial layout, retaining existing CMTrace Open structure where possible:

```text
theseus-desktop/
├── .github/
│   ├── CODEOWNERS
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug.yml
│   │   ├── feature.yml
│   │   ├── security-internal.yml
│   │   └── upstream-intake.yml
│   ├── PULL_REQUEST_TEMPLATE.md
│   └── workflows/
│       ├── ci.yml
│       ├── security.yml
│       ├── preview-release.yml
│       ├── release.yml
│       └── upstream-intake.yml
├── docs/
│   ├── architecture/
│   ├── adr/
│   ├── product/
│   ├── release/
│   ├── security/
│   ├── support/
│   └── upstream/
├── product/
│   ├── manifest.json
│   ├── capabilities.json
│   ├── branding/
│   └── release-channels.json
├── upstream/
│   ├── baseline.json
│   ├── intake-policy.md
│   └── integrations/
├── crates/
├── src/
├── src-tauri/
├── tests/
├── LICENSE
├── THIRD-PARTY-NOTICES.md
├── COMMERCIAL-LICENSE.md       when selected
├── SECURITY.md
├── SUPPORT.md
├── UPSTREAM.md
├── VERSIONING.md
└── README.md
```

Do not restructure the inherited application merely to match this diagram. Add the smallest durable seams first.

## 5.1 Required root files

### `UPSTREAM.md`

Must state:

- public upstream repository;
- initial baseline commit;
- integration policy;
- no automatic merge policy;
- how to classify and import upstream work;
- how commercial-only changes are protected from accidental upstream publication.

### `upstream/baseline.json`

Example:

```json
{
  "schemaVersion": 1,
  "upstreamRepository": "adamgell/cmtraceopen",
  "upstreamBranch": "main",
  "initialBaselineCommit": "<sha>",
  "lastReviewedCommit": "<sha>",
  "lastIntegratedCommit": "<sha>",
  "createdAt": "<utc>",
  "integrationMethod": "independent-history-preserving-downstream"
}
```

### `product/manifest.json`

Temporary example:

```json
{
  "schemaVersion": 1,
  "productId": "com.adamgell.endpoint-evidence.desktop",
  "internalProgram": "Project Theseus",
  "displayName": "Project Theseus Preview",
  "edition": "commercial-preview",
  "publisher": "Adam Gell",
  "publisherGeneration": 1,
  "updateChannel": "preview",
  "capabilities": {
    "localInvestigation": true,
    "serverMode": true,
    "assetHistory": false,
    "collectionJobs": false
  }
}
```

The eventual stable product ID must be selected before customer upgrade identity becomes difficult to change.

### `VERSIONING.md`

Define independent versions for:

- desktop application;
- server/platform;
- agent;
- evidence protocol;
- bundle manifest;
- API surface;
- database schema.

Do not assume all components must share one semantic version.

### `THIRD-PARTY-NOTICES.md`

Must include:

- inherited MIT notice for CMTrace Open portions;
- third-party Rust, JavaScript, Tauri, and platform dependencies according to their license requirements;
- generated inventory process;
- manual notices for assets or libraries not covered by automated dependency scanning.

---

# 6. Platform repository skeleton

Suggested layout, retaining current ancestry:

```text
theseus-platform/
├── .github/
│   ├── CODEOWNERS
│   ├── ISSUE_TEMPLATE/
│   ├── PULL_REQUEST_TEMPLATE.md
│   └── workflows/
│       ├── ci.yml
│       ├── security.yml
│       ├── publish-agent-preview.yml
│       ├── publish-platform-preview.yml
│       ├── terraform-validate.yml
│       └── release.yml
├── crates/
│   ├── agent/
│   ├── api-server/
│   ├── common-wire/
│   ├── evidence-manifest/       future
│   ├── identity-model/          future
│   └── job-protocol/            future
├── web/
│   └── console/                 migrate current web surface deliberately
├── infra/
│   ├── azure/
│   ├── observability/
│   └── environments/
├── deploy/
│   ├── intune/
│   ├── local/
│   └── pilot/
├── docs/
│   ├── architecture/
│   ├── adr/
│   ├── operations/
│   ├── pilot/
│   ├── provisioning/
│   ├── release/
│   ├── security/
│   └── support/
├── protocol/
│   ├── compatibility.json
│   ├── capabilities.md
│   └── schemas/
├── release/
│   ├── component-manifest.schema.json
│   ├── signing-history.json
│   └── channels/
├── tests/
│   ├── e2e/
│   ├── integration/
│   ├── load/
│   ├── identity/
│   └── upgrade/
├── HISTORICAL-SOURCE.md
├── LICENSES.md
├── SECURITY.md
├── SUPPORT.md
├── VERSIONING.md
└── README.md
```

Again, do not perform a large path rewrite before the first vertical slice. This is a target organization, not a prerequisite refactor.

## 6.1 `HISTORICAL-SOURCE.md`

Record:

- original public repository;
- final source baseline used for private continuation;
- license applicable to inherited files;
- date active private development began;
- statement that no ongoing public platform upstream is expected.

## 6.2 Compatibility manifest

Example:

```json
{
  "schemaVersion": 1,
  "protocolGeneration": 1,
  "desktop": {
    "minimum": "0.1.0",
    "maximum": "0.1.x"
  },
  "agent": {
    "minimum": "0.1.0",
    "maximum": "0.1.x"
  },
  "capabilities": [
    "devices.list",
    "sessions.list",
    "sessions.bundle.download"
  ]
}
```

## 6.3 Signing history

Example:

```json
{
  "schemaVersion": 1,
  "publishers": [
    {
      "generation": 1,
      "displayName": "Adam Gell",
      "status": "active",
      "effectiveFrom": "<utc>",
      "artifactTypes": ["desktop", "agent", "installer"]
    }
  ]
}
```

Do not store private certificate material or sensitive certificate-management details in this file.

---

# 7. Branch and pull-request model

## 7.1 Protected branches

Initial:

```text
main
```

Optional later:

```text
release/<major>.<minor>
```

Rules for `main`:

- no direct pushes except emergency owner override with audit;
- pull request required;
- required CI checks;
- conversation resolution required;
- signed commits optional, signed release artifacts mandatory;
- force push disabled;
- deletion disabled;
- stale approvals dismissed on material changes where practical.

## 7.2 Branch naming

Examples:

```text
feat/server-session-download
feat/desktop-server-profile
feat/asset-continuity-model
fix/agent-queue-recovery
security/token-redaction
upstream/cmtraceopen-2026-08-15
release/preview-0.1.0
```

## 7.3 Pull-request classes

Each PR should declare one class:

- product;
- architecture;
- feature;
- fix;
- security;
- upstream intake;
- infrastructure;
- release;
- documentation.

Upstream-intake PRs must include:

- upstream range reviewed;
- commits integrated;
- commits deferred/rejected;
- conflicts and resolutions;
- commercial regression results;
- protocol/release impact.

---

# 8. Issue hierarchy

Use a predictable hierarchy:

```text
Program milestone
  └── Cross-repository epic
        └── Repository epic
              └── Implementation issue
                    └── Pull request
```

Suggested labels:

```text
area:desktop
area:agent
area:server
area:web
area:identity
area:evidence
area:infra
area:release
area:security
area:commercial

kind:epic
kind:feature
kind:bug
kind:security
kind:adr
kind:research
kind:upstream-intake

priority:p0
priority:p1
priority:p2
priority:p3

status:blocked
status:needs-decision
status:ready
status:pilot
```

Do not use labels to duplicate data already represented by issue state or milestone unless the label materially improves triage.

---

# 9. Actions environments and secrets

## 9.1 Environments

Initial environments:

### `preview`

- internal preview artifacts;
- founder signing permitted;
- nonproduction cloud deployment;
- automatic deployment may be allowed from protected branches after tests.

### `release`

- customer-distributed artifacts;
- manual approval required;
- restricted reviewers;
- signing and timestamp credentials;
- production package/container publication;
- immutable release record.

### `pilot-<customer>`

Create only when a design partner exists. Keep customer secrets and deployment approvals isolated.

## 9.2 Secret categories

- code-signing access;
- timestamp service;
- Apple notarization;
- package/container publication;
- cloud deployment credentials;
- Entra application credentials where required;
- test environment tokens;
- telemetry/error-reporting keys;
- release-download storage.

Rules:

1. No secret in source, issue bodies, PR bodies, build logs, or release notes.
2. Prefer short-lived or federated credentials.
3. Restrict environment secrets to required workflows.
4. Require manual approval for customer release signing.
5. Document rotation and revocation.
6. Test release workflows without exposing secrets to untrusted pull requests.

---

# 10. CI skeleton

## Desktop required checks

- Rust workspace check;
- Rust tests;
- clippy with warnings denied;
- TypeScript build/typecheck;
- frontend tests;
- Tauri compile on supported OS matrix;
- Lite/community-seam regression where relevant;
- license inventory;
- secret scan;
- dependency/security scan;
- installer identity tests;
- preview artifact smoke test.

## Platform required checks

- Rust workspace check/test/clippy;
- web build/test;
- common-wire/schema compatibility tests;
- database migration tests;
- local FS and Azure storage integration tests where feasible;
- agent Windows compile/service tests;
- container build;
- Terraform validate/plan policy;
- security and dependency scans;
- e2e ingest/query/download tests;
- release-manifest generation validation.

## Cross-repository compatibility

At minimum, maintain a scheduled or release-gated matrix testing:

- current desktop vs current platform;
- current desktop vs previous supported platform;
- current platform vs previous supported agent;
- manifest/protocol schema compatibility;
- upgrade from prior supported preview.

---

# 11. Release skeleton

## 11.1 Component release manifest

Every commercial release should produce one signed or integrity-protected manifest:

```json
{
  "schemaVersion": 1,
  "releaseChannel": "preview",
  "releaseVersion": "0.1.0",
  "releasedAt": "<utc>",
  "publisher": {
    "name": "Adam Gell",
    "generation": 1
  },
  "components": {
    "desktop": "0.1.0",
    "agent": "0.1.0",
    "server": "0.1.0",
    "webConsole": "0.1.0"
  },
  "protocol": 1,
  "bundleManifest": 1,
  "databaseSchema": 1,
  "sourceCommits": {
    "desktop": "<sha>",
    "platform": "<sha>"
  }
}
```

## 11.2 Channels

Initial:

```text
internal
preview
```

Later:

```text
stable
lts
```

Do not create `stable` before there is a supported customer release and lifecycle policy.

## 11.3 Artifact naming

Use brand-neutral or temporary names until the public name is selected, but keep naming consistent and machine parseable.

Example internal preview:

```text
ProjectTheseus-Desktop_0.1.0_windows_x64.msi
ProjectTheseus-Agent_0.1.0_windows_x64.msi
theseus-server_0.1.0_linux_amd64.oci
release-manifest_0.1.0.json
```

Before external production, replace internal codename names where public exposure would be undesirable.

---

# 12. Security documentation skeleton

Each private repository should contain or link to:

- threat model;
- data-flow diagram;
- authentication and authorization model;
- secret inventory;
- logging/redaction policy;
- evidence-data classification;
- vulnerability intake and response;
- release signing and provenance;
- dependency policy;
- supported-version policy;
- incident-response contacts;
- customer security architecture later.

Security-sensitive architecture may remain private. Customer-facing summaries can be generated from the private source of truth.

---

# 13. Documentation skeleton

## Architecture

- product overview;
- desktop/platform/agent component map;
- protocols and capabilities;
- asset continuity;
- evidence chain;
- job system;
- storage and retention;
- authentication/RBAC;
- release compatibility.

## Operations

- installation;
- health monitoring;
- backup/restore;
- upgrade/rollback;
- certificate rotation;
- agent troubleshooting;
- queue recovery;
- storage capacity;
- incident playbooks;
- retirement/removal.

## Product

- target customer;
- user journeys;
- packaging;
- roadmap;
- metrics;
- design-partner process;
- naming/brand decisions.

## Support

- support bundle contents;
- safe logs;
- escalation procedure;
- known issue template;
- compatibility collection;
- customer ticket correlation.

---

# 14. Copy-ready repository initialization checklist

## Organization

- [ ] Select organization name.
- [ ] Create organization.
- [ ] Configure owner recovery and MFA.
- [ ] Set default repository visibility to private.
- [ ] Configure base permissions.
- [ ] Create initial teams.
- [ ] Enable security features.
- [ ] Restrict Actions policy.

## Desktop

- [ ] Create private repository.
- [ ] Mirror CMTrace Open history and tags.
- [ ] Add `upstream` instructions.
- [ ] Record baseline commit.
- [ ] Add `UPSTREAM.md` and baseline JSON.
- [ ] Preserve license and notices.
- [ ] Configure branch protection.
- [ ] Configure CI.
- [ ] Create preview/release environments.
- [ ] Add product manifest.
- [ ] Establish independent app/install/update identity.

## Platform

- [ ] Create private repository.
- [ ] Mirror `cmtraceopen-web` history and tags.
- [ ] Record historical-source baseline.
- [ ] Preserve license and notices.
- [ ] Redirect private desktop dependency.
- [ ] Migrate package/container naming.
- [ ] Migrate Actions and environments.
- [ ] Migrate cloud/deployment references.
- [ ] Configure branch protection and CI.
- [ ] Establish component compatibility manifest.

## Release

- [ ] Define publisher generation 1: Adam Gell.
- [ ] Configure protected signing.
- [ ] Configure timestamping.
- [ ] Define internal and preview channels.
- [ ] Generate component release manifest.
- [ ] Verify artifact signatures after download.
- [ ] Test side-by-side behavior with CMTrace Open.

## Governance

- [ ] Add CODEOWNERS.
- [ ] Add PR template.
- [ ] Add issue templates and labels.
- [ ] Add ADR process.
- [ ] Add security contact.
- [ ] Add third-party license generation.
- [ ] Add upstream-intake template.

---

# 15. Repository skeleton exit criteria

The skeleton is considered ready when:

1. A fresh clone from the organization builds without access to a personal local checkout.
2. The desktop and platform have exact recorded ancestry.
3. Required license notices are present.
4. Protected CI runs on pull requests.
5. Signing secrets are restricted to protected environments.
6. Internal preview artifacts can be generated and verified.
7. The private platform references the private desktop where intended.
8. A developer can identify how an upstream CMTrace Open improvement enters the commercial desktop.
9. A developer cannot accidentally publish commercial artifacts into CMTrace Open release channels.
10. The repository names can later change without changing logical product, protocol, or customer identity.
