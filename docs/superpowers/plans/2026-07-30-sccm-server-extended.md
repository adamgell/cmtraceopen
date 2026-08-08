# SCCM Server Extended Roles Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** Deliver issues #331, #332, and #334 as evidence-first SCCM Server extensions for hierarchy/replication, Provider/Admin Service, and a rigorously gated catalog of advanced server-role sources.

**Architecture:** Reuse the common SCCM schema (#318) and server intake/topology contract (#335). Hierarchy/replication and Provider/Admin Service each get a narrow role-local source catalog, transaction key model, state reducer, test corpus, and conservative findings. #334 is deliberately a source-contract and fixture-discovery program; it does not turn every known SCCM log into an unsupported optimistic parser.

**Tech Stack:** Rust 1.88, cmtraceopen-parser, cmtrace-open native capture adapter, serde/serde_json, raw CCM/IIS parser families, synthetic corpus, Windows SCCM Server development environment for role/configured-path validation.

## Global Constraints

- #318 and #335 are hard prerequisites. #327's site-core vocabulary may be cited where useful but neither #331 nor #332 may use it as an unproven causal shortcut.
- This plan covers #331, #332, and #334 only. It does not implement client workflows, MP/DP/SUP core workflows, cross-side correlation, UI, SQL/database analytics, or any direct service/API interaction in the parser crate.
- The pure parser must stay platform-neutral and wasm-compatible. Windows discovery/registry/service/IIS configuration belongs in native capture only.
- No new ParserKind is introduced. CCM remains a raw grammar; semantic source classification happens from server manifest role/provenance plus catalogued basename.
- A site link, provider endpoint, Admin Service endpoint, cloud role, PXE role, reporting role, or certificate role is never inferred solely from a default directory or a filename. It must be observed/configured or left as a coverage/candidate state.
- Do not collapse recipient/remote-site, host, role, path, source version, message ID, request ID, caller identity, HTTP URL, certificate reference, or token-like fields into public output. Preserve only redacted/opaque correlation handles when #318 explicitly permits them.
- Exact profile-validated keys and topology are required for high-confidence linking. A same-minute replication error, provider error, or HTTP error cannot be blamed for a different client/server workflow by timing alone.
- Advanced-role source discovery must be source-card driven. No semantic reducer can merge until a curated source card, sanitized fixtures, terminal-state grammar, version scope, and explicit issue dependency have been reviewed.
- Native development-server results are validation evidence. They must not be committed wholesale or converted directly into fixture logs.
- Every expected source absent/access-denied/capped/skipped/unsupported/parse-failed state is explicit. No absence proves health, a disabled role, or a root cause.

---

## Scope, Dependencies, and Delivery Order

| Issue | Outcome | Dependencies | Review boundary | Follow-on |
| --- | --- | --- | --- | --- |
| #331 | Site-to-site/hierarchy/replication transactions | #318 + #335; optional #327 context | site-link key/topology/ordering and no false remote cause | later controlled correlation only when a pair is designed |
| #332 | Provider and Admin Service request transactions | #318 + #335 | caller/privacy, provider vs API layers, source coverage | future console/API workspace support |
| #334 | Advanced role source-card catalog and fixture gate | #318 + #335 | documented source evidence before code | one narrowly scoped implementation issue per validated source family |

#331 and #332 can be developed in parallel after #335's server manifest contract is frozen. #334 runs continuously alongside them but must not turn an observation into a production analyzer. A source card accepted under #334 creates a follow-up implementation issue with its own files, fixture matrix, and terminal criteria; #334 itself remains a catalog/triage issue.

## File Structure and Ownership

~~~text
crates/cmtraceopen-parser/
├── src/sccm/server/windows/
│   ├── hierarchy_and_replication.rs      # #331
│   ├── provider_and_admin_service.rs     # #332
│   ├── advanced_roles.rs                 # #334 source-card catalog only
│   ├── catalog.rs                        # #335 shared role/source declarations
│   └── mod.rs
├── tests/
│   ├── sccm_server_hierarchy_and_replication.rs
│   ├── sccm_server_provider_and_admin_service.rs
│   ├── sccm_server_advanced_roles_catalog.rs
│   └── fixtures/sccm/server/
│       ├── hierarchy_and_replication/<scenario>/
│       ├── provider_and_admin_service/<scenario>/
│       └── advanced_roles/
│           ├── source-cards/
│           └── catalog-fixtures/
src-tauri/
├── src/sccm/collector/discovery.rs       # role/config candidate observation only
├── src/sccm/collector/engine.rs          # capture only admitted advanced sources
├── src/sccm/collector/manifest.rs        # source-card/capture provenance
└── tests/sccm_server_collection.rs
docs/
└── sccm/
    ├── source-catalog/advanced-roles.md
    └── validation/server-extended-lab-checklist.md
~~~

The parser source-card data may be a typed Rust table or a versioned fixture data file, but it must have a single owner. Do not make an unreviewed native discovery list silently diverge from parser catalog metadata. Do not expose raw source-card research/URLs in customer-facing analysis output.

## Common Review Contract

All #331/#332 transactions/facts must be keyed and cited. Each accepted finding must state:

1. role/topology scope;
2. named workflow phase and last evidenced good phase;
3. evidence refs and profile/source version;
4. capture/coverage limits;
5. exact/strong versus candidate key basis;
6. class and confidence;
7. smallest next artifact request when evidence is insufficient.

Before a new advanced source is promoted past #334, reviewers must be able to answer:

| Question | Required proof |
| --- | --- |
| What exact role/source is this? | Source card with observed/configured role provenance and declared basename/path-class candidates |
| Which raw grammar frames it? | CCM/IIS/plain/etc. parser family plus logical-record rule |
| What version scope is known? | Sanitized manifest/source version plus fixture profile IDs |
| What does healthy look like? | One minimal success fixture with cited terminal/steady-state evidence |
| What is a terminal failure? | One minimal failure fixture with source-specific terminal evidence, not a generic error token |
| How are transactions keyed? | Versioned stable key extraction rule plus collision/adversarial fixture |
| What coverage is required? | Explicit mandatory/optional source group and absent/access/cap/skip behavior |
| What data must redact? | Source-card privacy fields and exported projection test |
| What issue owns code? | A new linked issue after the source card passes review |

## Task 1: Define #331 hierarchy and replication source/key contracts

**Files:**

- Create: crates/cmtraceopen-parser/src/sccm/server/windows/hierarchy_and_replication.rs
- Modify: crates/cmtraceopen-parser/src/sccm/server/windows/mod.rs
- Modify: crates/cmtraceopen-parser/src/sccm/server/windows/catalog.rs
- Create: crates/cmtraceopen-parser/tests/sccm_server_hierarchy_and_replication.rs
- Create: fixtures hierarchy-and-replication/healthy-link, sender-failure, receiver-processing-failure, backlog-retry, topology-mismatch, clock-offset-unknown, rotation-boundary, absent-remote-source, and incomplete
- Modify native discovery/manifest only after pure source contract proves required data cannot be supplied by #335

**Consumes:** #318 shared evidence/key/time/finding/redaction contracts; #335 role/topology/server manifest intake; catalogued evidence such as replmgr.log, rcmctrl.log, sender.log, despool.log, and only other observed role sources.

**Produces:** A table-driven hierarchy/replication source catalog and safe link/transaction candidate grouping. It does not yet emit final diagnosis state transitions.

### Topology/key rule

The transaction identifier must contain a profile-validated site-link/message/replication key plus compatible origin/target site/role topology. A remote host or site code alone is not enough. The source catalog records whether evidence is origin-side, target-side, or topology-only. Cross-site timestamp comparison requires valid offset provenance; unknown/invalid offsets prevent high-confidence ordering across hosts.

- [ ] **Step 1: Write source/topology grouping tests first**

Require tests that:

  - a healthy link uses exact same link/message key plus compatible source/target topology;
  - two same-minute sender failures for different remote sites remain separate;
  - a record with an unknown/missing offset cannot establish sender-before-receiver causality;
  - a site-code-looking string in a generic message cannot create a hierarchy link;
  - an absent remote-side artifact is a coverage gap with a bounded remote source request, not a remote-site failure;
  - rotated fragments retain direction/path/role provenance and partial fragments cannot create a message/link key;
  - reordering artifacts gives byte-identical candidate output.

- [ ] **Step 2: Run the narrow test red**

~~~bash
cargo test --locked -p cmtraceopen-parser --test sccm_server_hierarchy_and_replication source_and_topology
~~~

Expected: FAIL because no hierarchy module/catalog/API exists.

- [ ] **Step 3: Implement source admission and candidate grouping**

Create source-specific fact extraction for only declared replication/log families. Preserve direction, safe site handles, message/link identifiers, phase candidate, terminality candidate, timestamp provenance, and evidence reference. Use the #318 versioned key registry; raw values with unvalidated profile/version become low-confidence candidates plus key-extraction gaps. Do not read site configuration/native state in this crate.

- [ ] **Step 4: Make contract tests green**

~~~bash
cargo fmt --check --all
cargo test --locked -p cmtraceopen-parser --test sccm_server_hierarchy_and_replication source_and_topology
cargo test --locked -p cmtraceopen-parser --test sccm_server_intake
cargo test --locked -p cmtraceopen-parser --test sccm_spine_contract
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
git diff --check
~~~

- [ ] **Step 5: Commit #331 source/key boundary separately**

~~~bash
git add crates/cmtraceopen-parser/src/sccm/server crates/cmtraceopen-parser/tests/sccm_server_hierarchy_and_replication.rs crates/cmtraceopen-parser/tests/fixtures/sccm/server/hierarchy_and_replication
git commit -m "feat(sccm): model hierarchy replication evidence"
~~~

## Task 2: Implement #331 hierarchy and replication state reducers

**Files:**

- Modify: crates/cmtraceopen-parser/src/sccm/server/windows/hierarchy_and_replication.rs
- Modify: crates/cmtraceopen-parser/tests/sccm_server_hierarchy_and_replication.rs
- Modify: #331 fixture expected files

**Consumes:** Source/key facts from Task 1.

**Produces:** Per-link/message replication analyses with conservative sender, receiver, retry/backlog, and coverage findings.

### State contract

~~~text
Initiate -> QueueOrSerialize -> Send -> Receive -> Process -> Acknowledge -> HealthyOrTerminal
~~~

This sequence models role-local evidence; it does not promise every topology emits every phase. A retry/backlog remains blocked/deferred or symptom unless source-specific terminal evidence proves failure. A later acknowledgement demonstrates recovery only under compatible exact link/message keys and ordering provenance.

- [ ] **Step 1: Add failing phase/terminal fixture tests**

Include:

  - healthy end-to-end link with cited acknowledgment;
  - terminal send failure;
  - receiver/processing failure after an evidenced send;
  - retry/backlog with no terminal record;
  - mismatched topology/key that stays unlinked;
  - conflicting clocks / invalid offset downgraded from causal diagnosis;
  - missing remote evidence requesting only the relevant role/source;
  - a later success for the same key showing recovery;
  - logical record/rotation boundary that never becomes a terminal transaction.

- [ ] **Step 2: Run full #331 target red**

~~~bash
cargo test --locked -p cmtraceopen-parser --test sccm_server_hierarchy_and_replication
~~~

- [ ] **Step 3: Implement per-link reducer and finding rules**

Use stable maps/sorts by exact normalized link/message/topology key. Advance phases only on profile-recognized facts. Retain contradictory evidence. A high-confidence confirmed failure needs terminal origin/target evidence or independent corroboration with compatible topology—not mere absence of an acknowledgement. For insufficient evidence, request a bounded counterpart source such as the remote sender/receiver artifact, never broad site/server capture.

- [ ] **Step 4: Run complete parser gates and commit**

~~~bash
cargo fmt --check --all
cargo test --locked -p cmtraceopen-parser --test sccm_server_hierarchy_and_replication
cargo test --locked -p cmtraceopen-parser
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
git diff --check

git add crates/cmtraceopen-parser/src/sccm/server/windows/hierarchy_and_replication.rs crates/cmtraceopen-parser/tests/sccm_server_hierarchy_and_replication.rs crates/cmtraceopen-parser/tests/fixtures/sccm/server/hierarchy_and_replication
git commit -m "feat(sccm): analyze hierarchy replication transactions"
~~~

Update #331 with supported source/profile list and explicit limits around remote environment coverage.

## Task 3: Define #332 Provider and Admin Service source/privacy/key contracts

**Files:**

- Create: crates/cmtraceopen-parser/src/sccm/server/windows/provider_and_admin_service.rs
- Modify: crates/cmtraceopen-parser/src/sccm/server/windows/mod.rs
- Modify: crates/cmtraceopen-parser/src/sccm/server/windows/catalog.rs
- Create: crates/cmtraceopen-parser/tests/sccm_server_provider_and_admin_service.rs
- Create: fixtures provider-and-admin-service/provider-success, provider-authz-denied, provider-query-failure, provider-timeout, admin-service-success, admin-service-auth-failure, admin-service-backend-failure, iis-supplemental, privacy-redaction, rotation-boundary, incomplete

**Consumes:** #318 redaction/signal/key/finding contracts; #335 server role/topology source metadata; curated provider/Admin Service sources such as smsprov.log, AdminService.log, and explicitly catalogued IIS supplement only when observed.

**Produces:** A privacy-safe source catalog and request candidate grouping that distinguishes Provider from Admin Service layers before final workflow findings.

### Request key and privacy rule

A request transaction needs a profile-validated request/correlation ID, operation/query handle, and compatible role/endpoint context. Caller identity, query text, URL parameters, authorization header/token, tenant/domain host, and certificate details are never public key values. If correlation requires an identity-like field, use the #318 deterministic redacted handle and test that raw form is absent from exports.

- [ ] **Step 1: Write failing source/privacy tests**

Assert:

  - Provider and Admin Service source records produce different role/workflow candidates;
  - a request cannot be keyed only by endpoint path or same-minute timestamp;
  - authz/authorization evidence redacts raw caller/token-like content;
  - unrecognized IIS source remains supplemental/unsupported, not an Admin Service transaction;
  - missing provider source and missing Admin Service source request the exact distinct artifact group;
  - same request-like identifier from incompatible topology/role cannot merge;
  - rotation fragment/unknown version cannot emit an exact request key.

- [ ] **Step 2: Run red**

~~~bash
cargo test --locked -p cmtraceopen-parser --test sccm_server_provider_and_admin_service source_privacy_and_keys
~~~

- [ ] **Step 3: Implement layered source/fact extraction**

Keep separate private fact kinds for Provider service, Admin Service, and supplementary IIS. Each contains sanitized request key candidate, operation category, phase candidate, terminality, signals, evidence ref, and redaction class. Use source/version profile admission before emitting exact keys. Do not log/query SQL/provider/database/API data or make network calls.

- [ ] **Step 4: Run contract gates and commit**

~~~bash
cargo fmt --check --all
cargo test --locked -p cmtraceopen-parser --test sccm_server_provider_and_admin_service source_privacy_and_keys
cargo test --locked -p cmtraceopen-parser --test sccm_spine_contract
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
git diff --check

git add crates/cmtraceopen-parser/src/sccm/server crates/cmtraceopen-parser/tests/sccm_server_provider_and_admin_service.rs crates/cmtraceopen-parser/tests/fixtures/sccm/server/provider_and_admin_service
git commit -m "feat(sccm): model provider and admin service evidence"
~~~

## Task 4: Implement #332 Provider/Admin Service state reducers

**Files:**

- Modify: crates/cmtraceopen-parser/src/sccm/server/windows/provider_and_admin_service.rs
- Modify: crates/cmtraceopen-parser/tests/sccm_server_provider_and_admin_service.rs
- Modify: #332 fixture expected files

**Consumes:** Task 3 fact candidates and shared finding builder.

**Produces:** Layer-specific request transaction findings with strict privacy projection.

### State contracts

~~~text
Provider:     Receive -> AuthenticateOrAuthorize -> ExecuteProviderOperation -> Respond -> RecordOutcome
AdminService: Receive -> AuthenticateOrAuthorize -> Route -> ExecuteBackendOperation -> Respond -> RecordOutcome
~~~

A 4xx/5xx-like signal cannot alone determine which state happened. A terminal failure needs source-specific completion/error evidence. A missing IIS supplement cannot make a provider/Admin Service result fail; it may lower confidence or request the narrow supplemental source only where the rule truly requires it.

- [ ] **Step 1: Add failing operational fixtures**

Require Provider success, explicit authorization deny, provider query/operation failure, timeout/incomplete result, Admin Service success, auth failure, backend failure, optional IIS correlation, privacy redaction, mismatched request keys, and incomplete source coverage. Assert phase, last success, class, confidence, evidence refs, redacted output, and minimal next request.

- [ ] **Step 2: Run full #332 test target red**

~~~bash
cargo test --locked -p cmtraceopen-parser --test sccm_server_provider_and_admin_service
~~~

- [ ] **Step 3: Implement separate request reducers**

Group facts only by safe exact normalized keys. Enforce layer/role topology. Use monotonic phase progression and source-specific terminal facts. Keep client/console impact outside the conclusion: output says what the Provider/Admin Service evidence proves, not “the console/user failed because of this” unless future paired evidence supports it.

- [ ] **Step 4: Add privacy/determinism regressions, verify, and commit**

Test byte-identical public output on reordered artifacts, raw sensitive field absence, raw snapshot immutability after redacted projection, invalid offsets lowering cross-artifact confidence, and generic unknown error retention.

~~~bash
cargo fmt --check --all
cargo test --locked -p cmtraceopen-parser --test sccm_server_provider_and_admin_service
cargo test --locked -p cmtraceopen-parser --test sccm_server_intake
cargo test --locked -p cmtraceopen-parser
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
git diff --check

git add crates/cmtraceopen-parser/src/sccm/server/windows/provider_and_admin_service.rs crates/cmtraceopen-parser/tests/sccm_server_provider_and_admin_service.rs crates/cmtraceopen-parser/tests/fixtures/sccm/server/provider_and_admin_service
git commit -m "feat(sccm): analyze provider and admin service transactions"
~~~

## Task 5: Build #334 advanced-role source-card catalog

**Files:**

- Create: crates/cmtraceopen-parser/src/sccm/server/windows/advanced_roles.rs
- Modify: crates/cmtraceopen-parser/src/sccm/server/windows/mod.rs
- Create: crates/cmtraceopen-parser/tests/sccm_server_advanced_roles_catalog.rs
- Create: crates/cmtraceopen-parser/tests/fixtures/sccm/server/advanced_roles/source-cards/*.json
- Create: crates/cmtraceopen-parser/tests/fixtures/sccm/server/advanced_roles/catalog-fixtures/{valid,missing-required-field,unvalidated-source,redaction-required}/{source-card.json,expected.json}
- Create: docs/sccm/source-catalog/advanced-roles.md
- Modify native discovery only to preserve a candidate source card ID/capture state; no semantic rule belongs there

**Consumes:** #318 schema/version/redaction types and #335 observed role/capture manifest contract.

**Produces:** Versioned, reviewable source cards that prevent unvalidated role logs from entering production analyzers.

### Initial candidate families

The catalog starts with families such as:

| Source-card family | Candidate examples | Status at #334 start |
| --- | --- | --- |
| OS deployment/PXE | smspxe.log, PXE/OSD role logs observed in the lab | candidate only; no reducer |
| Client notification/BGB | server-side BGB/notification logs observed in the lab | candidate only; distinguish from client notification |
| Cloud/service connection | CloudMgr, service connector, CMG-related logs observed/configured | candidate only; privacy review required |
| Reporting | catalogued reporting service logs observed/configured | candidate only |
| Certificate enrollment/PKI | explicitly observed SCCM enrollment/certificate role logs | candidate only; high privacy sensitivity |
| SQL/database/export | explicit server-side supplementary diagnostics | unsupported by parser in this phase unless a dedicated source contract is approved |

A source card must not state that a candidate exists merely because the file name is familiar. The source needs observed/configured role provenance in a sanitized lab or authoritative source mapping before promotion.

- [ ] **Step 1: Write failing source-card schema tests**

Create a typed card model/JSON fixture that fails unless it includes: card ID/version, role/family, candidate basenames/path classes, raw parser family, source version scope, mandatory/optional capture classification, rotation policy, privacy/redaction classes, expected healthy evidence description, terminal failure evidence description, correlation/key policy, fixture IDs, owner issue, and promotion status.

Test malformed/missing fields, unknown parser family, candidate-only source trying to declare a production reducer, raw sensitive field projection, deterministic sorted catalog, and deprecation/supersession semantics.

- [ ] **Step 2: Run source-card test red**

~~~bash
cargo test --locked -p cmtraceopen-parser --test sccm_server_advanced_roles_catalog
~~~

- [ ] **Step 3: Implement typed source cards and admission states**

Use explicit states such as Candidate, Observed, FixtureValidated, RuleValidated, and Deferred. Only RuleValidated may be exported to a production semantic catalog, and a corresponding linked implementation issue must exist. Candidate/Observed cards can appear in diagnostics as capture capability requests but cannot create a transaction or failure. Preserve unknown cards as data; do not panic or silently accept them.

- [ ] **Step 4: Add initial cards and documentation**

Write source cards only for families with the required evidence available. For each card, document what has been observed versus still unknown, source permission/capture limits, redaction needs, and exact next evidence to promote it. Do not create filler cards with generic phrases such as “parse log and identify errors.”

- [ ] **Step 5: Verify and commit #334 catalog gate**

~~~bash
cargo fmt --check --all
cargo test --locked -p cmtraceopen-parser --test sccm_server_advanced_roles_catalog
cargo test --locked -p cmtraceopen-parser --test sccm_server_intake
cargo test --locked -p cmtraceopen-parser
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
git diff --check

git add crates/cmtraceopen-parser/src/sccm/server crates/cmtraceopen-parser/tests/sccm_server_advanced_roles_catalog.rs crates/cmtraceopen-parser/tests/fixtures/sccm/server/advanced_roles docs/sccm/source-catalog/advanced-roles.md
git commit -m "feat(sccm): catalog advanced server role sources"
~~~

## Task 6: Validate #331–#334 against the development SCCM Server and issue review gates

**Files:**

- Create: docs/sccm/validation/server-extended-lab-checklist.md
- Modify: issues #331, #332, #334 with exact fixture/test/validation evidence
- Add a follow-up GitHub issue for each source card promoted past Candidate/Observed

**Consumes:** Complete pure tests, native SCCM server collector, and authorized lab access.

**Produces:** Accurate evidence classification: pure contract proven, native test-double proven, Windows lab observed, or explicitly pending.

- [ ] **Step 1: Run focused and aggregate parser checks**

~~~bash
cargo test --locked -p cmtraceopen-parser --test sccm_server_hierarchy_and_replication
cargo test --locked -p cmtraceopen-parser --test sccm_server_provider_and_admin_service
cargo test --locked -p cmtraceopen-parser --test sccm_server_advanced_roles_catalog
cargo test --locked -p cmtraceopen-parser
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo fmt --check --all
git diff --check
~~~

- [ ] **Step 2: Run native collection regressions**

~~~bash
cargo test --locked -p cmtrace-open --test sccm_server_collection --features sccm-diagnostics
cargo test --locked -p cmtrace-open --test sccm_client_intake --features sccm-diagnostics
cargo test --locked -p cmtrace-open --test esp_diagnostics_sources --all-features
cargo test --locked -p cmtrace-open --test parser_expanded_corpus --all-features
cargo clippy --locked -p cmtrace-open --all-targets --all-features -- -D warnings
~~~

- [ ] **Step 3: Use the lab in discovery-first mode**

Confirm dev-only host, version, observed role topology, selected source-card candidate, configuration path, safe synthetic scenario, redaction, capture caps, and data retention. First record discovery/capability results. Capture only a bounded approved source group. An unobserved or access-denied source becomes source-card evidence/capture state; it does not justify a broad privilege increase or parser guess.

- [ ] **Step 4: Promote source cards only with precise artifacts**

A Candidate becomes Observed only with sanitized role/path/version provenance. It becomes FixtureValidated only with minimum success/failure/coverage fixtures. It becomes RuleValidated only after exact key/phase/terminal tests pass and an implementation issue/PR is linked. Keep rejected/unsupported source cards with a reason, instead of deleting their evidence.

- [ ] **Step 5: Write individual issue evidence**

#331 must list source/link profile versions and remote-side coverage limitations. #332 must list redaction tests and layers supported. #334 must list each card's state and linked follow-up issue, not claim broad role support. Do not close any issue because a lab exists; close only when its enumerated fixtures/tests/acceptance evidence are present.

## Exit Criteria

### #331 Hierarchy/replication

- [ ] Link/message/topology keys prevent cross-site and same-minute false joins.
- [ ] Healthy, terminal, retry/backlog, recovery, incompatible topology, unknown offset, rotation, and absent counterpart fixtures pass.
- [ ] High-confidence root-cause wording requires compatible terminal/corroborating role evidence.

### #332 Provider/Admin Service

- [ ] Provider and Admin Service source layers stay separate and key/privacy gated.
- [ ] Public/redacted exports contain no caller/query/token/URL/certificate-like raw fields.
- [ ] Successful/auth/authorization/backend/timeout/incomplete cases have exact contracts.

### #334 Advanced roles

- [ ] Source-card schema and promotion state rules are typed, tested, deterministic, and privacy aware.
- [ ] Only RuleValidated sources can enter a semantic analyzer, each with a linked implementation issue.
- [ ] Candidate/Observed sources remain useful capture guidance without claiming support or diagnosis.
