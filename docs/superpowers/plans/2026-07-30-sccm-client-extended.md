# SCCM Client Extended Workflow Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver issues #324, #325, and #326 as independent, evidence-first SCCM Client analyzers for Task Sequences, inventory/compliance/metering, and co-management/scripts/notification/Software Center.

**Architecture:** Build on the shared SCCM spine (#318) and deterministic Client intake contract (#319), but keep each extended workflow in a separate reducer with a precise source catalog, transaction key, state machine, fixture corpus, and failure boundary. These workflows may share evidence/coverage/key/finding types only; they must not use app deployment or policy reducer state as an undocumented substitute for their own evidence.

**Tech Stack:** Rust 1.88, `cmtraceopen-parser`, `cmtrace-open` native SCCM bundle adapter, serde/serde_json, existing CCM logical-record parser, synthetic fixture corpus, Windows SCCM Client development host for source-path and live-log validation.

## Global Constraints

- #318 and #319 are required before implementation. #320–#323 can inform a UI/workspace later but are not required to make these analyzers correct.
- This plan implements #324, #325, and #326 only. It does not add server role capture, management-point/DP/SUP rules, client-to-server correlation, or an SCCM workspace UI.
- No `ParserKind::Sccm`, no per-log raw parser, no direct filesystem or Windows API use in `cmtraceopen-parser`. Every semantic record comes through #318's complete logical-record evidence path.
- A source's default path is a discovery candidate, never proof that a source must exist on every client, boot phase, client version, or co-management configuration.
- A missing/relocated Task Sequence log, absent inventory source, unavailable notification channel, or client-side workload ownership handoff is explicit coverage/capability state—not a failure by default.
- Each analyzer uses stable evidence references, exact validated keys, and source/version provenance. Same filename, approximate time, component name, or a generic error code alone never merges unrelated transactions.
- Preserve task execution context, client identity, user identity, command lines, token-like data, and internal host/path values behind #318's redaction boundary. Fixtures must have synthetic paths and opaque test identifiers.
- `SMSTSLogPath` and actual captured artifact provenance are authoritative for Task Sequence source location; do not guess a stage from a single default `smsts.log` path.
- Co-management workload ownership is a first-class terminal classification. If a workload is Intune-owned, SCCM is allowed to explain its own observed handoff but must not diagnose an Intune failure.
- Do not claim an SCCM client notification, Software Center, inventory, or Task Sequence cause until a terminal/corroborating record exists. A red record alone may create a symptom.
- Native Windows acceptance validates discovery/capture layout and permissions. Pure fixture tests must cover all diagnostic semantics even when no lab is available.

---

## Issue Sequencing and Review Boundaries

| Issue | Narrow outcome | Required prior contract | Review focus | Future dependency |
| --- | --- | --- | --- | --- |
| #324 | One Task Sequence execution reconstructed across capture locations/rotations | #318/#319 | execution identity, relocation, phase/terminal semantics | later OSD/server correlation only after a specific server pair is designed |
| #325 | Separate inventory, compliance, and metering transactions | #318/#319 | no conflation of collection/evaluation/reporting | future device health workspace views |
| #326 | Ownership-aware client management diagnostics | #318/#319 | workload handoff, optional source capability, no cross-platform overreach | future Intune and SCCM client workspaces |

Do not combine all three issues into one implementation PR. #324 is higher-risk because it crosses boot environments and log relocation; it should be its own PR series. #325 may split its three reducers into reviewable commits beneath the issue if the shared source contract remains stable. #326 must begin with a source/capability catalog gate before it begins semantic finding rules.

## File Structure and Ownership

```text
crates/cmtraceopen-parser/
├── src/sccm/client/
│   ├── mod.rs                     # public re-exports + analyze_client_bundle composition
│   ├── task_sequence.rs           # #324 TS source/instance state machine
│   ├── inventory.rs               # #325 inventory, compliance, metering reducers
│   └── management.rs              # #326 co-management/scripts/notification/Software Center reducers
├── src/sccm/catalog.rs            # shared source names + capability metadata; no I/O
├── tests/
│   ├── sccm_client_task_sequence.rs
│   ├── sccm_client_inventory.rs
│   ├── sccm_client_management.rs
│   └── fixtures/sccm/client/
│       ├── task_sequence/<scenario>/{manifest.json,evidence/,expected.json}
│       ├── inventory/<scenario>/{manifest.json,evidence/,expected.json}
│       └── management/<scenario>/{manifest.json,evidence/,expected.json}

src-tauri/
├── src/sccm/intake.rs             # extend only with catalogued discovery/capture candidates
├── src/sccm/manifest.rs           # preserve source/capability/path/rotation provenance
└── tests/sccm_client_intake.rs    # native temporary-path/regression cases only
```

The parser crate's extended analyzers must not read `src-tauri` types. Conversely, the native intake layer must not implement workflow state machines. No code in this plan changes generic `collector::ArtifactStatus` without an independently reviewed generic schema migration.

## Shared Result Contract

Every workflow returns a shared `SccmWorkflowAnalysis` composed of stable `SccmTransaction` and `SccmFinding` records. Each transaction must include at least:

```rust
pub struct SccmTransaction {
    pub transaction_id: String,
    pub workflow: SccmWorkflow,
    pub phase: SccmPhase,
    pub state: SccmTransactionState,
    pub last_successful_phase: Option<SccmPhase>,
    pub keys: Vec<SccmCorrelationKey>,
    pub evidence: Vec<SccmEvidenceRef>,
    pub coverage_gap_artifact_ids: Vec<String>,
}
```

For every analysis result, assert these reviewer-visible properties:

- transaction/finding/evidence/key/request arrays are deterministically sorted;
- findings link to exact artifact/entry references or explicit coverage, never an unreferenced summary;
- `ConfirmedFailure` cannot be emitted without terminal/corroborating evidence defined by that workflow's catalog/version profile;
- `BlockedOrDeferred` distinguishes intentional wait/reboot/maintenance/handoff from a terminal failure;
- `InsufficientEvidence` names the smallest logical artifact group needed next;
- a malformed record/unknown version/invalid offset yields degraded confidence, never fabricated ordering;
- raw sensitive context is not present in exported/snapshot output.

## Task 1: Establish #324 Task Sequence source and execution-identity contracts

**Files:**

- Create: `crates/cmtraceopen-parser/src/sccm/client/task_sequence.rs`
- Modify: `crates/cmtraceopen-parser/src/sccm/client/mod.rs`
- Modify: `crates/cmtraceopen-parser/src/sccm/catalog.rs`
- Create: `crates/cmtraceopen-parser/tests/sccm_client_task_sequence.rs`
- Create: `crates/cmtraceopen-parser/tests/fixtures/sccm/client/task_sequence/README.md`
- Create: fixture directories `winpe`, `post-format`, `pre-client`, `client-installed`, `completed`, `relocated-fragments`, `unrelated-runs`, `rotation-boundary`, and `incomplete`
- Modify only after pure tests specify a new candidate: `src-tauri/src/sccm/intake.rs`, `src-tauri/src/sccm/manifest.rs`, and `src-tauri/tests/sccm_client_intake.rs`

**Consumes:** #318 artifact/evidence/coverage/timestamp/key/finding contracts and #319's versioned manifest/capture adapter.

**Produces:** A source catalog and execution-identity model that lets a Task Sequence analyzer know which captured `smsts` fragment belongs to a possible execution without treating a path or filename as the execution key.

### Candidate source rule

`smsts.log` is deliberately modeled as a dynamic captured artifact family. Candidate locations may include WinPE, temporary setup, post-format, full-OS, and client-installed locations, but the source catalog must never hard-code a single path as required. The native manifest records the observed original path and an optional sanitized path class (`winpe`, `setup`, `fullOs`, `client`, `unknown`) derived from an allow-listed discovery rule. The pure parser consumes only the artifact provenance/path class; it does not calculate a Windows path.

### Execution key rule

The preferred execution key is a profile-validated execution/run identifier or a stable combination of Task Sequence package/advertisement plus explicit run context. A mere `smsts.log` filename, machine name, timestamp range, task-sequence display name, or single step message is insufficient. When the identifier cannot be safely extracted, expose a low-confidence unlinked execution observation; do not combine it with any other fragment or later workflow.

- [ ] **Step 1: Write failing source and identity tests before parsing TS semantics**

Add tests that load synthetic manifests/fragments and assert:

  - `winpe`, `post-format`, `pre-client`, and `client-installed` artifacts retain their observed path classes and do not lose provenance after bundle normalization;
  - fragments with the same `smsts.log` basename from `winpe` and `fullOs` remain separate until an exact execution key joins them;
  - `relocated-fragments` with the same validated execution key joins in deterministic evidence order across a path transition;
  - `unrelated-runs` with similar timestamps but different validated execution IDs never join;
  - a rotation tail/malformed start cannot emit an execution key;
  - absence of an `smsts` candidate produces a Task Sequence coverage gap, not “no Task Sequence ran.”

Use an explicit API assertion:

```rust
let result = analyze_client_task_sequence(&load_bundle("task_sequence/relocated-fragments"));
assert_eq!(result.transactions.len(), 1);
assert_eq!(result.transactions[0].keys[0].kind, SccmCorrelationKeyKind::TaskSequenceExecutionId);
assert_eq!(result.transactions[0].evidence.len(), 4);
```

- [ ] **Step 2: Run the focused test target and preserve the red failure**

Run:

```bash
cargo test --locked -p cmtraceopen-parser --test sccm_client_task_sequence source_and_execution_identity
```

Expected: FAIL because no Task Sequence module/catalog/API exists.

- [ ] **Step 3: Implement candidate classification and key-safe fragment grouping**

Add only catalog metadata and pure grouping code in this step. The catalog should recognize `smsts.log` plus explicitly declared rotation forms; it may not classify arbitrary `*.log` files as Task Sequence evidence. `task_sequence.rs` must turn captured artifacts into fragment groups, preserve original artifact/path class/rotation evidence refs, then use #318 extraction-profile results to form execution candidates. Treat missing source version or unknown key pattern as a coverage/key-extraction gap.

For native intake, add a test-first, bounded candidate list. Capture only explicitly configured/observed allowed locations; preserve an unrecognized location as `unknown` rather than copying an entire disk. Test that each captured path is canonicalized inside an approved root and that duplicate `smsts.log` names receive distinct bundle-relative destinations.

- [ ] **Step 4: Make the source contract green**

Run:

```bash
cargo fmt --check --all
cargo test --locked -p cmtraceopen-parser --test sccm_client_task_sequence source_and_execution_identity
cargo test --locked -p cmtraceopen-parser --test sccm_client_intake
cargo test --locked -p cmtraceopen-parser --test sccm_spine_contract
cargo test --locked -p cmtrace-open --test sccm_client_intake --features sccm-diagnostics
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
git diff --check
```

- [ ] **Step 5: Commit the #324 source/key contract before phase rules**

```bash
git add crates/cmtraceopen-parser/src/sccm/client crates/cmtraceopen-parser/src/sccm/catalog.rs crates/cmtraceopen-parser/tests/sccm_client_task_sequence.rs crates/cmtraceopen-parser/tests/fixtures/sccm/client/task_sequence src-tauri/src/sccm src-tauri/tests/sccm_client_intake.rs
git commit -m "feat(sccm): model task sequence source provenance"
```

If native TS discovery requires materially different permissions or collection behavior from #319, keep it in a follow-up commit under #324 and document the separation in the issue.

## Task 2: Implement #324 Task Sequence state-machine analysis

**Files:**

- Modify: `crates/cmtraceopen-parser/src/sccm/client/task_sequence.rs`
- Modify: `crates/cmtraceopen-parser/src/sccm/client/mod.rs`
- Modify: `crates/cmtraceopen-parser/tests/sccm_client_task_sequence.rs`
- Modify: Task Sequence fixture directories with `expected.json` phase/finding contracts

**Consumes:** Validated execution groups from Task 1 and shared evidence/finding builders.

**Produces:** One transaction per safe Task Sequence execution, with relocation-aware phase progression and conservative terminal/deferred finding output.

### State contract

```text
Start -> Preflight -> DiskOrImage -> SetupWindows -> InstallClient -> InstallSoftware -> PostAction -> Complete
```

The exact names can evolve only through a versioned profile/change review. The reducer must distinguish a phase boundary observed in WinPE from a phase observed after path relocation. `Complete` needs terminal completion evidence for the same execution. A reboot, continuation handoff, or expected setup transition is `BlockedOrDeferred`/in progress—not a failed run.

- [ ] **Step 1: Add phase-specific failing fixtures/tests**

Add assertions for:

  - a completed run across relocation has one transaction and reaches `Complete`;
  - a terminal preflight failure has no later phase and is `ConfirmedFailure` only with terminal evidence;
  - a disk/image phase failure does not become an application deployment failure;
  - setup transitions from WinPE to full OS are recorded as expected boundary/deferred evidence when the same execution key is proven;
  - client installation failure stays in `InstallClient` and requests only relevant client setup evidence if coverage is incomplete;
  - software installation failure after a completed client install stays in `InstallSoftware` and does not reuse #322's app transaction as a cause;
  - reboot/continuation after an evidenced phase is deferred, not terminal;
  - a complete-looking message without exact execution key is low confidence;
  - fragments from two runs with matching times never combine;
  - an incomplete final log requests the next `task-sequence` artifact/path class rather than declaring failure.

- [ ] **Step 2: Run the entire #324 target red**

```bash
cargo test --locked -p cmtraceopen-parser --test sccm_client_task_sequence
```

Expected: FAIL because only source grouping exists; no phase reducer/finding rules should have been implemented in Task 1.

- [ ] **Step 3: Implement a per-execution monotonic reducer**

Represent source-local facts with phase candidate, evidence ref, terminality, and execution key. Sort safely, process only one execution candidate at a time, and retain contradictions instead of moving backward silently. A later success may demonstrate recovery only under the same exact execution key and coherent timestamp/provenance. Emit a high-confidence terminal failure only under the shared #318 finding validation rules plus a TS profile-recognized terminal fact.

For a partial path sequence, add a coverage gap describing the missing path class/captured continuation rather than assuming an error. Never request an unbounded Windows volume capture; requests must name a logical Task Sequence artifact and supported path class/reason.

- [ ] **Step 4: Add deterministic/negative regressions and run full gates**

Add tests for input-order invariant JSON, invalid offset ordering downgrade, unknown TS version profile, redacted execution context, and rotation physical-fragment isolation.

Run:

```bash
cargo fmt --check --all
cargo test --locked -p cmtraceopen-parser --test sccm_client_task_sequence
cargo test --locked -p cmtraceopen-parser
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
git diff --check
```

- [ ] **Step 5: Commit the #324 diagnostic slice and record validation limits**

```bash
git add crates/cmtraceopen-parser/src/sccm/client crates/cmtraceopen-parser/tests/sccm_client_task_sequence.rs crates/cmtraceopen-parser/tests/fixtures/sccm/client/task_sequence
git commit -m "feat(sccm): analyze task sequence execution evidence"
```

In #324, record which path classes and ConfigMgr/OS deployment profile versions have sanitized fixtures. Leave unobserved boot/recovery variants as explicit coverage gaps, not broad source support claims.

## Task 3: Establish #325 independent inventory, compliance, and metering source/transaction contracts

**Files:**

- Create: `crates/cmtraceopen-parser/src/sccm/client/inventory.rs`
- Modify: `crates/cmtraceopen-parser/src/sccm/client/mod.rs`
- Modify: `crates/cmtraceopen-parser/src/sccm/catalog.rs`
- Create: `crates/cmtraceopen-parser/tests/sccm_client_inventory.rs`
- Create: `crates/cmtraceopen-parser/tests/fixtures/sccm/client/inventory/README.md`
- Create: fixture directories `inventory-success`, `inventory-provider-wmi`, `inventory-queue-failure`, `compliance-success`, `compliance-evaluation-failure`, `compliance-remediation`, `compliance-reporting-failure`, `metering-success`, `metering-collection-failure`, `mixed-unrelated`, and `incomplete`

**Consumes:** #318 shared contracts and #319 bundle intake. Source names are admitted only after catalog/fixture evidence validates them.

**Produces:** Three separate transaction families, never one generic “client reporting” conclusion.

### Initial source catalog rule

Start with explicit candidate groups and mark uncertain names as provisional until a sanitized fixture/source reference proves their grammar:

| Logical group | Candidate log families | Consumed by | Required semantics |
| --- | --- | --- | --- |
| `client-inventory` | `InventoryAgent.log`, `InventoryProvider.log`, `InventoryAgentProvider.log` when observed | hardware/software inventory | collection, provider, serialization, queue/send, report |
| `client-compliance` | `CIAgent.log`, `CITaskMgr.log`, `DCMAgent.log`, `DCMReporting.log`, `StateMessage.log` when observed | configuration item/compliance | evaluate, remediate, report state |
| `client-metering` | `SWMTRReportGen.log` and explicitly observed metering logs | software metering | collect, aggregate, report |

The actual catalog must use only observed/proven suffixes. A provisional entry is allowed to be captured/represented as `Unsupported` or `Candidate`, but must not create a diagnostic phase rule until a test fixture and reviewed profile validate it.

### State contracts

```text
Inventory:  Collect -> Provider -> Serialize -> Queue -> Report
Compliance: Evaluate -> Remediate -> Report
Metering:   Collect -> Aggregate -> Report
```

Compliance remediation is a separate phase from evaluation. A non-compliant state is not itself a client collection failure. Inventory queue trouble cannot become a compliance diagnosis, even if both appear in the same StateMessage artifact.

- [ ] **Step 1: Write failing source separation tests**

Require tests to prove that input evidence creates distinct `SccmWorkflow` values/transactions for inventory, compliance, and metering; a CI/resource/state ID is not assumed to identify a software-metering report; and source coverage is tracked per workflow. Include a fixture with same-minute inventory and compliance failures that cannot merge.

- [ ] **Step 2: Run the #325 target red**

```bash
cargo test --locked -p cmtraceopen-parser --test sccm_client_inventory
```

Expected: FAIL because module/catalog/reducers do not exist.

- [ ] **Step 3: Implement catalog admission and three narrow fact extractors**

Create private source-specific fact structures—`InventoryFact`, `ComplianceFact`, and `MeteringFact`—each preserving evidence refs, profile version, candidate phase, keys, and terminality. Catalog admission must be table-driven and testable. Never scan arbitrary messages for terms such as “inventory”/“compliance” to create a workflow.

Use keys appropriate to each family: resource/inventory cycle IDs where profile-validated; CI/baseline/state IDs for compliance; metering/report identifiers for metering. If a key is unknown/unvalidated, retain a source-local symptom and coverage/key gap rather than attaching it to a transaction.

- [ ] **Step 4: Make source and basic transaction tests green**

Run:

```bash
cargo fmt --check --all
cargo test --locked -p cmtraceopen-parser --test sccm_client_inventory source_
cargo test --locked -p cmtraceopen-parser --test sccm_client_inventory separates_
cargo test --locked -p cmtraceopen-parser --test sccm_spine_contract
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
git diff --check
```

Expected: PASS. Do not add terminal diagnoses until Task 4 fixtures are red first.

- [ ] **Step 5: Commit source/transaction foundations separately**

```bash
git add crates/cmtraceopen-parser/src/sccm/client crates/cmtraceopen-parser/src/sccm/catalog.rs crates/cmtraceopen-parser/tests/sccm_client_inventory.rs crates/cmtraceopen-parser/tests/fixtures/sccm/client/inventory
git commit -m "feat(sccm): define inventory compliance and metering evidence"
```

## Task 4: Implement #325 state reducers and findings

**Files:**

- Modify: `crates/cmtraceopen-parser/src/sccm/client/inventory.rs`
- Modify: `crates/cmtraceopen-parser/tests/sccm_client_inventory.rs`
- Modify: #325 fixture expected files

**Consumes:** The source/fact contracts from Task 3.

**Produces:** Evidence-backed state completion, failure, deferred, and coverage outputs for each of the three workflows.

- [ ] **Step 1: Add failure/coverage twins for each workflow**

For inventory, test provider/WMI failure, queue/send failure, a successful later report recovery with the same exact cycle key, and missing report coverage. For compliance, test successful evaluation, terminal evaluation error, remediation action/result, non-compliant-but-evaluated state, report failure, and missing StateMessage coverage. For metering, test collect/aggregate/report success, collection failure, unknown source version, and absence of metering source.

Every failed fixture must assert class/confidence/last success/evidence/request. Every healthy fixture must assert no spurious `ConfirmedFailure`. Every missing-source twin must assert `InsufficientEvidence` with a specific group request.

- [ ] **Step 2: Run the complete #325 target red**

```bash
cargo test --locked -p cmtraceopen-parser --test sccm_client_inventory
```

Expected: FAIL because the Task 3 fact extractors should not yet make final state claims.

- [ ] **Step 3: Implement three isolated finite reducers**

Write one reducer per state contract. Permit a later recovery only with the same validated transaction key and safe source ordering. Treat explicit non-compliance as a compliance evaluation result, not a client malfunction. A queue/report failure must name the failed last step and request only the next relevant artifact if coverage is incomplete. Preserve contradictory evidence as low confidence rather than discard it.

- [ ] **Step 4: Run detailed test/compatibility gates**

```bash
cargo fmt --check --all
cargo test --locked -p cmtraceopen-parser --test sccm_client_inventory
cargo test --locked -p cmtraceopen-parser --test sccm_client_intake
cargo test --locked -p cmtraceopen-parser
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
git diff --check
```

- [ ] **Step 5: Commit #325's reducers and issue evidence**

```bash
git add crates/cmtraceopen-parser/src/sccm/client/inventory.rs crates/cmtraceopen-parser/tests/sccm_client_inventory.rs crates/cmtraceopen-parser/tests/fixtures/sccm/client/inventory
git commit -m "feat(sccm): analyze inventory compliance and metering"
```

Update #325 with the precise catalogued sources and validated profile/version scope. Do not call the entire inventory/compliance ecosystem supported from a small initial corpus.

## Task 5: Establish #326 co-management, scripts, notification, and Software Center capability contracts

**Files:**

- Create: `crates/cmtraceopen-parser/src/sccm/client/management.rs`
- Modify: `crates/cmtraceopen-parser/src/sccm/client/mod.rs`
- Modify: `crates/cmtraceopen-parser/src/sccm/catalog.rs`
- Create: `crates/cmtraceopen-parser/tests/sccm_client_management.rs`
- Create: `crates/cmtraceopen-parser/tests/fixtures/sccm/client/management/README.md`
- Create fixture directories `co-management-intune-owned`, `co-management-sccm-owned`, `co-management-unknown`, `script-success`, `script-failure`, `script-incomplete`, `notification-received`, `notification-deferred`, `software-center-observed`, `software-center-insufficient`, and `mixed-unrelated`

**Consumes:** #318 contracts and #319 catalog/intake. Native intake is extended only for explicit, tested source candidates.

**Produces:** Capability/ownership classification before any management diagnostic state machine runs.

### Candidate source rule and ownership boundary

Start with source names verified in source documentation or sanitized lab fixtures, such as `CoManagementHandler.log`, `Scripts.log`, `CcmNotificationAgent.log`, and explicitly observed Software Center client logs. BGB/server logs are server evidence and must not enter client source catalog just because notification traffic relates to them. If a Software Center log name/version is not yet validated, represent it as a candidate/unsupported artifact and open a narrow source-contract follow-up rather than guessing parsing behavior.

Co-management classification must make one of these outcomes before a workload analyzer runs:

```text
SccmOwned | IntuneOwned | SharedOrTransitioning | UnknownOwnership
```

`IntuneOwned` means SCCM evidence observed/indicates handoff; resulting finding is a handoff/capability observation, not an Intune root-cause diagnosis. `UnknownOwnership` blocks high-confidence workload conclusions and requests the minimal co-management evidence.

- [ ] **Step 1: Write capability/ownership tests first**

Assert that an Intune-owned workload causes a terminal handoff classification with cited `CoManagementHandler` evidence, no SCCM failure claim, and no request for every SCCM source. Assert SCCM-owned and transitioning cases remain distinct. Assert missing co-management evidence is unknown rather than a default SCCM-owned assumption. Assert unsupported Software Center candidates remain capability gaps, not parsed generic logs.

- [ ] **Step 2: Run #326 management target red**

```bash
cargo test --locked -p cmtraceopen-parser --test sccm_client_management capability_and_ownership
```

Expected: FAIL because management catalog/model/reducer APIs do not exist.

- [ ] **Step 3: Implement admission/capability model before operational reducers**

Create a private source admission table and an ownership resolver that consumes only version-profile-validated co-management records. It returns a precise classification with evidence refs, confidence, and coverage gaps. Do not use registry/tenant state directly in the parser crate. Native capture may include an explicitly structured registry export only if #319's manifest and privacy review permit it; otherwise leave the source missing and lower confidence.

- [ ] **Step 4: Verify the capability contract**

```bash
cargo fmt --check --all
cargo test --locked -p cmtraceopen-parser --test sccm_client_management capability_and_ownership
cargo test --locked -p cmtraceopen-parser --test sccm_spine_contract
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
git diff --check
```

- [ ] **Step 5: Commit the ownership gate alone**

```bash
git add crates/cmtraceopen-parser/src/sccm/client/management.rs crates/cmtraceopen-parser/src/sccm/catalog.rs crates/cmtraceopen-parser/tests/sccm_client_management.rs crates/cmtraceopen-parser/tests/fixtures/sccm/client/management
git commit -m "feat(sccm): classify client management ownership"
```

## Task 6: Implement #326 scripts, notification, and Software Center analysis behind the ownership gate

**Files:**

- Modify: `crates/cmtraceopen-parser/src/sccm/client/management.rs`
- Modify: `crates/cmtraceopen-parser/tests/sccm_client_management.rs`
- Modify: management fixture expected files

**Consumes:** Task 5 ownership/capability results, shared evidence/signals/keys/findings, and admitted source catalog entries.

**Produces:** Independent script, notification, and Software Center analyses that are explicitly scoped to SCCM-client evidence.

### State contracts

```text
Script:        Receive -> Execute -> Report
Notification:  Receive -> DeferOrDispatch -> Acknowledge
SoftwareCenter: ObserveRequest -> ClientAction -> ObserveOutcome
```

The Software Center contract is intentionally observational. It may report that a request/action/outcome was or was not evidenced in catalogued client records, but does not assert UI rendering, user intent, or server-side availability without dedicated evidence. Notification `Deferred` is not a delivery failure unless a terminal acknowledgement/timeout record exists for the same validated notification key.

- [ ] **Step 1: Add failing operational fixture tests**

Require:

  - script success/reported state;
  - terminal script failure with exact script/execution key and preserved exit signal;
  - missing final script report as insufficient evidence rather than success/failure;
  - received notification and deferred notification separate from terminal notification failure;
  - a generic service error in the same minute does not attach to a notification;
  - Software Center observed action/outcome only when supported catalog evidence exists;
  - unavailable/unsupported Software Center log declares capability insufficiency;
  - Intune-owned work does not emit SCCM script/deployment causality even if an unrelated SCCM log contains an error.

- [ ] **Step 2: Run #326 target red**

```bash
cargo test --locked -p cmtraceopen-parser --test sccm_client_management
```

Expected: FAIL because Task 5 implements only capability/ownership classification.

- [ ] **Step 3: Implement scoped reducers**

Extract source-local facts per admitted group, group by exact validated script/notification/action keys, and run the small state machine. Require terminal source-specific facts for high-confidence failure. Existing #318 signal extraction enriches raw codes but does not by itself assign a script/notification phase. Attach ownership classification to every management result and cap confidence at low/medium whenever ownership is transitioning/unknown.

- [ ] **Step 4: Add redaction/order/coverage regressions and run checks**

Ensure exported output masks user context/command arguments, artifact input reordering has stable JSON, unknown source versions cannot create exact command/action keys, and partial logical records cannot establish a terminal result.

Run:

```bash
cargo fmt --check --all
cargo test --locked -p cmtraceopen-parser --test sccm_client_management
cargo test --locked -p cmtraceopen-parser --test sccm_client_inventory
cargo test --locked -p cmtraceopen-parser
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
git diff --check
```

- [ ] **Step 5: Commit #326 operational analysis separately from the ownership gate**

```bash
git add crates/cmtraceopen-parser/src/sccm/client/management.rs crates/cmtraceopen-parser/tests/sccm_client_management.rs crates/cmtraceopen-parser/tests/fixtures/sccm/client/management
git commit -m "feat(sccm): analyze client management evidence"
```

## Task 7: Run the extended-client acceptance and issue-review gate

**Files:**

- Create: `docs/sccm/validation/client-extended-lab-checklist.md`
- Modify: GitHub issues #324–#326 with fixture/test/validation evidence
- Modify parser README only if actual public API calls need user-facing documentation

**Consumes:** Completed issue slices, pure test corpus, and an authorized development client/lab when available.

**Produces:** Reviewable completion evidence that distinguishes fixture coverage from live Windows source acceptance.

- [ ] **Step 1: Run every focused and aggregate parser test**

```bash
cargo test --locked -p cmtraceopen-parser --test sccm_spine_contract
cargo test --locked -p cmtraceopen-parser --test sccm_client_intake
cargo test --locked -p cmtraceopen-parser --test sccm_client_task_sequence
cargo test --locked -p cmtraceopen-parser --test sccm_client_inventory
cargo test --locked -p cmtraceopen-parser --test sccm_client_management
cargo test --locked -p cmtraceopen-parser
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo fmt --check --all
git diff --check
```

- [ ] **Step 2: Run native candidate-regression tests**

```bash
cargo test --locked -p cmtrace-open --test sccm_client_intake --features sccm-diagnostics
cargo test --locked -p cmtrace-open --test esp_diagnostics_sources --all-features
cargo test --locked -p cmtrace-open --test parser_expanded_corpus --all-features
cargo clippy --locked -p cmtrace-open --all-targets --all-features -- -D warnings
```

- [ ] **Step 3: Validate source candidates on a Windows development client only**

The lab checklist must ask for ConfigMgr/OS version, boot context, observed TS path class, selected non-production synthetic scenario, discovered candidate source names, access/cap behavior, capture limits, sanitization/replacement map, and explicit statement of which candidates were not observed. Do not use live boot/task sequence evidence or real client identifiers as committed fixtures.

- [ ] **Step 4: Inspect one JSON output per branch before review**

For each issue inspect: a success, a terminal failure, a deferred/handoff/non-failure state, an incomplete coverage case, and an adversarial same-time/unrelated case. Check source provenance, exact evidence refs, state/last-success distinction, confidence cap, minimal artifact requests, stable serialized ordering, and exported redaction.

- [ ] **Step 5: Update issue closure status conservatively**

For #324 list validated path classes, execution-key/profile scope, and untested boot/relocation variants. For #325 list each admitted source family and separate state machines. For #326 list ownership classifications/source candidates and clarify that Intune-owned work is not diagnosed by this issue. Keep an issue open if any required corpus case or Windows capture acceptance is absent; a successful compile is not closure evidence.

## Exit Criteria

### #324 Task Sequence

- [ ] Dynamic/relocated `smsts` capture provenance is preserved and no filename-only merging occurs.
- [ ] Execution transaction keys are exact/profile-validated; unkeyed fragments remain low-confidence observations.
- [ ] Every defined phase has success, terminal, boundary/deferred, contradictory, rotation, and missing-coverage fixtures.
- [ ] Native path candidate validation is recorded separately from pure parser acceptance.

### #325 Inventory, compliance, metering

- [ ] Three workflow source catalogs/fact extractors/reducers remain separate.
- [ ] Non-compliant is not conflated with client/collection failure; queue/report failure is not conflated with evaluation.
- [ ] Unknown source/version/key produces explicit coverage/key gaps rather than a false transaction.
- [ ] Each workflow has healthy, terminal, recovery/contradictory, and incomplete fixture contracts.

### #326 Client management

- [ ] Co-management ownership is resolved or explicitly unknown before action-level diagnoses.
- [ ] Intune-owned/shared/transitioning workloads do not produce SCCM root-cause claims.
- [ ] Scripts, notification, and Software Center analyses only consume catalogued source evidence and distinguish deferred/capability gaps from failure.
- [ ] Raw command/user/context values remain redacted in public output and fixtures.
