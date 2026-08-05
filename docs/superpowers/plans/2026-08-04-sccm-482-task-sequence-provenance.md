# SCCM #482 Task Sequence Relocation Provenance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Task Sequence stage and relocation authority explicit, bounded, deterministic, and integrity-sealed from canonical client intake through admitted evidence.

**Architecture:** Add one versioned nested provenance object to physical `client-task-sequence-smsts` artifacts. Validate it in canonical intake, copy it without inference into admitted authority, bind it into the existing integrity seal, and make the reducer consume only that sealed provenance for path class and relocation order.

**Tech Stack:** Rust, Serde, the pure `cmtraceopen-parser` SCCM intake/admission/reducer modules, Cargo tests, wasm32, Clippy.

**Frozen base:** `8064b5aa1457f72ea8dbb7cb979ec3ea863c524c`

---

### Task 1: Add the versioned intake provenance contract

**Files:**
- Modify: `crates/cmtraceopen-parser/src/sccm/client/intake.rs`
- Test: `crates/cmtraceopen-parser/src/sccm/client/admission_tests.rs`

- [ ] **Step 1: Write failing serde and physical-artifact tests**

Cover valid version 1, missing provenance, version 2, unsafe evidence, unsafe lineage, and relative-path/class mismatch. Missing physical provenance must return `MissingTaskSequenceProvenance`; malformed provenance must return `InvalidTaskSequenceProvenance`.

```rust
let provenance = SccmTaskSequenceProvenance {
    version: 1,
    path_class: SccmTaskSequencePathClass::Setup,
    smsts_log_path_evidence: Some("synthetic:smsts-path:setup".to_owned()),
    relocation_lineage: "synthetic:ts-relocation:relocated-fragments".to_owned(),
    relocation_ordinal: 1,
};
```

- [ ] **Step 2: Run the red tests**

```sh
cargo test --locked -p cmtraceopen-parser --lib client::admission_tests
```

Expected: FAIL before the type and validators exist.

- [ ] **Step 3: Implement the minimal nested type**

```rust
pub const SCCM_TASK_SEQUENCE_PROVENANCE_VERSION: u16 = 1;
pub const MAX_SCCM_TASK_SEQUENCE_PATH_EVIDENCE_CHARS: usize = 256;
pub const MAX_SCCM_TASK_SEQUENCE_RELOCATION_LINEAGE_CHARS: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SccmTaskSequenceProvenance {
    pub version: u16,
    pub path_class: SccmTaskSequencePathClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub smsts_log_path_evidence: Option<String>,
    pub relocation_lineage: String,
    pub relocation_ordinal: u32,
}
```

Add `task_sequence_provenance: Option<SccmTaskSequenceProvenance>` to `SccmClientIntakeArtifact`, `SccmClientIntakeFragment`, and their wire projections. Add `MissingTaskSequenceProvenance`, `InvalidTaskSequenceProvenance`, and `CollidingTaskSequenceRelocation` errors.

Rules: physical Task Sequence fragments require version 1; other artifacts and coverage-only declarations may not carry it. Evidence is optional but bounded and may be only a closed synthetic token or versioned opaque token—never a drive path, UNC path, separator-bearing path, traversal, or control-bearing value. Relocation lineage is bounded and distinct from physical `rotation_lineage`. If `relative_path` exists, its encoded class must agree with explicit class, but explicit class remains authoritative.

- [ ] **Step 4: Run tests and commit**

```sh
cargo test --locked -p cmtraceopen-parser --lib client::admission_tests
git add crates/cmtraceopen-parser/src/sccm/client/intake.rs crates/cmtraceopen-parser/src/sccm/client/admission_tests.rs
git commit -m "feat(sccm): add task sequence relocation provenance"
```

### Task 2: Validate relocation identity and ordering

**Files:**
- Modify: `crates/cmtraceopen-parser/src/sccm/client/intake.rs`
- Test: `crates/cmtraceopen-parser/src/sccm/client/admission_tests.rs`

- [ ] **Step 1: Add red tests** for duplicate lineage+ordinal, distinct lineages reusing an ordinal, reverse input order, explicit unknown class, absent stages, and incomplete rotation boundaries.
- [ ] **Step 2: Run the focused test and observe the collision failure.**
- [ ] **Step 3: Implement a `BTreeMap<(String, u32), String>` keyed by relocation lineage and ordinal, valued by physical artifact identity. Reject a second distinct identity. Canonical ordering is `(relocation_lineage, relocation_ordinal, artifact_id)`; never input order or timestamps.**
- [ ] **Step 4: Re-run and commit.**

```sh
cargo test --locked -p cmtraceopen-parser --lib client::admission_tests
git add crates/cmtraceopen-parser/src/sccm/client/intake.rs crates/cmtraceopen-parser/src/sccm/client/admission_tests.rs
git commit -m "fix(sccm): seal task sequence relocation identity"
```

### Task 3: Carry provenance through admission and integrity

**Files:**
- Modify: `crates/cmtraceopen-parser/src/sccm/client/admission.rs`
- Test: `crates/cmtraceopen-parser/src/sccm/client/authority_contract_tests.rs`

- [ ] **Step 1: Add mutation tests** for class, evidence token, relocation lineage, and ordinal. Every post-admission mutation must make `verify_integrity()` fail closed.
- [ ] **Step 2: Run the red authority tests.**
- [ ] **Step 3: Replace relative-path derivation with required sealed provenance.**

```rust
pub(crate) struct SccmClientAdmittedTaskSequenceSource {
    pub(crate) provenance: SccmTaskSequenceProvenance,
    pub(crate) rotation: SccmRotation,
    pub(crate) coverage: SccmCoverageState,
    pub(crate) fragment_complete: Option<bool>,
    pub(crate) physical_evidence: Option<SccmClientAdmittedTaskSequencePhysicalEvidence>,
}
```

Clone the validated fragment provenance in `admit_client_evidence`. Remove the `task_sequence_path_class_for_relative_path` authority construction. The existing `IntegrityProjection` must serialize the nested provenance; do not create another seal.

- [ ] **Step 4: Re-run and commit.**

```sh
cargo test --locked -p cmtraceopen-parser --lib client::authority_contract_tests client::admission_tests
git add crates/cmtraceopen-parser/src/sccm/client/admission.rs crates/cmtraceopen-parser/src/sccm/client/authority_contract_tests.rs
git commit -m "fix(sccm): bind relocation provenance to admission"
```

### Task 4: Consume only sealed provenance in the reducer

**Files:**
- Modify: `crates/cmtraceopen-parser/src/sccm/client/task_sequence.rs`
- Test: `crates/cmtraceopen-parser/tests/sccm_client_task_sequence.rs`

- [ ] **Step 1: Add regressions** for four-stage relocation, reversed input, unrelated lineages, unknown class, missing `_SMSTSLogPath`, and a record path contradicting the sealed class.
- [ ] **Step 2: Run the test and confirm the authority-inversion regression fails.**
- [ ] **Step 3: Read `source.provenance.path_class`, `relocation_lineage`, and `relocation_ordinal`. Add ordinal to path observations. Restrict/remove `classify_observed_path`; filenames, `relative_path`, `_SMSTSLogPath`, and timestamps may corroborate but never create stage authority.**
- [ ] **Step 4: Re-run and commit.**

```sh
cargo test --locked -p cmtraceopen-parser --test sccm_client_task_sequence
git add crates/cmtraceopen-parser/src/sccm/client/task_sequence.rs crates/cmtraceopen-parser/tests/sccm_client_task_sequence.rs
git commit -m "fix(sccm): consume sealed task sequence relocation"
```

Do not change Task Sequence transactions, findings, phase semantics, or cross-side causality.

### Task 5: Promote fixtures and run the full gate

**Files:**
- Modify: `crates/cmtraceopen-parser/tests/sccm_client_task_sequence_fixture_contract.rs`
- Modify: `crates/cmtraceopen-parser/tests/fixtures/sccm/client/task_sequence/**/manifest.json`
- Test: `crates/cmtraceopen-parser/tests/sccm_spine_contract.rs`

- [ ] **Step 1: Replace parallel design authority with canonical nested provenance** on every physical Task Sequence fixture. Keep explicit absence for a valid WinPE record without a path token and do not invent provenance for coverage-only gaps.

```json
"taskSequenceProvenance": {
  "version": 1,
  "pathClass": "setup",
  "smstsLogPathEvidence": "synthetic:smsts-path:setup",
  "relocationLineage": "synthetic:ts-relocation:relocated-fragments",
  "relocationOrdinal": 1
}
```

- [ ] **Step 2: Add boundary/privacy cases** for at-limit and limit+1 evidence/lineage, unsafe Windows/UNC/traversal values, unsupported version, duplicate ordinal, malformed/capped/denied/incomplete fragments, and deterministic ordering.
- [ ] **Step 3: Run all gates.**

```sh
cargo test --locked -p cmtraceopen-parser --lib
cargo test --locked -p cmtraceopen-parser --test sccm_client_task_sequence
cargo test --locked -p cmtraceopen-parser --test sccm_client_task_sequence_fixture_contract
cargo test --locked -p cmtraceopen-parser --test sccm_spine_contract
cargo test --locked -p cmtraceopen-parser
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo fmt --check --all
git diff --check
```

Expected: every command exits `0`.

- [ ] **Step 4: Commit and deliver the evidence pack.**

```sh
git add crates/cmtraceopen-parser/src/sccm/client crates/cmtraceopen-parser/tests/sccm_client_task_sequence.rs crates/cmtraceopen-parser/tests/sccm_client_task_sequence_fixture_contract.rs crates/cmtraceopen-parser/tests/sccm_spine_contract.rs crates/cmtraceopen-parser/tests/fixtures/sccm/client/task_sequence
git commit -m "test(sccm): pin task sequence relocation provenance"
git diff --stat 8064b5aa1457f72ea8dbb7cb979ec3ea863c524c..HEAD
git show --check --oneline HEAD
git status --porcelain
```

The handoff must include exact SHA, changed files, focused/full/wasm32/Clippy/fmt/diff results, and reproduction commands. Do not merge; independent review follows.

## Self-review

- Spec coverage: every #482 required-contract and red-first item maps to Tasks 1–5.
- Placeholder scan: no validation, privacy, error, or edge-state work is deferred.
- Type consistency: `SccmTaskSequenceProvenance` is the sole provenance type across intake, fragments, admitted authority, integrity sealing, and reducer consumption.
- Scope: no native discovery, filesystem I/O, semantic expansion, cross-side causality, or compatibility fallback.
