# SCCM Production Correlation Implementation Plan

> **For agentic workers:** Execute this plan inline. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Correlate exactly the policy↔management-point, content↔distribution-point, and updates↔software-update-point pairs without weakening any source-local result.

**Architecture:** Add one public `sccm::correlation` module. Pair adapters translate only accepted public endpoint facts and bounded coverage/profile metadata into one private canonical reducer; the reducer owns all shared guards, deterministic ordering, hashed public handles, reason codes, and artifact requests. The source analyses are borrowed and never mutated or reserialized by the reducer.

**Tech Stack:** Rust, Serde, SHA-256 via the existing `sha2` dependency, JSON fixture oracles, Cargo test/Clippy/rustfmt.

---

### Task 1: Freeze the production contract

**Files:**
- Create: `crates/cmtraceopen-parser/src/sccm/correlation.rs`
- Modify: `crates/cmtraceopen-parser/src/sccm/mod.rs`

- [x] **Step 1: Add public pair/result types and private canonical facts**

Define `SccmCorrelationPair`, `SccmCorrelationOutcome`, `SccmCorrelationLinkStrength`, `SccmCorrelationConfidence`, `SccmCorrelationGuard`, `SccmCorrelationReason`, `SccmCorrelationArtifactRequest`, `SccmCorrelationResult`, and `SccmCorrelationAnalysis`. All serialized enums use camelCase; collections are sorted and bounded.

- [x] **Step 2: Add three typed pair inputs**

Expose private-field input structs created only by `from_analyses` adapters:

```rust
pub struct SccmPolicyManagementPointInput { canonical: CanonicalInput }
pub struct SccmContentDistributionPointInput { canonical: CanonicalInput }
pub struct SccmUpdatesSoftwareUpdatePointInput { canonical: CanonicalInput }
```

Each adapter reads accepted public counterpart facts/transactions plus profile, coverage, and rotation state; it does not parse raw records or accept caller-provided identities.

- [x] **Step 3: Export the module**

Add `pub mod correlation;` and `pub use correlation::*;` through `sccm/mod.rs`.

### Task 2: Implement pair translation and the shared reducer

**Files:**
- Modify: `crates/cmtraceopen-parser/src/sccm/correlation.rs`

- [x] **Step 1: Translate policy and management-point facts**

Use request ID + policy ID as the exact key and site code as shared topology. Admit only the accepted client and server profile IDs. Use normalized observation timestamps and server terminal evidence; carry only bounded logical artifact requests.

- [x] **Step 2: Translate content and distribution-point facts**

Use package ID + content ID + content version as the exact key and the opaque DP handle as topology. Use the client counterpart-ready request fact and the server transaction's terminal observation; reject content-version conflicts.

- [x] **Step 3: Translate updates and software-update-point facts**

Use update ID as the exact cross-side key and site code + opaque SUP handle as topology. Use the client counterpart-ready location fact and the server transaction's terminal observation.

- [x] **Step 4: Enforce the shared gates**

The reducer checks all 13 registered guards for every pair. `ExactCorroborated` + `High` is possible only with accepted profiles, one compatible exact key, compatible topology, normalized comparable ordering, complete coverage/rotation, and a matching terminal server failure. Every other state returns conservative strength/confidence, reason codes, and side-owned requests.

- [x] **Step 5: Make output deterministic and private**

Sort/deduplicate facts and requests before reduction. Compute result IDs and fact handles from canonical SHA-256 preimages. Do not serialize raw keys, paths, hostnames, users, tokens, evidence messages, or unapproved identifiers.

### Task 3: Promote the registry and matrices to production oracles

**Files:**
- Modify: `crates/cmtraceopen-parser/tests/fixtures/sccm/correlation/pair-registry.json`
- Modify: `crates/cmtraceopen-parser/tests/fixtures/sccm/correlation/shared/adversarial-matrix.json`
- Modify: `crates/cmtraceopen-parser/tests/fixtures/sccm/correlation/policy_management_point/adversarial-matrix.json`
- Modify: `crates/cmtraceopen-parser/tests/fixtures/sccm/correlation/content_distribution_point/adversarial-matrix.json`
- Create: `crates/cmtraceopen-parser/tests/fixtures/sccm/correlation/updates_software_update_point/adversarial-matrix.json`

- [x] **Step 1: Mark exactly three pairs production enabled**

Set every pair to `ruleValidated`, `productionEnabled: true`, `ruleValidated: true`, implementation module `sccm::correlation`, all 13 guards, and no blockers.

- [x] **Step 2: Add exact expected serialized outputs and hashes**

Each pair matrix contains a healthy exact case plus one executable construction for every guard, including opposite-order A/B cases with identical expected output. Pin the complete JSON output and its SHA-256 hash.

- [x] **Step 3: Apply every shared guard to every pair**

Update the shared matrix `appliesTo` arrays to include all three workflows and retain closed required-output obligations.

### Task 4: Replace scaffolding tests with production tests

**Files:**
- Modify: `crates/cmtraceopen-parser/tests/sccm_correlation_contract.rs`

- [x] **Step 1: Execute all three matrices through the public reducers**

Build typed endpoint analyses/facts, run each pair adapter and reducer, compare the entire serialized `SccmCorrelationAnalysis`, then hash those exact bytes and compare the pinned digest.

- [x] **Step 2: Add mutation gates**

Mutate each guard input and assert it cannot remain exact/high. Add duplicate/collision, contradictory recovery, malformed expected projection/hash, and missing-counterpart request tests.

- [x] **Step 3: Add ordering and privacy gates**

Reverse and duplicate input facts and assert byte-identical output and IDs. Seed raw path/host/user/token markers in source-local fields and assert none appears in correlation JSON.

- [x] **Step 4: Prove source-local immutability**

Serialize both source analyses before input construction and correlation, then assert the bytes remain identical afterward for all three pairs.

### Task 5: Validate and freeze

**Files:**
- Test: all touched correlation and upstream suites

- [x] **Step 1: Run focused tests**

Run `cargo test --locked -p cmtraceopen-parser --test sccm_correlation_contract` and the six upstream endpoint suites.

- [x] **Step 2: Run package and target gates**

Run full parser tests, wasm32 check, and strict all-target Clippy.

- [x] **Step 3: Run hygiene gates and commit**

Run scoped rustfmt, `jq empty` on all correlation JSON, `git diff --check`, inspect the issue-only diff, commit, and verify a clean worktree at the frozen SHA.
