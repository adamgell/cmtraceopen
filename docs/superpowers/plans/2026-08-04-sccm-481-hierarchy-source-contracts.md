# SCCM #481 Hierarchy Source Contracts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Admit only evidence-supported hierarchy source contracts through canonical server intake, preserving missing version, topology, direction, and key authority as explicit gaps.

**Architecture:** Add one typed hierarchy subcontract to the existing server catalog and one optional hierarchy admission projection to existing artifact assessments. Validate exact source/basename/component/rotation tuples from bounded CCM evidence, bind the projection into the existing intake integrity seal, and keep unproven direction, topology, keys, and supplements coverage-only.

**Tech Stack:** Rust, Serde, existing `cmtraceopen-parser` SCCM catalog/intake/evidence modules, Cargo tests, wasm32, Clippy.

**Frozen base:** `8064b5aa1457f72ea8dbb7cb979ec3ea863c524c`

**Observed witness:** ConfigMgr `5.00.9141.1000`, draft tag `sccm-lab-pr490-6fbf1f09`, archive SHA256 `f46df02daeabbe53d73f98ea9782ea53bf7949ef7cca8322a633d9d0ba55e217`.

---

### Task 1: Declare the exact hierarchy source/component/rotation contract

**Files:**
- Modify: `crates/cmtraceopen-parser/src/sccm/server/windows/catalog.rs`
- Test: `crates/cmtraceopen-parser/tests/sccm_server_hierarchy_source_contract.rs`

- [ ] **Step 1: Write a failing exact-catalog test**

Assert these and only these observed rows:

| Source ID | Basename/rotation | Component |
|---|---|---|
| `server-hierarchy-control` | `replmgr.log` current | `SMS_REPLICATION_MANAGER` |
| `server-hierarchy-control` | `rcmctrl.log` current | `SMS_REPLICATION_CONFIGURATION_MONITOR` |
| `server-hierarchy-control` | `rcmctrl.lo_` lo_ | `SMS_REPLICATION_CONFIGURATION_MONITOR` |
| `server-hierarchy-transfer` | `sender.log` current | `SMS_LAN_SENDER` |
| `server-hierarchy-transfer` | `despool.log` current | `SMS_DESPOOLER` |

Do not declare `sender.lo_`: the lab did not observe it.

- [ ] **Step 2: Run the red test**

```sh
cargo test --locked -p cmtraceopen-parser --test sccm_server_hierarchy_source_contract
```

- [ ] **Step 3: Add the minimal typed subcatalog**

```rust
pub const SCCM_SERVER_HIERARCHY_SOURCE_CONTRACT_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmServerHierarchyDirection {
    Origin,
    Target,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SccmServerHierarchyRotationContract {
    Current,
    LoUnderscore,
}

#[derive(Debug)]
pub struct SccmServerHierarchySourceContract {
    pub contract_version: u32,
    pub source_id: &'static str,
    pub logical_name: &'static str,
    pub producer_role: SccmRole,
    pub expected_component: &'static str,
    pub allowed_rotations: &'static [SccmServerHierarchyRotationContract],
}
```

Keep this rotation-policy enum crate-private unless a tested public consumer requires it; the public manifest continues to use the existing `SccmRotation` wire contract. Direction is intentionally not inferred by this table. It becomes authoritative only when a manifest declares it and topology validates it.

Add `declared_hierarchy_source_contracts()` and a crate-private exact classifier. Keep the broad catalog as the single discovery registry.

- [ ] **Step 4: Re-run and commit**

```sh
cargo test --locked -p cmtraceopen-parser --test sccm_server_hierarchy_source_contract
git add crates/cmtraceopen-parser/src/sccm/server/windows/catalog.rs crates/cmtraceopen-parser/tests/sccm_server_hierarchy_source_contract.rs
git commit -m "feat(sccm): declare hierarchy source contracts"
```

### Task 2: Add typed canonical intake admission and gaps

**Files:**
- Modify: `crates/cmtraceopen-parser/src/sccm/server/windows/intake.rs`
- Modify: `crates/cmtraceopen-parser/src/sccm/server/windows/mod.rs`
- Test: `crates/cmtraceopen-parser/tests/sccm_server_hierarchy_source_contract.rs`

- [ ] **Step 1: Add red intake tests** for exact tuple success, wrong component, wrong rotation, unknown contract version, missing source version, missing direction, missing topology link, direction/topology contradiction, and reverse input order.

- [ ] **Step 2: Run and observe failures.**

- [ ] **Step 3: Add one hierarchy-specific projection, not a generalized parallel admission system.**

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmServerHierarchyAdmission {
    pub contract_version: u32,
    pub component: String,
    pub direction: Option<SccmServerHierarchyDirection>,
    pub profile_id: Option<String>,
    pub confidence: SccmKeyConfidence,
    pub gaps: Vec<SccmServerHierarchyAdmissionGap>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmServerHierarchyAdmissionGap {
    MissingVersion,
    UnvalidatedProfile,
    MissingTopology,
    UnvalidatedDirection,
    UnvalidatedKeys,
    ComponentMismatch,
    RotationMismatch,
    UnsupportedContractVersion,
}
```

Add `hierarchy_admission: Option<SccmServerHierarchyAdmission>` to `SccmServerArtifactAssessment` and the intake-integrity identity/projection. Non-hierarchy artifacts remain unchanged.

For a captured hierarchy CCM file, scan bounded logical records using the existing parser, require the exact observed component for source/basename/rotation, and compute a content digest only as parser-computed integrity. Do not claim the collector supplied `contentSha256` when it is null.

Version/profile rules:

- The lab’s `sourceVersion=null` produces `MissingVersion` and `UnvalidatedProfile`.
- ConfigMgr `5.00.9141.1000` is retained as external capture metadata, not guessed from timestamps or executable paths inside the pure parser.
- Exact profile confidence is available only when an explicit supported source version/profile is present.

Direction/topology rules:

- Basename and component never imply origin or target.
- Direction requires an explicit manifest value plus a matching validated hierarchy link.
- Missing link/direction stays a gap; contradiction fails closed.
- Extend `normalize_hierarchy_link` to accept production opaque site/host handles, rejecting empty/equal endpoints, unsafe handles, and duplicates. Retain the closed synthetic vocabulary.

- [ ] **Step 4: Re-run, verify order-independent serialization, and commit.**

```sh
cargo test --locked -p cmtraceopen-parser --test sccm_server_hierarchy_source_contract
git add crates/cmtraceopen-parser/src/sccm/server/windows/intake.rs crates/cmtraceopen-parser/src/sccm/server/windows/mod.rs crates/cmtraceopen-parser/tests/sccm_server_hierarchy_source_contract.rs
git commit -m "fix(sccm): bind hierarchy admission to intake"
```

### Task 3: Keep hierarchy keys profile-bound and source-local

**Files:**
- Modify: `crates/cmtraceopen-parser/src/sccm/keys.rs`
- Modify: `crates/cmtraceopen-parser/src/sccm/models.rs` only if a genuinely missing key kind is required by observed or committed profile data
- Test: `crates/cmtraceopen-parser/tests/sccm_server_hierarchy_source_contract.rs`
- Test: `crates/cmtraceopen-parser/tests/sccm_spine_contract.rs`

- [ ] **Step 1: Add red tests** proving thread IDs, `SiteNumber`, SQL names, and a `pszSiteCode` function token are not correlation keys. Missing version/profile/topology must emit no exact sender/message/link/package/content/flow key.
- [ ] **Step 2: Run the tests.**
- [ ] **Step 3: Gate existing hierarchy key extraction on the sealed hierarchy admission’s exact profile and declared field vocabulary.** Do not add labels such as `SenderJobId=` or `ReplicationFlowId=` as live grammar unless a reviewed fixture actually contains them. Keep synthetic grammar isolated to its explicit synthetic profile.
- [ ] **Step 4: Re-run and commit.**

```sh
cargo test --locked -p cmtraceopen-parser --test sccm_server_hierarchy_source_contract --test sccm_spine_contract
git add crates/cmtraceopen-parser/src/sccm/keys.rs crates/cmtraceopen-parser/src/sccm/models.rs crates/cmtraceopen-parser/tests/sccm_server_hierarchy_source_contract.rs crates/cmtraceopen-parser/tests/sccm_spine_contract.rs
git commit -m "fix(sccm): keep hierarchy keys profile bound"
```

### Task 4: Define the optional structured supplement boundary

**Files:**
- Modify: `crates/cmtraceopen-parser/src/sccm/server/windows/catalog.rs`
- Modify: `crates/cmtraceopen-parser/src/sccm/server/windows/intake.rs`
- Test: `crates/cmtraceopen-parser/tests/sccm_server_hierarchy_source_contract.rs`
- Create: `crates/cmtraceopen-parser/tests/fixtures/sccm/server/hierarchy_and_replication/supplemental-database/{absent,malformed,oversized,unknown-version}/`

- [ ] **Step 1: Add red tests** for absent, unauthorized, malformed, oversized/capped, and unknown-schema supplements.
- [ ] **Step 2: Run the red matrix.**
- [ ] **Step 3: Add an optional manifest extension** with explicit operator authorization, schema version, privacy class, byte/file caps, copied-byte count, content digest, collection timestamp, and payload reference. Normalize it through the same intake and integrity seal. Public provenance is exactly `imported supplemental evidence`; query text, table names, connection strings, credentials, raw database/server/site values, and raw identifiers are forbidden.

The current raw lab does not prove this contract. Consequently, no production schema/profile is admitted yet: absent is valid optional coverage; unknown version is coverage-only; unauthorized/malformed data fails closed; capped data preserves the cap gap and is not interpreted. `rcmctrl.lo_` is a rotated CCM log, never a database supplement.

- [ ] **Step 4: Re-run and commit.**

```sh
cargo test --locked -p cmtraceopen-parser --test sccm_server_hierarchy_source_contract
git add crates/cmtraceopen-parser/src/sccm/server/windows/catalog.rs crates/cmtraceopen-parser/src/sccm/server/windows/intake.rs crates/cmtraceopen-parser/tests/sccm_server_hierarchy_source_contract.rs crates/cmtraceopen-parser/tests/fixtures/sccm/server/hierarchy_and_replication/supplemental-database
git commit -m "feat(sccm): define hierarchy supplement boundary"
```

### Task 5: Add the sanitized observed fixture and full verification

**Files:**
- Create: `crates/cmtraceopen-parser/tests/fixtures/sccm/server/hierarchy_and_replication/live-lab-5.00.9141.1000/`
- Modify: `crates/cmtraceopen-parser/tests/sccm_server_hierarchy_source_contract.rs`
- Modify: `crates/cmtraceopen-parser/tests/sccm_server_intake.rs`

- [ ] **Step 1: Add a sanitized observed fixture** containing only safe source IDs, basenames, roles, rotations, exact component tags, byte counts, opaque lineage/digest handles, and safe generic CCM envelopes. Do not copy raw lab payloads, host/site values, SQL/database values, paths, or thread IDs.
- [ ] **Step 2: Assert** all five rows classify exactly; `rcmctrl.lo_` is the only observed rotation; null source version yields profile gaps; null path class is not guessed; empty hierarchy links yield direction/topology gaps; no exact hierarchy keys are emitted; and public output contains no raw identifiers.
- [ ] **Step 3: Assert deterministic ordering for identical inputs**, not byte identity between the two captures; live `rcmctrl.log` changed between captures.
- [ ] **Step 4: Run every gate.**

```sh
cargo test --locked -p cmtraceopen-parser --test sccm_server_hierarchy_source_contract
cargo test --locked -p cmtraceopen-parser --test sccm_server_intake
cargo test --locked -p cmtraceopen-parser --test sccm_server_intake_fixture_contract
cargo test --locked -p cmtraceopen-parser --test sccm_spine_contract
cargo test --locked -p cmtraceopen-parser
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo fmt --check --all
git diff --check
```

Expected: every command exits `0`; no `src-tauri` or `server/windows/hierarchy.rs` change exists.

- [ ] **Step 5: Commit and deliver the evidence pack.**

```sh
git add crates/cmtraceopen-parser docs/superpowers/plans/2026-08-04-sccm-481-hierarchy-source-contracts.md
git commit -m "test(sccm): pin observed hierarchy source coverage"
git diff --name-only 8064b5aa1457f72ea8dbb7cb979ec3ea863c524c..HEAD
git show --check --oneline HEAD
git status --porcelain
```

The handoff must name exact SHA, changed files, test counts/results, wasm32/Clippy/fmt/diff results, fixture provenance, and every still-unproven semantic. Do not merge; independent review follows.

## Self-review

- Spec coverage: catalog, version/profile admission, topology, direction, provenance, keys, rotation, coverage states, supplement boundary, privacy, and determinism map to Tasks 1–5.
- Evidence fidelity: the plan declares only `rcmctrl.lo_`, makes direction/topology/keys explicit gaps for the single-site lab, and never treats SQL/thread metadata as keys.
- Placeholder scan: every error/privacy/boundary state has a test and implementation step.
- Type consistency: one hierarchy subcatalog and one optional hierarchy admission projection extend the existing canonical intake; no parallel manifest or reducer is added.
- Scope: no native discovery, database collection, semantic transactions, causal joins, or compatibility fallback.
