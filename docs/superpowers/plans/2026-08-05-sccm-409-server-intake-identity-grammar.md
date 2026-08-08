# SCCM #409 Server Intake Identity Grammar Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove fixture-specific server-intake identity allowlists while keeping synthetic and production manifests privacy-safe and fail-closed.

**Architecture:** Keep declared source IDs owned by the server source catalog, rather than duplicating them in intake. Synthetic artifact, lineage, path, host, and subject identities use a domain-bound `synthetic:<domain>:sha256.v1:<64 lowercase hex>` contract, so fixture labels cannot become public identities. Synthetic topology uses three-character uppercase site codes and SCCM role hosts such as `LAB-CM01`; the host validator proves ASCII and binds the host site to the declared site before parsing its role/ordinal. Production remains opaque-handle-only. Malformed, Unicode, or identity-bearing strings are rejected before public projection.

**Tech Stack:** Rust, Serde, existing `cmtraceopen-parser` SCCM server catalog/intake modules, Cargo tests, Clippy, rustfmt.

---

## File structure

- `crates/cmtraceopen-parser/src/sccm/server/windows/catalog.rs` owns declared server source-ID membership.
- `crates/cmtraceopen-parser/src/sccm/server/windows/intake.rs` owns generic synthetic/opaque identity validation and topology normalization.
- `crates/cmtraceopen-parser/src/sccm/server/windows/hierarchy.rs` binds the synthetic hierarchy profile to reviewed payload digests rather than fixture artifact IDs.
- `crates/cmtraceopen-parser/src/sccm/server/windows/management_point.rs` accepts the new opaque synthetic host namespace without a fixture-host literal.
- `crates/cmtraceopen-parser/tests/sccm_server_intake.rs` proves generic synthetic acceptance plus rejection of malformed and identity-bearing values.
- `crates/cmtraceopen-parser/tests/sccm_hierarchy_reducer.rs` proves the opaque fixture identities survive the downstream semantic adapter.

### Task 1: Prove generic synthetic identities and privacy rejection

**Files:**
- Modify: `crates/cmtraceopen-parser/tests/sccm_server_intake.rs`

- [x] **Step 1: Add failing acceptance and rejection cases**

Add one test that mutates a committed synthetic manifest with a new conforming artifact ID, lineage, path fingerprint, producer host, workflow subject, and SCCM-shaped topology; `assess_server_intake` must succeed. Add table-driven mutations that must return `InvalidTopology` or `InvalidArtifact`: bare/user-like identifiers, malformed token separators, non-three-character site code, topology host without a typed two-digit suffix, and malformed synthetic handles.

```rust
assert!(assess_server_intake(&serialize_manifest(&manifest), &payloads).is_ok());
assert_eq!(
    assess_server_intake(&serialize_manifest(&malformed), &payloads),
    Err(SccmServerIntakeError::InvalidArtifact)
);
```

- [x] **Step 2: Run the red test**

Run: `cargo test -p cmtraceopen-parser --test sccm_server_intake server_intake_accepts_new_conforming_synthetic_identities`

Expected: FAIL while literal fixture allowlists reject the new conforming values.

### Task 2: Make the catalog the sole owner of declared source IDs

**Files:**
- Modify: `crates/cmtraceopen-parser/src/sccm/server/windows/catalog.rs`
- Modify: `crates/cmtraceopen-parser/src/sccm/server/windows/intake.rs`
- Test: `crates/cmtraceopen-parser/tests/sccm_server_intake.rs`

- [x] **Step 1: Add catalog membership helper**

Expose a crate-visible helper that recognizes a source ID in `SERVER_SOURCE_SPECS` or `SERVER_STRUCTURED_SUPPLEMENT_SPEC`; do not restate source strings in intake.

```rust
pub(crate) fn is_declared_server_source_id(source_id: &str) -> bool {
    SERVER_SOURCE_SPECS
        .iter()
        .chain(std::iter::once(&SERVER_STRUCTURED_SUPPLEMENT_SPEC))
        .any(|spec| spec.source_id == source_id)
}
```

- [x] **Step 2: Replace the intake source literal match**

Make `safe_source_id` call that helper for known IDs and preserve its current opaque-future allowance only for non-synthetic retained-unknown artifacts.

```rust
is_declared_server_source_id(value)
    || (allow_unknown
        && !synthetic_fixture
        && opaque_sha256_handle(value, "cmtraceopen.source.sha256.v1:"))
```

- [x] **Step 3: Run the focused test**

Run: `cargo test -p cmtraceopen-parser --test sccm_server_intake`

Expected: PASS; catalogued sources, opaque future sources, and untrusted sources retain their existing outcomes.

### Task 3: Replace synthetic fixture allowlists with closed grammars

**Files:**
- Modify: `crates/cmtraceopen-parser/src/sccm/server/windows/intake.rs`
- Test: `crates/cmtraceopen-parser/tests/sccm_server_intake.rs`

- [x] **Step 1: Delete fixture-derived constants and literal matches**

Remove `SYNTHETIC_HIERARCHY_*` constants and the literal sets in `safe_manifest_artifact_id`, `safe_lineage_id`, `safe_path_fingerprint`, `safe_optional_handle`, `normalize_topology`, and `normalize_hierarchy_link`.

- [x] **Step 2: Add bounded field grammars**

Implement small ASCII validators with no fixture values. Identity-bearing surfaces accept only domain-bound synthetic SHA-256 tokens; topology is limited to a structural site/role/ordinal grammar and validates ASCII before any byte-sensitive operation.

```rust
fn synthetic_identity(value: &str, domain: &str) -> bool {
    value
        .strip_prefix("synthetic:")
        .and_then(|value| value.split_once(":sha256.v1:"))
        .is_some_and(|(actual_domain, digest)| {
            actual_domain == domain
                && digest.len() == 64
                && digest.bytes().all(|byte| {
                    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
                })
        })
}
```

Use them for the identity-bearing fields and links. Keep `safe_original_path_marker`, opaque SHA-256 production handles, canonical role/source classification, payload binding, and path-collision checks unchanged.

Migrate committed intake identities and downstream canonical-intake builders to the same contract. Bind the reviewed hierarchy profile to payload digests only, so a new conforming fixture identity does not require a production allowlist edit.

- [x] **Step 3: Run focused tests**

Run: `cargo test -p cmtraceopen-parser --test sccm_server_intake`

Expected: PASS (66 tests), including accepted generic synthetic values, the four critic reproductions, and rejected Unicode/malformed mutations without panics.

### Task 4: Freeze the regression boundary

**Files:**
- Modify: `crates/cmtraceopen-parser/src/sccm/server/windows/catalog.rs`
- Modify: `crates/cmtraceopen-parser/src/sccm/server/windows/distribution_point.rs`
- Modify: `crates/cmtraceopen-parser/src/sccm/server/windows/hierarchy.rs`
- Modify: `crates/cmtraceopen-parser/src/sccm/server/windows/intake.rs`
- Modify: `crates/cmtraceopen-parser/src/sccm/server/windows/management_point.rs`
- Modify: `crates/cmtraceopen-parser/src/sccm/server/windows/site_core.rs`
- Modify: `crates/cmtraceopen-parser/tests/sccm_server_intake.rs`
- Modify: downstream canonical-intake builders and exact fixture oracles under `crates/cmtraceopen-parser/tests/`
- Modify: `docs/superpowers/plans/2026-08-05-sccm-409-server-intake-identity-grammar.md`

- [x] **Step 1: Format and run targeted verification**

Run:

```bash
rustfmt --check $(git diff --name-only -- '*.rs')
cargo test -p cmtraceopen-parser --test sccm_server_intake
cargo test -p cmtraceopen-parser --test sccm_hierarchy_reducer
cargo test -p cmtraceopen-parser --test issue_413_unicode_panics
cargo test -p cmtraceopen-parser
cargo clippy -p cmtraceopen-parser --all-targets -- -D warnings
git diff --check origin/main...HEAD
```

Expected: every command exits zero.

- [x] **Step 2: Commit the isolated change**

```bash
git add docs/superpowers/plans/2026-08-05-sccm-409-server-intake-identity-grammar.md crates/cmtraceopen-parser
git commit -m "fix(sccm): seal synthetic intake identities"
```

## Self-review

- Spec coverage: catalog source IDs, synthetic topology/artifact/lineage/path/handles, production opaque identities, and malformed/identity-bearing rejection each have a task and test.
- Placeholder scan: no deferred behavior or compatibility path is proposed.
- Type consistency: the catalog helper returns a boolean source-membership answer; intake remains the only identity validator and public schema is unchanged.
