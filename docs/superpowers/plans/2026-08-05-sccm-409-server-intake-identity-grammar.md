# SCCM #409 Server Intake Identity Grammar Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove fixture-specific server-intake identity allowlists while keeping synthetic and production manifests privacy-safe and fail-closed.

**Architecture:** Keep declared source IDs owned by the server source catalog, rather than duplicating them in intake. Replace every synthetic fixture identity list in intake with small field-specific closed grammars: structural synthetic artifact/lineage/path tokens, synthetic host/subject handles, and SCCM-shaped synthetic topology. Production remains opaque-handle-only; malformed or identity-bearing strings remain rejected before public projection.

**Tech Stack:** Rust, Serde, existing `cmtraceopen-parser` SCCM server catalog/intake modules, Cargo tests, Clippy, rustfmt.

---

## File structure

- `crates/cmtraceopen-parser/src/sccm/server/windows/catalog.rs` owns declared server source-ID membership.
- `crates/cmtraceopen-parser/src/sccm/server/windows/intake.rs` owns generic synthetic/opaque identity validation and topology normalization.
- `crates/cmtraceopen-parser/tests/sccm_server_intake.rs` proves generic synthetic acceptance plus rejection of malformed and identity-bearing values.

### Task 1: Prove generic synthetic identities and privacy rejection

**Files:**
- Modify: `crates/cmtraceopen-parser/tests/sccm_server_intake.rs`

- [ ] **Step 1: Add failing acceptance and rejection cases**

Add one test that mutates a committed synthetic manifest with a new conforming artifact ID, lineage, path fingerprint, producer host, workflow subject, and SCCM-shaped topology; `assess_server_intake` must succeed. Add table-driven mutations that must return `InvalidTopology` or `InvalidArtifact`: bare/user-like identifiers, malformed token separators, non-three-character site code, topology host without a typed two-digit suffix, and malformed synthetic handles.

```rust
assert!(assess_server_intake(&serialize_manifest(&manifest), &payloads).is_ok());
assert_eq!(
    assess_server_intake(&serialize_manifest(&malformed), &payloads),
    Err(SccmServerIntakeError::InvalidArtifact)
);
```

- [ ] **Step 2: Run the red test**

Run: `cargo test -p cmtraceopen-parser --test sccm_server_intake server_intake_accepts_new_conforming_synthetic_identities`

Expected: FAIL while literal fixture allowlists reject the new conforming values.

### Task 2: Make the catalog the sole owner of declared source IDs

**Files:**
- Modify: `crates/cmtraceopen-parser/src/sccm/server/windows/catalog.rs`
- Modify: `crates/cmtraceopen-parser/src/sccm/server/windows/intake.rs`
- Test: `crates/cmtraceopen-parser/tests/sccm_server_intake.rs`

- [ ] **Step 1: Add catalog membership helper**

Expose a crate-visible helper that recognizes a source ID in `SERVER_SOURCE_SPECS` or `SERVER_STRUCTURED_SUPPLEMENT_SPEC`; do not restate source strings in intake.

```rust
pub(crate) fn is_declared_server_source_id(source_id: &str) -> bool {
    SERVER_SOURCE_SPECS
        .iter()
        .chain(std::iter::once(&SERVER_STRUCTURED_SUPPLEMENT_SPEC))
        .any(|spec| spec.source_id == source_id)
}
```

- [ ] **Step 2: Replace the intake source literal match**

Make `safe_source_id` call that helper for known IDs and preserve its current opaque-future allowance only for non-synthetic retained-unknown artifacts.

```rust
is_declared_server_source_id(value)
    || (allow_unknown
        && !synthetic_fixture
        && opaque_sha256_handle(value, "cmtraceopen.source.sha256.v1:"))
```

- [ ] **Step 3: Run the focused test**

Run: `cargo test -p cmtraceopen-parser --test sccm_server_intake`

Expected: PASS; catalogued sources, opaque future sources, and untrusted sources retain their existing outcomes.

### Task 3: Replace synthetic fixture allowlists with closed grammars

**Files:**
- Modify: `crates/cmtraceopen-parser/src/sccm/server/windows/intake.rs`
- Test: `crates/cmtraceopen-parser/tests/sccm_server_intake.rs`

- [ ] **Step 1: Delete fixture-derived constants and literal matches**

Remove `SYNTHETIC_HIERARCHY_*` constants and the literal sets in `safe_manifest_artifact_id`, `safe_lineage_id`, `safe_path_fingerprint`, `safe_optional_handle`, `normalize_topology`, and `normalize_hierarchy_link`.

- [ ] **Step 2: Add bounded field grammars**

Implement small ASCII validators with no fixture values:

```rust
fn synthetic_slug(value: &str) -> bool {
    (3..=128).contains(&value.len())
        && value.contains('-')
        && !value.starts_with('-')
        && !value.ends_with('-')
        && !value.contains("--")
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
        })
}

fn synthetic_handle(value: &str, domain: &str) -> bool {
    value
        .strip_prefix(&format!("synthetic:{domain}:"))
        .is_some_and(synthetic_numbered_slug)
}

fn synthetic_site_code(value: &str) -> bool {
    value.len() == 3 && value.bytes().all(|byte| byte.is_ascii_uppercase())
}

fn synthetic_capture_host(value: &str) -> bool {
    let Some((site, role_and_ordinal)) = value.split_once('-') else {
        return false;
    };
    if role_and_ordinal.len() < 3 {
        return false;
    }
    let (role, ordinal) = role_and_ordinal.split_at(role_and_ordinal.len() - 2);
    synthetic_site_code(site)
        && matches!(role, "CM" | "MP" | "DP" | "SUP" | "PROVIDER" | "ADMIN")
        && ordinal.bytes().all(|byte| byte.is_ascii_digit())
}
```

Use them for the identity-bearing fields and links. Keep `safe_original_path_marker`, opaque SHA-256 production handles, canonical role/source classification, payload binding, and path-collision checks unchanged.

- [ ] **Step 3: Run focused tests**

Run: `cargo test -p cmtraceopen-parser --test sccm_server_intake`

Expected: PASS, including accepted generic synthetic values and rejected privacy/malformed mutations.

### Task 4: Freeze the regression boundary

**Files:**
- Modify: `crates/cmtraceopen-parser/src/sccm/server/windows/catalog.rs`
- Modify: `crates/cmtraceopen-parser/src/sccm/server/windows/intake.rs`
- Modify: `crates/cmtraceopen-parser/tests/sccm_server_intake.rs`
- Modify: `docs/superpowers/plans/2026-08-05-sccm-409-server-intake-identity-grammar.md`
- Modify: `library.md`

- [ ] **Step 1: Format and run targeted verification**

Run:

```bash
rustfmt --check crates/cmtraceopen-parser/src/sccm/server/windows/catalog.rs crates/cmtraceopen-parser/src/sccm/server/windows/intake.rs crates/cmtraceopen-parser/tests/sccm_server_intake.rs
cargo test -p cmtraceopen-parser --test sccm_server_intake
cargo test -p cmtraceopen-parser
cargo clippy -p cmtraceopen-parser --all-targets -- -D warnings
git diff --check origin/main...HEAD
```

Expected: every command exits zero.

- [ ] **Step 2: Commit the isolated change**

```bash
git add library.md docs/superpowers/plans/2026-08-05-sccm-409-server-intake-identity-grammar.md crates/cmtraceopen-parser/src/sccm/server/windows/catalog.rs crates/cmtraceopen-parser/src/sccm/server/windows/intake.rs crates/cmtraceopen-parser/tests/sccm_server_intake.rs
git commit -m "fix(sccm): remove fixture identity allowlists from intake"
```

## Self-review

- Spec coverage: catalog source IDs, synthetic topology/artifact/lineage/path/handles, production opaque identities, and malformed/identity-bearing rejection each have a task and test.
- Placeholder scan: no deferred behavior or compatibility path is proposed.
- Type consistency: the catalog helper returns a boolean source-membership answer; intake remains the only identity validator and public schema is unchanged.
