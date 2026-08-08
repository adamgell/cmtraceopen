# SCCM Native Product Path Rework Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship SCCM diagnostics as an executable Windows product path that discovers installed client/server roles, creates bounded privacy-safe bundles, and exposes coverage outcomes in a dedicated application workspace.

**Architecture:** Keep semantic analysis in `cmtraceopen-parser`; add a feature-gated native collector under `src-tauri/src/sccm/collector` with an injectable discovery provider and one collision-safe capture engine. Tauri commands expose only discovery and capture summaries—never raw registry data, hostnames, site codes, or source paths—and the React workspace presents the returned roles, source states, and retained bundle location.

**Tech Stack:** Rust 1.88+, Tauri v2, `winreg`, Windows PowerShell/CIM with a fixed read-only query, serde/serde_json, React 19, TypeScript, Zustand, Fluent UI

---

## File structure

- `src-tauri/src/sccm/collector/mod.rs`: public collector entry points and shared request/result wire types.
- `src-tauri/src/sccm/collector/discovery.rs`: injectable discovery provider plus the Windows registry/CIM implementation.
- `src-tauri/src/sccm/collector/engine.rs`: allow-listed enumeration, rotation classification, bounds, no-overwrite copy, and coverage rows.
- `src-tauri/src/sccm/collector/client_manifest.rs`: existing schema-v1 client manifest construction and validation.
- `src-tauri/src/sccm/collector/server_manifest.rs`: canonical server manifest JSON construction and parser-side validation.
- `src-tauri/src/commands/sccm.rs`: Tauri command boundary and app-cache destination selection.
- `src-tauri/tests/sccm_native_collection.rs`: fake-provider discovery/capture contract suite.
- `src/workspaces/sccm/`: one Windows workspace, store, wire types, styles, and component tests.

### Task 1: Put SCCM diagnostics in the shipped feature graph

**Files:**
- Modify: `src-tauri/Cargo.toml`
- Modify: `src-tauri/src/commands/mod.rs`
- Modify: `src-tauri/src/lib.rs`
- Modify: `src-tauri/src/commands/app_config.rs`

- [ ] **Step 1: Write availability and registration tests**

Add assertions that a default/full build contains `sccm`, and that the invoke handler contains both SCCM commands:

```rust
#[test]
fn sccm_workspace_availability_matches_the_build_feature() {
    assert_eq!(
        get_available_workspaces().contains(&"sccm"),
        cfg!(feature = "sccm-diagnostics")
    );
}
```

- [ ] **Step 2: Run the focused test red**

Run: `cargo test --locked -p cmtrace-open commands::app_config::tests::sccm_workspace_availability_matches_the_build_feature --features sccm-diagnostics`

Expected: FAIL because `sccm` is not returned or registered.

- [ ] **Step 3: Wire the feature and command module**

Set `full` to include `sccm-diagnostics`, declare `commands::sccm`, and register these commands behind the same feature:

```rust
commands::sccm::discover_sccm_environment,
commands::sccm::capture_sccm_diagnostics,
```

- [ ] **Step 4: Re-run the focused test**

Run: `cargo test --locked -p cmtrace-open commands::app_config::tests::sccm_workspace_availability_matches_the_build_feature --features sccm-diagnostics`

Expected: PASS.

### Task 2: Define the privacy-safe native command contract

**Files:**
- Create: `src-tauri/src/sccm/collector/mod.rs`
- Modify: `src-tauri/src/sccm/mod.rs`
- Test: `src-tauri/tests/sccm_native_collection.rs`

- [ ] **Step 1: Write serialization tests for the public result**

Use these wire types and verify serialized JSON contains no raw discovery facts:

```rust
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmEnvironmentDiscovery {
    pub supported: bool,
    pub configmgr_version: Option<String>,
    pub roles: Vec<SccmDetectedRole>,
    pub sources: Vec<SccmSourceStatus>,
    pub issues: Vec<SccmDiscoveryIssue>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmCaptureResult {
    pub bundle_root: String,
    pub captured_at_utc: String,
    pub roles: Vec<SccmRole>,
    pub sources: Vec<SccmSourceStatus>,
    pub artifact_count: usize,
    pub retained_bytes: u64,
}
```

`SccmDetectedRole` carries only `role` and an enum discovery basis; `SccmSourceStatus` carries role, source ID, rotation category, coverage state, retained bytes, and optional generic detail code. Raw host, site code, registry values, source roots, and source filenames outside the allow-listed catalog are private collector fields.

- [ ] **Step 2: Run the new target red**

Run: `cargo test --locked -p cmtrace-open --test sccm_native_collection --features sccm-diagnostics`

Expected: FAIL on missing collector types.

- [ ] **Step 3: Implement the wire contract and deterministic sorting**

Sort roles by canonical serialized role name and source rows by `(role, source_id, rotation, state)`. Serialize a fixture containing sentinel host/path/site values and assert none are present.

- [ ] **Step 4: Run the contract test green**

Run: `cargo test --locked -p cmtrace-open --test sccm_native_collection public_result --features sccm-diagnostics`

Expected: PASS.

### Task 3: Implement read-only Windows role and root discovery

**Files:**
- Create: `src-tauri/src/sccm/collector/discovery.rs`
- Test: `src-tauri/tests/sccm_native_collection.rs`

- [ ] **Step 1: Write fake-provider discovery tests**

Define the test seam:

```rust
pub(crate) trait SccmDiscoveryProvider {
    fn discover(&self) -> Result<PrivateSccmEnvironment, SccmDiscoveryFailure>;
}
```

Tests must prove: client service/registry evidence produces only `Client`; each explicit server-role fact produces only its corresponding role; default folders alone never produce roles; denied registry/CIM reads become an issue; duplicate roots collapse by canonical identity; and output order is stable.

- [ ] **Step 2: Run discovery tests red**

Run: `cargo test --locked -p cmtrace-open --test sccm_native_collection discovery_ --features sccm-diagnostics`

Expected: FAIL on the missing provider.

- [ ] **Step 3: Implement the Windows provider**

On Windows, read only allow-listed ConfigMgr registry keys and run a fixed non-interactive PowerShell/CIM query when server-role facts require it. Do not interpolate user input. Use registry/service facts to prove the client and site-system roles; use defaults only to add candidate roots after a role is observed. Keep raw site code, host, paths, and CIM payload private and derive only HMAC/SHA-256 opaque handles for manifests.

On non-Windows platforms return `supported: false` with the generic `unsupportedPlatform` issue.

- [ ] **Step 4: Run cross-platform and Windows compile gates**

Run:

```bash
cargo test --locked -p cmtrace-open --test sccm_native_collection discovery_ --features sccm-diagnostics
cargo check --locked -p cmtrace-open --features sccm-diagnostics
```

Expected: PASS locally; the Windows implementation is exercised by hosted Windows CI.

### Task 4: Implement one bounded collision-safe capture engine

**Files:**
- Create: `src-tauri/src/sccm/collector/engine.rs`
- Create: `src-tauri/src/sccm/collector/client_manifest.rs`
- Create: `src-tauri/src/sccm/collector/server_manifest.rs`
- Test: `src-tauri/tests/sccm_native_collection.rs`

- [ ] **Step 1: Write capture-engine failures first**

Fake-root tests must cover current, `.lo_`, numbered, and timestamped rotations; absent/access-denied/capped/skipped/unsupported rows; malformed rotation names; per-source file and byte caps; symlink/reparse escape; duplicate destination preflight; pre-existing destination no-overwrite; deterministic output; and two roots with the same basename remaining distinct.

- [ ] **Step 2: Run the capture matrix red**

Run: `cargo test --locked -p cmtrace-open --test sccm_native_collection capture_ --features sccm-diagnostics`

Expected: FAIL on the missing engine.

- [ ] **Step 3: Implement bounded enumeration and copying**

Use fixed production caps of 8 fragments and 16 MiB per logical source. Canonicalize the approved root, reject any candidate outside it, reject reparse/symlink files, preflight all bundle-relative destinations, then create each destination with create-new semantics. Hash and count the exact retained bytes; a truncated prefix is `Capped`, never `Captured`.

- [ ] **Step 4: Write and validate both manifests**

Client capture writes `sccm-manifest.json` using `SccmBundleManifestV1`, then reopens it with `read_sccm_client_intake_bundle`. Server capture writes `sccm-server-manifest.json` with `bundleRole: "server"`, opaque topology handles, canonical role/source/rotation provenance, and no raw paths, then validates the JSON and payloads with `normalize_server_bundle` before returning success.

- [ ] **Step 5: Run the full native target**

Run: `cargo test --locked -p cmtrace-open --test sccm_native_collection --features sccm-diagnostics`

Expected: PASS.

### Task 5: Expose discovery and capture through Tauri

**Files:**
- Create: `src-tauri/src/commands/sccm.rs`
- Modify: `src-tauri/src/lib.rs`
- Test: `src-tauri/src/commands/sccm.rs`

- [ ] **Step 1: Write command-level tests**

Test the non-Tauri implementation functions with a fake provider and temporary app-cache root. Assert discovery performs no writes; capture creates a UUID-named private bundle below the supplied cache root; and command errors contain only generic codes/details.

- [ ] **Step 2: Implement commands**

```rust
#[tauri::command]
pub fn discover_sccm_environment() -> Result<SccmEnvironmentDiscovery, AppError>;

#[tauri::command]
pub fn capture_sccm_diagnostics(
    app: tauri::AppHandle,
) -> Result<SccmCaptureResult, AppError>;
```

The capture command selects the app cache directory itself. It accepts no source path, role claim, host, site, or cap from the frontend.

- [ ] **Step 3: Run command and registration tests**

Run: `cargo test --locked -p cmtrace-open commands::sccm --features sccm-diagnostics`

Expected: PASS.

### Task 6: Add the Windows SCCM workspace

**Files:**
- Create: `src/workspaces/sccm/index.ts`
- Create: `src/workspaces/sccm/types.ts`
- Create: `src/workspaces/sccm/sccm-store.ts`
- Create: `src/workspaces/sccm/SccmWorkspace.tsx`
- Create: `src/workspaces/sccm/sccm-workspace.css`
- Create: `src/workspaces/sccm/SccmWorkspace.test.tsx`
- Modify: `src/workspaces/registry.ts`
- Modify: `src/workspaces/registry.test.ts`
- Modify: `src/types/log.ts`
- Modify: `src/lib/commands.ts`

- [ ] **Step 1: Write registry, store, and component tests**

Assert `sccm` is Windows-only; initial render offers read-only discovery; discovered roles and every source state render; capture is disabled during work; errors preserve the previous discovery; and a successful capture displays retained artifact/byte counts plus a reveal action.

- [ ] **Step 2: Run the frontend tests red**

Run: `npx vitest run src/workspaces/registry.test.ts src/workspaces/sccm/SccmWorkspace.test.tsx`

Expected: FAIL because the workspace does not exist.

- [ ] **Step 3: Implement the workspace**

Use an industrial/utilitarian evidence-console treatment within existing Fluent tokens: a narrow status header, role chips, one primary `Capture diagnostic bundle` action, and a dense source ledger with columns Source, Role, Rotation, State, and Retained. Access-denied/capped/malformed/unsupported states must remain text labels with icons/colors as secondary cues, not color-only signals.

- [ ] **Step 4: Run frontend gates**

Run:

```bash
npx vitest run src/workspaces/registry.test.ts src/workspaces/sccm/SccmWorkspace.test.tsx
npx tsc --noEmit
```

Expected: PASS.

### Task 7: Freeze, review, publish, and repeat the lab

**Files:**
- Modify: `.github/workflows/ci.yml` only if the existing Windows all-target gate does not exercise the new feature target
- Modify: PR #490 evidence comment

- [ ] **Step 1: Run the complete local gate**

Run:

```bash
cargo test --locked --workspace --all-targets --quiet
cargo clippy --locked -p cmtrace-open --all-targets --all-features -- -D warnings
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
npx vitest run src/workspaces/registry.test.ts src/workspaces/sccm/SccmWorkspace.test.tsx
npx tsc --noEmit
git diff --check
```

Expected: PASS, with only the documented inherited repo-wide formatting baseline excluded.

- [ ] **Step 2: Obtain independent review on a frozen SHA**

The critic receives the exact SHA, file list, native/frontend test commands, privacy sentinel test, and reproduction steps. Rework until the verdict is `ACCEPT`.

- [ ] **Step 3: Publish and wait for hosted Windows artifacts**

Push PR #490, require every hosted job to pass, and verify the new Windows provenance file names the frozen SHA.

- [ ] **Step 4: Repeat the authorized lab matrix**

The lab must install the new artifact, invoke the SCCM workspace, exercise discovery/capture for every installed role, and post `SCCM-LAB-RESULT: PASS` or `REWORK`. Merge remains prohibited until PASS is independently reviewed.
