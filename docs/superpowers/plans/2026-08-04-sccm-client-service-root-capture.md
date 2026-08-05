# SCCM Client Service-Root Capture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Capture evidence for #483–#485 from the exact client log root beside a validated `CcmExec.exe`, without exposing paths or weakening catalog/cap/reparse controls.

**Architecture:** Extend the existing fixed Win32 service query to return only `Name` and `PathName`. Parse one exact `CcmExec` record, validate a drive-qualified `CcmExec.exe`, derive its sibling `Logs` directory privately, and feed that root into the unchanged native collector and manifest pipeline.

**Tech Stack:** Rust, Serde JSON, Tauri native SCCM collector, existing manifest/contract tests, Windows lab validation.

**Frozen base:** `8064b5aa1457f72ea8dbb7cb979ec3ea863c524c`

---

### Task 1: Parse the exact CcmExec service path

**Files:**
- Modify: `src-tauri/src/sccm/collector/discovery.rs`

- [ ] **Step 1: Add red unit tests**

Add:

- `ccmexec_service_path_derives_one_sibling_logs_root`
- `ccmexec_service_path_accepts_quotes_and_trailing_arguments`
- `ccmexec_service_path_rejects_wrapper_relative_unc_and_wrong_basename`
- `missing_legacy_windir_root_is_not_selected`
- `fixed_cim_query_selects_only_exact_service_name_and_path`
- `serialized_discovery_never_contains_service_path`
- `ccmexec_role_is_retained_when_service_root_is_absent`

Representative input/output:

```rust
let json = br#"{"Name":"CcmExec","PathName":"\"C:\\Program Files\\SMS_CCM\\CcmExec.exe\" -service"}"#;
let root = client_root_from_service_output(json).expect("validated root");
assert_eq!(root, PathBuf::from(r"C:\Program Files\SMS_CCM\Logs"));
```

- [ ] **Step 2: Run the red tests**

```sh
cargo test --locked -p cmtrace-open discovery::tests::ccmexec_service_path_derives_one_sibling_logs_root
cargo test --locked -p cmtrace-open discovery::tests::missing_legacy_windir_root_is_not_selected
```

- [ ] **Step 3: Extend the fixed query and add a private parser**

The PowerShell query remains fixed and non-interpolated:

```rust
const FIXED_ROLE_QUERY: &str = "$ErrorActionPreference='Stop'; Get-CimInstance -Namespace 'root/cimv2' -ClassName 'Win32_Service' -Filter \"Name='CcmExec' OR Name='SMS_EXECUTIVE' OR Name='SMS_ADMIN_SERVICE' OR Name='WSUSService'\" | Select-Object Name,PathName | ConvertTo-Json -Compress";
```

Use a deny-unknown-fields record and object-or-array wire shape:

```rust
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct CimServiceFact {
    name: String,
    path_name: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum CimServiceFacts {
    One(CimServiceFact),
    Many(Vec<CimServiceFact>),
}
```

The private path parser must:

- admit only exact case-sensitive service `Name == "CcmExec"`;
- parse quoted executable paths and ignore only trailing arguments after the closing quote;
- parse an unquoted drive-qualified path only through the first case-insensitive `.exe` boundary;
- require `[A-Za-z]:\` absolute form and exact case-insensitive basename `CcmExec.exe`;
- reject UNC, relative, empty, wrapper, alternate-basename, control-bearing, forward-slash, repeated-separator, `.`/`..`, alternate data stream, and ambiguous forms;
- derive exactly the executable parent plus `Logs`;
- never return or serialize the raw `PathName` outside the private discovery structure.

Use explicit string validation so tests behave identically on macOS and Windows; do not rely on host-platform `Path::components()` to interpret a Windows path.

- [ ] **Step 4: Re-run and commit**

```sh
cargo test --locked -p cmtrace-open discovery::tests
git add src-tauri/src/sccm/collector/discovery.rs
git commit -m "fix(sccm): derive client root from CcmExec"
```

### Task 2: Use one private derived root and remove the fixed fallback

**Files:**
- Modify: `src-tauri/src/sccm/collector/discovery.rs`
- Test: `src-tauri/tests/sccm_native_collection.rs`

- [ ] **Step 1: Add red integration tests**

Add:

- `derived_client_root_emits_absent_rows_for_all_required_sources`
- `client_capture_accepts_only_required_exact_basenames_and_rotations`
- `client_manifest_contains_hashes_caps_and_opaque_provenance`
- `client_capture_rejects_symlink_or_reparse_evidence`
- `mtrmgr_is_not_admitted_without_catalog_evidence`

- [ ] **Step 2: Run the focused red tests**

```sh
cargo test --locked -p cmtrace-open --test sccm_native_collection
```

- [ ] **Step 3: Wire the derived root into existing discovery**

Remove the registry branch’s unconditional `%WINDIR%\CCM\Logs` insertion and remove `client_log_root()`. Registry may establish the Client role/version, while the exact service fact establishes the only private client root. A valid nonexistent derived root remains in the private environment so the existing engine emits explicit `Absent` rows. Unsafe/malformed `PathName` retains the Client role but supplies no root.

Keep `engine.rs`, `client_manifest.rs`, `contract.rs`, and `commands/sccm.rs` behavior unchanged. Reuse direct enumeration, exact catalog membership, rotation checks, no-follow/reparse defenses, `MAX_FRAGMENTS_PER_SOURCE = 8`, `MAX_BYTES_PER_SOURCE = 16 * 1024 * 1024`, opaque handles, content hashes, and post-write manifest validation.

Do not add `mtrmgr.log`: no reviewed observation exists. Keep `StateMessage.log` in its existing `client-policy-state` capture membership.

- [ ] **Step 4: Re-run and commit**

```sh
cargo test --locked -p cmtrace-open --test sccm_native_collection
git add src-tauri/src/sccm/collector/discovery.rs src-tauri/tests/sccm_native_collection.rs
git commit -m "test(sccm): pin service-root client capture"
```

### Task 3: Run security, parser, and platform gates

**Files:**
- Test only; no new upload implementation

- [ ] **Step 1: Verify exact-name and privacy behavior**

The public discovery/result/manifest must contain neither the raw service path nor `C:\Program Files\SMS_CCM` nor `C:\Windows\CCM\Logs`. Only exact catalog basenames/rotations are eligible. Unknown/lookalike/temp files remain skipped/unsupported according to the existing engine.

- [ ] **Step 2: Run all local gates**

```sh
cargo fmt --check --all
cargo test --locked -p cmtrace-open --test sccm_native_collection
cargo test --locked -p cmtrace-open --test sccm_client_discovery
cargo test --locked -p cmtraceopen-parser --test sccm_spine_contract
cargo test --locked -p cmtraceopen-parser --test sccm_client_inventory_compliance_metering_fixture_contract
cargo clippy --locked -p cmtrace-open --all-targets --all-features -- -D warnings
git diff --check
```

If `sccm_client_discovery` is not a standalone test target, run the exact discovery unit suite instead and record the correction. Pester is required only if an existing collection script changes; this plan makes no script change.

- [ ] **Step 3: Commit any test-only corrections and prepare the evidence pack**

```sh
git diff --name-only 8064b5aa1457f72ea8dbb7cb979ec3ea863c524c..HEAD
git show --check --oneline HEAD
git status --porcelain
```

The handoff must include exact SHA, changed files, test counts/results, strict Clippy/fmt/diff results, clean status, and the Windows reproduction below. Do not merge; independent review follows.

### Task 4: Validate on the authorized Windows lab

**Files:**
- No repository file changes; evidence goes only to the retained draft-release channel

- [ ] **Step 1: Verify the service fact**

```powershell
Get-CimInstance -Namespace root/cimv2 -ClassName Win32_Service -Filter "Name='CcmExec'" |
  Select-Object Name,PathName |
  ConvertTo-Json -Compress
```

Expected: exact `CcmExec` and an executable rooted at `C:\Program Files\SMS_CCM\CcmExec.exe`.

- [ ] **Step 2: Run a negative capture** with a valid but nonexistent sibling `Logs` directory. Every admitted client source must be `Absent`, with zero retained bytes and no raw root.
- [ ] **Step 3: Run a positive capture** against the actual sibling `Logs` directory. Verify exact catalog IDs, rotations, byte counts, SHA-256, fragment/cap metadata, safe relative paths, and absence of raw roots. `mtrmgr.log` remains unadmitted.
- [ ] **Step 4: Exercise caps and unsafe evidence** using lab-safe fixtures: over 16 MiB, more than eight rotations, lookalikes, unsupported rotations, ACL denial, and reparse entries. Verify bounded coverage states.
- [ ] **Step 5: Package only the validated local bundle** and upload through the already-approved draft-release HTTPS/SAS path. SAS is transient, query data is redacted, upload failure retains the local bundle, and no raw evidence/URL/credential enters git or issue comments.

## Self-review

- Spec coverage: exact service/root derivation, one-root policy, catalog-only admission, caps, hashes, privacy, unsafe paths, absent/present captures, and Windows reproduction are explicit.
- Placeholder scan: every validation and edge condition has a concrete test or lab step.
- Type consistency: one private service fact feeds the existing `SccmCaptureRoot`; no new public path type or alternate collector exists.
- Scope: no free-form override, PowerShell recapture, upload backend, parser/analyzer change, `mtrmgr.log` promotion, raw repo artifact, or compatibility fallback.
