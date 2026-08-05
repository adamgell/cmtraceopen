# SCCM Advanced Server Capture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add one bounded, capture-only native surface for the six #475–#479 advanced SCCM server log sources, with explicit authorization and provenance, while leaving every source card candidate-only and outside semantic analysis.

**Architecture:** `src-tauri/src/sccm/collector/advanced_capture.rs` owns the six typed capture contracts and is the only advanced-source collector surface. Existing discovery supplies only observed role/root facts; a private, operator-authorized supplemental request supplies an exact card/source/root tuple when discovery cannot prove the role. The engine enumerates only those typed contracts, applies each contract's cap and rotation policy, and writes opaque, redacted server-manifest rows plus raw payloads that remain in the local capture bundle.

**Tech Stack:** Rust 1.88, `cmtrace-open` native Tauri crate, `cmtraceopen-parser` server-manifest validator, serde/serde_json, Windows Registry/CIM discovery, bounded filesystem reads with no-follow/reparse rejection, synthetic fixtures, and an authorized Windows SCCM development deployment.

---

## Frozen scope and non-goals

- Work from base `8064b5aa1457f72ea8dbb7cb979ec3ea863c524c` on branch `codex/sccm-advanced-server-capture` in `.worktrees/sccm-advanced-server-capture`.
- The allowlist is exactly `smspxe.log`, `crp.log`, `srsrp.log`, `CloudMgr.log`, `SMS_Cloud_ProxyConnector.log`, and `BgbServer.log`.
- The six JSON cards under `crates/cmtraceopen-parser/tests/fixtures/sccm/server/advanced_roles/source-cards/` remain `candidate`, `captureGuidanceOnly`, and semantically inert. Do not edit them, promote them, add a reducer, add findings, or add a parser semantic catalog entry.
- Do not infer a producer role, configured root, PXE enablement, or role instance from a basename, default directory, registry path guess, service name analogy, or file presence.
- Do not expose a free-form filesystem path or arbitrary glob in the Tauri/API surface. Do not add a compatibility fallback or legacy collector path.
- Do not commit, print, fixture, or upload raw Windows evidence. The only committed evidence is sanitized test data and metadata contracts.

## Current evidence and decision

The current native collector has one `SccmCaptureRoot { role, path }` per discovered generic role, matches server files through `declared_server_source_catalog()`, uses process-wide `MAX_FRAGMENTS_PER_SOURCE = 8` and `MAX_BYTES_PER_SOURCE = 16 MiB`, and writes server rows with `sourceVersion: null` and `pathClass: null` for non-WSUS sources. That surface cannot safely collect these candidates: none of the six names is in the current parser/server catalog, the discovery model has no advanced-role or PXE-enabled fact, and the current default roots are not proof that an optional role is configured.

The capture matrix is deliberately conservative:

| Source | Card role scope | Existing discovered root sufficient? | Required gate | Capture result before gate |
| --- | --- | --- | --- | --- |
| `smspxe.log` | `distributionPointPxe`, `siteServer` | No. A `DistributionPoint` root does not prove PXE enablement; a `SiteServer` root does not identify the PXE producer. | A discovered PXE-enabled DP fact with configured-path provenance, or an operator-authorized typed request that includes that observed fact and topology binding. | `Unsupported`/`notRequested`; never `Absent` from a generic DP root. |
| `crp.log` | `certificateRegistrationPoint` | No. No current discovery role fact names the certificate registration point. | Typed operator-authorized request or a future observed role fact; the request must state the exact role scope and path class. | `Unsupported`/`notRequested`. |
| `srsrp.log` | `reportingServicesPoint` | No. No current discovery role fact names the reporting services point. | Typed operator-authorized request or a future observed role fact. | `Unsupported`/`notRequested`. |
| `CloudMgr.log` | `cloudManagementGatewayConnectionPoint`, `serviceConnectionPoint` | No. A site-server log root does not prove either configured cloud role. | Typed operator-authorized configured-role request or a future observed role fact. | `Unsupported`/`notRequested`. |
| `SMS_Cloud_ProxyConnector.log` | `cloudManagementGatewayConnectionPoint`, `serviceConnectionPoint` | No; it shares the cloud card but not an implied site-server root. | The same typed configured-role request as `CloudMgr.log`, with the exact basename allowlist. | `Unsupported`/`notRequested`. |
| `BgbServer.log` | `clientNotificationServer`, `managementPoint` | Conditional. An observed `ManagementPoint` role plus an observed/configured MP root is sufficient for a role-bound capture request. A generic site-server root is not. | MP role fact and `configuredRoleLogRoot` or `siteServerLogs` path provenance; otherwise a typed request or future notification-server fact. | `Unsupported`/`notRequested` when the MP binding is absent. |

For all six cards, the current card contract is exact: optional capture, maximum 4 MiB per source, least-privilege/no escalation, rotations `current` and `lo_`, maximum two files, high-sensitivity redaction, no raw sensitive projection, and no time-only correlation. The implementation must keep these limits per typed source contract even though the current six values happen to match; it must not route through the existing global 8-file/16-MiB policy.

## File structure and ownership

**Create:**

- `src-tauri/src/sccm/collector/advanced_capture.rs` — the single owner of typed advanced-source contracts, card/source allowlists, per-source limits, role/path admission, supplemental-request validation, and advanced candidate identity.
- `src-tauri/tests/sccm_advanced_server_capture.rs` — integration coverage for the public native capture result, server manifest, coverage states, opaque handles, and raw-local-only boundary.

**Modify:**

- `src-tauri/src/sccm/collector/mod.rs` — register the one owner module and add private discovery/root provenance plus typed supplemental-request plumbing without exposing arbitrary paths.
- `src-tauri/src/sccm/collector/discovery.rs` — attach observed `pathClass` and observed ConfigMgr version to roots; add only evidence-backed PXE/advanced-role facts, never guessed registry keys or default-root role assertions.
- `src-tauri/src/sccm/collector/engine.rs` — pass discovered roots and authorized supplemental contracts through the one collector surface; preserve deterministic ordering, no-follow/reparse checks, source-specific caps, and explicit coverage rows.
- `src-tauri/src/sccm/collector/server_manifest.rs` — write the advanced card/source identity, producer role claim, source version, path class, rotation lineage, opaque handles, source-specific limits, and redacted privacy projection without hardcoded or guessed metadata.
- `src-tauri/tests/sccm_native_collection.rs` — retain existing generic collector regression coverage and add the shared root/provenance assertions where the existing test helper is the correct owner.
- `crates/cmtraceopen-parser/tests/sccm_server_intake.rs` — add only manifest contract cases required to accept the bounded capture-only rows, including explicitly unrequested/unsupported advanced coverage; do not add semantic admission.

Do not modify the six source-card JSON files, `crates/cmtraceopen-parser/src/sccm/catalog.rs`, or semantic server-role reducers. The parser remains the manifest validation boundary, not the owner of advanced capture policy.

## Typed contract

The implementation owner must encode one immutable contract per source, equivalent to the following Rust shape (names may follow local conventions, but the fields and invariants are required):

```rust
struct AdvancedCaptureContract {
    card_id: &'static str,
    card_version: &'static str,
    source_id: &'static str,
    basenames: &'static [&'static str],
    role_scopes: &'static [&'static str],
    path_classes: &'static [&'static str],
    max_bytes: u64,
    max_files: usize,
    rotations: &'static [AdvancedRotation],
}

struct AuthorizedAdvancedRequest {
    contract: &'static AdvancedCaptureContract,
    declared_role_scope: &'static str,
    root: SccmCaptureRoot,
    authorization_handle: OpaqueAuthorizationHandle,
    observed_source_version: Option<String>,
}
```

The request constructor is private to native discovery/operator code. It must reject a card/source mismatch, a basename outside the immutable allowlist, a role scope outside the card, a path class outside the card, missing authorization, duplicate source/root tuples, numbered or timestamped rotations, and any path that is not a validated root. A request carries a root handle derived from the validated canonical root, but never exports the raw path. A test-only constructor may create deterministic authorized requests from temporary roots; production callers cannot construct one from an arbitrary string.

The existing discovered-root path is admitted only when its observed role and path provenance match a contract. For `BgbServer.log`, that is the MP role binding. A generic root without the required role fact produces `notRequested`/`Unsupported` coverage and is not scanned for the basename. Supplemental requests are additive typed inputs to this same engine, not a second collector.

Every physical or coverage row is keyed by `(cardId, cardVersion, sourceId, producerRoleScope, rootHandle, basename, rotation)`. Preserve `sourceVersion` only from an observed ConfigMgr/source-version fact or the authorized request; otherwise serialize null and retain the coverage limitation. Preserve `pathClass` as `configuredRoleLogRoot`, `reportServerLogs`, or `siteServerLogs` only when observed or explicitly authorized by the request. Never write a guessed version or path class.

## Implementation tasks

### Task 1: Lock the advanced capture contract with red tests

**Files:**

- Create: `src-tauri/src/sccm/collector/advanced_capture.rs`
- Modify: `src-tauri/src/sccm/collector/mod.rs`
- Create: `src-tauri/tests/sccm_advanced_server_capture.rs`

- [ ] **Step 1: Add contract table tests before implementation.** Assert that the owner returns exactly the six basenames, six card/source identities, the card versions, 4 MiB byte cap, two-file cap, and only `current`/`lo_` rotations. Assert that `sql-database-export` and every unlisted basename are rejected.

- [ ] **Step 2: Run the focused red test.**

```bash
cargo test --locked -p cmtrace-open --test sccm_advanced_server_capture --features sccm-diagnostics advanced_contract
```

Expected result: `FAIL` because the advanced owner module and typed contract do not yet exist.

- [ ] **Step 3: Implement the immutable contract table and validation functions.** Keep the table in `advanced_capture.rs`; do not derive capture behavior from a basename or add entries to the parser semantic catalog. Make validation return a typed rejection for card/source/role/path/authorization/rotation violations. Keep unknown roles as explicit operator claims (`SccmRole::Unknown` only when the request states the canonical card scope); never synthesize them from a filename.

- [ ] **Step 4: Re-run the focused contract tests.**

```bash
cargo test --locked -p cmtrace-open --test sccm_advanced_server_capture --features sccm-diagnostics advanced_contract
```

Expected result: `PASS`, with no changes to existing source-card inventory or semantic admission tests.

### Task 2: Preserve observed discovery facts and authorize supplemental roots

**Files:**

- Modify: `src-tauri/src/sccm/collector/mod.rs`
- Modify: `src-tauri/src/sccm/collector/discovery.rs`
- Modify: `src-tauri/src/sccm/collector/advanced_capture.rs`
- Test: `src-tauri/src/sccm/collector/discovery.rs` tests
- Test: `src-tauri/tests/sccm_advanced_server_capture.rs`

- [ ] **Step 1: Add failing admission tests for the decision matrix.** Cover: MP role plus an observed MP root admits `BgbServer.log`; DP role alone rejects `smspxe.log`; site-server root alone rejects all cloud sources; no current role fact admits `crp.log` or `srsrp.log`; a typed authorized request admits only its exact source; an unauthorized, duplicate, mismatched, or arbitrary-path request is rejected.

- [ ] **Step 2: Run the red discovery/admission tests.**

```bash
cargo test --locked -p cmtrace-open --test sccm_advanced_server_capture --features sccm-diagnostics discovery_admission
```

Expected result: `FAIL` on the new typed provenance/request API.

- [ ] **Step 3: Extend private root facts.** Carry `path_class`, observed ConfigMgr/source version, and a root authorization handle alongside `role` and `path`. Mark registry-provided log directories as `configuredRoleLogRoot`; mark a site installation `Logs` fallback as `siteServerLogs` only when the site-server installation fact is observed. Preserve the existing rule that roots without role facts do not admit roles. Do not add guessed registry keys for certificate, reporting, cloud, notification, or PXE roles.

- [ ] **Step 4: Add only observed advanced-role discovery inputs.** The Windows discovery boundary may add a narrowly allowlisted, read-only fact for PXE enablement or an advanced configured-role path when the deployment exposes that fact. If the fact is not observed, leave the source `notRequested`/`Unsupported`. Do not treat `SMS_EXECUTIVE`, a default directory, or the presence of a candidate file as an advanced-role fact.

- [ ] **Step 5: Implement the private operator-authorized request constructor.** Require the contract ID, exact declared role scope, validated root, path class, authorization handle, and optional observed version. Validate all fields against the immutable contract and deduplicate by the complete source/root identity. There is no public arbitrary-path request and no fallback to a legacy collector.

- [ ] **Step 6: Run discovery and existing native regressions.**

```bash
cargo test --locked -p cmtrace-open --test sccm_advanced_server_capture --features sccm-diagnostics discovery_admission
cargo test --locked -p cmtrace-open --test sccm_native_collection --features sccm-diagnostics
```

Expected result: `PASS`; existing generic discovery still never invents a role from a root.

### Task 3: Integrate one bounded collector surface

**Files:**

- Modify: `src-tauri/src/sccm/collector/engine.rs`
- Modify: `src-tauri/src/sccm/collector/advanced_capture.rs`
- Modify: `src-tauri/src/sccm/collector/mod.rs`
- Test: `src-tauri/tests/sccm_advanced_server_capture.rs`
- Test: `src-tauri/tests/sccm_native_collection.rs`

- [ ] **Step 1: Add failing capture tests.** Use temporary roots and typed test requests for each allowlisted source. Assert capture of `current` and `lo_`, rejection/coverage for numbered and timestamped rotations, per-source 4 MiB truncation and two-file cap, and no capture of similarly named or unlisted files. Assert two authorized roots with the same basename retain distinct opaque identity.

- [ ] **Step 2: Add failing safety and coverage tests.** Cover absent root, access denied, unreadable file, file cap, byte cap, malformed rotation, symlink/reparse root, symlink/reparse entry, root escape, duplicate request, and destination collision. Each must produce an explicit coverage state and zero payload for unsafe/blocked cases.

- [ ] **Step 3: Run the red capture tests.**

```bash
cargo test --locked -p cmtrace-open --test sccm_advanced_server_capture --features sccm-diagnostics capture_contract
```

Expected result: `FAIL` until advanced contracts are routed through the engine.

- [ ] **Step 4: Route discovered and supplemental contracts through the same engine.** Replace basename-driven advanced matching with a contract lookup already bound to `(role/root/request, cardId, sourceId)`. Enumerate only exact contract basenames. Reuse the existing canonical-root, `symlink_metadata`, `is_reparse_point`, parent containment, and `open_source_no_follow` checks. Do not broaden directory traversal or use a glob.

- [ ] **Step 5: Apply contract-local limits and rotations.** Track file and byte totals by full source identity, use 4 MiB and two fragments for these six sources, reject every other rotation, and retain `Capped`/`Unsupported`/`Skipped` coverage rows for omitted candidates. Do not change the existing generic constants for unrelated client/server sources.

- [ ] **Step 6: Run focused and generic collection tests.**

```bash
cargo test --locked -p cmtrace-open --test sccm_advanced_server_capture --features sccm-diagnostics capture_contract
cargo test --locked -p cmtrace-open --test sccm_native_collection --features sccm-diagnostics
```

Expected result: `PASS`; no raw source bytes appear in test output or public result JSON.

### Task 4: Emit provenance-safe server manifest rows

**Files:**

- Modify: `src-tauri/src/sccm/collector/server_manifest.rs`
- Modify: `src-tauri/src/sccm/collector/engine.rs`
- Modify: `crates/cmtraceopen-parser/tests/sccm_server_intake.rs`
- Test: `src-tauri/tests/sccm_advanced_server_capture.rs`

- [ ] **Step 1: Add failing manifest assertions.** Require each captured or coverage row to retain card ID/version, source ID, declared producer role scope, observed source version when present, observed path class, root/source/path opaque handles, rotation kind/lineage, coverage state, source-local file/byte limits, and redacted `originalPath`. Reject raw paths, raw host/site values, raw sensitive fields, free-form request fields, and hardcoded source versions.

- [ ] **Step 2: Run the red manifest tests.**

```bash
cargo test --locked -p cmtraceopen-parser --test sccm_server_intake advanced_capture
cargo test --locked -p cmtrace-open --test sccm_advanced_server_capture --features sccm-diagnostics manifest_provenance
```

Expected result: `FAIL` until the manifest carries the new capture-only metadata.

- [ ] **Step 3: Extend the native manifest input/output structs.** Carry the typed contract metadata into `CapturedServerArtifact` and `ServerCoverageRecord`. Write `sourceVersion` from observed facts only; write `configuredPathProvenance.pathClass` from the validated root/request only; retain `null` plus a coverage limitation when unknown. Remove the current non-WSUS hardcoded/null shortcut for advanced rows. Keep raw payloads under the private bundle root and keep public projections to opaque handles, card/source identity, provenance state, capture limits, and coverage.

- [ ] **Step 4: Represent blocked advanced sources without false absence.** Emit a manifest coverage row with `captureState: unsupported` and `configuredPathProvenance.state: notRequested` when the required role/configuration fact was not observed. Emit `Absent` only after a validated contract/root was enumerated and the exact basename/rotation was missing. Emit no payload or relative path for blocked, unsafe, denied, or unsupported rows.

- [ ] **Step 5: Re-run manifest and parser gates.**

```bash
cargo test --locked -p cmtraceopen-parser --test sccm_server_intake advanced_capture
cargo test --locked -p cmtraceopen-parser --test sccm_server_advanced_roles_catalog
cargo test --locked -p cmtrace-open --test sccm_advanced_server_capture --features sccm-diagnostics manifest_provenance
cargo test --locked -p cmtrace-open --test sccm_native_collection --features sccm-diagnostics
```

Expected result: `PASS`; all six cards remain candidate-only and no reducer/finding test changes are needed.

### Task 5: Exercise the authorized Windows deployment path

**Files:**

- Test: `src-tauri/tests/sccm_advanced_server_capture.rs`
- Test: `src-tauri/tests/sccm_native_collection.rs`
- Validation record (local only): `/tmp/cmtraceopen-sccm-advanced-capture-validation/`

- [ ] **Step 1: Prepare a sanitized Windows lab matrix.** Use an authorized SCCM development server with known ConfigMgr version and host/site handles. Record, outside the repository and without raw logs, which of the following facts are actually observed: MP role/root for BGB, PXE-enabled DP topology, certificate registration point, reporting services point, service connection/CMG role, configured path class, and source version.

- [ ] **Step 2: Prove the negative gates first.** Run capture with only current generic discovery. Confirm BGB is eligible only from an observed MP root; `smspxe.log` does not become eligible from DP alone; `crp.log`, `srsrp.log`, and both cloud sources remain `notRequested`/`Unsupported` without their role facts; no candidate basename creates a role.

- [ ] **Step 3: Prove typed supplemental capture.** For each observed advanced role, issue only its typed operator-authorized request, collect only the exact current/`lo_` files, and verify manifest row identity, source version, path class, rotation lineage, source-local caps, and redacted public metadata. Verify bytes against the local lab copy only; never paste or commit them.

- [ ] **Step 4: Prove terminal disposition is still capture-only.** A rejection, service error, absent file, access denial, and partial/capped capture remain coverage/source evidence. No implementation in this plan turns them into a transaction, terminal diagnosis, reducer, or finding.

### Task 6: Run complete gates and review the diff

**Files:**

- All implementation files listed above; no source-card or raw-evidence changes.

- [ ] **Step 1: Run the complete required verification suite.**

```bash
cargo fmt --all -- --check
cargo test --locked -p cmtraceopen-parser --test sccm_server_advanced_roles_catalog
cargo test --locked -p cmtraceopen-parser --test sccm_server_intake
cargo test --locked -p cmtraceopen-parser
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
cargo test --locked -p cmtrace-open --test sccm_advanced_server_capture --features sccm-diagnostics
cargo test --locked -p cmtrace-open --test sccm_native_collection --features sccm-diagnostics
cargo clippy --locked -p cmtrace-open --all-targets --all-features -- -D warnings
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
npx tsc --noEmit
npm run frontend:build
git diff --check
```

Expected result: every command exits zero. A Windows CI/native run is mandatory before implementation merge because Registry/CIM facts, Windows reparse behavior, and no-follow flags are not fully reproduced on macOS.

- [ ] **Step 2: Perform the red-first self-review.** Confirm the diff has exactly one advanced collector owner; no new semantic source catalog, reducer, finding, card promotion, compatibility fallback, guessed registry path, arbitrary filesystem API, raw payload, or public raw path. Confirm every source has exact card/source/basename/role/path/version/cap/rotation coverage and that blocked role facts are not reported as absent.

- [ ] **Step 3: Commit the implementation in small commits.** Keep contract tests, discovery authorization, engine integration, and manifest changes separately reviewable. Do not merge or push from this worktree.

## Self-review checklist and stop conditions

- 🔴 Stop if any source can be selected by basename without a bound role/root contract.
- 🔴 Stop if a generic DP root yields `smspxe.log` without an observed PXE-enabled fact and topology binding.
- 🔴 Stop if a missing default file is reported as role absence, health, or terminal failure.
- 🔴 Stop if source version or path class is guessed, hardcoded, or silently dropped.
- 🔴 Stop if a numbered/timestamped rotation is copied despite the card's `current`/`lo_` contract.
- 🔴 Stop if per-source limits are replaced by the existing generic 8-file/16-MiB limits.
- 🔴 Stop if a symlink/reparse root or file is followed, or if a supplemental path can escape its authorized root.
- 🔴 Stop if public JSON contains raw path, host, site, certificate, tenant, endpoint, token, user, device, MAC, network, report, query, or data-source values.
- 🔴 Stop if blocked/unobserved sources disappear instead of retaining explicit `Unsupported` plus `notRequested` provenance.
- 🔴 Stop if any source card becomes `observed`, `fixtureValidated`, or `ruleValidated` as a side effect of capture work.

The first post-SUP action is to run the contract/admission red tests against the accepted SUP-frozen manifest/discovery API, then implement Task 1 only. No coupled collector code should be changed before that freeze and acceptance.
