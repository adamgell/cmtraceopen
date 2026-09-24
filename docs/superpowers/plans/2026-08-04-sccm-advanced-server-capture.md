# SCCM Advanced Server Capture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add one bounded, capture-only native surface for the six #475–#479 advanced SCCM server log sources, with a real Windows picker/consent flow, backend-issued opaque capabilities, provenance, and no semantic promotion.

**Architecture:** The existing SCCM workspace uses the installed `@tauri-apps/plugin-dialog` folder picker. It sends a typed authorization request containing only the selected directory plus exact card/source/role/path-class fields to a backend command; the backend re-discovers facts, classifies the request as either observed-role/path or operator-declared candidate, stores the private request in a bounded expiring capability store, and returns a cryptographically random digest handle. A second command consumes that handle through one collector owner, `advanced_capture.rs`; raw paths stay private and the manifest carries the provenance level, operator claim, validated metadata, and opaque handles.

**Tech Stack:** Rust 1.88, Tauri v2 commands and managed state, React/TypeScript SCCM workspace, `@tauri-apps/plugin-dialog` already present in `package.json`, `cmtraceopen-parser` server intake, serde/serde_json, bounded Windows filesystem/Registry/CIM access, and authorized Windows SCCM reproduction.

---

## Frozen scope and non-goals

- Work from base `8064b5aa1457f72ea8dbb7cb979ec3ea863c524c` on branch `codex/sccm-advanced-server-capture` in `.worktrees/sccm-advanced-server-capture`.
- The exact allowlist is `smspxe.log`, `crp.log`, `srsrp.log`, `CloudMgr.log`, `SMS_Cloud_ProxyConnector.log`, and `BgbServer.log`.
- The six JSON cards under `crates/cmtraceopen-parser/tests/fixtures/sccm/server/advanced_roles/source-cards/` remain `candidate`, `captureGuidanceOnly`, and semantically inert. Do not edit or promote them, add reducers/findings, or add a semantic parser catalog entry.
- Do not infer a producer role, configured root, PXE enablement, or role instance from a basename, default directory, guessed registry path, service-name analogy, or file presence.
- Do not expose a free-form filesystem API, glob, arbitrary basename, raw selected path, raw host/site identity, or raw evidence outside the native private capture path. The selected path may cross IPC once as an ephemeral authorization input; it must never appear in command results, manifests, logs, or frontend state persisted beyond the consent operation.
- Do not add a compatibility fallback. Existing zero-argument generic capture remains the existing generic path; advanced sources are reachable only through the new typed authorization/capability path.
- Do not commit, print, fixture, or upload raw Windows evidence.

## Current evidence and decision

The current native path is `discover_sccm_environment` → `capture_sccm_diagnostics(app)` → `capture_environment(provider, bundle_root)`. `capture_sccm_diagnostics` accepts no request, `PrivateSccmEnvironment` has only generic `{ role, path }` roots, and `declared_server_source_catalog()` contains none of the six names. The current collector uses global 8-fragment/16-MiB limits and writes non-WSUS rows with null source version/path class. A private Rust request with no command, state, or UI producer would therefore be dead code and is explicitly not the design.

The repository already has the needed production primitives: the SCCM workspace in `src/workspaces/sccm/`, `@tauri-apps/plugin-dialog` in `package.json`, `commands::sccm` registered in `src-tauri/src/lib.rs`, and managed `AppState` in `src-tauri/src/state/app_state.rs`. Use those primitives to make the flow reachable. A picker request is allowed to bootstrap exact bytes for a candidate role that discovery cannot yet prove, but it must remain visibly and cryptographically marked unvalidated.

| Source | Card role scope | Existing discovered root sufficient? | Production gate | Before the gate |
| --- | --- | --- | --- | --- |
| `smspxe.log` | `distributionPointPxe`, `siteServer` | No. Generic DP discovery does not prove PXE enablement; a site-server root does not identify the PXE producer. | Observed mode requires a fresh PXE-enabled DP fact plus topology/path provenance. Operator-declared mode may bootstrap exact bytes only as an unvalidated candidate; it cannot invent PXE enablement. | Operator mode is `Unsupported`/`operatorDeclared`, never role `Absent`. |
| `crp.log` | `certificateRegistrationPoint` | No current role fact names the certificate registration point. | Observed mode waits for a role/path fact. Operator-declared mode may bootstrap exact bytes from an explicitly authorized candidate root. | Operator mode is `Unsupported`/`operatorDeclared`. |
| `srsrp.log` | `reportingServicesPoint` | No current role fact names the reporting services point. | Observed mode waits for a role/path fact. Operator-declared mode may bootstrap exact bytes from an explicitly authorized candidate root. | Operator mode is `Unsupported`/`operatorDeclared`. |
| `CloudMgr.log` | `cloudManagementGatewayConnectionPoint`, `serviceConnectionPoint` | No. A site-server log root does not prove either configured cloud role. | Observed mode requires the configured cloud role fact. Operator-declared mode may bootstrap exact bytes from an explicitly authorized candidate root; no site-server fallback. | Operator mode is `Unsupported`/`operatorDeclared`. |
| `SMS_Cloud_ProxyConnector.log` | `cloudManagementGatewayConnectionPoint`, `serviceConnectionPoint` | No; the shared card does not imply a site-server root. | Same observed/operator-declared split as `CloudMgr.log`, with backend-selected exact source contract. | Operator mode is `Unsupported`/`operatorDeclared`. |
| `BgbServer.log` | `clientNotificationServer`, `managementPoint` | Conditional. An observed MP role and observed/configured MP root can authorize the MP scope. A generic site-server root cannot. | Backend validates the MP role fact and `configuredRoleLogRoot`/`siteServerLogs` path class, or requires the typed role request. | `Unsupported`/`notRequested` when MP binding is absent. |

Every card currently declares optional capture, 4 MiB per source, least-privilege/no escalation, rotations `current` and `lo_`, max two files, high sensitivity, redaction required, no raw sensitive projection, and no time-only correlation. Keep these limits in the native contract per source, not in the generic global constants.

### Two provenance levels

The implementation must never collapse these levels:

| Level | Meaning | Allowed manifest claim | Missing file meaning |
| --- | --- | --- | --- |
| `observed` | Native discovery observed the role and its path/version fact, or an already validated role-specific fact supplied by the deployment. | `producerRole` may be the observed role; `configuredPathProvenance.state` may be `configured`/`supplied` with an observed `pathClass`; `captureContract.roleProvenance` and `pathProvenance` are `observed`. | `Absent` is a source/file coverage state only after the observed root was enumerated; it never proves role absence or failure. |
| `operatorDeclared` | The operator explicitly selected and authorized a candidate root for the exact card/source/role claim, but discovery did not prove the role/path. | `producerRole` is `unclassified`; `captureContract.roleClaim` preserves the operator claim; `captureContract.roleProvenance` and `pathProvenance` are `operatorDeclared`; `configuredPathProvenance.state` is `operatorDeclared` and `pathClass` is null. | Missing candidate bytes remain `Unsupported` with `operatorDeclared` provenance. Never emit an `Absent` role row or role-absence conclusion. |

Operator-declared mode is intentionally useful only for bounded evidence bootstrap: exact allowlisted bytes may be retained locally, but cards remain candidates, rows are parser-ineligible, no keys/transactions/findings are created, and no role/configuration fact is promoted. The UI must label it `Operator-declared candidate root — role not observed; capture only` and label observed mode `Observed role/path — bounded capture`.

## Production file map and one owner

**Frontend path:**

- Modify `src/workspaces/sccm/SccmWorkspace.tsx` to display sanitized advanced-source options with observed versus operator-declared labels, open a directory picker, show a consent summary, and call authorize then capture/cancel commands. It never accepts or displays a basename/path returned by the backend.
- Modify `src/workspaces/sccm/sccm-store.ts` to track `authorizing`/`capturingAdvanced` and the opaque capability only for the active operation; clear it after capture/cancel/error and invoke explicit cancel on abandoned authorization.
- Modify `src/workspaces/sccm/types.ts` with exact serialized request/option/capability/result types and no raw-path result field.
- Modify `src/lib/commands.ts` with `authorizeSccmAdvancedCapture(request)`, `captureSccmAdvancedDiagnostics(capabilityHandle)`, and `cancelSccmAdvancedCapture(capabilityHandle)` wrappers.
- Modify `src/workspaces/sccm/SccmWorkspace.test.tsx`, `src/workspaces/sccm/sccm-store.test.ts`, and `src/lib/commands.test.ts` for UI/command contract coverage.

**Tauri/backend path:**

- Modify `src-tauri/src/commands/sccm.rs` with the serde-deny-unknown-fields request, `authorize_sccm_advanced_capture`, `capture_sccm_advanced_diagnostics`, and `cancel_sccm_advanced_capture` commands plus testable provider helpers. The authorize command receives the ephemeral selected path, but returns only a capability handle and sanitized contract summary.
- Modify `src-tauri/src/lib.rs` to register all three commands under `sccm-diagnostics` and to manage the capability store.
- Modify `src-tauri/src/state/app_state.rs` to add a mutex-protected, in-memory `SccmAdvancedCapabilityStore` with a fixed capacity of 8 entries and a five-minute TTL under the SCCM feature. It stores private canonical paths and contract facts only until consume/cancel/expiry; it is never serialized or restored across restart.
- Create `src-tauri/src/sccm/collector/advanced_capture.rs` as the single owner of the six immutable contracts, role/path admission, source-local caps/rotations, capability-bound request types, exact source selection, and opaque identity derivation.
- Modify `src-tauri/src/sccm/collector/mod.rs`, `discovery.rs`, and `engine.rs` to carry observed root/path/version facts, publish sanitized `advancedSources` options, and consume the capability's private request through the same collector engine.
- Modify `src-tauri/src/sccm/collector/server_manifest.rs` to emit capture-contract metadata, observed version/path class, opaque handles, source-local limits, and explicit coverage without raw paths.
- Create `src-tauri/tests/sccm_advanced_server_capture.rs` for native contract/capability/collector/manifest coverage and `src-tauri/tests/sccm_advanced_ipc.rs` for command-boundary negative cases and a sanitized end-to-end command flow.
- Extend `src-tauri/src/commands/sccm.rs` unit tests for provider-backed IPC validation and `src-tauri/tests/sccm_native_collection.rs` only where generic collector regressions overlap.

**Parser production path:**

- Modify `crates/cmtraceopen-parser/src/sccm/server/windows/intake.rs` to add typed `captureContract` raw/public fields, validate them, preserve them on artifact and coverage assessments, and include card/source/role/path/version/capability identity in canonical intake integrity and duplicate identity checks.
- Modify `crates/cmtraceopen-parser/src/sccm/server/windows/mod.rs` only if re-exports are required by existing public intake consumers.
- Modify `crates/cmtraceopen-parser/tests/sccm_server_intake.rs` with captured/coverage contract rows, malformed/missing/mismatched contract cases, and order/tamper integrity tests. These are parser production tests, not only fixture tests.
- Do not modify `crates/cmtraceopen-parser/src/sccm/catalog.rs` or `crates/cmtraceopen-parser/tests/sccm_server_advanced_roles_catalog.rs` except to prove the cards remain candidate-only.

## Boundary contract

The IPC request is a closed DTO, not a collector request:

```rust
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SccmAdvancedCaptureAuthorizationRequest {
    pub card_id: String,
    pub card_version: String,
    pub source_id: String,
    pub role_scope: String,
    pub path_class: String,
    pub expected_source_version: Option<String>,
    pub selected_root: String, // ephemeral input only; never returned or logged
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmAdvancedCaptureCapability {
    pub capability_handle: String, // cmtraceopen.capture-capability.sha256.v1:<digest>
    pub card_id: String,
    pub card_version: String,
    pub source_id: String,
    pub role_scope: String,
    pub path_class: String,
    pub source_version: Option<String>,
}
```

The backend ignores no field and accepts no extra field. It re-runs native discovery, verifies the exact card/source/version against the immutable native contract, compares `expectedSourceVersion` to the freshly observed version when supplied, verifies the role/path fact when observed mode is requested, canonicalizes the selected directory, rejects symlink/reparse roots and non-directories, and creates a cryptographically random 32-byte nonce whose exposed handle is a SHA-256 digest. The capability store retains at most 8 entries, purges expired entries before authorize and access, expires each entry after 5 minutes, and never persists across restart. The capability is bound to the canonical root, contract, provenance level, role claim, path provenance, observed version, and authorization nonce. The capability store is the only place that retains the private path. `capture_sccm_advanced_diagnostics` accepts only the opaque handle, purges then consumes it before any filesystem read, and passes the private authorized request to the one collector owner. `cancel_sccm_advanced_capture` removes an unconsumed handle idempotently; capture/error cleanup never leaves a consumed handle behind.

`discover_sccm_environment` gains a sanitized `advancedSources` array. Each `SccmAdvancedSourceOption` contains `cardId`, `cardVersion`, `sourceId`, allowed `roleScopes`, allowed `pathClasses`, observed `sourceVersion`, a bounded availability state (`observed`, `operatorDeclaredCandidate`, or `blocked`), and the card-local cap/rotation summary. It contains no basename, filesystem path, root handle, host/site identifier, or authorization token. `discovery.rs` builds these options from the immutable native contract plus observed facts; the UI does not invent options.

The frontend cannot choose a basename, rotation, cap, source version, or producer role outside the option it displays. A malicious IPC caller that submits a different card/source/role/path class, a guessed registry path, a glob-like string, a symlink root, or an extra field receives a generic validation error and no capability. The capture result contains only the existing bundle receipt and public coverage rows.

The manifest adds a typed `captureContract` object to advanced artifact and coverage rows:

```json
{
  "cardId": "osd-pxe",
  "cardVersion": "1.0.0",
  "capabilityHandle": "cmtraceopen.capture-capability.sha256.v1:<digest>",
  "authorizationHandle": "cmtraceopen.capture-authorization.sha256.v1:<digest>",
  "roleClaim": "distributionPointPxe",
  "pathClaim": "configuredRoleLogRoot",
  "roleProvenance": "operatorDeclared",
  "pathProvenance": "operatorDeclared"
}
```

`capabilityHandle` and `authorizationHandle` are non-reusable opaque digests, not the private selected path. Parser production intake must deserialize and validate this object, require it for `sourceKind: "advancedCapture"`, bind all seven contract fields plus `configuredPathProvenance.state`/`pathClass` into artifact and coverage identity, and reject missing, malformed, duplicate, or tampered contract metadata. Generic existing source rows remain on their existing schema path; advanced rows cannot enter semantic classification or emit findings.

The current parser vocabulary cannot safely represent an unvalidated operator candidate, so production intake adds these exact fields/states: `captureContract.roleClaim: String`, `captureContract.pathClaim: String`, `captureContract.roleProvenance: "observed" | "operatorDeclared"`, `captureContract.pathProvenance: "observed" | "operatorDeclared"`, `captureContract.capabilityHandle: opaque handle`, `captureContract.authorizationHandle: opaque handle`, and `configuredPathProvenance.state: "operatorDeclared"`. For `operatorDeclared`, `producerRole` must be `unclassified`, `pathClass` must be null, `roleClaim`/`pathClaim` preserve the operator's exact contract claims, and `captureState` is `captured` only when exact bytes were retained or `unsupported` when the candidate is absent/blocked. The parser must not turn either claim into topology `rolesObserved`, a configured path, an `Absent` role row, a parser-eligible artifact, or any semantic evidence.

## Red-first implementation tasks

### Task 1: Define the reachable UI-to-capability flow

**Files:** `src/workspaces/sccm/SccmWorkspace.tsx`, `src/workspaces/sccm/sccm-store.ts`, `src/workspaces/sccm/types.ts`, `src/lib/commands.ts`, `src-tauri/src/commands/sccm.rs`, `src-tauri/src/lib.rs`, `src-tauri/src/state/app_state.rs`, `src-tauri/src/sccm/collector/mod.rs`, `src-tauri/src/sccm/collector/advanced_capture.rs`, `src-tauri/tests/sccm_advanced_ipc.rs`, `src/lib/commands.test.ts`, `src/workspaces/sccm/SccmWorkspace.test.tsx`, `src/workspaces/sccm/sccm-store.test.ts`.

- [ ] **Step 1: Write failing IPC/UI tests.** Assert the frontend calls `open({ directory: true, multiple: false })`, renders only the sanitized `advancedSources` options, labels `observed` and `operatorDeclaredCandidate` distinctly, sends only `cardId`, `cardVersion`, `sourceId`, `roleScope`, `pathClass`, `expectedSourceVersion`, and the ephemeral selected directory to `authorize_sccm_advanced_capture`, then sends only `capabilityHandle` to `capture_sccm_advanced_diagnostics`. Assert no request has `basename`, `glob`, or arbitrary source path result fields. Assert consent cancellation calls `cancel_sccm_advanced_capture` when a capability exists and never leaves a pending token in the UI store.
- [ ] **Step 2: Write failing backend boundary/lifecycle tests.** Through the command request DTO, reject unknown fields, arbitrary card/source/role/path class, mismatched card/source, glob-like selected paths, symlink/reparse roots, and a path outside the validated directory contract. Assert every rejection leaves the capability store empty and reveals only a generic error code. Add expiry after five minutes, fixed capacity of eight with purge-before-reject, purge-on-authorize, purge-on-access, explicit cancel, replay rejection, consume-before-read, capture-error cleanup, and restart/non-persistence tests.
- [ ] **Step 3: Run red tests.**

```bash
npx vitest run src/lib/commands.test.ts src/workspaces/sccm/SccmWorkspace.test.tsx src/workspaces/sccm/sccm-store.test.ts
cargo test --locked -p cmtrace-open --test sccm_advanced_ipc --features sccm-diagnostics
```

Expected result: `FAIL` because the command, capability store, and picker flow do not yet exist.
- [ ] **Step 4: Implement the smallest reachable path.** Add the closed DTO, sanitized `advancedSources` discovery output, managed single-use capability store, three registered commands, TypeScript wrappers, picker/consent UI, and store transitions. Generate a cryptographically random 32-byte nonce, expose only its SHA-256 opaque digest, cap the store at eight pending entries, purge by five-minute TTL before every authorize/access, consume before reading, remove on cancel/error, and keep the store memory-only. Keep time behind a small injectable clock or deadline argument so expiry tests are deterministic; production uses `Instant::now()`. Keep generic `capture_sccm_diagnostics` unchanged for generic sources; advanced capture has no zero-argument fallback.
- [ ] **Step 5: Run the focused tests green.**

```bash
npx vitest run src/lib/commands.test.ts src/workspaces/sccm/SccmWorkspace.test.tsx src/workspaces/sccm/sccm-store.test.ts
cargo test --locked -p cmtrace-open --test sccm_advanced_ipc --features sccm-diagnostics
```

### Task 2: Implement the single native advanced contract owner and provenance split

**Files:** `src-tauri/src/sccm/collector/advanced_capture.rs`, `src-tauri/src/sccm/collector/mod.rs`, `src-tauri/src/sccm/collector/discovery.rs`, `src-tauri/src/state/app_state.rs`, `src-tauri/tests/sccm_advanced_server_capture.rs`.

- [ ] **Step 1: Add red contract tests.** Require exactly six source contracts, exact card IDs/versions, exact basenames, role scopes, allowed path classes, 4 MiB/two-file/current+lo_ policy, and no SQL/database or unlisted source. Require MP-root-only BGB admission in observed mode, PXE fact for `smspxe.log` in observed mode, and no generic-root role assertion for CRP/SRSRP/cloud. Separately require operator-declared candidate mode for all five currently unobserved roles to retain exact bytes without becoming observed/configured.
- [ ] **Step 2: Add private discovery/provenance types.** Carry observed path class, ConfigMgr/source version, role fact, PXE/topology fact where actually observed, operator claim, provenance level, and canonical root handle. Keep raw paths private. A typed operator request may select a candidate directory after backend validation of exact card/source/role claim and authorization even when the role is unobserved; it must be marked `operatorDeclared` and cannot manufacture an observed role/path fact.
- [ ] **Step 3: Implement contract validation and capability materialization.** Validate the closed DTO against the table, re-discover facts, choose `observed` only when all required role/path facts match, otherwise accept only the explicit operator-declared candidate mode, reject unauthorized role/path/version tuples, reject no-follow/reparse violations, and store only the private request behind a digest capability. Deduplicate by complete `(card, version, source, role claim, provenance level, path provenance, root handle, observed version)` identity.
- [ ] **Step 4: Run green native admission tests.**

```bash
cargo test --locked -p cmtrace-open --test sccm_advanced_server_capture --features sccm-diagnostics advanced_contract
cargo test --locked -p cmtrace-open --test sccm_native_collection --features sccm-diagnostics
```

### Task 3: Route authorized capabilities through one bounded collector

**Files:** `src-tauri/src/sccm/collector/engine.rs`, `src-tauri/src/sccm/collector/advanced_capture.rs`, `src-tauri/src/sccm/collector/server_manifest.rs`, `src-tauri/tests/sccm_advanced_server_capture.rs`, `src-tauri/tests/sccm_native_collection.rs`.

- [ ] **Step 1: Add red capture/safety tests.** Test all six sources through a consumed capability in both observed and operator-declared modes; capture only exact current/`lo_` files; reject numbered/timestamped rotations and similarly named files; enforce per-source 4 MiB/two-file limits; preserve distinct opaque identity for duplicate basenames in distinct authorized roots; and cover observed absent, operator-declared missing candidate, denied, capped, skipped, unsupported, malformed, symlink/reparse, root escape, replayed capability, and destination collision cases.
- [ ] **Step 2: Integrate the capability's private request into the existing engine.** Enumerate only contract-selected exact basenames, reuse canonical-root containment, `symlink_metadata`, `is_reparse_point`, and `open_source_no_follow`, and consume the capability before reading. Do not add a glob, directory-wide arbitrary collection, or generic basename matching for advanced sources.
- [ ] **Step 3: Emit explicit coverage.** Use `Unsupported` plus `configuredPathProvenance.state: notRequested` when no request exists; use `Unsupported` plus `configuredPathProvenance.state: operatorDeclared` for an authorized candidate whose role/path is unvalidated, including a missing candidate file; use `Absent` only for an observed role/path root after enumeration, and never project it as role absence. Retain `AccessDenied`, `Capped`, `Skipped`, `ParseFailed`, and `Captured` with source-local limits and rotation identity.
- [ ] **Step 4: Run green focused/native tests.**

```bash
cargo test --locked -p cmtrace-open --test sccm_advanced_server_capture --features sccm-diagnostics capture_contract
cargo test --locked -p cmtrace-open --test sccm_native_collection --features sccm-diagnostics
```

### Task 4: Make manifest fields real in native writer and parser intake

**Files:** `src-tauri/src/sccm/collector/server_manifest.rs`, `src-tauri/src/sccm/collector/engine.rs`, `crates/cmtraceopen-parser/src/sccm/server/windows/intake.rs`, `crates/cmtraceopen-parser/src/sccm/server/windows/mod.rs` if re-export is needed, `crates/cmtraceopen-parser/tests/sccm_server_intake.rs`, `src-tauri/tests/sccm_advanced_server_capture.rs`.

- [ ] **Step 1: Add parser-production red tests before changing the wire types.** Assert `captureContract` is required for `advancedCapture`, card/source/version/capability mismatch is rejected, observed/operator-declared provenance is preserved on artifact and coverage assessments, operator-declared rows force `producerRole: unclassified`, `pathClass: null`, and `configuredPathProvenance.state: operatorDeclared`, duplicate/tampered rows fail canonical integrity, and order changes do not change the normalized integrity result. Assert an operator-declared missing file is `Unsupported`, not role `Absent`, and advanced rows remain parser-ineligible with no semantic evidence/findings.
- [ ] **Step 2: Add production raw/public intake types.** In `intake.rs`, add `RawServerCaptureContract`, public `SccmServerCaptureContract`, and optional `capture_contract` fields to `SccmServerArtifactAssessment` and `SccmServerCoverage`. Add `operatorDeclared` to `SccmServerConfiguredPathState`; validate canonical card ID/version, opaque capability and authorization handles, role/path claims, `roleProvenance`, `pathProvenance`, required advanced source kind, source/role binding, and no raw path. The advanced-capture branch must permit an `unclassified` producer for `operatorDeclared` rows, must not require that role in `topology.rolesObserved`, and must set `parser_eligible=false` for both observed and operator-declared advanced rows. Include every capture-contract field plus configured path state/class in canonical artifact identity, coverage identity, path-lineage duplicate checks, and `SccmServerIntakeIntegrity` digest input. Update `RawServerArtifact::KNOWN_FIELDS`, `RawServerCaptureContract::KNOWN_FIELDS`, and bounded manifest preflight lists.
- [ ] **Step 3: Write native manifest metadata from the validated capability.** Add the same contract object to captured and coverage rows; observed mode writes the observed role/path/version; operator-declared mode writes `producerRole: unclassified`, `roleClaim`, `pathClaim`, `roleProvenance: operatorDeclared`, `pathProvenance: operatorDeclared`, `configuredPathProvenance.state: operatorDeclared`, null `pathClass`, and opaque authorization/capability handles. Retain raw payload only under the private bundle root; remove the old advanced-row null/hardcoded shortcut. Generic rows keep their current path.
- [ ] **Step 4: Run parser/native green gates.**

```bash
cargo test --locked -p cmtraceopen-parser --test sccm_server_intake advanced_capture
cargo test --locked -p cmtraceopen-parser --test sccm_server_advanced_roles_catalog
cargo test --locked -p cmtrace-open --test sccm_advanced_server_capture --features sccm-diagnostics manifest_provenance
cargo test --locked -p cmtrace-open --test sccm_native_collection --features sccm-diagnostics
```

### Task 5: Reproduce the user flow on authorized Windows

**Files:** `src-tauri/tests/sccm_advanced_ipc.rs`, `src-tauri/tests/sccm_advanced_server_capture.rs`, `src/workspaces/sccm/SccmWorkspace.test.tsx`; raw validation output remains under `/tmp/cmtraceopen-sccm-advanced-capture-validation/` and is never committed.

- [ ] **Step 1: Discover and display only sanitized options.** Confirm the UI receives card/source/role/path-class availability and version facts, never paths or basenames. Render `Observed role/path — bounded capture` versus `Operator-declared candidate root — role not observed; capture only`. Confirm the native picker returns a selected directory only to the authorize command.
- [ ] **Step 2: Prove negative gates first.** With generic discovery only, confirm BGB requires MP binding for observed mode; DP alone does not admit observed PXE; CRP/SRSRP/cloud show operator-declared candidate availability rather than observed availability; malicious IPC payloads cannot change card/source/role/path class or inject a basename/glob; and a missing operator candidate is `Unsupported`/`operatorDeclared`, not role `Absent`.
- [ ] **Step 3: Prove consent and capability lifecycle.** In `src-tauri/tests/sccm_advanced_ipc.rs`, run the same serialized request shape used by the UI through authorize then capture, assert one successful end-to-end command contract, test five-minute expiry, eight-entry capacity, purge-before-authorize/access, explicit cancel, capture-error cleanup, restart/non-persistence, authorize once/capture once, and replay failure. Confirm result/manifest/logs contain no selected path or raw evidence.
- [ ] **Step 4: Prove exact source/rotation/cap behavior.** In the sanitized lab, place only allowlisted current/`lo_` files, verify local byte hashes against the operator's private copy, verify source-specific caps and lineage, verify operator-declared manifest provenance remains unvalidated, and retain only metadata in repository-facing test output.

### Task 6: Complete gates and self-review

- [ ] **Step 1: Run all required gates.**

```bash
cargo fmt --all -- --check
cargo test --locked -p cmtraceopen-parser --test sccm_server_advanced_roles_catalog
cargo test --locked -p cmtraceopen-parser --test sccm_server_intake
cargo test --locked -p cmtraceopen-parser
cargo check --locked -p cmtraceopen-parser --target wasm32-unknown-unknown
cargo test --locked -p cmtrace-open --test sccm_advanced_ipc --features sccm-diagnostics
cargo test --locked -p cmtrace-open --test sccm_advanced_server_capture --features sccm-diagnostics
cargo test --locked -p cmtrace-open --test sccm_native_collection --features sccm-diagnostics
cargo clippy --locked -p cmtrace-open --all-targets --all-features -- -D warnings
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
npx vitest run src/lib/commands.test.ts src/workspaces/sccm/SccmWorkspace.test.tsx src/workspaces/sccm/sccm-store.test.ts
npx tsc --noEmit
npm run frontend:build
git diff --check
```

Expected result: every command exits zero. Windows CI/native execution is mandatory before implementation merge because Registry/CIM facts, Windows reparse behavior, and no-follow flags are not fully reproduced on macOS.

- [ ] **Step 2: Re-run self-review against the reworked scope.** Confirm the request is reachable from the existing SCCM UI; the command is registered; managed state creates and consumes the capability; backend—not frontend—validates every field; parser production types validate and integrity-bind every new manifest field; one collector owner handles all six sources; no card promotion/reducer/finding/compatibility fallback/arbitrary filesystem collection/raw evidence exists.
- [ ] **Step 3: Commit implementation in reviewable commits only after SUP acceptance.** Keep UI/IPC, native contract/collector, and parser manifest work separable. Do not merge or push from this worktree.

## Blocking self-review and stop conditions

- 🔴 Stop if no user-visible picker/consent action can create a capability.
- 🔴 Stop if advanced capture still relies on a zero-argument command or an unreachable private constructor.
- 🔴 Stop if capabilities have no cryptographically random nonce, five-minute TTL, fixed eight-entry capacity, purge-before-authorize/access, explicit cancel, consume-before-read, error cleanup, replay rejection, or restart non-persistence.
- 🔴 Stop if any frontend-provided card/source/role/path/version value is trusted without fresh backend validation.
- 🔴 Stop if any command returns a raw path or stores a capability that can be replayed.
- 🔴 Stop if parser production intake does not deserialize, validate, preserve, and integrity-bind `captureContract` on both artifact and coverage rows.
- 🔴 Stop if an operator-declared role/path is serialized as observed/configured, if its path class is non-null, or if its claim enters `rolesObserved`.
- 🔴 Stop if a source can be selected by basename, glob, default root, or guessed registry path.
- 🔴 Stop if generic DP discovery yields PXE capture without observed PXE enablement/topology.
- 🔴 Stop if source version/path class is guessed or silently dropped.
- 🔴 Stop if numbered/timestamped rotations or global 8-file/16-MiB limits replace the card-local contract.
- 🔴 Stop if a symlink/reparse root/file is followed or a supplemental root escapes its authorized directory.
- 🔴 Stop if public JSON contains raw host, site, path, certificate, tenant, endpoint, token, user, device, MAC, network, report, query, or data-source values.
- 🔴 Stop if blocked sources disappear instead of retaining `Unsupported` plus `notRequested` provenance.
- 🔴 Stop if a missing operator-declared candidate emits an `Absent` role row or implies role absence.
- 🔴 Stop if any card becomes `observed`, `fixtureValidated`, or `ruleValidated` as a side effect of capture work.

The first post-SUP action is to run Task 1's red UI/IPC and parser-contract tests against the accepted SUP-frozen APIs. No coupled collector implementation starts before SUP is frozen and accepted.
