# Graph Permission Upgrade Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a user-triggered, non-destructive WAM permission upgrade for an existing partial Microsoft Graph connection.

**Architecture:** The Settings tab invokes a zero-argument Tauri command. Rust owns the fixed five-scope request, classifies the WAM candidate against the current token-free status, and atomically replaces the cached token only when the candidate is a same-account, same-tenant strict declared-scope superset. Structured outcomes let the UI remain connected and explain cancellation, denial, unchanged consent, provider failure, or a stale race without exposing an access token.

**Tech Stack:** Rust, Tauri 2, Windows WAM/WinRT, React, TypeScript, Vitest.

## Global constraints

- Do not add, remove, or rename any Graph delegated permission.
- Do not accept scopes, tenant IDs, account IDs, or tokens from frontend IPC.
- Do not invoke the new command from startup, ESP diagnostics, Graph refresh, or any background task.
- Do not clear or replace a working partial token before a strict-superset candidate wins the existing generation compare-and-swap.
- Do not persist, serialize, log, or return an access token.
- Do not change ESP `deviceMatch`, skipped-section behavior, or the read-only workspace contract.
- Keep the existing `graph_authenticate` behavior intact for initial connection.
- A Settings disable while WAM is open invalidates frontend publication. It does not add a new native cancel command or change the existing enable/disable token-retention semantics.

---

## Task 1: Add the portable result contract and candidate classifier

**Files:**

- Modify: `src-tauri/src/graph_api/models.rs`
- Test: `src-tauri/tests/graph_esp_diagnostics.rs`

- [ ] **Step 1: Write failing serialization and classification tests**

Add portable tests that assert:

1. `GraphPermissionUpgradeOutcome` serializes to `upgraded`, `unchanged`, `cancelled`, `denied`, `failed`, and `stale`.
2. `GraphPermissionUpgradeResult` serializes only `outcome`, `status`, and `message`; its JSON and `Debug` output contain no access-token field.
3. A same-account, same-tenant strict declared-scope superset classifies as `Upgrade`.
4. Equal declared-scope sets classify as `Unchanged`.
5. A subset classifies as `ScopeRegression`.
6. Tenant and account changes classify as mismatch before replacement.
7. Tenant, UPN, and scopes compare case-insensitively.
8. A missing UPN on either side does not invent an account mismatch.
9. Only names in `GRAPH_DELEGATED_SCOPES` participate in comparison.

Run:

```bash
cargo test --locked -p cmtrace-open --all-features --test graph_esp_diagnostics graph_permission_ -- --nocapture
```

Expected: compilation fails because the new contract and classifier do not exist.

- [ ] **Step 2: Add the public token-free wire contract**

Add beside `GraphAuthStatus`:

```rust
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum GraphPermissionUpgradeOutcome {
    Upgraded,
    Unchanged,
    Cancelled,
    Denied,
    Failed,
    Stale,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GraphPermissionUpgradeResult {
    pub outcome: GraphPermissionUpgradeOutcome,
    pub status: GraphAuthStatus,
    pub message: Option<String>,
}
```

- [ ] **Step 3: Add the pure declared-scope classifier**

Add a portable decision enum and function:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphPermissionCandidateDecision {
    Upgrade,
    Unchanged,
    InvalidCandidate,
    AccountMismatch,
    TenantMismatch,
    ScopeRegression,
}

pub fn classify_graph_permission_candidate(
    current: &GraphAuthStatus,
    candidate: &GraphAuthStatus,
) -> GraphPermissionCandidateDecision
```

The function must require an authenticated candidate, compare tenant IDs, compare UPNs only when both are present, derive both sets exclusively from `GRAPH_DELEGATED_SCOPES`, reject any missing current scope, return `Upgrade` only for a strict superset, and otherwise return `Unchanged`.

- [ ] **Step 4: Run the focused portable tests**

Run the Task 1 command again.

Expected: all `graph_permission_` tests pass on macOS and remain platform-neutral.

- [ ] **Step 5: Commit the portable contract**

```bash
git add src-tauri/src/graph_api/models.rs src-tauri/tests/graph_esp_diagnostics.rs
git commit -m "feat(graph): define permission upgrade contract"
```

---

## Task 2: Implement non-destructive native WAM acquisition

**Files:**

- Modify: `src-tauri/src/graph_api.rs`
- Test: `src-tauri/src/graph_api.rs`

- [ ] **Step 1: Write failing Windows state-transition tests**

Add Windows-only tests around an injectable acquisition closure for:

- disconnected and already-complete preconditions do not invoke WAM;
- strict superset replaces the token and advances dependent state once;
- equal scopes retain the original token and generation;
- subset, account mismatch, and tenant mismatch retain the original token;
- cancellation, denial, and provider failure retain the original token;
- a newer sign-out/auth generation prevents a stale candidate from replacing current state;
- a stale failure returns current authoritative status;
- successful replacement clears the GUID cache and cancels older ESP work through the existing generation path.

Run on the Windows target boundary:

```bash
cargo xwin test --locked -p cmtrace-open --target x86_64-pc-windows-msvc --all-features graph_permission_upgrade --no-run
```

Expected: compilation fails until the upgrade core and typed WAM outcomes exist.

- [ ] **Step 2: Give WAM acquisition typed internal failures**

Refactor the internal WAM acquisition result without changing public initial-auth behavior:

```rust
enum WamAcquisitionFailure {
    Cancelled,
    Denied,
    Failed(AppError),
}
```

Map `UserCancel` to `Cancelled`. Map consent or interaction-required statuses that do not yield credentials to `Denied` with fixed safe text. Map COM, provider, timeout, and malformed-result failures to `Failed(AppError)`. `authenticate()` must convert these back into its existing disconnected/error behavior.

- [ ] **Step 3: Add the injectable generation-safe upgrade core**

Implement a private helper shaped as:

```rust
fn request_missing_permissions_with<F>(
    state: &GraphAuthState,
    acquire: F,
) -> Result<GraphPermissionUpgradeResult, AppError>
where
    F: FnOnce() -> Result<CachedToken, WamAcquisitionFailure>
```

The helper must:

1. Snapshot `(CachedToken, generation)` with `get_valid_token()` without clearing it.
2. Return a precondition error if disconnected or if `missing_scopes` is empty.
3. Invoke the closure exactly once.
4. On cancellation, denial, or failure, generation-check and return the retained current status; if another generation won, return `Stale` with current status.
5. Classify a successful candidate with `classify_graph_permission_candidate`.
6. Call `set_token_if_generation` only for `Upgrade`.
7. Map equal scopes to `Unchanged`; map mismatch/regression/invalid candidates to `Failed` with static sanitized copy.
8. Return `Stale` if the compare-and-swap loses.

No result or message may include provider payloads or token material.

- [ ] **Step 4: Add the public Windows entry point**

```rust
pub fn request_missing_permissions(
    state: &GraphAuthState,
    hwnd_raw: isize,
) -> Result<GraphPermissionUpgradeResult, AppError> {
    request_missing_permissions_with(state, || {
        wam::acquire_permission_consent_token_on_initialized_worker(hwnd_raw)
    })
}
```

Live Windows evidence falsified reuse of `GRAPH_WAM_REQUEST`: the default/resource request returned the cached partial token without showing consent. The explicit action must instead use the fixed native `GRAPH_WAM_PERMISSION_REQUEST`: `ForceAuthentication` paired with `wam_compat=2.0` and `prompt=consent`, the interactive `/common` authority workaround, and no `resource` property. The established initial-connect path remains unchanged. No scope parameter may cross IPC.

- [ ] **Step 5: Run native focused gates**

```bash
cargo test --locked -p cmtrace-open --all-features graph_permission_upgrade -- --nocapture
cargo xwin test --locked -p cmtrace-open --target x86_64-pc-windows-msvc --all-features graph_permission_upgrade --no-run
cargo xwin clippy --locked -p cmtrace-open --target x86_64-pc-windows-msvc --all-targets --all-features -- -D warnings
```

Expected: host portable tests pass, Windows tests compile, and Windows Clippy is clean.

- [ ] **Step 6: Commit the native state flow**

```bash
git add src-tauri/src/graph_api.rs
git commit -m "feat(graph): preserve partial token during permission upgrade"
```

---

## Task 3: Expose the zero-argument command through the production IPC boundary

**Files:**

- Modify: `src-tauri/src/commands/graph_api.rs`
- Modify: `src-tauri/src/lib.rs`
- Modify: `src-tauri/src/ipc_bridge.rs`
- Modify: `src/lib/commands.ts`
- Test: `src/lib/commands.test.ts`
- Test: `src-tauri/src/ipc_bridge.rs`

- [ ] **Step 1: Write failing IPC contract tests**

Add frontend coverage that `graphRequestMissingPermissions()` invokes exactly:

```ts
invoke("graph_request_missing_permissions", undefined)
```

Add a bridge test showing the development HTTP bridge rejects `graph_request_missing_permissions`, including a hostile request with a `scopes` field.

Run:

```bash
npm test -- --run src/lib/commands.test.ts
cargo test --locked -p cmtrace-open --all-features ipc_bridge -- --nocapture
```

Expected: frontend compilation fails and the bridge protection test fails until the boundary is implemented.

- [ ] **Step 2: Add the Tauri command and registration**

Add a Windows-only command beside `graph_authenticate`:

```rust
#[tauri::command]
#[cfg(target_os = "windows")]
pub async fn graph_request_missing_permissions(
    app: tauri::AppHandle,
    state: tauri::State<'_, GraphAuthState>,
) -> CmdResult<GraphPermissionUpgradeResult> {
    let hwnd = get_main_hwnd(&app)?;
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        graph_api::request_missing_permissions_on_initialized_worker(&state, hwnd)
    })
    .await
    .map_err(|error| AppError::Internal(format!("GraphPermissionTaskFailed: {error}")))?
}
```

The initialized-worker helper must balance `RoInitialize(RO_INIT_MULTITHREADED)` with `RoUninitialize` before and after WAM on the blocking thread. Register the command in the production invoke handler under the same Windows cfg. Add its name to the development bridge's explicit protected-command rejection list so the bridge never returns a misleading null result and never forwards caller-supplied scopes.

- [ ] **Step 3: Add the frontend token-free wrapper**

```ts
export type GraphPermissionUpgradeOutcome =
  | "upgraded"
  | "unchanged"
  | "cancelled"
  | "denied"
  | "failed"
  | "stale";

export interface GraphPermissionUpgradeResult {
  outcome: GraphPermissionUpgradeOutcome;
  status: GraphAuthStatus;
  message: string | null;
}

export async function graphRequestMissingPermissions(): Promise<GraphPermissionUpgradeResult> {
  return invokeCommand<GraphPermissionUpgradeResult>(
    "graph_request_missing_permissions",
  );
}
```

- [ ] **Step 4: Run focused IPC tests and compile checks**

```bash
npm test -- --run src/lib/commands.test.ts
cargo test --locked -p cmtrace-open --all-features ipc_bridge -- --nocapture
cargo check --locked -p cmtrace-open --all-features
cargo xwin check --locked -p cmtrace-open --target x86_64-pc-windows-msvc --all-features
```

Expected: wrappers, production registration, bridge rejection, and both platform boundaries pass.

- [ ] **Step 5: Commit the IPC boundary**

```bash
git add src-tauri/src/commands/graph_api.rs src-tauri/src/lib.rs src-tauri/src/ipc_bridge.rs src/lib/commands.ts src/lib/commands.test.ts
git commit -m "feat(graph): expose permission upgrade command"
```

---

## Task 4: Add the explicit Settings action and non-destructive feedback

**Files:**

- Modify: `src/components/dialogs/settings/GraphApiTab.tsx`
- Test: `src/components/dialogs/settings/GraphApiTab.test.tsx`

- [ ] **Step 1: Write failing Settings behavior tests**

Add tests that assert:

- partial status shows **Request missing permissions**, but mounting never invokes it;
- full and disconnected status hide the button;
- one click invokes the command once, shows **Requesting permissions...**, and locks sign-in, cache, permission, and sign-out actions;
- upgraded/full status updates rows and removes the button;
- upgraded/still-partial status updates rows and keeps the button;
- unchanged, cancelled, denied, and failed structured results remain connected and show exact inline guidance;
- an unexpected rejected promise uses sanitized fallback copy and retains partial status;
- disabling Graph while the promise is pending suppresses late UI publication;
- a stale result cannot overwrite a newer frontend operation generation.

Run:

```bash
npm test -- --run src/components/dialogs/settings/GraphApiTab.test.tsx
```

Expected: tests fail because the action and result handling are absent.

- [ ] **Step 2: Extend the Settings action state machine**

Extend `GraphAction` with `permissions`; reuse `beginGraphAction`, `finishGraphAction`, and `isCurrentGraphOperation`. Do not publish `connecting` while WAM is open because the old token remains valid.

Add local permission feedback with success, warning, and error tones. Use deterministic copy:

- Upgraded: `Permissions updated. Additional Graph capabilities are now available.`
- Unchanged: `No additional permissions were granted. A tenant administrator may need to approve the missing permissions.`
- Cancelled: `Permission request cancelled. Your existing Graph permissions are unchanged.`
- Denied: `Consent was not granted. Your existing Graph permissions remain available. A tenant administrator may need to approve the missing permissions.`
- Failed: `Windows could not complete the permission request. Your existing Graph permissions remain available.`
- Stale: `The permission request was superseded by a newer Graph connection change.`

Prefer a non-empty native sanitized message only for denied, failed, or stale. Clear the notice when Graph is disabled, a fresh initial sign-in begins, or sign-out succeeds. Do not clear it for cache hydration.

- [ ] **Step 3: Render the primary permission button**

Render the button first in the authenticated action row only when `missingScopes.length > 0`. Use **Request missing permissions** and **Requesting permissions...**. Keep the cache and sign-out actions visually secondary, add `flexWrap: "wrap"`, disable all Graph actions while any action is active, and leave the enable checkbox operable so the existing frontend generation invalidation can win.

Use `role="status"` for success/warning and `role="alert"` for failure.

- [ ] **Step 4: Run the focused Settings suite**

```bash
npm test -- --run src/components/dialogs/settings/GraphApiTab.test.tsx
npx tsc --noEmit
```

Expected: all Settings tests and TypeScript pass.

- [ ] **Step 5: Commit the Settings experience**

```bash
git add src/components/dialogs/settings/GraphApiTab.tsx src/components/dialogs/settings/GraphApiTab.test.tsx
git commit -m "feat(graph): request missing permissions from settings"
```

---

## Task 5: Pin the explicit-only boundary and update acceptance documentation

**Files:**

- Modify: `src/hooks/use-graph-api-startup.test.ts`
- Modify: `src/workspaces/esp-diagnostics/esp-diagnostics-store.test.ts`
- Modify: `docs/esp-diagnostics-windows-vm-acceptance.md`
- Modify: `README.md`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Add negative invocation tests**

Mock the new command in startup and ESP coordinator tests. Prove:

- persisted Graph startup may call `graph_authenticate` but never `graph_request_missing_permissions` for a partial status;
- ESP Graph refresh calls its fetch/cancel commands but never the upgrade command;
- no production dependency injects the upgrade function into either path.

Run:

```bash
npm test -- --run src/hooks/use-graph-api-startup.test.ts src/workspaces/esp-diagnostics/esp-diagnostics-store.test.ts
```

Expected: the tests pass after mocks explicitly pin zero upgrade calls and no production code changes are needed.

- [ ] **Step 2: Update user and Windows acceptance documentation**

Document that Settings can explicitly open WAM to re-request the complete fixed five-permission union. Add Windows rows for partial-button visibility, HWND parenting, upgraded, unchanged/admin-consent-needed, cancelled, denied, retained old capabilities, restart with no prompt, token-free IPC/logging, and no arbitrary scope input. Qualify README text that previously implied no later sign-in surface could ever open.

Add an Unreleased changelog entry for the user-triggered, non-destructive upgrade.

- [ ] **Step 3: Commit explicit-only coverage and docs**

```bash
git add src/hooks/use-graph-api-startup.test.ts src/workspaces/esp-diagnostics/esp-diagnostics-store.test.ts docs/esp-diagnostics-windows-vm-acceptance.md README.md CHANGELOG.md
git commit -m "test(graph): pin explicit permission upgrade boundary"
```

---

## Task 6: Verify, review, push, and prepare Windows acceptance

- [ ] **Step 1: Run focused regression gates**

```bash
cargo test --locked -p cmtrace-open --all-features --test graph_esp_diagnostics -- --nocapture
cargo test --locked -p cmtrace-open --all-features
cargo test --locked -p cmtrace-open --no-default-features
cargo check --locked -p cmtrace-open --no-default-features
cargo +1.77.2 check --workspace --all-features --locked
cargo clippy --locked -p cmtrace-open --all-targets --all-features -- -D warnings
cargo clippy --locked -p cmtrace-open --no-default-features --all-targets -- -D warnings
cargo xwin clippy --locked -p cmtrace-open --target x86_64-pc-windows-msvc --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
npm test
npx tsc --noEmit
npm run build
git diff --check
```

- [ ] **Step 2: Perform independent scoped review**

Review the merge-base diff for destructive token mutation, raw provider leakage, arbitrary IPC scopes, startup/ESP invocation, stale generation replacement, platform cfg gaps, and Settings race/accessibility regressions. Address every actionable finding and rerun affected gates.

- [ ] **Step 3: Update the SDD checkpoint and push**

Update `.superpowers/sdd/progress.md` with the exact timestamp, head, verification results, review verdict, and remaining Windows live acceptance. Push `codex/esp-diagnostics` to PR #266.

- [ ] **Step 4: Validate the exact pushed Windows artifact**

After CI is green, install the artifact tied to the exact pushed SHA. On the Windows test machine, use the partial-permission session to verify button visibility, explicit-click-only WAM, parented dialog, authorized upgrade when available, cancel/denial retention, old capability usability, and restart without an automatic prompt. Do not claim live WAM acceptance from automated tests alone.
