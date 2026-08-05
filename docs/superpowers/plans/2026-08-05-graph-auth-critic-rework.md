# Graph Authentication Critic Rework Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove every passive WAM path, use one organizations-only scope request for all interactive Graph consent, and make cancellation target a native-issued non-reusable attempt.

**Architecture:** Reading the in-memory connection snapshot remains passive and broker-free. An explicit sign-in or permission click first reserves an opaque native UUID ticket, then the matching command consumes that ticket exactly once and runs capability discovery plus WAM under the same lease and absolute deadline. Initial sign-in and permission upgrade share one scope-based organizations request; the legacy resource and compatibility paths are deleted.

**Tech Stack:** Rust 1.88, Tauri 2, Windows WebAuthenticationCoreManager, UUID v4, React 19, TypeScript, Zustand, Vitest.

---

## File map

- `src-tauri/src/graph_api/models.rs`: one WAM scope contract and serialized native attempt ticket.
- `src-tauri/src/graph_api.rs`: native reservation/claim registry, generation-safe cancellation, shared WAM acquisition, and adversarial registry tests.
- `src-tauri/src/commands/graph_api.rs`: reserve, authenticate, permission, and cancel IPC commands; no passive probe command.
- `src-tauri/src/lib.rs`: command registration and IPC contract coverage.
- `src-tauri/src/ipc_bridge.rs`: debug-command rejection list after deleting passive probe IPC.
- `src-tauri/tests/graph_esp_diagnostics.rs`: source and serialization contracts for the single WAM path and native attempt ownership.
- `src/lib/commands.ts`: validated reserve-ticket wrapper and attempt-ID-bearing interactive wrappers; no probe wrapper.
- `src/lib/commands.test.ts`: valid and malformed native ticket and replay-safe IPC tests.
- `src/components/dialogs/settings/GraphApiTab.tsx`: passive status-only mount and native-ticket interactive state machine.
- `src/components/dialogs/settings/GraphApiTab.test.tsx`: literal no-WAM passive contract plus late, replay, remount, timeout, retry, and concurrency cases.
- `src/stores/ui-store.ts`: remove the obsolete passive capability-check phase.
- `src/stores/ui-store.test.ts`: restart remains disconnected with no transient operation.
- `src/components/layout/StatusBar.tsx`: remove the obsolete capability-check indicator.

### Task 1: Make mount, opt-in, restart, and remount broker-free

**Files:**

- Modify: `src/components/dialogs/settings/GraphApiTab.tsx`
- Modify: `src/components/dialogs/settings/GraphApiTab.test.tsx`
- Modify: `src/stores/ui-store.ts`
- Modify: `src/components/layout/StatusBar.tsx`
- Modify: `src/lib/commands.ts`
- Modify: `src-tauri/src/commands/graph_api.rs`
- Modify: `src-tauri/src/lib.rs`
- Modify: `src-tauri/src/ipc_bridge.rs`

- [ ] **Step 1: Write the literal passive-boundary test**

Add one table-driven settings test that covers initial opt-in, persisted restart, mount, unmount/remount, and StrictMode initialization. For every scenario assert:

```typescript
expect(graphGetAuthStatus).toHaveBeenCalled();
expect(graphReserveInteractiveOperation).not.toHaveBeenCalled();
expect(graphAuthenticate).not.toHaveBeenCalled();
expect(graphRequestMissingPermissions).not.toHaveBeenCalled();
```

The test must not mock or call a capability-probe wrapper because that wrapper is deleted.

- [ ] **Step 2: Run the settings test and confirm failure**

```bash
npx vitest run src/components/dialogs/settings/GraphApiTab.test.tsx
```

Expected: the current mount effect calls `graphProbeCapability`.

- [ ] **Step 3: Delete passive capability IPC and state**

Delete `graphProbeCapability`, `graph_probe_capability`, standalone `probe_host_capability`, and `checkingCapability`. Replace the mount refresh body with only:

```typescript
const status = await graphGetAuthStatus();
if (!isCurrentRefresh()) return;
setAuthStatus(status);
useUiStore.getState().setGraphApiStatus(graphApiPhaseFromStatus(status));
```

Capability discovery remains inside `authenticate` after the explicit click and shares its 120-second deadline.

- [ ] **Step 4: Run focused frontend and IPC tests**

```bash
npx vitest run src/components/dialogs/settings/GraphApiTab.test.tsx src/lib/commands.test.ts src/stores/ui-store.test.ts
npx tsc --noEmit
```

Expected: passive scenarios invoke only the in-memory status command.

### Task 2: Collapse WAM onto one organizations-only scope request

**Files:**

- Modify: `src-tauri/src/graph_api/models.rs`
- Modify: `src-tauri/src/graph_api.rs`
- Modify: `src-tauri/tests/graph_esp_diagnostics.rs`

- [ ] **Step 1: Replace compatibility tests with a single-contract test**

Assert one contract with the five delegated scopes plus `openid profile offline_access`, no `resource`, no `wam_compat`, no request mode, and one native constructor path used by both authentication and permission upgrade.

- [ ] **Step 2: Run the contract test and confirm failure**

```bash
cargo +1.88 --manifest-path src-tauri/Cargo.toml test --locked --test graph_esp_diagnostics graph_wam -- --nocapture
```

Expected: legacy resource and `wam_compat=2.0` assertions still exist.

- [ ] **Step 3: Implement the one-path request**

Keep one platform-neutral contract:

```rust
pub const GRAPH_WAM_SCOPE_REQUEST: &str = concat!(
    "DeviceManagementManagedDevices.Read.All ",
    "DeviceManagementServiceConfig.Read.All ",
    "DeviceManagementApps.Read.All ",
    "DeviceManagementConfiguration.Read.All ",
    "DeviceManagementScripts.Read.All ",
    "openid profile offline_access"
);
```

Delete `GRAPH_SCOPE_REQUEST`, `GRAPH_WAM_PERMISSION_SCOPE_REQUEST`, both old request structs, `WamRequestMode`, the resource property branch, and the compatibility property branch. `authenticate` and `request_missing_permissions` must both call the same `wam::acquire_token`.

- [ ] **Step 4: Run Graph model and integration tests**

```bash
cargo +1.88 --manifest-path src-tauri/Cargo.toml test --locked graph_wam -- --nocapture
cargo +1.88 --manifest-path src-tauri/Cargo.toml test --locked --all-features --test graph_esp_diagnostics
```

Expected: one organizations provider and one scope constructor are proven.

### Task 3: Issue and consume native-owned attempt tickets

**Files:**

- Modify: `src-tauri/src/graph_api/models.rs`
- Modify: `src-tauri/src/graph_api.rs`
- Modify: `src-tauri/src/commands/graph_api.rs`
- Modify: `src/lib/commands.ts`
- Modify: `src/lib/commands.test.ts`
- Modify: `src/components/dialogs/settings/GraphApiTab.tsx`
- Modify: `src/components/dialogs/settings/GraphApiTab.test.tsx`

- [ ] **Step 1: Write failing native ownership tests**

Cover reserve/claim once, wrong-kind claim, duplicate claim, replayed cancel after drop, old cancel after a new reservation, cancel-before-claim, cancel plus restart, rapid retry, late publication, and a timeout-boundary cancellation. The registry shape is:

```rust
struct GraphInteractiveOperationEntry {
    attempt_id: uuid::Uuid,
    kind: GraphInteractiveOperationKind,
    claimed: bool,
    cancelled: Arc<AtomicBool>,
    accepts_cancellation: bool,
}
```

- [ ] **Step 2: Implement reserve then claim**

Add a synchronous `graph_reserve_interactive_operation(kind)` command returning:

```rust
#[serde(rename_all = "camelCase")]
pub struct GraphInteractiveOperationTicket {
    pub attempt_id: String,
}
```

`reserve` creates `Uuid::new_v4()` inside native state. `claim` must match ticket plus operation kind and flip `claimed` exactly once. Cancel accepts only the native ticket. Drop removes only the matching UUID. Replayed or delayed old tickets return `false` and cannot affect a later entry.

- [ ] **Step 3: Move the frontend to native tickets**

Remove `crypto.randomUUID()` from Graph authentication. After `beginSharedGraphAction`, await the reserve wrapper, attach its validated UUID to the current action, then call authenticate or permission consent. If the action was retired, disabled, or superseded before reservation resolves, immediately send cancel for that ticket and never call WAM.

- [ ] **Step 4: Add adversarial frontend and IPC tests**

Cover duplicate/replayed native ticket responses, cancel then retry with a distinct ticket, late success after disable/re-enable, controlled timeout result, rapid clicks, unmount/remount, and simultaneous authentication/permission attempts. Malformed or reused reserve payloads must reject before interactive IPC.

- [ ] **Step 5: Run focused native and frontend suites**

```bash
cargo +1.88 --manifest-path src-tauri/Cargo.toml test --locked graph_interactive_operation -- --nocapture
npx vitest run src/components/dialogs/settings/GraphApiTab.test.tsx src/lib/commands.test.ts
npx tsc --noEmit
```

Expected: every cancel is bound to one native UUID generation.

### Task 4: Freeze and verify the reworked PR

**Files:**

- Modify: `docs/superpowers/plans/2026-08-05-graph-auth-critic-rework.md`
- Modify: `library.md`

- [ ] **Step 1: Run local gates**

```bash
npm test -- --run
npm run frontend:build
cargo +1.88 --manifest-path src-tauri/Cargo.toml test --locked --workspace --all-features
cargo +1.88 --manifest-path src-tauri/Cargo.toml clippy --locked --workspace --all-targets --all-features -- -D warnings
```

- [ ] **Step 2: Rebase current main and rerun affected gates**

Fetch and rebase only if `origin/main` is not an ancestor. Record the frozen SHA after the final commit.

- [ ] **Step 3: Push and hold for hosted evidence**

Require green TypeScript, E2E, Rust, both MSRV lanes, Windows Graph/ESP/full-workspace/Clippy, CodeQL, and Windows/Linux/macOS packages. Do not merge and do not begin live WAM validation.

- [ ] **Step 4: Update the PR evidence pack**

Record target SHA, CI run, claims, reproduce commands, viewing conditions, and the explicit out-of-scope statement: live WAM validation was not started during this rework.
