# Graph API Non-Blocking WAM Authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Graph authentication responsive, cancellable, capability-aware, and deterministic on Windows while preserving explicit opt-in and the existing delegated-permission workflow.

**Architecture:** Keep one organizations-only Windows WAM path. Separate the persistent connection snapshot from the last interactive attempt, execute every WAM operation on a blocking worker behind an async Tauri command, and give the backend sole ownership of one request-ID-scoped interactive operation at a time. The frontend persists only the opt-in preference; runtime capability, action, and attempt state reset on process restart and never launch WAM automatically.

**Tech Stack:** Rust 1.88, Tauri 2, Windows WebAuthenticationCoreManager/WAM, React 19, TypeScript, Zustand, Vitest.

---

## File map

- `src-tauri/src/graph_api/models.rs`: serialized capability, connection, and attempt contracts.
- `src-tauri/src/graph_api.rs`: capability classification, one-operation ownership, cancellation, deadline handling, token-generation safety, and Windows WAM execution.
- `src-tauri/src/commands/graph_api.rs`: async/off-thread IPC entry points and HWND lifetime handling.
- `src-tauri/src/lib.rs`: command registration and IPC coverage.
- `src/lib/commands.ts`: exact TypeScript mirrors and request-ID-bearing command wrappers.
- `src/stores/ui-store.ts`: non-persisted deterministic Graph runtime phase, capability, and last-attempt state; only `graphApiEnabled` remains persisted.
- `src/stores/ui-store.test.ts`: persistence/restart contract.
- `src/components/dialogs/settings/GraphApiTab.tsx`: explicit consent, capability check, sign-in/cancel controls, and typed outcome rendering.
- `src/components/dialogs/settings/GraphApiTab.test.tsx`: frontend state-machine, remount, cancellation, and stale-completion behavior.
- `src-tauri/tests/graph_esp_diagnostics.rs`: serialized Graph status contract adjustments after removing attempt errors from connection state.
- `e2e/graph-api-settings.spec.ts`: running-app settings smoke coverage proving opt-in does not launch Windows WAM.

### Task 1: Define typed capability and authentication-attempt contracts

**Files:**

- Modify: `src-tauri/src/graph_api/models.rs`
- Modify: `src/lib/commands.ts`
- Test: `src-tauri/src/graph_api/models.rs`
- Test: `src-tauri/tests/graph_esp_diagnostics.rs`

- [ ] **Step 1: Write failing Rust serialization tests**

Cover the exact camel-case JSON contract for:

```rust
pub enum GraphHostCapabilityKind {
    Available,
    PersonalAccountOnly,
    NoOrganizationalAccount,
    ProviderUnavailable,
    Unknown,
}

pub struct GraphHostCapability {
    pub kind: GraphHostCapabilityKind,
}

pub enum GraphAuthAttemptOutcome {
    Connected,
    Cancelled,
    TimedOut,
    Unavailable,
    Failed,
    Stale,
}

pub struct GraphAuthAttemptResult {
    pub outcome: GraphAuthAttemptOutcome,
    pub status: GraphAuthStatus,
    pub capability: GraphHostCapability,
    pub message: Option<String>,
}
```

Verify that `GraphAuthStatus` contains connection and delegated-capability data only; remove its obsolete `error` field and make `GraphAuthStatus::disconnected()` argument-free.

- [ ] **Step 2: Run the contract tests and confirm they fail**

Run from `src-tauri/`:

```bash
cargo +1.88 --manifest-path src-tauri/Cargo.toml test --locked graph_auth_attempt_contract -- --nocapture
```

Expected: compilation or assertion failure because the new types do not exist yet.

- [ ] **Step 3: Implement the minimal Rust and TypeScript contracts**

Mirror the Rust shapes exactly in `src/lib/commands.ts`; do not add permissive optional fields or string aliases. Replace `graphAuthenticate()` with `graphAuthenticate(requestId)` returning `GraphAuthAttemptResult`, add `graphProbeCapability()`, and add `graphCancelAuthentication(requestId)`.

- [ ] **Step 4: Update status fixtures and run contract tests**

Run:

```bash
cargo +1.88 --manifest-path src-tauri/Cargo.toml test --locked graph_auth -- --nocapture
npx vitest run src/components/dialogs/settings/GraphApiTab.test.tsx
```

Expected: Rust contract tests pass; frontend tests may still fail where they expect the old command signature or error-bearing status.

- [ ] **Step 5: Commit the contract package**

```bash
git add src-tauri/src/graph_api/models.rs src-tauri/tests/graph_esp_diagnostics.rs src/lib/commands.ts
git commit -m "refactor(graph): type authentication attempts"
```

### Task 2: Add native capability probing, ownership, cancellation, and deadline safety

**Files:**

- Modify: `src-tauri/src/graph_api.rs`

- [ ] **Step 1: Write failing platform-neutral operation tests**

Add tests proving:

- only one interactive request ID owns the native slot;
- a mismatched request ID cannot cancel it;
- a matching request ID sets cancellation exactly once;
- dropping the lease releases ownership;
- late token set/clear operations cannot cross an auth generation;
- cancelled and timed-out waits are distinct;
- one absolute deadline is reused across provider lookup, account enumeration, and token acquisition.

- [ ] **Step 2: Write failing capability-classification tests**

Use pure inputs rather than WinRT objects:

```rust
fn classify_graph_host_capability(
    organizational_accounts: AccountEnumeration,
    personal_accounts: AccountEnumeration,
) -> GraphHostCapabilityKind
```

Cover organizational account available, personal-only, no accounts, provider unavailable, enumeration denied/not supported, and unknown provider failure.

- [ ] **Step 3: Run the focused tests and confirm failure**

```bash
cargo +1.88 --manifest-path src-tauri/Cargo.toml test --locked graph_interactive_operation -- --nocapture
cargo +1.88 --manifest-path src-tauri/Cargo.toml test --locked graph_host_capability -- --nocapture
```

- [ ] **Step 4: Implement the single-owner operation lease**

Store one active `{ request_id, cancelled }` entry under `GraphAuthState`. Return a lease that owns the cancellation flag and releases only its matching request on drop. Do not log request-adjacent identity data, tokens, tenant IDs, or UPNs.

- [ ] **Step 5: Make WAM waiting cooperative**

Replace the single 120-second `recv_timeout` with a bounded polling loop that checks the matching lease cancellation flag and the same absolute deadline. On cancellation or timeout, call `IAsyncOperation::Cancel()` and return a typed acquisition failure. Never use a second timeout budget for later WAM stages.

- [ ] **Step 6: Implement organizations-only capability discovery**

On the initialized WinRT worker, use the existing Microsoft provider ID with the `organizations` authority and `FindAllAccountsAsync`. Query `consumers` only to distinguish a proven personal-only host after organizations returns zero accounts. Do not authenticate against `consumers` or `common`. Treat enumeration-denied/not-supported results as `Unknown`, not as proof that no organizational account exists.

- [ ] **Step 7: Gate authentication and preserve token safety**

Before interactive token acquisition, perform capability discovery under the operation's absolute deadline. Return `Unavailable` without showing WAM for proven personal-only, no-organizational-account, or unavailable-provider states. Re-check cancellation after WAM returns and before installing a token. A cancelled, timed-out, failed, unavailable, or stale operation must not publish a token.

- [ ] **Step 8: Put permission upgrade under the same owner**

Pass a request-scoped lease to the existing permission-upgrade WAM operation. Preserve current cancellation/denial/unchanged/upgraded semantics and original-token retention, while preventing it from overlapping initial sign-in.

- [ ] **Step 9: Run native unit tests and commit**

```bash
cargo +1.88 --manifest-path src-tauri/Cargo.toml test --locked graph_interactive_operation -- --nocapture
cargo +1.88 --manifest-path src-tauri/Cargo.toml test --locked graph_host_capability -- --nocapture
cargo +1.88 --manifest-path src-tauri/Cargo.toml test --locked graph_permission_upgrade -- --nocapture
git add src-tauri/src/graph_api.rs
git commit -m "fix(graph): own and cancel WAM operations"
```

### Task 3: Move Graph authentication behind async Tauri commands

**Files:**

- Modify: `src-tauri/src/commands/graph_api.rs`
- Modify: `src-tauri/src/lib.rs`

- [ ] **Step 1: Add IPC coverage for the new command names and request ID**

Assert that the handler exposes `graph_probe_capability`, async `graph_authenticate`, and `graph_cancel_authentication`; initial authentication and permission upgrade both require `requestId`.

- [ ] **Step 2: Replace the synchronous authentication command**

Make `graph_authenticate` async, acquire the main HWND/always-on-top guard, clone managed state, claim the request lease, and run WinRT work through `tauri::async_runtime::spawn_blocking`. Remove the old direct synchronous path rather than retaining an alias or fallback.

- [ ] **Step 3: Add capability and cancellation commands**

Run capability probing on `spawn_blocking`. Keep cancellation lightweight and synchronous: it may set only the matching native flag and returns whether a request was cancelled.

- [ ] **Step 4: Apply the same request-ID ownership to permission upgrades**

Change the permission command signature rather than adding a compatibility overload.

- [ ] **Step 5: Run Rust checks and commit**

```bash
cargo +1.88 --manifest-path src-tauri/Cargo.toml check --locked
cargo +1.88 --manifest-path src-tauri/Cargo.toml test --locked graph_auth -- --nocapture
git add src-tauri/src/commands/graph_api.rs src-tauri/src/lib.rs
git commit -m "fix(graph): run WAM authentication off thread"
```

### Task 4: Implement deterministic frontend states and cancellation UX

**Files:**

- Modify: `src/stores/ui-store.ts`
- Modify: `src/stores/ui-store.test.ts`
- Modify: `src/components/dialogs/settings/GraphApiTab.tsx`
- Modify: `src/components/dialogs/settings/GraphApiTab.test.tsx`

- [ ] **Step 1: Write failing store persistence tests**

Replace the old four-phase status with:

```typescript
type GraphApiPhase =
  | "checkingCapability"
  | "disconnected"
  | "signingIn"
  | "cancelling"
  | "connected"
  | "unsupported"
  | "error";
```

Add non-persisted `graphApiCapability` and `graphApiLastAttempt`. Verify that rehydration restores only `graphApiEnabled`, resets runtime state to `disconnected`, and never marks an operation active.

- [ ] **Step 2: Write failing Graph settings tests**

Cover explicit opt-in without automatic WAM, capability checking, available/personal-only/no-organizational/provider-unavailable/unknown rendering, request-ID forwarding, sign-in cancellation, cancellation during disable, timeout Retry, remount, StrictMode, stale completion, concurrent-click suppression, and restart without automatic interactive authentication.

- [ ] **Step 3: Implement the runtime state transitions**

On opt-in or restart, refresh the in-memory connection snapshot, then run only the non-interactive capability probe when disconnected. Never call `graphAuthenticate` from an effect. Store typed capability and attempt results separately from `GraphAuthStatus`.

- [ ] **Step 4: Implement sign-in and cancellation controls**

Generate one request ID per interactive action. Show `Cancel sign-in` during initial authentication and a cancelling state after the matching cancel command is sent. Do not release the shared frontend action until the native promise settles. Disable/re-enable must not allow a second request while cancellation is pending.

- [ ] **Step 5: Preserve explicit permission consent**

Give permission upgrade its own request ID, place it under the same shared busy/cancel ownership, and keep existing upgraded/unchanged/cancelled/denied/failed/stale copy and token-retention behavior.

- [ ] **Step 6: Render deterministic capability-aware copy**

Tell personal-only users that Intune Graph requires a work or school account. Tell no-organizational-account users to add a work or school account in Windows Settings. Keep unknown capability retryable without claiming the host lacks Entra. Do not display raw provider responses.

- [ ] **Step 7: Run frontend tests and commit**

```bash
npx vitest run src/components/dialogs/settings/GraphApiTab.test.tsx src/stores/ui-store.test.ts
npx tsc --noEmit
git add src/stores/ui-store.ts src/stores/ui-store.test.ts src/components/dialogs/settings/GraphApiTab.tsx src/components/dialogs/settings/GraphApiTab.test.tsx
git commit -m "fix(graph): make sign-in cancellable and deterministic"
```

### Task 5: Integration verification and evidence handoff

**Files:**

- Create: `e2e/graph-api-settings.spec.ts`
- Modify: `docs/superpowers/plans/2026-08-05-graph-auth-nonblocking.md`

- [ ] **Step 1: Run focused verification**

```bash
npx vitest run src/components/dialogs/settings/GraphApiTab.test.tsx src/stores/ui-store.test.ts
cargo +1.88 --manifest-path src-tauri/Cargo.toml test --locked graph_auth -- --nocapture
cargo +1.88 --manifest-path src-tauri/Cargo.toml test --locked graph_permission_upgrade -- --nocapture
```

- [ ] **Step 2: Run full repository gates**

```bash
npx tsc --noEmit
npm test -- --run
npm run frontend:build
cargo +1.88 --manifest-path src-tauri/Cargo.toml test --locked --workspace
cargo +1.88 --manifest-path src-tauri/Cargo.toml clippy --locked --workspace --all-targets --all-features -- -D warnings
```

- [ ] **Step 3: Run available platform checks**

On macOS, verify non-Windows configuration and compile Windows-target code if the MSVC target/link-independent check is available. Do not claim WAM runtime acceptance from compilation.

- [ ] **Step 4: Integrate current main and rerun affected gates**

Fetch `origin/main`, rebase the branch, record the new frozen SHA, and rerun focused Rust/TypeScript tests plus strict clippy/typecheck.

- [ ] **Step 5: Prepare the Windows evidence pack**

Require an exact Windows full-build SHA and six inspectable scenarios: organizational happy path, broker cancel, provider error, controlled 120-second timeout, personal/no-Entra host, and restart during sign-in. Each record includes viewing conditions, monotonic timestamps, typed outcome, reproduce steps, and out-of-scope statement. Redact identity and token material.

- [ ] **Step 6: Commit documentation, push, and open the PR**

```bash
git add docs/superpowers/plans/2026-08-05-graph-auth-nonblocking.md library.md e2e/graph-api-settings.spec.ts
git commit -m "docs(graph): record issue 441 verification"
git push -u origin codex/issue-441-nonblocking-graph-auth
gh pr create --base main --head codex/issue-441-nonblocking-graph-auth
```

The PR body must contain `Closes #441`, the final frozen SHA, commands/results, the Windows evidence matrix, and an explicit statement that Windows-only runtime acceptance remains required before merge.
