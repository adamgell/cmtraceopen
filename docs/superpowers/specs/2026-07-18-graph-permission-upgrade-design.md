# User-Triggered Graph Permission Upgrade Design

Date: 2026-07-18

## Summary

CMTrace Open can receive a valid Microsoft Graph token that contains only part of its declared delegated permission set. The Graph settings tab correctly reports that state as connected with partial permissions, but the user cannot request the missing permissions without first signing out and discarding the working token.

Add a **Request missing permissions** action to the connected partial-permission state. The action is always initiated by an explicit user click. It re-requests CMTrace Open's complete fixed Graph permission set through the existing Windows WAM flow, preserves the current partial token if the request is cancelled or unsuccessful, and atomically replaces it only when the returned token is safe to use.

## Goals

- Let a connected user request permissions that are absent from the current token.
- Keep the request bound to CMTrace Open's fixed native permission allowlist.
- Preserve all currently working Graph capabilities when consent is cancelled, denied, unchanged, stale, or otherwise unsuccessful.
- Update the capability list immediately after a successful permission upgrade.
- Keep Windows sign-in and consent interaction explicitly user-initiated.
- Continue storing tokens only in memory and never expose them through IPC, logs, evidence, or UI.

## Non-goals

- Do not add or remove any delegated permission in this change.
- Do not accept permission names from the frontend or any other IPC caller.
- Do not alter persisted-startup authentication behavior.
- Do not initiate WAM from the ESP Diagnostics workspace.
- Do not change Graph device matching, skipped-section behavior, enrichment refresh timing, or local evidence collection.
- Do not sign the Windows account out or revoke tenant consent.
- Do not attempt to grant administrator consent; CMTrace Open can request consent but cannot approve it for the tenant.

## Permission boundary

The native allowlist remains the single source of truth:

1. `DeviceManagementManagedDevices.Read.All`
2. `DeviceManagementServiceConfig.Read.All`
3. `DeviceManagementApps.Read.All`
4. `DeviceManagementConfiguration.Read.All`
5. `DeviceManagementScripts.Read.All`

Every permission-upgrade attempt re-requests this complete union as short delegated scope names with `resource=https://graph.microsoft.com`. It does not request only the currently missing scope because replacing the bearer token with a narrower token could remove capabilities that already work.

Future versions may extend the native allowlist through a separately reviewed permission change. When that happens, existing tokens will naturally report the newly absent scope in `missingScopes`, and the same user-triggered action can request the then-current complete allowlist. No arbitrary or dynamically supplied permission is permitted.

## Settings experience

When `GraphAuthStatus.isAuthenticated` is true and `missingScopes` is non-empty, the connected status card shows a primary **Request missing permissions** button next to the existing actions.

Clicking it:

1. Locks the other Graph actions for the duration of the request.
2. Changes the label to **Requesting permissions...**.
3. Starts the existing HWND-parented WAM request for the full native permission set. Windows may show consent or account interaction when necessary.
4. Refreshes the displayed account, tenant, capability rows, and missing-scope list from the returned status.

Expected outcomes:

- **Upgraded:** the returned token adds permissions without losing any previously granted scope. The UI replaces the capability status and shows a concise success message. The button remains only if permissions are still missing.
- **Unchanged:** WAM returns a valid token with no additional declared permission. The existing partial connection remains active and the UI explains that tenant administrator consent may still be required.
- **Cancelled:** the existing partial connection remains active and the UI states that no permissions changed.
- **Denied or failed:** the existing partial connection remains active. A sanitized inline error explains that consent was not granted or the request failed; the status is not changed to disconnected.
- **Stale:** sign-out, disable, or another authentication generation wins while WAM is open. The stale result does not overwrite newer state.

The action never runs on tab mount, settings refresh, cold startup, ESP startup, or Graph enrichment refresh. There is no automatic retry loop.

## Native command and state flow

Add a dedicated command, conceptually `graph_request_missing_permissions`, instead of changing the meaning of `graph_authenticate`.

The command:

1. Requires a valid cached token with at least one missing declared permission.
2. Snapshots the current auth generation and partial status without clearing them.
3. Builds the WAM request exclusively from `GRAPH_WAM_REQUEST` in native code.
4. Acquires a candidate token through the existing HWND-parented WAM path using the default prompt semantics. It does not use forced authentication merely to request consent.
5. Projects and validates its audience, expiry, tenant, and delegated capabilities using the existing token-status projection.
6. Rejects an unexpected tenant change. If both the old and new status contain a user principal name, it also rejects an account change.
7. Requires the candidate's granted declared scopes to be a superset of the existing granted declared scopes. A strict superset is an upgrade; an equal set is unchanged; a subset is rejected.
8. Atomically installs only an improved candidate if the original auth generation is still current.

A successful replacement uses the existing generation transition so stale ESP Graph work is invalidated and the GUID cache is reset consistently. Expected consent outcomes return a structured, token-free result containing the retained or upgraded `GraphAuthStatus`, an outcome code, and an optional sanitized message. Unexpected command/IPC failures remain ordinary command errors.

The current `graph_authenticate` path remains responsible for establishing the initial connection. It may continue returning a valid cached token without opening WAM. The new command deliberately bypasses that cached-token short circuit only after the user clicks the upgrade action.

## Safety and privacy

- The frontend cannot choose or broaden scopes.
- The working partial token is never cleared before an upgrade succeeds.
- Token replacement is generation-checked to prevent stale WAM completion from restoring obsolete credentials.
- Returned candidate tokens cannot silently switch tenant or remove a working declared capability.
- Access tokens and authorization headers remain memory-only and redacted.
- Error text is sanitized and must not include tokens, account object internals, or raw provider payloads.
- The change performs no Graph data mutation and does not change the read-only ESP contract.

## Testing

### Native and portable tests

- The upgrade request uses the fixed five-scope union and Graph resource property.
- No command argument can supply arbitrary scopes.
- A strict capability superset replaces the cached token and advances dependent state exactly once.
- An equal capability set returns unchanged and retains the existing token.
- A capability subset is rejected and retains the existing token.
- Cancellation, consent denial, provider failure, account mismatch, and tenant mismatch retain the partial token.
- A stale generation cannot replace newer auth state.
- Sanitized results contain status and outcome information but never the access token.

### Frontend tests

- The button is visible only for an authenticated partial status.
- One click issues exactly one permission-upgrade command.
- All Graph actions are mutually exclusive while the request is active.
- Success refreshes capability rows and removes the button when no scopes remain missing.
- Unchanged, cancelled, and failed outcomes keep the UI connected and show actionable inline text.
- Disabling Graph or signing out while an upgrade is pending prevents stale UI publication.
- Startup and ESP workspace tests prove that neither surface invokes the new command.

### Windows acceptance

On a Windows test device:

1. Establish a partial Graph connection.
2. Confirm the missing permission is listed and the upgrade button is visible.
3. Click **Request missing permissions** and, when Windows displays WAM interaction, verify it is parented to CMTrace Open.
4. Grant consent in an authorized test tenant and verify the capability becomes available without signing out.
5. Repeat with cancellation or unavailable administrator consent and verify the original partial capabilities remain usable.
6. Restart CMTrace Open and verify this feature introduces no new automatic permission prompt.

## Acceptance criteria

- A connected partial session can request the complete declared permission set with one explicit click.
- Failure to obtain additional consent never destroys the working partial session.
- Successful consent updates the connected capability display without sign-out.
- No new scope is introduced, no scope is accepted from IPC, and no token is persisted or exposed.
- Existing startup, ESP enrichment, device matching, and read-only behavior remain unchanged.
