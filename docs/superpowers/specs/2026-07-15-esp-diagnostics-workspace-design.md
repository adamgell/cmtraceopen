# ESP Diagnostics Workspace — Design Specification

**Date:** 2026-07-15

**Status:** Implemented in the feature branch; live Windows acceptance pending

## Product outcome

CMTrace Open gains a dedicated, read-only **ESP Diagnostics** workspace for troubleshooting Windows Autopilot Enrollment Status Page and software-deployment failures while they are happening, and for inspecting captured diagnostic bundles later.

The workspace is a single full-width diagnostic cockpit inside the existing CMTrace Open application chrome. It has no left sidebar. Local evidence is always the source of truth. Existing opt-in WAM authentication adds Intune/Graph names and remote status when available, but Graph is never required for the workspace to function.

## Non-negotiable behavior

- The workspace is read-only. It must not sync MDM, retry or install software, start or stop services, change registry values, import `.reg` files, run remediation, or alter Intune objects.
- Running elevated is strongly recommended and visibly reported because protected registry, event-log, process-command-line, and SYSTEM-temp evidence affects coverage.
- A non-elevated session still produces partial results and explicit coverage gaps.
- Local evidence renders immediately whether Graph is disabled, disconnected, denied, offline, partial, or cancelled.
- When the existing Graph setting is enabled and authenticated, remote data enriches raw GUIDs and local status. It never replaces the raw identifiers or provenance.
- Log discovery is bounded to known deployment paths and shallow, high-signal temp inspection. There is no full-drive scan and no deep-scan control.
- Live evidence collection continues while the evidence pane is collapsed and while the user visits another workspace.
- Repeated events and retries remain separate timeline occurrences.
- Unknown, missing, malformed, denied, and unsupported evidence must remain distinguishable.
- Classic Autopilot ESP and Autopilot Device Preparation are separate scenarios with separate rules.

## Approved workspace layout

The desktop app chrome remains visible. The existing workspace selector identifies **ESP Diagnostics**. The left sidebar is absent for this workspace.

The workspace body contains:

1. A top session header with scenario, current phase, elapsed time, elevation, local coverage, and Graph status.
2. A persistent elevation banner when the process is not elevated, including a user-initiated **Restart as administrator** action when supported.
3. A visible **What MSIEXEC is doing now** card with process, parent, product/app correlation, PID, start time, command line summary, active MSI log, correlation confidence, and direct evidence links.
4. An actionable findings area with blockers, warnings, confidence, and evidence provenance. Findings are explanations and recommended checks, not remediation buttons.
5. Real-time ESP phase and workload regions that update independently from the log viewer.
6. Collapsible evidence sections for device/profile, ESP settings, enrollment sessions, apps, scripts, policies, certificates, join/registration, Delivery Optimization, hardware, NodeCache, and coverage.
7. A prominent primary toolbar button labeled **Open live logs** with a live indicator and unread/new-evidence count.
8. A live evidence/log surface with three states:
   - **Collapsed** by default.
   - **Docked** at the bottom and vertically resizable.
   - **Full workspace** while retaining a clear restore action.

The dock state and dock height persist for the active workspace session. Hiding or resizing the dock never stops collection or loses evidence.

## Source architecture

```text
ESP React workspace + isolated Zustand store
       |                              |
local commands/events       optional Graph overlay command
       |                    existing setting + connected WAM
native ESP session service           |
       |                    portable Graph provider/orchestrator
bounded logs + Windows facts          |
       |                              |
source-neutral evidence records   remote overlay
       |                              |
pure Rust reducer/rules/timeline -----+
                  |
       immutable displayed snapshot
```

### Pure parser layer

`cmtraceopen-parser::esp` owns source-neutral models, status decoding, scenario classification, identity/workload correlation, timeline construction, and deterministic findings. It cannot read files, registry, event logs, processes, clocks, WMI, Graph, or Tauri state.

### Native layer

`src-tauri/src/esp` owns Windows read-only data collection, bounded discovery, tailing, process sampling, captured-bundle resolution, session lifecycle, cancellation, and event emission. It does not read frontend settings or wait for Graph.

`src-tauri/src/graph_api` exposes a separate cancellable ESP overlay provider. Portable models/client/correlation compile on every platform; WAM and the real HTTP adapter remain Windows-only.

### Frontend layer

`src/workspaces/esp-diagnostics` owns display state, live session state, stale request/sequence rejection, Graph scheduling/overlay presentation, dock mode/size, filtering, and accessibility. After persisted settings hydrate, it automatically queries only when the existing Graph option is enabled and already connected. A connecting/disconnected state never queues work or opens WAM; explicit refresh is required after connection. Disabling cancels and clears the remote overlay without signing out or altering local evidence.

The ESP domain must not be added to the 2,036-line `commands/intune.rs`, the 1,095-line Intune Zustand store, or the existing `IntuneAnalysisResult` contract.

## Evidence contract

Every raw record carries a stable ID and provenance before normalization:

- source kind and source artifact ID;
- file path and line/record number when applicable;
- registry hive/key/value when applicable;
- event channel, event ID, record ID, and named event-data fields when applicable;
- source timestamp, original offset, normalized UTC timestamp, and observation timestamp;
- raw value/status and sensitivity classification;
- parse state and source access state.

Occurrence identity is source-derived rather than dependent on unrelated provider arrival order. Its base key combines the source artifact ID and evidence ID, both escaped for the wire ID; a source-local collision ordinal distinguishes only concurrently retained records with the same base key. Equal-timestamp timeline rows are ordered by their stable entry ID, then their source-local sequence. Shuffling records with independent base keys therefore preserves timeline IDs and equal-time row order, while repeated identical same-source retries remain distinct. Eviction never renumbers an occurrence that remains retained; occurrence-key accounting is itself bounded to retained evidence.

Derived records carry their evidence references, correlation basis, and confidence. A derived finding cannot exist without at least one evidence reference or an explicit coverage-gap reference.

## PowerShell v6.3 parity contract

The native implementation incorporates the attached script's applicable data, but does not execute or embed the script.

Required scenarios:

- Unknown
- Autopilot v1
- Autopilot for existing devices JSON
- ESP only
- Autopilot Device Preparation v2

Required data:

- Profile name, tenant domain/ID, correlation ID, EntDMID, UPN, enrollment IDs, and raw IDs.
- Raw `CloudAssignedOobeConfig` and all ten decoded OOBE flags.
- Profile download time, Entra/hybrid join mode, ODJ applied, and skip-domain-connectivity state.
- Device/user ESP enabled flags, timeout, blocking, reset, retry, and continue-anyway settings.
- Device Preparation agent/page timeouts, skip-on-failure, diagnostics permission, scripts, and all eight workload states.
- Every device and user session, defaulting the UI to latest without discarding older sessions.
- MSI, Office, UWP/modern app, Win32, policy, SCEP certificate, platform script, and Device Preparation workload evidence.
- Office status values 0, 10, 20, 25, 30, 40, 48, 50, 55, 60, and 70.
- Classic ESP status values 1 through 4, policy status values 0 and 1, unknown status preservation, exit codes, and enforcement errors.
- Numerically ordered NodeCache entries without stopping at a missing index.
- Event IDs 72, 100, 101, 107, 109, 110, 111, 304, 306, 1905, 1906, 1920, 1922, and 1924.
- Delivery Optimization raw HTTP/LAN/cache counters and app/Office transfer events.
- OS version/build, manufacturer, model, serial, and TPM version without exposing the raw hardware hash.
- A complete, non-deduplicated observed timeline.

The following script behaviors are explicitly rejected:

- access-token, bearer-token, app-secret, authorization-header, or raw Graph-body output;
- accepting app secrets or bearer tokens from the frontend;
- automatic Graph module installation;
- `.reg` import into HKCU or deletion of fixed temp/registry locations;
- consulting the analyst machine while interpreting a captured bundle;
- hardware-hash command-line exposure or normal UI/export exposure;
- retry/event de-duplication;
- mixed local/UTC/unspecified timestamps;
- green success styling for detailed Office failure;
- stopping NodeCache enumeration at the first numeric gap;
- reading the device Sidecar branch for a user session;
- assuming missing evidence means success;
- inferring service/process health from registry presence.

## Bounded discovery contract

The live collector has no arbitrary-drive-root input.

Always-known sources include current and up to three rotated copies of:

- `IntuneManagementExtension.log`
- `AppWorkload.log`
- `AppActionProcessor.log`
- `AgentExecutor.log`
- `Win32AppInventory.log`
- high-signal ConfigMgr deployment logs when the client is present
- Patch My PC and PSAppDeployToolkit paths when their known roots exist

Temp roots are explicit and non-recursive:

- `%WINDIR%\Temp`
- `%WINDIR%\System32\config\systemprofile\AppData\Local\Temp`
- `%TEMP%`
- active ProfileList user temp directories

Limits:

- inspect at most 128 newest directory entries per temp root;
- look back 30 minutes by default;
- attach a temp file only when a running installer names it, its name matches a high-signal MSI/setup pattern, or its first 4 KiB has a known MSI/setup signature;
- never follow reparse points outside an allowed root;
- maintain at most 16 active tails, prioritizing IME sources and explicitly referenced MSI logs;
- read at most the final 8 MiB for initial context, then appended bytes;
- detect truncation and rotation and emit reset provenance;
- re-run bounded discovery every two seconds while live;
- debounce UI snapshot emission to 250 ms;
- expire a live session after eight hours with a final state.
- retain at most 25,000 evidence records and 32 MiB of serialized evidence in the reducer;
- evict the oldest high-volume stream evidence first while preserving lower-volume registry, JSON, and coverage state when possible;
- never renumber retained source occurrences after eviction;
- emit explicit `session.evidence-retention` coverage with discarded record/byte counts, and derive conclusions only from the retained evidence.

## MSIEXEC status contract

The process sampler reads only the allowlist needed for deployment correlation and does not repeatedly spawn PowerShell.

Correlation precedence:

1. Exact `msiexec` `/L`, `/L*V`, or `/log` path to canonical MSI log path.
2. IME or AgentExecutor parent/child PID chain to `msiexec.exe`.
3. Exact app GUID, product code, or install command found in local IME evidence.
4. A single active workload within a plus/minus 120-second window, labeled temporal.
5. Multiple candidates remain visibly uncorrelated.

PID and process start time form the process identity so PID reuse cannot merge observations.

## Graph contract

The existing WAM provider, public client, HWND-parented interaction, and in-memory token cache remain the only authentication mechanism. The workspace never silently initiates authentication. Consent uses a WAM v2 scope request with the five fully qualified Graph scope names and no resource property; capability display uses their short `scp` values. Unsigned token claims are only decoded/sanity-checked for cache and UX, while Graph 401/403 responses remain authoritative.

Requested delegated read scopes:

- `DeviceManagementManagedDevices.Read.All`
- `DeviceManagementServiceConfig.Read.All`
- `DeviceManagementApps.Read.All`
- `DeviceManagementConfiguration.Read.All`
- `DeviceManagementScripts.Read.All`

No write, privileged-operation, or group-membership permission is requested. Assignment target group/filter IDs are shown as declared targeting; they are not presented as effective membership.

The client prefers Graph v1.0 and labels beta-derived sections. Each native overlay section has an independent request state: available, not found, permission denied, failed, skipped, or cancelled. A dependency-blocked section stores `blockedBy` in its structured error and reports `apiVersion: notRequested` when no HTTP request was dispatched. A 403 affects only its section. A 401 invalidates the cached token once. Responses to 429, 503, and 504 honor bounded `Retry-After` retries. Pagination has host, page, item, and body-size limits and is cancellable.

The frontend, not the native overlay, owns global Graph-disabled, disconnected, connecting, loading, stale, and cancelled states. Disabled means local evidence only and clears/cancels remote state without a warning; disconnected or connecting preserves local evidence, presents `GraphNotConnected`, never opens WAM, and requires an explicit refresh after connection.

Remote correlation order is managed-device ID, Entra device ID, serial, then exact hostname plus tenant/user evidence. Ambiguous weak matches require explicit device selection and do not continue automatically.

Graph may provide:

- managed-device and Autopilot identity/profile facts;
- Autopilot event and policy-status detail;
- ESP configuration and declared assignments;
- app names, assignments, intent, and device/user state when available;
- policy, certificate/configuration profile, platform script, and remediation names/status.

Raw local IDs remain visible beside enriched names.

## Captured evidence

The workspace accepts CMTrace Open evidence bundles plus supported MDM diagnostic CAB/ZIP inputs. Registry exports are parsed in place and never imported. Bundle resolution uses manifest artifact IDs/families first and a bounded legacy fallback second.

The built-in collector manifest must enumerate every actual collected file in `artifacts[]`; missing and failed sources stay in coverage gaps. Path traversal, absolute paths outside the bundle, symlink escapes, and unbounded archive expansion are rejected.

An ESP-only bundle with no IME text logs is a valid analysis input.

## Privacy and security

- Tokens remain memory-only and have redacted debug behavior.
- Authorization headers and raw remote response bodies are never logged.
- UPN, SID, tenant, EntDMID, serial, and NodeCache payloads are marked sensitive and masked by default.
- The raw hardware hash is never included in normal IPC, screenshots, logs, copy actions, or export.
- Process command lines are sanitized for secret-like arguments before IPC/logging.
- Graph diagnostics commands are not exposed through the debug localhost IPC bridge.
- Copy/export surfaces require explicit user action and apply the established sensitive-field policy.

## Completion definition

The deliverable is complete only after:

- all parity fixtures and release-gate checks pass;
- live local operation works with Graph off;
- partial/elevated coverage behavior is verified on Windows;
- all three live-log states work and remain resizable;
- MSIEXEC correlation works and ambiguity is visible;
- Graph full/partial/offline/cancelled states are verified;
- captured and live-equivalent fixtures produce equivalent conclusions;
- TypeScript, Vitest, Playwright, Rust test/check/clippy, lite build, and Windows acceptance gates pass;
- README, changelog, screenshots, and privacy/read-only documentation match the shipped behavior.
