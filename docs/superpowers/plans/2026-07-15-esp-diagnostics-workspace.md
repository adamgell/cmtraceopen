# ESP Diagnostics Workspace — Full Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Use `superpowers:test-driven-development` for every behavior change, `superpowers:systematic-debugging` for failures, and `superpowers:verification-before-completion` before any completion claim. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the complete read-only ESP Diagnostics workspace: live Autopilot/ESP and software-deployment troubleshooting, bounded log discovery and tailing, MSIEXEC correlation, full attached PowerShell v6.3 data parity, captured-bundle analysis, actionable provenance-backed findings, and optional enrichment through CMTrace Open's existing WAM/Graph connection.

**Architecture:** A standalone `esp-diagnostics` workspace and Zustand store consume immutable snapshots from a dedicated native ESP session service. The native service performs bounded Windows discovery, registry/event/process/system reads, bundle resolution, and tailing. A separate cancellable native Graph command reuses the existing WAM state, while the global frontend ESP orchestrator alone decides whether to request and merge that overlay from the existing setting. A source-neutral pure-Rust reducer owns normalization, timeline construction, correlation, redaction, and deterministic findings. Local evidence is complete and usable without Graph.

**Tech Stack:** Tauri v2, Rust 2021, `cmtraceopen-parser`, `serde`, `chrono`, `winreg`, Windows APIs, `notify`, React 19, TypeScript, Zustand, Fluent UI, TanStack Virtual, Vitest, Testing Library, and Playwright.

**Spec:** `docs/superpowers/specs/2026-07-15-esp-diagnostics-workspace-design.md`

**Source parity contract:** `Get-AutopilotDiagnostics.ps1` v6.3 behavior is captured in the checked-in fixtures under `crates/cmtraceopen-parser/tests/fixtures/esp/` (`normalization-cases.json`, `scenario-cases.json`, `edge-cases.json`, `graph-cases.json`, and `bundle-live-equivalence.json`). A clean checkout never depends on the original chat attachment. A future source-parity re-audit must take an explicitly supplied v6.3 script path and fail clearly when that external input is absent; it must not embed a developer-specific absolute path.

---

## Global constraints

- This is the entire deliverable, not a reduced phase-one subset. Milestone gates protect code quality; they do not reduce the active `/goal` or its done-definition.
- Do not implement source changes on the current unrelated `pr/260` branch. Execution starts from a current `origin/main` in an isolated `codex/esp-diagnostics` worktree created with `superpowers:using-git-worktrees`.
- Follow `CLAUDE.md`: a phase touches no more than five files; verify each phase; request the required checkpoint approval; swarm independent file groups; re-read files before editing.
- Before structurally refactoring any file over 300 lines, remove only confirmed dead props, exports, imports, and debug logging, verify, and commit that cleanup separately.
- Use `apply_patch` for source and documentation edits. Do not overwrite or discard unrelated user changes.
- Strictly read-only diagnostics: no MDM sync, retry, installation, remediation, service control, registry writes, `.reg` import, tenant mutation, Graph writes, or automatic module installation.
- The only device-state-changing action is an explicit user-requested application relaunch through Windows `runas`; it changes application privilege, not managed-device configuration.
- No arbitrary root, recursive drive scan, deep-scan command, or deep-scan UI affordance may exist.
- Graph is optional and additive. Graph-disabled, disconnected, denied, offline, partial, throttled, and cancelled states must preserve all local results.
- Do not add an ESP-specific Graph toggle or `includeGraph` request field. Local ESP commands are Graph-agnostic; the global frontend ESP orchestrator reads the app's existing hydrated `graphApiEnabled`/connection state and invokes the separate Graph overlay command only when appropriate.
- Reuse existing WAM authentication. Do not create a second login system or accept app secrets/bearer tokens.
- Raw evidence, normalized facts, remote enrichment, and derived findings remain separate. A finding must cite evidence or a coverage gap.
- Preserve raw IDs and unknown values even when a friendly name or normalized status exists.
- Preserve every repeated retry/event occurrence and normalize all comparable timestamps to UTC while retaining original offset/text.
- Sensitive values are marked at ingestion. Never expose raw tokens, authorization headers, hardware hashes, or unredacted Graph bodies.
- Prefer Graph v1.0; isolate and label beta endpoints and tolerate schema/enum additions.
- Offline bundle analysis remains available cross-platform. Live acquisition is Windows-only and returns a typed unsupported result elsewhere.
- Do not expand `src-tauri/src/commands/intune.rs`, `src/workspaces/intune/intune-store.ts`, or `IntuneAnalysisResult` with this domain.
- Do not expose full Graph ESP commands through the debug localhost IPC bridge.
- Do not call raw Tauri `invoke` from workspace stores; all IPC goes through `src/lib/commands.ts`.
- `npx tsc --noEmit` is mandatory before every completion claim. Final verification also requires all Rust, Vitest, Playwright, lite-build, and Windows acceptance gates listed below.

## Delivery sequence

| Milestone | Outcome |
|---|---|
| 0 | Isolated branch/worktree and clean baselines |
| 1 | Structural cleanup gates for large shell and Graph files |
| 2 | Correct collector artifact manifest and safe bundle intake |
| 3 | Complete source-neutral ESP data contract and status dictionaries |
| 4 | Scenario/session/workload/timeline parsing and full PowerShell parity fixtures |
| 5 | Deterministic findings and MSI/process correlation |
| 6 | Read-only Windows registry, EVTX, system, and elevation acquisition |
| 7 | Bounded known/temp log discovery and multi-file live tailing |
| 8 | Cancellable native live-session service and IPC |
| 9 | Captured CMTrace/MDM CAB/ZIP evidence analysis |
| 10 | Capability-aware existing WAM auth and hardened typed Graph client |
| 11 | Device/Autopilot/ESP/app/policy/script Graph orchestration |
| 12 | Registry-driven app shell slots and standalone workspace state |
| 13 | Approved full-width cockpit, MSIEXEC card, evidence sections, and findings |
| 14 | Collapsed/docked/full live logs, resize behavior, and primary chrome button |
| 15 | Graph overlay UX, privacy, accessibility, end-to-end, Windows, and release gates |

## Core contracts to implement

### Source-neutral parser contract

Create these exact public types in `crates/cmtraceopen-parser/src/esp/models.rs`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EspScenario {
    Unknown,
    AutopilotV1,
    ExistingDeviceJson,
    EspOnly,
    AutopilotDevicePreparationV2,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EspPhase {
    NotStarted,
    DevicePreparation,
    DeviceSetup,
    AccountSetup,
    Completed,
    Failed,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EspTrackedKind {
    Msi,
    Office,
    ModernApp,
    Win32App,
    Policy,
    ScepCertificate,
    PlatformScript,
    DevicePreparationWorkload,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EspNormalizedStatus {
    NotStarted,
    NotInstalled,
    Initialized,
    Pending,
    Downloading,
    Downloaded,
    Installing,
    InProgress,
    Processed,
    Succeeded,
    Failed,
    Skipped,
    Uninstalled,
    RebootRequired,
    Cancelled,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EspArtifactStatus {
    Available,
    Missing,
    PermissionDenied,
    ParseFailed,
    Unsupported,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EspCorrelationConfidence {
    Exact,
    Strong,
    Temporal,
    Uncorrelated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EspDiagnosticsSnapshot {
    pub schema_version: u32,
    pub scenario: EspScenario,
    pub phase: EspPhase,
    pub generated_at_utc: String,
    pub elevation: EspElevationState,
    pub identity: EspIdentityEvidence,
    pub profile: Option<EspProfileEvidence>,
    pub enrollments: Vec<EspEnrollmentEvidence>,
    pub sessions: Vec<EspSession>,
    pub workloads: Vec<EspWorkload>,
    pub installer_correlations: Vec<EspInstallerCorrelation>,
    pub node_cache: Vec<EspNodeCacheEntry>,
    pub registration_events: Vec<EspRegistrationEvent>,
    pub delivery_optimization: Option<EspDeliveryOptimizationEvidence>,
    pub hardware: Option<EspHardwareEvidence>,
    pub activity: Vec<EspTimelineEntry>,
    pub findings: Vec<EspDiagnosticFinding>,
    pub coverage: Vec<EspArtifactCoverage>,
    pub raw_evidence: Vec<EspRawEvidenceRecord>,
    pub graph: Option<EspGraphOverlay>,
}
```

All referenced supporting structs live in the same file and use camelCase serde output. `EspRawEvidenceRecord`, `EspTimelineEntry`, `EspWorkload`, `EspInstallerCorrelation`, `EspDiagnosticFinding`, and every Graph-correlated record contain `Vec<EspEvidenceRef>` provenance.

### Reducer contract

Create in `crates/cmtraceopen-parser/src/esp/reducer.rs`:

```rust
pub enum EspEvidenceRecord {
    Registry(EspRegistryObservation),
    Json(EspJsonObservation),
    EventLog(EspEventLogObservation),
    Ime(EspImeObservation),
    DeploymentLog(EspDeploymentLogObservation),
    Process(EspProcessObservation),
    System(EspSystemObservation),
    DeliveryOptimization(EspDeliveryOptimizationObservation),
    Graph(EspGraphObservation),
    Coverage(EspArtifactCoverage),
}

pub struct EspDiagnosticsReducer {
    // Private indexes only; no I/O, clock, platform, or Tauri dependency.
}

impl EspDiagnosticsReducer {
    pub fn new(generated_at_utc: String) -> Self;
    pub fn ingest(&mut self, record: EspEvidenceRecord);
    pub fn ingest_all<I: IntoIterator<Item = EspEvidenceRecord>>(&mut self, records: I);
    pub fn snapshot(&self) -> EspDiagnosticsSnapshot;
}
```

### Native session contract

Create in `src-tauri/src/esp/session.rs`:

```rust
pub const ESP_SESSION_UPDATE_EVENT: &str = "esp-diagnostics-session-update";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EspSessionEnvelope {
    pub session_id: String,
    pub request_id: String,
    pub sequence: u64,
    pub state: EspSessionState,
    pub snapshot: EspDiagnosticsSnapshot,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EspSessionUpdate {
    pub session_id: String,
    pub request_id: String,
    pub sequence: u64,
    pub reason: EspUpdateReason,
    pub emitted_at_utc: String,
    pub snapshot: EspDiagnosticsSnapshot,
}
```

Only one live session may exist. A second start returns a typed conflict and never replaces the existing session. Bundle analysis is stateless. Every update has a monotonically increasing sequence.

Expose these Tauri commands from `src-tauri/src/commands/esp_diagnostics.rs`:

```rust
analyze_esp_evidence(path, request_id)
start_esp_diagnostics_session(request_id)
get_esp_diagnostics_session(session_id)
stop_esp_diagnostics_session(session_id)
restart_esp_as_administrator()
```

Neither local analysis command accepts a caller-controlled Graph Boolean or reads frontend persistence. They always produce raw local evidence. The global frontend ESP orchestrator applies CMTrace Open's existing hydrated Graph option and connection state to both live and imported snapshots: disabled means local evidence only; enabled and connected permits a separate additive Graph request; enabled but disconnected/connecting means local evidence plus `GraphNotConnected` and an explicit **Refresh Graph data** action. It never queues behind authentication or initiates WAM.

Graph state ownership is deliberately split: the native overlay returns only per-section request results, while the frontend owns the global disabled, disconnected, connecting, loading, stale, and cancelled presentation states. Disabling Graph cancels any in-flight overlay and clears remote data without producing a warning or altering local evidence. Connected requests represent a dependency that was never dispatched as `status: Skipped`, `data: null`, `error.blockedBy: <dependency>`, and `apiVersion: NotRequested` (`"notRequested"` on the wire); they never claim `v1.0` or `beta` for a request that did not occur.

### Graph section contract

Create the serializable overlay contract in `crates/cmtraceopen-parser/src/esp/models.rs` so the source-neutral snapshot owns its complete schema and never depends on Tauri. `src-tauri/src/graph_api/models.rs` contains only token capabilities, request types, and raw transport DTOs, then maps them into these parser-owned types:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphSection<T> {
    pub status: GraphSectionStatus,
    pub required_scope: Option<String>,
    pub api_version: GraphApiVersion,
    pub data: Option<T>,
    pub error: Option<GraphSectionError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum GraphSectionStatus {
    Available,
    NotFound,
    PermissionDenied,
    Failed,
    Skipped,
    Cancelled,
}
```

`blockedBy` belongs to `GraphSectionError`, not to `GraphSectionStatus`. `GraphApiVersion` has the known wire values `v1.0`, `beta`, and `notRequested`, while still preserving unknown future values.

### Frontend store contract

Create in `src/workspaces/esp-diagnostics/esp-diagnostics-store.ts`:

```ts
export type EspWorkspacePhase =
  | "idle"
  | "analyzing"
  | "starting"
  | "live"
  | "stopping"
  | "ready"
  | "error";

export type EspEvidenceViewMode = "collapsed" | "docked" | "full";

export interface EspDiagnosticsStore {
  phase: EspWorkspacePhase;
  requestId: string | null;
  sessionId: string | null;
  sequence: number;
  snapshot: EspDiagnosticsSnapshot | null;
  error: string | null;
  graphRequestId: string | null;
  graphPhase: "disabled" | "unavailable" | "idle" | "loading" | "ready" | "partial" | "error" | "cancelled";
  evidenceViewMode: EspEvidenceViewMode;
  evidenceDockHeight: number;
  unreadEvidenceCount: number;
  beginAnalysis(requestId: string): void;
  beginLiveStart(requestId: string): void;
  applyAnalysis(requestId: string, snapshot: EspDiagnosticsSnapshot): void;
  applySessionUpdate(update: EspSessionUpdate): void;
  fail(requestId: string, error: string): void;
  beginGraph(requestId: string): void;
  applyGraphOverlay(requestId: string, overlay: EspGraphOverlay): void;
  setGraphUnavailable(reason: EspGraphUnavailableReason): void;
  cancelGraph(requestId: string): void;
  clearGraphOverlay(): void;
  setEvidenceViewMode(mode: EspEvidenceViewMode): void;
  setEvidenceDockHeight(height: number): void;
  markEvidenceRead(): void;
  clearStoppedSession(sessionId: string): void;
}
```

`applyAnalysis` rejects stale request IDs. `applySessionUpdate` rejects wrong session IDs and non-increasing sequences. Logs continue accumulating in every view mode.

---

## Exact file structure

### Pure Rust parser — new

| File | Responsibility |
|---|---|
| `crates/cmtraceopen-parser/src/esp/mod.rs` | Public exports |
| `crates/cmtraceopen-parser/src/esp/models.rs` | Complete source-neutral DTO contract |
| `crates/cmtraceopen-parser/src/esp/normalize.rs` | URI/GUID decoding, status dictionaries, OOBE bits, time normalization |
| `crates/cmtraceopen-parser/src/esp/reducer.rs` | Scenario/session/workload state reducer |
| `crates/cmtraceopen-parser/src/esp/timeline.rs` | Stable non-deduplicating chronology |
| `crates/cmtraceopen-parser/src/esp/correlation.rs` | Identity, workload, Graph, MSI/process correlation |
| `crates/cmtraceopen-parser/src/esp/rules.rs` | Deterministic actionable findings |
| `crates/cmtraceopen-parser/src/esp/redaction.rs` | Sensitivity marking and safe copy/export projection |
| `crates/cmtraceopen-parser/tests/esp_diagnostics.rs` | Full fixture-driven behavior suite |
| `crates/cmtraceopen-parser/tests/fixtures/esp/**` | Scenario, status, malformed, retry, Graph, and equivalence fixtures |

### Native Rust — new

| File | Responsibility |
|---|---|
| `src-tauri/src/esp/mod.rs` | Module exports and platform capability |
| `src-tauri/src/esp/discovery.rs` | Fixed bounded known/temp source discovery |
| `src-tauri/src/esp/registry.rs` | Read-only targeted Windows registry acquisition |
| `src-tauri/src/esp/event_logs.rs` | Live and captured event-channel acquisition with named EventData |
| `src-tauri/src/esp/system.rs` | Elevation, identity, hardware, TPM, service and DO observations |
| `src-tauri/src/esp/process.rs` | Fakeable provider and command-line correlation parsing |
| `src-tauri/src/esp/process_win32.rs` | Allowlisted Windows process sampling without PowerShell polling |
| `src-tauri/src/esp/tailing.rs` | ESP-owned multi-file tails and rotation/truncation handling |
| `src-tauri/src/esp/bundle.rs` | CMTrace bundle plus bounded legacy artifact resolution |
| `src-tauri/src/esp/archive.rs` | Safe CAB/ZIP extraction and direct registry/JSON/EVTX intake |
| `src-tauri/src/esp/session.rs` | Live session lifecycle, debounce, expiry, cancellation, emission |
| `src-tauri/src/esp/relaunch.rs` | Explicit Windows `runas` relaunch with safe argument handling |
| `src-tauri/src/commands/esp_diagnostics.rs` | Thin typed Tauri command surface |
| `src-tauri/tests/esp_diagnostics_sources.rs` | Native source/bundle/session integration tests |
| `src-tauri/tests/fixtures/esp-bundle/**` | Safe full and sparse bundle fixtures |

### Graph — new

| File | Responsibility |
|---|---|
| `src-tauri/src/graph_api/client.rs` | Typed allowlisted HTTP, retry, pagination, caps, cancellation |
| `src-tauri/src/graph_api/models.rs` | Token capabilities, Graph request types, and raw transport DTOs |
| `src-tauri/src/graph_api/correlation.rs` | Deterministic local-to-remote device/object matching |
| `src-tauri/src/graph_api/esp.rs` | Ordered ESP endpoint orchestration and partial results |
| `src-tauri/tests/graph_esp_diagnostics.rs` | Transport, permission, retry, correlation, and redaction tests |
| `src-tauri/tests/fixtures/graph/esp/**` | Sanitized Graph response fixtures |

### Frontend — new

| File | Responsibility |
|---|---|
| `src/workspaces/esp-diagnostics/index.ts` | Workspace definition and source routing |
| `src/workspaces/esp-diagnostics/types.ts` | TypeScript mirror of serialized Rust contracts |
| `src/workspaces/esp-diagnostics/esp-diagnostics-store.ts` | Isolated local/live/Graph/dock state |
| `src/workspaces/esp-diagnostics/esp-diagnostics-store.test.ts` | State and stale-update contract |
| `src/workspaces/esp-diagnostics/use-esp-session-updates.ts` | Global Tauri update subscription |
| `src/workspaces/esp-diagnostics/EspDiagnosticsWorkspace.tsx` | Full-width single-page composition |
| `src/workspaces/esp-diagnostics/EspWorkspaceHeader.tsx` | Scenario/session/coverage/Graph summary |
| `src/workspaces/esp-diagnostics/ElevationBanner.tsx` | Admin warning and relaunch action |
| `src/workspaces/esp-diagnostics/MsiexecStatus.tsx` | Visible installer activity/correlation box |
| `src/workspaces/esp-diagnostics/ActionCenter.tsx` | Findings, confidence, provenance, recommended checks |
| `src/workspaces/esp-diagnostics/EspPhaseProgress.tsx` | Classic and Device Preparation progress |
| `src/workspaces/esp-diagnostics/LiveActivity.tsx` | Non-log real-time activity stream |
| `src/workspaces/esp-diagnostics/EspWorkloadTable.tsx` | Apps/scripts/policies/certs/workloads |
| `src/workspaces/esp-diagnostics/EvidenceSections.tsx` | Profile, sessions, join, DO, hardware, NodeCache, coverage |
| `src/workspaces/esp-diagnostics/GraphEnrichmentPanel.tsx` | Optional Graph section states and device selection |
| `src/workspaces/esp-diagnostics/esp-view-model.ts` | Stable presentation mapping and masking |
| `src/workspaces/esp-diagnostics/LiveEvidenceDock.tsx` | Collapsed/docked/full state and resize handle |
| `src/workspaces/esp-diagnostics/LiveEvidenceTable.tsx` | Virtualized multi-source evidence rows |
| `src/workspaces/esp-diagnostics/EspToolbarAction.tsx` | Prominent app-chrome live-log button |
| `src/workspaces/esp-diagnostics/EspStatusBarContent.tsx` | Workspace-specific status text |
| `src/workspaces/esp-diagnostics/EspDiagnosticsWorkspace.test.tsx` | Cockpit state and interaction tests |
| `src/workspaces/esp-diagnostics/LiveEvidenceDock.test.tsx` | Mode, resize, retention, and accessibility tests |
| `src/workspaces/esp-diagnostics/esp-view-model.test.ts` | Evidence section and masking contract |
| `src/workspaces/registry.test.ts` | Registry-driven shell behavior |
| `src/components/dialogs/settings/GraphApiTab.test.tsx` | Consent, capability, partial-permission, and privacy behavior |
| `e2e/esp-diagnostics.spec.ts` | End-to-end workspace flow |
| `e2e/fixtures/demo/esp-diagnostics.json` | Deterministic browser fixture |

### Existing files to modify

| File | Change |
|---|---|
| `crates/cmtraceopen-parser/src/lib.rs` | Export `esp` |
| `crates/cmtraceopen-parser/src/collector/types.rs` | Record every collected file plus parse hints |
| `crates/cmtraceopen-parser/src/collector/profile.rs` | Backward-compatible parse hints/profile validation |
| `crates/cmtraceopen-parser/src/collector/profile_data.json` | Complete ESP evidence families |
| `crates/cmtraceopen-parser/src/collector/mod.rs` | Embedded/profile parity tests |
| `scripts/collection/intune-evidence-profile.json` | Targeted ESP evidence profile parity |
| `references/collection/intune-evidence-profile.json` | Shipped reference profile parity |
| `scripts/collection/README.md` | Targeted collector usage and evidence contract |
| `references/collection/README.md` | Reference profile usage and evidence contract |
| `src-tauri/src/collector/artifacts.rs` | Return actual collected file records |
| `src-tauri/src/collector/manifest.rs` | Populate deterministic `artifacts[]` |
| `src-tauri/src/commands/bundle_ops.rs` | Collector-manifest serialization and path-safety tests |
| `src-tauri/src/commands/intune_bundle.rs` | Nested manifest-first Intune artifact resolution test |
| `src-tauri/src/intune/evtx_parser.rs` | Preserve named ordered EventData |
| `src-tauri/src/watcher/tail.rs` | Optional compatible tail-reader extraction only if reuse requires it |
| `src-tauri/src/graph_api.rs` | WAM scope/capability-aware root module |
| `src-tauri/src/commands/graph_api.rs` | ESP Graph fetch/cancel commands |
| `src-tauri/src/state/app_state.rs` | One managed ESP live-session slot |
| `src-tauri/src/commands/mod.rs` | Export ESP commands |
| `src-tauri/src/commands/app_config.rs` | Feature/platform workspace availability |
| `src-tauri/src/lib.rs` | Modules, managed state, command registration, shutdown cleanup |
| `src-tauri/src/ipc_bridge.rs` | Local ESP fixture commands only; reject Graph ESP commands |
| `src-tauri/Cargo.toml` | `esp-diagnostics` feature and Windows API features/dependencies |
| `Cargo.lock` | Reproducible archive dependencies and Rust 1.77.2-compatible `time` resolution |
| `src/types/log.ts` | Add `esp-diagnostics` workspace ID |
| `src/workspaces/types.ts` | Sidebar visibility and lazy toolbar/status slots |
| `src/workspaces/registry.ts` | Register ESP workspace |
| `src/stores/ui-store.test.ts` | Backend/platform workspace availability behavior |
| `src/workspaces/event-log/index.ts` | Replace event-log shell hardcode with `sidebar: false` |
| `src/components/layout/AppShell.tsx` | Registry sidebar behavior and global ESP listener |
| `src/components/layout/Toolbar.tsx` | Render lazy registry toolbar action |
| `src/components/layout/StatusBar.tsx` | Render lazy registry status content |
| `src/lib/commands.ts` | Typed local/live/Graph/relaunch wrappers |
| `src/components/dialogs/settings/GraphApiTab.tsx` | Scopes, capabilities, beta/privacy/partial UX |
| `e2e/fixtures/tauri-shim.ts` | Deterministic local ESP command/event behavior |
| `e2e/fixtures/screenshot-data.ts` | Sanitized approved cockpit screenshot state |
| `e2e/screenshots/capture.spec.ts` | Capture ESP workspace in actual app chrome |
| `README.md` | Workspace, elevation, Graph, and read-only documentation |
| `CHANGELOG.md` | Shipped feature and privacy notes |
| `docs/superpowers/specs/2026-07-15-esp-diagnostics-workspace-design.md` | Approved contract and implementation drift record |
| `docs/superpowers/plans/2026-07-15-esp-diagnostics-workspace.md` | Executed checklist and verification evidence |
| `.github/workflows/cmtrace-ci.yml` | Compile and test Windows-only ESP, WAM, Graph, registry, event, and process paths |

---

## Task 0: Isolate the implementation and establish baselines

**Files:** No source edits. The design and plan documents are copied into the new worktree with `apply_patch` before the first implementation commit.

- [x] **Step 1: Re-read the worktree skill and create the isolated branch**

Run from `/Users/Adam.Gell/repo/cmtraceopen`:

```bash
git status --short --branch
git fetch origin main
git worktree add /Users/Adam.Gell/repo/cmtraceopen-esp-diagnostics -b codex/esp-diagnostics origin/main
```

Expected: the original checkout remains on `pr/260`; the new visible sibling worktree is on `codex/esp-diagnostics` based on the fetched `origin/main`.

- [x] **Step 2: Copy this plan and its spec into the worktree with `apply_patch`**

Expected paths:

```text
/Users/Adam.Gell/repo/cmtraceopen-esp-diagnostics/docs/superpowers/plans/2026-07-15-esp-diagnostics-workspace.md
/Users/Adam.Gell/repo/cmtraceopen-esp-diagnostics/docs/superpowers/specs/2026-07-15-esp-diagnostics-workspace-design.md
```

- [ ] **Step 3: Install dependencies and run clean baselines**

```bash
npm ci
npx tsc --noEmit
npm test
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Expected: all baseline checks pass. If a baseline fails on untouched `origin/main`, record the exact failure before any feature edit and route it through `superpowers:systematic-debugging`.

- [x] **Step 4: Commit only the approved design and plan**

```bash
git add -f docs/superpowers/plans/2026-07-15-esp-diagnostics-workspace.md docs/superpowers/specs/2026-07-15-esp-diagnostics-workspace-design.md
git commit -m "docs: define ESP diagnostics workspace"
```

- [ ] **Step 5: Checkpoint**

Show baseline evidence and the isolated worktree path. The active goal remains the complete deliverable.

## Task 1: Satisfy structural cleanup gates before adding extension seams

### Phase 1A — shell cleanup

**Files:**

- Modify only if confirmed dead: `src/components/layout/AppShell.tsx`
- Modify only if confirmed dead: `src/components/layout/Toolbar.tsx`
- Modify only if confirmed dead: `src/components/layout/StatusBar.tsx`

- [x] **Step 1: Audit direct, type, dynamic, export, string, and test references**

```bash
rg -n "AppShell|Toolbar|StatusBar|useAppActions|renderWorkspace|activeViewLabel" src e2e
npx tsc --noEmit --noUnusedLocals --noUnusedParameters
```

Expected: a concrete list of dead imports/props/exports/logs or a recorded no-op audit. Do not alter behavior in this phase.

- [x] **Step 2: Remove only proven dead code and run shell tests**

```bash
npx tsc --noEmit
npm test -- src/stores/ui-store.test.ts src/components/log-view/LogListView.test.tsx
```

Expected: pass with no workspace or shell behavior change.

- [x] **Step 3: Commit cleanup separately if anything changed**

```bash
git add src/components/layout/AppShell.tsx src/components/layout/Toolbar.tsx src/components/layout/StatusBar.tsx
git commit -m "chore: clean app shell before workspace slots"
```

### Phase 1B — Graph cleanup

**Files:**

- Modify only if confirmed dead: `src-tauri/src/graph_api.rs`

- [ ] **Step 1: Audit token, cache, HTTP, DTO, and test references**

```bash
rg -n "GraphAuthState|CachedToken|fetch_apps_batch|fetch_single_app|GRAPH_BETA_BASE|graph_" src-tauri/src src-tauri/tests
cargo check -p cmtrace-open --all-features
```

- [ ] **Step 2: Remove only proven dead code/debug output, then verify**

```bash
cargo fmt --all -- --check
cargo test -p cmtrace-open --all-features graph_api
cargo clippy -p cmtrace-open --all-targets --all-features -- -D warnings
```

- [ ] **Step 3: Commit cleanup separately if anything changed**

```bash
git add src-tauri/src/graph_api.rs
git commit -m "chore: clean Graph module before ESP expansion"
```

- [ ] **Step 4: Checkpoint**

Show exact cleanup/no-op evidence before beginning structural changes.

## Task 2: Repair the collector artifact contract before offline analysis

### Phase 2A — collected-file model and deterministic manifest

**Files:**

- Modify: `crates/cmtraceopen-parser/src/collector/types.rs`
- Modify: `src-tauri/src/collector/artifacts.rs`
- Modify: `src-tauri/src/collector/manifest.rs`
- Modify tests in: `src-tauri/src/commands/bundle_ops.rs`
- Modify tests in: `src-tauri/src/commands/intune_bundle.rs`

- [x] **Step 1: Write failing tests**

Add these exact tests:

```text
collector_manifest_serializes_each_globbed_file
manifest_artifacts_are_sorted_and_root_relative
nested_built_in_intune_logs_resolve_from_manifest
artifact_relative_path_cannot_escape_bundle_root
```

The expected `ArtifactResult` shape is:

```rust
pub struct CollectedArtifactFile {
    pub relative_path: String,
    pub origin_path: Option<String>,
    pub bytes_copied: u64,
}

pub struct ArtifactResult {
    pub id: String,
    pub category: String,
    pub family: String,
    pub parse_hints: Vec<String>,
    pub notes: Option<String>,
    pub status: ArtifactStatus,
    pub files: Vec<CollectedArtifactFile>,
    pub error: Option<String>,
}
```

- [x] **Step 2: Run the focused tests and confirm failure**

```bash
cargo test -p cmtrace-open --all-features collector_manifest_serializes_each_globbed_file -- --nocapture
cargo test -p cmtrace-open --all-features nested_built_in_intune_logs_resolve_from_manifest -- --nocapture
```

Expected: fail because `artifacts[]` is currently empty and nested files are not represented.

- [x] **Step 3: Implement the file-record and manifest behavior**

Only actual collected files enter `artifacts[]`. Missing/failed sources remain in `collection.results.gaps`. Canonicalize bundle-root membership, store slash-normalized root-relative paths, and sort by `relativePath`, then `artifactId`. Add `parse_hints` to the collection-item and result structs in `collector/types.rs` with `#[serde(default)]` so profiles that predate `parseHints` remain valid; Phase 2B pins profile validation and backwards compatibility.

- [x] **Step 4: Run focused and package tests**

```bash
cargo test -p cmtrace-open --all-features collector::
cargo test -p cmtrace-open --all-features bundle_ops::
cargo test -p cmtrace-open --all-features intune_bundle::
cargo clippy -p cmtrace-open --all-targets --all-features -- -D warnings
```

- [x] **Step 5: Commit**

```bash
git add crates/cmtraceopen-parser/src/collector/types.rs src-tauri/src/collector/artifacts.rs src-tauri/src/collector/manifest.rs src-tauri/src/commands/bundle_ops.rs src-tauri/src/commands/intune_bundle.rs
git commit -m "fix: enumerate collected evidence artifacts"
```

### Phase 2B — ESP collection profile parity

**Files:**

- Modify: `crates/cmtraceopen-parser/src/collector/profile.rs`
- Modify: `crates/cmtraceopen-parser/src/collector/profile_data.json`
- Modify tests in: `crates/cmtraceopen-parser/src/collector/mod.rs`

- [x] **Step 1: Write failing profile tests**

Add:

```text
esp_profile_has_required_registry_families
esp_profile_has_wmansvc_autopilot_json
esp_profile_has_structured_hardware_and_do_outputs
profile_parse_hints_are_backward_compatible
esp_profile_artifact_ids_are_unique
```

Required additions cover `EnterpriseDesktopAppManagement`, `OfficeCSP`, Provisioning diagnostics/settings/OMADM/NodeCache, EnrollmentStatusTracking, Enrollments/FirstSync, IME/Win32Apps, the exact `ServiceState\wmansvc\AutopilotDDSZTDFile.json`, structured OS/hardware/TPM output, and filtered Delivery Optimization output.

- [x] **Step 2: Confirm red, implement, and verify**

```bash
cargo test -p cmtraceopen-parser collector:: -- --nocapture
cargo fmt --all -- --check
cargo clippy -p cmtraceopen-parser --all-targets -- -D warnings
```

Expected: tests pass and older profile JSON without `parseHints` still deserializes.

- [x] **Step 3: Commit and checkpoint**

```bash
git add crates/cmtraceopen-parser/src/collector/profile.rs crates/cmtraceopen-parser/src/collector/profile_data.json crates/cmtraceopen-parser/src/collector/mod.rs
git commit -m "feat: complete ESP evidence collection profile"
```

Show a generated manifest with populated artifacts before parser work begins.

### Phase 2C — synchronize targeted and reference collection profiles

**Files:**

- Modify: `scripts/collection/intune-evidence-profile.json`
- Modify: `references/collection/intune-evidence-profile.json`
- Modify: `scripts/collection/README.md`
- Modify: `references/collection/README.md`
- Modify tests in: `crates/cmtraceopen-parser/src/collector/mod.rs`

- [x] **Step 1: Write failing cross-profile parity tests**

Normalize the applicable ESP artifact IDs, registry roots, event channels, export paths, and command-output contracts from the targeted, reference, and embedded profiles. Assert that each contains the required evidence families and that duplicate parent/child exports are explicitly de-duplicated.

- [x] **Step 2: Synchronize the shipped profiles**

Bring the targeted/reference versions and contents into alignment. Add `EnterpriseDesktopAppManagement`, `OfficeCSP`, exact `ServiceState\wmansvc\AutopilotDDSZTDFile.json`, structured hardware facts, and filtered DO output where missing. Document read-only capture, sensitive fields, and the fact that raw hardware hash is excluded from normal analysis.

- [x] **Step 3: Verify and commit**

```bash
cargo test -p cmtraceopen-parser collector::cross_profile_ -- --nocapture
git diff --check
git add scripts/collection/intune-evidence-profile.json references/collection/intune-evidence-profile.json scripts/collection/README.md references/collection/README.md crates/cmtraceopen-parser/src/collector/mod.rs
git commit -m "fix: synchronize ESP evidence profiles"
```

- [x] **Step 4: Checkpoint**

Show the normalized cross-profile parity output before parser work begins.

## Task 3: Create the complete ESP data model and normalization dictionaries

### Phase 3A — models and serialization

**Files:**

- Create: `crates/cmtraceopen-parser/src/esp/mod.rs`
- Create: `crates/cmtraceopen-parser/src/esp/models.rs`
- Modify: `crates/cmtraceopen-parser/src/lib.rs`
- Create: `crates/cmtraceopen-parser/tests/esp_diagnostics.rs`

- [x] **Step 1: Write compile-time and serialization tests first**

Add tests for camelCase JSON, every enum variant, evidence provenance, sensitivity, coverage, raw/normalized separation, `schemaVersion = 1`, and every `GraphSection<T>` state/API-version/error shape embedded in `EspGraphOverlay`.

- [x] **Step 2: Confirm the module is missing**

```bash
cargo test -p cmtraceopen-parser --test esp_diagnostics models_serialize_camel_case -- --nocapture
```

Expected: compilation fails because `cmtraceopen_parser::esp` does not exist.

- [x] **Step 3: Implement all supporting DTOs referenced by the core contract**

The model must include identity, profile, ten OOBE booleans, enrollments, device/user scope, classic and v2 sessions, every tracked kind, raw/normalized status, workload timestamps, exit/enforcement codes, NodeCache, registration, DO, hardware, process observations, installer correlation, timeline, coverage, raw evidence, findings, and the parser-owned Graph overlay/section/status/API-version/error types.

- [x] **Step 4: Verify and commit**

```bash
cargo test -p cmtraceopen-parser --test esp_diagnostics models_ -- --nocapture
cargo fmt --all -- --check
cargo clippy -p cmtraceopen-parser --all-targets -- -D warnings
git add crates/cmtraceopen-parser/src/esp crates/cmtraceopen-parser/src/lib.rs crates/cmtraceopen-parser/tests/esp_diagnostics.rs
git commit -m "feat: define ESP diagnostics evidence contract"
```

### Phase 3B — exact status, URI, OOBE, and timestamp normalization

**Files:**

- Create: `crates/cmtraceopen-parser/src/esp/normalize.rs`
- Modify: `crates/cmtraceopen-parser/src/esp/mod.rs`
- Modify: `crates/cmtraceopen-parser/tests/esp_diagnostics.rs`
- Create: `crates/cmtraceopen-parser/tests/fixtures/esp/normalization-cases.json`

- [x] **Step 1: Add failing table-driven tests**

Pin:

- Office states `0,10,20,25,30,40,48,50,55,60,70`;
- classic ESP states `1,2,3,4`;
- policy states `0,1`;
- v2 states `NotStarted,Completed,Skipped,Uninstalled,Failed,InProgress,RebootRequired,Cancelled`;
- unknown numeric/string preservation;
- URI unescaping and GUID extraction;
- all ten `CloudAssignedOobeConfig` bits with raw mask retention;
- local, UTC, offset, and unspecified timestamps;
- detailed Office failure overriding an outer processed state.

- [x] **Step 2: Confirm failure, implement pure functions, and verify**

```bash
cargo test -p cmtraceopen-parser --test esp_diagnostics normalization_ -- --nocapture
```

Expected before implementation: missing functions. Expected after implementation: every table row passes and no unknown raw value is discarded.

- [x] **Step 3: Commit and checkpoint**

```bash
git add crates/cmtraceopen-parser/src/esp/normalize.rs crates/cmtraceopen-parser/src/esp/mod.rs crates/cmtraceopen-parser/tests/esp_diagnostics.rs crates/cmtraceopen-parser/tests/fixtures/esp/normalization-cases.json
git commit -m "feat: normalize ESP statuses and profile settings"
```

Show the serialized model and dictionary coverage.

## Task 4: Implement scenario, session, workload, and timeline parity

### Phase 4A — reducer and non-deduplicating timeline

**Files:**

- Create: `crates/cmtraceopen-parser/src/esp/reducer.rs`
- Create: `crates/cmtraceopen-parser/src/esp/timeline.rs`
- Modify: `crates/cmtraceopen-parser/src/esp/mod.rs`
- Modify: `crates/cmtraceopen-parser/tests/esp_diagnostics.rs`
- Create: `crates/cmtraceopen-parser/tests/fixtures/esp/scenario-cases.json`

- [x] **Step 1: Write failing scenario tests**

Cover all five scenarios, classic device and two-user sessions, out-of-order session keys, latest-session selection by chronology, Autopilot Device Preparation isolation, ESP-only with no IME logs, and no false success from absent evidence.

- [x] **Step 2: Write failing workload and timeline tests**

Cover MSI, Office, UWP, Win32, policy, SCEP certificate, platform script, v2 workload, exit/enforcement codes, profile download, ODJ, registration, Delivery Optimization, and repeated identical retries that must remain distinct stable entries.

- [x] **Step 3: Confirm red and implement the reducer**

```bash
cargo test -p cmtraceopen-parser --test esp_diagnostics reducer_ -- --nocapture
cargo test -p cmtraceopen-parser --test esp_diagnostics timeline_ -- --nocapture
```

The reducer indexes by source identity and session/workload identity, never by display name alone. `snapshot()` is deterministic for the same ordered evidence input.

- [x] **Step 4: Verify and commit**

```bash
cargo test -p cmtraceopen-parser --test esp_diagnostics
cargo fmt --all -- --check
cargo clippy -p cmtraceopen-parser --all-targets -- -D warnings
git add crates/cmtraceopen-parser/src/esp/reducer.rs crates/cmtraceopen-parser/src/esp/timeline.rs crates/cmtraceopen-parser/src/esp/mod.rs crates/cmtraceopen-parser/tests/esp_diagnostics.rs crates/cmtraceopen-parser/tests/fixtures/esp/scenario-cases.json
git commit -m "feat: reduce ESP sessions and timeline evidence"
```

### Phase 4B — edge-case parity

**Files:**

- Modify: `crates/cmtraceopen-parser/tests/esp_diagnostics.rs`
- Create: `crates/cmtraceopen-parser/tests/fixtures/esp/edge-cases.json`
- Create: `crates/cmtraceopen-parser/tests/fixtures/esp/graph-cases.json`
- Create: `crates/cmtraceopen-parser/tests/fixtures/esp/bundle-live-equivalence.json`

- [x] **Step 1: Add the remaining parity cases**

Pin NodeCache keys `2,10,42` with key `0` absent; malformed PageSettings/ProvisioningProgress/enforcement JSON; unknown states; permission-denied roots; sensitive fields; partial Graph names; captured/live logical equivalence; event IDs `72,100,101,107,109,110,111,304,306,1905,1906,1920,1922,1924`; and raw hardware-hash exclusion.

- [x] **Step 2: Run the full parity suite**

```bash
cargo test -p cmtraceopen-parser --test esp_diagnostics -- --nocapture
```

Expected: every raw field, normalized status, source reference, timestamp, and stable entry ID is asserted; tests do not rely only on counts.

- [x] **Step 3: Commit and checkpoint**

```bash
git add crates/cmtraceopen-parser/tests/esp_diagnostics.rs crates/cmtraceopen-parser/tests/fixtures/esp/edge-cases.json crates/cmtraceopen-parser/tests/fixtures/esp/graph-cases.json crates/cmtraceopen-parser/tests/fixtures/esp/bundle-live-equivalence.json
git commit -m "test: lock ESP diagnostics script parity"
```

Show the parity checklist before adding native I/O.

## Task 5: Add evidence-backed findings, redaction, and process correlation

### Phase 5A — rules and redaction

**Files:**

- Create: `crates/cmtraceopen-parser/src/esp/rules.rs`
- Create: `crates/cmtraceopen-parser/src/esp/redaction.rs`
- Modify: `crates/cmtraceopen-parser/src/esp/mod.rs`
- Modify: `crates/cmtraceopen-parser/tests/esp_diagnostics.rs`

- [x] **Step 1: Write failing finding tests**

Cover failed blocking app, stalled download/install, ESP timeout, failed registration/join, policy/certificate not processed, IME evidence missing, non-elevated coverage loss, ambiguous installer, inconsistent local/Graph state, malformed source, and successful completion with no fabricated warning.

Each assertion pins `finding_id`, severity, confidence, recommended check text, and at least one evidence or coverage-gap reference.

- [x] **Step 2: Write failing redaction tests**

Mask UPN, SID, tenant, EntDMID, serial, NodeCache payload, and secret-like command-line arguments by default. Remove tokens, authorization headers, raw Graph responses, and raw hardware hashes entirely.

- [x] **Step 3: Implement, verify, and commit**

```bash
cargo test -p cmtraceopen-parser --test esp_diagnostics findings_ -- --nocapture
cargo test -p cmtraceopen-parser --test esp_diagnostics redaction_ -- --nocapture
cargo clippy -p cmtraceopen-parser --all-targets -- -D warnings
git add crates/cmtraceopen-parser/src/esp/rules.rs crates/cmtraceopen-parser/src/esp/redaction.rs crates/cmtraceopen-parser/src/esp/mod.rs crates/cmtraceopen-parser/tests/esp_diagnostics.rs
git commit -m "feat: derive safe ESP diagnostic findings"
```

### Phase 5B — pure installer/process correlation

**Files:**

- Create: `crates/cmtraceopen-parser/src/esp/correlation.rs`
- Modify: `crates/cmtraceopen-parser/src/esp/mod.rs`
- Modify: `crates/cmtraceopen-parser/src/esp/reducer.rs`
- Modify: `crates/cmtraceopen-parser/tests/esp_diagnostics.rs`

- [x] **Step 1: Write failing correlation tests**

Test quoted and unquoted `/L`, `/L*V`, `/log`, mixed-case switches, exact canonical log path, IME/AgentExecutor parent PID chain, exact app GUID/product code, PID reuse guarded by process start time, one temporal match, multiple candidates remaining uncorrelated, and sanitized command-line evidence.

- [x] **Step 2: Implement the exact precedence contract**

Never infer correlation from time when an exact contradictory identifier exists. Return reasons and evidence for every confidence result.

- [x] **Step 3: Verify, commit, and checkpoint**

```bash
cargo test -p cmtraceopen-parser --test esp_diagnostics correlation_ -- --nocapture
cargo test -p cmtraceopen-parser
cargo fmt --all -- --check
git add crates/cmtraceopen-parser/src/esp/correlation.rs crates/cmtraceopen-parser/src/esp/mod.rs crates/cmtraceopen-parser/src/esp/reducer.rs crates/cmtraceopen-parser/tests/esp_diagnostics.rs
git commit -m "feat: correlate MSI activity with ESP workloads"
```

Show exact, temporal, and ambiguous correlation outputs.

## Task 6: Add read-only Windows registry, event, system, and process acquisition

### Phase 6A — module/feature wiring and registry acquisition

**Files:**

- Create: `src-tauri/src/esp/mod.rs`
- Create: `src-tauri/src/esp/registry.rs`
- Modify: `src-tauri/Cargo.toml`
- Modify: `src-tauri/src/lib.rs`
- Create: `src-tauri/tests/esp_diagnostics_sources.rs`

- [x] **Step 1: Write failing registry acquisition tests against fake snapshots**

Pin `KEY_READ | KEY_WOW64_64KEY`, depth/value-size caps, numeric NodeCache ordering with gaps, per-root permission errors, device/user branch separation, uninstall-name lookup only for observed product codes, and no registry write/import API in the module.

Target roots:

```text
HKLM\SOFTWARE\Microsoft\Provisioning\Diagnostics\Autopilot
HKLM\SOFTWARE\Microsoft\Provisioning\AutopilotSettings
HKLM\SOFTWARE\Microsoft\Provisioning\OMADM
HKLM\SOFTWARE\Microsoft\Provisioning\NodeCache\CSP
HKLM\SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking
HKLM\SOFTWARE\Microsoft\Enrollments
HKLM\SOFTWARE\Microsoft\EnterpriseDesktopAppManagement
HKLM\SOFTWARE\Microsoft\OfficeCSP
HKLM\SOFTWARE\Microsoft\IntuneManagementExtension
```

- [x] **Step 2: Add the feature and module root**

Add `esp-diagnostics = ["intune-diagnostics"]` without adding it to `full` yet. Export `esp` behind that feature and expose a cross-platform offline capability plus Windows-only live capability.

- [x] **Step 3: Confirm red, implement, and verify**

```bash
cargo test -p cmtrace-open --all-features --test esp_diagnostics_sources registry_ -- --nocapture
cargo check -p cmtrace-open --no-default-features --features esp-diagnostics
```

Missing Autopilot keys are `Missing`, not fatal. Access-denied keys are `PermissionDenied`. Registry observations retain exact hive/key/value provenance.

- [x] **Step 4: Commit**

```bash
git add src-tauri/src/esp/mod.rs src-tauri/src/esp/registry.rs src-tauri/Cargo.toml src-tauri/src/lib.rs src-tauri/tests/esp_diagnostics_sources.rs
git commit -m "feat: collect read-only ESP registry evidence"
```

### Phase 6B — named event-data acquisition

**Files:**

- Create: `src-tauri/src/esp/event_logs.rs`
- Modify: `src-tauri/src/esp/mod.rs`
- Modify: `src-tauri/src/intune/evtx_parser.rs`
- Modify: `src-tauri/tests/esp_diagnostics_sources.rs`

- [x] **Step 1: Write failing event-data tests**

Extend parsed event records with ordered `event_data: Vec<EventLogProperty>` containing name and value. Pin all 14 required IDs and deterministic fields for event 109/110 state, MSI product code, app/policy ID, result code, and record ID.

- [x] **Step 2: Implement live/captured event normalization**

Reuse the existing live channel reader and EVTX parser. Missing channels are coverage gaps. Access denied is distinct. Event records retain channel, event ID, record ID, source timestamp, named fields, and raw message provenance.

- [x] **Step 3: Verify and commit**

```bash
cargo test -p cmtrace-open --all-features --test esp_diagnostics_sources event_ -- --nocapture
cargo test -p cmtrace-open --all-features intune::evtx_parser::
git add src-tauri/src/esp/event_logs.rs src-tauri/src/esp/mod.rs src-tauri/src/intune/evtx_parser.rs src-tauri/tests/esp_diagnostics_sources.rs
git commit -m "feat: collect ESP event evidence"
```

### Phase 6C — elevation, system facts, and allowlisted process sampling

**Files:**

- Modify: `src-tauri/src/esp/mod.rs`
- Create: `src-tauri/src/esp/system.rs`
- Create: `src-tauri/src/esp/process.rs`
- Create: `src-tauri/src/esp/process_win32.rs`
- Modify: `src-tauri/Cargo.toml`

- [x] **Step 1: Write failing unit tests inside the new modules**

Cover elevation supported/elevated/non-elevated/error, hardware value parsing, DO counter semantics, timeout/partial source behavior, process allowlisting, PID/start-time identity, parent chain, command-line sanitization, and non-Windows unsupported capability.

- [x] **Step 2: Add only required Windows API features**

Add `Win32_Security_Authorization`, `Win32_System_Threading`, `Win32_System_Com`, `Win32_System_Ole`, `Win32_System_Variant`, `Win32_System_Wmi`, `Win32_UI_Shell` for the later explicit `runas` relaunch, and the process-query features actually required by the implementation. Do not enable unrelated feature groups.

- [x] **Step 3: Implement read-only providers**

Collect elevation, hostname/OS/build, manufacturer/model/serial, TPM version, IME service/process observation, and DO counters/log observations. Prefer Windows/WMI APIs. Any read-only command fallback is non-interactive, has a fixed executable/argument allowlist, captures structured JSON, and times out. Never collect or return the raw hardware hash.

Process sampling is limited to:

```text
IntuneManagementExtension.exe
AgentExecutor.exe
msiexec.exe
winget.exe
installer image names explicitly referenced by local IME policy evidence
```

- [x] **Step 4: Verify Windows-gated and cross-platform builds**

```bash
cargo test -p cmtrace-open --all-features esp::system::
cargo test -p cmtrace-open --all-features esp::process::
cargo check -p cmtrace-open --no-default-features --features esp-diagnostics
cargo clippy -p cmtrace-open --all-targets --all-features -- -D warnings
```

- [x] **Step 5: Commit and checkpoint**

```bash
git add src-tauri/src/esp/mod.rs src-tauri/src/esp/system.rs src-tauri/src/esp/process.rs src-tauri/src/esp/process_win32.rs src-tauri/Cargo.toml
git commit -m "feat: observe ESP system and installer processes"
```

Show non-elevated partial coverage and at least zero/one/multiple MSI process snapshots.

## Task 7: Implement bounded known/temp discovery and multi-file live tails

### Phase 7A — bounded discovery

**Files:**

- Create: `src-tauri/src/esp/discovery.rs`
- Modify: `src-tauri/src/esp/mod.rs`
- Modify tests in: `src-tauri/tests/esp_diagnostics_sources.rs`

- [x] **Step 1: Write failing discovery tests with temporary directories**

Add:

```text
discovery_uses_embedded_known_source_families
temp_discovery_is_non_recursive
temp_discovery_inspects_only_128_newest_entries
temp_discovery_excludes_files_older_than_30_minutes
discovery_caps_rotations_at_three_per_stem
discovery_rejects_symlink_or_reparse_escape
discovery_accepts_msi_signature_in_first_4k
discovery_accepts_explicit_running_process_log
discovery_has_no_arbitrary_root_or_deep_mode
```

- [x] **Step 2: Implement fixed limits**

```rust
pub const MAX_ROTATIONS_PER_KNOWN_LOG: usize = 3;
pub const MAX_TEMP_ENTRIES_INSPECTED_PER_ROOT: usize = 128;
pub const MAX_ACTIVE_TAILS: usize = 16;
pub const MAX_INITIAL_READ_BYTES: u64 = 8 * 1024 * 1024;
pub const TEMP_LOOKBACK: Duration = Duration::from_secs(30 * 60);
pub const DISCOVERY_INTERVAL: Duration = Duration::from_secs(2);
pub const UPDATE_DEBOUNCE: Duration = Duration::from_millis(250);
pub const MAX_SESSION_DURATION: Duration = Duration::from_secs(8 * 60 * 60);
```

Derive stable deployment roots/families from the embedded collector profile rather than cloning its catalog. Add runtime `%WINDIR%\Temp`, SYSTEM temp, current `%TEMP%`, and active ProfileList user temp roots. Temp inspection is never recursive.

Known high-signal sources include IME, ConfigMgr application/content/update logs, Patch My PC, PSAppDeployToolkit, MSI, WinGet, and Windows deployment/reporting logs from existing profile families. Current IME logs win priority over rotations and temp candidates.

- [x] **Step 3: Verify and commit**

```bash
cargo test -p cmtrace-open --all-features --test esp_diagnostics_sources discovery_ -- --nocapture
cargo clippy -p cmtrace-open --all-targets --all-features -- -D warnings
git add src-tauri/src/esp/discovery.rs src-tauri/src/esp/mod.rs src-tauri/tests/esp_diagnostics_sources.rs
git commit -m "feat: bound ESP deployment log discovery"
```

### Phase 7B — ESP-owned multi-file tailing

**Files:**

- Create: `src-tauri/src/esp/tailing.rs`
- Modify: `src-tauri/src/esp/mod.rs`
- Modify tests in: `src-tauri/tests/esp_diagnostics_sources.rs`
- Modify only if reuse requires a compatible extraction: `src-tauri/src/watcher/tail.rs`

- [x] **Step 1: Write failing tail tests**

Cover final-8-MiB initial context, shared read/write/delete behavior on Windows, appended bytes, UTF-8/Windows-1252 handling, partial records, truncation reset, rotation reset, source attachment once, known-source priority, 16-tail cap, and stop cleanup.

- [x] **Step 2: Implement without using the Log Explorer tail-session map**

Reuse `TailReader` semantics where compatible, but ESP owns its handles because one diagnostic session tails many sources. Known rotations are snapshot-parsed; only current files and newest explicitly active MSI logs are tailed.

- [x] **Step 3: Verify, commit, and checkpoint**

```bash
cargo test -p cmtrace-open --all-features --test esp_diagnostics_sources tail_ -- --nocapture
cargo test -p cmtrace-open --all-features watcher::tail::
cargo fmt --all -- --check
git add src-tauri/src/esp/tailing.rs src-tauri/src/esp/mod.rs src-tauri/tests/esp_diagnostics_sources.rs src-tauri/src/watcher/tail.rs
git commit -m "feat: tail bounded ESP evidence sources"
```

If `watcher/tail.rs` did not change, omit it from `git add`. Show rotation/truncation provenance and tail-cap ordering.

## Task 8: Build the cancellable native live-session service and IPC

### Phase 8A — session lifecycle and managed state

**Files:**

- Create: `src-tauri/src/esp/session.rs`
- Modify: `src-tauri/src/esp/mod.rs`
- Modify: `src-tauri/src/state/app_state.rs`
- Create: `src-tauri/src/commands/esp_diagnostics.rs`
- Modify tests in: `src-tauri/tests/esp_diagnostics_sources.rs`

- [x] **Step 1: Write failing fake-provider session tests**

Inject fake clock, discovery, registry/event/system/process providers, tail factory, and event sink. Pin one-session conflict, monotonic sequence, request/session IDs, 250-ms debounce, two-second discovery, source attachment once, 16-tail priority, rotation replacement, late callback rejection after stop, stop/join, eight-hour expiration, partial source errors, and no lock held during I/O/emission.

- [x] **Step 2: Confirm red and implement the service**

```bash
cargo test -p cmtrace-open --all-features --test esp_diagnostics_sources session_ -- --nocapture
```

The initial command returns a usable local snapshot, then emits updates. Graph work is scheduled independently and cannot block the first local snapshot.

- [x] **Step 3: Implement thin commands and typed errors**

Commands validate IDs and path mode, then delegate. Starting live on non-Windows returns `UnsupportedPlatform`. Starting while active returns `SessionConflict { existingSessionId }`. There is no `includeGraph` request field and no Graph dependency in the native ESP session; local startup never waits for remote work.

- [x] **Step 4: Verify and commit**

```bash
cargo test -p cmtrace-open --all-features --test esp_diagnostics_sources session_
cargo clippy -p cmtrace-open --all-targets --all-features -- -D warnings
git add src-tauri/src/esp/session.rs src-tauri/src/esp/mod.rs src-tauri/src/state/app_state.rs src-tauri/src/commands/esp_diagnostics.rs src-tauri/tests/esp_diagnostics_sources.rs
git commit -m "feat: manage live ESP diagnostic sessions"
```

### Phase 8B — feature, command, shutdown, and bridge wiring

**Files:**

- Modify: `src-tauri/src/lib.rs`
- Modify: `src-tauri/src/commands/mod.rs`
- Modify including tests: `src-tauri/src/commands/app_config.rs`
- Modify: `src-tauri/src/ipc_bridge.rs`
- Modify: `src-tauri/Cargo.toml`

- [x] **Step 1: Write failing feature/availability tests**

Full builds expose `esp-diagnostics`; lite builds do not. Offline analysis is reported cross-platform. Live capability reports Windows only. Shutdown stops and joins a session.

- [x] **Step 2: Register commands and lifecycle cleanup**

Add the existing `esp-diagnostics` feature to `full`. Register local ESP commands. The debug bridge may support sanitized fixture-driven local analysis/live events but explicitly rejects Graph ESP commands.

- [x] **Step 3: Verify full and minimal feature sets**

```bash
cargo test -p cmtrace-open --all-features app_config::
cargo check -p cmtrace-open --no-default-features
cargo check -p cmtrace-open --no-default-features --features esp-diagnostics
cargo test -p cmtrace-open --all-features
```

- [x] **Step 4: Commit and checkpoint**

```bash
git add src-tauri/src/lib.rs src-tauri/src/commands/mod.rs src-tauri/src/commands/app_config.rs src-tauri/src/ipc_bridge.rs src-tauri/Cargo.toml
git commit -m "feat: expose ESP diagnostics native capability"
```

Show live start/get/stop payloads and non-Windows typed behavior.

### Phase 8C — explicit restart-as-administrator path

**Files:**

- Create: `src-tauri/src/esp/relaunch.rs`
- Modify: `src-tauri/src/esp/mod.rs`
- Modify: `src-tauri/src/commands/esp_diagnostics.rs`
- Modify: `src-tauri/src/lib.rs`
- Modify tests in: `src-tauri/tests/esp_diagnostics_sources.rs`

- [x] **Step 1: Write failing relaunch-provider tests**

Inject a fake relaunch provider and pin already-elevated behavior, `ShellExecuteExW` request shape with verb `runas`, Windows-safe quoting, allowlisted startup-argument preservation, NUL/secret-bearing argument rejection, UAC cancellation, launch failure, non-Windows `UnsupportedPlatform`, and the rule that the current process remains alive unless the elevated child launch succeeds.

- [x] **Step 2: Implement the explicit user action**

`restart_esp_as_administrator` is invoked only from the elevation banner. On Windows it resolves the current executable, forwards only allowlisted app-owned startup flags needed to reopen `esp-diagnostics`, uses `ShellExecuteExW` with `SEE_MASK_NOCLOSEPROCESS`, closes the returned process handle, and asks Tauri to exit only after launch success. It returns typed `AlreadyElevated`, `ElevationCancelled`, `UnsafeArgument`, and `LaunchFailed` results. It never forwards tokens, authorization data, arbitrary shell text, or untrusted evidence paths.

- [x] **Step 3: Verify and commit**

```bash
cargo test -p cmtrace-open --all-features --test esp_diagnostics_sources relaunch_ -- --nocapture
cargo check -p cmtrace-open --no-default-features --features esp-diagnostics
cargo clippy -p cmtrace-open --all-targets --all-features -- -D warnings
git add src-tauri/src/esp/relaunch.rs src-tauri/src/esp/mod.rs src-tauri/src/commands/esp_diagnostics.rs src-tauri/src/lib.rs src-tauri/tests/esp_diagnostics_sources.rs
git commit -m "feat: restart ESP diagnostics as administrator"
```

- [x] **Step 4: Checkpoint**

Show fake-provider success/cancel/failure evidence. Defer the real UAC prompt to Windows acceptance; do not trigger it in automated tests.

## Task 9: Add safe captured bundle and MDM CAB/ZIP analysis

### Phase 9A — pinned archive dependencies and safe extraction

**Files:**

- Create: `src-tauri/src/esp/archive.rs`
- Modify: `src-tauri/src/esp/mod.rs`
- Modify: `src-tauri/Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `src-tauri/tests/esp_diagnostics_sources.rs`

- [x] **Step 1: Write failing archive-safety tests**

Use sanitized ZIP/CAB fixtures. Reject absolute paths, `..`, drive prefixes, symlinks/reparse escapes, more than 512 entries, more than 1 GiB total uncompressed data, more than 256 MiB per file, unsupported archive types, and output outside a unique temporary directory.

- [x] **Step 2: Add exact MSRV-compatible dependencies**

Add these exact entries to `src-tauri/Cargo.toml`:

```toml
zip = { version = "=2.4.2", default-features = false, features = ["deflate"] }
cab = "=0.6.0"
time = { version = "=0.3.36", default-features = false }
```

`zip` 2.4.2 declares Rust 1.73; only Deflate is enabled, excluding AES, bzip2, zstd, xz, and other unused codecs. `cab` 0.6.0 is pure Rust. The exact `time` constraint prevents `cab`, Tauri, and the existing dependency graph from resolving to a release newer than the repository's Rust 1.77.2 minimum can compile. Update and commit `Cargo.lock`; do not use floating archive versions.

- [x] **Step 3: Implement bounded extraction and direct parsing**

Extract only allowlisted evidence. Parse `.reg` content directly with the existing registry parser; never import it. Parse captured JSON/EVTX/command output without consulting the local machine. Temporary extraction is uniquely scoped and automatically removed on success, failure, cancellation, and panic unwinding.

- [ ] **Step 4: Verify the exact toolchain and commit**

```bash
rustup toolchain install 1.77.2 --profile minimal
cargo update -p time --precise 0.3.36
cargo +1.77.2 check --workspace --all-features --locked
cargo test -p cmtrace-open --all-features --test esp_diagnostics_sources archive_ -- --nocapture
cargo clippy -p cmtrace-open --all-targets --all-features -- -D warnings
git add src-tauri/src/esp/archive.rs src-tauri/src/esp/mod.rs src-tauri/Cargo.toml Cargo.lock src-tauri/tests/esp_diagnostics_sources.rs
git commit -m "feat: extract captured ESP archives safely"
```

Expected: Rust 1.77.2 check exits zero and archive rejection/cleanup tests pass. Any dependency that breaks the declared MSRV blocks this phase; do not waive the gate.

### Phase 9B — manifest-first bundle resolution

**Files:**

- Create: `src-tauri/src/esp/bundle.rs`
- Modify: `src-tauri/src/esp/mod.rs`
- Modify: `src-tauri/tests/esp_diagnostics_sources.rs`

- [x] **Step 1: Write failing bundle-resolution tests**

Cover manifest-ID/family precedence, actual nested files, sparse ESP-only bundle, missing/malformed coverage, legacy fallback bounded to depth three/256 entries, allowlisted extensions/basenames, no analyst-machine registry lookup, and bundle/live normalized equivalence.

- [x] **Step 2: Implement source-neutral bundle intake**

Resolve populated manifest artifacts first. Use the legacy fallback only inside the canonical bundle root and within its fixed limits. Feed registry, JSON, EVTX, command output, and deployment logs into the same reducer used by live evidence; do not consult equivalent facts on the analyst machine.

- [x] **Step 3: Verify and commit**

```bash
cargo test -p cmtrace-open --all-features --test esp_diagnostics_sources bundle_ -- --nocapture
cargo test -p cmtrace-open --all-features --test esp_diagnostics_sources archive_ -- --nocapture
cargo clippy -p cmtrace-open --all-targets --all-features -- -D warnings
git add src-tauri/src/esp/bundle.rs src-tauri/src/esp/mod.rs src-tauri/tests/esp_diagnostics_sources.rs
git commit -m "feat: analyze captured ESP evidence bundles"
```

- [x] **Step 4: Checkpoint**

Show equivalent conclusions for live-shaped and bundle-shaped fixtures, plus ZIP/CAB rejection and cleanup evidence.

## Task 10: Make the existing WAM connection capability-aware and harden Graph transport

### Phase 10A — make the Graph core cross-platform and keep WAM Windows-only

**Files:**

- Modify: `src-tauri/src/graph_api.rs`
- Modify: `src-tauri/src/lib.rs`
- Create: `src-tauri/src/graph_api/models.rs`
- Create: `src-tauri/tests/graph_esp_diagnostics.rs`

- [x] **Step 1: Write the failing platform-boundary test**

The current crate gates the entire `graph_api` module behind `cfg(target_os = "windows")`, so macOS/Linux cannot compile or test the new Graph models and orchestration. Add a test that imports platform-neutral Graph request/transport DTOs and round-trips them on the implementation host.

```bash
cargo test -p cmtrace-open --all-features --test graph_esp_diagnostics platform_boundary_ -- --nocapture
```

Expected before implementation: compilation fails because the module/types are unavailable off Windows.

- [x] **Step 2: Split the module boundary**

Compile the `graph_api` module shell and portable DTOs on every platform. Before removing the outer module gate, place every current `ureq`, WAM, HWND, Tauri-state, and Windows symbol/import/function behind internal `cfg(target_os = "windows")` boundaries; the portable side must not name those types. Phase 10C then extracts the reusable client/transport trait. Leave `windows`, `windows-future`, and `ureq` target-specific in `Cargo.toml`; fake transports must not depend on them.

- [x] **Step 3: Verify and commit**

```bash
cargo test -p cmtrace-open --all-features --test graph_esp_diagnostics platform_boundary_ -- --nocapture
cargo check -p cmtrace-open --all-features
cargo clippy -p cmtrace-open --all-targets --all-features -- -D warnings
git add src-tauri/src/graph_api.rs src-tauri/src/lib.rs src-tauri/src/graph_api/models.rs src-tauri/tests/graph_esp_diagnostics.rs
git commit -m "refactor: separate Graph core from Windows WAM"
```

### Phase 10B — explicit delegated read capabilities

**Files:**

- Modify: `src-tauri/src/graph_api.rs`
- Modify: `src-tauri/src/commands/graph_api.rs`
- Modify: `src/lib/commands.ts`
- Modify: `src/components/dialogs/settings/GraphApiTab.tsx`
- Create: `src/components/dialogs/settings/GraphApiTab.test.tsx`

- [x] **Step 1: Write failing auth/capability tests**

Pin full, app-only, missing-scope, expired, malformed, unacceptable-audience, both accepted Graph audiences, and tenant-mismatch token claims. Keep unsigned claim decoding/sanity checks and capability projection platform-neutral so these tests run on macOS/Linux; only actual WAM acquisition is Windows-gated. `GraphAuthStatus` must expose `grantedScopes`, `missingScopes`, `expiresAt`, `tenantId`, and per-capability availability without returning the token.

Request only these delegated read scopes:

```text
DeviceManagementManagedDevices.Read.All
DeviceManagementServiceConfig.Read.All
DeviceManagementApps.Read.All
DeviceManagementConfiguration.Read.All
DeviceManagementScripts.Read.All
```

The WAM v2 acquisition request uses the space-separated fully qualified forms and does not send a `resource` property:

```text
https://graph.microsoft.com/DeviceManagementManagedDevices.Read.All
https://graph.microsoft.com/DeviceManagementServiceConfig.Read.All
https://graph.microsoft.com/DeviceManagementApps.Read.All
https://graph.microsoft.com/DeviceManagementConfiguration.Read.All
https://graph.microsoft.com/DeviceManagementScripts.Read.All
```

Capability matching uses the short names returned in `scp`.

- [x] **Step 2: Confirm current status lacks capabilities**

```bash
cargo test -p cmtrace-open --all-features graph_auth_status_reports_capabilities -- --nocapture
npm test -- src/components/dialogs/settings/GraphApiTab.test.tsx
```

Expected: fail because current WAM resource-mode status does not report scope claims/capabilities.

- [x] **Step 3: Preserve WAM while making permission use explicit**

Keep the existing provider, public client ID, HWND-parented interaction, and memory-only cache. Decode and sanity-check unsigned `scp`, `aud`, `tid`, and `exp` only for expiry/cache/capability UX; Microsoft Graph 401/403 responses remain the authorization truth. Accept `aud` values `https://graph.microsoft.com` and `00000003-0000-0000-c000-000000000000`, derive expiry from `exp`, and remove the current fixed 50-minute fallback. Remove token-bearing `Debug` behavior. Continue current app-name enrichment when only app-read capability exists.

The existing empty-scope/resource-mode request may remain only as a compatibility path for inspecting already-granted tokens and current app-name behavior. It must never be represented as capable of requesting the five-scope consent set.

- [ ] **Step 4: Add the public-client release gate**

On a Windows test device, make one interactive WAM v2 request with the exact five fully qualified scopes and inspect the resulting short `scp` values. This live public-client feasibility result is a prerequisite to Task 11; mocked CI cannot establish consent. If the existing client cannot request/consent to the set, surface `UnsupportedClientScopeSet` with the missing scopes and stop for an explicit authentication-client decision—do not replace authentication or broaden permissions silently.

- [ ] **Step 5: Verify and commit**

```bash
cargo test -p cmtrace-open --all-features graph_auth_
npm test -- src/components/dialogs/settings/GraphApiTab.test.tsx
npx tsc --noEmit
git add src-tauri/src/graph_api.rs src-tauri/src/commands/graph_api.rs src/lib/commands.ts src/components/dialogs/settings/GraphApiTab.tsx src/components/dialogs/settings/GraphApiTab.test.tsx
git commit -m "feat: expose Graph read capabilities"
```

Record the Windows WAM scope-acquisition evidence before Task 11 begins.

### Phase 10C — fakeable typed HTTP client

**Files:**

- Create: `src-tauri/src/graph_api/client.rs`
- Modify: `src-tauri/src/graph_api/models.rs`
- Modify: `src-tauri/src/graph_api.rs`
- Modify: `src-tauri/tests/graph_esp_diagnostics.rs`

- [x] **Step 1: Write failing transport tests**

Pin exact method/path/query/header contracts, unknown enum preservation, 401 invalidation signal, 403 required-scope error, 404 not found, 429/503/504 retry, `Retry-After` handling, four-attempt exhaustion, cancellation during retry/pagination, HTTPS Graph-host allowlisting, malicious `nextLink`, page/item/body caps, timeout, and redacted errors/logs. Run all fake-transport tests on macOS/Linux as well as Windows.

Use these fixed budgets:

```rust
pub const MAX_GRAPH_ATTEMPTS: usize = 4;
pub const MAX_GRAPH_RETRY_DELAY: Duration = Duration::from_secs(30);
pub const MAX_GRAPH_PAGES: usize = 25;
pub const MAX_GRAPH_ITEMS: usize = 5_000;
pub const MAX_GRAPH_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
```

- [x] **Step 2: Implement a fakeable transport and typed page client**

`GraphPage<T>` accepts unknown JSON fields. `@odata.nextLink` must be HTTPS and match the configured Graph host. Cancellation is checked before requests, before pagination, and during retry waits. Errors expose sanitized status, Graph request ID when present, and required scope—not body or authorization data. The concrete WAM/`ureq` adapter remains Windows-only; the trait, client logic, and test fake remain platform-neutral.

- [x] **Step 3: Verify and commit**

```bash
cargo test -p cmtrace-open --all-features --test graph_esp_diagnostics client_ -- --nocapture
cargo fmt --all -- --check
cargo clippy -p cmtrace-open --all-targets --all-features -- -D warnings
git add src-tauri/src/graph_api/client.rs src-tauri/src/graph_api/models.rs src-tauri/src/graph_api.rs src-tauri/tests/graph_esp_diagnostics.rs
git commit -m "feat: harden Graph read transport"
```

- [x] **Step 4: Checkpoint**

Show cross-platform fake-transport output, capability results, 403 partial behavior, throttled retry, cancelled pagination, and malicious next-link rejection. Windows CI later proves the concrete WAM/`ureq` adapter.

## Task 11: Orchestrate device, Autopilot, ESP, app, policy, and script enrichment

### Phase 11A — deterministic remote correlation and section orchestration

**Files:**

- Create: `src-tauri/src/graph_api/correlation.rs`
- Create: `src-tauri/src/graph_api/esp.rs`
- Modify: `src-tauri/src/graph_api.rs`
- Modify: `src-tauri/tests/graph_esp_diagnostics.rs`
- Create: `src-tauri/tests/fixtures/graph/esp/orchestration-cases.json`

- [x] **Step 1: Write failing identity-correlation tests**

Match priority is explicit managed-device ID, Entra device ID, serial, then exact hostname plus matching tenant/user evidence. Multiple weak candidates return candidates and stop dependent sections. Pin exact GUID correlation, no accidental name merge, declared-versus-effective assignment semantics, and no false ESP-blocking claim from assignment alone. Never treat `policyStatusDetails.id` as the underlying app/policy GUID: it identifies the status-detail object. Exact app IDs come from local evidence or ESP `selectedMobileAppIds`; policy-status detail type/display-name correlation is lower-confidence unless a bounded catalog lookup supplies the real object ID.

- [x] **Step 2: Write failing endpoint-orchestration tests**

Use this dependency order:

1. `GET /v1.0/deviceManagement/managedDevices` with the narrowest supported query and a bounded fallback.
2. `GET /v1.0/deviceManagement/windowsAutopilotDeviceIdentities` and correlate locally.
3. `GET /beta/deviceManagement/windowsAutopilotDeviceIdentities/{id}/deploymentProfile` and `/intendedDeploymentProfile`.
4. Using the returned profile ID: `GET /beta/deviceManagement/windowsAutopilotDeploymentProfiles/{profileId}/assignments`.
5. `GET /beta/deviceManagement/autopilotEvents`, then `/beta/deviceManagement/autopilotEvents/{eventId}/policyStatusDetails` for the newest matching local evidence window.
6. `GET /v1.0/deviceManagement/deviceEnrollmentConfigurations/{id}` and `/v1.0/deviceManagement/deviceEnrollmentConfigurations/{id}/assignments`.
7. For locally or remotely referenced apps only: `GET /v1.0/deviceAppManagement/mobileApps/{id}` and `/v1.0/deviceAppManagement/mobileApps/{id}/assignments` as separate requests.
8. Optional beta **user-scoped** cross-check: obtain `userId` from the matched managed device, call `GET /beta/users/{userId}/mobileAppIntentAndStates`, then client-filter `managedDeviceIdentifier` to the matched device.
9. For referenced IDs only, use these exact read paths and bounded client-side device filtering:
   - `/v1.0/deviceManagement/deviceConfigurations/{id}`, `/v1.0/deviceManagement/deviceConfigurations/{id}/assignments`, `/v1.0/deviceManagement/deviceConfigurations/{id}/deviceStatuses`;
   - `/v1.0/deviceManagement/deviceCompliancePolicies/{id}`, `/v1.0/deviceManagement/deviceCompliancePolicies/{id}/assignments`, `/v1.0/deviceManagement/deviceCompliancePolicies/{id}/deviceStatuses`;
   - `/beta/deviceManagement/configurationPolicies/{id}` and `/beta/deviceManagement/configurationPolicies/{id}/assignments`;
   - `/beta/deviceManagement/deviceManagementScripts/{id}`, `/beta/deviceManagement/deviceManagementScripts/{id}/assignments`, `/beta/deviceManagement/deviceManagementScripts/{id}/deviceRunStates`;
   - `/beta/deviceManagement/deviceHealthScripts/{id}`, `/beta/deviceManagement/deviceHealthScripts/{id}/assignments`, `/beta/deviceManagement/deviceHealthScripts/{id}/deviceRunStates`.

Do not request `GroupMember.Read.All`. Preserve group/filter target IDs as **declared targeting**. Mark an object ESP-blocking only when local tracking, `trackedOnEnrollmentStatus`, Autopilot policy status, or another device-specific result supports it.

- [x] **Step 3: Implement section-isolated partial behavior**

Gate `graph_api::esp` behind `feature = "esp-diagnostics"` so lite/no-default builds retain only existing Graph behavior. Its orchestration is generic over an `EspGraphProvider`/portable client and must not depend directly on Tauri or Windows `GraphAuthState`. Tests use a fake provider on every platform; the Windows command adapter later wraps `GraphAuthState`, while a non-Windows provider returns typed `UnsupportedPlatform`/`Skipped`.

```rust
pub trait EspGraphProvider: Send + Sync {
    fn fetch(
        &self,
        request: &EspGraphRequest,
        cancellation: &GraphCancellation,
    ) -> Result<EspGraphOverlay, GraphError>;
}
```

Each section is `Available`, `NotFound`, `PermissionDenied`, `Failed`, `Skipped`, or `Cancelled`, includes API version and required scope, and preserves completed siblings. Unknown beta values are retained. If device matching is ambiguous, dependent sections use `status: Skipped`, `apiVersion: NotRequested`, `data: None`, and `error.blockedBy: "deviceMatch"`.

- [x] **Step 4: Verify and commit**

```bash
cargo test -p cmtrace-open --all-features --test graph_esp_diagnostics correlation_ -- --nocapture
cargo test -p cmtrace-open --all-features --test graph_esp_diagnostics orchestration_ -- --nocapture
cargo clippy -p cmtrace-open --all-targets --all-features -- -D warnings
git add src-tauri/src/graph_api/correlation.rs src-tauri/src/graph_api/esp.rs src-tauri/src/graph_api.rs src-tauri/tests/graph_esp_diagnostics.rs src-tauri/tests/fixtures/graph/esp/orchestration-cases.json
git commit -m "feat: enrich ESP evidence from Graph"
```

### Phase 11B — cancellable Windows Graph IPC adapter

**Files:**

- Modify: `src-tauri/src/commands/graph_api.rs`
- Modify: `src-tauri/src/lib.rs`
- Modify: `src/lib/commands.ts`
- Modify: `src-tauri/tests/graph_esp_diagnostics.rs`

- [x] **Step 1: Write failing cancellation and stale-overlay tests**

Pin command serialization, per-request cancellation, operation-state removal, 401 cache invalidation once, provider isolation, and typed unsupported behavior. Portable integration tests use the fake provider; Windows-gated tests compile the concrete auth/transport adapter without making tenant calls.

- [x] **Step 2: Add the commands**

```text
graph_fetch_esp_diagnostics(request)
graph_cancel_esp_diagnostics(requestId)
```

On Windows with `esp-diagnostics`, the command adapter wraps `GraphAuthState` as the concrete `EspGraphProvider`. `GraphAuthState` uses `Arc`-backed memory-only token/cache/operation state so blocking HTTP work runs away from the command runtime. Command execution never opens WAM; unauthenticated state returns `GraphNotConnected`. Non-Windows and lite capability metadata prevents invocation and returns a typed unsupported result if reached. The local ESP session remains completely independent of `GraphAuthState`.

- [x] **Step 3: Verify and commit**

```bash
cargo test -p cmtrace-open --all-features --test graph_esp_diagnostics ipc_ -- --nocapture
npx tsc --noEmit
git add src-tauri/src/commands/graph_api.rs src-tauri/src/lib.rs src/lib/commands.ts src-tauri/tests/graph_esp_diagnostics.rs
git commit -m "feat: expose cancellable ESP Graph overlay"
```

- [x] **Step 4: Checkpoint**

Show fake-provider full, partial, cancelled, unauthorized, and unsupported command results. Frontend scheduling/off-state behavior lands in Phase 12C.

## Task 12: Add registry-driven shell seams and isolated frontend state

### Phase 12A — workspace definition contract

**Files:**

- Modify: `src/types/log.ts`
- Modify: `src/workspaces/types.ts`
- Modify tests in: `src/stores/ui-store.test.ts`
- Create: `src/workspaces/registry.test.ts`

- [x] **Step 1: Write failing availability/definition tests**

Pin `esp-diagnostics` as a valid workspace ID, sidebar default behavior, `sidebar: false`, live-capability metadata, and lazy toolbar/status content slot typing. Verify backend-enabled workspace filtering still falls back safely.

- [x] **Step 2: Add registry capabilities instead of new ID branches**

Extend `WorkspaceCapabilities` with:

```ts
sidebar?: boolean;
liveAcquisition?: boolean;
```

Extend `WorkspaceDefinition` with:

```ts
toolbarAction?: LazyExoticComponent<ComponentType>;
statusBarContent?: LazyExoticComponent<ComponentType>;
```

`sidebar` defaults to `true`. `liveAcquisition` is capability metadata, not a platform assumption.

- [x] **Step 3: Implement the contracts and verify**

```bash
npm test -- src/stores/ui-store.test.ts src/workspaces/registry.test.ts
npx tsc --noEmit
```

- [x] **Step 4: Commit**

```bash
git add src/types/log.ts src/workspaces/types.ts src/stores/ui-store.test.ts src/workspaces/registry.test.ts
git commit -m "feat: define ESP workspace shell capabilities"
```

### Phase 12B — generic no-sidebar and lazy chrome slots

**Files:**

- Modify: `src/components/layout/AppShell.tsx`
- Modify: `src/components/layout/Toolbar.tsx`
- Modify: `src/components/layout/StatusBar.tsx`
- Modify: `src/workspaces/event-log/index.ts`
- Modify: `src/workspaces/registry.test.ts`

- [x] **Step 1: Write failing registry shell tests**

Pin default sidebar behavior, `sidebar: false`, event-log migration away from its hard-coded exception, lazy toolbar rendering, lazy status rendering, and unaffected legacy workspace labels/actions.

- [x] **Step 2: Replace hard-coded shell exceptions with the registry**

`AppShell` checks `workspace.capabilities?.sidebar !== false`. `Toolbar` and `StatusBar` render their active workspace's lazy slot inside `Suspense`. Legacy status logic remains as fallback until migrated separately; ESP adds no new ID branch.

- [x] **Step 3: Verify and commit**

```bash
npm test -- src/workspaces/registry.test.ts src/stores/ui-store.test.ts
npx tsc --noEmit
git add src/components/layout/AppShell.tsx src/components/layout/Toolbar.tsx src/components/layout/StatusBar.tsx src/workspaces/event-log/index.ts src/workspaces/registry.test.ts
git commit -m "refactor: drive workspace chrome from registry"
```

### Phase 12C — typed commands, mirrored types, store, and listener

**Files:**

- Create: `src/workspaces/esp-diagnostics/types.ts`
- Create: `src/workspaces/esp-diagnostics/esp-diagnostics-store.ts`
- Create: `src/workspaces/esp-diagnostics/esp-diagnostics-store.test.ts`
- Create: `src/workspaces/esp-diagnostics/use-esp-session-updates.ts`
- Modify: `src/lib/commands.ts`

- [x] **Step 1: Write failing store tests first**

Pin idle/analyzing/starting/live/stopping/ready/error transitions; stale analysis response; wrong session; duplicate and out-of-order sequence; stop; error recovery; and local snapshot preservation after Graph failure. Pin Graph setting disabled, enabled/idle-disconnected, enabled/connecting, enabled/connected, explicit refresh, stale response, disable-during-query cancellation, no sign-out side effect, no automatic WAM invocation, identity-fingerprint de-duplication, and identical behavior for live/imported snapshots. Also pin collapsed default, dock-height clamping, unread count while hidden, and mark-read behavior.

- [x] **Step 2: Mirror Rust contracts exactly and add typed wrappers**

Add wrappers for analyze/start/get/stop/relaunch and Graph fetch/cancel. All invoke errors use the existing normalized command error path. No store imports Tauri directly.

- [x] **Step 3: Implement one global event subscriber**

The hook attaches once after Zustand persistence hydration, validates the envelope, applies the raw local snapshot immediately, and cleans up its listener without stopping the native session on component unmount.

The same global hook/store orchestration owns optional Graph scheduling for live and imported snapshots:

- If `graphApiEnabled` is false, clear any remote overlay and leave local IDs/evidence unchanged.
- If enabled and `graphApiStatus === "connected"`, issue one Graph request for the stable local-identity fingerprint; later log-only updates do not refetch.
- If enabled while `graphApiStatus` is `idle`, `connecting`, or `error`, set `GraphNotConnected`, do not queue work, do not call `graphAuthenticate`, and require **Refresh Graph data** after the existing connection succeeds.
- **Refresh Graph data** rechecks enabled/connected state and starts a new request ID; late responses cannot replace it.
- Disabling during a request calls Graph cancel, removes the remote overlay, prevents new requests, retains the local snapshot, and does not sign out WAM.
- Navigating to another workspace does not stop local collection or an already-authorized Graph request.

- [x] **Step 4: Verify and commit**

```bash
npm test -- src/workspaces/esp-diagnostics/esp-diagnostics-store.test.ts
npx tsc --noEmit
git add src/workspaces/esp-diagnostics/types.ts src/workspaces/esp-diagnostics/esp-diagnostics-store.ts src/workspaces/esp-diagnostics/esp-diagnostics-store.test.ts src/workspaces/esp-diagnostics/use-esp-session-updates.ts src/lib/commands.ts
git commit -m "feat: manage ESP diagnostics frontend state"
```

### Phase 12D — base workspace and registry definition

**Files:**

- Create: `src/workspaces/esp-diagnostics/EspDiagnosticsWorkspace.tsx`
- Create: `src/workspaces/esp-diagnostics/index.ts`
- Modify: `src/workspaces/registry.ts`
- Modify: `src/workspaces/registry.test.ts`

- [x] **Step 1: Write failing definition and routing tests**

Pin label `ESP Diagnostics`, cross-platform offline availability, Windows-only live capability, `sidebar: false`, no tab strip, and source routing for CMTrace evidence folders, `manifest.json`, CAB, and ZIP.

- [x] **Step 2: Implement a real base workspace and definition**

The base workspace renders production idle/analyzing/error state and explicit start-live/import actions from the store; it is not placeholder content. The definition uses `platforms: "all"`, `capabilities.sidebar: false`, and does not import the Intune store.

```bash
npm test -- src/workspaces/registry.test.ts src/workspaces/esp-diagnostics/esp-diagnostics-store.test.ts
npx tsc --noEmit
```

- [x] **Step 3: Commit**

```bash
git add src/workspaces/esp-diagnostics/EspDiagnosticsWorkspace.tsx src/workspaces/esp-diagnostics/index.ts src/workspaces/registry.ts src/workspaces/registry.test.ts
git commit -m "feat: register ESP diagnostics workspace"
```

### Phase 12E — global listener and workspace chrome components

**Files:**

- Modify: `src/components/layout/AppShell.tsx`
- Create: `src/workspaces/esp-diagnostics/EspToolbarAction.tsx`
- Create: `src/workspaces/esp-diagnostics/EspStatusBarContent.tsx`
- Modify: `src/workspaces/esp-diagnostics/index.ts`
- Modify: `src/workspaces/registry.test.ts`

- [x] **Step 1: Write failing slot and listener tests**

Pin one listener mount, prominent primary toolbar action only in ESP, live indicator, evidence count, start/stop status, source count, elevation/Graph summary, and no session stop when switching workspace.

- [x] **Step 2: Implement and verify**

The toolbar action reads only the ESP store and controls evidence visibility; live-session start remains a workspace action. The status component reads the ESP store and replaces generic status content only for ESP.

```bash
npm test -- src/workspaces/registry.test.ts src/workspaces/esp-diagnostics/esp-diagnostics-store.test.ts
npx tsc --noEmit
```

- [x] **Step 3: Commit and checkpoint**

```bash
git add src/components/layout/AppShell.tsx src/workspaces/esp-diagnostics/EspToolbarAction.tsx src/workspaces/esp-diagnostics/EspStatusBarContent.tsx src/workspaces/esp-diagnostics/index.ts src/workspaces/registry.test.ts
git commit -m "feat: add ESP live evidence app chrome"
```

Show full-width content with no sidebar and the primary app-chrome live-log button.

## Task 13: Build the approved single-page diagnostic cockpit

### Phase 13A — workspace frame, header, elevation, and MSIEXEC

**Files:**

- Modify: `src/workspaces/esp-diagnostics/EspDiagnosticsWorkspace.tsx`
- Create: `src/workspaces/esp-diagnostics/EspWorkspaceHeader.tsx`
- Create: `src/workspaces/esp-diagnostics/ElevationBanner.tsx`
- Create: `src/workspaces/esp-diagnostics/MsiexecStatus.tsx`
- Create: `src/workspaces/esp-diagnostics/EspDiagnosticsWorkspace.test.tsx`

- [x] **Step 1: Write failing component tests**

Cover empty, analyzing, live, ready, partial, error, classic ESP, existing-device, ESP-only, Device Preparation, elevated, non-elevated, relaunch supported/unsupported, zero/one/multiple MSI processes, exact/temporal/ambiguous correlation, command-line redaction, and evidence-link actions.

- [x] **Step 2: Implement the app-chrome cockpit frame**

Use Fluent UI/tokens and the existing Segoe/log typography. Keep the page dense and Windows-native, with a clear reading hierarchy. Do not add a secondary left navigation rail. The header shows scenario, phase, elapsed time, coverage, local live state, and Graph state.

- [x] **Step 3: Implement the persistent admin recommendation**

Non-elevated mode explains exactly which evidence is restricted and offers the explicit relaunch command. Dismissal, if supported, applies only to the current view and does not hide the coverage gaps.

- [x] **Step 4: Verify and commit**

```bash
npm test -- src/workspaces/esp-diagnostics/EspDiagnosticsWorkspace.test.tsx
npx tsc --noEmit
git add src/workspaces/esp-diagnostics/EspDiagnosticsWorkspace.tsx src/workspaces/esp-diagnostics/EspWorkspaceHeader.tsx src/workspaces/esp-diagnostics/ElevationBanner.tsx src/workspaces/esp-diagnostics/MsiexecStatus.tsx src/workspaces/esp-diagnostics/EspDiagnosticsWorkspace.test.tsx
git commit -m "feat: build ESP diagnostics cockpit frame"
```

### Phase 13B — findings, phase progress, activity, and workload table

**Files:**

- Create: `src/workspaces/esp-diagnostics/ActionCenter.tsx`
- Create: `src/workspaces/esp-diagnostics/EspPhaseProgress.tsx`
- Create: `src/workspaces/esp-diagnostics/LiveActivity.tsx`
- Create: `src/workspaces/esp-diagnostics/EspWorkloadTable.tsx`
- Modify: `src/workspaces/esp-diagnostics/EspDiagnosticsWorkspace.test.tsx`

- [x] **Step 1: Write failing interaction/state tests**

Pin finding severity/confidence/evidence, recommended checks without remediation controls, distinct classic/v2 phase labels, independent real-time activity updates, all workload kinds/states, device/user scope, all-sessions toggle, latest-session default, exit/enforcement codes, raw IDs beside Graph names, and unknown values.

- [x] **Step 2: Implement with stable keys and accessible semantics**

Tables sort deterministically, retain retries, expose full values in details, and use text/icon labels in addition to color. The Action Center never presents a destructive or mutating button.

- [x] **Step 3: Verify and commit**

```bash
npm test -- src/workspaces/esp-diagnostics/EspDiagnosticsWorkspace.test.tsx
npx tsc --noEmit
git add src/workspaces/esp-diagnostics/ActionCenter.tsx src/workspaces/esp-diagnostics/EspPhaseProgress.tsx src/workspaces/esp-diagnostics/LiveActivity.tsx src/workspaces/esp-diagnostics/EspWorkloadTable.tsx src/workspaces/esp-diagnostics/EspDiagnosticsWorkspace.test.tsx
git commit -m "feat: show ESP blockers and live workload progress"
```

### Phase 13C — complete evidence sections and view model

**Files:**

- Create: `src/workspaces/esp-diagnostics/EvidenceSections.tsx`
- Create: `src/workspaces/esp-diagnostics/esp-view-model.ts`
- Create: `src/workspaces/esp-diagnostics/esp-view-model.test.ts`
- Modify: `src/workspaces/esp-diagnostics/EspDiagnosticsWorkspace.tsx`
- Modify: `src/workspaces/esp-diagnostics/EspDiagnosticsWorkspace.test.tsx`

- [x] **Step 1: Write failing view-model tests**

Pin sections for identity/profile, OOBE flags, ESP configuration, enrollment/device/user sessions, apps, scripts, policies, certificates, join/registration, Delivery Optimization, hardware, NodeCache, source coverage, and raw provenance. Empty sections show source-aware absence rather than disappearing silently.

- [x] **Step 2: Implement collapsible inline sections**

All sections live on the same workspace page. Keep primary blockers/workloads above the fold; deeper evidence is collapsed by category. Sensitive fields are masked with an explicit reveal/copy policy. Raw IDs remain visible when Graph is off and beside names when Graph is on.

- [x] **Step 3: Verify and commit**

```bash
npm test -- src/workspaces/esp-diagnostics/esp-view-model.test.ts src/workspaces/esp-diagnostics/EspDiagnosticsWorkspace.test.tsx
npx tsc --noEmit
git add src/workspaces/esp-diagnostics/EvidenceSections.tsx src/workspaces/esp-diagnostics/esp-view-model.ts src/workspaces/esp-diagnostics/esp-view-model.test.ts src/workspaces/esp-diagnostics/EspDiagnosticsWorkspace.tsx src/workspaces/esp-diagnostics/EspDiagnosticsWorkspace.test.tsx
git commit -m "feat: expose complete ESP evidence sections"
```

- [ ] **Step 4: Checkpoint**

Compare the implemented page at 1200×800 and 1440×900 against the approved actual-app-chrome mock direction.

## Task 14: Add collapsed, resizable, and full-workspace live evidence

### Phase 14A — virtualized evidence table and resize contract

**Files:**

- Create: `src/workspaces/esp-diagnostics/LiveEvidenceTable.tsx`
- Create: `src/workspaces/esp-diagnostics/LiveEvidenceDock.tsx`
- Create: `src/workspaces/esp-diagnostics/LiveEvidenceDock.test.tsx`
- Modify: `src/workspaces/esp-diagnostics/esp-diagnostics-store.test.ts`

- [x] **Step 1: Write failing dock tests**

Pin collapsed default, hidden collection continuity, unread count, dock open, minimum 180-pixel height, maximum 70% workspace height, pointer resize, keyboard resize through an accessible separator, full-workspace mode, restore to prior dock height, collapse from either open mode, and state retention while navigating away/back.

- [x] **Step 2: Write failing evidence-table tests**

Pin virtualized rendering, timestamp/source/severity/component/message columns, source filters, text filter, error/warning filter, auto-follow only while near bottom, paused visual follow without pausing collection, rotation/reset rows, raw provenance drill-down, and stable selection during updates.

- [x] **Step 3: Implement and verify**

The evidence table owns no native session. It renders store records and can be hidden without unsubscribe or data loss. Use TanStack Virtual rather than the global Log Explorer store so ESP state cannot contaminate open log tabs.

```bash
npm test -- src/workspaces/esp-diagnostics/LiveEvidenceDock.test.tsx src/workspaces/esp-diagnostics/esp-diagnostics-store.test.ts
npx tsc --noEmit
```

- [x] **Step 4: Commit**

```bash
git add src/workspaces/esp-diagnostics/LiveEvidenceTable.tsx src/workspaces/esp-diagnostics/LiveEvidenceDock.tsx src/workspaces/esp-diagnostics/LiveEvidenceDock.test.tsx src/workspaces/esp-diagnostics/esp-diagnostics-store.test.ts
git commit -m "feat: add resizable ESP live evidence dock"
```

### Phase 14B — cockpit and primary chrome integration

**Files:**

- Modify: `src/workspaces/esp-diagnostics/EspDiagnosticsWorkspace.tsx`
- Modify: `src/workspaces/esp-diagnostics/EspToolbarAction.tsx`
- Modify: `src/workspaces/esp-diagnostics/EspDiagnosticsWorkspace.test.tsx`
- Modify: `src/workspaces/esp-diagnostics/LiveEvidenceDock.test.tsx`

- [x] **Step 1: Write failing end-to-end component interactions**

The toolbar button says **Open live logs** while collapsed, has a live dot and count, opens the dock, can promote it to full workspace, restores it, and never hides the MSIEXEC/action/progress regions except in intentional full-log mode. Full-log mode has an obvious restore action.

- [x] **Step 2: Integrate and verify responsive behavior**

```bash
npm test -- src/workspaces/esp-diagnostics/EspDiagnosticsWorkspace.test.tsx src/workspaces/esp-diagnostics/LiveEvidenceDock.test.tsx
npx tsc --noEmit
npm run frontend:build
```

- [ ] **Step 3: Commit and checkpoint**

```bash
git add src/workspaces/esp-diagnostics/EspDiagnosticsWorkspace.tsx src/workspaces/esp-diagnostics/EspToolbarAction.tsx src/workspaces/esp-diagnostics/EspDiagnosticsWorkspace.test.tsx src/workspaces/esp-diagnostics/LiveEvidenceDock.test.tsx
git commit -m "feat: integrate ESP live logs into app chrome"
```

Show collapsed, resized docked, and full-workspace states inside the actual CMTrace Open chrome.

## Task 15: Finish Graph UX, end-to-end coverage, Windows acceptance, and release documentation

### Phase 15A — Graph overlay and device-selection UX

**Files:**

- Create: `src/workspaces/esp-diagnostics/GraphEnrichmentPanel.tsx`
- Modify: `src/workspaces/esp-diagnostics/EvidenceSections.tsx`
- Modify: `src/workspaces/esp-diagnostics/EspDiagnosticsWorkspace.tsx`
- Modify: `src/workspaces/esp-diagnostics/EspDiagnosticsWorkspace.test.tsx`
- Modify: `src/components/dialogs/settings/GraphApiTab.tsx`

- [x] **Step 1: Write failing Graph presentation tests**

Cover setting disabled, idle/disconnected, connecting-at-session-start (`GraphNotConnected`, no queue), connected/full, connected/partial, permission denied per section, offline, throttled/retrying, stale, cancelled, disable-during-query, no sign-out, manual refresh after connection, no device match, ambiguous device candidates, explicit candidate selection, beta labels, local raw ID beside friendly name, and local evidence remaining visible after every remote failure.

- [x] **Step 2: Implement explicit remote controls**

Starting or importing an ESP diagnostic session permits its configured Graph lookup only when the persisted option is already enabled and `graphApiStatus` is already connected. The workspace also provides **Refresh Graph data** and **Cancel Graph query**. It never opens WAM automatically, never queues behind a connection attempt, and keeps sign-in in existing settings. Ambiguous weak matches require candidate selection before dependent requests resume.

- [x] **Step 3: Make targeting language precise**

Show group/filter IDs as **Declared targeting**. Show **Effective** only for device-specific status, local ESP tracking, or Autopilot policy-status evidence. A required app assignment alone never becomes a blocking conclusion.

- [x] **Step 4: Verify and commit**

```bash
npm test -- src/workspaces/esp-diagnostics/EspDiagnosticsWorkspace.test.tsx src/components/dialogs/settings/GraphApiTab.test.tsx
npx tsc --noEmit
git add src/workspaces/esp-diagnostics/GraphEnrichmentPanel.tsx src/workspaces/esp-diagnostics/EvidenceSections.tsx src/workspaces/esp-diagnostics/EspDiagnosticsWorkspace.tsx src/workspaces/esp-diagnostics/EspDiagnosticsWorkspace.test.tsx src/components/dialogs/settings/GraphApiTab.tsx
git commit -m "feat: present optional Graph ESP enrichment"
```

### Phase 15B — browser fixtures, E2E, and actual-chrome screenshots

**Files:**

- Modify: `e2e/fixtures/tauri-shim.ts`
- Create: `e2e/fixtures/demo/esp-diagnostics.json`
- Create: `e2e/esp-diagnostics.spec.ts`
- Modify: `e2e/fixtures/screenshot-data.ts`
- Modify: `e2e/screenshots/capture.spec.ts`

- [x] **Step 1: Add deterministic sanitized fixtures**

Include non-elevated local-only failure, elevated live install, v2 mixed workloads, exact MSI correlation, ambiguous MSI correlation, full Graph overlay, partial Graph overlay, sparse bundle, and rotation update. The shim rejects full Graph ESP IPC and supplies only explicit test fixtures.

- [x] **Step 2: Implement E2E scenarios**

Pin workspace selection, no sidebar, local start, bundle import, admin banner, MSIEXEC box, live phase/activity updates, action evidence drill-down, all evidence sections, raw IDs with Graph off, names with Graph on, collapsed default, hidden collection, dock resize, full logs, restore, source filtering, stop state, and navigation away/back without session loss.

- [ ] **Step 3: Capture the approved app-chrome states**

Capture sanitized 1200×800 and 1440×900 views for collapsed, docked, full logs, non-elevated, and Device Preparation states.

- [ ] **Step 4: Verify and commit**

```bash
npx playwright test e2e/esp-diagnostics.spec.ts
npm run screenshots -- --grep "ESP Diagnostics"
git add e2e/fixtures/tauri-shim.ts e2e/fixtures/demo/esp-diagnostics.json e2e/esp-diagnostics.spec.ts e2e/fixtures/screenshot-data.ts e2e/screenshots/capture.spec.ts
git commit -m "test: cover ESP diagnostics end to end"
```

### Phase 15C — documentation and privacy contract

**Files:**

- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `docs/superpowers/specs/2026-07-15-esp-diagnostics-workspace-design.md`
- Modify: `docs/superpowers/plans/2026-07-15-esp-diagnostics-workspace.md`

- [x] **Step 1: Document shipped behavior exactly**

Document the workspace, elevation recommendation, bounded discovery limits, no deep scan, read-only boundary, local-first behavior, optional WAM/Graph scopes, beta sections, sensitive fields, captured evidence support, live-log modes, MSIEXEC correlation confidence, and incomplete-coverage interpretation.

- [x] **Step 2: Mark completed plan items and reconcile design drift**

Any implementation difference requires an explicit rationale in the spec before release. Do not change the done-definition to match missing code.

**Validation-sequencing drift:** No functional contract drift has been identified. Graph orchestration and UX proceeded against portable models and fake transports before the planned live WAM public-client feasibility gate could run. The exact five-scope WAM v2 request without a resource property is implemented and cross-compiled, but live consent and `scp` evidence remain required in Phase 15F. Fixture-driven Playwright app-shell captures are not accepted as native Windows Tauri visual evidence. Parallel worktrees also split or folded some planned commit boundaries without changing the done-definition.

- [x] **Step 3: Run documentation link/path checks and commit**

```bash
rg -n "ESP Diagnostics|DeviceManagementManagedDevices.Read.All|deep scan|read-only|MSIEXEC" README.md CHANGELOG.md docs/superpowers
git diff --check
git add README.md CHANGELOG.md
git add -f docs/superpowers/specs/2026-07-15-esp-diagnostics-workspace-design.md docs/superpowers/plans/2026-07-15-esp-diagnostics-workspace.md
git commit -m "docs: document ESP diagnostics workspace"
```

### Phase 15D — Windows CI coverage for platform-only paths

**Files:**

- Modify: `.github/workflows/cmtrace-ci.yml`

- [x] **Step 1: Record the failing CI coverage assertion**

Inspect the workflow and confirm that the existing Windows matrix builds the application but does not execute the Windows-only ESP/Graph tests or clippy. Treat that missing job as a release-gate failure; Linux success cannot prove the `cfg(windows)` acquisition and WAM paths compile or behave correctly.

- [x] **Step 2: Add a dedicated pinned-action Windows test job**

Add `windows-esp` on `windows-latest`, with the same pinned checkout/toolchain/cache conventions as the existing workflow. It runs from the repository root and executes:

```powershell
cargo test -p cmtraceopen-parser --test esp_diagnostics
cargo test -p cmtrace-open --all-features --test esp_diagnostics_sources
cargo test -p cmtrace-open --all-features --test graph_esp_diagnostics
cargo test -p cmtrace-open --all-features
cargo clippy -p cmtrace-open --all-targets --all-features -- -D warnings
```

The job uses only sanitized fixtures and mock transports. It compiles the concrete Windows WAM/`ureq`/registry/event/process adapters and exercises portable models, claims, client, correlation, and fake orchestration, but it must not require an interactive WAM session, an Intune tenant, administrator rights, or live device state. It is not evidence that the public client can consent to the five scopes.

- [ ] **Step 3: Validate the workflow and commit**

```bash
ruby -e 'require "yaml"; YAML.load_file(ARGV.fetch(0)); puts "valid YAML"' .github/workflows/cmtrace-ci.yml
git diff --check
git add .github/workflows/cmtrace-ci.yml
git commit -m "ci: test ESP diagnostics on Windows"
```

Expected: YAML formatting passes, all actions remain commit-SHA pinned, and the Windows job exercises the platform-only modules before the build matrix can be treated as sufficient.

### Phase 15E — complete automated verification

**Files:** No edits unless a failing gate exposes a defect; fix defects in a new bounded phase with tests.

- [x] **Step 1: Pure parser gates**

```bash
cargo fmt --all -- --check
cargo test -p cmtraceopen-parser --test esp_diagnostics -- --nocapture
cargo test -p cmtraceopen-parser
```

- [ ] **Step 2: Native and feature gates**

```bash
cargo test -p cmtrace-open --all-features --test esp_diagnostics_sources -- --nocapture
cargo test -p cmtrace-open --all-features --test graph_esp_diagnostics -- --nocapture
cargo test --workspace --all-features
cargo check -p cmtrace-open --no-default-features
cargo check -p cmtrace-open --no-default-features --features esp-diagnostics
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

- [x] **Step 3: Frontend gates**

```bash
npm test
npx tsc --noEmit
npm run frontend:build
npx playwright test e2e/esp-diagnostics.spec.ts
```

- [ ] **Step 4: Application build gates**

```bash
npm run app:build:lite
npm run app:build:debug
```

Expected: every command exits zero. Save concise evidence for each gate.

### Phase 15F — Windows live acceptance

**Files:** No source edits during acceptance. Any discovered defect returns to a focused red-green-refactor phase.

- [ ] **Step 1: Elevation and coverage**

On a Windows test device, start non-elevated, confirm the recommendation and explicit coverage gaps, relaunch through **Restart as administrator**, and confirm protected evidence coverage improves without any device remediation.

- [ ] **Step 2: Live deployment observation**

Start before an ESP/app installation. Verify new IME and MSI files attach without restart, temporary MSI logs are found only in bounded roots, log appends appear live while the pane is collapsed, rotations reset cleanly, and stopping leaves no watcher/process sampler thread.

- [ ] **Step 3: Installer states**

Exercise zero, one, and multiple concurrent `msiexec` processes. Confirm exact log/PID/GUID correlation, temporal confidence, ambiguous no-match, PID reuse protection, and redacted command lines.

- [ ] **Step 4: Graph states**

First prove that the existing public client makes a WAM v2 request for the five fully qualified scopes without a resource property and receives all five short names in `scp`; record the client ID, tenant, consent result, and redacted capability output. Then exercise Graph disabled, connecting-at-start/no queue, manual refresh after connection, disable-during-query/no sign-out, full consent, app-only/partial consent, denied section, expired token, offline, cancellation, ambiguous device, and beta unknown value. Compare the selected managed device, Autopilot event/profile, profile assignments, ESP configuration, and app status against the Intune portal.

- [ ] **Step 5: Read-only audit**

Use static review plus a Windows ProcMon/network trace to confirm:

- device diagnostic registry access is read/query only;
- no MDM sync, service control, installer/remediation, or tenant mutation occurs;
- Graph ESP traffic uses GET only;
- filesystem writes are limited to CMTrace Open's own logs/settings, unique temporary archive extraction, and explicit user export;
- temporary extraction is removed;
- no access token, authorization header, raw hardware hash, or unredacted sensitive payload appears in app logs.

- [ ] **Step 6: Final code review**

Use `superpowers:requesting-code-review` and the repository's code-review skill. Resolve every actionable correctness, security, privacy, race, and accessibility issue, then re-run all affected gates and the full verification suite.

- [ ] **Step 7: Final delivery commit**

```bash
git status --short
git log --oneline --decorate origin/main..HEAD
git diff --check origin/main...HEAD
```

Commit any final verified fixes with scoped messages. Do not merge, push, or open a PR unless the user requests that external action.

---

## Full PowerShell parity release gate

- [x] All five scenarios classify correctly: unknown, Autopilot v1, existing-device JSON, ESP-only, and Device Preparation v2.
- [x] Profile name, tenant domain/ID, correlation ID, EntDMID, UPN, enrollment GUID/provider, and raw IDs are preserved and sensitivity-marked.
- [x] Raw OOBE mask and all ten decoded flags are present.
- [x] Profile download, Entra/hybrid join, ODJ applied, and skip-connectivity evidence are present.
- [x] Device/user ESP enabled, timeout, blocking, reset, retry, and continue settings are present per enrollment.
- [x] V2 agent/page timeouts, skip-on-failure, diagnostics permission, scripts, and all eight workload states are present.
- [x] Every device/user session is retained; latest is chronological; all sessions remain selectable.
- [x] MSI, Office, UWP, Win32, policy, SCEP certificate, platform script, and v2 workload evidence is present.
- [x] All Office, classic ESP, policy, v2, and unknown status values retain raw plus normalized state.
- [x] Exit codes and enforcement error codes appear in item details and timeline.
- [x] NodeCache gaps do not truncate later numeric keys.
- [x] Event IDs 72, 100, 101, 107, 109, 110, 111, 304, 306, 1905, 1906, 1920, 1922, and 1924 are asserted.
- [x] Profile-download, ODJ, registration, MSI, script, workload, app/Office DO, and coverage events enter the timeline.
- [x] Repeated retries/events are never collapsed.
- [x] DO raw counters and derived shares are labeled accurately.
- [x] OS/build, manufacturer, model, serial, and TPM are present without raw hardware-hash exposure.
- [x] Bundle parsing never reads equivalent facts from the analyst machine.
- [x] Missing, permission-denied, malformed, unsupported, and Graph-partial sources remain distinct and non-fatal.
- [x] An ESP-only sparse bundle with zero IME text logs produces a useful result.
- [x] Local and captured-equivalent fixtures produce equivalent normalized conclusions.

## Product and UX release gate

- [x] The workspace uses actual CMTrace Open chrome and has no left sidebar.
- [x] The approved single-page cockpit shows header, admin state, MSIEXEC, findings, progress, activity, workloads, and evidence sections.
- [x] Running non-elevated is prominent and explains lost coverage; partial diagnostics still work.
- [x] **Open live logs** is a prominent primary chrome action with live indicator and evidence count.
- [x] Live evidence is collapsed by default, docked/resizable, and expandable to the full workspace.
- [x] Collection continues while logs are hidden and while another workspace is active.
- [x] The MSIEXEC card covers zero/one/multiple processes and exposes correlation confidence/evidence.
- [x] Bounded known/temp discovery finds IME and deployment logs without a full-drive scan.
- [x] No deep-scan command, request field, menu, button, or hidden debug route exists.
- [x] Classic ESP and Device Preparation have distinct phase/rule presentation.
- [x] Raw IDs render with Graph off and remain visible beside Graph names when on.
- [x] Graph partial/offline/cancelled errors never erase local evidence.
- [x] A session started while Graph is connecting shows `GraphNotConnected`, does not queue or invoke WAM, and enriches only after explicit refresh.
- [x] Disabling Graph cancels in-flight ESP enrichment and clears its overlay without signing out or altering local evidence.
- [x] Findings are actionable and provenance-backed but never offer mutating remediation.
- [x] Every status uses text/icon semantics in addition to color.
- [ ] Keyboard, focus, accessible names, virtualized row navigation, resize separator, and reduced-motion behavior pass.
- [ ] 1200×800 and 1440×900 actual-chrome captures are legible without clipped primary actions.

## Security and privacy release gate

- [x] All diagnostic registry access is read-only and scoped.
- [x] All Graph ESP requests are read-only and use only the five declared delegated read scopes.
- [x] The existing WAM flow is reused; no second login, app secret, or bearer-token input exists.
- [ ] WAM v2 requests exactly the five fully qualified delegated scopes with no resource property; short `scp` capability evidence is recorded on Windows.
- [x] Tokens remain memory-only and redacted from `Debug`, IPC, logs, screenshots, copy, and export.
- [x] Graph host, pagination, item, response-size, timeout, retry, and cancellation limits are enforced.
- [x] CAB/ZIP entry count, size, path, type, and extraction-root limits are enforced.
- [x] UPN, SID, tenant, EntDMID, serial, NodeCache, and command-line sensitive values are masked by default.
- [x] Raw hardware hash is absent from normal IPC, UI, logs, screenshots, copy, and export.
- [x] Full Graph ESP commands are unavailable through the debug localhost bridge.
- [ ] Read-only Windows acceptance and cleanup leave no watcher, process sampler, Graph operation, or temp extraction behind.

## Self-review checklist for this plan

- [x] Re-read the approved design and every prior user correction.
- [x] Confirm every implementation phase touches five or fewer files.
- [x] Confirm every behavior change starts with a failing test.
- [x] Confirm exact file paths, commands, expected outcomes, constants, and interface names are present.
- [x] Confirm no unfinished-marker comments, placeholder UI, fake production data, or deferred parity category remains.
- [x] Confirm `esp-diagnostics`, `EspDiagnosticsSnapshot`, `EspSessionUpdate`, and `GraphSection<T>` naming is consistent across Rust and TypeScript.
- [x] Confirm Graph-off local behavior is independently complete.
- [x] Confirm the hydrated frontend setting, WAM v2 feasibility gate, cancellation, and connection-race behavior are explicit.
- [x] Confirm live-session cleanup, stale request handling, and race tests are explicit.
- [x] Confirm the plan does not copy unsafe PowerShell behaviors.
- [x] Confirm the final gates include TypeScript, all Rust tests/clippy, Vitest, Playwright, lite/full builds, Windows CI/live verification, privacy, and read-only audit.

## Execution handoff

Recommended execution mode: **Subagent-Driven Development in this task**. Assign independent parser, native acquisition, Graph, and frontend slices to agents only after their prerequisite contracts land; perform spec and quality review after every bounded phase. The active `/goal` remains open until Task 15 and every release gate are complete.
