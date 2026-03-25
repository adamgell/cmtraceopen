# Software Deployment Analysis Workspace

**Date:** 2026-03-23
**Status:** Draft
**Depends on:** [MSI Parser, PSADT Support & Deployment Sources](./2026-03-23-msi-parser-and-deployment-sources-design.md)
**Mockup:** [deployment-workspace-mockup.html](./deployment-workspace-mockup.html)

---

## Problem

When a user opens a deployment log folder (e.g., `C:\Windows\Logs\Software`), they currently get a flat file list. There's no way to see which deployments succeeded or failed without opening each file individually. For troubleshooting, users must manually search each log for errors, then cross-reference PSADT and MSI logs to find root causes.

## Goals

1. A dedicated workspace that scans a folder for PSADT and MSI logs, classifies each deployment's outcome, and presents a triage-first view
2. Inline error context — expand a failed deployment to see the relevant log lines without leaving the workspace
3. "Open in log viewer" buttons to jump from the workspace into the full log viewer at a specific line
4. Single-file MSI/PSADT logs continue to open in the regular log viewer (no workspace routing for individual files)

## Non-Goals

- Cross-file timeline merging (PSADT + MSI interleaved chronologically)
- IME/Intune log correlation (the Intune workspace handles that)
- Automatic remediation suggestions
- PSADT phase-aware collapsible sections within the workspace

---

## 1. Architecture Overview

The workspace follows the same bespoke pattern as the Intune and DSRegCmd workspaces:

```
User opens folder → Toolbar dispatches to deployment workspace
  → Frontend switches activeView to "deployment"
  → Backend command scans folder, parses logs, classifies outcomes
  → Results populate Zustand store
  → Workspace component renders: inventory → outcomes → errors → successes
```

### 1.1 New Files

| Layer | File | Purpose |
|-------|------|---------|
| Frontend | `src/components/deployment/DeploymentWorkspace.tsx` | Main workspace component — single scrollable page |
| Frontend | `src/components/deployment/DeploymentErrorCard.tsx` | Expandable error card with inline log context |
| Frontend | `src/components/deployment/DeploymentSuccessTable.tsx` | Table for succeeded/deferred deployments |
| Frontend | `src/components/deployment/DeploymentSidebar.tsx` | Sidebar: folder path, rescan button, file list, outcome summary |
| Store | `src/stores/deployment-store.ts` | Zustand store for workspace state |
| Backend | `src-tauri/src/commands/deployment.rs` | IPC command: scan folder, parse, classify |

### 1.2 Integration Points (Existing Files Modified)

| File | Change |
|------|--------|
| `src/stores/ui-store.ts` | Add `"deployment"` to `WorkspaceId` union type |
| `src/components/layout/AppShell.tsx` | Add conditional render for `DeploymentWorkspace` |
| `src/components/layout/FileSidebar.tsx` | Add `DeploymentSidebar` variant |
| `src/components/layout/Toolbar.tsx` | Add deployment workspace dispatch in `openPathForActiveWorkspace` |
| `src-tauri/src/lib.rs` | Register `analyze_deployment_folder` in `tauri::generate_handler!` |
| `src-tauri/src/commands/mod.rs` | Add `pub mod deployment;` |

---

## 2. Backend: Folder Analysis Command

### 2.1 IPC Command

```rust
#[tauri::command]
pub async fn analyze_deployment_folder(
    path: String,
    app_handle: tauri::AppHandle,
) -> Result<DeploymentAnalysisResult, String>
```

### 2.2 Scan Logic

1. **Enumerate files** in the folder matching `*.log` (non-recursive)
2. **Detect format** for each file using the existing `detect_parser()` (which now handles MSI and PSADT Legacy, and CCM/PSADT CMTrace was already supported)
3. **Filter** to only files detected as: `ParserKind::Msi`, `ParserKind::PsadtLegacy`, `ParserKind::Ccm` (PSADT CMTrace-format logs detect as CCM)
4. **Parse each file** using the appropriate parser
5. **Extract deployment metadata** from each parsed log (see 2.3)
6. **Classify outcomes** per deployment (see 2.4)
7. **Extract error context** for failed deployments (see 2.5)
8. **Return** the complete `DeploymentAnalysisResult`

### 2.3 Deployment Metadata Extraction

For each parsed log, extract:

| Field | Source (PSADT CMTrace) | Source (PSADT Legacy) | Source (MSI Verbose) |
|-------|----------------------|----------------------|---------------------|
| `app_name` | Message in `Open-ADTSession` line: `[AppVendor AppName AppVersion]` | Same pattern in message | `Product:` line or `ProductName` property dump |
| `app_version` | From session open message | Same | `ProductVersion` property dump |
| `deploy_type` | From session open message: `Install`/`Uninstall`/`Repair` | Same | Inferred from command line: `/i` = Install, `/x` = Uninstall, `/f` = Repair |
| `exit_code` | `Close-ADTSession` message: `exit code [N]` | Same | `MainEngineThread is returning N` |
| `start_time` | First log entry timestamp | First log entry timestamp | Header `=== Verbose logging started:` timestamp |
| `end_time` | Last log entry timestamp | Last log entry timestamp | Footer `=== Verbose logging stopped:` timestamp |
| `log_format` | `"PSADT (CMTrace)"` | `"PSADT (Legacy)"` | `"MSI Verbose"` |
| `file_path` | Source file path | Source file path | Source file path |
| `file_name` | Filename only | Filename only | Filename only |
| `total_lines` | Line count | Line count | Line count |

### 2.4 Outcome Classification

Each deployment is classified into one of three outcomes based on its exit code:

| Outcome | Exit Codes |
|---------|------------|
| `Succeeded` | 0, 3010 (reboot required but suppressed) |
| `Failed` | 1603, 1618, 1619, 1605, 1625, 1638, 1722, 1935, 60001-60008, and any other non-zero not in Deferred |
| `Deferred` | 1602, 1604, 60012 |

### 2.5 Error Context Extraction

For each failed deployment, the backend extracts the key error lines plus surrounding context:

**For MSI verbose logs:**
1. Find the first `Return value 3` line → this is the primary error
2. Extract 5 lines before and 3 lines after as context
3. Find the `MainEngineThread is returning` line
4. Extract the `Note: 1: NNNN` line closest to the first `Return value 3` (if present) → look up error code description
5. Find the `Product: ... -- Installation failed` line (if present)

**For PSADT logs (both formats):**
1. Find the `Close-ADTSession` line with the exit code
2. Find the `Start-ADTMsiProcess` or `Start-ADTProcess` line with the `[Exit code: N]` result
3. Find the `Executing [msiexec.exe ...]` line → extract the MSI log path from `/L*V "path"`
4. Extract 2 lines before and 1 line after each key line

The extracted context is returned as:

```rust
pub struct ErrorContext {
    /// Primary error description (human-readable)
    pub description: String,
    /// MSI error code if applicable
    pub msi_error_code: Option<u32>,
    /// MSI error code description from error_db
    pub msi_error_description: Option<String>,
    /// Failing action name (e.g., "CcmValidateServerConfig")
    pub failing_action: Option<String>,
    /// Context blocks from each relevant log file
    pub context_blocks: Vec<LogContextBlock>,
}

pub struct LogContextBlock {
    /// Source file path
    pub file_path: String,
    /// Source file name
    pub file_name: String,
    /// Label for the block (e.g., "PSADT Log Context", "MSI Log — First Return Value 3")
    pub label: String,
    /// Log lines with their line numbers and severity
    pub lines: Vec<ContextLine>,
}

pub struct ContextLine {
    pub line_number: u32,
    pub text: String,
    pub severity: Severity,
    /// Whether this is the primary error line (highlighted differently)
    pub is_primary: bool,
}
```

### 2.6 PSADT ↔ MSI Log Correlation

When a PSADT log references an MSI verbose log via the `Start-ADTMsiProcess` "Executing" line:

```
Executing [msiexec.exe /i "app.msi" ... /L*V "C:\Windows\Logs\Software\Vendor_App_1.0.0_Install.log"]
```

The backend extracts the MSI log path using:
```
/[Ll]\*[Vv]\s+"([^"]+)"
```

If the referenced MSI log file exists in the same folder (or at the absolute path), the backend:
1. Parses it
2. Extracts its error context
3. Includes both PSADT and MSI context blocks in the `ErrorContext`

If the MSI log is not found, only the PSADT context is included, and `msi_log_missing: true` is set on the deployment entry.

### 2.7 Result Structure

```rust
pub struct DeploymentAnalysisResult {
    /// Folder that was scanned
    pub folder_path: String,
    /// File inventory counts
    pub inventory: FileInventory,
    /// All detected deployments
    pub deployments: Vec<DeploymentEntry>,
}

pub struct FileInventory {
    pub psadt_count: u32,
    pub msi_count: u32,
    pub wrapper_count: u32,
    pub total_count: u32,
    /// Files that were found but not recognized as deployment logs
    pub unrecognized_count: u32,
}

pub struct DeploymentEntry {
    /// Unique ID for this deployment (index-based)
    pub id: u32,
    /// Application name (best effort extraction)
    pub app_name: String,
    /// Application version
    pub app_version: Option<String>,
    /// Install / Uninstall / Repair
    pub deploy_type: DeploymentType,
    /// The process exit code
    pub exit_code: i32,
    /// Classified outcome
    pub outcome: DeploymentOutcome,
    /// When the deployment started
    pub start_time: Option<String>,
    /// When the deployment ended
    pub end_time: Option<String>,
    /// Which log formats were involved
    pub log_formats: Vec<String>,
    /// Primary source file (PSADT log if present, else MSI log)
    pub primary_file: String,
    /// All source files for this deployment
    pub source_files: Vec<String>,
    /// Error context (only populated for Failed deployments)
    pub error_context: Option<ErrorContext>,
    /// Whether a referenced MSI log was not found
    pub msi_log_missing: bool,
}

pub enum DeploymentType { Install, Uninstall, Repair, Unknown }
pub enum DeploymentOutcome { Succeeded, Failed, Deferred }
```

---

## 3. Frontend: Zustand Store

### 3.1 Store Shape

```typescript
interface DeploymentStore {
  // Analysis state
  phase: "idle" | "analyzing" | "ready" | "error" | "empty";
  errorMessage: string | null;

  // Results
  folderPath: string | null;
  inventory: FileInventory | null;
  deployments: DeploymentEntry[];

  // Derived (computed from deployments)
  succeeded: DeploymentEntry[];
  failed: DeploymentEntry[];
  deferred: DeploymentEntry[];

  // UI state
  expandedErrorIds: Set<number>;

  // Actions
  beginAnalysis(folderPath: string): void;
  setResults(result: DeploymentAnalysisResult): void;
  failAnalysis(error: string): void;
  toggleErrorExpanded(id: number): void;
  expandAllErrors(): void;
  collapseAllErrors(): void;
  reset(): void;
}
```

### 3.2 Analysis Flow

```
beginAnalysis(path)
  → set phase = "analyzing"
  → invoke("analyze_deployment_folder", { path })
  → on success: setResults(result) → phase = "ready"
  → on error: failAnalysis(msg) → phase = "error"
  → if result.deployments.length === 0: phase = "empty"
```

---

## 4. Frontend: Workspace Component

### 4.1 DeploymentWorkspace.tsx

Single scrollable page with four sections, matching the approved mockup:

```
┌─────────────────────────────────────────────┐
│ Header: "Software Deployment Analysis" [path]│
├─────────────────────────────────────────────┤
│ File Inventory Bar                           │
│ [5 PSADT] [3 MSI verbose] [2 Wrapper] [Σ10] │
├─────────────────────────────────────────────┤
│ Outcome Summary                              │
│ [✓3 Succeeded] [✗2 Failed] [⏎1 Deferred]   │
├─────────────────────────────────────────────┤
│ ── ERRORS (2) ─────────────────────────────  │
│ ▸ VideoLAN VLC 3.0.20 [Install] Exit 1603   │
│   (expanded: inline log context)             │
│ ▸ 7-Zip 24.09 [Install] Exit 1722           │
├─────────────────────────────────────────────┤
│ ── SUCCEEDED (3) ──────────────────────────  │
│ Table: app, type, format, exit, time, file   │
├─────────────────────────────────────────────┤
│ ── DEFERRED (1) ───────────────────────────  │
│ Table: app, type, format, exit, time, file   │
└─────────────────────────────────────────────┘
```

**Phase-based rendering:**
- `idle`: Empty state with "Open a folder to begin" prompt
- `analyzing`: Spinner with "Scanning folder..." message
- `ready`: Full workspace content
- `error`: Error message with retry button
- `empty`: "No deployment logs found in this folder" message

### 4.2 DeploymentErrorCard.tsx

Each error card renders:

**Collapsed state:**
- Chevron, app name, deploy type badge, format badge, exit code, timestamp

**Expanded state (adds):**
- Error description bar with MSI error code lookup
- Metadata: source file names
- Log context blocks (one per source file, each with line numbers and severity coloring)
- Action buttons: "Open in Log Viewer" (opens the file in the main log viewer, scrolled to the error line), "Jump to Line N"

**Log line rendering** reuses severity-based CSS classes:
- Normal: default text on dark background
- Error: red-tinted background, light red text (`#ffa0a0`), red line number
- Warning: amber-tinted background, amber text
- Highlight: blue-tinted background (for `MainEngineThread` line)

### 4.3 DeploymentSuccessTable.tsx

Shared table component for Succeeded and Deferred sections. Columns:
- Application (name + version)
- Type (Install/Uninstall/Repair badge)
- Format (PSADT / MSI / PSADT + MSI badge)
- Exit Code (color-coded badge)
- Timestamp
- Source File

Rows are clickable → opens the log file in the regular log viewer.

### 4.4 DeploymentSidebar.tsx

Matches the sidebar pattern from other workspaces:

- **Folder path** display with copy button
- **Rescan** button
- **File list** — all discovered log files grouped by format (PSADT, MSI, Wrapper), clickable to open in log viewer
- **Quick stats** — outcome counts as compact badges
- **Open Folder** button — opens the folder in the OS file explorer

---

## 5. Navigation & Entry Points

### 5.1 How the User Gets Here

1. **Known Sources toolbar** → User clicks a folder source under "Software Deployment" group → toolbar detects it's a folder → dispatches to deployment workspace
2. **Open Folder dialog** → User opens any folder → if deployment logs are detected in the folder, offer to switch to the deployment workspace (or open as flat file list in the log viewer — user's choice)
3. **Sidebar** → When in the deployment workspace, the sidebar shows the folder contents and allows rescanning

### 5.2 How the User Leaves

- Click any "Open in Log Viewer" button → switches `activeView` to `"log"` and opens the specified file at the specified line
- Click a file in the sidebar → same behavior
- Open a different file/folder → standard workspace switching

### 5.3 WorkspaceId Registration

In `ui-store.ts`:
```typescript
type WorkspaceId = "log" | IntuneWorkspaceId | "dsregcmd" | "macos-diag" | "deployment";
```

---

## 6. "Open in Log Viewer" Navigation

When the user clicks "Open in Log Viewer" or "Jump to Line N" from an error card:

1. Store the target: `{ filePath: string, targetLine: number }`
2. Call `useUiStore.getState().setActiveWorkspace("log")`
3. Invoke the existing file-open command for the target file
4. After the log viewer loads, scroll to `targetLine`

This requires a small addition to the log store: a `pendingScrollTarget: number | null` that the log list component checks after loading a new file. If set, it scrolls to that line and clears the target.

---

## 7. Testing Strategy

### 7.1 Backend Tests

- **Folder scan**: Given a folder with mixed log files, correctly counts PSADT/MSI/wrapper/unrecognized
- **Metadata extraction**: App name, version, deploy type extracted from PSADT CMTrace, PSADT Legacy, and MSI verbose logs
- **Outcome classification**: Exit code 0 → Succeeded, 1603 → Failed, 1602 → Deferred, 3010 → Succeeded
- **Error context extraction**: For a failed MSI log, returns context around first `Return value 3` with correct line numbers
- **PSADT ↔ MSI correlation**: When PSADT references an MSI log path that exists, both context blocks are returned
- **Missing MSI log**: When PSADT references an MSI log that doesn't exist, `msi_log_missing` is set

### 7.2 Frontend Tests (Manual)

- Workspace renders all four sections with correct data
- Error cards expand/collapse on click
- Log context lines display correct severity coloring
- "Open in Log Viewer" navigates to the correct file and line
- Sidebar shows file list and outcome badges
- Empty state displays when no deployment logs found
- Error state displays when folder scan fails

---

## 8. Implementation Order

| Step | Description | Dependencies |
|------|-------------|--------------|
| 1 | Backend: `DeploymentAnalysisResult` types and `analyze_deployment_folder` command | MSI parser + PSADT parser from parent design |
| 2 | Backend: Metadata extraction logic for each format | Step 1 |
| 3 | Backend: Outcome classification and error context extraction | Step 2 |
| 4 | Backend: PSADT ↔ MSI log correlation | Step 3 |
| 5 | Frontend: `deployment-store.ts` Zustand store | Step 1 (types) |
| 6 | Frontend: `DeploymentWorkspace.tsx` main component | Step 5 |
| 7 | Frontend: `DeploymentErrorCard.tsx` with inline log context | Step 6 |
| 8 | Frontend: `DeploymentSuccessTable.tsx` | Step 6 |
| 9 | Frontend: `DeploymentSidebar.tsx` | Step 6 |
| 10 | Integration: Wire into `AppShell`, `FileSidebar`, `Toolbar`, `ui-store` | Steps 6-9 |
| 11 | Navigation: "Open in Log Viewer" with scroll-to-line | Step 10 |
| 12 | Register command in `lib.rs`, add `pub mod deployment` | Step 4 |
| 13 | Tests | All steps |

---

## 9. Files Changed Summary

| File | Change |
|------|--------|
| `src-tauri/src/commands/deployment.rs` | **New** — `analyze_deployment_folder` command, metadata extraction, outcome classification, error context |
| `src-tauri/src/commands/mod.rs` | Add `pub mod deployment;` |
| `src-tauri/src/lib.rs` | Register `analyze_deployment_folder` in handler |
| `src/components/deployment/DeploymentWorkspace.tsx` | **New** — main workspace, single scrollable page |
| `src/components/deployment/DeploymentErrorCard.tsx` | **New** — expandable error card with log context |
| `src/components/deployment/DeploymentSuccessTable.tsx` | **New** — table for succeeded/deferred entries |
| `src/components/deployment/DeploymentSidebar.tsx` | **New** — sidebar for deployment workspace |
| `src/stores/deployment-store.ts` | **New** — Zustand store |
| `src/stores/ui-store.ts` | Add `"deployment"` to `WorkspaceId` |
| `src/stores/log-store.ts` | Add `pendingScrollTarget` for jump-to-line |
| `src/components/layout/AppShell.tsx` | Add `DeploymentWorkspace` render branch |
| `src/components/layout/FileSidebar.tsx` | Add `DeploymentSidebar` variant |
| `src/components/layout/Toolbar.tsx` | Add deployment workspace dispatch |
| `src-tauri/tests/` | Backend test fixtures and cases |
