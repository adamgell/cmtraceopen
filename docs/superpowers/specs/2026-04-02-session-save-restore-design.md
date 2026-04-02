# Session Save/Restore

## Overview

Save the current workspace state (open files, scroll positions, filters, merged tabs, workspace context) to a `.cmtrace` JSON file. Double-click or "Open Session..." to restore the full workspace. Recent sessions submenu for quick access.

## File Format

```json
{
  "version": 1,
  "savedAt": "2026-04-02T12:00:00Z",
  "workspace": "log",
  "tabs": [
    {
      "filePath": "/path/to/AppWorkload.log",
      "fileHash": "sha256:abc123...",
      "fileSize": 524288,
      "selectedId": 42,
      "scrollPosition": 1500,
      "activeColumns": ["severity", "dateTime", "message", "component"]
    }
  ],
  "activeTabIndex": 0,
  "mergedTabState": {
    "sourceFilePaths": ["/path/a.log", "/path/b.log"],
    "fileVisibility": { "/path/a.log": true, "/path/b.log": true },
    "correlationWindowMs": 1000,
    "autoCorrelate": true
  },
  "filters": {
    "clauses": [],
    "findQuery": "error",
    "findCaseSensitive": false,
    "findUseRegex": false,
    "highlightText": "timeout"
  },
  "workspaceState": {
    "type": "log"
  }
}
```

For non-log workspaces:

```json
{
  "workspaceState": {
    "type": "intune",
    "sourceFile": "/path/to/folder",
    "activeTab": "timeline",
    "filterEventType": "All",
    "filterStatus": "All",
    "timelineViewMode": "list"
  }
}
```

```json
{
  "workspaceState": {
    "type": "dsregcmd",
    "sourcePath": "/path/to/dsregcmd.txt"
  }
}
```

The `version` field allows forward-compatible migration. Unknown fields are ignored on restore.

## Save Flow

1. User clicks File → Save Session... (Ctrl+Shift+S) or native menu
2. System save dialog opens with `.cmtrace` extension filter
3. Frontend collects state from all stores:
   - `log-store`: open file paths, entries metadata, selected IDs, merged state
   - `ui-store`: active tab index, active workspace, active columns
   - `filter-store`: filter clauses
   - `intune-store` / `dsregcmd-store`: workspace-specific state if active
4. For each open file, calls backend `compute_file_hash(path)` to get SHA-256 hash + file size
5. Writes JSON to chosen path
6. Adds path to recent sessions list in ui-store

## Restore Flow

1. User clicks File → Open Session..., selects from Recent Sessions, or double-clicks `.cmtrace` file
2. Frontend reads and validates JSON (check `version` field)
3. For each tab entry:
   - Check if file exists at `filePath`
   - If exists: compare hash/size with saved values
   - If hash differs: show warning "File has changed since session was saved" with option to continue or skip
   - If missing: show warning "File not found: /path/to/file.log" with option to locate or skip
4. Parse each valid file using the existing `parse_files_batch` command
5. Restore tab order, active tab index
6. For each tab: restore selected entry ID, scroll position (via `pendingScrollTarget` pattern)
7. Restore active columns per tab
8. Restore filters and find query
9. If merged tab state exists: call `createMergedTab` with the saved source paths, restore visibility and correlation settings
10. Switch to the saved workspace and restore workspace-specific state

## Recent Sessions

- Stored in ui-store persisted preferences: `recentSessions: string[]` (last 5 file paths)
- "Recent Sessions" submenu in the File menu lists saved paths
- Each entry shows the filename (basename) with full path as tooltip
- Clicking opens that session file
- Entries pointing to deleted `.cmtrace` files are pruned when the submenu is built
- New saves push to the front, duplicates are moved to front, oldest dropped when exceeding 5

## File Association

### Windows (NSIS/MSI installer)
- Register `.cmtrace` file extension during install
- Associate with `cmtrace-open.exe` with `--session` argument
- Icon: app icon with a small session overlay

### macOS (Info.plist)
- Register `com.cmtraceopen.session` document type for `.cmtrace` extension
- App receives the file path via Tauri's file association handler

### Fallback prompt
- On first save, if association isn't registered, prompt via existing `FileAssociationPromptDialog` pattern
- User can dismiss or register

### Command line
- `cmtrace-open session.cmtrace` — opens the session
- `cmtrace-open --session path/to/session.cmtrace` — explicit flag

## Backend

One new Rust command:

```rust
#[tauri::command]
pub fn compute_file_hash(path: String) -> Result<FileHashResult, AppError> {
    // SHA-256 hash of file contents + file size
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileHashResult {
    pub hash: String,      // "sha256:<hex>"
    pub size_bytes: u64,
}
```

Everything else is frontend-only — collecting and restoring store state.

## Menu Changes

### Native menu (`menu.rs`)
- Add: `MENU_ID_FILE_SAVE_SESSION` → action `"save_session"` (Ctrl+Shift+S)
- Add: `MENU_ID_FILE_OPEN_SESSION` → action `"open_session"`
- Add: "Recent Sessions" submenu (dynamic, built from persisted list)

### Frontend (`use-app-menu.ts`)
- Handle `"save_session"` → trigger save flow
- Handle `"open_session"` → open file dialog filtered to `.cmtrace`
- Handle `"open_recent_session"` → restore from path

## Store Changes

### ui-store
- Add `recentSessions: string[]` (persisted, max 5)
- Add `addRecentSession(path: string): void`
- Add `clearRecentSessions(): void`

## New Files

| File | Responsibility |
|------|----------------|
| `src/lib/session.ts` | Session file format types, serialize/deserialize, validation |
| `src/lib/session-save.ts` | Collect state from all stores, call hash command, write file |
| `src/lib/session-restore.ts` | Read file, validate, warn about changes, restore state to stores |
| `src-tauri/src/commands/file_hash.rs` | SHA-256 hash command |

## Out of Scope

- Auto-save on exit (future enhancement)
- Embedding log data in the session file
- Saving UI preferences (theme, font size) — these stay global
- Session file encryption
