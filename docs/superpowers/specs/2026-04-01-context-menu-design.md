# Right-Click Context Menu — Design Spec

**Issue:** #53 — Create Exclude filter on right click
**Date:** 2026-04-01

## Overview

Add a native OS context menu to log rows in the main log view. The menu provides quick filtering, clipboard operations, and navigation actions. Uses Tauri's native menu API for platform-consistent look and feel.

## Menu Structure

```
Copy Line                    (copies full formatted line)
Copy Message                 (copies message column text)
Copy Timestamp               (copies datetime column text)
────────────────────────────
Include Filter: "<text>"     (creates "contains" filter for clicked cell text)
Exclude Filter: "<text>"     (creates "not contains" filter for clicked cell text)
────────────────────────────
Error Lookup                 (opens error lookup for error code in line, if present)
Jump to Line...              (opens jump-to-line input)
Open Source File              (reveals source file in OS, if sourceFile column present)
```

**Dynamic behavior:**
- `<text>` in filter items shows a truncated preview of the clicked cell value (max 40 chars)
- "Error Lookup" is only shown if the line contains a recognizable error code pattern (hex `0x...` or known error format)
- "Open Source File" is only shown if the event has a `sourceFile` value and the file exists on disk
- If no text is selected/clicked, filter items are disabled

## Architecture

### Trigger
Right-click on any row in `LogRow.tsx` (the virtual list row component). The handler captures:
- The clicked row's `LogEntry` data
- The column the click landed in (for cell-specific copy/filter)

### Native Menu Creation
Use Tauri v2's `Menu` and `MenuItem` APIs from the Rust backend:

**Backend command:** `show_log_row_context_menu`
- Receives: row data (message, timestamp, component, thread, sourceFile, errorCode)
- Builds a native `Menu` with `MenuItem` entries
- Shows the menu at the cursor position
- Returns the selected action ID to the frontend

**Frontend handler:** `use-context-menu.ts` hook
- Attaches `onContextMenu` handler to log rows
- Calls the Tauri command with row data
- Dispatches the returned action to the appropriate store/dialog

### Filter Actions
The filter store needs a new convenience action:

```typescript
// In filter-store.ts
addQuickFilter(field: FilterField, value: string, operator: "Contains" | "NotContains"): void
```

This creates a new filter clause and activates it immediately, equivalent to the user manually creating a filter in the FilterDialog.

## Files

| File | Action | Purpose |
|------|--------|---------|
| `src-tauri/src/commands/context_menu.rs` | New | Backend command to build and show native context menu |
| `src-tauri/src/lib.rs` | Modify | Register new command in `invoke_handler` |
| `src/hooks/use-context-menu.ts` | New | Hook: right-click handler + action dispatcher |
| `src/components/log-view/LogRow.tsx` | Modify | Attach `onContextMenu` handler |
| `src/stores/filter-store.ts` | Modify | Add `addQuickFilter()` action |

## Platform Considerations

- **Windows/macOS:** Native menus work out of the box via Tauri
- **Linux:** Native menus work but appearance depends on desktop environment
- Menu items use standard OS keyboard accelerator hints where applicable

## Verification

1. Right-click a log row → native context menu appears
2. "Copy Line" → clipboard contains the full log line text
3. "Copy Message" → clipboard contains only the message column
4. "Include Filter" → filter store gains a new "Contains" clause, log view filters immediately
5. "Exclude Filter" → filter store gains a "NotContains" clause
6. "Error Lookup" → error lookup dialog opens with the error code pre-filled
7. "Open Source File" → OS file manager opens to the source file location
8. Right-click on a row with no error code → "Error Lookup" is hidden/disabled
