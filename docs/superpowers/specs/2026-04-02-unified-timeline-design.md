# Multi-File Unified Timeline

## Overview

Merge entries from multiple open log files into a single time-sorted view. Two entry points: manual tab selection and optional folder merge. The merged view lives in a virtual tab with per-file color coding, toggle visibility, a lightweight cache, and cross-file timestamp correlation.

## Entry Points

### Manual Merge

A "Merge Tabs..." button in the toolbar (visible when 2+ file tabs are open). Opens a dialog listing all open tabs with checkboxes. Select 2+ and click "Merge." Creates a virtual merged tab.

Files without parseable timestamps are shown with a warning icon and excluded from selection. The dialog shows each file's entry count and time range to help the user decide.

### Folder Merge

When a folder is loaded and the file sidebar lists multiple files, a "Merge into Timeline" button appears at the top of the sidebar. Clicking it merges all timestamped files into a virtual merged tab. Files without timestamps are excluded with a toast notification listing the skipped files.

## Merged Tab

### Identity

- Tab title: "Merged: file1 + file2 + ..." (truncated to fit, full list in tooltip)
- Tab icon: a distinct merge/layers icon to differentiate from file tabs
- Tab type: `"merged"` (new `SourceOpenMode` variant)

### Lifecycle

- Original file tabs remain open and independent
- Closing the merged tab does not affect originals
- Closing an original file tab removes its entries from the merged view and triggers a re-merge
- If only 1 source tab remains, the merged tab auto-closes with a toast: "Merged view closed — only one source file remains"

### Sorting

- Primary: `timestamp` epoch (ascending, descending toggle)
- Secondary: filename alphabetical
- Tertiary: line number within file
- Entries without timestamps are excluded (strict mode)

## Visual Differentiation

### Color Stripes

Each source file is assigned a color from an 8-color palette:

```
["#2563eb", "#dc2626", "#16a34a", "#9333ea", "#ea580c", "#0891b2", "#c026d3", "#854d0e"]
```

Colors cycle if more than 8 files. Applied as a 3px left border on each log row, replacing the default alternating row background for merged views.

### Source Column

An optional "Source" column showing the truncated filename (last path segment). Enabled by default in merged views. Can be toggled via column settings.

### Legend Bar

A horizontal bar below the toolbar, visible only in merged tabs. Contains:

- One chip per source file: colored dot + truncated filename + entry count
- Each chip is a toggle button — click to show/hide that file's entries
- "All" / "None" toggle buttons on the right
- Compact: single row, horizontally scrollable if many files

Toggling a file off filters its entries from the view without re-sorting the remaining entries (just a filter mask on the merged array).

## Merge Cache

### Structure

```typescript
interface MergedTabState {
  sourceFilePaths: string[];
  colorAssignments: Record<string, string>; // filePath → hex color
  fileVisibility: Record<string, boolean>;  // filePath → visible toggle
  mergedEntries: LogEntry[];                // cached sorted merge result
  cacheKey: string;                         // hash of source paths + entry counts
}
```

### Invalidation

The cache invalidates (triggers re-merge) when:
- A source tab closes (entries removed)
- A source tab receives new entries via tail (`appendEntries`)
- File visibility toggles do NOT invalidate the cache — they apply a filter mask on top of the cached `mergedEntries`

### Performance

- Merge uses a k-way merge (already implemented as `compareMergedLogEntries` in log-store) rather than concat + sort
- For 10 files x 50K entries each = 500K entries, the k-way merge is O(n log k) and should complete in under 500ms
- The virtualized list handles rendering — only ~50 rows in the DOM at any time

## Cross-File Timestamp Correlation ("Jump to Same Timestamp")

### Trigger

When the user selects an entry in the merged view, a "Correlate" action appears in the detail pane (or via keyboard shortcut). This highlights all entries from OTHER source files within a configurable time window of the selected entry's timestamp.

### Behavior

1. User selects entry at timestamp T from file A
2. System finds entries from files B, C, ... where `abs(entry.timestamp - T) <= windowMs`
3. Default window: 1000ms (1 second)
4. Matching entries get a subtle highlight (background tint matching their file's color, at 20% opacity)
5. The detail pane shows a "Correlated entries" section listing the matches grouped by file, with timestamps showing the delta from T (e.g., "+200ms", "-50ms")
6. Arrow keys in the correlated list jump between correlated entries

### Configuration

- Time window adjustable: 100ms, 500ms, 1s (default), 5s, 10s
- Dropdown in the legend bar or detail pane
- Auto-correlation toggle: when enabled, correlation runs on every selection change. When disabled, requires explicit "Correlate" click. Default: enabled.

## Store Changes

### log-store.ts

Add to `LogState`:

```typescript
mergedTabState: MergedTabState | null;
correlationWindow: number;       // ms, default 1000
autoCorrelate: boolean;          // default true
correlatedEntryIds: Set<number>; // IDs of entries within correlation window
```

Actions:

```typescript
createMergedTab: (sourceFilePaths: string[]) => void;
closeMergedTab: () => void;
setFileVisibility: (filePath: string, visible: boolean) => void;
setAllFileVisibility: (visible: boolean) => void;
setCorrelationWindow: (ms: number) => void;
setAutoCorrelate: (enabled: boolean) => void;
correlateFromEntry: (entryId: number) => void;
```

### TabEntrySnapshot

Add `sourceOpenMode: "merged"` variant. Merged tabs use `MergedTabState` instead of a file path for their cache key.

## UI Changes

### Toolbar

- "Merge Tabs..." button — visible when 2+ file tabs are open, hidden otherwise

### Tab Strip

- Merged tabs show a merge icon and the combined filename label
- Tooltip shows full list of source files

### Legend Bar (new component)

- `src/components/log-view/MergeLegendBar.tsx`
- Renders between toolbar and log list, only for merged tabs
- File chips with color dots, toggle checkboxes, entry counts
- Correlation window dropdown
- Auto-correlate toggle

### LogRow

- In merged view, left border color comes from the file's assigned color instead of severity
- Correlated entries get a background highlight tint

### InfoPane

- When auto-correlate is on and an entry is selected, shows a "Correlated Entries" section below the main detail
- Groups correlated entries by source file
- Shows timestamp delta from the selected entry
- Click to jump to that entry in the merged list

## No Backend Changes

All merge logic is client-side. Entries already exist in the tab cache (`tabEntryCache`). The merge reads from cached snapshots and produces a new sorted array.

## Out of Scope

- Merging entries from different workspaces (e.g., Intune + log viewer)
- Saving merged views to disk (that's the Session Save/Restore feature)
- Diff between files (that's the Log Diff feature)
- Merging files with incompatible timestamp formats (excluded with warning)
