# Multi-File Unified Timeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Merge entries from multiple open log files into a single time-sorted view with per-file color coding, visibility toggles, and cross-file timestamp correlation.

**Architecture:** Client-side only — no backend changes. A new `MergedTabState` in the log store holds the merged entry array, color assignments, and visibility toggles. Merge is triggered from a toolbar dialog or folder sidebar button and creates a virtual tab. A `MergeLegendBar` component provides file toggles and correlation controls. The `LogRow` component gains a file-color left border in merged mode, and the `InfoPane` gains a correlated entries section.

**Tech Stack:** React 19, Zustand, TanStack Virtual (existing), Fluent UI v9 tokens (existing)

---

## File Structure

| File | Action | Responsibility |
|------|--------|----------------|
| `src/lib/merge-entries.ts` | Create | Pure merge logic: k-way merge, color assignment, correlation search |
| `src/stores/log-store.ts` | Modify | Add `MergedTabState`, merge/correlation actions, cache invalidation |
| `src/components/dialogs/MergeTabsDialog.tsx` | Create | Dialog for selecting tabs to merge |
| `src/components/log-view/MergeLegendBar.tsx` | Create | File chips with toggles, correlation controls |
| `src/components/log-view/LogRow.tsx` | Modify | File-color left border, correlation highlight |
| `src/components/log-view/LogListView.tsx` | Modify | Pass merged state props to LogRow, render legend bar |
| `src/components/log-view/InfoPane.tsx` | Modify | Correlated entries section |
| `src/components/layout/Toolbar.tsx` | Modify | "Merge Tabs..." button |
| `src/components/layout/TabStrip.tsx` | Modify | Merged tab icon and label |
| `src/components/layout/FileSidebar.tsx` | Modify | "Merge into Timeline" button |
| `src/components/layout/AppShell.tsx` | Modify | Render MergeTabsDialog |
| `src/stores/ui-store.ts` | Modify | Add `showMergeTabsDialog` state |

---

### Task 1: Pure Merge Logic

**Files:**
- Create: `src/lib/merge-entries.ts`

This module contains all merge logic with no React dependency — pure functions that are easy to test.

- [ ] **Step 1: Create the merge-entries module with types and color palette**

```typescript
// src/lib/merge-entries.ts
import type { LogEntry } from "../types/log";

export const MERGE_FILE_COLORS = [
  "#2563eb", "#dc2626", "#16a34a", "#9333ea",
  "#ea580c", "#0891b2", "#c026d3", "#854d0e",
];

export interface MergedTabState {
  sourceFilePaths: string[];
  colorAssignments: Record<string, string>;
  fileVisibility: Record<string, boolean>;
  mergedEntries: LogEntry[];
  cacheKey: string;
}

export interface CorrelatedEntry {
  entry: LogEntry;
  deltaMs: number;
  fileColor: string;
}

/**
 * Assign a color to each file path, cycling through the palette.
 */
export function assignFileColors(
  filePaths: string[]
): Record<string, string> {
  const assignments: Record<string, string> = {};
  for (let i = 0; i < filePaths.length; i++) {
    assignments[filePaths[i]] = MERGE_FILE_COLORS[i % MERGE_FILE_COLORS.length];
  }
  return assignments;
}

/**
 * Build a cache key from source file paths and their entry counts.
 */
export function buildMergeCacheKey(
  filePaths: string[],
  entryCounts: Record<string, number>
): string {
  return filePaths
    .map((fp) => `${fp}:${entryCounts[fp] ?? 0}`)
    .sort()
    .join("|");
}

/**
 * Merge entries from multiple files into a single time-sorted array.
 * Only includes entries with timestamps (strict mode).
 * Sort: timestamp → filename → line number.
 */
export function mergeEntries(
  entriesByFile: Record<string, LogEntry[]>
): LogEntry[] {
  const allTimestamped: LogEntry[] = [];

  for (const entries of Object.values(entriesByFile)) {
    for (const entry of entries) {
      if (entry.timestamp != null) {
        allTimestamped.push(entry);
      }
    }
  }

  allTimestamped.sort((a, b) => {
    // Primary: timestamp
    if (a.timestamp !== b.timestamp) return a.timestamp! - b.timestamp!;
    // Secondary: filename
    const fileCmp = a.filePath.localeCompare(b.filePath);
    if (fileCmp !== 0) return fileCmp;
    // Tertiary: line number
    return a.lineNumber - b.lineNumber;
  });

  return allTimestamped;
}

/**
 * Apply file visibility filter to merged entries.
 * Does not re-sort — just filters.
 */
export function filterByVisibility(
  entries: LogEntry[],
  visibility: Record<string, boolean>
): LogEntry[] {
  return entries.filter((e) => visibility[e.filePath] !== false);
}

/**
 * Count entries per file path.
 */
export function countEntriesByFile(
  entries: LogEntry[]
): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const entry of entries) {
    counts[entry.filePath] = (counts[entry.filePath] ?? 0) + 1;
  }
  return counts;
}

/**
 * Find entries from other files within a time window of a target timestamp.
 */
export function findCorrelatedEntries(
  entries: LogEntry[],
  targetEntry: LogEntry,
  windowMs: number,
  colorAssignments: Record<string, string>
): CorrelatedEntry[] {
  if (targetEntry.timestamp == null) return [];

  const targetTs = targetEntry.timestamp;
  const results: CorrelatedEntry[] = [];

  for (const entry of entries) {
    if (entry.filePath === targetEntry.filePath) continue;
    if (entry.timestamp == null) continue;

    const delta = entry.timestamp - targetTs;
    if (Math.abs(delta) <= windowMs) {
      results.push({
        entry,
        deltaMs: delta,
        fileColor: colorAssignments[entry.filePath] ?? "#888",
      });
    }
  }

  results.sort((a, b) => Math.abs(a.deltaMs) - Math.abs(b.deltaMs));
  return results;
}

/**
 * Get the basename of a file path.
 */
export function fileBaseName(filePath: string): string {
  return filePath.split(/[\\/]/).pop() ?? filePath;
}
```

- [ ] **Step 2: Verify TypeScript compiles**

Run: `npx tsc --noEmit`
Expected: No errors

- [ ] **Step 3: Commit**

```bash
git add src/lib/merge-entries.ts
git commit -m "feat(merge): add pure merge logic — sorting, colors, correlation"
```

---

### Task 2: Store Changes — MergedTabState and Actions

**Files:**
- Modify: `src/stores/log-store.ts`

Add the merged tab state, correlation state, and all actions to the log store.

- [ ] **Step 1: Add imports at the top of log-store.ts**

Add after the existing `guid-name-map` import:

```typescript
import {
  type MergedTabState,
  type CorrelatedEntry,
  assignFileColors,
  buildMergeCacheKey,
  mergeEntries,
  filterByVisibility,
  countEntriesByFile,
  findCorrelatedEntries,
} from "../lib/merge-entries";
```

- [ ] **Step 2: Export MergedTabState from log-store**

Add re-export after imports:

```typescript
export type { MergedTabState, CorrelatedEntry };
```

- [ ] **Step 3: Add fields to the LogState interface**

Add after the `guidNameMap` field (~line 542):

```typescript
  /** Merged tab state when viewing a multi-file merged timeline. */
  mergedTabState: MergedTabState | null;
  /** Correlation time window in milliseconds. */
  correlationWindowMs: number;
  /** Whether correlation runs automatically on selection change. */
  autoCorrelate: boolean;
  /** Entries from other files within the correlation window of the selected entry. */
  correlatedEntries: CorrelatedEntry[];
```

- [ ] **Step 4: Add action signatures to LogState interface**

Add after the existing `setPendingScrollTarget` action:

```typescript
  createMergedTab: (sourceFilePaths: string[]) => void;
  closeMergedTab: () => void;
  setFileVisibility: (filePath: string, visible: boolean) => void;
  setAllFileVisibility: (visible: boolean) => void;
  setCorrelationWindowMs: (ms: number) => void;
  setAutoCorrelate: (enabled: boolean) => void;
  updateCorrelation: () => void;
```

- [ ] **Step 5: Add default values in the store creation**

Add after `guidNameMap: {},`:

```typescript
  mergedTabState: null,
  correlationWindowMs: 1000,
  autoCorrelate: true,
  correlatedEntries: [],
```

- [ ] **Step 6: Implement createMergedTab action**

Add after the `setPendingScrollTarget` action implementation:

```typescript
  createMergedTab: (sourceFilePaths) => {
    // Collect entries from tab cache for each source file
    const entriesByFile: Record<string, LogEntry[]> = {};
    const entryCounts: Record<string, number> = {};

    for (const fp of sourceFilePaths) {
      const snapshot = getCachedTabSnapshot(fp);
      if (snapshot) {
        entriesByFile[fp] = snapshot.entries;
        entryCounts[fp] = snapshot.entries.length;
      }
    }

    const validPaths = Object.keys(entriesByFile);
    if (validPaths.length < 2) return;

    const colorAssignments = assignFileColors(validPaths);
    const fileVisibility: Record<string, boolean> = {};
    for (const fp of validPaths) {
      fileVisibility[fp] = true;
    }

    const merged = mergeEntries(entriesByFile);
    const cacheKey = buildMergeCacheKey(validPaths, entryCounts);

    set({
      mergedTabState: {
        sourceFilePaths: validPaths,
        colorAssignments,
        fileVisibility,
        mergedEntries: merged,
        cacheKey,
      },
      entries: filterByVisibility(merged, fileVisibility),
      sourceOpenMode: "merged" as SourceOpenMode,
      selectedId: null,
      correlatedEntries: [],
    });
  },
```

- [ ] **Step 7: Implement closeMergedTab action**

```typescript
  closeMergedTab: () => {
    set({
      mergedTabState: null,
      entries: [],
      sourceOpenMode: null,
      selectedId: null,
      correlatedEntries: [],
    });
  },
```

- [ ] **Step 8: Implement file visibility actions**

```typescript
  setFileVisibility: (filePath, visible) => {
    set((state) => {
      if (!state.mergedTabState) return {};
      const fileVisibility = {
        ...state.mergedTabState.fileVisibility,
        [filePath]: visible,
      };
      return {
        mergedTabState: { ...state.mergedTabState, fileVisibility },
        entries: filterByVisibility(state.mergedTabState.mergedEntries, fileVisibility),
        selectedId: null,
        correlatedEntries: [],
      };
    });
    recomputeAndSetMatches();
  },

  setAllFileVisibility: (visible) => {
    set((state) => {
      if (!state.mergedTabState) return {};
      const fileVisibility: Record<string, boolean> = {};
      for (const fp of state.mergedTabState.sourceFilePaths) {
        fileVisibility[fp] = visible;
      }
      return {
        mergedTabState: { ...state.mergedTabState, fileVisibility },
        entries: visible
          ? state.mergedTabState.mergedEntries
          : [],
        selectedId: null,
        correlatedEntries: [],
      };
    });
    recomputeAndSetMatches();
  },
```

- [ ] **Step 9: Implement correlation actions**

```typescript
  setCorrelationWindowMs: (ms) => set({ correlationWindowMs: ms }),

  setAutoCorrelate: (enabled) => set({ autoCorrelate: enabled }),

  updateCorrelation: () => {
    const state = useLogStore.getState();
    if (!state.mergedTabState || !state.autoCorrelate || state.selectedId == null) {
      if (state.correlatedEntries.length > 0) {
        set({ correlatedEntries: [] });
      }
      return;
    }

    const selectedEntry = state.entries.find((e) => e.id === state.selectedId);
    if (!selectedEntry) {
      set({ correlatedEntries: [] });
      return;
    }

    const correlated = findCorrelatedEntries(
      state.mergedTabState.mergedEntries,
      selectedEntry,
      state.correlationWindowMs,
      state.mergedTabState.colorAssignments
    );
    set({ correlatedEntries: correlated });
  },
```

- [ ] **Step 10: Update selectEntry to trigger correlation**

Find the existing `selectEntry` action and modify it:

```typescript
  selectEntry: (id) => {
    set({ selectedId: id });
    // Trigger correlation update in merged mode
    setTimeout(() => useLogStore.getState().updateCorrelation(), 0);
  },
```

- [ ] **Step 11: Update SourceOpenMode type**

Change line 92:

```typescript
export type SourceOpenMode = "single-file" | "aggregate-folder" | "merged" | null;
```

- [ ] **Step 12: Add mergedTabState to clearActiveFile and clear actions**

In `clearActiveFile`, add `mergedTabState: null, correlatedEntries: [],` to the set object.

In `clear`, add `mergedTabState: null, correlatedEntries: [],` to the set object.

- [ ] **Step 13: Verify TypeScript compiles**

Run: `npx tsc --noEmit`
Expected: No errors

- [ ] **Step 14: Commit**

```bash
git add src/stores/log-store.ts
git commit -m "feat(merge): add MergedTabState, merge/correlation actions to log store"
```

---

### Task 3: UI Store — Merge Dialog Toggle

**Files:**
- Modify: `src/stores/ui-store.ts`

- [ ] **Step 1: Add showMergeTabsDialog state**

Add to the `UiState` interface, near `showGuidRegistryDialog`:

```typescript
  showMergeTabsDialog: boolean;
  setShowMergeTabsDialog: (show: boolean) => void;
```

Add default value `showMergeTabsDialog: false,` in the store creation.

Add setter: `setShowMergeTabsDialog: (show) => set({ showMergeTabsDialog: show }),`

- [ ] **Step 2: Commit**

```bash
git add src/stores/ui-store.ts
git commit -m "feat(merge): add showMergeTabsDialog state to ui-store"
```

---

### Task 4: Merge Tabs Dialog

**Files:**
- Create: `src/components/dialogs/MergeTabsDialog.tsx`

- [ ] **Step 1: Create the dialog component**

```typescript
// src/components/dialogs/MergeTabsDialog.tsx
import { useMemo, useState } from "react";
import {
  Button,
  Checkbox,
  Dialog,
  DialogActions,
  DialogBody,
  DialogContent,
  DialogSurface,
  DialogTitle,
  tokens,
} from "@fluentui/react-components";
import { WarningRegular } from "@fluentui/react-icons";
import { LOG_MONOSPACE_FONT_FAMILY } from "../../lib/log-accessibility";
import { getCachedTabSnapshot } from "../../stores/log-store";
import { useUiStore } from "../../stores/ui-store";
import { formatLogEntryTimestamp } from "../../lib/date-time-format";

interface MergeTabsDialogProps {
  isOpen: boolean;
  onClose: () => void;
  onMerge: (filePaths: string[]) => void;
}

interface TabInfo {
  filePath: string;
  fileName: string;
  entryCount: number;
  hasTimestamps: boolean;
  timeRange: string | null;
}

function getTabInfo(filePath: string): TabInfo {
  const snapshot = getCachedTabSnapshot(filePath);
  const fileName = filePath.split(/[\\/]/).pop() ?? filePath;
  if (!snapshot) {
    return { filePath, fileName, entryCount: 0, hasTimestamps: false, timeRange: null };
  }

  const timestamped = snapshot.entries.filter((e) => e.timestamp != null);
  const hasTimestamps = timestamped.length > 0;

  let timeRange: string | null = null;
  if (hasTimestamps) {
    const first = formatLogEntryTimestamp(timestamped[0]);
    const last = formatLogEntryTimestamp(timestamped[timestamped.length - 1]);
    if (first && last) {
      timeRange = `${first} — ${last}`;
    }
  }

  return {
    filePath,
    fileName,
    entryCount: snapshot.entries.length,
    hasTimestamps,
    timeRange,
  };
}

export function MergeTabsDialog({ isOpen, onClose, onMerge }: MergeTabsDialogProps) {
  const openTabs = useUiStore((s) => s.openTabs);
  const [selected, setSelected] = useState<Set<string>>(new Set());

  const tabInfos = useMemo(() => {
    return openTabs.map((tab) => getTabInfo(tab.filePath));
  }, [openTabs]);

  const toggleFile = (filePath: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(filePath)) next.delete(filePath);
      else next.add(filePath);
      return next;
    });
  };

  const selectAll = () => {
    const eligible = tabInfos.filter((t) => t.hasTimestamps).map((t) => t.filePath);
    setSelected(new Set(eligible));
  };

  const selectNone = () => setSelected(new Set());

  const canMerge = selected.size >= 2;

  const handleMerge = () => {
    if (!canMerge) return;
    onMerge(Array.from(selected));
    setSelected(new Set());
    onClose();
  };

  const handleClose = () => {
    setSelected(new Set());
    onClose();
  };

  return (
    <Dialog open={isOpen} onOpenChange={(_, data) => { if (!data.open) handleClose(); }}>
      <DialogSurface style={{ maxWidth: "600px", width: "90vw" }}>
        <DialogBody>
          <DialogTitle>Merge Tabs into Timeline</DialogTitle>
          <DialogContent>
            <div style={{ marginBottom: "8px", fontSize: "12px", color: tokens.colorNeutralForeground3 }}>
              Select 2 or more tabs to merge into a unified time-sorted view.
              Files without timestamps cannot be merged.
            </div>

            <div style={{ display: "flex", gap: "8px", marginBottom: "12px" }}>
              <Button size="small" appearance="subtle" onClick={selectAll}>Select All</Button>
              <Button size="small" appearance="subtle" onClick={selectNone}>Select None</Button>
            </div>

            <div
              style={{
                maxHeight: "300px",
                overflowY: "auto",
                border: `1px solid ${tokens.colorNeutralStroke2}`,
                borderRadius: "4px",
              }}
            >
              {tabInfos.map((tab) => (
                <div
                  key={tab.filePath}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "8px",
                    padding: "8px 12px",
                    borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
                    opacity: tab.hasTimestamps ? 1 : 0.5,
                  }}
                >
                  <Checkbox
                    checked={selected.has(tab.filePath)}
                    onChange={() => toggleFile(tab.filePath)}
                    disabled={!tab.hasTimestamps}
                  />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{
                      fontWeight: 500,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}>
                      {tab.fileName}
                      {!tab.hasTimestamps && (
                        <WarningRegular
                          style={{ marginLeft: "6px", color: tokens.colorPaletteMarigoldForeground1 }}
                          fontSize={14}
                        />
                      )}
                    </div>
                    <div style={{
                      fontSize: "11px",
                      color: tokens.colorNeutralForeground3,
                      fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                    }}>
                      {tab.entryCount} entries
                      {tab.timeRange && ` | ${tab.timeRange}`}
                      {!tab.hasTimestamps && " | No timestamps — cannot merge"}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </DialogContent>
          <DialogActions>
            <Button appearance="secondary" onClick={handleClose}>Cancel</Button>
            <Button appearance="primary" disabled={!canMerge} onClick={handleMerge}>
              Merge {canMerge ? `(${selected.size} files)` : ""}
            </Button>
          </DialogActions>
        </DialogBody>
      </DialogSurface>
    </Dialog>
  );
}
```

- [ ] **Step 2: Verify TypeScript compiles**

Run: `npx tsc --noEmit`
Expected: No errors

- [ ] **Step 3: Commit**

```bash
git add src/components/dialogs/MergeTabsDialog.tsx
git commit -m "feat(merge): create MergeTabsDialog component"
```

---

### Task 5: Merge Legend Bar

**Files:**
- Create: `src/components/log-view/MergeLegendBar.tsx`

- [ ] **Step 1: Create the legend bar component**

```typescript
// src/components/log-view/MergeLegendBar.tsx
import { tokens } from "@fluentui/react-components";
import { useLogStore, type MergedTabState } from "../../stores/log-store";
import { fileBaseName } from "../../lib/merge-entries";
import { LOG_UI_FONT_FAMILY } from "../../lib/log-accessibility";

const CORRELATION_WINDOWS = [
  { label: "100ms", value: 100 },
  { label: "500ms", value: 500 },
  { label: "1s", value: 1000 },
  { label: "5s", value: 5000 },
  { label: "10s", value: 10000 },
];

export function MergeLegendBar() {
  const mergedTabState = useLogStore((s) => s.mergedTabState);
  const correlationWindowMs = useLogStore((s) => s.correlationWindowMs);
  const autoCorrelate = useLogStore((s) => s.autoCorrelate);
  const setFileVisibility = useLogStore((s) => s.setFileVisibility);
  const setAllFileVisibility = useLogStore((s) => s.setAllFileVisibility);
  const setCorrelationWindowMs = useLogStore((s) => s.setCorrelationWindowMs);
  const setAutoCorrelate = useLogStore((s) => s.setAutoCorrelate);
  const entries = useLogStore((s) => s.entries);

  if (!mergedTabState) return null;

  // Count visible entries per file
  const fileCounts: Record<string, number> = {};
  for (const entry of mergedTabState.mergedEntries) {
    fileCounts[entry.filePath] = (fileCounts[entry.filePath] ?? 0) + 1;
  }

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: "6px",
        padding: "4px 12px",
        backgroundColor: tokens.colorNeutralBackground3,
        borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
        fontFamily: LOG_UI_FONT_FAMILY,
        fontSize: "11px",
        overflowX: "auto",
        scrollbarWidth: "none",
        flexShrink: 0,
      }}
    >
      {mergedTabState.sourceFilePaths.map((fp) => {
        const color = mergedTabState.colorAssignments[fp] ?? "#888";
        const visible = mergedTabState.fileVisibility[fp] !== false;
        const count = fileCounts[fp] ?? 0;

        return (
          <button
            key={fp}
            type="button"
            onClick={() => setFileVisibility(fp, !visible)}
            title={fp}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "4px",
              padding: "2px 8px",
              borderRadius: "12px",
              border: `1px solid ${visible ? color : tokens.colorNeutralStroke2}`,
              backgroundColor: visible ? `${color}20` : "transparent",
              color: visible ? tokens.colorNeutralForeground1 : tokens.colorNeutralForeground4,
              cursor: "pointer",
              opacity: visible ? 1 : 0.5,
              whiteSpace: "nowrap",
              fontSize: "11px",
              fontFamily: LOG_UI_FONT_FAMILY,
            }}
          >
            <span
              style={{
                width: "8px",
                height: "8px",
                borderRadius: "50%",
                backgroundColor: visible ? color : tokens.colorNeutralForeground4,
                flexShrink: 0,
              }}
            />
            <span>{fileBaseName(fp)}</span>
            <span style={{ color: tokens.colorNeutralForeground3, fontWeight: 600 }}>
              {count}
            </span>
          </button>
        );
      })}

      <div style={{ width: "1px", height: "16px", backgroundColor: tokens.colorNeutralStroke2, margin: "0 2px", flexShrink: 0 }} />

      <button
        type="button"
        onClick={() => setAllFileVisibility(true)}
        style={smallBtnStyle}
      >
        All
      </button>
      <button
        type="button"
        onClick={() => setAllFileVisibility(false)}
        style={smallBtnStyle}
      >
        None
      </button>

      <div style={{ width: "1px", height: "16px", backgroundColor: tokens.colorNeutralStroke2, margin: "0 2px", flexShrink: 0 }} />

      <span style={{ color: tokens.colorNeutralForeground3, fontWeight: 600, fontSize: "10px", textTransform: "uppercase" }}>
        Correlate:
      </span>
      <select
        value={correlationWindowMs}
        onChange={(e) => setCorrelationWindowMs(Number(e.target.value))}
        style={{
          fontSize: "11px",
          padding: "1px 4px",
          border: `1px solid ${tokens.colorNeutralStroke2}`,
          borderRadius: "3px",
          backgroundColor: tokens.colorNeutralBackground1,
          color: tokens.colorNeutralForeground1,
        }}
      >
        {CORRELATION_WINDOWS.map((w) => (
          <option key={w.value} value={w.value}>{w.label}</option>
        ))}
      </select>
      <button
        type="button"
        onClick={() => setAutoCorrelate(!autoCorrelate)}
        style={{
          ...smallBtnStyle,
          backgroundColor: autoCorrelate ? tokens.colorBrandBackground2 : tokens.colorNeutralBackground1,
          color: autoCorrelate ? tokens.colorBrandForeground1 : tokens.colorNeutralForeground3,
          border: `1px solid ${autoCorrelate ? tokens.colorBrandStroke1 : tokens.colorNeutralStroke2}`,
        }}
      >
        Auto
      </button>

      <div style={{ marginLeft: "auto", color: tokens.colorNeutralForeground3, flexShrink: 0 }}>
        {entries.length} merged
      </div>
    </div>
  );
}

const smallBtnStyle: React.CSSProperties = {
  fontSize: "10px",
  padding: "2px 6px",
  border: `1px solid var(--colorNeutralStroke2)`,
  borderRadius: "3px",
  backgroundColor: "var(--colorNeutralBackground1)",
  color: "var(--colorNeutralForeground1)",
  cursor: "pointer",
};
```

- [ ] **Step 2: Verify TypeScript compiles**

Run: `npx tsc --noEmit`
Expected: No errors

- [ ] **Step 3: Commit**

```bash
git add src/components/log-view/MergeLegendBar.tsx
git commit -m "feat(merge): create MergeLegendBar with file toggles and correlation controls"
```

---

### Task 6: LogRow — File Color Border and Correlation Highlight

**Files:**
- Modify: `src/components/log-view/LogRow.tsx`
- Modify: `src/components/log-view/LogListView.tsx`

- [ ] **Step 1: Add merge-related props to LogRow**

In `LogRow.tsx`, add to `LogRowProps` interface:

```typescript
  /** Hex color for file-based left border in merged views. Null when not in merged mode. */
  mergeFileColor?: string | null;
  /** Whether this entry is a correlation match in merged view. */
  isCorrelated?: boolean;
  /** Color to use for correlation highlight tint. */
  correlationColor?: string | null;
```

- [ ] **Step 2: Apply merge color border in LogRow rendering**

In the `<div>` that renders the row (the one with `boxShadow: inset 3px 0 0 ...`), update the boxShadow logic:

```typescript
boxShadow: mergeFileColor
  ? `inset 3px 0 0 ${mergeFileColor}`
  : `inset 3px 0 0 ${isSelected ? tokens.colorNeutralForegroundOnBrand : "transparent"}`,
```

For correlation highlight, add to the style object:

```typescript
...(isCorrelated && correlationColor && !isSelected ? {
  backgroundImage: `linear-gradient(${correlationColor}30, ${correlationColor}30)`,
} : {}),
```

- [ ] **Step 3: Pass merge props from LogListView**

In `LogListView.tsx`, add store selectors:

```typescript
const mergedTabState = useLogStore((s) => s.mergedTabState);
const correlatedEntries = useLogStore((s) => s.correlatedEntries);
```

Create a correlation ID set:

```typescript
const correlatedIdSet = useMemo(
  () => new Set(correlatedEntries.map((c) => c.entry.id)),
  [correlatedEntries]
);
```

In the `<LogRow>` render, add the new props:

```typescript
mergeFileColor={mergedTabState?.colorAssignments[entry.filePath] ?? null}
isCorrelated={correlatedIdSet.has(entry.id)}
correlationColor={mergedTabState?.colorAssignments[entry.filePath] ?? null}
```

- [ ] **Step 4: Render MergeLegendBar in LogListView**

Import and render the legend bar above the virtualized list:

```typescript
import { MergeLegendBar } from "./MergeLegendBar";
```

Add before the virtualizer `<div ref={parentRef}>`:

```tsx
{mergedTabState && <MergeLegendBar />}
```

- [ ] **Step 5: Verify TypeScript compiles**

Run: `npx tsc --noEmit`
Expected: No errors

- [ ] **Step 6: Commit**

```bash
git add src/components/log-view/LogRow.tsx src/components/log-view/LogListView.tsx
git commit -m "feat(merge): add file color borders, correlation highlights, and legend bar to log view"
```

---

### Task 7: Toolbar — Merge Button

**Files:**
- Modify: `src/components/layout/Toolbar.tsx`

- [ ] **Step 1: Add "Merge Tabs..." button to the toolbar**

In the `Toolbar` component, after the existing toolbar buttons (near the Highlight input area), add a "Merge Tabs..." button. This button should be visible only when the active workspace is "log" and there are 2+ open tabs:

```typescript
const openTabs = useUiStore((s) => s.openTabs);
const setShowMergeTabsDialog = useUiStore((s) => s.setShowMergeTabsDialog);
const canMergeTabs = activeWorkspace === "log" && openTabs.length >= 2;
```

Render the button in the toolbar (after the Highlight input, before the Details/Info toggles):

```tsx
{canMergeTabs && (
  <button
    type="button"
    onClick={() => setShowMergeTabsDialog(true)}
    title="Merge open tabs into a unified timeline"
    style={{
      fontSize: "12px",
      padding: "4px 10px",
      border: `1px solid ${tokens.colorNeutralStroke2}`,
      borderRadius: "4px",
      backgroundColor: tokens.colorNeutralBackground1,
      color: tokens.colorNeutralForeground1,
      cursor: "pointer",
    }}
  >
    Merge Tabs...
  </button>
)}
```

- [ ] **Step 2: Verify TypeScript compiles**

Run: `npx tsc --noEmit`
Expected: No errors

- [ ] **Step 3: Commit**

```bash
git add src/components/layout/Toolbar.tsx
git commit -m "feat(merge): add Merge Tabs button to toolbar"
```

---

### Task 8: AppShell — Wire Dialog and Merge Action

**Files:**
- Modify: `src/components/layout/AppShell.tsx`

- [ ] **Step 1: Import and render the MergeTabsDialog**

Add import:

```typescript
import { MergeTabsDialog } from "../dialogs/MergeTabsDialog";
```

Add store selectors:

```typescript
const showMergeTabsDialog = useUiStore((s) => s.showMergeTabsDialog);
const setShowMergeTabsDialog = useUiStore((s) => s.setShowMergeTabsDialog);
const createMergedTab = useLogStore((s) => s.createMergedTab);
```

Add the dialog render near the other dialogs:

```tsx
<MergeTabsDialog
  isOpen={showMergeTabsDialog}
  onClose={() => setShowMergeTabsDialog(false)}
  onMerge={(filePaths) => createMergedTab(filePaths)}
/>
```

- [ ] **Step 2: Verify TypeScript compiles**

Run: `npx tsc --noEmit`
Expected: No errors

- [ ] **Step 3: Commit**

```bash
git add src/components/layout/AppShell.tsx
git commit -m "feat(merge): wire MergeTabsDialog into AppShell"
```

---

### Task 9: TabStrip — Merged Tab Display

**Files:**
- Modify: `src/components/layout/TabStrip.tsx`

- [ ] **Step 1: Display merged tab differently**

In `TabStrip.tsx`, read the merged state:

```typescript
const sourceOpenMode = useLogStore((s) => s.sourceOpenMode);
const mergedTabState = useLogStore((s) => s.mergedTabState);
```

When `sourceOpenMode === "merged"` and the active tab is selected, show a merged indicator. Add a visual cue to the active tab — prepend a merge icon or change the tab label. The simplest approach is to show a special tab label when in merged mode:

In the tab rendering, when the active tab matches and `sourceOpenMode === "merged"`:

```tsx
{sourceOpenMode === "merged" && index === activeTabIndex && mergedTabState ? (
  <span title={mergedTabState.sourceFilePaths.join("\n")}>
    Merged ({mergedTabState.sourceFilePaths.length} files)
  </span>
) : (
  <span>{tab.fileName}</span>
)}
```

Also handle closing the merged tab — when the merged tab's close button is clicked, call `closeMergedTab()` instead of the normal tab close:

```typescript
const closeMergedTab = useLogStore((s) => s.closeMergedTab);
```

- [ ] **Step 2: Verify TypeScript compiles**

Run: `npx tsc --noEmit`
Expected: No errors

- [ ] **Step 3: Commit**

```bash
git add src/components/layout/TabStrip.tsx
git commit -m "feat(merge): show merged tab indicator in tab strip"
```

---

### Task 10: InfoPane — Correlated Entries Section

**Files:**
- Modify: `src/components/log-view/InfoPane.tsx`

- [ ] **Step 1: Add correlated entries display**

Import:

```typescript
import { useLogStore, type CorrelatedEntry } from "../../stores/log-store";
import { fileBaseName } from "../../lib/merge-entries";
```

Add store selectors inside the `InfoPane` component:

```typescript
const mergedTabState = useLogStore((state) => state.mergedTabState);
const correlatedEntries = useLogStore((state) => state.correlatedEntries);
const selectEntry = useLogStore((state) => state.selectEntry);
```

Add a correlated entries section after the `AppWorkloadScriptDetail` and before the raw message, only when in merged mode and correlations exist:

```tsx
{mergedTabState && correlatedEntries.length > 0 && (
  <div
    style={{
      marginBottom: "8px",
      padding: "6px 8px",
      backgroundColor: tokens.colorNeutralBackground3,
      border: `1px solid ${tokens.colorNeutralStroke2}`,
      borderRadius: "4px",
      fontSize: `${Math.max(logDetailsFontSize - 1, 11)}px`,
    }}
  >
    <div style={{
      fontWeight: 600,
      color: tokens.colorNeutralForeground2,
      marginBottom: "4px",
    }}>
      Correlated Entries ({correlatedEntries.length})
    </div>
    <div style={{ display: "flex", flexDirection: "column", gap: "2px" }}>
      {correlatedEntries.slice(0, 20).map((corr) => (
        <div
          key={corr.entry.id}
          onClick={() => selectEntry(corr.entry.id)}
          style={{
            display: "flex",
            alignItems: "center",
            gap: "6px",
            padding: "2px 4px",
            borderRadius: "3px",
            cursor: "pointer",
            borderLeft: `3px solid ${corr.fileColor}`,
          }}
        >
          <span style={{
            fontFamily: LOG_MONOSPACE_FONT_FAMILY,
            color: tokens.colorNeutralForeground3,
            width: "60px",
            flexShrink: 0,
          }}>
            {corr.deltaMs >= 0 ? "+" : ""}{corr.deltaMs}ms
          </span>
          <span style={{
            color: tokens.colorNeutralForeground3,
            flexShrink: 0,
          }}>
            {fileBaseName(corr.entry.filePath)}
          </span>
          <span style={{
            color: tokens.colorNeutralForeground2,
            fontFamily: LOG_MONOSPACE_FONT_FAMILY,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            flex: 1,
            minWidth: 0,
          }}>
            {corr.entry.message.slice(0, 100)}
          </span>
        </div>
      ))}
      {correlatedEntries.length > 20 && (
        <div style={{ color: tokens.colorNeutralForeground3, fontSize: "10px" }}>
          +{correlatedEntries.length - 20} more
        </div>
      )}
    </div>
  </div>
)}
```

- [ ] **Step 2: Verify TypeScript compiles**

Run: `npx tsc --noEmit`
Expected: No errors

- [ ] **Step 3: Commit**

```bash
git add src/components/log-view/InfoPane.tsx
git commit -m "feat(merge): add correlated entries section to InfoPane"
```

---

### Task 11: FileSidebar — Folder Merge Button

**Files:**
- Modify: `src/components/layout/FileSidebar.tsx`

- [ ] **Step 1: Add "Merge into Timeline" button**

Read `FileSidebar.tsx` first, then add a "Merge into Timeline" button at the top of the file list when multiple files are shown. Import the merge action:

```typescript
const createMergedTab = useLogStore((s) => s.createMergedTab);
const sourceEntries = useLogStore((s) => s.sourceEntries);
```

Add a button above the file list when `sourceEntries.filter(e => !e.isDir).length >= 2`:

```tsx
{fileEntries.length >= 2 && (
  <button
    type="button"
    onClick={() => {
      const filePaths = fileEntries.map((e) => e.path);
      createMergedTab(filePaths);
    }}
    style={{
      width: "100%",
      padding: "6px 8px",
      marginBottom: "8px",
      fontSize: "11px",
      border: `1px solid ${tokens.colorNeutralStroke2}`,
      borderRadius: "4px",
      backgroundColor: tokens.colorNeutralBackground1,
      color: tokens.colorNeutralForeground1,
      cursor: "pointer",
      fontWeight: 500,
    }}
  >
    Merge into Timeline
  </button>
)}
```

Note: This button only works when the files are already parsed and cached. If they haven't been opened yet, the button should first open/parse them before merging. Check how the sidebar currently handles file selection to match the pattern. If files aren't cached, the button should be disabled with a tooltip "Open files first to merge."

- [ ] **Step 2: Verify TypeScript compiles**

Run: `npx tsc --noEmit`
Expected: No errors

- [ ] **Step 3: Commit**

```bash
git add src/components/layout/FileSidebar.tsx
git commit -m "feat(merge): add Merge into Timeline button to folder sidebar"
```

---

### Task 12: Final Integration and Verification

**Files:** All modified files

- [ ] **Step 1: Run TypeScript check**

Run: `npx tsc --noEmit`
Expected: No errors

- [ ] **Step 2: Run Rust tests**

Run: `cd src-tauri && cargo test`
Expected: All tests pass (no Rust changes, but verify nothing broke)

- [ ] **Step 3: Run clippy**

Run: `cd src-tauri && cargo clippy -- -D warnings`
Expected: No warnings

- [ ] **Step 4: Manual smoke test**

1. Open 2+ log files as separate tabs
2. Click "Merge Tabs..." — verify dialog shows all tabs with entry counts
3. Select 2+ tabs and click Merge — verify merged timeline appears
4. Verify color-coded left borders on each row
5. Verify legend bar shows file chips with toggle buttons
6. Toggle a file off — verify its entries disappear
7. Click "All" / "None" — verify bulk toggle works
8. Select an entry — verify correlated entries section appears in InfoPane
9. Change correlation window — verify the number of correlated entries changes
10. Click a correlated entry — verify it jumps to that entry
11. Close the merged tab — verify original tabs are unaffected

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(merge): final integration and cleanup"
```
