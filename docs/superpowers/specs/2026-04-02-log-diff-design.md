# Log Diff

## Overview

Compare two log sources (two files or two time ranges within one file) and show which entries are unique to each source vs. common to both. Uses fuzzy pattern matching to normalize GUIDs, timestamps, and numbers so "same event, different instance" lines are recognized as matches. Display in side-by-side split or unified inline view, both virtualized.

## Modes

### Two-File Diff
Select two open tabs. Compare all entries from each file.

### Time-Range Diff
Select one open tab. Pick two time ranges by start/end timestamp. Compare entries within each range.

A mode toggle in the diff config dialog and the diff view itself switches between them.

## Entry Point

"Diff Tabs..." button in the toolbar, next to "Merge Tabs...", visible when 2+ tabs are open.

Opens `DiffConfigDialog`:
- Mode toggle: "Two Files" / "Time Range"
- **Two Files mode**: Two dropdowns to select Tab A and Tab B
- **Time Range mode**: One dropdown to select the file, then two pairs of timestamp pickers (or entry selectors) for Range A and Range B
- "Compare" button launches the diff
- Creates a virtual diff tab (similar to merged tab pattern)

## Matching Algorithm

### Normalization

Each log line's message is normalized before comparison:

1. Replace GUIDs (`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-...-[0-9a-fA-F]{12}`) → `{GUID}`
2. Replace timestamps (ISO 8601 patterns, common date formats) → `{TS}`
3. Replace numeric sequences of 5+ digits → `{NUM}`
4. Lowercase the result
5. Trim whitespace

### Pattern Key

The "identity" of a log line for matching purposes:

```typescript
type PatternKey = string; // hash of (normalizedMessage, component, severity)
```

Two lines from different sources with the same pattern key are considered "the same pattern."

### Classification

For each source (A and B):
1. Build a `Map<PatternKey, LogEntry[]>` of all entries
2. Keys present in both maps → **Common** (matched)
3. Keys only in A → **Only A** (green)
4. Keys only in B → **Only B** (red)

### Stats

Displayed in the diff view header:
- `N common patterns`
- `M only in A (filename)`
- `K only in B (filename)`

## Display

### Side-by-Side (default)

Two virtualized columns, each showing entries from their respective source.

- Common entries: neutral background, aligned by timestamp when both have timestamps, otherwise by sequence
- Only-in-A entries: green-tinted background in left column, empty space in right column
- Only-in-B entries: empty space in left column, red-tinted background in right column
- Synchronized scrolling: scrolling one side scrolls the other
- Each row shows: severity dot, timestamp, message (truncated)

### Unified Inline

Single virtualized list showing all entries interleaved by timestamp.

- Common entries: neutral background, no marker
- Only-in-A entries: green left border + "A" badge
- Only-in-B entries: red left border + "B" badge
- Each row shows: source badge (A/B/both), severity dot, timestamp, message

### Toggle

Button in the diff view header: "Side-by-Side" / "Unified". Persisted per diff session (not globally).

## Diff View Tab

- Tab title: "Diff: fileA vs fileB" (truncated, full in tooltip)
- Tab icon: distinct diff icon
- Virtual tab — closing doesn't affect source tabs
- Source tabs remain open and independent
- Selecting an entry in the diff view shows its full detail in the InfoPane

## Store Changes

### log-store.ts

```typescript
interface DiffState {
  mode: "two-file" | "time-range";
  sourceA: DiffSource;
  sourceB: DiffSource;
  displayMode: "side-by-side" | "unified";
  entriesA: LogEntry[];            // Source A entries (filtered by range if time-range mode)
  entriesB: LogEntry[];            // Source B entries
  commonKeys: Set<string>;         // Pattern keys found in both
  onlyAKeys: Set<string>;          // Pattern keys only in A
  onlyBKeys: Set<string>;          // Pattern keys only in B
  entryClassification: Map<number, "common" | "only-a" | "only-b">; // entry.id → class
  stats: { common: number; onlyA: number; onlyB: number };
}

interface DiffSource {
  filePath: string;
  label: string;
  startTime?: number;   // epoch ms, for time-range mode
  endTime?: number;      // epoch ms, for time-range mode
}
```

Actions:

```typescript
createDiff: (sourceA: DiffSource, sourceB: DiffSource) => void;
closeDiff: () => void;
setDiffDisplayMode: (mode: "side-by-side" | "unified") => void;
```

## New Files

| File | Responsibility |
|------|----------------|
| `src/lib/diff-entries.ts` | Normalization, pattern key generation, classification logic |
| `src/components/dialogs/DiffConfigDialog.tsx` | Mode selection, source pickers, time range pickers |
| `src/components/log-view/DiffView.tsx` | Side-by-side and unified diff rendering |
| `src/components/log-view/DiffHeader.tsx` | Stats bar, display mode toggle, source labels |

## No Backend Changes

Normalization and matching are pure client-side functions. No new Rust commands needed.

## Performance

- Normalization is O(n) per entry — regex replacements on message strings
- Pattern key hashing is O(n) total
- Classification is O(n) via two Map lookups
- For 50K entries per source: normalization + classification should complete in under 200ms
- Both display modes use TanStack Virtual — only visible rows in the DOM

## Out of Scope

- Saving diff results to file
- Three-way diff
- Line-level diff within a single log message (character-level comparison)
- Diff across workspaces (e.g., Intune events vs. log entries)
