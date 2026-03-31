# Intune Diagnostics Column Sorting

**Issue:** #70 — Feature request: Intune Diagnostics, column sorting
**Date:** 2026-03-30
**Scope:** Event Timeline + Download Stats surfaces

## Approach

Hybrid: backend pre-computes epoch timestamps during analysis, frontend sorts instantly on numeric values. No IPC round-trip on sort changes.

## Data Model Changes

### Rust — `IntuneEvent` (`src-tauri/src/intune/models.rs`)

Add two fields:

```rust
pub start_time_epoch: Option<i64>,  // milliseconds since Unix epoch
pub end_time_epoch: Option<i64>,
```

Populated in `timeline.rs::build_timeline()` from the already-parsed `NaiveDateTime` values using `.and_utc().timestamp_millis()`.

### Rust — `DownloadStat` (`src-tauri/src/intune/models.rs`)

Add one field:

```rust
pub timestamp_epoch: Option<i64>,
```

Populated in `download_stats.rs` using the same timestamp parsing approach.

### TypeScript — `IntuneEvent` (`src/types/`)

```typescript
startTimeEpoch: number | null;
endTimeEpoch: number | null;
```

### TypeScript — `DownloadStat` (`src/types/`)

```typescript
timestampEpoch: number | null;
```

## Sort State — Zustand Store (`src/stores/intune-store.ts`)

### Event Timeline Sort

```typescript
type IntuneSortField = "time" | "name" | "type" | "status" | "duration";

sortField: IntuneSortField;         // default: "time"
sortDirection: "asc" | "desc";      // default: "asc"
setSortField: (field: IntuneSortField) => void;
toggleSortDirection: () => void;
```

### Download Stats Sort

```typescript
type DownloadSortField = "name" | "size" | "speed" | "doPercentage" | "duration" | "timestamp";

downloadSortField: DownloadSortField;      // default: "timestamp"
downloadSortDirection: "asc" | "desc";      // default: "asc"
setDownloadSortField: (field: DownloadSortField) => void;
toggleDownloadSortDirection: () => void;
```

Both reset to defaults on new analysis (inside `setResults()`).

## Sort Comparisons

### Event Timeline

| Field | Key | Comparison |
|-------|-----|-----------|
| Time | `startTimeEpoch` | Numeric, nulls last |
| Name | `name` | `localeCompare` |
| Type | `eventType` | `localeCompare` |
| Status | `status` | Ordered rank: Failed(0) > Timeout(1) > InProgress(2) > Pending(3) > Success(4) > Unknown(5) |
| Duration | `durationSecs` | Numeric, nulls last |

### Download Stats

| Field | Key | Comparison |
|-------|-----|-----------|
| Name | `name` | `localeCompare` |
| Size | `sizeBytes` | Numeric |
| Speed | `speedBps` | Numeric |
| DO % | `doPercentage` | Numeric |
| Duration | `durationSecs` | Numeric |
| Timestamp | `timestampEpoch` | Numeric, nulls last |

## Sort Logic — Frontend

Both surfaces use `useMemo` to sort their respective filtered arrays:

```typescript
const sortedEvents = useMemo(() => {
  return [...filteredEvents].sort((a, b) => {
    // comparison by sortField, direction-aware
    // nulls always last regardless of direction
  });
}, [filteredEvents, sortField, sortDirection]);
```

## UI Changes

### Event Timeline — `IntuneDashboardNavBar.tsx`

Add a "Sort by" `Dropdown` and an asc/desc toggle `Button` to the existing filter row:

```
[Event Type ▼] [Status ▼] [Time Window ▼]  [Sort by: Time ▼] [↑↓]
```

- Dropdown options: Time, Name, Type, Status, Duration
- Toggle button: arrow-up/arrow-down icon, switches `sortDirection`
- Uses existing Fluent UI `Dropdown` and `Button` components

### Download Stats — `DownloadStats.tsx`

Add clickable column headers to the existing `<table>`:

- `<th>` elements get `cursor: pointer` and `onClick` handler
- Clicking sets `downloadSortField`; clicking the active column toggles direction
- Active column header displays `▲` (asc) or `▼` (desc) indicator

## Files Changed

| File | Change |
|------|--------|
| `src-tauri/src/intune/models.rs` | Add epoch fields to `IntuneEvent` and `DownloadStat` |
| `src-tauri/src/intune/timeline.rs` | Populate `start_time_epoch`, `end_time_epoch` from parsed timestamps |
| `src-tauri/src/intune/download_stats.rs` | Populate `timestamp_epoch` from parsed timestamp |
| `src/types/` | Add epoch fields to TypeScript types |
| `src/stores/intune-store.ts` | Add sort state, setters, reset in `setResults()` |
| `src/components/intune/EventTimeline.tsx` | `useMemo` sort before virtual list |
| `src/components/intune/IntuneDashboardNavBar.tsx` | Sort dropdown + direction toggle |
| `src/components/intune/DownloadStats.tsx` | Clickable headers + `useMemo` sort |

## Defaults & Behavior

- Default sort: time ascending (preserves current chronological order)
- Null values sort last regardless of direction
- Sort state resets on new analysis
- No persistence across sessions
