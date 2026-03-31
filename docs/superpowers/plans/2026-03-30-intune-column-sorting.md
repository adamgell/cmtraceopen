# Intune Diagnostics Column Sorting — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add column sorting to the Intune Diagnostics Event Timeline and Download Stats surfaces, with backend-computed epoch timestamps for fast frontend sorting.

**Architecture:** Backend populates epoch millisecond fields on `IntuneEvent` and `DownloadStat` during analysis (zero additional IPC calls). Frontend adds sort state to the Intune Zustand store and sorts filtered arrays via `useMemo` before rendering. Timeline gets a "Sort by" dropdown in the navbar; Download Stats gets clickable column headers.

**Tech Stack:** Rust (chrono), React, TypeScript, Zustand, Fluent UI tokens

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `src-tauri/src/intune/models.rs` | Modify | Add `start_time_epoch`, `end_time_epoch` to `IntuneEvent`; `timestamp_epoch` to `DownloadStat` |
| `src-tauri/src/intune/timeline.rs` | Modify | Populate epoch fields from parsed `NaiveDateTime` |
| `src-tauri/src/intune/download_stats.rs` | Modify | Populate `timestamp_epoch` from parsed timestamp |
| `src/types/intune.ts` | Modify | Add epoch fields to TS interfaces |
| `src/stores/intune-store.ts` | Modify | Add sort state + setters for timeline and downloads |
| `src/components/intune/EventTimeline.tsx` | Modify | Sort filtered events via `useMemo` |
| `src/components/intune/IntuneDashboardNavBar.tsx` | Modify | Add sort dropdown + direction toggle |
| `src/components/intune/DownloadStats.tsx` | Modify | Add clickable headers + sort logic |

---

### Task 1: Add epoch fields to Rust models

**Files:**
- Modify: `src-tauri/src/intune/models.rs:122-149` (IntuneEvent struct)
- Modify: `src-tauri/src/intune/models.rs:152-171` (DownloadStat struct)
- Modify: `src-tauri/src/intune/models.rs:536-553` (IntuneAnalysisResult custom Serialize)

- [ ] **Step 1: Add epoch fields to IntuneEvent**

In `src-tauri/src/intune/models.rs`, add two fields after `line_number` (line 148):

```rust
/// A single Intune event extracted from log analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntuneEvent {
    /// Unique identifier for this event
    pub id: u64,
    /// Event type category
    pub event_type: IntuneEventType,
    /// Display name (resolved from GUID or extracted from context)
    pub name: String,
    /// GUID identifier if available
    pub guid: Option<String>,
    /// Status of the operation
    pub status: IntuneStatus,
    /// Timestamp of event start (ISO 8601 string)
    pub start_time: Option<String>,
    /// Timestamp of event end (ISO 8601 string)
    pub end_time: Option<String>,
    /// Duration in seconds
    pub duration_secs: Option<f64>,
    /// Error code if failed
    pub error_code: Option<String>,
    /// Additional detail message
    pub detail: String,
    /// Source log file path
    pub source_file: String,
    /// Line number in source file
    pub line_number: u32,
    /// Start time as milliseconds since Unix epoch (pre-computed for fast frontend sorting)
    pub start_time_epoch: Option<i64>,
    /// End time as milliseconds since Unix epoch (pre-computed for fast frontend sorting)
    pub end_time_epoch: Option<i64>,
}
```

- [ ] **Step 2: Add epoch field to DownloadStat**

In the same file, add after `timestamp` (line 170):

```rust
pub struct DownloadStat {
    // ... existing fields ...
    /// Timestamp
    pub timestamp: Option<String>,
    /// Timestamp as milliseconds since Unix epoch (pre-computed for fast frontend sorting)
    pub timestamp_epoch: Option<i64>,
}
```

- [ ] **Step 3: Fix all IntuneEvent and DownloadStat construction sites**

Every place that constructs an `IntuneEvent` or `DownloadStat` needs the new fields. Search for these with `cargo check` — the compiler will tell you exactly where. Add `start_time_epoch: None, end_time_epoch: None` to each `IntuneEvent` literal, and `timestamp_epoch: None` to each `DownloadStat` literal. The epoch values will be populated later in the pipeline (timeline.rs and download_stats.rs).

Key files with construction sites:
- `src-tauri/src/intune/event_tracker.rs` — `IntuneEvent` construction
- `src-tauri/src/intune/download_stats.rs` — `DownloadStat` construction
- `src-tauri/src/intune/timeline.rs` — test helpers constructing `IntuneEvent`
- Any other files flagged by `cargo check`

- [ ] **Step 4: Run cargo check**

Run: `cd src-tauri && cargo check`
Expected: PASS (all construction sites updated)

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/intune/models.rs src-tauri/src/intune/event_tracker.rs src-tauri/src/intune/download_stats.rs src-tauri/src/intune/timeline.rs
git commit -m "feat(intune): add epoch timestamp fields to IntuneEvent and DownloadStat"
```

---

### Task 2: Populate epoch fields in timeline.rs

**Files:**
- Modify: `src-tauri/src/intune/timeline.rs:39-57` (build_timeline function)
- Test: `src-tauri/src/intune/timeline.rs` (existing test module)

- [ ] **Step 1: Write the failing test**

Add to the `mod tests` block in `src-tauri/src/intune/timeline.rs`:

```rust
#[test]
fn build_timeline_populates_epoch_fields() {
    let timeline = build_timeline(vec![
        IntuneEvent {
            id: 0,
            event_type: IntuneEventType::Win32App,
            name: "Test".to_string(),
            guid: None,
            status: IntuneStatus::Success,
            start_time: Some("01-15-2024 10:30:00.000".to_string()),
            end_time: Some("01-15-2024 10:35:00.000".to_string()),
            duration_secs: Some(300.0),
            error_code: None,
            detail: "test".to_string(),
            source_file: "a.log".to_string(),
            line_number: 1,
            start_time_epoch: None,
            end_time_epoch: None,
        },
        IntuneEvent {
            id: 1,
            event_type: IntuneEventType::Win32App,
            name: "NoTime".to_string(),
            guid: None,
            status: IntuneStatus::Pending,
            start_time: None,
            end_time: None,
            duration_secs: None,
            error_code: None,
            detail: "no time".to_string(),
            source_file: "b.log".to_string(),
            line_number: 1,
            start_time_epoch: None,
            end_time_epoch: None,
        },
    ]);

    // Event with timestamps should have epoch values populated
    let timed = &timeline[0];
    assert!(timed.start_time_epoch.is_some(), "start_time_epoch should be populated");
    assert!(timed.end_time_epoch.is_some(), "end_time_epoch should be populated");

    // Event without timestamps should have None
    let untimed = &timeline[1];
    assert!(untimed.start_time_epoch.is_none());
    assert!(untimed.end_time_epoch.is_none());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd src-tauri && cargo test build_timeline_populates_epoch_fields -- --nocapture`
Expected: FAIL — epoch fields are `None` because `build_timeline` doesn't populate them yet.

- [ ] **Step 3: Populate epoch fields in build_timeline**

Modify `build_timeline` in `src-tauri/src/intune/timeline.rs`. After the sort and ID reassignment (line 52-54), add epoch population before the final `.map()`:

```rust
pub fn build_timeline(events: Vec<IntuneEvent>) -> Vec<IntuneEvent> {
    let mut timeline = deduplicate_events(events);

    // Sort by the cached parsed timestamp first, then source+line for deterministic ordering.
    timeline.sort_by(|a, b| {
        a.parsed_time
            .cmp(&b.parsed_time)
            .then_with(|| a.event.source_file.cmp(&b.event.source_file))
            .then_with(|| a.event.line_number.cmp(&b.event.line_number))
            .then_with(|| a.event.name.cmp(&b.event.name))
    });

    // Re-assign sequential IDs and populate epoch fields from cached parsed times.
    for (i, entry) in timeline.iter_mut().enumerate() {
        entry.event.id = i as u64;
        entry.event.start_time_epoch = entry
            .event
            .start_time
            .as_deref()
            .and_then(parse_timestamp)
            .map(|dt| dt.and_utc().timestamp_millis());
        entry.event.end_time_epoch = entry
            .event
            .end_time
            .as_deref()
            .and_then(parse_timestamp)
            .map(|dt| dt.and_utc().timestamp_millis());
    }

    timeline.into_iter().map(|entry| entry.event).collect()
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd src-tauri && cargo test build_timeline_populates_epoch_fields -- --nocapture`
Expected: PASS

- [ ] **Step 5: Run all existing timeline tests**

Run: `cd src-tauri && cargo test timeline -- --nocapture`
Expected: All PASS (existing tests unaffected)

- [ ] **Step 6: Commit**

```bash
git add src-tauri/src/intune/timeline.rs
git commit -m "feat(intune): populate epoch timestamps in build_timeline"
```

---

### Task 3: Populate epoch field in download_stats.rs

**Files:**
- Modify: `src-tauri/src/intune/download_stats.rs`

- [ ] **Step 1: Write the failing test**

Add to the `mod tests` block in `src-tauri/src/intune/download_stats.rs`:

```rust
#[test]
fn completed_download_has_timestamp_epoch() {
    let lines = vec![
        ImeLine {
            line_number: 1,
            timestamp: Some("01-15-2024 10:00:00.000".to_string()),
            timestamp_utc: None,
            message: "Starting content download for app id: a1b2c3d4-e5f6-7890-abcd-ef1234567890".to_string(),
            component: None,
        },
        ImeLine {
            line_number: 2,
            timestamp: Some("01-15-2024 10:00:05.000".to_string()),
            timestamp_utc: None,
            message: "Download completed successfully. Content size: 5242880 bytes, speed: 1048576 Bps, Delivery Optimization: 75.5%".to_string(),
            component: None,
        },
    ];

    let downloads = extract_downloads(&lines, "C:/Logs/AppWorkload.log", &empty_registry());
    assert_eq!(downloads.len(), 1);
    assert!(downloads[0].timestamp_epoch.is_some(), "timestamp_epoch should be populated");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd src-tauri && cargo test completed_download_has_timestamp_epoch -- --nocapture`
Expected: FAIL — `timestamp_epoch` is `None`

- [ ] **Step 3: Populate timestamp_epoch in download construction**

Import the parse_timestamp function at the top of `download_stats.rs`:

```rust
use super::timeline::parse_timestamp;
```

Then update the two places where `DownloadStat` is constructed:

In `finalize_download` (around line 478), change the return to populate `timestamp_epoch`:

```rust
    let ts = timestamp
        .map(|value| value.to_string())
        .or(partial.last_timestamp)
        .or(partial.start_time);

    Some(DownloadStat {
        content_id: resolved_content_id,
        name,
        size_bytes: partial.size_bytes.unwrap_or(0),
        speed_bps: partial.speed_bps.unwrap_or(0.0),
        do_percentage: partial.do_percentage.unwrap_or(0.0),
        duration_secs: partial.duration_secs.unwrap_or(0.0),
        success,
        timestamp_epoch: ts.as_deref().and_then(parse_timestamp).map(|dt| dt.and_utc().timestamp_millis()),
        timestamp: ts,
    })
```

In the abandoned-partial loop (around line 213), do the same:

```rust
    let ts = partial.last_timestamp.clone().or(partial.start_time.clone());
    downloads.push(DownloadStat {
        content_id: cid,
        name,
        size_bytes: partial.size_bytes.unwrap_or(0),
        speed_bps: partial.speed_bps.unwrap_or(0.0),
        do_percentage: partial.do_percentage.unwrap_or(0.0),
        duration_secs: partial.duration_secs.unwrap_or(0.0),
        success: false,
        timestamp_epoch: ts.as_deref().and_then(parse_timestamp).map(|dt| dt.and_utc().timestamp_millis()),
        timestamp: ts,
    });
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd src-tauri && cargo test completed_download_has_timestamp_epoch -- --nocapture`
Expected: PASS

- [ ] **Step 5: Run all tests**

Run: `cd src-tauri && cargo test`
Expected: All PASS

- [ ] **Step 6: Run clippy**

Run: `cd src-tauri && cargo clippy -- -D warnings`
Expected: PASS with zero warnings

- [ ] **Step 7: Commit**

```bash
git add src-tauri/src/intune/download_stats.rs
git commit -m "feat(intune): populate timestamp_epoch in download stats"
```

---

### Task 4: Add epoch fields to TypeScript types

**Files:**
- Modify: `src/types/intune.ts:23-36` (IntuneEvent interface)
- Modify: `src/types/intune.ts:38-46` (DownloadStat interface)

- [ ] **Step 1: Add fields to IntuneEvent interface**

In `src/types/intune.ts`, add after `lineNumber: number;` (line 35):

```typescript
export interface IntuneEvent {
  id: number;
  eventType: IntuneEventType;
  name: string;
  guid: string | null;
  status: IntuneStatus;
  startTime: string | null;
  endTime: string | null;
  durationSecs: number | null;
  errorCode: string | null;
  detail: string;
  sourceFile: string;
  lineNumber: number;
  startTimeEpoch: number | null;
  endTimeEpoch: number | null;
}
```

- [ ] **Step 2: Add field to DownloadStat interface**

In the same file, add after `timestamp: string | null;` (line 46):

```typescript
export interface DownloadStat {
  contentId: string;
  name: string;
  sizeBytes: number;
  speedBps: number;
  doPercentage: number;
  durationSecs: number;
  success: boolean;
  timestamp: string | null;
  timestampEpoch: number | null;
}
```

- [ ] **Step 3: Run TypeScript check**

Run: `npx tsc --noEmit`
Expected: PASS (new fields are optional-ish — they'll always be present from the backend, but existing code doesn't reference them yet so nothing breaks)

- [ ] **Step 4: Commit**

```bash
git add src/types/intune.ts
git commit -m "feat(intune): add epoch timestamp fields to TypeScript types"
```

---

### Task 5: Add sort state to Intune Zustand store

**Files:**
- Modify: `src/stores/intune-store.ts`

- [ ] **Step 1: Add sort type and state**

At the top of `src/stores/intune-store.ts`, after the existing type imports and before the `buildSourceContext` function, add:

```typescript
export type IntuneSortField = "time" | "name" | "type" | "status" | "duration";
export type DownloadSortField = "name" | "size" | "speed" | "doPercentage" | "duration" | "timestamp";
export type SortDirection = "asc" | "desc";
```

- [ ] **Step 2: Add sort fields to IntuneState interface**

In the `IntuneState` interface (around line 158), add after `activeTab`:

```typescript
  sortField: IntuneSortField;
  sortDirection: SortDirection;
  downloadSortField: DownloadSortField;
  downloadSortDirection: SortDirection;
```

Add the setters after `setActiveTab`:

```typescript
  setSortField: (field: IntuneSortField) => void;
  toggleSortDirection: () => void;
  setDownloadSortField: (field: DownloadSortField) => void;
  toggleDownloadSortDirection: () => void;
```

- [ ] **Step 3: Add defaults to defaultInteractionState**

In `defaultInteractionState` (around line 214), add:

```typescript
const defaultInteractionState = {
  selectedEventId: null,
  selectedEventLogEntryId: null as number | null,
  timeWindow: "all" as const,
  filterEventType: "All" as const,
  filterStatus: "All" as const,
  eventLogFilterChannel: "All" as EventLogChannel | "All",
  eventLogFilterSeverity: "All" as EventLogSeverity | "All",
  activeTab: "timeline" as const,
  sortField: "time" as IntuneSortField,
  sortDirection: "asc" as SortDirection,
  downloadSortField: "timestamp" as DownloadSortField,
  downloadSortDirection: "asc" as SortDirection,
};
```

This ensures sort state resets on new analysis since `setResults` spreads `...defaultInteractionState`.

- [ ] **Step 4: Add setter implementations**

In the `create<IntuneState>` block, add after `setActiveTab`:

```typescript
  setSortField: (field) => set({ sortField: field }),
  toggleSortDirection: () =>
    set((state) => ({ sortDirection: state.sortDirection === "asc" ? "desc" : "asc" })),
  setDownloadSortField: (field) => set({ downloadSortField: field }),
  toggleDownloadSortDirection: () =>
    set((state) => ({ downloadSortDirection: state.downloadSortDirection === "asc" ? "desc" : "asc" })),
```

- [ ] **Step 5: Run TypeScript check**

Run: `npx tsc --noEmit`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/stores/intune-store.ts
git commit -m "feat(intune): add sort state to Intune Zustand store"
```

---

### Task 6: Add sorting to EventTimeline

**Files:**
- Modify: `src/components/intune/EventTimeline.tsx`

- [ ] **Step 1: Add sort logic to EventTimeline**

In `src/components/intune/EventTimeline.tsx`, add the sort imports and logic. After the existing `filteredEvents` useMemo (line 35-48), add a `sortedEvents` useMemo:

```typescript
import type { IntuneEvent, IntuneStatus } from "../../types/intune";
import type { IntuneSortField, SortDirection } from "../../stores/intune-store";
```

Add store selectors after the existing ones (around line 23):

```typescript
  const sortField = useIntuneStore((s) => s.sortField);
  const sortDirection = useIntuneStore((s) => s.sortDirection);
```

Add the sort memo after `filteredEvents`:

```typescript
  const STATUS_RANK: Record<IntuneStatus, number> = {
    Failed: 0,
    Timeout: 1,
    InProgress: 2,
    Pending: 3,
    Success: 4,
    Unknown: 5,
  };

  const sortedEvents = useMemo(() => {
    const sorted = [...filteredEvents].sort((a, b) => {
      let cmp = 0;
      switch (sortField) {
        case "time": {
          const aTime = a.startTimeEpoch;
          const bTime = b.startTimeEpoch;
          if (aTime == null && bTime == null) cmp = 0;
          else if (aTime == null) cmp = 1;
          else if (bTime == null) cmp = -1;
          else cmp = aTime - bTime;
          break;
        }
        case "name":
          cmp = a.name.localeCompare(b.name);
          break;
        case "type":
          cmp = a.eventType.localeCompare(b.eventType);
          break;
        case "status":
          cmp = STATUS_RANK[a.status] - STATUS_RANK[b.status];
          break;
        case "duration": {
          const aDur = a.durationSecs;
          const bDur = b.durationSecs;
          if (aDur == null && bDur == null) cmp = 0;
          else if (aDur == null) cmp = 1;
          else if (bDur == null) cmp = -1;
          else cmp = aDur - bDur;
          break;
        }
      }
      return sortDirection === "asc" ? cmp : -cmp;
    });
    return sorted;
  }, [filteredEvents, sortField, sortDirection]);
```

- [ ] **Step 2: Replace filteredEvents with sortedEvents in rendering**

Replace all remaining references to `filteredEvents` in the component with `sortedEvents`:

- Line 54: `const selectedStillVisible = sortedEvents.some(...)`
- Line 62: `() => sortedEvents.findIndex(...)`
- Line 68: `count: sortedEvents.length,`
- Line 71: `sortedEvents[index]?.id === selectedEventId`
- Line 72: `(index) => sortedEvents[index]?.id ?? index`
- Line 89: `if (events.length === 0)` — keep this as `events` (checks raw data)
- Line 97: `if (sortedEvents.length === 0)`
- Line 112: `aria-label={...${sortedEvents.length} events...}`
- Line 138: `const event = sortedEvents[virtualRow.index];`

- [ ] **Step 3: Run TypeScript check**

Run: `npx tsc --noEmit`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add src/components/intune/EventTimeline.tsx
git commit -m "feat(intune): sort timeline events by selected field"
```

---

### Task 7: Add sort controls to IntuneDashboardNavBar

**Files:**
- Modify: `src/components/intune/IntuneDashboardNavBar.tsx`

- [ ] **Step 1: Import sort types and store selectors**

Add to the type import from `../../types/intune` (already imported):

```typescript
import type { IntuneSortField, SortDirection } from "../../stores/intune-store";
```

Add store selectors inside the component (after existing selectors, around line 46):

```typescript
  const sortField = useIntuneStore((s) => s.sortField);
  const sortDirection = useIntuneStore((s) => s.sortDirection);
  const setSortField = useIntuneStore((s) => s.setSortField);
  const toggleSortDirection = useIntuneStore((s) => s.toggleSortDirection);
```

- [ ] **Step 2: Add sort controls to the timeline filter row**

Inside the `{activeTab === "timeline" && ...}` conditional block (line 160), add the sort controls after the "Filters:" label and filter dropdowns, before the timeline scope pill. Insert right before the `{timelineScope.filePath && (` block (line 217):

```tsx
          <div style={{ width: "1px", height: "16px", backgroundColor: tokens.colorNeutralStroke2, margin: "0 2px" }} />
          <span style={{ fontSize: "10px", color: tokens.colorNeutralForeground3, fontWeight: 600, textTransform: "uppercase" }}>Sort:</span>
          <select
            value={sortField}
            onChange={(e) => setSortField(e.target.value as IntuneSortField)}
            style={selectStyle}
            disabled={isAnalyzing}
          >
            <option value="time">Time</option>
            <option value="name">Name</option>
            <option value="type">Type</option>
            <option value="status">Status</option>
            <option value="duration">Duration</option>
          </select>
          <button
            type="button"
            onClick={toggleSortDirection}
            disabled={isAnalyzing}
            title={sortDirection === "asc" ? "Ascending" : "Descending"}
            style={{
              fontSize: "12px",
              padding: "2px 6px",
              border: `1px solid ${tokens.colorNeutralStroke2}`,
              borderRadius: "3px",
              backgroundColor: tokens.colorNeutralCardBackground,
              color: tokens.colorNeutralForeground1,
              cursor: isAnalyzing ? "not-allowed" : "pointer",
              lineHeight: 1,
            }}
          >
            {sortDirection === "asc" ? "▲" : "▼"}
          </button>
```

- [ ] **Step 3: Run TypeScript check**

Run: `npx tsc --noEmit`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add src/components/intune/IntuneDashboardNavBar.tsx
git commit -m "feat(intune): add sort dropdown and direction toggle to timeline navbar"
```

---

### Task 8: Add sorting to DownloadStats table

**Files:**
- Modify: `src/components/intune/DownloadStats.tsx`

- [ ] **Step 1: Add sort imports and store selectors**

Add imports:

```typescript
import { useIntuneStore } from "../../stores/intune-store";
import type { DownloadSortField, SortDirection } from "../../stores/intune-store";
```

Add store selectors inside the component:

```typescript
  const downloadSortField = useIntuneStore((s) => s.downloadSortField);
  const downloadSortDirection = useIntuneStore((s) => s.downloadSortDirection);
  const setDownloadSortField = useIntuneStore((s) => s.setDownloadSortField);
  const toggleDownloadSortDirection = useIntuneStore((s) => s.toggleDownloadSortDirection);
```

- [ ] **Step 2: Add sort memo**

After the `aggregate` useMemo, add:

```typescript
  const sortedDownloads = useMemo(() => {
    return [...downloads].sort((a, b) => {
      let cmp = 0;
      switch (downloadSortField) {
        case "name":
          cmp = a.name.localeCompare(b.name);
          break;
        case "size":
          cmp = a.sizeBytes - b.sizeBytes;
          break;
        case "speed":
          cmp = a.speedBps - b.speedBps;
          break;
        case "doPercentage":
          cmp = a.doPercentage - b.doPercentage;
          break;
        case "duration":
          cmp = a.durationSecs - b.durationSecs;
          break;
        case "timestamp": {
          const aTime = a.timestampEpoch;
          const bTime = b.timestampEpoch;
          if (aTime == null && bTime == null) cmp = 0;
          else if (aTime == null) cmp = 1;
          else if (bTime == null) cmp = -1;
          else cmp = aTime - bTime;
          break;
        }
      }
      return downloadSortDirection === "asc" ? cmp : -cmp;
    });
  }, [downloads, downloadSortField, downloadSortDirection]);
```

- [ ] **Step 3: Make column headers clickable**

Replace the static `<th>` elements with clickable ones. Create a helper function inside the component:

```typescript
  const sortIndicator = (field: DownloadSortField) =>
    downloadSortField === field ? (downloadSortDirection === "asc" ? " ▲" : " ▼") : "";

  const handleHeaderClick = (field: DownloadSortField) => {
    if (downloadSortField === field) {
      toggleDownloadSortDirection();
    } else {
      setDownloadSortField(field);
    }
  };
```

Replace the `<thead>` block:

```tsx
          <thead style={{ position: "sticky", top: 0, zIndex: 1 }}>
            <tr
              style={{
                backgroundColor: tokens.colorNeutralBackground2,
                borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
                boxShadow: "0 1px 2px rgba(0,0,0,0.02)",
              }}
            >
              <th style={thStyle}>Status</th>
              <th style={{ ...thStyle, cursor: "pointer" }} onClick={() => handleHeaderClick("name")}>Content{sortIndicator("name")}</th>
              <th style={{ ...thStyle, textAlign: "right", width: "80px", cursor: "pointer" }} onClick={() => handleHeaderClick("size")}>Size{sortIndicator("size")}</th>
              <th style={{ ...thStyle, textAlign: "right", width: "90px", cursor: "pointer" }} onClick={() => handleHeaderClick("speed")}>Speed{sortIndicator("speed")}</th>
              <th style={{ ...thStyle, width: "120px", cursor: "pointer" }} onClick={() => handleHeaderClick("doPercentage")}>DO %{sortIndicator("doPercentage")}</th>
              <th style={{ ...thStyle, textAlign: "right", width: "70px", cursor: "pointer" }} onClick={() => handleHeaderClick("duration")}>Dur.{sortIndicator("duration")}</th>
              <th style={{ ...thStyle, width: "130px", cursor: "pointer" }} onClick={() => handleHeaderClick("timestamp")}>Timestamp{sortIndicator("timestamp")}</th>
            </tr>
          </thead>
```

- [ ] **Step 4: Replace downloads with sortedDownloads in tbody**

Change the `{downloads.map((dl, i) => (` line to `{sortedDownloads.map((dl, i) => (`.

- [ ] **Step 5: Run TypeScript check**

Run: `npx tsc --noEmit`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/components/intune/DownloadStats.tsx
git commit -m "feat(intune): add clickable column header sorting to download stats"
```

---

### Task 9: Final verification

**Files:** None (verification only)

- [ ] **Step 1: Run all Rust tests**

Run: `cd src-tauri && cargo test`
Expected: All PASS

- [ ] **Step 2: Run Rust clippy**

Run: `cd src-tauri && cargo clippy -- -D warnings`
Expected: PASS with zero warnings

- [ ] **Step 3: Run TypeScript check**

Run: `npx tsc --noEmit`
Expected: PASS

- [ ] **Step 4: Run frontend dev build**

Run: `npm run frontend:build`
Expected: PASS — clean build

- [ ] **Step 5: Verify end-to-end with dev server**

Run: `npm run frontend:dev`
Manual check: Open browser, verify no console errors. The sort controls won't function without the Tauri backend, but they should render and respond to clicks.
