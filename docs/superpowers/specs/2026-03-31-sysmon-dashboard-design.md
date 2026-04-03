# Sysmon Dashboard View Design

**Date:** 2026-03-31
**Status:** Approved

## Context

The Sysmon workspace currently has 3 tabs: Events (virtualized list), Summary (basic metric cards + event type table), and Config (metadata viewer). The Summary tab provides only raw numbers with no visualizations. Users analyzing Sysmon EVTX data need an at-a-glance dashboard with charts and ranked lists to quickly understand event patterns, identify top processes, network activity, DNS queries, security alerts, file activity, and registry changes.

## Decision Summary

- **Layout:** Single scrollable dashboard as a new tab (default when data loads)
- **Charts:** `@fluentui/react-charts` v9 (React 19 compatible, consistent with Fluent UI v9 design system)
- **Aggregation:** Backend (Rust) computes all dashboard data — no frontend-side aggregation
- **Timeline granularity:** User-selectable (minute/hour/day) with all 3 pre-computed by backend

## 1. Backend Data Model

### New Structs (`src-tauri/src/sysmon/models.rs`)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeBucket {
    pub timestamp: String,
    pub timestamp_ms: i64,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RankedItem {
    pub name: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecuritySummary {
    pub total_warnings: usize,
    pub total_errors: usize,
    pub events_by_type: Vec<RankedItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SysmonDashboardData {
    pub timeline_minute: Vec<TimeBucket>,
    pub timeline_hourly: Vec<TimeBucket>,
    pub timeline_daily: Vec<TimeBucket>,
    pub top_processes: Vec<RankedItem>,
    pub top_destinations: Vec<RankedItem>,
    pub top_ports: Vec<RankedItem>,
    pub top_dns_queries: Vec<RankedItem>,
    pub security_events: SecuritySummary,
    pub top_target_files: Vec<RankedItem>,
    pub top_registry_keys: Vec<RankedItem>,
}
```

### Updated Result

`SysmonAnalysisResult` gains a `dashboard: SysmonDashboardData` field alongside existing `summary` and `config`.

## 2. Backend Aggregation

### New Function (`src-tauri/src/sysmon/evtx_parser.rs`)

`build_dashboard_data(events: &[SysmonEvent]) -> SysmonDashboardData`

**Timeline buckets:**
- Iterate events once, bucket `timestamp_ms` into minute/hour/day maps using integer division (ms / 60000, ms / 3600000, ms / 86400000)
- Convert each map to sorted `Vec<TimeBucket>`
- Generate ISO 8601 timestamp strings for each bucket start (e.g., `2024-01-15T10:00:00Z` for hourly, `2024-01-15T00:00:00Z` for daily)

**Top-N lists (all capped at 20):**
- **Processes:** Count `image` field across all events, sort desc
- **Destinations:** Filter `NetworkConnect` events, count `destination_ip` (prefer `destination_hostname` if present)
- **Ports:** Filter `NetworkConnect` events, count `destination_port`
- **DNS:** Filter `DnsQuery` events, count `query_name`
- **Files:** Filter file-related event types (`FileCreate`, `FileCreateTime`, `FileDelete`, `FileDeleteDetected`, `FileBlockExecutable`, `FileBlockShredding`, `FileExecutableDetected`, `FileCreateStreamHash`), count `target_filename`
- **Registry:** Filter registry event types (`RegistryAddOrDelete`, `RegistryValueSet`, `RegistryRename`), count `target_object`

**Security summary:**
- Filter events where severity is Warning or Error
- Count totals for each severity
- Group by event type, sort desc

### Integration

Called from `analyze_sysmon_logs` command in `src-tauri/src/commands/sysmon.rs` after events are sorted, alongside existing `build_summary()` and `extract_config()`.

## 3. TypeScript Types

### New Types (`src/types/sysmon.ts`)

```typescript
export interface TimeBucket {
  timestamp: string;
  timestampMs: number;
  count: number;
}

export interface RankedItem {
  name: string;
  count: number;
}

export interface SecuritySummary {
  totalWarnings: number;
  totalErrors: number;
  eventsByType: RankedItem[];
}

export interface SysmonDashboardData {
  timelineMinute: TimeBucket[];
  timelineHourly: TimeBucket[];
  timelineDaily: TimeBucket[];
  topProcesses: RankedItem[];
  topDestinations: RankedItem[];
  topPorts: RankedItem[];
  topDnsQueries: RankedItem[];
  securityEvents: SecuritySummary;
  topTargetFiles: RankedItem[];
  topRegistryKeys: RankedItem[];
}
```

`SysmonAnalysisResult` updated to include `dashboard: SysmonDashboardData`.

## 4. Store Changes

### `src/stores/sysmon-store.ts`

- Add `dashboard: SysmonDashboardData | null` to state (initial: `null`)
- `setResults()` populates `dashboard` from `result.dashboard`
- `clear()` resets `dashboard` to `null`
- Update `activeTab` union type to include `"dashboard"`
- Default `activeTab` set to `"dashboard"` in `setResults()`

## 5. New Dependency

```bash
npm install @fluentui/react-charts
```

`@fluentui/react-charts` v9.3.2 — Fluent UI v9 charting library, React 19 compatible.

Chart components used:
- `VerticalBarChart` — event volume timeline
- `DonutChart` — event type breakdown
- `HorizontalBarChart` — top-N ranked lists
- All respect Fluent UI theming (dark/light mode)

## 6. Frontend Components

### Component Architecture

All new components in `src/components/sysmon/`:

| Component | Purpose |
|-----------|---------|
| `SysmonDashboardView.tsx` | Main scrollable container with responsive 2-column grid |
| `DashboardMetricCards.tsx` | Hero row: total events, unique processes, unique computers, time range, parse errors |
| `DashboardTimeline.tsx` | VerticalBarChart + minute/hour/day dropdown |
| `DashboardEventTypeChart.tsx` | DonutChart of event type distribution |
| `DashboardSecurityAlerts.tsx` | Warning/error totals + breakdown by event type |
| `DashboardTopList.tsx` | Reusable HorizontalBarChart for top-N lists (used 6 times) |

### Layout

```
┌─────────────────────────────────────────────────────┐
│  METRIC CARDS ROW (full width)                      │
│  [Total Events] [Processes] [Computers] [Range] [E] │
├─────────────────────────────────────────────────────┤
│  EVENT VOLUME TIMELINE (full width)    [Min|Hr|Day] │
│  VerticalBarChart                                   │
├──────────────────────────┬──────────────────────────┤
│  EVENT TYPE BREAKDOWN    │  SECURITY ALERTS          │
│  DonutChart              │  Counts + table           │
├──────────────────────────┬──────────────────────────┤
│  TOP PROCESSES           │  NETWORK ACTIVITY         │
│  HorizontalBarChart      │  Destinations + Ports     │
├──────────────────────────┬──────────────────────────┤
│  DNS QUERIES             │  FILE ACTIVITY            │
│  HorizontalBarChart      │  HorizontalBarChart       │
├─────────────────────────────────────────────────────┤
│  REGISTRY ACTIVITY (full width)                     │
│  HorizontalBarChart                                 │
└─────────────────────────────────────────────────────┘
```

- Responsive grid: `grid-template-columns: repeat(auto-fit, minmax(400px, 1fr))`
- Each widget in a card container with Fluent UI tokens for background/border
- Gap: 16px between cards
- Full-width widgets span the grid with `grid-column: 1 / -1`

### `DashboardTopList.tsx` (Reusable)

Props: `title: string`, `items: RankedItem[]`, `emptyMessage?: string`

Used for: top processes, destinations, ports, DNS queries, files, registry keys. Shows "No data" message when items array is empty.

## 7. Tab Integration

### `SysmonWorkspace.tsx`

- Add `"dashboard"` to tab list as first tab
- Tab order: **Dashboard** | Events (n) | Summary | Config
- Dashboard is the default active tab when results load
- No count badge on Dashboard tab

## 8. Styling

- All styles via Fluent UI `makeStyles` and design tokens
- Metric cards: horizontal flex row, `tokens.colorNeutralBackground3` background
- Widget cards: consistent padding (16px), border radius, subtle border
- Charts inherit theme automatically from `FluentProvider`
- Dark/light theme support via Fluent UI's built-in theming

## 9. Files Changed

### Backend (3 files modified)

| File | Change |
|------|--------|
| `src-tauri/src/sysmon/models.rs` | Add `TimeBucket`, `RankedItem`, `SecuritySummary`, `SysmonDashboardData`; add `dashboard` to `SysmonAnalysisResult` |
| `src-tauri/src/sysmon/evtx_parser.rs` | Add `build_dashboard_data()` function |
| `src-tauri/src/commands/sysmon.rs` | Call `build_dashboard_data()`, include in result |

### Frontend (4 modified, 6 new)

| File | Change |
|------|--------|
| `package.json` | Add `@fluentui/react-charts` |
| `src/types/sysmon.ts` | Add dashboard types, update `SysmonAnalysisResult` |
| `src/stores/sysmon-store.ts` | Add `dashboard` state, update `activeTab` |
| `src/components/sysmon/SysmonWorkspace.tsx` | Add Dashboard tab as default |
| `src/components/sysmon/SysmonDashboardView.tsx` | **New** |
| `src/components/sysmon/DashboardMetricCards.tsx` | **New** |
| `src/components/sysmon/DashboardTimeline.tsx` | **New** |
| `src/components/sysmon/DashboardEventTypeChart.tsx` | **New** |
| `src/components/sysmon/DashboardSecurityAlerts.tsx` | **New** |
| `src/components/sysmon/DashboardTopList.tsx` | **New** |

## 10. Verification

1. `cargo check` from `src-tauri/` — Rust types compile
2. `cargo test` from `src-tauri/` — existing tests pass + new unit tests for `build_dashboard_data()`
3. `cargo clippy -- -D warnings` — zero warnings
4. `npx tsc --noEmit` — TypeScript compiles
5. Manual: open Sysmon EVTX file, Dashboard tab appears as default, all 9 widgets render
6. Manual: switch timeline granularity (minute/hour/day), chart updates
7. Manual: empty data edge cases (no network events = "No data" message)
8. Manual: dark/light theme toggle, charts respect theme
