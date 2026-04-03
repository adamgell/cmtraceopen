# Sysmon Dashboard View Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Dashboard tab to the Sysmon workspace with 9 widgets (metric cards, timeline chart, event type donut, security alerts, top processes, network activity, DNS queries, file activity, registry activity) powered by backend-computed aggregations and `@fluentui/react-charts`.

**Architecture:** Backend computes all dashboard aggregations in a new `build_dashboard_data()` function alongside existing `build_summary()`. A new `SysmonDashboardData` struct is added to `SysmonAnalysisResult`. Frontend renders 6 new components using Fluent UI v9 charts in a scrollable 2-column grid layout. Dashboard becomes the default tab.

**Tech Stack:** Rust (serde, chrono, HashMap aggregations), TypeScript/React 19, Zustand, `@fluentui/react-charts` v9, `@fluentui/react-components` v9

**Spec:** `docs/superpowers/specs/2026-03-31-sysmon-dashboard-design.md`

---

## File Structure

### Backend (Rust)
| File | Action | Responsibility |
|------|--------|---------------|
| `src-tauri/src/sysmon/models.rs` | Modify | Add `TimeBucket`, `RankedItem`, `SecuritySummary`, `SysmonDashboardData` structs; add `dashboard` field to `SysmonAnalysisResult` |
| `src-tauri/src/sysmon/evtx_parser.rs` | Modify | Add `build_dashboard_data()` function |
| `src-tauri/src/commands/sysmon.rs` | Modify | Call `build_dashboard_data()` and wire into result |
| `src-tauri/tests/sysmon_parser.rs` | Modify | Add tests for `build_dashboard_data()` |

### Frontend (TypeScript)
| File | Action | Responsibility |
|------|--------|---------------|
| `package.json` | Modify | Add `@fluentui/react-charts` dependency |
| `src/types/sysmon.ts` | Modify | Add `TimeBucket`, `RankedItem`, `SecuritySummary`, `SysmonDashboardData` interfaces; update `SysmonAnalysisResult` |
| `src/stores/sysmon-store.ts` | Modify | Add `dashboard` state, update `activeTab` type, update actions |
| `src/components/sysmon/SysmonWorkspace.tsx` | Modify | Add Dashboard tab as default |
| `src/components/sysmon/SysmonDashboardView.tsx` | Create | Main scrollable dashboard container |
| `src/components/sysmon/DashboardMetricCards.tsx` | Create | Hero metric row (5 cards) |
| `src/components/sysmon/DashboardTimeline.tsx` | Create | VerticalBarChart + granularity picker |
| `src/components/sysmon/DashboardEventTypeChart.tsx` | Create | DonutChart of event types |
| `src/components/sysmon/DashboardSecurityAlerts.tsx` | Create | Warning/error summary widget |
| `src/components/sysmon/DashboardTopList.tsx` | Create | Reusable HorizontalBarChart for top-N lists |

---

## Task 1: Add Backend Data Model Structs

**Files:**
- Modify: `src-tauri/src/sysmon/models.rs:288-300`

- [ ] **Step 1: Add new structs before `SysmonAnalysisResult`**

Insert the following after line 286 (closing `}` of `SysmonConfig`) in `src-tauri/src/sysmon/models.rs`:

```rust
/// A time-bucketed event count for timeline charts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimeBucket {
    /// ISO 8601 timestamp for the bucket start.
    pub timestamp: String,
    /// Unix ms timestamp for the bucket start.
    pub timestamp_ms: i64,
    /// Number of events in this bucket.
    pub count: u64,
}

/// A named item with a count, used for top-N rankings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RankedItem {
    pub name: String,
    pub count: u64,
}

/// Aggregated security alert statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecuritySummary {
    pub total_warnings: u64,
    pub total_errors: u64,
    pub events_by_type: Vec<RankedItem>,
}

/// Pre-computed dashboard aggregations.
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

- [ ] **Step 2: Add `dashboard` field to `SysmonAnalysisResult`**

In the same file, add a field to `SysmonAnalysisResult` (after `config` field, before `source_path`):

```rust
/// Pre-computed dashboard aggregations.
pub dashboard: SysmonDashboardData,
```

- [ ] **Step 3: Run cargo check**

Run: `cd src-tauri && cargo check 2>&1`
Expected: Compilation errors in `commands/sysmon.rs` because `dashboard` field is now required but not provided. This is expected — we'll fix it in Task 3.

- [ ] **Step 4: Commit**

```bash
git add src-tauri/src/sysmon/models.rs
git commit -m "feat(sysmon): add dashboard data model structs"
```

---

## Task 2: Implement `build_dashboard_data()` in Rust

**Files:**
- Modify: `src-tauri/src/sysmon/evtx_parser.rs`

- [ ] **Step 1: Add the `build_dashboard_data` function**

Add the following function after `build_summary()` (after line 322) in `src-tauri/src/sysmon/evtx_parser.rs`:

```rust
/// Builds pre-computed dashboard aggregations from parsed events.
pub fn build_dashboard_data(events: &[SysmonEvent]) -> SysmonDashboardData {
    use chrono::{DateTime, Utc, Timelike, Datelike};

    const TOP_N: usize = 20;

    // --- Timeline bucketing ---
    let mut minute_buckets: HashMap<i64, u64> = HashMap::new();
    let mut hourly_buckets: HashMap<i64, u64> = HashMap::new();
    let mut daily_buckets: HashMap<i64, u64> = HashMap::new();

    // --- Top-N counters ---
    let mut process_counts: HashMap<String, u64> = HashMap::new();
    let mut dest_counts: HashMap<String, u64> = HashMap::new();
    let mut port_counts: HashMap<String, u64> = HashMap::new();
    let mut dns_counts: HashMap<String, u64> = HashMap::new();
    let mut file_counts: HashMap<String, u64> = HashMap::new();
    let mut registry_counts: HashMap<String, u64> = HashMap::new();

    // --- Security ---
    let mut total_warnings: u64 = 0;
    let mut total_errors: u64 = 0;
    let mut security_type_counts: HashMap<String, u64> = HashMap::new();

    for event in events {
        // Timeline: bucket by timestamp_ms
        if let Some(ms) = event.timestamp_ms {
            let minute_key = (ms / 60_000) * 60_000;
            let hourly_key = (ms / 3_600_000) * 3_600_000;
            let daily_key = (ms / 86_400_000) * 86_400_000;
            *minute_buckets.entry(minute_key).or_insert(0) += 1;
            *hourly_buckets.entry(hourly_key).or_insert(0) += 1;
            *daily_buckets.entry(daily_key).or_insert(0) += 1;
        }

        // Top processes
        if let Some(ref image) = event.image {
            if !image.is_empty() {
                *process_counts.entry(image.clone()).or_insert(0) += 1;
            }
        }

        // Network: destinations and ports (NetworkConnect = EventID 3)
        if event.event_id == 3 {
            // Prefer hostname over IP
            let dest = event
                .destination_hostname
                .as_deref()
                .filter(|s| !s.is_empty())
                .or(event.destination_ip.as_deref().filter(|s| !s.is_empty()));
            if let Some(d) = dest {
                *dest_counts.entry(d.to_string()).or_insert(0) += 1;
            }
            if let Some(port) = event.destination_port {
                *port_counts.entry(port.to_string()).or_insert(0) += 1;
            }
        }

        // DNS queries (DnsQuery = EventID 22)
        if event.event_id == 22 {
            if let Some(ref qname) = event.query_name {
                if !qname.is_empty() {
                    *dns_counts.entry(qname.clone()).or_insert(0) += 1;
                }
            }
        }

        // File activity (EventIDs: 2, 11, 15, 23, 24, 26, 27, 28, 29)
        match event.event_id {
            2 | 11 | 15 | 23 | 24 | 26 | 27 | 28 | 29 => {
                if let Some(ref tf) = event.target_filename {
                    if !tf.is_empty() {
                        *file_counts.entry(tf.clone()).or_insert(0) += 1;
                    }
                }
            }
            _ => {}
        }

        // Registry activity (EventIDs: 12, 13, 14)
        match event.event_id {
            12 | 13 | 14 => {
                if let Some(ref to) = event.target_object {
                    if !to.is_empty() {
                        *registry_counts.entry(to.clone()).or_insert(0) += 1;
                    }
                }
            }
            _ => {}
        }

        // Security: warning and error severity events
        match event.severity {
            SysmonSeverity::Warning => {
                total_warnings += 1;
                *security_type_counts
                    .entry(event.event_type.display_name().to_string())
                    .or_insert(0) += 1;
            }
            SysmonSeverity::Error => {
                total_errors += 1;
                *security_type_counts
                    .entry(event.event_type.display_name().to_string())
                    .or_insert(0) += 1;
            }
            SysmonSeverity::Info => {}
        }
    }

    // --- Helper: convert bucket map to sorted Vec<TimeBucket> ---
    let buckets_to_vec = |map: HashMap<i64, u64>| -> Vec<TimeBucket> {
        let mut vec: Vec<TimeBucket> = map
            .into_iter()
            .map(|(ms, count)| {
                let ts = DateTime::<Utc>::from_timestamp_millis(ms)
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_default();
                TimeBucket {
                    timestamp: ts,
                    timestamp_ms: ms,
                    count,
                }
            })
            .collect();
        vec.sort_by_key(|b| b.timestamp_ms);
        vec
    };

    // --- Helper: convert count map to top-N Vec<RankedItem> ---
    let top_n = |map: HashMap<String, u64>| -> Vec<RankedItem> {
        let mut vec: Vec<RankedItem> = map
            .into_iter()
            .map(|(name, count)| RankedItem { name, count })
            .collect();
        vec.sort_by(|a, b| b.count.cmp(&a.count));
        vec.truncate(TOP_N);
        vec
    };

    let mut security_by_type: Vec<RankedItem> = security_type_counts
        .into_iter()
        .map(|(name, count)| RankedItem { name, count })
        .collect();
    security_by_type.sort_by(|a, b| b.count.cmp(&a.count));

    SysmonDashboardData {
        timeline_minute: buckets_to_vec(minute_buckets),
        timeline_hourly: buckets_to_vec(hourly_buckets),
        timeline_daily: buckets_to_vec(daily_buckets),
        top_processes: top_n(process_counts),
        top_destinations: top_n(dest_counts),
        top_ports: top_n(port_counts),
        top_dns_queries: top_n(dns_counts),
        security_events: SecuritySummary {
            total_warnings,
            total_errors,
            events_by_type: security_by_type,
        },
        top_target_files: top_n(file_counts),
        top_registry_keys: top_n(registry_counts),
    }
}
```

- [ ] **Step 2: Add required imports at top of file**

Ensure these are imported at the top of `evtx_parser.rs` (add if missing):

```rust
use super::models::{SysmonDashboardData, TimeBucket, RankedItem, SecuritySummary};
```

Also ensure `chrono` import includes `DateTime` and `Utc` (may already exist — check existing imports).

- [ ] **Step 3: Run cargo check**

Run: `cd src-tauri && cargo check 2>&1`
Expected: Still fails because `commands/sysmon.rs` doesn't provide `dashboard` field yet. The new function itself should compile.

- [ ] **Step 4: Commit**

```bash
git add src-tauri/src/sysmon/evtx_parser.rs
git commit -m "feat(sysmon): implement build_dashboard_data aggregation"
```

---

## Task 3: Wire Dashboard Data Into Command

**Files:**
- Modify: `src-tauri/src/commands/sysmon.rs:259-283`

- [ ] **Step 1: Add dashboard computation after build_summary**

In `src-tauri/src/commands/sysmon.rs`, after line 262 (`let config = ...`), add:

```rust
    // Build dashboard aggregations
    let dashboard = evtx_parser::build_dashboard_data(&all_events);
```

- [ ] **Step 2: Add `dashboard` to the result struct**

Update the `Ok(SysmonAnalysisResult { ... })` block (around line 278) to include the `dashboard` field:

```rust
    Ok(SysmonAnalysisResult {
        events: all_events,
        summary,
        config,
        dashboard,
        source_path: path,
    })
```

- [ ] **Step 3: Run cargo check**

Run: `cd src-tauri && cargo check 2>&1`
Expected: PASS — all Rust code compiles.

- [ ] **Step 4: Run cargo clippy**

Run: `cd src-tauri && cargo clippy -- -D warnings 2>&1`
Expected: PASS with zero warnings.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/commands/sysmon.rs
git commit -m "feat(sysmon): wire dashboard data into analyze command"
```

---

## Task 4: Add Backend Tests for `build_dashboard_data`

**Files:**
- Modify: `src-tauri/tests/sysmon_parser.rs`

- [ ] **Step 1: Add import for `build_dashboard_data`**

At the top of `src-tauri/tests/sysmon_parser.rs`, update line 1 to:

```rust
use app_lib::sysmon::evtx_parser::{build_dashboard_data, build_summary};
```

- [ ] **Step 2: Add test for empty events**

Append after the last test:

```rust
#[test]
fn dashboard_data_empty_events() {
    let data = build_dashboard_data(&[]);
    assert!(data.timeline_minute.is_empty());
    assert!(data.timeline_hourly.is_empty());
    assert!(data.timeline_daily.is_empty());
    assert!(data.top_processes.is_empty());
    assert!(data.top_destinations.is_empty());
    assert!(data.top_ports.is_empty());
    assert!(data.top_dns_queries.is_empty());
    assert!(data.top_target_files.is_empty());
    assert!(data.top_registry_keys.is_empty());
    assert_eq!(data.security_events.total_warnings, 0);
    assert_eq!(data.security_events.total_errors, 0);
}
```

- [ ] **Step 3: Add test for timeline bucketing**

```rust
#[test]
fn dashboard_data_timeline_bucketing() {
    let events = vec![
        // Two events in same minute, same hour
        make_event(0, "2024-04-28T10:00:00Z", Some(1714298400000), 1),
        make_event(1, "2024-04-28T10:00:30Z", Some(1714298430000), 1),
        // One event in different hour
        make_event(2, "2024-04-28T11:00:00Z", Some(1714302000000), 1),
    ];
    let data = build_dashboard_data(&events);

    // Minute buckets: 2 at 10:00, 1 at 10:00:30 rounds to same minute? No — 10:00 and 10:00 are same minute key
    // 1714298400000 / 60000 * 60000 = 1714298400000 (10:00:00)
    // 1714298430000 / 60000 * 60000 = 1714298400000 (10:00:00)
    // So 2 events in minute bucket at 10:00, 1 at 11:00
    assert_eq!(data.timeline_minute.len(), 2);
    assert_eq!(data.timeline_minute[0].count, 2); // 10:00 bucket
    assert_eq!(data.timeline_minute[1].count, 1); // 11:00 bucket

    // Hourly: 2 at 10:00 hour, 1 at 11:00 hour
    assert_eq!(data.timeline_hourly.len(), 2);

    // Daily: all same day
    assert_eq!(data.timeline_daily.len(), 1);
    assert_eq!(data.timeline_daily[0].count, 3);
}
```

- [ ] **Step 4: Add test for top processes**

```rust
#[test]
fn dashboard_data_top_processes() {
    let mut e1 = make_event(0, "2024-04-28T10:00:00Z", Some(1714298400000), 1);
    e1.image = Some("C:\\Windows\\svchost.exe".to_string());
    let mut e2 = make_event(1, "2024-04-28T10:00:01Z", Some(1714298401000), 1);
    e2.image = Some("C:\\Windows\\svchost.exe".to_string());
    let mut e3 = make_event(2, "2024-04-28T10:00:02Z", Some(1714298402000), 1);
    e3.image = Some("C:\\Windows\\explorer.exe".to_string());

    let data = build_dashboard_data(&[e1, e2, e3]);
    assert_eq!(data.top_processes.len(), 2);
    assert_eq!(data.top_processes[0].name, "C:\\Windows\\svchost.exe");
    assert_eq!(data.top_processes[0].count, 2);
    assert_eq!(data.top_processes[1].name, "C:\\Windows\\explorer.exe");
    assert_eq!(data.top_processes[1].count, 1);
}
```

- [ ] **Step 5: Add test for network and DNS aggregation**

```rust
#[test]
fn dashboard_data_network_and_dns() {
    // NetworkConnect event (EventID 3)
    let mut net1 = make_event(0, "2024-04-28T10:00:00Z", Some(1714298400000), 3);
    net1.destination_ip = Some("10.0.0.1".to_string());
    net1.destination_port = Some(443);
    net1.destination_hostname = Some("example.com".to_string());

    let mut net2 = make_event(1, "2024-04-28T10:00:01Z", Some(1714298401000), 3);
    net2.destination_ip = Some("10.0.0.1".to_string());
    net2.destination_port = Some(80);

    // DnsQuery event (EventID 22)
    let mut dns1 = make_event(2, "2024-04-28T10:00:02Z", Some(1714298402000), 22);
    dns1.query_name = Some("google.com".to_string());

    let mut dns2 = make_event(3, "2024-04-28T10:00:03Z", Some(1714298403000), 22);
    dns2.query_name = Some("google.com".to_string());

    let data = build_dashboard_data(&[net1, net2, dns1, dns2]);

    // Destinations: "example.com" (hostname preferred), "10.0.0.1" (IP fallback)
    assert_eq!(data.top_destinations.len(), 2);
    assert_eq!(data.top_destinations[0].count, 1); // each destination appears once

    // Ports: 443 and 80
    assert_eq!(data.top_ports.len(), 2);

    // DNS: google.com x2
    assert_eq!(data.top_dns_queries.len(), 1);
    assert_eq!(data.top_dns_queries[0].name, "google.com");
    assert_eq!(data.top_dns_queries[0].count, 2);
}
```

- [ ] **Step 6: Add test for security events**

```rust
#[test]
fn dashboard_data_security_events() {
    // CreateRemoteThread (EventID 8) → Warning severity
    let mut e1 = make_event(0, "2024-04-28T10:00:00Z", Some(1714298400000), 8);
    e1.severity = SysmonSeverity::Warning;
    // Error event (EventID 255)
    let mut e2 = make_event(1, "2024-04-28T10:00:01Z", Some(1714298401000), 255);
    e2.severity = SysmonSeverity::Error;
    // Normal info event
    let e3 = make_event(2, "2024-04-28T10:00:02Z", Some(1714298402000), 1);

    let data = build_dashboard_data(&[e1, e2, e3]);
    assert_eq!(data.security_events.total_warnings, 1);
    assert_eq!(data.security_events.total_errors, 1);
    assert_eq!(data.security_events.events_by_type.len(), 2);
}
```

- [ ] **Step 7: Run all tests**

Run: `cd src-tauri && cargo test 2>&1`
Expected: All tests pass including new dashboard tests.

- [ ] **Step 8: Commit**

```bash
git add src-tauri/tests/sysmon_parser.rs
git commit -m "test(sysmon): add unit tests for build_dashboard_data"
```

---

## Task 5: Install `@fluentui/react-charts`

**Files:**
- Modify: `package.json`

- [ ] **Step 1: Install the package**

Run: `npm install @fluentui/react-charts`

- [ ] **Step 2: Verify installation**

Run: `node -e "const p = require('./node_modules/@fluentui/react-charts/package.json'); console.log(p.name, p.version)"`
Expected: `@fluentui/react-charts 9.x.x`

- [ ] **Step 3: Run TypeScript check**

Run: `npx tsc --noEmit 2>&1`
Expected: PASS (no type errors from new dependency)

- [ ] **Step 4: Commit**

```bash
git add package.json package-lock.json
git commit -m "chore: add @fluentui/react-charts dependency"
```

---

## Task 6: Add TypeScript Types

**Files:**
- Modify: `src/types/sysmon.ts`

- [ ] **Step 1: Add new interfaces before `SysmonAnalysisResult`**

Insert the following before the `SysmonAnalysisResult` interface (before line 116) in `src/types/sysmon.ts`:

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

- [ ] **Step 2: Add `dashboard` field to `SysmonAnalysisResult`**

Update the `SysmonAnalysisResult` interface to include:

```typescript
export interface SysmonAnalysisResult {
  events: SysmonEvent[];
  summary: SysmonSummary;
  config: SysmonConfig;
  dashboard: SysmonDashboardData;
  sourcePath: string;
}
```

- [ ] **Step 3: Run TypeScript check**

Run: `npx tsc --noEmit 2>&1`
Expected: Errors in `sysmon-store.ts` because `setResults` doesn't handle `dashboard` yet. Expected — fixed in next task.

- [ ] **Step 4: Commit**

```bash
git add src/types/sysmon.ts
git commit -m "feat(sysmon): add dashboard TypeScript types"
```

---

## Task 7: Update Sysmon Store

**Files:**
- Modify: `src/stores/sysmon-store.ts`

- [ ] **Step 1: Update imports**

Update the import from `../types/sysmon` to include `SysmonDashboardData`:

```typescript
import type {
  SysmonAnalysisResult,
  SysmonDashboardData,
  SysmonEvent,
  SysmonEventType,
  SysmonSeverity,
} from "../types/sysmon";
```

- [ ] **Step 2: Update `SysmonWorkspaceTab` type**

Change line 11 from:
```typescript
type SysmonWorkspaceTab = "events" | "summary" | "config";
```
to:
```typescript
type SysmonWorkspaceTab = "dashboard" | "events" | "summary" | "config";
```

- [ ] **Step 3: Add `dashboard` to state interface**

In `SysmonState` interface, add after `config: SysmonConfig | null;`:

```typescript
  dashboard: SysmonDashboardData | null;
```

- [ ] **Step 4: Update initial state**

In the `create<SysmonState>()` call, add to initial state (after `config: null,`):

```typescript
    dashboard: null,
```

- [ ] **Step 5: Update `beginAnalysis` action**

In `beginAnalysis`, add `dashboard: null,` to the reset state object.

- [ ] **Step 6: Update `setResults` action**

In `setResults`, change `activeTab: "events"` to `activeTab: "dashboard"` and add `dashboard: result.dashboard,`:

```typescript
    setResults: (result) =>
      set({
        events: result.events,
        summary: result.summary,
        config: result.config,
        dashboard: result.dashboard,
        sourcePath: result.sourcePath,
        isAnalyzing: false,
        analysisError: null,
        progressMessage: null,
        activeTab: "dashboard",
      }),
```

- [ ] **Step 7: Update `clear` action**

In `clear`, add `dashboard: null,` to the reset state object.

- [ ] **Step 8: Run TypeScript check**

Run: `npx tsc --noEmit 2>&1`
Expected: PASS

- [ ] **Step 9: Commit**

```bash
git add src/stores/sysmon-store.ts
git commit -m "feat(sysmon): add dashboard state to store"
```

---

## Task 8: Create `DashboardTopList` Component (Reusable)

**Files:**
- Create: `src/components/sysmon/DashboardTopList.tsx`

- [ ] **Step 1: Create the reusable top-N chart component**

Create `src/components/sysmon/DashboardTopList.tsx`:

```tsx
import { tokens, makeStyles } from "@fluentui/react-components";
import { HorizontalBarChart, HorizontalBarChartVariant } from "@fluentui/react-charts";
import type { RankedItem } from "../../types/sysmon";

const useStyles = makeStyles({
  container: {
    backgroundColor: tokens.colorNeutralBackground3,
    borderRadius: tokens.borderRadiusMedium,
    border: `1px solid ${tokens.colorNeutralStroke2}`,
    padding: "16px",
  },
  title: {
    fontSize: "14px",
    fontWeight: 600,
    marginBottom: "12px",
    color: tokens.colorNeutralForeground1,
  },
  empty: {
    fontSize: "12px",
    color: tokens.colorNeutralForeground3,
    fontStyle: "italic",
  },
});

interface DashboardTopListProps {
  title: string;
  items: RankedItem[];
  emptyMessage?: string;
  color?: string;
}

export function DashboardTopList({
  title,
  items,
  emptyMessage = "No data",
  color,
}: DashboardTopListProps) {
  const styles = useStyles();

  if (items.length === 0) {
    return (
      <div className={styles.container}>
        <div className={styles.title}>{title}</div>
        <div className={styles.empty}>{emptyMessage}</div>
      </div>
    );
  }

  const maxCount = items[0].count;
  const chartData = items.map((item, i) => ({
    chartTitle: item.name,
    chartData: [
      {
        legend: item.name,
        horizontalBarChartdata: { x: item.count, y: maxCount },
        color: color || tokens.colorBrandBackground,
      },
    ],
  }));

  return (
    <div className={styles.container}>
      <div className={styles.title}>{title}</div>
      <HorizontalBarChart
        data={chartData}
        variant={HorizontalBarChartVariant.AbsoluteScale}
        hideLabels={false}
        barHeight={16}
      />
    </div>
  );
}
```

- [ ] **Step 2: Run TypeScript check**

Run: `npx tsc --noEmit 2>&1`
Expected: PASS or may have minor import issues to fix depending on exact `@fluentui/react-charts` export names.

- [ ] **Step 3: Commit**

```bash
git add src/components/sysmon/DashboardTopList.tsx
git commit -m "feat(sysmon): add reusable DashboardTopList component"
```

---

## Task 9: Create `DashboardMetricCards` Component

**Files:**
- Create: `src/components/sysmon/DashboardMetricCards.tsx`

- [ ] **Step 1: Create the metric cards component**

Create `src/components/sysmon/DashboardMetricCards.tsx`:

```tsx
import { tokens, makeStyles } from "@fluentui/react-components";
import type { SysmonSummary } from "../../types/sysmon";

const useStyles = makeStyles({
  row: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))",
    gap: "12px",
    marginBottom: "16px",
  },
  card: {
    backgroundColor: tokens.colorNeutralBackground3,
    borderRadius: tokens.borderRadiusMedium,
    border: `1px solid ${tokens.colorNeutralStroke2}`,
    padding: "12px 16px",
  },
  label: {
    fontSize: "12px",
    color: tokens.colorNeutralForeground3,
    marginBottom: "4px",
  },
  value: {
    fontSize: "20px",
    fontWeight: 600,
    color: tokens.colorNeutralForeground1,
  },
  errorValue: {
    fontSize: "20px",
    fontWeight: 600,
    color: tokens.colorPaletteRedForeground1,
  },
  subtext: {
    fontSize: "11px",
    color: tokens.colorNeutralForeground3,
    marginTop: "2px",
  },
});

interface DashboardMetricCardsProps {
  summary: SysmonSummary;
}

export function DashboardMetricCards({ summary }: DashboardMetricCardsProps) {
  const styles = useStyles();

  const formatNumber = (n: number) => n.toLocaleString();

  return (
    <div className={styles.row}>
      <div className={styles.card}>
        <div className={styles.label}>Total Events</div>
        <div className={styles.value}>{formatNumber(summary.totalEvents)}</div>
      </div>
      <div className={styles.card}>
        <div className={styles.label}>Unique Processes</div>
        <div className={styles.value}>
          {formatNumber(summary.uniqueProcesses)}
        </div>
      </div>
      <div className={styles.card}>
        <div className={styles.label}>Unique Computers</div>
        <div className={styles.value}>
          {formatNumber(summary.uniqueComputers)}
        </div>
      </div>
      <div className={styles.card}>
        <div className={styles.label}>Time Range</div>
        <div className={styles.subtext}>
          {summary.earliestTimestamp
            ? `${summary.earliestTimestamp} — ${summary.latestTimestamp}`
            : "N/A"}
        </div>
      </div>
      {summary.parseErrors > 0 && (
        <div className={styles.card}>
          <div className={styles.label}>Parse Errors</div>
          <div className={styles.errorValue}>
            {formatNumber(summary.parseErrors)}
          </div>
        </div>
      )}
    </div>
  );
}
```

- [ ] **Step 2: Run TypeScript check**

Run: `npx tsc --noEmit 2>&1`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add src/components/sysmon/DashboardMetricCards.tsx
git commit -m "feat(sysmon): add DashboardMetricCards component"
```

---

## Task 10: Create `DashboardTimeline` Component

**Files:**
- Create: `src/components/sysmon/DashboardTimeline.tsx`

- [ ] **Step 1: Create the timeline chart component**

Create `src/components/sysmon/DashboardTimeline.tsx`:

```tsx
import { useState } from "react";
import {
  tokens,
  makeStyles,
  Dropdown,
  Option,
} from "@fluentui/react-components";
import { VerticalBarChart } from "@fluentui/react-charts";
import type { TimeBucket, SysmonDashboardData } from "../../types/sysmon";

const useStyles = makeStyles({
  container: {
    backgroundColor: tokens.colorNeutralBackground3,
    borderRadius: tokens.borderRadiusMedium,
    border: `1px solid ${tokens.colorNeutralStroke2}`,
    padding: "16px",
    gridColumn: "1 / -1",
  },
  header: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: "12px",
  },
  title: {
    fontSize: "14px",
    fontWeight: 600,
    color: tokens.colorNeutralForeground1,
  },
  empty: {
    fontSize: "12px",
    color: tokens.colorNeutralForeground3,
    fontStyle: "italic",
    textAlign: "center" as const,
    padding: "40px 0",
  },
});

type Granularity = "minute" | "hourly" | "daily";

const GRANULARITY_LABELS: Record<Granularity, string> = {
  minute: "Per Minute",
  hourly: "Per Hour",
  daily: "Per Day",
};

interface DashboardTimelineProps {
  dashboard: SysmonDashboardData;
}

export function DashboardTimeline({ dashboard }: DashboardTimelineProps) {
  const styles = useStyles();
  const [granularity, setGranularity] = useState<Granularity>("hourly");

  const dataMap: Record<Granularity, TimeBucket[]> = {
    minute: dashboard.timelineMinute,
    hourly: dashboard.timelineHourly,
    daily: dashboard.timelineDaily,
  };

  const buckets = dataMap[granularity];

  if (buckets.length === 0) {
    return (
      <div className={styles.container}>
        <div className={styles.header}>
          <div className={styles.title}>Event Volume Timeline</div>
        </div>
        <div className={styles.empty}>No timeline data available</div>
      </div>
    );
  }

  const chartPoints = buckets.map((b) => ({
    x: new Date(b.timestamp),
    y: b.count,
  }));

  const chartData = [
    {
      chartTitle: "Events",
      data: chartPoints,
      color: tokens.colorBrandBackground,
    },
  ];

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <div className={styles.title}>Event Volume Timeline</div>
        <Dropdown
          value={GRANULARITY_LABELS[granularity]}
          selectedOptions={[granularity]}
          onOptionSelect={(_, data) => {
            if (data.optionValue) {
              setGranularity(data.optionValue as Granularity);
            }
          }}
          style={{ minWidth: "120px" }}
        >
          <Option value="minute">Per Minute</Option>
          <Option value="hourly">Per Hour</Option>
          <Option value="daily">Per Day</Option>
        </Dropdown>
      </div>
      <div style={{ height: "250px" }}>
        <VerticalBarChart
          data={chartData}
          height={250}
          barWidth={16}
          yAxisTickCount={5}
          hideLegend
        />
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Run TypeScript check**

Run: `npx tsc --noEmit 2>&1`
Expected: PASS (may need adjustments to chart prop names based on actual `@fluentui/react-charts` API)

- [ ] **Step 3: Commit**

```bash
git add src/components/sysmon/DashboardTimeline.tsx
git commit -m "feat(sysmon): add DashboardTimeline component"
```

---

## Task 11: Create `DashboardEventTypeChart` Component

**Files:**
- Create: `src/components/sysmon/DashboardEventTypeChart.tsx`

- [ ] **Step 1: Create the donut chart component**

Create `src/components/sysmon/DashboardEventTypeChart.tsx`:

```tsx
import { tokens, makeStyles } from "@fluentui/react-components";
import { DonutChart } from "@fluentui/react-charts";
import type { SysmonSummary } from "../../types/sysmon";

const useStyles = makeStyles({
  container: {
    backgroundColor: tokens.colorNeutralBackground3,
    borderRadius: tokens.borderRadiusMedium,
    border: `1px solid ${tokens.colorNeutralStroke2}`,
    padding: "16px",
  },
  title: {
    fontSize: "14px",
    fontWeight: 600,
    marginBottom: "12px",
    color: tokens.colorNeutralForeground1,
  },
  empty: {
    fontSize: "12px",
    color: tokens.colorNeutralForeground3,
    fontStyle: "italic",
  },
});

// Fluent UI brand-adjacent palette for up to 12 slices; overflow uses gray
const SLICE_COLORS = [
  tokens.colorBrandBackground,
  tokens.colorPaletteBlueBorderActive,
  tokens.colorPaletteTealBorderActive,
  tokens.colorPaletteGreenBorderActive,
  tokens.colorPaletteMarigoldBorderActive,
  tokens.colorPalettePeachBorderActive,
  tokens.colorPalettePurpleBorderActive,
  tokens.colorPalettePinkBorderActive,
  tokens.colorPaletteLilacBorderActive,
  tokens.colorPaletteLavenderBorderActive,
  tokens.colorPaletteRedBorderActive,
  tokens.colorPaletteDarkOrangeBorderActive,
];

interface DashboardEventTypeChartProps {
  summary: SysmonSummary;
}

export function DashboardEventTypeChart({
  summary,
}: DashboardEventTypeChartProps) {
  const styles = useStyles();

  if (summary.eventTypeCounts.length === 0) {
    return (
      <div className={styles.container}>
        <div className={styles.title}>Event Type Breakdown</div>
        <div className={styles.empty}>No events</div>
      </div>
    );
  }

  const chartData = {
    chartTitle: "Event Types",
    chartData: summary.eventTypeCounts.map((tc, i) => ({
      legend: `${tc.displayName} (${tc.count})`,
      data: tc.count,
      color: SLICE_COLORS[i % SLICE_COLORS.length],
    })),
  };

  return (
    <div className={styles.container}>
      <div className={styles.title}>Event Type Breakdown</div>
      <DonutChart
        data={chartData}
        innerRadius={55}
        height={250}
        hideLegend={false}
        valueInsideDonut={summary.totalEvents.toLocaleString()}
      />
    </div>
  );
}
```

- [ ] **Step 2: Run TypeScript check**

Run: `npx tsc --noEmit 2>&1`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add src/components/sysmon/DashboardEventTypeChart.tsx
git commit -m "feat(sysmon): add DashboardEventTypeChart component"
```

---

## Task 12: Create `DashboardSecurityAlerts` Component

**Files:**
- Create: `src/components/sysmon/DashboardSecurityAlerts.tsx`

- [ ] **Step 1: Create the security alerts component**

Create `src/components/sysmon/DashboardSecurityAlerts.tsx`:

```tsx
import { tokens, makeStyles, Badge } from "@fluentui/react-components";
import type { SecuritySummary } from "../../types/sysmon";

const useStyles = makeStyles({
  container: {
    backgroundColor: tokens.colorNeutralBackground3,
    borderRadius: tokens.borderRadiusMedium,
    border: `1px solid ${tokens.colorNeutralStroke2}`,
    padding: "16px",
  },
  title: {
    fontSize: "14px",
    fontWeight: 600,
    marginBottom: "12px",
    color: tokens.colorNeutralForeground1,
  },
  metricsRow: {
    display: "flex",
    gap: "16px",
    marginBottom: "12px",
  },
  metric: {
    display: "flex",
    alignItems: "center",
    gap: "6px",
  },
  metricCount: {
    fontSize: "18px",
    fontWeight: 600,
  },
  metricLabel: {
    fontSize: "12px",
    color: tokens.colorNeutralForeground3,
  },
  table: {
    width: "100%",
    borderCollapse: "collapse" as const,
    fontSize: "12px",
  },
  th: {
    textAlign: "left" as const,
    padding: "4px 8px",
    borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
    color: tokens.colorNeutralForeground3,
    fontWeight: 600,
  },
  td: {
    padding: "4px 8px",
    borderBottom: `1px solid ${tokens.colorNeutralStroke3}`,
    color: tokens.colorNeutralForeground1,
  },
  tdRight: {
    padding: "4px 8px",
    borderBottom: `1px solid ${tokens.colorNeutralStroke3}`,
    color: tokens.colorNeutralForeground1,
    textAlign: "right" as const,
  },
  empty: {
    fontSize: "12px",
    color: tokens.colorNeutralForeground3,
    fontStyle: "italic",
  },
});

interface DashboardSecurityAlertsProps {
  securityEvents: SecuritySummary;
}

export function DashboardSecurityAlerts({
  securityEvents,
}: DashboardSecurityAlertsProps) {
  const styles = useStyles();
  const total = securityEvents.totalWarnings + securityEvents.totalErrors;

  return (
    <div className={styles.container}>
      <div className={styles.title}>Security Alerts</div>

      {total === 0 ? (
        <div className={styles.empty}>No warning or error events detected</div>
      ) : (
        <>
          <div className={styles.metricsRow}>
            <div className={styles.metric}>
              <Badge appearance="filled" color="warning">
                {securityEvents.totalWarnings}
              </Badge>
              <span className={styles.metricLabel}>Warnings</span>
            </div>
            <div className={styles.metric}>
              <Badge appearance="filled" color="danger">
                {securityEvents.totalErrors}
              </Badge>
              <span className={styles.metricLabel}>Errors</span>
            </div>
          </div>

          {securityEvents.eventsByType.length > 0 && (
            <table className={styles.table}>
              <thead>
                <tr>
                  <th className={styles.th}>Event Type</th>
                  <th className={styles.th} style={{ textAlign: "right" }}>
                    Count
                  </th>
                </tr>
              </thead>
              <tbody>
                {securityEvents.eventsByType.map((item) => (
                  <tr key={item.name}>
                    <td className={styles.td}>{item.name}</td>
                    <td className={styles.tdRight}>{item.count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
    </div>
  );
}
```

- [ ] **Step 2: Run TypeScript check**

Run: `npx tsc --noEmit 2>&1`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add src/components/sysmon/DashboardSecurityAlerts.tsx
git commit -m "feat(sysmon): add DashboardSecurityAlerts component"
```

---

## Task 13: Create `SysmonDashboardView` Container Component

**Files:**
- Create: `src/components/sysmon/SysmonDashboardView.tsx`

- [ ] **Step 1: Create the main dashboard view**

Create `src/components/sysmon/SysmonDashboardView.tsx`:

```tsx
import { tokens, makeStyles } from "@fluentui/react-components";
import { useSysmonStore } from "../../stores/sysmon-store";
import { DashboardMetricCards } from "./DashboardMetricCards";
import { DashboardTimeline } from "./DashboardTimeline";
import { DashboardEventTypeChart } from "./DashboardEventTypeChart";
import { DashboardSecurityAlerts } from "./DashboardSecurityAlerts";
import { DashboardTopList } from "./DashboardTopList";

const useStyles = makeStyles({
  container: {
    padding: "16px 24px",
    overflowY: "auto",
    height: "100%",
  },
  grid: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fit, minmax(400px, 1fr))",
    gap: "16px",
  },
  fullWidth: {
    gridColumn: "1 / -1",
  },
  empty: {
    fontSize: "12px",
    color: tokens.colorNeutralForeground3,
    fontStyle: "italic",
    padding: "40px",
    textAlign: "center" as const,
  },
});

export function SysmonDashboardView() {
  const styles = useStyles();
  const summary = useSysmonStore((s) => s.summary);
  const dashboard = useSysmonStore((s) => s.dashboard);

  if (!summary || !dashboard) {
    return <div className={styles.empty}>No dashboard data available</div>;
  }

  return (
    <div className={styles.container}>
      <DashboardMetricCards summary={summary} />

      <div className={styles.grid}>
        <DashboardTimeline dashboard={dashboard} />

        <DashboardEventTypeChart summary={summary} />
        <DashboardSecurityAlerts securityEvents={dashboard.securityEvents} />

        <DashboardTopList
          title="Top Processes"
          items={dashboard.topProcesses}
          emptyMessage="No process data"
        />
        <DashboardTopList
          title="Network Destinations"
          items={dashboard.topDestinations}
          emptyMessage="No network events"
        />

        <DashboardTopList
          title="DNS Queries"
          items={dashboard.topDnsQueries}
          emptyMessage="No DNS queries"
        />
        <DashboardTopList
          title="File Activity"
          items={dashboard.topTargetFiles}
          emptyMessage="No file events"
        />

        <DashboardTopList
          title="Top Ports"
          items={dashboard.topPorts}
          emptyMessage="No port data"
        />
        <DashboardTopList
          title="Registry Activity"
          items={dashboard.topRegistryKeys}
          emptyMessage="No registry events"
        />
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Run TypeScript check**

Run: `npx tsc --noEmit 2>&1`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add src/components/sysmon/SysmonDashboardView.tsx
git commit -m "feat(sysmon): add SysmonDashboardView container component"
```

---

## Task 14: Integrate Dashboard Tab Into `SysmonWorkspace`

**Files:**
- Modify: `src/components/sysmon/SysmonWorkspace.tsx`

- [ ] **Step 1: Add import for SysmonDashboardView**

Add to the imports section of `src/components/sysmon/SysmonWorkspace.tsx`:

```typescript
import { SysmonDashboardView } from "./SysmonDashboardView";
```

- [ ] **Step 2: Add Dashboard tab to TabList**

In the `<TabList>` component (around line 88), add the Dashboard tab as the first tab:

```tsx
<TabList
  selectedValue={activeTab}
  onTabSelect={(_, data) =>
    setActiveTab(data.value as SysmonWorkspaceTab)
  }
  size="small"
>
  <Tab value="dashboard">Dashboard</Tab>
  <Tab value="events">Events ({events.length.toLocaleString()})</Tab>
  <Tab value="summary">Summary</Tab>
  <Tab value="config">Configuration</Tab>
</TabList>
```

- [ ] **Step 3: Add Dashboard tab content rendering**

In the content area (around line 113-117), add the dashboard case:

```tsx
{activeTab === "dashboard" && <SysmonDashboardView />}
{activeTab === "events" && <SysmonEventTable />}
{activeTab === "summary" && <SysmonSummaryView />}
{activeTab === "config" && <SysmonConfigView />}
```

- [ ] **Step 4: Run TypeScript check**

Run: `npx tsc --noEmit 2>&1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/components/sysmon/SysmonWorkspace.tsx
git commit -m "feat(sysmon): integrate dashboard tab into workspace"
```

---

## Task 15: Final Verification

**Files:** None (verification only)

- [ ] **Step 1: Run full Rust verification**

Run: `cd src-tauri && cargo check && cargo test && cargo clippy -- -D warnings 2>&1`
Expected: All pass with zero warnings.

- [ ] **Step 2: Run full TypeScript verification**

Run: `npx tsc --noEmit 2>&1`
Expected: PASS

- [ ] **Step 3: Run existing frontend tests**

Run: `npx vitest run 2>&1`
Expected: All existing tests pass (ui-store.test.ts etc.)

- [ ] **Step 4: Fix any issues found**

If any checks fail, fix the issues and re-run verification.

- [ ] **Step 5: Final commit (if fixes were needed)**

```bash
git add -A
git commit -m "fix(sysmon): address dashboard verification issues"
```
