# Quick Stats Panel — Technical Design

## Problem

When viewing large CMTrace logs in CMTrace Open, users lack immediate visibility into:
- **Total line count** (especially valuable when filtering)
- **Error/Warning/Info distribution** across the log
- **Time range** (earliest to latest timestamp)
- **Top error codes** without manual scanning or repeated lookups

This forces users to manually scan or use filters repeatedly to understand log characteristics, which is inefficient for log analysis workflows.

## Constraints

| Constraint | Details |
|------------|---------|
| **Tech Stack** | React 19 + TypeScript (frontend), Rust + Tauri 2 (backend), Fluent UI v9 |
| **State Management** | Zustand stores (`src/stores/`). No React Context for app state. |
| **Real-time Updates** | Must update when logs are filtered or when tailing incoming lines |
| **Performance** | Should not block UI when processing 10K+ logs |
| **Platform** | Cross-platform (Windows, macOS, Linux) — no Windows-specific APIs |
| **Design** | Fluent UI v9 components only; must match existing app aesthetic |
| **Architecture** | Read-only — consumes existing parser data from stores, no new IPC needed |

## Proposed Approach

### Architecture

The Quick Stats Panel is a **read-only, reactive component** that:
1. Listens to the existing `logStore` (filtered logs, line count, timestamps)
2. Computes aggregated stats on the frontend using existing `LogEntry` data
3. Displays in a compact, collapsible horizontal panel below the toolbar

### Data Flow

```mermaid
graph LR
    A[LogFile opened] --> B[Rust Parser]
    B --> C[parsed LogEntry[]]
    C --> D[logStore state]
    D --> E[QuickStatsPanel subscribes]
    E --> F[Computes stats: counts, time range, top codes]
    F --> G[Render panel]
    H[User applies filter] --> D
    I[Tail mode: new lines] --> B
```

### Component Structure

```
src/components/panels/
  └─ QuickStatsPanel.tsx          # Main container
src/components/panels/quick-stats/
  ├─ StatCard.tsx                 # Reusable stat display card
  ├─ ErrorCodeList.tsx            # Top error codes list
  └─ TimeRangeBadge.tsx           # Timestamp range display
```

### State Logic

All computation happens in **front-end derived state**:

```ts
// src/stores/log-store.ts or src/hooks/use-quick-stats.ts
export function useQuickStats() {
  const filteredLogs = useLogStore((s) => s.filteredLogs);
  const totalCount = useLogStore((s) => s.totalLineCount);

  return useMemo(() => {
    // Compute: error/warning/info counts
    // Compute: min/max timestamps
    // Compute: top N error codes
  }, [filteredLogs, totalCount]);
}
```

**Why derived state?**
- No new IPC commands needed
- Updates reactively when filters change
- No backend load (all data already in memory)
- Simpler to test and debug

### UI Layout

The panel appears as a **collapsible row** between the toolbar and the main log view:

```
┌───────────────────────────────────────────────────────────┐
│ [Toolbar: Open, Filter, Find, Tail Mode, ...]            │
├───────────────────────────────────────────────────────────┤
│ ▶ Quick Stats  | Total: 12,453 | Errors: 127 | Warnings: 45    │
│   ┌────────┐ ┌────────┐ ┌────────┐                        │
│   │ Errors │ │Warnings│ │  Info  │                        │
│   │  127   │ │   45   │ │  8,942 │                        │
│   └────────┘ └────────┘ └────────┘                        │
│   Top Errors: 0x80070002 (12), 0xC10300E1 (8)             │
│   Time Range: 2024-01-15 08:23 → 2024-01-15 14:47          │
├───────────────────────────────────────────────────────────┤
│ [Main Log View - Virtual Scrolling]                       │
│  [LogEntry 1]  │ 08:23:41 │ Info │ ccmexec.log            │
│  [LogEntry 2]  │ 08:23:45 │ Error│ 0x80070002             │
└───────────────────────────────────────────────────────────┘
```

**Behavior:**
- Collapsible (expand/collapse toggle)
- Persist collapse state to user settings
- Click on an error code opens the Error Lookup dialog

### Error Code Aggregation Strategy

For performance with 10K+ logs:
- Use a JavaScript `Map<string, number>` to count error codes
- Limit top codes to top 5–10 (configurable)
- Skip if no error codes present

```ts
const errorCounts = new Map<string, number>();
logs.forEach((log) => {
  if (log.level === 'error' && log.errorCode) {
    errorCounts.set(log.errorCode, (errorCounts.get(log.errorCode) || 0) + 1);
  }
});
const topErrors = Array.from(errorCounts.entries())
  .sort((a, b) => b[1] - a[1])
  .slice(0, 5);
```

## Alternatives Considered

| Alternative | Pros | Cons | Rejected Because |
|-------------|------|------|------------------|
| **Backend computation** | Centralized logic, offloads frontend | Requires new IPC commands, slower updates, more Rust code | All data already in memory; derived state is simpler and faster |
| **Side-by-side sidebar** | More room for details | Takes permanent vertical space, inconsistent with current layout | Horizontal collapsible panel is less intrusive and fits existing UX |
| **Status bar only** | Minimal UI footprint | Too cramped for multiple metrics | Need room for error codes and time range |
| **Modal stats view** | Full details on demand | Extra click, interrupts workflow | Inline panel is always visible, context-aware |

## Implementation Plan

### Phase 1: Core Infrastructure (1–2 hours)

**Scope:** 2–3 files

| File | Changes |
|------|---------|
| `src/hooks/use-quick-stats.ts` | Hook to compute stats from store data |
| `src/components/panels/QuickStatsPanel.tsx` | Main panel skeleton, collapse logic |
| `src/components/panels/quick-stats/StatCard.tsx` | Reusable stat card component |

**Deliverables:**
- Panel renders with hardcoded data (verify layout)
- Collapse/expand works
- Hook returns correct shape (verified with mock data)

**Verification:**
```bash
npx tsc --noEmit
cargo clippy -- -D warnings
```

---

### Phase 2: Real Data Integration (2–3 hours)

**Scope:** 2–3 files

| File | Changes |
|------|---------|
| `src/hooks/use-quick-stats.ts` | Wire to `logStore` state |
| `src/components/panels/QuickStatsPanel.tsx` | Replace hardcoded data with real stats |
| `src/components/panels/quick-stats/ErrorCard.tsx` | Error code list with click → lookup |

**Deliverables:**
- Panel updates when log is opened
- Panel updates when filter is applied
- Click on error code opens Error Lookup dialog

**Verification:**
- Open test log file → stats display correctly
- Apply filter → stats update
- Click error code → dialog opens with correct code

---

### Phase 3: Polish & Persistence (1–2 hours)

**Scope:** 2–3 files

| File | Changes |
|------|---------|
| `src/components/panels/QuickStatsPanel.tsx` | Persist collapse state to settings |
| `src/stores/settings-store.ts` | Add `quickStatsPanelExpanded` setting |
| `src/components/panels/quick-stats/TimeRangeBadge.tsx` | Pretty timestamp formatting |

**Deliverables:**
- Expand/collapse state persists across app restarts
- Time range formatted nicely (e.g., "08:23 → 14:47")
- Responsive design (panel doesn't overflow on small screens)

**Verification:**
- Toggle expand/collapse → restart app → state persists
- Load log at end of day → time range shows correctly
- Resize window → panel responds gracefully

---

### Phase 4: Testing & Bug Fixes (1–2 hours)

**Scope:** 1–3 files

| File | Changes |
|------|---------|
| `src/hooks/__tests__/use-quick-stats.test.ts` | Unit tests for derived state logic |
| `src/components/panels/__tests__/QuickStatsPanel.test.tsx` | Component snapshot/integration tests |
| `src/components/panels/quick-stats/` | Fix any bugs discovered in Phases 1–3 |

**Deliverables:**
- All new code has test coverage for edge cases (empty log, no errors, etc.)
- No TypeScript errors
- No ESLint warnings

**Verification:**
```bash
npm test  # Run Jest tests
npx tsc --noEmit
cargo test
```

---

### Phase 5: Manual QA & Documentation (30 min–1 hour)

**Scope:** No code changes

| Task | Verification |
|------|--------------|
| Open 10K-line log | Stats render in <100ms |
| Apply narrow filter | Stats update instantly |
| Enable tail mode | Stats update as new lines arrive |
| Load log with no errors | "No errors" message displays |
| Load log with single error type | Top errors shows 1 entry |
| Switch tabs/panels | Stats panel doesn't interfere with other views |

**Documentation:**
- Add usage note to `.clairvoyance/Docs/architecture.md` (optional)
- Update `CHANGELOG.md` under `[Unreleased] → Added`

## Open Questions

| Question | Impact | Decision Needed From |
|----------|--------|---------------------|
| **Should the panel show stats for filtered or total logs?** | Affects UX clarity | User |
| *Suggestion:* Show both: "Total: 12,453 (Filtered: 127)" | | |
| **Max number of top error codes to display?** | Affects panel width/crowding | User |
| *Suggestion:* Default to 5, expandable on click | | |
| **Should the panel auto-collapse if no logs are open?** | Affects layout simplicity | User |
| **Should we persist per-log settings (e.g., last expanded log)?** | Complexity vs. convenience | User |

## Verification Criteria

The feature is **done** when:
- [x] Panel displays accurate counts for error/warning/info levels
- [x] Panel displays correct time range (min/max timestamps)
- [x] Panel displays top 5 error codes with counts
- [x] Click on error code opens Error Lookup dialog
- [x] Panel updates reactively when filters are applied
- [x] Panel persists expand/collapse state across app restarts
- [x] All verification commands pass (`npx tsc --noEmit`, `cargo clippy`, tests)
- [x] No TypeScript or ESLint errors
- [x] Performance: Stats compute in <100ms for 10K logs

## Next Steps

1. **User decides** on open questions above (especially: filtered vs. total stats display)
2. **I start Phase 1** if approved → deliver `use-quick-stats.ts` + panel skeleton
3. **You review** Phase 1 output → approve → move to Phase 2
4. **Repeat** until complete

Ready when you are — just say "let's build this" and confirm your preferences on the open questions!
