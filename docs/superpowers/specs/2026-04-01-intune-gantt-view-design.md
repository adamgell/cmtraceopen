# Intune Activity Gantt View

## Overview

Add a Gantt chart view to the Intune diagnostics Timeline tab that visualizes app activity lifecycles as swimlanes. Each app (Edge, 7-Zip, Visual C++, etc.) gets its own section showing download, install, detection, and other phases as time-positioned bars. Built using the `mermaid` npm package, rendered live in-app from the same filtered event data the list view uses.

## Motivation

The flat timeline shows every event individually. When troubleshooting "what happened to Edge's install?", users must mentally correlate scattered events across the list. A Gantt view groups all events for one app into a single swimlane, making the start-to-end lifecycle immediately visible.

## UI Integration

### Toggle Control

A segmented toggle ("List" / "Gantt") in `IntuneDashboardNavBar.tsx`, placed near the existing sort controls. Default is "List".

When Gantt is active:
- The `EventTimeline` component renders `EventGanttView` instead of the virtualized list
- All existing filter controls remain functional (event type, status, time window, file scope) — they filter events before Gantt generation
- Sort controls are hidden (Gantt is inherently time-ordered)
- Counter badges (TOTAL, SUCCESS, FAIL, etc.) still reflect filtered counts

### Store Changes

Add to `IntuneState`:
```typescript
timelineViewMode: "list" | "gantt";
setTimelineViewMode: (mode: "list" | "gantt") => void;
```

Default: `"list"`.

## Data Flow

```
filtered IntuneEvent[] → buildGanttSyntax() → Mermaid string → mermaid.render() → SVG in DOM
```

### Grouping Algorithm

1. Take filtered events array (after event type, status, time window, file scope filters)
2. Exclude events without `startTime` (cannot be positioned on time axis)
3. Group by `guid` (lowercase). Events with no GUID group by normalized `name` as fallback
4. For each group, determine section label: resolved app name from `guidRegistry` if available, otherwise event `name` with GUID suffix stripped
5. Sort sections by earliest `startTimeEpoch` (first activity first)
6. Within each section, sort events by `startTimeEpoch` ascending

### Event-to-Task Mapping

| Event field | Mermaid Gantt property |
|---|---|
| Short phase label extracted from `name` ("Download", "Install", "Detection", etc.) | Task label |
| `startTime` | Start timestamp |
| `endTime` (or `startTime + 1s` if missing) | End timestamp |
| `status === Success` | `done` style (green) |
| `status === Failed` | `crit` style (red) |
| `status === InProgress` | `active` style (blue) |
| All others (Pending, Timeout, Unknown) | Default style (gray) |

### Phase Label Extraction

Strip common prefixes from event names to get short labels:
- "AppWorkload Download Retry — Edge" → "Download Retry"
- "AppWorkload Install — Edge" → "Install"
- "Script Detection Complete — Edge" → "Script Detection Complete"
- "Win32 App — Edge" → "Win32 App"

Logic: if the name contains " — ", take the part before it. Then strip "AppWorkload " prefix if present.

### Generated Syntax Example

```
gantt
    title App Activity Timeline
    dateFormat YYYY-MM-DDTHH:mm:ss
    axisFormat %H:%M:%S

    section Microsoft Edge
    Download       :done, edge-1, 2026-04-01T14:03:04, 2026-04-01T14:03:09
    Install        :done, edge-2, 2026-04-01T14:03:09, 2026-04-01T14:03:13
    Detection      :done, edge-3, 2026-04-01T14:03:13, 2026-04-01T14:03:15

    section 7-Zip 24.09
    Download       :done, zip-1, 2026-04-01T14:03:16, 2026-04-01T14:03:18
    Install        :crit, zip-2, 2026-04-01T14:03:18, 2026-04-01T14:03:19
```

## Component Architecture

### New Files

**`src/lib/gantt-generator.ts`** — Pure function, no React dependency:
```typescript
export function buildGanttSyntax(
  events: IntuneEvent[],
  guidRegistry: Record<string, GuidRegistryEntry>
): string
```

Testable in isolation. Returns the complete Mermaid Gantt syntax string.

**`src/components/intune/EventGanttView.tsx`** — React component:
- Accepts filtered events and guidRegistry as props
- Calls `buildGanttSyntax()` to generate Mermaid syntax
- Renders via `mermaid.render()` into a ref'd div
- Re-renders when events change (debounced 300ms)
- Scrollable container (both horizontal and vertical for wide/tall diagrams)
- Detects dark/light theme from ui-store and configures Mermaid theme accordingly

### Modified Files

**`src/stores/intune-store.ts`** — Add `timelineViewMode` state + setter.

**`src/components/intune/IntuneDashboardNavBar.tsx`** — Add List/Gantt toggle button.

**`src/components/intune/EventTimeline.tsx`** — Conditionally render `EventGanttView` when `timelineViewMode === "gantt"`.

## Edge Cases

- **No events after filtering**: Show "No events match the current filters" (same as list view)
- **Events without timestamps**: Excluded from Gantt; only visible in list view
- **Events without end time**: Use `startTime + 1 second` to create a minimal visible bar
- **Large event counts (500+)**: Show a warning banner that the diagram may render slowly, with a "Switch to List" button
- **Duplicate phase names within a section**: Append counter suffix ("Install", "Install 2") — Mermaid requires unique task IDs per section
- **Theme switching**: Re-initialize Mermaid with updated theme (dark/light)
- **Special characters in app names**: Sanitize section labels — strip characters that break Mermaid syntax (colons, semicolons, newlines)

## Dependencies

**New**: `mermaid` npm package (latest stable). Adds ~200KB to the bundle.

**No backend changes.** All logic is client-side, consuming the existing `IntuneEvent[]` and `guidRegistry`.

## Out of Scope

- Click-to-select on Gantt bars (Mermaid lacks native click handler support for Gantt tasks)
- Gantt export/print functionality
- Custom zoom/pan controls
- Gantt as a separate tab (it's a toggle within the Timeline tab)
