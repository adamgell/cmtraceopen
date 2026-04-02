# Event Log Workspace — Design Spec

**Issues:** #77, #71 — EVTX Event Log viewer with cross-log comparison
**Date:** 2026-04-01

## Overview

A new workspace for viewing and cross-comparing Windows Event Logs. Supports two input modes: **live logs** queried directly from the local machine's Event Log service, and **file-based** parsing of exported `.evtx` files. Users load all available logs, then select which channels to compare in a unified timeline.

## User Flow

### Entry
User opens the Event Log workspace from the sidebar or menu.

### Source Selection
The workspace presents two source options:

**"This Computer" (Live — Windows only):**
1. Backend enumerates all event log channels on the machine via `wevtapi.dll` (`EvtOpenChannelEnum` / `EvtNextChannelPath`)
2. Frontend shows a channel picker: scrollable list with channel name, event count, last write time, log size
3. Typical machine has 300+ channels; show a search/filter box at the top
4. User checks which channels to load (common presets: "Security + Application + System", "Sysmon only")
5. Backend queries selected channels and streams events to frontend

**"Open .evtx Files" (File-based — Cross-platform):**
1. User selects one or more `.evtx` files via file picker or drag-drop
2. Backend parses each file with the `evtx` crate
3. Frontend shows discovered channels from the parsed files
4. User can add more files after initial load

### Unified Timeline
Once channels are loaded:
- All events from selected channels merge into a single timeline sorted by timestamp
- Each event shows: Timestamp, Level (icon), EventID, Channel (badge), Source/Provider, Message
- Source channel displayed as a colored badge (like Intune's source file badge)
- Virtual scrolling for 100K+ events

### Filtering
- **Channel:** Multi-select checkboxes to show/hide individual channels
- **Level:** Critical, Error, Warning, Information, Verbose (toggles)
- **EventID:** Text input for specific event IDs (comma-separated)
- **Search:** Full-text search across event messages
- **Time range:** Start/end datetime pickers

### Event Detail Pane
Clicking an event expands a detail pane showing:
- All structured fields from the event's `<EventData>` or `<UserData>` as a key-value table
- Raw XML view (collapsible)
- System metadata: Provider, EventRecordID, ProcessID, ThreadID, Computer, UserID

## Data Model

### Unified Event Record

Both live and file-based sources produce the same struct:

```rust
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvtxRecord {
    pub id: u64,                           // Sequential ID for frontend
    pub event_record_id: u64,              // Original EventRecordID
    pub timestamp: String,                 // ISO 8601 UTC
    pub timestamp_epoch: i64,              // Millis since epoch (for sorting)
    pub provider: String,                  // Provider name
    pub channel: String,                   // Channel name
    pub event_id: u32,                     // EventID
    pub level: EvtxLevel,                  // Critical/Error/Warning/Info/Verbose
    pub computer: String,                  // Computer name
    pub message: String,                   // Rendered message text
    pub event_data: Vec<EvtxField>,        // Structured key-value fields
    pub raw_xml: String,                   // Full XML for detail view
    pub source_label: String,              // "Live: Security" or "File: security.evtx"
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvtxField {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
pub enum EvtxLevel {
    Critical,    // 1
    Error,       // 2
    Warning,     // 3
    Information, // 4 (or 0)
    Verbose,     // 5
}
```

### Channel Metadata

```rust
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvtxChannelInfo {
    pub name: String,                      // e.g. "Microsoft-Windows-Sysmon/Operational"
    pub display_name: String,              // e.g. "Sysmon Operational"
    pub event_count: u64,
    pub last_write_time: Option<String>,   // ISO 8601
    pub log_size_bytes: u64,
    pub source_type: ChannelSourceType,    // Live or File
}

pub enum ChannelSourceType {
    Live,
    File { path: String },
}
```

## Backend Architecture

### Module: `src-tauri/src/evtx/`

```
evtx/
├── mod.rs              # Module declarations
├── models.rs           # EvtxRecord, EvtxChannelInfo, EvtxLevel
├── parser.rs           # File-based parsing via `evtx` crate
├── live.rs             # Live log queries via Windows Event Log API (cfg(windows))
├── commands.rs         # Tauri IPC command handlers
└── timeline.rs         # Merge + sort + deduplicate across sources
```

### File-Based Parsing (`parser.rs`)
- Uses `evtx` crate v0.11.2
- `EvtxParser::from_path()` with `records_json_value()` for structured extraction
- Wrapped in `tokio::task::spawn_blocking` (crate is synchronous)
- Streams results to frontend via Tauri event channel in batches of 500 records
- Progress events emitted: `evtx-parse-progress { file, recordsParsed, totalEstimate }`

### Live Log Queries (`live.rs`)
- Windows-only: `#[cfg(target_os = "windows")]`
- Uses `windows` crate bindings to `wevtapi.dll`:
  - `EvtOpenChannelEnum` + `EvtNextChannelPath` — enumerate channels
  - `EvtQuery` — query events from a channel with optional XPath filter
  - `EvtNext` — iterate results
  - `EvtRender` — render event to XML
  - `EvtGetChannelConfigProperty` — get channel metadata (size, count, last write)
- Queries run on a blocking thread pool
- Results streamed in batches like file parsing
- Admin elevation may be needed for Security log — detect and inform user

### Tauri Commands (`commands.rs`)

| Command | Input | Output | Platform |
|---------|-------|--------|----------|
| `evtx_enumerate_channels` | — | `Vec<EvtxChannelInfo>` | Windows |
| `evtx_query_channels` | `channels: Vec<String>, maxEvents: Option<u64>` | Streams `EvtxRecord` batches | Windows |
| `evtx_parse_files` | `paths: Vec<String>` | Streams `EvtxRecord` batches | All |
| `evtx_get_channel_presets` | — | `Vec<ChannelPreset>` | All |

### Timeline Merge (`timeline.rs`)
- Takes events from multiple sources (live + file)
- Sorts by `timestamp_epoch` globally
- Assigns sequential IDs
- Same pattern as `intune/timeline.rs::build_timeline()`

## Frontend Architecture

### Store: `src/stores/evtx-store.ts`

```typescript
interface EvtxState {
  // Data
  records: EvtxRecord[];
  channels: EvtxChannelInfo[];
  
  // Source state
  sourceMode: "none" | "live" | "file" | "mixed";
  isLoading: boolean;
  loadProgress: { channel: string; parsed: number; total: number } | null;
  
  // Filters
  selectedChannels: Set<string>;
  filterLevel: Set<EvtxLevel>;
  filterEventIds: string;        // comma-separated
  filterSearch: string;
  filterTimeStart: number | null;
  filterTimeEnd: number | null;
  
  // Sort
  sortField: "time" | "level" | "eventId" | "channel" | "message";
  sortDirection: "asc" | "desc";
  
  // Selection
  selectedRecordId: number | null;
  
  // Actions
  loadLiveChannels: () => Promise<void>;
  queryChannels: (channels: string[]) => Promise<void>;
  parseFiles: (paths: string[]) => Promise<void>;
  addMoreFiles: (paths: string[]) => Promise<void>;
  toggleChannel: (channel: string) => void;
  // ... filter/sort setters
}
```

### Components: `src/components/evtx/`

```
evtx/
├── EvtxWorkspace.tsx          # Main workspace layout
├── SourcePicker.tsx           # "This Computer" vs "Open Files" initial view
├── ChannelPicker.tsx          # Channel list with checkboxes, search, presets
├── EvtxTimeline.tsx           # Virtual-scrolled event list (reuses EventTimeline patterns)
├── EvtxTimelineRow.tsx        # Individual event row with level icon + channel badge
├── EvtxDetailPane.tsx         # Event detail: structured fields + raw XML
└── EvtxFilterBar.tsx          # Level toggles, EventID input, search, time range
```

### Channel Presets
Pre-defined channel groups for quick selection:

| Preset | Channels |
|--------|----------|
| Core Windows | Security, Application, System |
| Sysmon | Microsoft-Windows-Sysmon/Operational |
| PowerShell | Microsoft-Windows-PowerShell/Operational, PowerShellCore/Operational |
| Task Scheduler | Microsoft-Windows-TaskScheduler/Operational |
| All Selected | Toggle all discovered channels |

## Workspace Integration

- Register `"evtx"` workspace in `src-tauri/src/commands/app_config.rs`
- Gate behind a Cargo feature flag: `evtx-viewer` (enabled by default)
- Add sidebar icon and workspace tab in `AppShell.tsx`
- Support `.evtx` file association — opening an `.evtx` file switches to this workspace

## Platform Behavior

| Capability | Windows | macOS/Linux |
|-----------|---------|-------------|
| Live log enumeration | Yes | No (hidden) |
| Live log querying | Yes | No (hidden) |
| .evtx file parsing | Yes | Yes |
| Channel presets | Full list | File-only presets |

On non-Windows platforms, the "This Computer" option is hidden. Only file-based parsing is available.

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `evtx` | 0.11.2 | EVTX file parsing |
| `windows` | (already in use) | Live Event Log API bindings |

The `evtx` crate is the only new dependency. The `windows` crate is already used for other Windows-specific features.

## Verification

1. **File parsing:** Open a `.evtx` file → events display in timeline with correct timestamps, levels, messages
2. **Multi-file:** Open 3 `.evtx` files → events interleave by timestamp across files
3. **Live logs (Windows):** Click "This Computer" → channels enumerate → select Security → events load
4. **Cross-compare:** Load live Security + file-based Sysmon → unified timeline shows both with channel badges
5. **Filtering:** Toggle level filters → events filter immediately. Search text → matches highlight.
6. **Performance:** Load 100K+ events → virtual scrolling remains smooth
7. **Detail pane:** Click event → structured fields and raw XML display correctly
8. **macOS/Linux:** "This Computer" option is hidden. File parsing works.
