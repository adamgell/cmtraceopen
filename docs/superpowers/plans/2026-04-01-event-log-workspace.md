# Event Log Workspace — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a new workspace for viewing and cross-comparing Windows Event Logs — both live logs from the local machine and exported `.evtx` files. Users load all available logs, select which channels to compare, and see events in a unified timeline.

**Architecture:** Backend adds a new `event_log/` module with two data sources: file-based parsing via the `evtx` crate (already a dependency) and live querying via `wevtapi.dll` (Windows only). Both sources produce the same `EvtxRecord` struct. Frontend adds a new Zustand store, workspace component, and registers the workspace following the existing pattern (Cargo feature flag → `get_available_workspaces` → `WorkspaceId` → `AppShell` routing).

**Tech Stack:** Rust (`evtx` crate, `windows` crate), React, TypeScript, Zustand, Tauri v2 event channels, TanStack Virtual

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| **Backend** | | |
| `src-tauri/Cargo.toml` | Modify | Add `event-log` feature flag |
| `src-tauri/src/lib.rs` | Modify | Register `event_log` module and commands |
| `src-tauri/src/commands/app_config.rs` | Modify | Add `event-log` to workspace list |
| `src-tauri/src/event_log/mod.rs` | Create | Module declarations |
| `src-tauri/src/event_log/models.rs` | Create | `EvtxRecord`, `EvtxChannelInfo`, `EvtxLevel` types |
| `src-tauri/src/event_log/parser.rs` | Create | File-based `.evtx` parsing via `evtx` crate |
| `src-tauri/src/event_log/live.rs` | Create | Live Windows Event Log API queries (Windows only) |
| `src-tauri/src/event_log/commands.rs` | Create | Tauri IPC command handlers |
| **Frontend** | | |
| `src/types/log.ts` | Modify | Add `"event-log"` to `WorkspaceId` |
| `src/types/event-log-workspace.ts` | Create | TypeScript types for `EvtxRecord`, `EvtxChannelInfo` |
| `src/stores/evtx-store.ts` | Create | Zustand store for event log workspace |
| `src/stores/ui-store.ts` | Modify | Add `event-log` to platform map and labels |
| `src/components/layout/Toolbar.tsx` | Modify | Add `event-log` label and handler |
| `src/components/layout/AppShell.tsx` | Modify | Add workspace rendering case |
| `src/components/event-log-workspace/EventLogWorkspace.tsx` | Create | Main workspace layout |
| `src/components/event-log-workspace/SourcePicker.tsx` | Create | "This Computer" vs "Open Files" |
| `src/components/event-log-workspace/ChannelPicker.tsx` | Create | Channel list with checkboxes and search |
| `src/components/event-log-workspace/EvtxTimeline.tsx` | Create | Virtual-scrolled event list |
| `src/components/event-log-workspace/EvtxTimelineRow.tsx` | Create | Individual event row |
| `src/components/event-log-workspace/EvtxDetailPane.tsx` | Create | Event detail: fields + raw XML |
| `src/components/event-log-workspace/EvtxFilterBar.tsx` | Create | Level toggles, EventID, search |

---

### Task 1: Add Cargo feature flag and backend module skeleton

**Files:**
- Modify: `src-tauri/Cargo.toml`
- Modify: `src-tauri/src/lib.rs`
- Modify: `src-tauri/src/commands/app_config.rs`
- Create: `src-tauri/src/event_log/mod.rs`

- [ ] **Step 1: Add feature flag to Cargo.toml**

In `src-tauri/Cargo.toml`, add to the `[features]` section:

```toml
event-log = ["dep:evtx"]
```

Add `"event-log"` to the `full` feature list:

```toml
full = ["collector", "deployment", "dsregcmd", "event-log", "intune-diagnostics", "macos-diag"]
```

- [ ] **Step 2: Create module skeleton**

Create `src-tauri/src/event_log/mod.rs`:

```rust
pub mod commands;
pub mod models;
pub mod parser;

#[cfg(target_os = "windows")]
pub mod live;
```

- [ ] **Step 3: Register module in lib.rs**

In `src-tauri/src/lib.rs`, add after the existing module declarations:

```rust
#[cfg(feature = "event-log")]
pub mod event_log;
```

- [ ] **Step 4: Add to workspace list**

In `src-tauri/src/commands/app_config.rs`, add before the closing of `get_available_workspaces`:

```rust
    if cfg!(feature = "event-log") {
        workspaces.push("event-log");
    }
```

- [ ] **Step 5: Run cargo check (expect failures — modules are empty)**

Run: `cd src-tauri && cargo check`
Expected: FAIL — empty module files. We'll create them next.

- [ ] **Step 6: Commit**

```bash
git add src-tauri/Cargo.toml src-tauri/src/lib.rs src-tauri/src/commands/app_config.rs src-tauri/src/event_log/mod.rs
git commit -m "feat(event-log): add feature flag and module skeleton"
```

---

### Task 2: Define backend data models

**Files:**
- Create: `src-tauri/src/event_log/models.rs`

- [ ] **Step 1: Create the models file**

Create `src-tauri/src/event_log/models.rs`:

```rust
use serde::{Deserialize, Serialize};

/// A single event record from either a live query or parsed .evtx file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvtxRecord {
    /// Sequential ID assigned after merging/sorting (for frontend virtual list)
    pub id: u64,
    /// Original EventRecordID from the EVTX source
    pub event_record_id: u64,
    /// UTC timestamp as ISO 8601 string
    pub timestamp: String,
    /// Milliseconds since Unix epoch (for fast frontend sorting)
    pub timestamp_epoch: i64,
    /// Provider/source name (e.g. "Microsoft-Windows-Security-Auditing")
    pub provider: String,
    /// Channel name (e.g. "Security", "Application")
    pub channel: String,
    /// EventID number
    pub event_id: u32,
    /// Severity level
    pub level: EvtxLevel,
    /// Computer name from the event
    pub computer: String,
    /// Rendered message text (first 2000 chars)
    pub message: String,
    /// Structured key-value fields from EventData/UserData
    pub event_data: Vec<EvtxField>,
    /// Full XML for detail view
    pub raw_xml: String,
    /// Label identifying the source: "Live: Security" or "File: security.evtx"
    pub source_label: String,
}

/// A single key-value field from EventData.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvtxField {
    pub name: String,
    pub value: String,
}

/// Event severity level, matching Windows Event Log levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvtxLevel {
    Critical,    // 1
    Error,       // 2
    Warning,     // 3
    Information, // 4 (or 0)
    Verbose,     // 5
}

impl EvtxLevel {
    pub fn from_level_value(level: u8) -> Self {
        match level {
            1 => Self::Critical,
            2 => Self::Error,
            3 => Self::Warning,
            5 => Self::Verbose,
            _ => Self::Information, // 0 and 4 both map to Information
        }
    }
}

/// Metadata about a discovered event log channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvtxChannelInfo {
    /// Channel path (e.g. "Microsoft-Windows-Sysmon/Operational")
    pub name: String,
    /// Estimated event count
    pub event_count: u64,
    /// Source type
    pub source_type: ChannelSourceType,
}

/// Whether a channel comes from a live query or a file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ChannelSourceType {
    Live,
    File { path: String },
}

/// Result of parsing one or more .evtx files.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvtxParseResult {
    pub records: Vec<EvtxRecord>,
    pub channels: Vec<EvtxChannelInfo>,
    pub total_records: u64,
    pub parse_errors: u32,
}
```

- [ ] **Step 2: Run cargo check**

Run: `cd src-tauri && cargo check`
Expected: May still fail on missing modules. Models themselves should compile.

- [ ] **Step 3: Commit**

```bash
git add src-tauri/src/event_log/models.rs
git commit -m "feat(event-log): define EvtxRecord, EvtxChannelInfo, EvtxLevel models"
```

---

### Task 3: Implement file-based EVTX parser

**Files:**
- Create: `src-tauri/src/event_log/parser.rs`

- [ ] **Step 1: Create the parser**

Create `src-tauri/src/event_log/parser.rs`:

```rust
use std::collections::HashMap;
use std::path::Path;

use evtx::EvtxParser;
use serde_json::Value;

use super::models::{ChannelSourceType, EvtxChannelInfo, EvtxField, EvtxLevel, EvtxParseResult, EvtxRecord};

/// Parse one or more .evtx files and return a unified result.
pub fn parse_evtx_files(paths: &[String]) -> Result<EvtxParseResult, String> {
    let mut all_records = Vec::new();
    let mut channel_counts: HashMap<String, u64> = HashMap::new();
    let mut parse_errors = 0u32;

    for path in paths {
        let file_name = Path::new(path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| path.clone());

        let mut parser = EvtxParser::from_path(path)
            .map_err(|e| format!("Failed to open {}: {}", path, e))?;

        for record in parser.records_json_value() {
            match record {
                Ok(record) => {
                    if let Some(evt) = extract_record(&record.data, &file_name) {
                        *channel_counts.entry(evt.channel.clone()).or_default() += 1;
                        all_records.push(evt);
                    }
                }
                Err(_) => {
                    parse_errors += 1;
                }
            }
        }
    }

    // Sort all records by timestamp
    all_records.sort_by_key(|r| r.timestamp_epoch);

    // Reassign sequential IDs
    for (i, record) in all_records.iter_mut().enumerate() {
        record.id = i as u64;
    }

    let total_records = all_records.len() as u64;

    let channels = channel_counts
        .into_iter()
        .map(|(name, count)| EvtxChannelInfo {
            name,
            event_count: count,
            source_type: ChannelSourceType::File {
                path: paths.first().cloned().unwrap_or_default(),
            },
        })
        .collect();

    Ok(EvtxParseResult {
        records: all_records,
        channels,
        total_records,
        parse_errors,
    })
}

/// Extract an EvtxRecord from the JSON value produced by the evtx crate.
fn extract_record(data: &Value, source_file: &str) -> Option<EvtxRecord> {
    let event = data.get("Event")?;
    let system = event.get("System")?;

    let provider = system
        .get("Provider")
        .and_then(|p| p.get("#attributes"))
        .and_then(|a| a.get("Name"))
        .and_then(|n| n.as_str())
        .unwrap_or("Unknown")
        .to_string();

    let channel = system
        .get("Channel")
        .and_then(|c| c.as_str())
        .unwrap_or("Unknown")
        .to_string();

    let event_id = system
        .get("EventID")
        .and_then(|e| {
            // EventID can be a number or an object with #text
            e.as_u64().or_else(|| {
                e.get("#text").and_then(|t| t.as_u64())
            })
        })
        .unwrap_or(0) as u32;

    let level = system
        .get("Level")
        .and_then(|l| l.as_u64())
        .unwrap_or(4) as u8;

    let computer = system
        .get("Computer")
        .and_then(|c| c.as_str())
        .unwrap_or("")
        .to_string();

    let event_record_id = system
        .get("EventRecordID")
        .and_then(|e| e.as_u64())
        .unwrap_or(0);

    let timestamp = system
        .get("TimeCreated")
        .and_then(|t| t.get("#attributes"))
        .and_then(|a| a.get("SystemTime"))
        .and_then(|s| s.as_str())
        .unwrap_or("")
        .to_string();

    let timestamp_epoch = chrono::DateTime::parse_from_rfc3339(&timestamp)
        .map(|dt| dt.timestamp_millis())
        .unwrap_or(0);

    // Extract EventData fields
    let event_data = extract_event_data(event);

    // Build message from EventData values
    let message = event_data
        .iter()
        .take(5)
        .map(|f| format!("{}: {}", f.name, f.value))
        .collect::<Vec<_>>()
        .join("; ");

    let raw_xml = serde_json::to_string_pretty(data).unwrap_or_default();

    Some(EvtxRecord {
        id: 0, // Will be reassigned after sorting
        event_record_id,
        timestamp,
        timestamp_epoch,
        provider,
        channel,
        event_id,
        level: EvtxLevel::from_level_value(level),
        computer,
        message,
        event_data,
        raw_xml,
        source_label: format!("File: {}", source_file),
    })
}

/// Extract key-value fields from EventData or UserData.
fn extract_event_data(event: &Value) -> Vec<EvtxField> {
    let mut fields = Vec::new();

    let data_section = event
        .get("EventData")
        .or_else(|| event.get("UserData"));

    if let Some(data) = data_section {
        if let Some(obj) = data.as_object() {
            for (key, value) in obj {
                if key == "#attributes" {
                    continue;
                }
                let val = match value {
                    Value::String(s) => s.clone(),
                    Value::Null => String::new(),
                    other => other.to_string(),
                };
                fields.push(EvtxField {
                    name: key.clone(),
                    value: val,
                });
            }
        }
    }

    fields
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evtx_level_from_value() {
        assert_eq!(EvtxLevel::from_level_value(1), EvtxLevel::Critical);
        assert_eq!(EvtxLevel::from_level_value(2), EvtxLevel::Error);
        assert_eq!(EvtxLevel::from_level_value(3), EvtxLevel::Warning);
        assert_eq!(EvtxLevel::from_level_value(4), EvtxLevel::Information);
        assert_eq!(EvtxLevel::from_level_value(5), EvtxLevel::Verbose);
        assert_eq!(EvtxLevel::from_level_value(0), EvtxLevel::Information);
    }
}
```

- [ ] **Step 2: Run cargo check**

Run: `cd src-tauri && cargo check`
Expected: May still need commands.rs stub. Parser itself should compile.

- [ ] **Step 3: Commit**

```bash
git add src-tauri/src/event_log/parser.rs
git commit -m "feat(event-log): implement file-based EVTX parser"
```

---

### Task 4: Implement live Windows Event Log queries

**Files:**
- Create: `src-tauri/src/event_log/live.rs`

- [ ] **Step 1: Create the live query module**

Create `src-tauri/src/event_log/live.rs`:

```rust
//! Live Windows Event Log queries via wevtapi.dll.
//! This module is only compiled on Windows (`#[cfg(target_os = "windows")]`).

use std::collections::HashMap;

use windows::core::PCWSTR;
use windows::Win32::System::EventLog::{
    EvtClose, EvtNext, EvtOpenChannelEnum, EvtNextChannelPath,
    EvtQuery, EvtRender, EvtQueryChannelPath, EvtRenderEventXml,
    EVT_HANDLE,
};

use super::models::{ChannelSourceType, EvtxChannelInfo, EvtxRecord};

/// Enumerate all event log channels on the local machine.
pub fn enumerate_channels() -> Result<Vec<EvtxChannelInfo>, String> {
    let mut channels = Vec::new();

    unsafe {
        let handle = EvtOpenChannelEnum(None, 0)
            .map_err(|e| format!("EvtOpenChannelEnum failed: {}", e))?;

        let mut buffer = vec![0u16; 512];
        let mut used = 0u32;

        loop {
            match EvtNextChannelPath(handle, &mut buffer, &mut used) {
                Ok(()) => {
                    let name = String::from_utf16_lossy(&buffer[..used as usize - 1]);
                    channels.push(EvtxChannelInfo {
                        name,
                        event_count: 0, // Would need EvtGetChannelConfigProperty for real count
                        source_type: ChannelSourceType::Live,
                    });
                }
                Err(_) => break,
            }
        }

        let _ = EvtClose(handle);
    }

    // Sort by channel name for consistent display
    channels.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(channels)
}

/// Query events from a specific channel.
pub fn query_channel(
    channel: &str,
    max_events: Option<u64>,
) -> Result<Vec<EvtxRecord>, String> {
    let mut records = Vec::new();
    let channel_wide: Vec<u16> = channel.encode_utf16().chain(std::iter::once(0)).collect();
    let query_wide: Vec<u16> = "*".encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        let query_handle = EvtQuery(
            None,
            PCWSTR(channel_wide.as_ptr()),
            PCWSTR(query_wide.as_ptr()),
            EvtQueryChannelPath.0 as u32,
        )
        .map_err(|e| format!("EvtQuery failed for {}: {}", channel, e))?;

        let mut event_handles = vec![EVT_HANDLE::default(); 100];
        let mut returned = 0u32;
        let max = max_events.unwrap_or(u64::MAX);

        loop {
            if records.len() as u64 >= max {
                break;
            }

            let batch_size = std::cmp::min(event_handles.len(), (max - records.len() as u64) as usize);

            match EvtNext(
                query_handle,
                &mut event_handles[..batch_size],
                1000, // 1 second timeout
                0,
                &mut returned,
            ) {
                Ok(()) => {
                    for i in 0..returned as usize {
                        if let Ok(xml) = render_event_xml(event_handles[i]) {
                            if let Some(record) = parse_xml_to_record(&xml, channel) {
                                records.push(record);
                            }
                        }
                        let _ = EvtClose(event_handles[i]);
                    }
                }
                Err(_) => break,
            }
        }

        let _ = EvtClose(query_handle);
    }

    Ok(records)
}

/// Render an event handle to XML string.
unsafe fn render_event_xml(event: EVT_HANDLE) -> Result<String, String> {
    let mut buffer_size = 0u32;
    let mut property_count = 0u32;

    // First call to get required buffer size
    let _ = EvtRender(
        None,
        event,
        EvtRenderEventXml.0 as u32,
        0,
        None,
        &mut buffer_size,
        &mut property_count,
    );

    let mut buffer = vec![0u16; buffer_size as usize / 2 + 1];

    EvtRender(
        None,
        event,
        EvtRenderEventXml.0 as u32,
        buffer_size,
        Some(buffer.as_mut_ptr().cast()),
        &mut buffer_size,
        &mut property_count,
    )
    .map_err(|e| format!("EvtRender failed: {}", e))?;

    Ok(String::from_utf16_lossy(&buffer[..buffer_size as usize / 2]))
}

/// Parse a rendered XML event string into an EvtxRecord.
/// This is a simplified parser — for production, consider using quick-xml.
fn parse_xml_to_record(xml: &str, channel: &str) -> Option<EvtxRecord> {
    // Extract key fields from XML using simple string searching
    // In production, use quick-xml or similar for robust parsing
    let provider = extract_xml_attr(xml, "Provider", "Name")?;
    let event_id: u32 = extract_xml_text(xml, "EventID")?.parse().ok()?;
    let level: u8 = extract_xml_text(xml, "Level")?.parse().unwrap_or(4);
    let computer = extract_xml_text(xml, "Computer").unwrap_or_default();
    let event_record_id: u64 = extract_xml_text(xml, "EventRecordID")?.parse().ok()?;
    let timestamp = extract_xml_attr(xml, "TimeCreated", "SystemTime").unwrap_or_default();

    let timestamp_epoch = chrono::DateTime::parse_from_rfc3339(&timestamp)
        .map(|dt| dt.timestamp_millis())
        .unwrap_or(0);

    // Extract EventData fields
    let event_data = extract_xml_event_data(xml);
    let message = event_data
        .iter()
        .take(5)
        .map(|f| format!("{}: {}", f.name, f.value))
        .collect::<Vec<_>>()
        .join("; ");

    Some(EvtxRecord {
        id: 0,
        event_record_id,
        timestamp,
        timestamp_epoch,
        provider,
        channel: channel.to_string(),
        event_id,
        level: super::models::EvtxLevel::from_level_value(level),
        computer,
        message,
        event_data,
        raw_xml: xml.to_string(),
        source_label: format!("Live: {}", channel),
    })
}

fn extract_xml_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}", tag);
    let close = format!("</{}>", tag);
    let start = xml.find(&open)?;
    let content_start = xml[start..].find('>')? + start + 1;
    let end = xml[content_start..].find(&close)? + content_start;
    Some(xml[content_start..end].to_string())
}

fn extract_xml_attr(xml: &str, tag: &str, attr: &str) -> Option<String> {
    let tag_start = xml.find(&format!("<{}", tag))?;
    let tag_end = xml[tag_start..].find('>')? + tag_start;
    let tag_content = &xml[tag_start..tag_end];
    let attr_start = tag_content.find(&format!("{}='", attr))
        .or_else(|| tag_content.find(&format!("{}=\"", attr)))?;
    let value_start = attr_start + attr.len() + 2; // skip attr='
    let quote = tag_content.as_bytes()[attr_start + attr.len() + 1] as char;
    let value_end = tag_content[value_start..].find(quote)? + value_start;
    Some(tag_content[value_start..value_end].to_string())
}

fn extract_xml_event_data(xml: &str) -> Vec<super::models::EvtxField> {
    let mut fields = Vec::new();
    let data_pattern = "<Data Name='";
    let mut search_from = 0;

    while let Some(start) = xml[search_from..].find(data_pattern) {
        let abs_start = search_from + start + data_pattern.len();
        if let Some(name_end) = xml[abs_start..].find('\'') {
            let name = xml[abs_start..abs_start + name_end].to_string();
            let value_start = abs_start + name_end + 2; // skip '>
            if let Some(value_end) = xml[value_start..].find("</Data>") {
                let value = xml[value_start..value_start + value_end].to_string();
                fields.push(super::models::EvtxField { name, value });
                search_from = value_start + value_end;
            } else {
                break;
            }
        } else {
            break;
        }
    }

    fields
}
```

Note: The `windows` crate bindings for `wevtapi.dll` may require specific feature flags in the `windows` crate dependency. Check the existing `windows` dependency in `Cargo.toml` and add `"Win32_System_EventLog"` to its features if not present.

- [ ] **Step 2: Run cargo check (Windows only)**

Run: `cd src-tauri && cargo check`
Expected: PASS on Windows, skipped on macOS/Linux via `#[cfg(target_os = "windows")]`

- [ ] **Step 3: Commit**

```bash
git add src-tauri/src/event_log/live.rs
git commit -m "feat(event-log): implement live Windows Event Log queries via wevtapi"
```

---

### Task 5: Create Tauri IPC commands

**Files:**
- Create: `src-tauri/src/event_log/commands.rs`
- Modify: `src-tauri/src/lib.rs`

- [ ] **Step 1: Create commands**

Create `src-tauri/src/event_log/commands.rs`:

```rust
use super::models::{EvtxChannelInfo, EvtxParseResult};
use super::parser;

/// Parse one or more .evtx files and return all records.
#[tauri::command]
pub async fn evtx_parse_files(paths: Vec<String>) -> Result<EvtxParseResult, String> {
    tokio::task::spawn_blocking(move || parser::parse_evtx_files(&paths))
        .await
        .map_err(|e| format!("Task join error: {}", e))?
}

/// Enumerate all event log channels on the local machine (Windows only).
#[cfg(target_os = "windows")]
#[tauri::command]
pub async fn evtx_enumerate_channels() -> Result<Vec<EvtxChannelInfo>, String> {
    tokio::task::spawn_blocking(super::live::enumerate_channels)
        .await
        .map_err(|e| format!("Task join error: {}", e))?
}

#[cfg(not(target_os = "windows"))]
#[tauri::command]
pub async fn evtx_enumerate_channels() -> Result<Vec<EvtxChannelInfo>, String> {
    Ok(Vec::new())
}

/// Query events from specific channels (Windows only).
#[cfg(target_os = "windows")]
#[tauri::command]
pub async fn evtx_query_channels(
    channels: Vec<String>,
    max_events: Option<u64>,
) -> Result<EvtxParseResult, String> {
    tokio::task::spawn_blocking(move || {
        let mut all_records = Vec::new();
        let mut channel_infos = Vec::new();
        let mut parse_errors = 0u32;

        for channel in &channels {
            match super::live::query_channel(channel, max_events) {
                Ok(records) => {
                    channel_infos.push(EvtxChannelInfo {
                        name: channel.clone(),
                        event_count: records.len() as u64,
                        source_type: super::models::ChannelSourceType::Live,
                    });
                    all_records.extend(records);
                }
                Err(e) => {
                    eprintln!("Failed to query channel {}: {}", channel, e);
                    parse_errors += 1;
                }
            }
        }

        // Sort by timestamp
        all_records.sort_by_key(|r| r.timestamp_epoch);
        for (i, record) in all_records.iter_mut().enumerate() {
            record.id = i as u64;
        }

        let total_records = all_records.len() as u64;

        Ok(EvtxParseResult {
            records: all_records,
            channels: channel_infos,
            total_records,
            parse_errors,
        })
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?
}

#[cfg(not(target_os = "windows"))]
#[tauri::command]
pub async fn evtx_query_channels(
    _channels: Vec<String>,
    _max_events: Option<u64>,
) -> Result<EvtxParseResult, String> {
    Ok(EvtxParseResult {
        records: Vec::new(),
        channels: Vec::new(),
        total_records: 0,
        parse_errors: 0,
    })
}
```

- [ ] **Step 2: Register commands in lib.rs**

In `src-tauri/src/lib.rs`, add to the `invoke_handler` macro (inside the `generate_handler![]`):

```rust
    #[cfg(feature = "event-log")]
    event_log::commands::evtx_parse_files,
    #[cfg(feature = "event-log")]
    event_log::commands::evtx_enumerate_channels,
    #[cfg(feature = "event-log")]
    event_log::commands::evtx_query_channels,
```

Note: `cfg` attributes may not work inside `generate_handler!`. If they don't, wrap the handler registration conditionally or always include the commands with no-op implementations on unsupported platforms.

- [ ] **Step 3: Run cargo check**

Run: `cd src-tauri && cargo check`
Expected: PASS

- [ ] **Step 4: Run cargo test**

Run: `cd src-tauri && cargo test`
Expected: PASS (including the EvtxLevel test)

- [ ] **Step 5: Run cargo clippy**

Run: `cd src-tauri && cargo clippy -- -D warnings`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src-tauri/src/event_log/commands.rs src-tauri/src/lib.rs
git commit -m "feat(event-log): add Tauri IPC commands for EVTX parsing and live queries"
```

---

### Task 6: Create frontend types and store

**Files:**
- Create: `src/types/event-log-workspace.ts`
- Create: `src/stores/evtx-store.ts`
- Modify: `src/types/log.ts`

- [ ] **Step 1: Add "event-log" to WorkspaceId**

In `src/types/log.ts`, add `"event-log"` to the `WorkspaceId` union:

```typescript
export type WorkspaceId =
  | "log"
  | "intune"
  | "new-intune"
  | "dsregcmd"
  | "macos-diag"
  | "deployment"
  | "event-log";
```

- [ ] **Step 2: Create TypeScript types**

Create `src/types/event-log-workspace.ts`:

```typescript
export interface EvtxRecord {
  id: number;
  eventRecordId: number;
  timestamp: string;
  timestampEpoch: number;
  provider: string;
  channel: string;
  eventId: number;
  level: EvtxLevel;
  computer: string;
  message: string;
  eventData: EvtxField[];
  rawXml: string;
  sourceLabel: string;
}

export interface EvtxField {
  name: string;
  value: string;
}

export type EvtxLevel = "Critical" | "Error" | "Warning" | "Information" | "Verbose";

export interface EvtxChannelInfo {
  name: string;
  eventCount: number;
  sourceType: { Live: null } | { File: { path: string } };
}

export interface EvtxParseResult {
  records: EvtxRecord[];
  channels: EvtxChannelInfo[];
  totalRecords: number;
  parseErrors: number;
}
```

- [ ] **Step 3: Create the Zustand store**

Create `src/stores/evtx-store.ts`:

```typescript
import { create } from "zustand";
import { invoke } from "@tauri-apps/api/core";
import type {
  EvtxRecord,
  EvtxChannelInfo,
  EvtxLevel,
  EvtxParseResult,
} from "../types/event-log-workspace";

export type EvtxSortField = "time" | "level" | "eventId" | "channel" | "provider";
export type SortDirection = "asc" | "desc";

interface EvtxState {
  // Data
  records: EvtxRecord[];
  channels: EvtxChannelInfo[];
  totalRecords: number;
  parseErrors: number;

  // Source state
  sourceMode: "none" | "live" | "file" | "mixed";
  isLoading: boolean;
  loadError: string | null;

  // Filters
  selectedChannels: string[];
  filterLevels: Set<EvtxLevel>;
  filterEventIds: string;
  filterSearch: string;

  // Sort
  sortField: EvtxSortField;
  sortDirection: SortDirection;

  // Selection
  selectedRecordId: number | null;

  // Actions
  parseFiles: (paths: string[]) => Promise<void>;
  enumerateChannels: () => Promise<void>;
  queryChannels: (channels: string[], maxEvents?: number) => Promise<void>;
  setSelectedChannels: (channels: string[]) => void;
  toggleChannel: (channel: string) => void;
  setFilterLevels: (levels: Set<EvtxLevel>) => void;
  toggleFilterLevel: (level: EvtxLevel) => void;
  setFilterEventIds: (ids: string) => void;
  setFilterSearch: (search: string) => void;
  setSortField: (field: EvtxSortField) => void;
  toggleSortDirection: () => void;
  selectRecord: (id: number | null) => void;
  reset: () => void;
}

const defaultState = {
  records: [] as EvtxRecord[],
  channels: [] as EvtxChannelInfo[],
  totalRecords: 0,
  parseErrors: 0,
  sourceMode: "none" as const,
  isLoading: false,
  loadError: null as string | null,
  selectedChannels: [] as string[],
  filterLevels: new Set<EvtxLevel>(["Critical", "Error", "Warning", "Information", "Verbose"]),
  filterEventIds: "",
  filterSearch: "",
  sortField: "time" as EvtxSortField,
  sortDirection: "asc" as SortDirection,
  selectedRecordId: null as number | null,
};

export const useEvtxStore = create<EvtxState>((set, get) => ({
  ...defaultState,

  parseFiles: async (paths) => {
    set({ isLoading: true, loadError: null });
    try {
      const result = await invoke<EvtxParseResult>("evtx_parse_files", { paths });
      const channelNames = result.channels.map((c) => c.name);
      set({
        records: result.records,
        channels: result.channels,
        totalRecords: result.totalRecords,
        parseErrors: result.parseErrors,
        sourceMode: get().sourceMode === "live" ? "mixed" : "file",
        isLoading: false,
        selectedChannels: channelNames,
        selectedRecordId: null,
      });
    } catch (e) {
      set({ isLoading: false, loadError: String(e) });
    }
  },

  enumerateChannels: async () => {
    set({ isLoading: true, loadError: null });
    try {
      const channels = await invoke<EvtxChannelInfo[]>("evtx_enumerate_channels");
      set({ channels, isLoading: false, sourceMode: "live" });
    } catch (e) {
      set({ isLoading: false, loadError: String(e) });
    }
  },

  queryChannels: async (channels, maxEvents) => {
    set({ isLoading: true, loadError: null });
    try {
      const result = await invoke<EvtxParseResult>("evtx_query_channels", {
        channels,
        maxEvents: maxEvents ?? null,
      });
      set((state) => ({
        records: [...state.records, ...result.records],
        channels: [...state.channels, ...result.channels],
        totalRecords: state.totalRecords + result.totalRecords,
        parseErrors: state.parseErrors + result.parseErrors,
        sourceMode: state.sourceMode === "file" ? "mixed" : "live",
        isLoading: false,
        selectedChannels: [...state.selectedChannels, ...channels],
        selectedRecordId: null,
      }));
    } catch (e) {
      set({ isLoading: false, loadError: String(e) });
    }
  },

  setSelectedChannels: (channels) => set({ selectedChannels: channels }),
  toggleChannel: (channel) =>
    set((state) => ({
      selectedChannels: state.selectedChannels.includes(channel)
        ? state.selectedChannels.filter((c) => c !== channel)
        : [...state.selectedChannels, channel],
    })),

  setFilterLevels: (levels) => set({ filterLevels: levels }),
  toggleFilterLevel: (level) =>
    set((state) => {
      const next = new Set(state.filterLevels);
      if (next.has(level)) next.delete(level);
      else next.add(level);
      return { filterLevels: next };
    }),

  setFilterEventIds: (ids) => set({ filterEventIds: ids }),
  setFilterSearch: (search) => set({ filterSearch: search }),
  setSortField: (field) => set({ sortField: field }),
  toggleSortDirection: () =>
    set((state) => ({
      sortDirection: state.sortDirection === "asc" ? "desc" : "asc",
    })),
  selectRecord: (id) => set({ selectedRecordId: id }),
  reset: () => set(defaultState),
}));
```

- [ ] **Step 4: Run TypeScript check**

Run: `npx tsc --noEmit`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/types/log.ts src/types/event-log-workspace.ts src/stores/evtx-store.ts
git commit -m "feat(event-log): add frontend types and Zustand store"
```

---

### Task 7: Register workspace in frontend routing

**Files:**
- Modify: `src/stores/ui-store.ts`
- Modify: `src/components/layout/Toolbar.tsx`
- Modify: `src/components/layout/AppShell.tsx`

- [ ] **Step 1: Add to workspace platform map**

In `src/stores/ui-store.ts`, add to `WORKSPACE_PLATFORM_MAP`:

```typescript
"event-log": "all",
```

(Cross-platform because file-based parsing works everywhere. The "This Computer" option will be hidden on non-Windows.)

- [ ] **Step 2: Add workspace label**

In `src/components/layout/Toolbar.tsx`, add to `WORKSPACE_LABELS`:

```typescript
"event-log": "Event Log Viewer",
```

- [ ] **Step 3: Add rendering case in AppShell**

In `src/components/layout/AppShell.tsx`, add to the `renderWorkspace` function, before the default/fallback return:

```typescript
if (activeView === "event-log") {
  return (
    <div style={{ flex: 1, overflow: "hidden", display: "flex" }}>
      <EventLogWorkspace />
    </div>
  );
}
```

Add the import at the top:
```typescript
import { EventLogWorkspace } from "../event-log-workspace/EventLogWorkspace";
```

Note: The `EventLogWorkspace` component doesn't exist yet — create a placeholder that renders "Event Log Workspace - Coming Soon" so the app compiles.

- [ ] **Step 4: Create placeholder workspace component**

Create `src/components/event-log-workspace/EventLogWorkspace.tsx`:

```typescript
import { tokens } from "@fluentui/react-components";

export function EventLogWorkspace() {
  return (
    <div style={{
      flex: 1,
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      color: tokens.colorNeutralForeground3,
      fontSize: "14px",
    }}>
      Event Log Workspace — loading...
    </div>
  );
}
```

- [ ] **Step 5: Run TypeScript check**

Run: `npx tsc --noEmit`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/stores/ui-store.ts src/components/layout/Toolbar.tsx src/components/layout/AppShell.tsx src/components/event-log-workspace/EventLogWorkspace.tsx
git commit -m "feat(event-log): register workspace in frontend routing"
```

---

### Task 8: Build the workspace UI components

**Files:**
- Create: `src/components/event-log-workspace/SourcePicker.tsx`
- Create: `src/components/event-log-workspace/ChannelPicker.tsx`
- Create: `src/components/event-log-workspace/EvtxFilterBar.tsx`
- Create: `src/components/event-log-workspace/EvtxTimeline.tsx`
- Create: `src/components/event-log-workspace/EvtxTimelineRow.tsx`
- Create: `src/components/event-log-workspace/EvtxDetailPane.tsx`
- Modify: `src/components/event-log-workspace/EventLogWorkspace.tsx`

This is a large task — implement each component following the patterns established in the Intune workspace (`src/components/intune/`). Key patterns to follow:

- Virtual scrolling with `@tanstack/react-virtual` (see `EventTimeline.tsx`)
- Font sizing via `useUiStore` + `getLogListMetrics` (see `EventTimeline.tsx`)
- Filtering via `useMemo` over store state
- Sort via `useMemo` with `compareEvents`-style comparator

- [ ] **Step 1: Create SourcePicker**

The initial view when no data is loaded. Shows two buttons: "This Computer" (Windows only) and "Open .evtx Files".

- [ ] **Step 2: Create ChannelPicker**

A scrollable list of channels with checkboxes, a search/filter box, and preset buttons ("Core Windows", "Sysmon", "All").

- [ ] **Step 3: Create EvtxFilterBar**

Level toggles (Critical/Error/Warning/Info/Verbose), EventID text input, search box, sort controls.

- [ ] **Step 4: Create EvtxTimeline and EvtxTimelineRow**

Virtual-scrolled list of events. Each row shows: level icon, timestamp, EventID, channel badge, provider, message preview. Follow the `EventTimeline.tsx` + `EventTimelineRow.tsx` pattern.

- [ ] **Step 5: Create EvtxDetailPane**

Expandable detail view showing structured EventData fields as a key-value table, plus a collapsible raw XML section.

- [ ] **Step 6: Wire everything together in EventLogWorkspace**

Replace the placeholder with the full workspace layout:
- No data → show `SourcePicker`
- Loading → show progress
- Data loaded → show `EvtxFilterBar` + `ChannelPicker` (sidebar) + `EvtxTimeline` + `EvtxDetailPane`

- [ ] **Step 7: Run TypeScript check**

Run: `npx tsc --noEmit`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add src/components/event-log-workspace/
git commit -m "feat(event-log): build workspace UI components"
```

---

### Task 9: Final verification

- [ ] **Step 1: Run all backend checks**

Run: `cd src-tauri && cargo check && cargo test && cargo clippy -- -D warnings`
Expected: All PASS

- [ ] **Step 2: Run frontend checks**

Run: `npx tsc --noEmit && npm run frontend:build`
Expected: All PASS

- [ ] **Step 3: Manual testing (file-based)**

1. Switch to Event Log workspace from dropdown
2. Click "Open .evtx Files" → select an exported .evtx file
3. Events display in timeline with correct timestamps, levels, channels
4. Click an event → detail pane shows EventData fields and raw XML
5. Filter by level → events filter correctly
6. Search → matching events shown

- [ ] **Step 4: Manual testing (live — Windows only)**

1. Click "This Computer" → channels enumerate (may take a few seconds)
2. Search for "Security" → channel appears
3. Select Security + Application → click Load
4. Events from both channels interleave by timestamp
5. Channel badges distinguish sources

- [ ] **Step 5: Cross-platform check**

On macOS/Linux:
1. "This Computer" option is hidden
2. File-based parsing works
3. No compile errors or runtime crashes
