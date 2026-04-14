# `.cmtlog` Format, Markers, and PowerShell Integration — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a custom `.cmtlog` log format with sections/WhatIf/tags, color-coded user markers persisted to AppData, section divider rendering, multi-select copy, and a PowerShell authoring module.

**Architecture:** The `.cmtlog` format extends CCM's `<![LOG[...]LOG]!>` line structure with reserved component names (`__HEADER__`, `__SECTION__`, `__ITERATION__`) and optional extended attributes (`section`, `tag`, `whatif`, `iteration`, `color`). A new Rust parser module extracts these. Markers are independent — persisted as JSON in AppData keyed by file path hash. Frontend gains a marker store, gutter UI, section band rendering, WhatIf styling, and multi-select copy.

**Tech Stack:** Rust (parser, marker persistence), React + TypeScript (UI), Zustand (marker store), PowerShell (authoring module), Tauri IPC (marker commands)

**Spec:** `docs/superpowers/specs/2026-04-13-cmtlog-format-markers-design.md`

---

## File Structure

### New Files

| File | Responsibility |
|------|---------------|
| `src-tauri/src/parser/cmtlog.rs` | CmtLog parser — detects reserved components, extracts extended attributes |
| `src-tauri/src/commands/markers.rs` | Tauri IPC commands for marker load/save/delete |
| `src-tauri/tests/cmtlog_parser.rs` | Parser regression tests for `.cmtlog` format |
| `src-tauri/tests/fixtures/cmtlog/` | Test fixture `.cmtlog` files |
| `src/stores/marker-store.ts` | Zustand store for marker state per tab |
| `src/types/markers.ts` | TypeScript types for markers and categories |
| `scripts/powershell/CmtLog/CmtLog.psm1` | PowerShell module for writing `.cmtlog` files |

### Modified Files

| File | Changes |
|------|---------|
| `src-tauri/src/models/log_entry.rs` | Add `EntryKind` enum, `CmtLog` to `ParserKind`/`ParserImplementation`/`LogFormat`, new optional fields on `LogEntry` |
| `src-tauri/src/parser/mod.rs` | Add `pub mod cmtlog;`, dispatch arm in `parse_lines_with_selection` |
| `src-tauri/src/parser/detect.rs` | Add `.cmtlog` extension detection and content fallback |
| `src-tauri/src/lib.rs` | Register marker commands in `invoke_handler` |
| `src-tauri/src/commands/mod.rs` | Add `pub mod markers;` |
| `src-tauri/tauri.conf.json` | Add `.cmtlog` file association |
| `src/types/log.ts` | Add `CmtLog` to `LogFormat`, new optional fields on `LogEntry` interface |
| `src/components/log-view/LogRow.tsx` | Marker gutter, section bands, WhatIf styling, multi-select highlight |
| `src/components/log-view/LogListView.tsx` | Section divider rows, multi-select state, gutter column, copy handler |
| `src/stores/filter-store.ts` | Add WhatIf filter toggle |

---

## Task 1: Extend LogEntry Model with CmtLog Fields

**Files:**
- Modify: `src-tauri/src/models/log_entry.rs`

- [ ] **Step 1: Add `EntryKind` enum**

Add after the `Severity` enum (around line 10):

```rust
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EntryKind {
    Log,
    Section,
    Iteration,
    Header,
}

impl Default for EntryKind {
    fn default() -> Self {
        EntryKind::Log
    }
}
```

- [ ] **Step 2: Add `CmtLog` variant to `ParserKind` enum**

Add `CmtLog` to the `ParserKind` enum (around line 32-50):

```rust
CmtLog,
```

- [ ] **Step 3: Add `CmtLog` variant to `ParserImplementation` enum**

Add `CmtLog` to the `ParserImplementation` enum (around line 55-70):

```rust
CmtLog,
```

- [ ] **Step 4: Add `CmtLog` variant to `LogFormat` enum**

Add `CmtLog` to the `LogFormat` enum (around line 14-27):

```rust
CmtLog,
```

- [ ] **Step 5: Add optional CmtLog fields to `LogEntry` struct**

Add these fields to the `LogEntry` struct (after the existing DNS fields, before the closing brace):

```rust
    // CmtLog extended fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_kind: Option<EntryKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub whatif: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub section_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub section_color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iteration: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
```

- [ ] **Step 6: Run cargo check**

Run: `cargo check` from `src-tauri/`
Expected: Compiles with no errors. Warnings about unused variants are OK at this stage.

- [ ] **Step 7: Commit**

```bash
git add src-tauri/src/models/log_entry.rs
git commit -m "feat(models): add EntryKind enum and CmtLog fields to LogEntry"
```

---

## Task 2: Create CmtLog Parser Module

**Files:**
- Create: `src-tauri/src/parser/cmtlog.rs`
- Modify: `src-tauri/src/parser/mod.rs`

- [ ] **Step 1: Write the test fixture file**

Create `src-tauri/tests/fixtures/cmtlog/basic.cmtlog`:

```
<![LOG[Script started: Detect-WDAC.ps1 v2.1.0]LOG]!><time="10:30:00.000+000" date="04-13-2026" component="__HEADER__" context="" type="1" thread="0" file="" script="Detect-WDAC.ps1" version="2.1.0" runid="a3f8c9e1" mode="Normal" ps_version="7.4.2">
<![LOG[Detection Phase]LOG]!><time="10:32:01.000+000" date="04-13-2026" component="__SECTION__" context="" type="1" thread="0" file="" color="#5b9aff">
<![LOG[Scanning policy files]LOG]!><time="10:32:01.123+000" date="04-13-2026" component="Detect-WDAC" context="CONTOSO\admin" type="1" thread="1234" file="" section="detection" tag="phase:scan">
<![LOG[Policy validation failed]LOG]!><time="10:32:01.456+000" date="04-13-2026" component="Detect-WDAC" context="CONTOSO\admin" type="3" thread="1234" file="" section="detection">
<![LOG[Loop Iteration 1/3 - WDAC policies]LOG]!><time="10:32:02.000+000" date="04-13-2026" component="__ITERATION__" context="" type="1" thread="0" file="" iteration="1/3" color="#a78bfa">
<![LOG[Processing policy contoso.xml]LOG]!><time="10:32:02.100+000" date="04-13-2026" component="Detect-WDAC" context="CONTOSO\admin" type="1" thread="1234" file="" section="detection" iteration="1/3">
<![LOG[Would apply policy contoso.xml]LOG]!><time="10:32:02.200+000" date="04-13-2026" component="Detect-WDAC" context="CONTOSO\admin" type="1" thread="1234" file="" section="detection" whatif="1">
```

- [ ] **Step 2: Write the failing parser test**

Create `src-tauri/tests/cmtlog_parser.rs`:

```rust
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

struct TempLogFixture {
    dir: PathBuf,
    path: PathBuf,
}

impl TempLogFixture {
    fn new(file_name: &str, content: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("cmtrace-open-cmtlog-test-{unique}"));
        fs::create_dir_all(&dir).expect("create temp fixture dir");
        let path = dir.join(file_name);
        fs::write(&path, content).expect("write temp fixture");
        Self { dir, path }
    }

    fn parse(&self) -> app_lib::parser::ParseResult {
        let path_str = self.path.to_string_lossy().to_string();
        let (result, _selection) =
            app_lib::parser::parse_file(&path_str).expect("fixture should parse successfully");
        result
    }

    fn detect(&self) -> app_lib::parser::detect::ResolvedParser {
        let content =
            fs::read_to_string(&self.path).expect("fixture should be readable as UTF-8");
        app_lib::parser::detect::detect_parser(&self.path.to_string_lossy(), &content)
    }
}

impl Drop for TempLogFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn cmtlog_extension_triggers_cmtlog_parser() {
    let content = include_str!("fixtures/cmtlog/basic.cmtlog");
    let fixture = TempLogFixture::new("test.cmtlog", content);
    let selection = fixture.detect();
    assert_eq!(
        format!("{:?}", selection.parser),
        "CmtLog",
        "should detect CmtLog parser for .cmtlog extension"
    );
}

#[test]
fn cmtlog_parses_header_entry() {
    let content = include_str!("fixtures/cmtlog/basic.cmtlog");
    let fixture = TempLogFixture::new("test.cmtlog", content);
    let result = fixture.parse();
    let header = &result.entries[0];
    assert_eq!(header.component.as_deref(), Some("__HEADER__"));
    assert_eq!(
        header.entry_kind,
        Some(app_lib::models::log_entry::EntryKind::Header)
    );
    assert_eq!(header.message, "Script started: Detect-WDAC.ps1 v2.1.0");
}

#[test]
fn cmtlog_parses_section_entry() {
    let content = include_str!("fixtures/cmtlog/basic.cmtlog");
    let fixture = TempLogFixture::new("test.cmtlog", content);
    let result = fixture.parse();
    let section = &result.entries[1];
    assert_eq!(
        section.entry_kind,
        Some(app_lib::models::log_entry::EntryKind::Section)
    );
    assert_eq!(section.message, "Detection Phase");
    assert_eq!(section.section_color.as_deref(), Some("#5b9aff"));
}

#[test]
fn cmtlog_parses_iteration_entry() {
    let content = include_str!("fixtures/cmtlog/basic.cmtlog");
    let fixture = TempLogFixture::new("test.cmtlog", content);
    let result = fixture.parse();
    let iteration = &result.entries[4];
    assert_eq!(
        iteration.entry_kind,
        Some(app_lib::models::log_entry::EntryKind::Iteration)
    );
    assert_eq!(iteration.iteration.as_deref(), Some("1/3"));
    assert_eq!(iteration.section_color.as_deref(), Some("#a78bfa"));
}

#[test]
fn cmtlog_parses_regular_entries_with_section_name() {
    let content = include_str!("fixtures/cmtlog/basic.cmtlog");
    let fixture = TempLogFixture::new("test.cmtlog", content);
    let result = fixture.parse();
    let entry = &result.entries[2];
    assert_eq!(
        entry.entry_kind,
        Some(app_lib::models::log_entry::EntryKind::Log)
    );
    assert_eq!(entry.section_name.as_deref(), Some("detection"));
    assert_eq!(entry.message, "Scanning policy files");
    assert!(entry.tags.as_ref().unwrap().contains(&"phase:scan".to_string()));
}

#[test]
fn cmtlog_parses_whatif_flag() {
    let content = include_str!("fixtures/cmtlog/basic.cmtlog");
    let fixture = TempLogFixture::new("test.cmtlog", content);
    let result = fixture.parse();
    let whatif_entry = &result.entries[6];
    assert_eq!(whatif_entry.whatif, Some(true));
    assert_eq!(whatif_entry.message, "Would apply policy contoso.xml");
}

#[test]
fn cmtlog_regular_entries_have_correct_severity() {
    let content = include_str!("fixtures/cmtlog/basic.cmtlog");
    let fixture = TempLogFixture::new("test.cmtlog", content);
    let result = fixture.parse();
    // Entry at index 3 has type="3" → Error
    let error_entry = &result.entries[3];
    assert_eq!(
        error_entry.severity,
        app_lib::models::log_entry::Severity::Error
    );
}

#[test]
fn cmtlog_total_entries_count() {
    let content = include_str!("fixtures/cmtlog/basic.cmtlog");
    let fixture = TempLogFixture::new("test.cmtlog", content);
    let result = fixture.parse();
    assert_eq!(result.entries.len(), 7);
}

#[test]
fn cmtlog_content_fallback_detection() {
    // A .log file with __SECTION__ component should still detect as CmtLog
    let content = r#"<![LOG[Detection Phase]LOG]!><time="10:32:01.000+000" date="04-13-2026" component="__SECTION__" context="" type="1" thread="0" file="" color="#5b9aff">
<![LOG[Scanning policy files]LOG]!><time="10:32:01.123+000" date="04-13-2026" component="Detect-WDAC" context="CONTOSO\admin" type="1" thread="1234" file="" section="detection">"#;
    let fixture = TempLogFixture::new("test.log", content);
    let selection = fixture.detect();
    assert_eq!(
        format!("{:?}", selection.parser),
        "CmtLog",
        "should detect CmtLog parser via content fallback for .log with reserved components"
    );
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test --test cmtlog_parser` from `src-tauri/`
Expected: Compilation errors — `cmtlog` module doesn't exist yet, `EntryKind` variants may not be wired up.

- [ ] **Step 4: Create the cmtlog parser module**

Create `src-tauri/src/parser/cmtlog.rs`:

```rust
use lazy_static::lazy_static;
use regex::Regex;

use crate::models::log_entry::{EntryKind, LogEntry, LogFormat, Severity};
use crate::parser::ccm;

lazy_static! {
    /// Regex to extract extended attributes from the metadata portion of a CCM line.
    /// Matches key="value" pairs after the standard CCM attributes.
    static ref EXTENDED_ATTR_RE: Regex =
        Regex::new(r#"(\w+)="([^"]*)""#).expect("extended attribute regex should compile");
}

/// Reserved component names that signal structural entries.
const HEADER_COMPONENT: &str = "__HEADER__";
const SECTION_COMPONENT: &str = "__SECTION__";
const ITERATION_COMPONENT: &str = "__ITERATION__";

/// Returns true if a CCM-format line contains a reserved CmtLog component.
pub fn matches_cmtlog_record(line: &str) -> bool {
    line.contains(HEADER_COMPONENT)
        || line.contains(SECTION_COMPONENT)
        || line.contains(ITERATION_COMPONENT)
}

/// Classify a component string into an EntryKind.
fn classify_component(component: &str) -> EntryKind {
    match component {
        HEADER_COMPONENT => EntryKind::Header,
        SECTION_COMPONENT => EntryKind::Section,
        ITERATION_COMPONENT => EntryKind::Iteration,
        _ => EntryKind::Log,
    }
}

/// Extract extended attributes from the raw metadata portion of a line.
/// Returns a map of key-value pairs for known extended attributes.
struct ExtendedAttrs {
    section: Option<String>,
    color: Option<String>,
    tag: Option<String>,
    whatif: Option<bool>,
    iteration: Option<String>,
}

fn extract_extended_attrs(line: &str) -> ExtendedAttrs {
    let mut attrs = ExtendedAttrs {
        section: None,
        color: None,
        tag: None,
        whatif: None,
        iteration: None,
    };

    for cap in EXTENDED_ATTR_RE.captures_iter(line) {
        let key = &cap[1];
        let value = &cap[2];
        match key {
            "section" => attrs.section = Some(value.to_string()),
            "color" => attrs.color = Some(value.to_string()),
            "tag" => attrs.tag = Some(value.to_string()),
            "whatif" if value == "1" => attrs.whatif = Some(true),
            "whatif" if value == "0" => attrs.whatif = Some(false),
            "iteration" => attrs.iteration = Some(value.to_string()),
            _ => {} // standard CCM attrs and unknown attrs are ignored
        }
    }

    attrs
}

/// Parse lines as CmtLog format.
///
/// Delegates core CCM parsing to `ccm::parse_lines`, then post-processes
/// each entry to extract extended attributes and classify entry kinds.
pub fn parse_lines(lines: &[&str], file_path: &str) -> (Vec<LogEntry>, u32) {
    let (mut entries, error_count) = ccm::parse_lines(lines, file_path);

    // Track the current section name and color for propagation to child entries.
    let mut current_section_name: Option<String> = None;
    let mut current_section_color: Option<String> = None;

    for (i, entry) in entries.iter_mut().enumerate() {
        // Override format to CmtLog
        entry.format = LogFormat::CmtLog;

        let line = if i < lines.len() { lines[i] } else { "" };
        let attrs = extract_extended_attrs(line);
        let component = entry.component.as_deref().unwrap_or("");
        let kind = classify_component(component);

        match &kind {
            EntryKind::Section => {
                current_section_name = Some(entry.message.clone());
                current_section_color = attrs.color.clone();
                entry.section_name = current_section_name.clone();
                entry.section_color = attrs.color;
            }
            EntryKind::Iteration => {
                entry.iteration = attrs.iteration;
                entry.section_color = attrs.color.or(current_section_color.clone());
                entry.section_name = current_section_name.clone();
            }
            EntryKind::Header => {
                // Header is a metadata line — no section propagation
            }
            EntryKind::Log => {
                // Propagate current section context to regular log entries
                if entry.section_name.is_none() {
                    entry.section_name = attrs.section.or(current_section_name.clone());
                } else {
                    entry.section_name = attrs.section;
                }
                entry.section_color = current_section_color.clone();
                entry.whatif = attrs.whatif;
                entry.iteration = attrs.iteration;
                if let Some(tag_str) = attrs.tag {
                    entry.tags = Some(
                        tag_str
                            .split(',')
                            .map(|t| t.trim().to_string())
                            .filter(|t| !t.is_empty())
                            .collect(),
                    );
                }
            }
        }

        entry.entry_kind = Some(kind);
    }

    (entries, error_count)
}
```

- [ ] **Step 5: Register the module in parser/mod.rs**

Add to the module declarations at the top of `src-tauri/src/parser/mod.rs`:

```rust
pub mod cmtlog;
```

Add a dispatch arm in `parse_lines_with_selection` (inside the `match selection.implementation` block):

```rust
ParserImplementation::CmtLog => cmtlog::parse_lines(lines, file_path),
```

- [ ] **Step 6: Run cargo check**

Run: `cargo check` from `src-tauri/`
Expected: Compiles successfully.

- [ ] **Step 7: Commit**

```bash
git add src-tauri/src/parser/cmtlog.rs src-tauri/src/parser/mod.rs
git commit -m "feat(parser): add cmtlog parser module with extended attribute extraction"
```

---

## Task 3: Wire CmtLog Detection

**Files:**
- Modify: `src-tauri/src/parser/detect.rs`
- Create: `src-tauri/tests/fixtures/cmtlog/basic.cmtlog`
- Create: `src-tauri/tests/cmtlog_parser.rs`

- [ ] **Step 1: Add `.cmtlog` extension detection in `detect_parser`**

In `src-tauri/src/parser/detect.rs`, inside `detect_parser()`, add an early extension check before the existing path hint extraction. Add after the DHCP/IIS checks but before the sample-lines loop (around line 350):

```rust
    // ── CmtLog: extension-based detection ──
    let path_lower = path.to_lowercase();
    if path_lower.ends_with(".cmtlog") {
        return ResolvedParser {
            parser: ParserKind::CmtLog,
            implementation: ParserImplementation::CmtLog,
            provenance: ParserProvenance::Dedicated,
            parse_quality: ParseQuality::Structured,
            record_framing: RecordFraming::PhysicalLine,
            date_order: DateFieldOrder::MonthFirst,
            specialization: None,
        };
    }
```

Note: Check the existing code to see if `path_lower` is already defined. If so, reuse it. If the variable name differs, match the existing convention.

- [ ] **Step 2: Add content-based fallback detection**

In the sample-lines counting loop in `detect_parser()` (around lines 422-467), add a counter for CmtLog reserved components:

```rust
    let mut cmtlog_count = 0;
```

Inside the line-matching loop, add:

```rust
    if crate::parser::cmtlog::matches_cmtlog_record(line) {
        cmtlog_count += 1;
    }
```

In the decision tree (around lines 469-515), add a check before the CCM check — if we detected any reserved components and the file also has CCM lines, prefer CmtLog:

```rust
    if cmtlog_count > 0 && ccm_count > 0 {
        return ResolvedParser {
            parser: ParserKind::CmtLog,
            implementation: ParserImplementation::CmtLog,
            provenance: ParserProvenance::Heuristic,
            parse_quality: ParseQuality::Structured,
            record_framing: RecordFraming::PhysicalLine,
            date_order: DateFieldOrder::MonthFirst,
            specialization: None,
        };
    }
```

- [ ] **Step 3: Create the test fixtures directory and fixture file**

Run: `mkdir -p src-tauri/tests/fixtures/cmtlog` from project root.

The fixture file was already specified in Task 2, Step 1. Create it now if not already done.

- [ ] **Step 4: Create the test file**

The test file was already specified in Task 2, Step 2. Create it now if not already done.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test --test cmtlog_parser` from `src-tauri/`
Expected: All 9 tests pass.

- [ ] **Step 6: Run full cargo check and clippy**

Run: `cargo check && cargo clippy -- -D warnings` from `src-tauri/`
Expected: No errors, no warnings.

- [ ] **Step 7: Commit**

```bash
git add src-tauri/src/parser/detect.rs src-tauri/tests/cmtlog_parser.rs src-tauri/tests/fixtures/cmtlog/basic.cmtlog
git commit -m "feat(parser): wire cmtlog detection by extension and content fallback"
```

---

## Task 4: Update Frontend TypeScript Types

**Files:**
- Modify: `src/types/log.ts`
- Create: `src/types/markers.ts`

- [ ] **Step 1: Add CmtLog to LogFormat type**

In `src/types/log.ts`, find the `LogFormat` type union and add `"CmtLog"`:

```typescript
export type LogFormat = "Ccm" | "Simple" | "Plain" | "Timestamped" | "DnsDebug" | "DnsAudit" | "CmtLog";
```

Note: Match the exact existing variants — read the file first to confirm the current list.

- [ ] **Step 2: Add EntryKind type**

In `src/types/log.ts`, add:

```typescript
export type EntryKind = "Log" | "Section" | "Iteration" | "Header";
```

- [ ] **Step 3: Add CmtLog fields to LogEntry interface**

In `src/types/log.ts`, add these optional fields to the `LogEntry` interface:

```typescript
  entryKind?: EntryKind;
  whatif?: boolean;
  sectionName?: string;
  sectionColor?: string;
  iteration?: string;
  tags?: string[];
```

- [ ] **Step 4: Create marker types**

Create `src/types/markers.ts`:

```typescript
export interface MarkerCategory {
  id: string;
  label: string;
  color: string;
}

export interface Marker {
  lineId: number;
  category: string;
  color: string;
  added: string; // ISO 8601
}

export interface MarkerFile {
  version: number;
  sourcePath: string;
  sourceSize: number;
  created: string;
  modified: string;
  markers: Marker[];
  categories: MarkerCategory[];
}

export const DEFAULT_CATEGORIES: MarkerCategory[] = [
  { id: "bug", label: "Bug", color: "#ef4444" },
  { id: "investigate", label: "Investigate", color: "#60a5fa" },
  { id: "confirmed", label: "Confirmed", color: "#4ade80" },
];
```

- [ ] **Step 5: Run TypeScript check**

Run: `npx tsc --noEmit` from project root.
Expected: No type errors.

- [ ] **Step 6: Commit**

```bash
git add src/types/log.ts src/types/markers.ts
git commit -m "feat(types): add CmtLog format types, EntryKind, and marker type definitions"
```

---

## Task 5: Marker Persistence Backend

**Files:**
- Create: `src-tauri/src/commands/markers.rs`
- Modify: `src-tauri/src/commands/mod.rs`
- Modify: `src-tauri/src/lib.rs`

- [ ] **Step 1: Write the failing test for marker round-trip**

Add to the bottom of `src-tauri/tests/cmtlog_parser.rs` (or create a separate `src-tauri/tests/markers.rs`):

```rust
#[test]
fn marker_file_path_hash_is_deterministic() {
    use sha2::{Digest, Sha256};
    let path = r"C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\test.cmtlog";
    let hash1 = format!("{:x}", Sha256::digest(path.as_bytes()));
    let hash2 = format!("{:x}", Sha256::digest(path.as_bytes()));
    assert_eq!(hash1, hash2);
    assert_eq!(hash1.len(), 64);
}
```

- [ ] **Step 2: Add sha2 dependency**

Run: `cargo add sha2` from `src-tauri/`

- [ ] **Step 3: Run test to verify it passes**

Run: `cargo test marker_file_path_hash_is_deterministic` from `src-tauri/`
Expected: PASS

- [ ] **Step 4: Create the markers command module**

Create `src-tauri/src/commands/markers.rs`:

```rust
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use tauri::AppHandle;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MarkerCategory {
    pub id: String,
    pub label: String,
    pub color: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Marker {
    pub line_id: u64,
    pub category: String,
    pub color: String,
    pub added: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MarkerFile {
    pub version: u32,
    pub source_path: String,
    pub source_size: u64,
    pub created: String,
    pub modified: String,
    pub markers: Vec<Marker>,
    pub categories: Vec<MarkerCategory>,
}

fn markers_dir(app: &AppHandle) -> Result<PathBuf, crate::error::AppError> {
    let app_data = app
        .path()
        .app_data_dir()
        .map_err(|e| crate::error::AppError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;
    let dir = app_data.join("markers");
    if !dir.exists() {
        fs::create_dir_all(&dir)
            .map_err(crate::error::AppError::Io)?;
    }
    Ok(dir)
}

fn path_to_hash(file_path: &str) -> String {
    format!("{:x}", Sha256::digest(file_path.as_bytes()))
}

#[tauri::command]
pub fn load_markers(file_path: String, app: AppHandle) -> Result<Option<MarkerFile>, crate::error::AppError> {
    let dir = markers_dir(&app)?;
    let hash = path_to_hash(&file_path);
    let marker_path = dir.join(format!("{hash}.json"));

    if !marker_path.exists() {
        return Ok(None);
    }

    let content = fs::read_to_string(&marker_path)
        .map_err(crate::error::AppError::Io)?;
    let marker_file: MarkerFile = serde_json::from_str(&content)
        .map_err(|e| crate::error::AppError::Parse(e.to_string()))?;

    Ok(Some(marker_file))
}

#[tauri::command]
pub fn save_markers(file_path: String, marker_file: MarkerFile, app: AppHandle) -> Result<(), crate::error::AppError> {
    let dir = markers_dir(&app)?;
    let hash = path_to_hash(&file_path);
    let marker_path = dir.join(format!("{hash}.json"));

    let content = serde_json::to_string_pretty(&marker_file)
        .map_err(|e| crate::error::AppError::Parse(e.to_string()))?;

    fs::write(&marker_path, content)
        .map_err(crate::error::AppError::Io)?;

    Ok(())
}

#[tauri::command]
pub fn delete_markers(file_path: String, app: AppHandle) -> Result<(), crate::error::AppError> {
    let dir = markers_dir(&app)?;
    let hash = path_to_hash(&file_path);
    let marker_path = dir.join(format!("{hash}.json"));

    if marker_path.exists() {
        fs::remove_file(&marker_path)
            .map_err(crate::error::AppError::Io)?;
    }

    Ok(())
}
```

Note: Check the actual `AppError` enum variants in `src-tauri/src/error.rs` to make sure `Io` and `Parse` variants exist. If different names are used, match the existing pattern.

- [ ] **Step 5: Register the module**

In `src-tauri/src/commands/mod.rs`, add:

```rust
pub mod markers;
```

In `src-tauri/src/lib.rs`, add the three commands to `tauri::generate_handler!`:

```rust
commands::markers::load_markers,
commands::markers::save_markers,
commands::markers::delete_markers,
```

- [ ] **Step 6: Check that `tauri::path()` API matches**

Read `src-tauri/src/lib.rs` to verify how Tauri's `AppHandle` path resolver is used. The `app.path().app_data_dir()` call may need adjustment based on the Tauri v2 API. If the codebase uses a different pattern (e.g., `app.path_resolver().app_data_dir()`), match it.

- [ ] **Step 7: Run cargo check and clippy**

Run: `cargo check && cargo clippy -- -D warnings` from `src-tauri/`
Expected: No errors, no warnings.

- [ ] **Step 8: Commit**

```bash
git add src-tauri/src/commands/markers.rs src-tauri/src/commands/mod.rs src-tauri/src/lib.rs src-tauri/Cargo.toml src-tauri/Cargo.lock
git commit -m "feat(commands): add marker persistence commands (load/save/delete)"
```

---

## Task 6: Marker Store (Frontend)

**Files:**
- Create: `src/stores/marker-store.ts`

- [ ] **Step 1: Create the marker store**

Create `src/stores/marker-store.ts`:

```typescript
import { create } from "zustand";
import { invoke } from "@tauri-apps/api/core";
import {
  Marker,
  MarkerCategory,
  MarkerFile,
  DEFAULT_CATEGORIES,
} from "../types/markers";

interface MarkerState {
  /** Markers keyed by file path, then by line ID */
  markersByFile: Map<string, Map<number, Marker>>;
  /** Categories (shared across all files) */
  categories: MarkerCategory[];
  /** Currently active marker category for placement */
  activeCategory: string;
  /** Loading state per file */
  loadingFiles: Set<string>;

  // Actions
  loadMarkers: (filePath: string) => Promise<void>;
  saveMarkers: (filePath: string) => Promise<void>;
  toggleMarker: (filePath: string, lineId: number) => void;
  setMarkerCategory: (
    filePath: string,
    lineId: number,
    category: string
  ) => void;
  removeMarker: (filePath: string, lineId: number) => void;
  setActiveCategory: (category: string) => void;
  addCategory: (category: MarkerCategory) => void;
  getMarkersForFile: (filePath: string) => Map<number, Marker>;
  getMarkedLineIds: (filePath: string, category?: string) => number[];
  clearMarkersForFile: (filePath: string) => void;
}

export const useMarkerStore = create<MarkerState>((set, get) => ({
  markersByFile: new Map(),
  categories: [...DEFAULT_CATEGORIES],
  activeCategory: "bug",
  loadingFiles: new Set(),

  loadMarkers: async (filePath: string) => {
    const { loadingFiles } = get();
    if (loadingFiles.has(filePath)) return;

    set((state) => ({
      loadingFiles: new Set(state.loadingFiles).add(filePath),
    }));

    try {
      const result = await invoke<MarkerFile | null>("load_markers", {
        filePath,
      });

      if (result) {
        const markerMap = new Map<number, Marker>();
        for (const m of result.markers) {
          markerMap.set(m.lineId, m);
        }

        set((state) => {
          const updated = new Map(state.markersByFile);
          updated.set(filePath, markerMap);
          return {
            markersByFile: updated,
            categories:
              result.categories.length > 0
                ? result.categories
                : state.categories,
          };
        });
      }
    } finally {
      set((state) => {
        const updated = new Set(state.loadingFiles);
        updated.delete(filePath);
        return { loadingFiles: updated };
      });
    }
  },

  saveMarkers: async (filePath: string) => {
    const { markersByFile, categories } = get();
    const fileMarkers = markersByFile.get(filePath);
    if (!fileMarkers || fileMarkers.size === 0) {
      // No markers — delete the file if it exists
      await invoke("delete_markers", { filePath });
      return;
    }

    const now = new Date().toISOString();
    const markerFile: MarkerFile = {
      version: 1,
      sourcePath: filePath,
      sourceSize: 0, // Frontend doesn't know file size — backend could populate
      created: now,
      modified: now,
      markers: Array.from(fileMarkers.values()),
      categories,
    };

    await invoke("save_markers", { filePath, markerFile });
  },

  toggleMarker: (filePath: string, lineId: number) => {
    const { markersByFile, activeCategory, categories } = get();
    const fileMarkers = new Map(markersByFile.get(filePath) || new Map());
    const existing = fileMarkers.get(lineId);

    if (existing) {
      fileMarkers.delete(lineId);
    } else {
      const cat = categories.find((c) => c.id === activeCategory);
      fileMarkers.set(lineId, {
        lineId,
        category: activeCategory,
        color: cat?.color ?? "#ef4444",
        added: new Date().toISOString(),
      });
    }

    set((state) => {
      const updated = new Map(state.markersByFile);
      updated.set(filePath, fileMarkers);
      return { markersByFile: updated };
    });
  },

  setMarkerCategory: (filePath: string, lineId: number, category: string) => {
    const { markersByFile, categories } = get();
    const fileMarkers = new Map(markersByFile.get(filePath) || new Map());
    const existing = fileMarkers.get(lineId);
    if (!existing) return;

    const cat = categories.find((c) => c.id === category);
    fileMarkers.set(lineId, {
      ...existing,
      category,
      color: cat?.color ?? existing.color,
    });

    set((state) => {
      const updated = new Map(state.markersByFile);
      updated.set(filePath, fileMarkers);
      return { markersByFile: updated };
    });
  },

  removeMarker: (filePath: string, lineId: number) => {
    const { markersByFile } = get();
    const fileMarkers = new Map(markersByFile.get(filePath) || new Map());
    fileMarkers.delete(lineId);

    set((state) => {
      const updated = new Map(state.markersByFile);
      updated.set(filePath, fileMarkers);
      return { markersByFile: updated };
    });
  },

  setActiveCategory: (category: string) => {
    set({ activeCategory: category });
  },

  addCategory: (category: MarkerCategory) => {
    set((state) => ({
      categories: [...state.categories, category],
    }));
  },

  getMarkersForFile: (filePath: string) => {
    return get().markersByFile.get(filePath) || new Map();
  },

  getMarkedLineIds: (filePath: string, category?: string) => {
    const fileMarkers = get().markersByFile.get(filePath);
    if (!fileMarkers) return [];
    const entries = Array.from(fileMarkers.values());
    if (category) {
      return entries.filter((m) => m.category === category).map((m) => m.lineId);
    }
    return entries.map((m) => m.lineId);
  },

  clearMarkersForFile: (filePath: string) => {
    set((state) => {
      const updated = new Map(state.markersByFile);
      updated.delete(filePath);
      return { markersByFile: updated };
    });
  },
}));
```

- [ ] **Step 2: Run TypeScript check**

Run: `npx tsc --noEmit` from project root.
Expected: No type errors.

- [ ] **Step 3: Commit**

```bash
git add src/stores/marker-store.ts
git commit -m "feat(stores): add marker-store with Zustand for marker persistence and management"
```

---

## Task 7: Section Divider Rendering

**Files:**
- Modify: `src/components/log-view/LogListView.tsx`
- Modify: `src/components/log-view/LogRow.tsx`

- [ ] **Step 1: Read both files before editing**

Read `src/components/log-view/LogListView.tsx` and `src/components/log-view/LogRow.tsx` to understand the current rendering code, virtualizer setup, and row component props.

- [ ] **Step 2: Add section divider row rendering in LogListView**

In `LogListView.tsx`, modify the row rendering logic (where `LogRow` is mapped from virtual items). Before rendering a `LogRow`, check if the entry has `entryKind === "Section"` or `entryKind === "Iteration"`. If so, render a section divider instead:

```tsx
// Inside the virtualizer row map
const entry = displayEntries[virtualRow.index];

if (entry.entryKind === "Section" || entry.entryKind === "Iteration") {
  return (
    <div
      key={virtualRow.key}
      data-index={virtualRow.index}
      ref={virtualizer.measureElement}
      style={{
        position: "absolute",
        top: 0,
        left: 0,
        width: "100%",
        transform: `translateY(${virtualRow.start}px)`,
      }}
    >
      <SectionDividerRow entry={entry} />
    </div>
  );
}
```

Create a `SectionDividerRow` component inline or in a separate file:

```tsx
function SectionDividerRow({ entry }: { entry: LogEntry }) {
  const bgColor = entry.sectionColor ?? "#3b82f6";
  const isIteration = entry.entryKind === "Iteration";

  return (
    <div
      style={{
        padding: "4px 12px",
        background: bgColor + "22", // 13% opacity tint
        borderLeft: `4px solid ${bgColor}`,
        color: bgColor,
        fontWeight: 600,
        fontSize: "12px",
        letterSpacing: "0.3px",
        display: "flex",
        alignItems: "center",
        gap: "8px",
      }}
    >
      <span>{isIteration ? "\u25B6" : "\u25CF"}</span>
      <span>{entry.message}</span>
      {entry.iteration && (
        <span style={{ opacity: 0.7, fontWeight: 400 }}>
          {entry.iteration}
        </span>
      )}
    </div>
  );
}
```

- [ ] **Step 3: Add left-edge band to regular LogRow entries**

In `LogRow.tsx`, add a conditional left border based on `sectionColor`:

Find the outermost `<div>` of the row that applies the row styles. Add to its style:

```tsx
borderLeft: entry.sectionColor ? `4px solid ${entry.sectionColor}` : undefined,
```

Note: This interacts with the marker border — per the spec, marker color takes priority. This will be handled in Task 8 when marker gutter is added. For now, section band is the only left border.

- [ ] **Step 3a: Add auto-color palette for sections without explicit color**

When a section has no `color` attribute, the frontend should auto-assign from a palette. In `LogListView.tsx`, add a palette and assignment:

```tsx
const SECTION_PALETTE = [
  "#3b82f6", "#a78bfa", "#f59e0b", "#10b981",
  "#ef4444", "#ec4899", "#06b6d4", "#84cc16",
];

// Track section→color mapping for sections without explicit colors
const sectionColorMap = useMemo(() => {
  const map = new Map<string, string>();
  let paletteIdx = 0;
  for (const entry of displayEntries) {
    if (
      (entry.entryKind === "Section" || entry.entryKind === "Iteration") &&
      !entry.sectionColor &&
      entry.message
    ) {
      if (!map.has(entry.message)) {
        map.set(entry.message, SECTION_PALETTE[paletteIdx % SECTION_PALETTE.length]);
        paletteIdx++;
      }
    }
  }
  return map;
}, [displayEntries]);
```

Apply the auto-assigned color when rendering `SectionDividerRow` and when computing left-edge band color:

```tsx
const effectiveColor = entry.sectionColor ?? sectionColorMap.get(entry.sectionName ?? entry.message) ?? undefined;
```

- [ ] **Step 4: Run TypeScript check**

Run: `npx tsc --noEmit` from project root.
Expected: No type errors.

- [ ] **Step 5: Test visually**

Run: `npm run app:dev` and open the `basic.cmtlog` fixture file in CMTrace Open.
Expected: Section divider banner rows appear with colored left bands. Regular entries within a section show the left-edge color band. Sections without explicit colors get auto-assigned palette colors.

- [ ] **Step 6: Commit**

```bash
git add src/components/log-view/LogListView.tsx src/components/log-view/LogRow.tsx
git commit -m "feat(ui): add section divider rows, left-edge bands, and auto-color palette for cmtlog"
```

---

## Task 8: Marker Gutter UI

**Files:**
- Modify: `src/components/log-view/LogRow.tsx`
- Modify: `src/components/log-view/LogListView.tsx`

- [ ] **Step 1: Read both files before editing**

Re-read `LogRow.tsx` and `LogListView.tsx` to see current state after Task 7 changes.

- [ ] **Step 2: Add marker gutter to LogRow**

In `LogRow.tsx`, add a new prop for marker data:

```tsx
// Add to LogRowProps interface
marker?: Marker | null;
onToggleMarker?: (lineId: number) => void;
onMarkerContextMenu?: (lineId: number, event: React.MouseEvent) => void;
```

Add a gutter element as the first child of the row:

```tsx
<div
  style={{
    width: "20px",
    minWidth: "20px",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    cursor: "pointer",
  }}
  onClick={(e) => {
    e.stopPropagation();
    onToggleMarker?.(entry.id);
  }}
  onContextMenu={(e) => {
    e.stopPropagation();
    onMarkerContextMenu?.(entry.id, e);
  }}
>
  <div
    style={{
      width: 8,
      height: 8,
      borderRadius: "50%",
      background: marker ? marker.color : "transparent",
      border: marker ? "none" : "1px solid transparent",
      transition: "background 0.15s",
    }}
  />
</div>
```

Add marker row tint — if a marker exists, overlay a subtle background:

```tsx
// On the row container style
background: marker
  ? `${marker.color}18` // ~9% opacity
  : existingBackground,
borderLeft: marker
  ? `3px solid ${marker.color}`
  : entry.sectionColor
    ? `4px solid ${entry.sectionColor}`
    : undefined,
```

This implements the visual precedence rule: marker border wins over section band.

- [ ] **Step 3: Wire marker store into LogListView**

In `LogListView.tsx`, import and use the marker store:

```tsx
import { useMarkerStore } from "../../stores/marker-store";

// Inside the component
const activeTab = useUiStore((s) => s.openTabs[s.activeTabIndex]);
const filePath = activeTab?.filePath ?? "";
const markersForFile = useMarkerStore((s) => s.getMarkersForFile(filePath));
const toggleMarker = useMarkerStore((s) => s.toggleMarker);
const saveMarkers = useMarkerStore((s) => s.saveMarkers);
const loadMarkers = useMarkerStore((s) => s.loadMarkers);

// Load markers when tab changes
useEffect(() => {
  if (filePath) {
    loadMarkers(filePath);
  }
}, [filePath, loadMarkers]);

// Auto-save markers on changes (debounced)
useEffect(() => {
  if (!filePath) return;
  const timeout = setTimeout(() => {
    saveMarkers(filePath);
  }, 1000);
  return () => clearTimeout(timeout);
}, [markersForFile, filePath, saveMarkers]);
```

Pass marker data to each `LogRow`:

```tsx
<LogRow
  // ...existing props
  marker={markersForFile.get(entry.id) ?? null}
  onToggleMarker={(lineId) => toggleMarker(filePath, lineId)}
/>
```

- [ ] **Step 4: Add Ctrl+M keyboard shortcut**

In `LogListView.tsx`, add a keyboard handler for `Ctrl+M`:

```tsx
useEffect(() => {
  const handleKeyDown = (e: KeyboardEvent) => {
    if (e.ctrlKey && e.key === "m") {
      e.preventDefault();
      const selectedId = activeTab?.selectedLineId;
      if (selectedId != null && filePath) {
        toggleMarker(filePath, selectedId);
      }
    }
  };
  window.addEventListener("keydown", handleKeyDown);
  return () => window.removeEventListener("keydown", handleKeyDown);
}, [activeTab?.selectedLineId, filePath, toggleMarker]);
```

- [ ] **Step 5: Add right-click context menu for marker categories**

In `LogListView.tsx`, add a context menu state and handler for the marker gutter. When the user right-clicks the gutter, show a menu with marker categories:

```tsx
const [markerMenuAnchor, setMarkerMenuAnchor] = useState<{
  x: number;
  y: number;
  lineId: number;
} | null>(null);

const categories = useMarkerStore((s) => s.categories);
const setMarkerCategory = useMarkerStore((s) => s.setMarkerCategory);
const setActiveCategory = useMarkerStore((s) => s.setActiveCategory);
```

Render the context menu (use Fluent UI `MenuList` + `MenuPopover` or a simple positioned `<div>`):

```tsx
{markerMenuAnchor && (
  <div
    style={{
      position: "fixed",
      top: markerMenuAnchor.y,
      left: markerMenuAnchor.x,
      background: "var(--colorNeutralBackground1)",
      border: "1px solid var(--colorNeutralStroke1)",
      borderRadius: 4,
      padding: "4px 0",
      zIndex: 1000,
      boxShadow: "0 4px 12px rgba(0,0,0,0.3)",
    }}
    onMouseLeave={() => setMarkerMenuAnchor(null)}
  >
    {categories.map((cat) => (
      <div
        key={cat.id}
        style={{
          padding: "6px 16px",
          cursor: "pointer",
          display: "flex",
          alignItems: "center",
          gap: 8,
          fontSize: 13,
        }}
        onClick={() => {
          toggleMarker(filePath, markerMenuAnchor.lineId);
          // If toggling on, set to this category
          setActiveCategory(cat.id);
          setMarkerCategory(filePath, markerMenuAnchor.lineId, cat.id);
          setMarkerMenuAnchor(null);
        }}
      >
        <div
          style={{
            width: 10,
            height: 10,
            borderRadius: "50%",
            background: cat.color,
          }}
        />
        {cat.label}
      </div>
    ))}
  </div>
)}
```

Pass the context menu handler to `LogRow`:

```tsx
<LogRow
  // ...existing props
  onMarkerContextMenu={(lineId, event) => {
    event.preventDefault();
    setMarkerMenuAnchor({ x: event.clientX, y: event.clientY, lineId });
  }}
/>
```

- [ ] **Step 6: Run TypeScript check**

Run: `npx tsc --noEmit` from project root.
Expected: No type errors.

- [ ] **Step 7: Test visually**

Run: `npm run app:dev`, open any log file, click the gutter area or press Ctrl+M to toggle markers. Right-click the gutter for category selection. Close and reopen the file — markers should persist.

- [ ] **Step 8: Commit**

```bash
git add src/components/log-view/LogRow.tsx src/components/log-view/LogListView.tsx
git commit -m "feat(ui): add marker gutter, category context menu, and Ctrl+M shortcut"
```

---

## Task 9: WhatIf Rendering

**Files:**
- Modify: `src/components/log-view/LogRow.tsx`
- Modify: `src/stores/filter-store.ts`

- [ ] **Step 1: Read both files before editing**

Re-read `LogRow.tsx` and `filter-store.ts` to see current state.

- [ ] **Step 2: Add WhatIf styling to LogRow**

In `LogRow.tsx`, add conditional styling for WhatIf entries. On the row container:

```tsx
const isWhatIf = entry.whatif === true;

// Apply to the row's style
opacity: isWhatIf ? 0.6 : 1,
fontStyle: isWhatIf ? "italic" : "normal",
```

Add a WhatIf badge next to the severity indicator. Find where the severity dot is rendered and add after it:

```tsx
{isWhatIf && (
  <span
    style={{
      fontSize: "9px",
      fontWeight: 600,
      color: "#a78bfa",
      background: "#a78bfa22",
      borderRadius: "3px",
      padding: "1px 4px",
      marginLeft: "4px",
      fontStyle: "normal",
      letterSpacing: "0.3px",
    }}
  >
    WhatIf
  </span>
)}
```

- [ ] **Step 3: Add WhatIf filter to filter store**

In `src/stores/filter-store.ts`, add a `whatIfFilter` field to the state:

```typescript
// Add to FilterState interface
whatIfFilter: "all" | "whatif-only" | "real-only";
setWhatIfFilter: (filter: "all" | "whatif-only" | "real-only") => void;
```

Add to the store creation:

```typescript
whatIfFilter: "all",
setWhatIfFilter: (filter) => set({ whatIfFilter: filter }),
```

- [ ] **Step 4: Apply WhatIf filter in the filtering logic**

Find where `filteredIds` is computed in the filtering pipeline. Add WhatIf filtering:

```typescript
// After existing filter logic
const whatIfFilter = get().whatIfFilter;
if (whatIfFilter !== "all") {
  // Apply to the filtered entries
  filteredEntries = filteredEntries.filter((entry) => {
    if (whatIfFilter === "whatif-only") return entry.whatif === true;
    if (whatIfFilter === "real-only") return entry.whatif !== true;
    return true;
  });
}
```

Note: The exact integration point depends on how the filter pipeline is structured. Read the current code and wire it into the appropriate place.

- [ ] **Step 5: Run TypeScript check**

Run: `npx tsc --noEmit` from project root.
Expected: No type errors.

- [ ] **Step 6: Test visually**

Run: `npm run app:dev`, open the `basic.cmtlog` fixture. The "Would apply policy contoso.xml" entry should appear dimmed, italic, with a purple "WhatIf" badge.

- [ ] **Step 7: Commit**

```bash
git add src/components/log-view/LogRow.tsx src/stores/filter-store.ts
git commit -m "feat(ui): add WhatIf visual treatment (dimmed, italic, badge) and filter toggle"
```

---

## Task 10: Multi-Select and Copy

**Files:**
- Modify: `src/components/log-view/LogListView.tsx`
- Modify: `src/components/log-view/LogRow.tsx`

- [ ] **Step 1: Read both files before editing**

Re-read `LogListView.tsx` and `LogRow.tsx` to see current state.

- [ ] **Step 2: Add multi-select state to LogListView**

Add state for tracking selected IDs:

```tsx
const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set());
const lastClickedId = useRef<number | null>(null);
```

Create a click handler with multi-select logic:

```tsx
const handleRowClick = useCallback(
  (id: number, event: React.MouseEvent) => {
    if (event.ctrlKey || event.metaKey) {
      // Toggle individual line
      setSelectedIds((prev) => {
        const next = new Set(prev);
        if (next.has(id)) {
          next.delete(id);
        } else {
          next.add(id);
        }
        return next;
      });
      lastClickedId.current = id;
    } else if (event.shiftKey && lastClickedId.current != null) {
      // Range select
      const allIds = displayEntries.map((e) => e.id);
      const startIdx = allIds.indexOf(lastClickedId.current);
      const endIdx = allIds.indexOf(id);
      if (startIdx !== -1 && endIdx !== -1) {
        const [lo, hi] = startIdx < endIdx ? [startIdx, endIdx] : [endIdx, startIdx];
        const rangeIds = allIds.slice(lo, hi + 1);
        setSelectedIds((prev) => {
          const next = new Set(prev);
          for (const rid of rangeIds) {
            next.add(rid);
          }
          return next;
        });
      }
      lastClickedId.current = id;
    } else {
      // Single select — clear others
      setSelectedIds(new Set([id]));
      lastClickedId.current = id;
    }

    // Also update the existing single-selection for details pane etc.
    // Keep existing onClick behavior for the primary selection
  },
  [displayEntries]
);
```

- [ ] **Step 3: Add Ctrl+A handler**

Add to the existing keyboard handler:

```tsx
if ((e.ctrlKey || e.metaKey) && e.key === "a") {
  e.preventDefault();
  const allIds = new Set(displayEntries.map((entry) => entry.id));
  setSelectedIds(allIds);
}
```

- [ ] **Step 4: Add Ctrl+C copy handler**

```tsx
if ((e.ctrlKey || e.metaKey) && e.key === "c" && selectedIds.size > 0) {
  e.preventDefault();
  // Get messages in display order
  const selectedMessages = displayEntries
    .filter((entry) => selectedIds.has(entry.id))
    .map((entry) => entry.message);
  const text = selectedMessages.join("\n");
  navigator.clipboard.writeText(text);
}
```

- [ ] **Step 5: Pass multi-select state to LogRow**

Add prop to LogRow:

```tsx
// Add to LogRowProps
isMultiSelected?: boolean;
```

In the row container styling, add a multi-select highlight that doesn't conflict with marker tinting:

```tsx
// Multi-select gets a distinct outline/background
outline: isMultiSelected ? "1px solid rgba(59, 130, 246, 0.5)" : undefined,
background: isMultiSelected && !marker
  ? "rgba(59, 130, 246, 0.08)"
  : existingBackground,
```

Pass from `LogListView`:

```tsx
<LogRow
  // ...existing props
  isMultiSelected={selectedIds.has(entry.id)}
  onClick={(id) => handleRowClick(id, event)}
/>
```

Note: The click event needs to be passed through. Read how the existing `onClick` prop works on `LogRow` and adapt `handleRowClick` to receive the event. This may require changing the `onClick` signature from `(id: number) => void` to `(id: number, event: React.MouseEvent) => void`.

- [ ] **Step 6: Add "Copy marked lines" context menu option**

In the existing right-click context menu for the log view (find where `onContextMenu` is handled in `LogListView.tsx`), add options for each marker category:

```tsx
// Inside the context menu rendering
const getMarkedLineIds = useMarkerStore((s) => s.getMarkedLineIds);

// Add menu items for each category
{categories.map((cat) => {
  const markedIds = getMarkedLineIds(filePath, cat.id);
  if (markedIds.length === 0) return null;
  return (
    <div
      key={`copy-${cat.id}`}
      style={{ padding: "6px 16px", cursor: "pointer", fontSize: 13 }}
      onClick={() => {
        const markedIdSet = new Set(markedIds);
        const messages = displayEntries
          .filter((e) => markedIdSet.has(e.id))
          .map((e) => e.message);
        navigator.clipboard.writeText(messages.join("\n"));
        // Close menu
      }}
    >
      Copy all "{cat.label}" lines ({markedIds.length})
    </div>
  );
})}
```

- [ ] **Step 7: Run TypeScript check**

Run: `npx tsc --noEmit` from project root.
Expected: No type errors.

- [ ] **Step 8: Test visually**

Run: `npm run app:dev`, open a log file:
- Click a row -> single select
- Ctrl+Click -> toggle additional rows
- Shift+Click -> range select
- Ctrl+A -> select all visible
- Ctrl+C -> copies messages to clipboard
- Right-click -> "Copy all Bug lines" copies only marked lines

- [ ] **Step 9: Commit**

```bash
git add src/components/log-view/LogListView.tsx src/components/log-view/LogRow.tsx
git commit -m "feat(ui): add multi-select copy and copy-by-marker-category context menu"
```

---

## Task 11: File Association Registration

**Files:**
- Modify: `src-tauri/tauri.conf.json`

- [ ] **Step 1: Read the current config**

Read `src-tauri/tauri.conf.json` to find the `fileAssociations` array.

- [ ] **Step 2: Add `.cmtlog` extension**

Add to the `fileAssociations` array:

```json
{
  "ext": ["cmtlog"],
  "mimeType": "text/plain",
  "description": "CMTrace Open Log File"
}
```

- [ ] **Step 3: Update workspace file filters**

Find the Log workspace definition in `src/workspaces/log/index.ts` (or wherever `fileFilters` is defined for the log workspace). Add `"cmtlog"` to the extensions list:

```typescript
fileFilters: [
  { name: "Log Files", extensions: ["log", "cmtlog"] },
  // ...existing filters
],
```

Note: Read the exact file first to confirm the location and structure.

- [ ] **Step 4: Run cargo check**

Run: `cargo check` from `src-tauri/`
Expected: No errors.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/tauri.conf.json src/workspaces/log/index.ts
git commit -m "feat(config): register .cmtlog file association and add to file picker filters"
```

---

## Task 12: PowerShell Module

**Files:**
- Create: `scripts/powershell/CmtLog/CmtLog.psm1`

- [ ] **Step 1: Create directory structure**

Run: `mkdir -p scripts/powershell/CmtLog` from project root.

- [ ] **Step 2: Create the module**

Create `scripts/powershell/CmtLog/CmtLog.psm1`:

```powershell
<#
.SYNOPSIS
    CmtLog PowerShell module for writing .cmtlog format files compatible with CMTrace Open.

.DESCRIPTION
    Provides functions for structured log output in the .cmtlog format:
    - Start-CmtLog: Initialize a new log file with header
    - Write-LogEntry: Write a log line with optional extended attributes
    - Write-LogSection: Write a section divider
    - Write-LogIteration: Write a loop iteration marker
    - Write-LogHeader: Write a file header (called by Start-CmtLog)
#>

# Module-level state
$script:CmtLogFilePath = $null

function Get-CmtLogTimestamp {
    [CmdletBinding()]
    param()
    $Bias = (Get-CimInstance -ClassName Win32_TimeZone | Select-Object -ExpandProperty Bias)
    $Time = (Get-Date -Format "HH:mm:ss.fff") + "{0:+0;-0;+0}" -f $Bias
    $Date = (Get-Date -Format "MM-dd-yyyy")
    return @{ Time = $Time; Date = $Date }
}

function Write-LogHeader {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptName,

        [Parameter(Mandatory = $false)]
        [string]$Version = "1.0.0",

        [Parameter(Mandatory = $false)]
        [ValidateSet("Normal", "WhatIf", "Verbose")]
        [string]$Mode,

        [Parameter(Mandatory = $false)]
        [string]$FileName = $script:CmtLogFilePath
    )

    if (-not $Mode) {
        if ($WhatIfPreference) { $Mode = "WhatIf" }
        elseif ($VerbosePreference -ne "SilentlyContinue") { $Mode = "Verbose" }
        else { $Mode = "Normal" }
    }

    $ts = Get-CmtLogTimestamp
    $RunId = [guid]::NewGuid().ToString("N").Substring(0, 8)
    $PsVer = $PSVersionTable.PSVersion.ToString()

    $LogText = "<![LOG[Script started: $ScriptName v$Version]LOG]!>" +
        "<time=""$($ts.Time)"" date=""$($ts.Date)"" component=""__HEADER__"" " +
        "context="""" type=""1"" thread=""0"" file="""" " +
        "script=""$ScriptName"" version=""$Version"" runid=""$RunId"" " +
        "mode=""$Mode"" ps_version=""$PsVer"">"

    Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $FileName -ErrorAction Stop
}

function Start-CmtLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptName,

        [Parameter(Mandatory = $false)]
        [string]$Version = "1.0.0",

        [Parameter(Mandatory = $false)]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Normal", "WhatIf", "Verbose")]
        [string]$Mode
    )

    if (-not $OutputPath) {
        $OutputPath = Join-Path -Path $env:ProgramData -ChildPath "CMTraceOpen\Logs"
    }

    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    $SafeName = $ScriptName -replace '[^\w\-\.]', '_'
    $Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $FileName = "${SafeName}_${Timestamp}.cmtlog"
    $FullPath = Join-Path -Path $OutputPath -ChildPath $FileName

    $script:CmtLogFilePath = $FullPath

    Write-LogHeader -ScriptName $ScriptName -Version $Version -Mode $Mode -FileName $FullPath

    return $FullPath
}

function Write-LogEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Value,

        [Parameter(Mandatory = $true)]
        [ValidateSet("1", "2", "3")]
        [string]$Severity,

        [Parameter(Mandatory = $false)]
        [string]$Component = "Script",

        [Parameter(Mandatory = $false)]
        [string]$FileName = $script:CmtLogFilePath,

        [Parameter(Mandatory = $false)]
        [string]$Section,

        [Parameter(Mandatory = $false)]
        [string[]]$Tag,

        [Parameter(Mandatory = $false)]
        [switch]$WhatIfEntry,

        [Parameter(Mandatory = $false)]
        [string]$Iteration
    )

    $ts = Get-CmtLogTimestamp
    $Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)

    $ExtAttrs = ""
    if ($Section) { $ExtAttrs += " section=""$Section""" }
    if ($Tag) { $ExtAttrs += " tag=""$($Tag -join ',')""" }
    if ($WhatIfEntry) { $ExtAttrs += ' whatif="1"' }
    if ($Iteration) { $ExtAttrs += " iteration=""$Iteration""" }

    $LogText = "<![LOG[$Value]LOG]!>" +
        "<time=""$($ts.Time)"" date=""$($ts.Date)"" component=""$Component"" " +
        "context=""$Context"" type=""$Severity"" thread=""$PID"" file=""""$ExtAttrs>"

    try {
        Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $FileName -ErrorAction Stop
        if ($Severity -eq "1") { Write-Verbose -Message $Value }
        elseif ($Severity -eq "3") { Write-Warning -Message $Value }
    }
    catch [System.Exception] {
        Write-Warning -Message "Unable to append log entry to $FileName. Error: $($_.Exception.Message)"
    }
}

function Write-LogSection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [string]$Color,

        [Parameter(Mandatory = $false)]
        [string]$FileName = $script:CmtLogFilePath
    )

    $ts = Get-CmtLogTimestamp
    $ColorAttr = if ($Color) { " color=""$Color""" } else { "" }

    $LogText = "<![LOG[$Name]LOG]!>" +
        "<time=""$($ts.Time)"" date=""$($ts.Date)"" component=""__SECTION__"" " +
        "context="""" type=""1"" thread=""0"" file=""""$ColorAttr>"

    Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $FileName -ErrorAction Stop
}

function Write-LogIteration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [int]$Current,

        [Parameter(Mandatory = $true)]
        [int]$Total,

        [Parameter(Mandatory = $false)]
        [string]$Color,

        [Parameter(Mandatory = $false)]
        [string]$FileName = $script:CmtLogFilePath
    )

    $ts = Get-CmtLogTimestamp
    $IterStr = "$Current/$Total"
    $ColorAttr = if ($Color) { " color=""$Color""" } else { "" }

    $LogText = "<![LOG[Loop Iteration $IterStr - $Name]LOG]!>" +
        "<time=""$($ts.Time)"" date=""$($ts.Date)"" component=""__ITERATION__"" " +
        "context="""" type=""1"" thread=""0"" file="""" " +
        "iteration=""$IterStr""$ColorAttr>"

    Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $FileName -ErrorAction Stop
}

Export-ModuleMember -Function Start-CmtLog, Write-LogEntry, Write-LogSection, Write-LogIteration, Write-LogHeader
```

- [ ] **Step 3: Commit**

```bash
git add scripts/powershell/CmtLog/CmtLog.psm1
git commit -m "feat(powershell): add CmtLog module with Start-CmtLog, Write-LogEntry, Write-LogSection, Write-LogIteration"
```

---

## Task 13: Final Integration Verification

**Files:** None (verification only)

- [ ] **Step 1: Run full Rust checks**

Run from `src-tauri/`:
```bash
cargo check && cargo test && cargo clippy -- -D warnings
```
Expected: All checks pass, all tests pass, no warnings.

- [ ] **Step 2: Run TypeScript check**

Run from project root:
```bash
npx tsc --noEmit
```
Expected: No type errors.

- [ ] **Step 3: Run the full app**

Run: `npm run app:dev`

Test the following:
1. Open `src-tauri/tests/fixtures/cmtlog/basic.cmtlog` — should detect CmtLog parser
2. Section dividers render as banner rows with left-edge color bands
3. WhatIf entry appears dimmed, italic, with badge
4. Click gutter to toggle markers — colored dots and row tinting appear
5. Close and reopen the file — markers persist
6. Ctrl+Click to multi-select, Ctrl+C to copy, paste into notepad to verify plain text
7. Ctrl+M to toggle marker on selected row

- [ ] **Step 4: Final commit if any fixes needed**

Fix any issues found during integration testing and commit them individually.
