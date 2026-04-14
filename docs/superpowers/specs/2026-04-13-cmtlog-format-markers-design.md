# CMTrace Open: `.cmtlog` Format, Markers, and PowerShell Integration

**Issue:** #117
**Date:** 2026-04-13
**Approach:** Format-First — design the file format, then parser, then UI features

---

## Overview

Five features that form a cohesive system for PowerShell-driven log authoring and interactive log analysis:

1. **`.cmtlog` file format** — extends CCM's `<![LOG[...]LOG]!>` structure with metadata for sections, loops, WhatIf, and custom tags
2. **User markers** — color-coded annotations (Bug, Investigate, Confirmed) placed on log entries, persisted to AppData by file path
3. **Section dividers** — full-width banner rows + colored left-edge bands for visual grouping of phases and loop iterations
4. **Multi-select copy** — Ctrl+Click / Shift+Click line selection, Ctrl+C copies raw message text
5. **WhatIf rendering** — dimmed italic lines with a badge for simulated actions

---

## 1. `.cmtlog` File Format

### Design Principles

- Every line uses `<![LOG[...]LOG]!>` — fully backward-compatible with CMTrace.exe
- Structural markers use reserved component names — CMTrace.exe shows them as normal log lines
- Extended attributes on standard CCM lines are ignored by legacy parsers
- File extension `.cmtlog` triggers the enhanced parser in CMTrace Open

### File Header

A single `<![LOG[` line with reserved component `__HEADER__`, written once at script start:

```
<![LOG[Script started: Detect-WDAC.ps1 v2.1.0]LOG]!><time="10:30:00.000+000" date="04-13-2026" component="__HEADER__" context="" type="1" thread="0" file="" script="Detect-WDAC.ps1" version="2.1.0" runid="a3f8c9e1" mode="WhatIf" ps_version="7.4.2">
```

Header attributes:
- `script` — script filename
- `version` — script version
- `runid` — unique execution ID (for correlating runs)
- `mode` — execution mode (`"WhatIf"`, `"Verbose"`, `"Normal"`)
- `ps_version` — PowerShell version

If absent, the file is still valid `.cmtlog` — headerless.

### Log Entries

Standard CCM log lines with optional extended attributes:

```
<![LOG[Checking WDAC policy for contoso.xml]LOG]!><time="10:32:01.123+000" date="04-13-2026" component="Detect-WDAC" context="CONTOSO\admin" type="1" thread="1234" file="" section="detection" tag="phase:scan" whatif="0">
```

Extended attributes (all optional, ignored by CMTrace.exe):
- `section` — names the current section/phase (drives left-edge band coloring)
- `tag` — freeform key:value metadata for custom categories
- `whatif` — `"1"` for simulated actions, `"0"` or absent for real
- `iteration` — loop counter string, e.g., `"2/5"`

### Section Control Lines

Section and iteration boundaries use reserved component names:

```
<![LOG[Detection Phase]LOG]!><time="10:32:01.000+000" date="04-13-2026" component="__SECTION__" context="" type="1" thread="0" file="" color="#5b9aff">
<![LOG[Loop Iteration 2/5 - WDAC policies]LOG]!><time="10:32:02.000+000" date="04-13-2026" component="__ITERATION__" context="" type="1" thread="0" file="" iteration="2/5" color="#a78bfa">
```

Reserved components:
- `__HEADER__` — file-level metadata (parsed once, shown in file info panel)
- `__SECTION__` — phase/section divider (rendered as full-width banner row, starts left-edge band on subsequent lines)
- `__ITERATION__` — loop iteration boundary (rendered as banner row, inherits parent section color)

Optional `color` attribute allows scripts to specify section band colors as hex values. If absent, CMTrace Open auto-assigns from a default palette.

### Backward Compatibility

- CMTrace.exe reads all lines normally (ignores unknown attributes and shows reserved components as regular entries)
- CMTrace Open auto-detects `.cmtlog` extension and uses the enhanced parser
- Notepad/plain text editors can read the file — it's still text with the familiar CCM structure

---

## 2. User Markers

### Interaction

Three ways to place a marker on a log entry:
- **Gutter click** — click the left gutter area of a row (like IDE breakpoints)
- **Right-click context menu** — "Toggle Marker" with category submenu
- **Keyboard shortcut** — `Ctrl+M` while a row is selected

### Visual Rendering

Color-coded categories with:
- **Gutter dot** — colored circle in the left gutter matching the category
- **Row tint** — subtle background highlight in the category color
- **Left border** — 3px colored left border on marked rows

**Visual precedence:** When a marked line is also inside a section (both marker left-border and section left-edge band apply), the marker color takes priority on the left border since it represents user intent. The section band shifts to a secondary indicator (e.g., a thin 2px band outside the marker border, or the row tint carries the section color while the border carries the marker color).

### Default Categories

| ID | Label | Color |
|----|-------|-------|
| `bug` | Bug | `#ef4444` (red) |
| `investigate` | Investigate | `#60a5fa` (blue) |
| `confirmed` | Confirmed | `#4ade80` (green) |

Users can add custom categories via UI or right-click submenu.

### Persistence

Markers are stored in the OS app data directory, keyed by SHA-256 hash of the **file path**:

- **Windows:** `%APPDATA%\cmtrace-open\markers\<hash>.json`
- **macOS:** `~/Library/Application Support/cmtrace-open/markers/<hash>.json`
- **Linux:** `~/.local/share/cmtrace-open/markers/<hash>.json`

Tauri provides the base directory via `app_data_dir()`.

### Marker File Schema

```json
{
  "version": 1,
  "source_path": "C:\\ProgramData\\...\\Detect-WDAC.log",
  "source_size": 48230,
  "created": "2026-04-13T10:45:00Z",
  "modified": "2026-04-13T11:02:00Z",
  "markers": [
    {
      "line_id": 42,
      "category": "bug",
      "color": "#ef4444",
      "added": "2026-04-13T10:45:12Z"
    }
  ],
  "categories": [
    { "id": "bug", "label": "Bug", "color": "#ef4444" },
    { "id": "investigate", "label": "Investigate", "color": "#60a5fa" },
    { "id": "confirmed", "label": "Confirmed", "color": "#4ade80" }
  ]
}
```

### Tailing Behavior

- Markers are held in memory during active tailing sessions
- Flushed to disk when tailing stops or the tab closes
- File path hash is stable during tailing, so markers survive appends
- `source_size` field tracks last-known file size — if current size is smaller on next open, show a warning: "File appears to have been truncated since markers were added"

---

## 3. Section Dividers and Left-Edge Bands

### Divider Rows

When the parser encounters a `__SECTION__` or `__ITERATION__` component:
- Render a **full-width banner row** spanning all columns
- Banner uses the section's color as background with contrasting text
- Shows the section name and iteration info (e.g., "Loop Iteration 2/5 — WDAC policies")

### Left-Edge Bands

All log entries following a section marker get a **4px colored left border** in the section's color, until the next section marker or end of file. This provides persistent visual grouping — you can scan the left edge and see phase boundaries at a glance.

### Color Assignment

- Scripts can specify colors via the `color` attribute on section lines
- If no color specified, CMTrace Open assigns from a built-in palette that cycles through distinct, accessible colors
- Nested sections (iteration within a section) use the iteration's color if specified, otherwise inherit the parent section's color

---

## 4. Multi-Select and Copy

### Selection

- **Click** — selects a single line, clears previous selection
- **Ctrl+Click** — toggles a line in/out of selection (additive)
- **Shift+Click** — selects a range from last selected line to clicked line
- **Ctrl+A** — selects all visible lines (respects active filters)

Selected lines get a distinct highlight (border or background shade) that doesn't conflict with marker tinting.

### Copy

- **Ctrl+C** with multi-selection — copies selected lines as plain text, one per line, in log order
- Copies the `message` field only (raw log text), not timestamps or column data
- Lines joined with `\n`

### Convenience: Copy by Marker Category

Right-click context menu or command palette: "Copy all lines marked as [Bug/Investigate/Confirmed]" — selects and copies all lines in a specific marker category without manual multi-selection.

---

## 5. WhatIf Rendering

### Visual Treatment

Log entries with `whatif="1"` are rendered with:
- **Dimmed opacity** (~60%) — communicates "this didn't really happen"
- **Italic text** on the message
- **"WhatIf" badge** — small label near the severity column

### Filtering

The filter system gains a WhatIf toggle:
- **Show all** (default) — WhatIf and real lines together, visually differentiated
- **WhatIf only** — isolate simulated actions
- **Real only** — hide WhatIf lines

---

## 6. Parser and Format Detection

### New Module: `src-tauri/src/parser/cmtlog.rs`

- Reuses CCM parser's line-level `<![LOG[...]LOG]!>` parsing logic
- Extracts extended attributes: `section`, `tag`, `whatif`, `iteration`, `color`, `script`, `version`, `runid`, `mode`
- Recognizes reserved components: `__HEADER__`, `__SECTION__`, `__ITERATION__`
- Maps reserved components into `EntryKind` enum values

### Detection (in `detect.rs`)

Two-tier:
1. **Extension match** — `.cmtlog` → immediately select CmtLog parser
2. **Content fallback** — if a `.log` file contains `__SECTION__`, `__HEADER__`, or `__ITERATION__` components in the first 50 lines, upgrade to CmtLog parser

### ResolvedParser Configuration

| Field | Value |
|-------|-------|
| `ParserKind` | `CmtLog` |
| `ParserImplementation` | `CmtLog` |
| `ParseQuality` | `Structured` |
| `RecordFraming` | `PhysicalLine` |
| `ParserSpecialization` | `None` |

### LogEntry Extensions

New optional fields on `LogEntry` (skip-serialized when `None`):

- `entry_kind: Option<EntryKind>` — `Log` (default), `Section`, `Iteration`, `Header`
- `whatif: Option<bool>`
- `section_name: Option<String>` — current section name (for left-edge band)
- `section_color: Option<String>` — hex color for the band
- `iteration: Option<String>` — e.g., `"2/5"`
- `tags: Option<Vec<String>>` — freeform tags from `tag` attribute

All optional — existing parsers are unaffected.

---

## 7. PowerShell Module

### Location

`scripts/powershell/CmtLog/CmtLog.psm1` in the CMTrace Open repository.

### Functions

**`Start-CmtLog`** — creates the log file, writes the `__HEADER__` line, returns the file path.
- Parameters: `-ScriptName`, `-Version`, `-OutputPath` (optional), `-Mode` (auto-detects `$WhatIfPreference`)

**`Write-LogEntry`** — upgraded from existing function, emits a standard log line with optional extended attributes.
- Existing parameters: `-Value`, `-Severity`, `-Component`, `-FileName`
- New parameters: `-Section`, `-Tag`, `-WhatIfEntry`, `-Iteration`

**`Write-LogSection`** — emits a `__SECTION__` line.
- Parameters: `-Name`, `-Color` (optional)

**`Write-LogIteration`** — emits an `__ITERATION__` line.
- Parameters: `-Name`, `-Current`, `-Total`, `-Color` (optional)

**`Write-LogHeader`** — emits a `__HEADER__` line (called by `Start-CmtLog`, also available standalone).
- Parameters: `-ScriptName`, `-Version`, `-Mode`

### Example Usage

```powershell
$LogFile = Start-CmtLog -ScriptName "Detect-WDAC" -Version "2.1.0"

Write-LogSection -Name "Detection Phase" -Color "#5b9aff"

Write-LogEntry -Value "Scanning policy files" -Severity 1 -Section "Detection" -Tag "phase:scan"

foreach ($i in 1..5) {
    Write-LogIteration -Name "WDAC Policy" -Current $i -Total 5

    Write-LogEntry -Value "Processing policy $i" -Severity 1 -Iteration "$i/5"

    if ($WhatIfPreference) {
        Write-LogEntry -Value "Would apply policy $i" -Severity 1 -WhatIfEntry
    }
}

Write-LogSection -Name "Remediation Phase" -Color "#4ade80"
```

### Distribution

Standalone `.psm1` file. Users `Import-Module ./CmtLog.psm1` or copy functions into their scripts. PSGallery publication is out of scope for the initial release.

---

## Implementation Order (Format-First)

1. **`.cmtlog` format spec + parser** — `cmtlog.rs`, detection in `detect.rs`, `LogEntry` extensions
2. **PowerShell module** — `CmtLog.psm1` with all helper functions
3. **Marker system** — backend persistence (Rust commands for load/save), frontend store, gutter UI
4. **Section rendering** — divider banner rows + left-edge bands in the log view
5. **WhatIf rendering** — dimmed/italic/badge styling + filter toggle
6. **Multi-select copy** — selection model + Ctrl+C handler
7. **`.cmtlog` extension registration** — OS file association (Windows/macOS) so double-click opens in CMTrace Open
