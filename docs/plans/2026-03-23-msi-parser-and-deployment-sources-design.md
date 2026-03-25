# MSI Log Parser, PSADT Support & Software Deployment Known Sources

**Date:** 2026-03-23
**Status:** Draft

---

## Problem

CMTrace Open has no MSI log support. Users troubleshooting failed software deployments (SCCM, Intune, PSADT) must manually search MSI verbose logs for `Return value 3` and cross-reference error codes. PSADT v4 Legacy-format logs are not recognized. Additionally, common deployment log folders like `C:\Windows\Logs\Software` and PSADT output directories aren't in the Known Sources toolbar.

## Goals

1. Add UTF-16LE BOM decoding to the file reading pipeline (MSI logs are UTF-16LE with BOM and CRLF line endings)
2. Add a dedicated MSI verbose log parser that handles all ~12 distinct line patterns
3. Add a PSADT Legacy format parser for `[timestamp] [section] [source] [severity] :: message` logs
4. Handle PSADT's `type="0"` (Success) severity in the existing CCM parser
5. Embed all ~300 MSI error codes (1000-3002) and PSADT exit codes (60001-60012) into the error database
6. Add software deployment log folders to the Known Sources toolbar

## Non-Goals

- MSI transform (.mst) or patch (.msp) file analysis
- MSI database table inspection
- Localized MSI action start/end parsing (non-English systems) — future enhancement
- Wilogutl-style HTML report generation
- PSADT phase-aware collapsible sections (future enhancement)
- Parsing the `Invoke-AppDeployToolkit.exe` wrapper log as a dedicated format (it's plain text, handled by existing plain parser)

## References

- [MSI Error Codes 1000-3002](https://learn.microsoft.com/en-us/windows/win32/msi/windows-installer-error-messages) — Microsoft documentation
- MSI verbose log internal structure guide — comprehensive reverse-engineered format specification
- PSADT 4.x log format guide — CMTrace format spec, Legacy format, exit codes, Intune integration

---

## 1. UTF-16LE Encoding Support

### 1.1 The Problem

MSI verbose logs are **UTF-16 Little Endian with BOM** (`FF FE`) and CRLF line endings. The current parser pipeline only handles UTF-8 (with BOM strip) and Windows-1252 fallback. UTF-16LE files currently produce garbage output or parse as zero entries.

### 1.2 Changes to `parser/mod.rs`

The `decode_bytes_to_string()` function (currently: UTF-8 BOM strip → UTF-8 → Windows-1252 fallback) gains a new first step:

```
1. Check for UTF-16LE BOM (FF FE) → decode with encoding_rs::UTF_16LE
2. Check for UTF-16BE BOM (FE FF) → decode with encoding_rs::UTF_16BE
3. Check for UTF-8 BOM (EF BB BF) → strip and decode as UTF-8 (existing)
4. Try UTF-8 → Windows-1252 fallback (existing)
```

`encoding_rs` already supports `UTF_16LE` and `UTF_16BE` — no new dependencies needed.

CRLF normalization: After UTF-16 decode, replace `\r\n` with `\n` before splitting lines (the existing pipeline already handles this for other formats).

### 1.3 Changes to `watcher/tail.rs`

The tail watcher uses the same encoding logic. It must also detect UTF-16LE for new bytes appended during tailing. For UTF-16LE tailing:
- Track that the file was opened as UTF-16LE (store encoding in `TailSession`)
- Decode new chunks with `UTF_16LE` instead of UTF-8
- Handle the case where a read boundary splits a 2-byte code unit (buffer partial bytes)

### 1.4 Scope

This encoding change benefits **all file types**, not just MSI logs. Any UTF-16LE file opened in CMTrace Open will now decode correctly.

---

## 2. MSI Parser

### 2.1 New Files and Enum Variants

| Change | Location |
|--------|----------|
| New parser module | `src-tauri/src/parser/msi.rs` |
| `ParserKind::Msi` | `src-tauri/src/models/log_entry.rs` |
| `ParserImplementation::Msi` | `src-tauri/src/models/log_entry.rs` |
| `ResolvedParser::msi()` builder | `src-tauri/src/parser/detect.rs` |
| Module declaration | `src-tauri/src/parser/mod.rs` |
| Match arm in `parse_lines_with_selection` | `src-tauri/src/parser/mod.rs` |
| Detection logic in `detect_parser` | `src-tauri/src/parser/detect.rs` |

### 2.2 ResolvedParser Configuration

```rust
ResolvedParser::msi() -> Self {
    Self::new(
        ParserKind::Msi,
        ParserImplementation::Msi,
        ParserProvenance::Dedicated,
        ParseQuality::SemiStructured,
        RecordFraming::PhysicalLine,
        DateOrder::default(),
        None, // no specialization
    )
}
```

`LogFormat` compatibility: maps to `LogFormat::Timestamped` (no frontend `LogFormat` enum change needed).

### 2.3 Detection

**Path hints** (checked in `detect_parser`):
- Filename matches `MSI*.log` pattern (case-insensitive) — the auto-generated naming convention from `%TEMP%`
- Filename contains `msi` (case-insensitive) — e.g., `app-install.msi.log`
- Path contains `\windows\temp\` combined with MSI-like filename

**Content markers** (counted in the sample loop, first 20 non-empty lines):

| Marker | Weight | Pattern |
|--------|--------|---------|
| Header line | 3 (instant match) | `=== Verbose logging started:` or `=== Logging started:` |
| Engine prefix | 2 | `MSI (c)` or `MSI (s)` or `MSI (a)` |
| Action lifecycle | 1 | `^Action start \d` or `^Action ended \d` |
| Property dump | 1 | `^Property\(S\):` or `^Property\(C\):` |
| MainEngine return | 2 | `MainEngineThread is returning` |

**Detection threshold**: Total weight >= 3 triggers `ResolvedParser::msi()`. A single header line is enough. Two engine prefix lines are enough.

**Priority in detection chain**: After CCM/Simple (those have unambiguous `<![LOG[` / `$$<` markers), before generic timestamped. When a path hint matches AND weight >= 2, MSI wins.

### 2.4 All Line Patterns

MSI verbose logs contain ~12 distinct line patterns. Every line in a `/l*v` log matches one of these:

#### Pattern 1: Engine message line (most common)

```
MSI (c) (8C:98) [07:42:28:452]: Resetting cached policy values
MSI (s) (E8:F4) [17:15:50:123]: Note: 1: 2262 2: ActionText 3: ...
MSI (a) (30:F0) [09:02:46:647]: Custom action server started
```

Regex:
```
^MSI\s+\(([csaN])\)\s+\(([0-9A-Fa-f]+):([0-9A-Fa-f]+)\)\s+\[(\d{2}:\d{2}:\d{2}:\d{3})\]:\s+(.*)$
```

| Capture | Field |
|---------|-------|
| Group 1 | Context: `c`=client, `s`=server, `a`=custom action, `N`=nested |
| Group 2 | Process ID (hex, last 2 digits) |
| Group 3 | Thread ID (hex, last 2 digits) |
| Group 4 | Timestamp `HH:MM:SS:mmm` |
| Group 5 | Message body |

#### Pattern 2: Header line

```
=== Verbose logging started: 6/13/2023  9:02:46  Build type: SHIP UNICODE 5.00.10011.00  Calling process: C:\Windows\system32\MSIEXEC.EXE ===
```

Regex:
```
^=== (?:Verbose )?[Ll]ogging started: (\d{1,2}/\d{1,2}/\d{4})\s+(\d{1,2}:\d{2}:\d{2})\s+(.*)===\s*$
```

Extracts: date (M/D/YYYY US format), time, build info. The date is stored as parser state and carried forward to all subsequent entries.

#### Pattern 3: Footer line

```
=== Verbose logging stopped: 6/13/2023  9:02:46 ===
```

Severity: Info. Marks end of log.

#### Pattern 4: Action start

```
Action start 16:34:29: InstallFiles.
```

Regex:
```
^Action start (\d{1,2}:\d{2}:\d{2}): (\w+)\.\s*$
```

Extracts: timestamp (H:MM:SS, no milliseconds, no brackets), action name → `component`.

#### Pattern 5: Action ended with return value

```
Action ended 16:34:29: InstallFiles. Return value 1.
```

Regex:
```
^Action ended (\d{1,2}:\d{2}:\d{2}): (\w+)\. Return value (\d+)\.\s*$
```

The return value drives severity (see 2.6).

#### Pattern 6: Top-level action

```
Action 16:34:29: INSTALL.
```

Same as Pattern 4 but without "start" — indicates a top-level sequence action.

#### Pattern 7: Property change

```
MSI (c) (E0:4C) [17:14:09:576]: PROPERTY CHANGE: Adding OLDPRODUCTS property. Its value is '{54737F41-...}'.
MSI (c) (E0:4C) [17:14:09:576]: PROPERTY CHANGE: Modifying ProductToBeRegistered property. Its current value is '0'. Its new value: '1'.
MSI (c) (E0:4C) [17:14:09:576]: PROPERTY CHANGE: Deleting SOURCEDIR property. Its current value is 'C:\path\'.
```

These are engine message lines (Pattern 1) with `PROPERTY CHANGE:` in the message body. Parsed as Pattern 1; the property change is part of the message. Severity: Info.

#### Pattern 8: Property dump

```
Property(C): ProductCode = {C64CA371-69F2-473C-83C1-82B8B313C846}
Property(S): OLDPRODUCTS = {54737F41-13B0-4B98-9C70-F6C07F471E39}
```

No engine prefix, no timestamp. `Property(C)` = client-side, `Property(S)` = server-side. Severity: Info. Component: `MSI-properties`.

#### Pattern 9: Feature/component state

```
MSI (s) (C8:0C): Feature: Complete; Installed: Absent; Request: Local; Action: Local
MSI (s) (C8:0C): Component: Registry; Installed: Absent; Request: Local; Action: Local
```

Engine prefix but **no timestamp in brackets** (just the process/thread). Parsed as a variant of Pattern 1 with optional timestamp. Severity: Info.

#### Pattern 10: Internal error note

```
MSI (s) (48:00) [11:42:46:528]: Note: 1: 2205 2:  3: Error
```

Engine message line with `Note: 1: NNNN` format. The first number after `Note: 1:` is the MSI error code. Look up in error database for enrichment. Severity: depends on the error code.

#### Pattern 11: RunEngine block

```
MSI (c) (30:F0) [09:02:46:647]: ******* RunEngine:
           ******* Product: C:\path\to\product.msi
           ******* Action:
           ******* CommandLine: **********
```

Multi-line block with `*******` prefix on continuation lines. The first line is Pattern 1; continuation lines are indented with `*******`. These get appended to the first line's message or treated as separate Info entries.

#### Pattern 12: MainEngineThread return

```
MSI (c) (CC:70) [09:07:18:764]: MainEngineThread is returning 1603
```

Engine message line. The return code is the msiexec.exe exit code. This is the **single most important line** for failure diagnosis. Severity: derived from the return code (0 = Info, 1602/1604 = Warning, 1603 and others = Error).

#### Fallback: Plain text

Lines matching none of the above patterns are parsed as plain text with `detect_severity_from_text()` from the existing parser infrastructure.

### 2.5 Field Extraction

| LogEntry Field | Source |
|----------------|--------|
| `timestamp` | `[HH:MM:SS:mmm]` from engine lines, or `H:MM:SS` from action lines. Combined with header date (carried forward). Stored as Unix millis. |
| `timestamp_display` | Formatted: `MM-dd-yyyy HH:mm:ss.fff` (matches existing CMTrace Open format) |
| `component` | **Engine lines**: `MSI-client`, `MSI-server`, `MSI-action`, `MSI-nested` based on context letter. **Action lines**: action name (e.g., `InstallFiles`, `CostInitialize`). **Property dump**: `MSI-properties`. |
| `thread` | Hex thread ID from `(ProcID:ThreadID)` parsed as `u32`. For action lines without thread info: `None`. |
| `thread_display` | Original hex pair, e.g., `8C:98`. |
| `severity` | See severity mapping below |
| `message` | Everything after prefix/timestamp extraction |
| `format` | `LogFormat::Timestamped` |

### 2.6 Severity Mapping

**Priority order** (first match wins):

**1. MainEngineThread return code:**

| Code | Severity | Meaning |
|------|----------|---------|
| 0 | Info | Success |
| 1602 | Warning | User cancelled |
| 1603 | **Error** | Fatal error |
| 1604 | Warning | Suspended |
| 1605 | Error | Product not installed |
| 1618 | Error | Another install in progress |
| 1619 | Error | Could not open package |
| 1625 | Error | Blocked by policy |
| 1638 | Error | Another version installed |
| Other non-zero | Error | General failure |

**2. Action return value:**

| Value | Severity |
|-------|----------|
| `Return value 0` | Info (not called) |
| `Return value 1` | Info (success) |
| `Return value 2` | Warning (cancel / reboot) |
| `Return value 3` | **Error** (fatal) |
| `Return value 4` | Warning (suspended) |

**3. Note error codes:**

When `Note: 1: NNNN` is found, look up code NNNN. If the code is in the error database and maps to a known failure: Error. Otherwise: Warning (notes are often informational warnings).

**4. Known error signatures in message text:**

| Pattern | Severity |
|---------|----------|
| `Installation failed` | Error |
| `Installation success` | Info |
| `Removal completed successfully` | Info |
| `Failed to grab execution mutex` | Error |
| `error status: 1603` (or other non-zero) | Error |
| `error status: 0` | Info |

**5. Keyword fallback:**

Delegate to existing `detect_severity_from_text()` for remaining lines.

### 2.7 Date Handling

MSI logs have a split date model:
- **Header line** provides the date in US format: `M/D/YYYY` (single-digit month/day allowed, double-space separated from time)
- **Engine lines** have time-only: `[HH:MM:SS:mmm]`
- **Action lines** have time-only: `H:MM:SS`

Parser state machine:
1. Extract date from `=== Verbose logging started:` or `=== Logging started:` header
2. Store as `Option<NaiveDate>` in parser state
3. Combine with each line's time component to produce full `NaiveDateTime`
4. Detect midnight rollover: if current time < previous time by more than 23 hours, increment date
5. If no header found, timestamps have time-only display (no date component), `timestamp` field is `None`

### 2.8 Phase Tracking (Future Enhancement — Not in v1)

MSI logs flow through 6 predictable phases (Initialization → UI Sequence → Handoff → Execute Sequence → Property Dumps → Return). The `MSI (c)` → `MSI (s)` context switch marks the handoff from client UI to server execution. In v1, we parse all lines uniformly. Phase-aware grouping (collapsible sections in the UI) is a future enhancement.

---

## 3. MSI Error Code Database

### 3.1 Scope

All ~300 MSI error codes from 1000-3002, added to the existing `src-tauri/src/error_db/codes.rs`.

### 3.2 Code Ranges

| Range | Category | Count |
|-------|----------|-------|
| 1000-1999 | Ship errors (file I/O, registry, services, shortcuts, assemblies) | ~150 |
| 2000-2999 | Internal errors (database, UI, script, patching, custom actions) | ~140 |
| 3000-3002 | Patch sequencing errors | 3 |

### 3.3 Integration

Each code entry follows the existing pattern in `codes.rs`:
- Code: numeric string (e.g., `"1603"`)
- Description: message text (e.g., `"Fatal error during installation."`)
- Source: `"Windows Installer (MSI)"`
- Category: Based on range — `"MSI File/Path"`, `"MSI Registry"`, `"MSI Service"`, `"MSI Database"`, `"MSI Custom Action"`, etc.

These codes surface in:
- The **error lookup dialog** (Ctrl+E or toolbar) — users can search `1603` and see the description
- The **MSI parser's severity inference** — when `Note: 1: NNNN` or `Error NNNN` appears in a log line
- The **info pane** — when a log line is selected that contains a known error code, the description appears in the detail view

### 3.4 Common Error Codes to Prioritize in Testing

| Code | Description | How it appears in logs |
|------|-------------|----------------------|
| 1603 | Fatal error during installation | `Return value 3`, `error status: 1603` |
| 1618 | Another installation in progress | `Failed to grab execution mutex` |
| 1619 | Could not open installer package | `Note: 1: 2203` + `MainEngineThread is returning 1619` |
| 1605 | Product not currently installed | `Did not find item Products\...` |
| 1638 | Another version already installed | `PackagecodeChanging` property |
| 1722 | Problem with Windows Installer package (script) | Custom action failure |
| 1920 | Service failed to start | Service registration error |
| 1935 | Assembly installation error | .NET assembly / HRESULT |

---

## 4. PSADT Support

### 4.1 Existing Coverage: CMTrace Format (No New Parser Needed)

PSADT v4 writes CMTrace/CCM format logs by default (`LogStyle = 'CMTrace'`). These logs use the `<![LOG[...]LOG]!><time="..." date="..." ...>` format, which **the existing CCM parser already handles correctly**. PSADT logs written to `C:\Windows\Logs\Software\` will auto-detect as CCM format and parse with full field extraction (message, timestamp, component, thread, severity, source_file).

The `component` field captures PSADT function names (e.g., `Start-ADTMsiProcess`, `Close-ADTSession`, `Show-ADTInstallationWelcome`) — these are already extracted by the CCM parser's `component=""` attribute handling.

### 4.2 Severity 0 (Success) Handling

PSADT v4 introduces `type="0"` (Success) in the CCM format, which was not present in traditional Configuration Manager logs. The current CCM parser maps unknown type values to `Severity::Info`.

**Decision: Map type="0" to `Severity::Info` (no enum change).**

Rationale:
- Adding a `Severity::Success` enum variant would ripple across the entire frontend (filter UI, row coloring, severity icons, filter stores) for minimal benefit.
- CMTrace.exe renders type=0 as green text — informationally it behaves like a "good Info" message.
- The message content (`install completed with exit code [0]`) already communicates success clearly.
- The CCM parser's existing fallback `_ => Severity::Info` already produces the correct behavior.

**One small change**: In `severity_from_type_field()` in `parser/ccm.rs`, add an explicit `"0"` arm mapping to `Severity::Info` with a comment explaining PSADT Success, rather than relying on the catch-all. This makes the intent clear and prevents future regressions if someone changes the fallback.

### 4.3 PSADT Legacy Format Parser

When `LogStyle = 'Legacy'` is set in PSADT's `config.psd1`, logs are plain-text with a distinct structure:

```
[2024-12-24 14:44:13.658] [Finalization] [Close-ADTSession] [Info] :: Message text here
[2024-12-24 14:44:13.700] [Install] [Start-ADTMsiProcess] [Error] :: MSI installation failed. [Exit code: 1603]
```

Format: `[timestamp] [section] [source] [severity] :: message`

This is a **new parser** because no existing parser handles this bracketed-field format.

#### 4.3.1 New Files and Enum Variants

| Change | Location |
|--------|----------|
| New parser module | `src-tauri/src/parser/psadt.rs` |
| `ParserKind::PsadtLegacy` | `src-tauri/src/models/log_entry.rs` |
| `ParserImplementation::PsadtLegacy` | `src-tauri/src/models/log_entry.rs` |
| `ResolvedParser::psadt_legacy()` builder | `src-tauri/src/parser/detect.rs` |
| Module declaration | `src-tauri/src/parser/mod.rs` |
| Match arm in `parse_lines_with_selection` | `src-tauri/src/parser/mod.rs` |
| Detection logic in `detect_parser` | `src-tauri/src/parser/detect.rs` |

#### 4.3.2 ResolvedParser Configuration

```rust
ResolvedParser::psadt_legacy() -> Self {
    Self::new(
        ParserKind::PsadtLegacy,
        ParserImplementation::PsadtLegacy,
        ParserProvenance::Dedicated,
        ParseQuality::Structured,      // All fields are present in every line
        RecordFraming::PhysicalLine,
        DateOrder::Mdy,                // PSADT uses YYYY-MM-DD so order is unambiguous
        None,
    )
}
```

#### 4.3.3 Detection

**Content markers** (first 20 non-empty lines):

| Marker | Weight | Pattern |
|--------|--------|---------|
| Bracketed line match | 3 | `^\[\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\.\d{3}\]\s\[` |
| Section names | 1 | `[Initialization]`, `[Pre-Install]`, `[Install]`, `[Post-Install]`, `[Finalization]` etc. |
| PSADT function names | 1 | `[Open-ADTSession]`, `[Close-ADTSession]`, `[Start-ADTMsiProcess]` etc. |
| Banner delimiter | 2 | `*****` (10+ asterisks) in a bracketed line |

**Detection threshold**: Weight >= 3. A single bracketed line with the full pattern is enough.

**Priority in detection chain**: After CCM (since CCM format PSADT logs should detect as CCM), before generic timestamped. The `<![LOG[` marker in CCM format always wins over Legacy format detection.

#### 4.3.4 Line Format and Regex

```
^\[(?<timestamp>\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\.\d{3})\]\s\[(?<section>[^\]]+)\]\s\[(?<source>[^\]]+)\]\s\[(?<severity>\w+)\]\s::\s(?<message>.*)$
```

| Capture | LogEntry Field | Example |
|---------|---------------|---------|
| `timestamp` | `timestamp` + `timestamp_display` | `2024-12-24 14:44:13.658` |
| `section` | `component` | `Finalization`, `Install`, `Pre-Install` |
| `source` | `source_file` | `Close-ADTSession`, `Start-ADTMsiProcess` |
| `severity` | `severity` | `Info`, `Warning`, `Error`, `Success` |
| `message` | `message` | `Message text here` |

#### 4.3.5 Severity Mapping

| Legacy text | Severity |
|-------------|----------|
| `Success` | Info (same rationale as type=0 above) |
| `Info` or `Information` | Info |
| `Warning` or `Warn` | Warning |
| `Error` | Error |

#### 4.3.6 Timestamp Parsing

The Legacy format uses ISO-style `YYYY-MM-DD HH:MM:SS.fff` — fully specified, no date carry-forward needed. Parse directly with `chrono::NaiveDateTime::parse_from_str("%Y-%m-%d %H:%M:%S%.3f")`.

#### 4.3.7 Banner Lines

PSADT logs contain `*****` banner lines that delimit deployment sessions:
```
[2024-12-24 14:44:13.658] [Initialization] [Open-ADTSession] [Info] :: *******************************************************************************
```

These parse normally as Info-severity lines. The message is the asterisk string. No special handling needed — they're useful as visual separators when scrolling through the log.

### 4.4 PSADT Exit Codes for Error Database

PSADT defines framework-level exit codes separate from underlying installer return codes:

| Code | Hex | Description |
|------|-----|-------------|
| 0 | 0x0 | Success |
| 1602 | 0x642 | User deferred (v4.1+ default) |
| 1618 | 0x652 | UI timeout |
| 3010 | 0xBC2 | Reboot required (suppressed) |
| 60001 | 0xEA61 | General PSADT failure |
| 60002 | 0xEA62 | Missing file |
| 60003 | 0xEA63 | Requires admin but not elevated |
| 60004 | 0xEA64 | Failed to load assembly |
| 60005 | 0xEA65 | Error displaying installation prompt |
| 60007 | 0xEA67 | Scheduled task XML export failed |
| 60008 | 0xEA68 | Module load failure |
| 60012 | 0xEA6C | User deferred (v4.0.x default) |

These are added to `error_db/codes.rs` using the existing `(u32, &str)` tuple format with hex codes:

```rust
(0x0000EA61, "PSADT_E_GENERAL_FAILURE - Unknown error in Deploy-Application or unhandled exception"),
(0x0000EA62, "PSADT_E_FILE_NOT_FOUND - Required file not found"),
// ... etc.
```

**Intune hex conversion note**: Intune displays these with a `0x8007` prefix: `0x8007EA6C` → strip `0x8007` → `0xEA6C` → decimal 60012. The error lookup dialog should handle both the raw code and the Intune-prefixed form.

### 4.5 PSADT Log Signatures for Error Detection

Key patterns the parser should recognize for severity inference:

| Log Pattern | Severity | Meaning |
|-------------|----------|---------|
| `install completed with exit code [0]` | Info | Success |
| `install completed with exit code [NNNN]` (non-zero) | Error | Failure |
| `uninstall completed with exit code [0]` | Info | Success |
| `MSI installation failed. [Exit code: NNNN]` | Error | MSI failure |
| `MSI installation completed successfully. [Exit code: 0]` | Info | MSI success |
| `Process completed successfully. [Exit code: 0]` | Info | EXE success |
| `The user selected Defer` | Warning | User deferral |
| `Installation not complete within timeout` | Warning | UI timeout |
| `OOBE/ESP detected` | Info | Autopilot context |
| `requires the toolkit to be running with Administrator privileges` | Error | Missing elevation |

These patterns apply to both CMTrace-format and Legacy-format PSADT logs (the message content is the same in both formats).

---

## 5. Known Sources — Software Deployment

### 5.1 New Sources

| Source ID | Label | Path | Type | File Pattern |
|-----------|-------|------|------|--------------|
| `windows-deploy-logs-software` | Software Logs | `C:\Windows\Logs\Software` | Folder | `*.log` |
| `windows-deploy-ccm-logs` | CCM Client Logs | `C:\Windows\CCM\Logs` | Folder | `*.log` |
| `windows-deploy-temp-msi` | Windows Temp (MSI) | `C:\Windows\Temp` | Folder | `MSI*.log` |
| `windows-deploy-psadt-wrapper` | PSADT Wrapper Logs | `C:\Windows\Logs\Invoke-AppDeployToolkit.exe` | Folder | `*.log` |
| `windows-deploy-user-temp-msi` | User Temp (MSI verbose) | `%TEMP%` (runtime) | Folder | `MSI*.log` |
| `windows-deploy-ime-logs` | IME Logs | `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs` | Folder | `*.log` |

Note: `C:\Windows\Logs\Software` is PSADT's default `LogPath` for elevated deployments. PSADT CMTrace-format logs, MSI verbose logs from `Start-ADTMsiProcess`, and PSADT Legacy-format logs all land here. The `Invoke-AppDeployToolkit.exe` wrapper produces a separate plain-text log in its own subfolder.

### 5.2 Grouping

```
family_id:    "windows-deployment"
family_label: "Software Deployment"
group_id:     "deploy-logs"
group_label:  "Deployment Logs"
group_order:  50   (after Windows Servicing at 40)
```

Individual `source_order`: 10, 20, 30, 40, 50, 60 respectively.

### 5.3 Runtime Path Expansion

The `%TEMP%` source requires resolving the environment variable at runtime. This is new — all existing known sources use hardcoded paths.

Implementation: In `windows_known_log_sources()`, resolve `%TEMP%` using `std::env::var("TEMP")` with a fallback to `std::env::var("TMP")`, then to `C:\Users\<user>\AppData\Local\Temp`. Only include the source if the path resolves and exists.

Approach: resolve the path at source-list generation time (simple — the function is called per-request anyway). No structural refactor needed.

### 5.4 IME Logs Source

Added because the MSI verbose log guide specifically recommends admins direct MSI verbose logs to the IME logs directory for Intune Win32 app deployments:
```
msiexec /i "app.msi" /l*v "%programdata%\Microsoft\IntuneManagementExtension\Logs\AppName.log"
```

This folder already contains `AppWorkload.log` and `IntuneManagementExtension.log` (parsed by the existing Intune module), but admin-created MSI verbose logs would also land here.

---

## 6. Testing Strategy

### 6.1 Encoding Tests

- UTF-16LE BOM file decodes correctly (round-trip with known content)
- UTF-16BE BOM file decodes correctly
- UTF-8 BOM files still work (regression)
- Plain UTF-8 files still work (regression)
- Windows-1252 fallback still works (regression)
- Tail watcher handles UTF-16LE appended bytes correctly

### 6.2 Parser Detection Tests

- MSI header line alone triggers `ParserKind::Msi`
- Two `MSI (s)` lines trigger detection
- `MSI*.log` filename with 1 content marker triggers detection
- CCM format (`<![LOG[`) is NOT misdetected as MSI (PSADT CMTrace logs stay as CCM)
- PSADT Legacy format triggers `ParserKind::PsadtLegacy`
- PSADT Legacy is NOT misdetected when CCM `<![LOG[` markers are present
- Non-MSI timestamped logs are NOT misdetected

### 6.3 Parser Line Tests

- **Engine message line**: Extract all fields (context, PID, TID, timestamp, message)
- **Action start/ended**: Extract action name as component, return value as severity
- **Return value mapping**: 0→Info, 1→Info, 2→Warning, 3→Error, 4→Warning
- **MainEngineThread**: Extract return code, map to severity
- **Header date extraction**: US format `M/D/YYYY` parsed correctly
- **Date carry-forward**: Header date applied to all subsequent entries
- **Midnight rollover**: Date increments when time wraps
- **Property dump lines**: Parsed as Info with `MSI-properties` component
- **Feature/Component state lines**: Parsed correctly despite missing timestamp brackets
- **Note error codes**: `Note: 1: 2205` extracts code 2205
- **Mixed content**: Non-matching lines fall back to plain text

### 6.4 PSADT Legacy Parser Tests

- **Full line parse**: Extract all 5 fields (timestamp, section, source, severity, message)
- **Severity mapping**: `Success`→Info, `Info`→Info, `Warning`→Warning, `Error`→Error
- **Banner lines**: `*****` lines parse as Info with asterisk message
- **Exit code extraction**: `completed with exit code [1603]` → Error severity
- **MSI failure line**: `MSI installation failed. [Exit code: 1603]` → Error severity
- **Timestamp**: ISO format `YYYY-MM-DD HH:MM:SS.fff` parsed correctly
- **Section as component**: `[Install]` → component = `Install`
- **Source as source_file**: `[Start-ADTMsiProcess]` → source_file = `Start-ADTMsiProcess`

### 6.5 CCM Parser type="0" Test

- PSADT CMTrace log with `type="0"` maps to `Severity::Info` (explicit arm, not fallback)

### 6.6 Error Signature Tests

Using real-world log snippets for each common failure:
- **MSI Error 1603 pattern**: First `Return value 3` marked as Error
- **MSI Error 1618 pattern**: `Failed to grab execution mutex` marked as Error
- **MSI Error 1619 pattern**: Short log with `Note: 1: 2203` + return 1619
- **MSI Success pattern**: `MainEngineThread is returning 0`, `Installation success`
- **PSADT success**: `install completed with exit code [0]` → Info
- **PSADT failure**: `install completed with exit code [60001]` → Error
- **PSADT user defer**: `The user selected Defer` → Warning

### 6.7 Error Database Tests

- All ~300 MSI codes present and resolvable
- PSADT exit codes (60001-60012) present and resolvable
- Known success codes (1707, 1715, 1724) don't map to Error severity in parser context
- Lookup by code string returns correct description and source
- PSADT hex codes (0xEA61 etc.) resolve correctly

### 6.8 Known Sources Tests

- Runtime `%TEMP%` expansion produces a valid path
- All 6 sources appear in the toolbar grouping under "Software Deployment"
- `MSI*.log` filter correctly limits displayed files in temp folders



## 7. Implementation Order

| Step | Description | Dependencies |
|------|-------------|--------------|
| 1 | UTF-16LE/BE encoding support in `parser/mod.rs` and `watcher/tail.rs` | None |
| 2 | Add `ParserKind::Msi`, `ParserImplementation::Msi`, `ParserKind::PsadtLegacy`, `ParserImplementation::PsadtLegacy` enum variants | None |
| 3 | Implement `parser/msi.rs` — all 12 line patterns, severity mapping, date handling | Step 1, 2 |
| 4 | Implement `parser/psadt.rs` — Legacy format parser | Step 2 |
| 5 | Add explicit `type="0"` arm in `parser/ccm.rs` `severity_from_type_field()` | None |
| 6 | Wire detection in `parser/detect.rs` and dispatch in `parser/mod.rs` for both MSI and PSADT Legacy | Step 3, 4 |
| 7 | Add ~300 MSI error codes + PSADT exit codes to `error_db/codes.rs` | None (parallel with 1-6) |
| 8 | Add 6 Known Sources to `commands/file_ops.rs` | None (parallel with 1-7) |
| 9 | Tests for all of the above | Steps 1-8 |

## 8. Files Changed Summary

| File | Change |
|------|--------|
| `src-tauri/src/parser/mod.rs` | UTF-16LE/BE BOM detection in `decode_bytes_to_string()`, `pub mod msi;`, `pub mod psadt;`, match arms for `Msi` and `PsadtLegacy` |
| `src-tauri/src/parser/msi.rs` | **New** — MSI verbose log parser: 12 line patterns, severity mapping, date state machine |
| `src-tauri/src/parser/psadt.rs` | **New** — PSADT Legacy format parser: bracketed-field line format |
| `src-tauri/src/parser/ccm.rs` | Add explicit `"0" => Severity::Info` arm in `severity_from_type_field()` |
| `src-tauri/src/parser/detect.rs` | `ResolvedParser::msi()` and `ResolvedParser::psadt_legacy()` builders, detection logic for both |
| `src-tauri/src/models/log_entry.rs` | `ParserKind::Msi`, `ParserKind::PsadtLegacy`, `ParserImplementation::Msi`, `ParserImplementation::PsadtLegacy` enum variants |
| `src-tauri/src/watcher/tail.rs` | UTF-16LE encoding tracking in `TailSession`, decode new chunks accordingly |
| `src-tauri/src/error_db/codes.rs` | ~300 MSI error codes (1000-3002) + PSADT exit codes (60001-60012) |
| `src-tauri/src/commands/file_ops.rs` | 6 deployment sources in `windows_known_log_sources()`, `%TEMP%` resolution |
| `src-tauri/tests/` | New test fixtures (UTF-16LE sample, MSI log snippets, PSADT Legacy sample) and test cases |

---
``
## Windows Installer Error Messages: Win32 apps

The error codes detailed in this topic are returned by the Windows Installer, and have error codes of 1000 or greater. The error codes numbered 1000 to 1999 are ship errors and must be authored into the [Error table](error-table). The error codes numbered greater than 2000 are internal errors and do not have authored strings, but these can occur if the installation package has been incorrectly authored. For error codes specific to the Windows Installer functions **MsiExec.exe** and **InstMsi.exe**, see [MsiExec.exe and InstMsi.exe Error Messages](error-codes). For a list of reserved error codes, see [Error table](error-table). You can search the Internet or the [Microsoft support site](https://support.microsoft.com/) for solutions to many of the messages in the following table.



| Message Code | Message | Remarks |
| --- | --- | --- |
| 1101 | Could not open file stream: [2]. System error: [3] |  |
| 1301 | Cannot create the file '[2]'. A directory with this name already exists. |  |
| 1302 | Please insert the disk: [2] |  |
| 1303 | The Installer has insufficient privileges to access this directory: [2]. |  |
| 1304 | Error writing to File: [2] |  |
| 1305 | Error reading from File: [2]; System error code: [3] |  |
| 1306 | The file '[2]' is in use. If you can, please close the application that is using the file, then click **Retry**. | A system restart may be required because a file being updated is also currently in use. For more information, see [System Reboots](system-reboots). |
| 1307 | There is not enough disk space remaining to install this file: [2]. If you can, free up some disk space, and click **Retry**, or click **Cancel** to exit. |  |
| 1308 | Source file not found: [2] |  |
| 1309 | Error attempting to open the source file: [3]. System error code: [2] |  |
| 1310 | Error attempting to create the destination file: [3]. System error code: [2] |  |
| 1311 | Could not locate source file cabinet: [2]. |  |
| 1312 | Cannot create the directory '[2]'. A file with this name already exists. Please rename or remove the file and click **Retry**, or click **Cancel** to exit. |  |
| 1313 | The volume [2] is currently unavailable. Please select another. |  |
| 1314 | The specified path '[2]' is unavailable. |  |
| 1315 | Unable to write to the specified folder: [2]. |  |
| 1316 | A network error occurred while attempting to read from the file: [2] |  |
| 1317 | An error occurred while attempting to create the directory: [2] |  |
| 1318 | A network error occurred while attempting to create the directory: [2] |  |
| 1319 | A network error occurred while attempting to open the source file cabinet: [2]. |  |
| 1320 | The specified path is too long: '[2]' |  |
| 1321 | The Installer has insufficient privileges to modify this file: [2]. |  |
| 1322 | A portion of the folder path '[2]' is invalid. It is either empty or exceeds the length allowed by the system. |  |
| 1323 | The folder path '[2]' contains words that are not valid in folder paths. |  |
| 1324 | The folder path '[2]' contains an invalid character. |  |
| 1325 | '[2]' is not a valid short file name. |  |
| 1326 | Error getting file security: [3] GetLastError: [2] |  |
| 1327 | Invalid Drive: [2] |  |
| 1328 | Error applying patch to file [2]. It has probably been updated by other means, and can no longer be modified by this patch. For more information, contact your patch vendor. System Error: [3] |  |
| 1329 | A file that is required cannot be installed because the cabinet file [2] is not digitally signed. This may indicate that the cabinet file is corrupt. |  |
| 1330 | A file that is required cannot be installed because the cabinet file [2] has an invalid digital signature. This may indicate that the cabinet file is corrupt.{ Error [3] was returned by [**WinVerifyTrust**](/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust).} |  |
| 1331 | Failed to correctly copy [2] file: CRC error. |  |
| 1332 | Failed to correctly move [2] file: CRC error. |  |
| 1333 | Failed to correctly patch [2] file: CRC error. |  |
| 1334 | The file '[2]' cannot be installed because the file cannot be found in cabinet file '[3]'. This could indicate a network error, an error reading from the CD-ROM, or a problem with this package. |  |
| 1335 | The cabinet file '[2]' required for this installation is corrupt and cannot be used. This could indicate a network error, an error reading from the CD-ROM, or a problem with this package. |  |
| 1336 | There was an error creating a temporary file that is needed to complete this installation. Folder: [3]. System error code: [2] |  |
| 1401 | Could not create key: [2]. System error [3]. |  |
| 1402 | Could not open key: [2]. System error [3]. |  |
| 1403 | Could not delete value [2] from key [3]. System error [4]. |  |
| 1404 | Could not delete key [2]. System error [3]. |  |
| 1405 | Could not read value [2] from key [3]. System error [4]. |  |
| 1406 | Could not write value [2] to key [3]. System error [4]. |  |
| 1407 | Could not get value names for key [2]. System error [3]. |  |
| 1408 | Could not get sub key names for key [2]. System error [3]. |  |
| 1409 | Could not read security information for key [2]. System error [3]. |  |
| 1410 | Could not increase the available registry space. [2] KB of free registry space is required for the installation of this application. |  |
| 1500 | Another installation is in progress. You must complete that installation before continuing this one. | Test packages in high-traffic environments where users request the installation of many applications. For more information, see [_MSIExecute Mutex](-msiexecute-mutex). |
| 1501 | Error accessing secured data. Please make sure the Windows Installer is configured properly and try the install again. |  |
| 1502 | User '[2]' has previously initiated an install for product '[3]'. That user will need to run that install again before they can use that product. Your current install will now continue. | Test packages in high-traffic environments where users request the installation of many applications. For more information, see [_MSIExecute Mutex](-msiexecute-mutex). |
| 1503 | User '[2]' has previously initiated an install for product '[3]'. That user will need to run that install again before they can use that product. | Test packages in high-traffic environments where users request the installation of many applications. For more information, see [_MSIExecute Mutex](-msiexecute-mutex). |
| 1601 | Out of disk space -- Volume: '[2]'; required space: [3] KB; available space: [4] KB | Ensure that the custom action costs do not exceed available space. |
| 1602 | Are you sure you want to cancel? |  |
| 1603 | The file [2][3] is being held in use by the following process: Name: [4], Id: [5], Window Title: '[6]'. | A system restart may be required because the file being updated is also currently in use. Users may be given the opportunity to avoid some system restarts by using the [FilesInUse Dialog](filesinuse-dialog) or the [MsiRMFilesInUse Dialog](msirmfilesinuse-dialog). For more information, see [System Reboots](system-reboots) and [Logging of Reboot Requests](logging-of-reboot-requests). |
| 1604 | The product '[2]' is already installed, and has prevented the installation of this product. |  |
| 1605 | Out of disk space -- Volume: '[2]'; required space: [3] KB; available space: [4] KB. If rollback is disabled, enough space is available. Click **Cancel** to quit, **Retry** to check available disk space again, or **Ignore** to continue without rollback. | Ensure that the custom action costs do not exceed the available space. |
| 1606 | Could not access location [2]. | Do not list directories in the [Directory](directory-table) table which are not used by the installation. Rarely, this message is due to the issue discussed by [KB886549](https://support.microsoft.com). |
| 1607 | The following applications should be closed before continuing the install: | A system restart may be required because a file that is being updated is also currently in use. Users may be given the opportunity to avoid some system restarts by selecting to close some applications. For more information, see [System Reboots](system-reboots). |
| 1608 | Could not find any previously installed compliant products on the machine for installing this product | No file listed in the [CCPSearch](ccpsearch-table) table can be found on the user's computer. |
| 1609 | An error occurred while applying security settings. [2] is not a valid user or group. This could be a problem with the package, or a problem connecting to a domain controller on the network. Check your network connection and click **Retry**, or **Cancel** to end the install. Unable to locate the user's SID, system error [3] |  |
| 1610 | The setup must update files or services that cannot be updated while the system is running. If you choose to continue, a reboot will be required to complete the setup. | Available in Windows Installer version 4.0. |
| 1611 | The setup was unable to automatically close all requested applications. Please ensure that the applications holding files in use are closed before continuing with the installation. | Available in Windows Installer version 4.0. |
| 1651 | Admin user failed to apply patch for a per-user managed or a per-machine application which is in advertise state. | Available in Windows Installer version 3.0. |
| 1701 | [2] is not a valid entry for a product ID. |  |
| 1702 | Configuring [2] cannot be completed until you restart your system. To restart now and resume configuration click **Yes**, or click **No** to stop this configuration. | A scheduled system restart message. For more information, see [System Reboots](system-reboots) and [ScheduleReboot Action](schedulereboot-action). This message may be customized using the [Error](error-table) table. |
| 1703 | For the configuration changes made to [2] to take effect you must restart your system. To restart now click **Yes**, or click **No** if you plan to manually restart at a later time. | The scheduled system restart message when no other users are logged on the computer. For more information, see [System Reboots](system-reboots) and [ScheduleReboot Action](schedulereboot-action). This message may be customized using the [Error](error-table) table. |
| 1704 | An install for [2] is currently suspended. You must undo the changes made by that install to continue. Do you want to undo those changes? |  |
| 1705 | A previous install for this product is in progress. You must undo the changes made by that install to continue. Do you want to undo those changes? |  |
| 1706 | No valid source could be found for product [2]. |  |
| 1707 | Installation operation completed successfully. |  |
| 1708 | Installation operation failed. |  |
| 1709 | Product: [2] -- [3] |  |
| 1710 | You may either restore your computer to its previous state or continue the install later. Would you like to restore? |  |
| 1711 | An error occurred while writing installation information to disk. Check to make sure enough disk space is available, and click **Retry**, or **Cancel** to end the install. |  |
| 1712 | One or more of the files required to restore your computer to its previous state could not be found. Restoration will not be possible. |  |
| 1713 | [2] cannot install one of its required products. Contact your technical support group. System Error: [3]. |  |
| 1714 | The older version of [2] cannot be removed. Contact your technical support group. System Error [3]. |  |
| 1715 | Installed [2]. |  |
| 1716 | Configured [2]. |  |
| 1717 | Removed [2]. |  |
| 1718 | File [2] was rejected by digital signature policy. | A very large installation may cause the operating system to run out of memory. |
| 1719 | Windows Installer service could not be accessed. Contact your support personnel to verify that it is properly registered and enabled. |  |
| 1720 | There is a problem with this Windows Installer package. A script required for this install to complete could not be run. Contact your support personnel or package vendor. Custom action [2] script error [3], [4]: [5] Line [6], Column [7], [8] |  |
| 1721 | There is a problem with this Windows Installer package. A program required for this install to complete could not be run. Contact your support personnel or package vendor. Action: [2], location: [3], command: [4] |  |
| 1722 | There is a problem with this Windows Installer package. A program run as part of the setup did not finish as expected. Contact your support personnel or package vendor. Action [2], location: [3], command: [4] |  |
| 1723 | There is a problem with this Windows Installer package. A DLL required for this install to complete could not be run. Contact your support personnel or package vendor. Action [2], entry: [3], library: [4] | Ensure that the functions used by custom actions are actually exported. For more information about custom actions based upon a DLL, see [Dynamic-Link Libraries](dynamic-link-libraries). |
| 1724 | Removal completed successfully. |  |
| 1725 | Removal failed. |  |
| 1726 | Advertisement completed successfully. |  |
| 1727 | Advertisement failed. |  |
| 1728 | Configuration completed successfully. |  |
| 1729 | Configuration failed. |  |
| 1730 | You must be an Administrator to remove this application. To remove this application, you can log on as an administrator, or contact your technical support group for assistance. |  |
| 1731 | The source installation package for the product [2] is out of sync with the client package. Try the installation again using a valid copy of the installation package '[3]'. | Available beginning with Windows Installer for Windows Server 2003. |
| 1732 | In order to complete the installation of [2], you must restart the computer. Other users are currently logged on to this computer, and restarting may cause them to lose their work. Do you want to restart now? | The scheduled system restart message when other users are logged on the computer. For more information, see [System Reboots](system-reboots) and [ScheduleReboot Action](schedulereboot-action). This message may be customized using the [Error](error-table) table. Available beginning with Windows Installer for Windows Server 2003. |
| 1801 | The path [2] is not valid |  |
| 1802 | Out of memory |  |
| 1803 | There is no disk in drive [2]. Please, insert one and click **Retry**, or click **Cancel** to go back to the previously selected volume. |  |
| 1804 | There is no disk in drive [2]. Please, insert one and click **Retry**, or click **Cancel** to return to the browse dialog and select a different volume. |  |
| 1805 | The path [2] does not exist |  |
| 1806 | You have insufficient privileges to read this folder. |  |
| 1807 | A valid destination folder for the install could not be determined. |  |
| 1901 | Error attempting to read from the source install database: [2] |  |
| 1902 | Scheduling restart operation: Renaming file [2] to [3]. Must restart to complete operation. | An file being updated by the installation is currently in use. Windows Installer renames the file to update it and removes the old version at the next restart of the system. |
| 1903 | Scheduling restart operation: Deleting file [2]. Must restart to complete operation. | A system restart may be required because the file that is being updated is also currently in use. Users may be given the opportunity to avoid some system restarts by using the [FilesInUse Dialog](filesinuse-dialog) or [MsiRMFilesInUse Dialog](msirmfilesinuse-dialog). For more information, see [System Reboots](system-reboots) and [Logging of Reboot Requests](logging-of-reboot-requests). |
| 1904 | Module [2] failed to register. HRESULT [3]. |  |
| 1905 | Module [2] failed to unregister. HRESULT [3]. |  |
| 1906 | Failed to cache package [2]. Error: [3] |  |
| 1907 | Could not register font [2]. Verify that you have sufficient permissions to install fonts, and that the system supports this font. |  |
| 1908 | Could not unregister font [2]. Verify that you have sufficient permissions to remove fonts. |  |
| 1909 | Could not create shortcut [2]. Verify that the destination folder exists and that you can access it. |  |
| 1910 | Could not remove shortcut [2]. Verify that the shortcut file exists and that you can access it. |  |
| 1911 | Could not register type library for file [2]. Contact your support personnel. | Error loading a type library or DLL. |
| 1912 | Could not unregister type library for file [2]. Contact your support personnel. | Error loading a type library or DLL. |
| 1913 | Could not update the .ini file [2][3]. Verify that the file exists and that you can access it. |  |
| 1914 | Could not schedule file [2] to replace file [3] on restart. Verify that you have write permissions to file [3]. |  |
| 1915 | Error removing ODBC driver manager, ODBC error [2]: [3]. Contact your support personnel. |  |
| 1916 | Error installing ODBC driver manager, ODBC error [2]: [3]. Contact your support personnel. |  |
| 1917 | Error removing ODBC driver: [4], ODBC error [2]: [3]. Verify that you have sufficient privileges to remove ODBC drivers. |  |
| 1918 | Error installing ODBC driver: [4], ODBC error [2]: [3]. Verify that the file [4] exists and that you can access it. |  |
| 1919 | Error configuring ODBC data source: [4], ODBC error [2]: [3]. Verify that the file [4] exists and that you can access it. |  |
| 1920 | Service '[2]' ([3]) failed to start. Verify that you have sufficient privileges to start system services. |  |
| 1921 | Service '[2]' ([3]) could not be stopped. Verify that you have sufficient privileges to stop system services. |  |
| 1922 | Service '[2]' ([3]) could not be deleted. Verify that you have sufficient privileges to remove system services. |  |
| 1923 | Service '[2]' ([3]) could not be installed. Verify that you have sufficient privileges to install system services. |  |
| 1924 | Could not update environment variable '[2]'. Verify that you have sufficient privileges to modify environment variables. |  |
| 1925 | You do not have sufficient privileges to complete this installation for all users of the machine. Log on as administrator and then retry this installation. |  |
| 1926 | Could not set file security for file '[3]'. Error: [2]. Verify that you have sufficient privileges to modify the security permissions for this file. |  |
| 1927 | The installation requires COM+ Services to be installed. |  |
| 1928 | The installation failed to install the COM+ Application. |  |
| 1929 | The installation failed to remove the COM+ Application. |  |
| 1930 | The description for service '[2]' ([3]) could not be changed. |  |
| 1931 | The Windows Installer service cannot update the system file [2] because the file is protected by Windows. You may need to update your operating system for this program to work correctly. Package version: [3], OS Protected version: [4] | Windows Installer protects critical system files. For more information, see [Using Windows Installer and Windows Resource Protection](windows-resource-protection-on-windows-vista). For Windows Me, see the [InstallSFPCatalogFile action](installsfpcatalogfile-action), the [FileSFPCatalog table](filesfpcatalog-table), and the [SFPCatalog table](sfpcatalog-table). |
| 1932 | The Windows Installer service cannot update the protected Windows file [2]. Package version: [3], OS Protected version: [4], SFP Error: [5] | Windows Installer protects critical system files. For more information, see [Using Windows Installer and Windows Resource Protection](windows-resource-protection-on-windows-vista). For Windows Me, see the [InstallSFPCatalogFile action](installsfpcatalogfile-action), the [FileSFPCatalog table](filesfpcatalog-table), and the [SFPCatalog table](sfpcatalog-table). |
| 1933 | The Windows Installer service cannot update one or more protected Windows files. SFP Error: [2]. List of protected files:\r\n[3] | Windows Installer protects critical system files. For more information, see [Using Windows Installer and Windows Resource Protection](windows-resource-protection-on-windows-vista). For Windows Me, see the [InstallSFPCatalogFile action](installsfpcatalogfile-action), the [FileSFPCatalog table](filesfpcatalog-table), and the [SFPCatalog table](sfpcatalog-table). |
| 1934 | User installations are disabled through policy on the machine. |  |
| 1935 | An error occurred during the installation of assembly component [2]. HRESULT: [3]. {{assembly interface: [4], function: [5], assembly name: [6]}} | For more information, see [Assemblies](assemblies). Help and Support may have published a KB article that discusses the installation of this assembly. Go to the [Search the Support Knowledge Base](https://support.microsoft.com) page and search for articles that discuss this Windows Installer error message. |
| 1935 | An error occurred during the installation of assembly '[6]'. Please refer to Help and Support for more information. HRESULT: [3]. {{assembly interface: [4], function: [5], component: [2]}} | For more information, see [Assemblies](assemblies). Help and Support may have published a KB article that discusses the installation of this assembly. Go to the [Search the Support Knowledge Base](https://support.microsoft.com) page and search for articles that discuss this Windows Installer error message.  Available beginning with Windows Installer for Windows Server 2003. |
| 1936 | An error occurred during the installation of assembly '[6]'. The assembly is not strongly named or is not signed with the minimal key length. HRESULT: [3]. {{assembly interface: [4], function: [5], component: [2]}} | For more information, see [Assemblies](assemblies). Help and Support may have published a KB article that discusses the installation of this assembly. Go to the [Search the Support Knowledge Base](https://support.microsoft.com) page and search for articles that discuss this Windows Installer error message.  Available beginning with Windows Installer for Windows Server 2003. |
| 1937 | An error occurred during the installation of assembly '[6]'. The signature or catalog could not be verified or is not valid. HRESULT: [3]. {{assembly interface: [4], function: [5], component: [2]}} | For more information, see [Assemblies](assemblies). Help and Support may have published a KB article that discusses the installation of this assembly. Go to the [Search the Support Knowledge Base](https://support.microsoft.com) page and search for articles that discuss this Windows Installer error message.  Available beginning with Windows Installer for Windows Server 2003. |
| 1938 | An error occurred during the installation of assembly '[6]'. One or more modules of the assembly could not be found. HRESULT: [3]. {{assembly interface: [4], function: [5], component: [2]}} | For more information, see [Assemblies](assemblies). Help and Support may have published a KB article that discusses the installation of this assembly. Go to the [Search the Support Knowledge Base](https://support.microsoft.com) page and search for articles that discuss this Windows Installer error message.  Available beginning with Windows Installer for Windows Server 2003. |
| 1939 | Service '[2]' ([3]) could not be configured. This could be a problem with the package or your permissions. Verify that you have sufficient privileges to configure system services. | For information, see[Using Services Configuration](using-services-configuration). Available beginning with Windows Installer 5.0 for Windows 7 and Windows Server 2008 R2. |
| 1940 | Service '[2]' ([3]) could not be configured. Configuring services is supported only on Windows Vista/Server 2008 and above. | For information, see[Using Services Configuration](using-services-configuration). Available beginning with Windows Installer 5.0 for Windows 7 and Windows Server 2008 R2. |
| 1941 | Both LockPermissions and MsiLockPermissionsEx tables were found in the package. Only one of them should be present. This is a problem with the package. | A package cannot contain both the [MsiLockPermissionsEx Table](msilockpermissionsex-table) and the [LockPermissions Table](lockpermissions-table). Available beginning with Windows Installer 5.0 for Windows 7 and Windows Server 2008 R2. |
| 1942 | Multiple conditions ('[2]' and '[3]')have resolved to true while installing Object [4] (from table [5]). This may be a problem with the package. | Available beginning with Windows Installer 5.0 for Windows 7 and Windows Server 2008 R2. |
| 1943 | SDDL string '[2]' for object [3](in table [4]) could not be resolved into a valid Security Descriptor. | See [Securing Resources](securing-resources-) for information on using [MsiLockPermissionsEx](msilockpermissionsex-table) table. Available beginning with Windows Installer 5.0 for Windows 7 and Windows Server 2008 R2. |
| 1944 | Could not set security for service '[3]'. Error: [2]. Verify that you have sufficient privileges to modify the security permissions for this service. | Available beginning with Windows Installer 5.0 for Windows 7 and Windows Server 2008 R2. |
| 1945 | You do not have sufficient privileges to complete the re-advertisement of this product. Re-advertisement requires initiation by a local system account calling the MsiAdvertiseScript API | The process calling [**MsiAdvertiseScript**](/en-us/windows/desktop/api/Msi/nf-msi-msiadvertisescripta) must be running under the LocalSystem account. Available beginning with Windows Installer 5.0 for Windows 7 and Windows Server 2008 R2. |
| 1946 | Property '[2]' for shortcut '[3]' could not be set.{{ HRESULT [4].}} | This message is returned as a warning, and the installation continues, if Windows Installer is unable to set a shortcut property specified in the [MsiShortcutProperty table](msishortcutproperty-table). Available beginning with Windows Installer 5.0 for Windows 7 and Windows Server 2008 R2. |
| 2101 | Shortcuts not supported by the operating system. |  |
| 2102 | Invalid .ini action: [2] |  |
| 2103 | Could not resolve path for shell folder [2]. |  |
| 2104 | Writing .ini file: [3]: System error: [2]. |  |
| 2105 | Shortcut Creation [3] Failed. System error: [2]. |  |
| 2106 | Shortcut Deletion [3] Failed. System error: [2]. |  |
| 2107 | Error [3] registering type library [2]. |  |
| 2108 | Error [3] unregistering type library [2]. |  |
| 2109 | Section missing for .ini action. |  |
| 2110 | Key missing for .ini action. |  |
| 2111 | Detection of running applications failed, could not get performance data. Registered operation returned : [2]. |  |
| 2112 | Detection of running applications failed, could not get performance index. Registered operation returned : [2]. |  |
| 2113 | Detection of running applications failed. |  |
| 2200 | Database: [2]. Database object creation failed, mode = [3]. |  |
| 2201 | Database: [2]. Initialization failed, out of memory. |  |
| 2202 | Database: [2]. Data access failed, out of memory. |  |
| 2203 | Database: [2]. Cannot open database file. System error [3]. |  |
| 2204 | Database: [2]. Table already exists: [3]. |  |
| 2205 | Database: [2]. Table does not exist: [3]. |  |
| 2206 | Database: [2]. Table could not be dropped: [3]. |  |
| 2207 | Database: [2]. Intent violation. |  |
| 2208 | Database: [2]. Insufficient parameters for Execute. |  |
| 2209 | Database: [2]. Cursor in invalid state. |  |
| 2210 | Database: [2]. Invalid update data type in column [3]. |  |
| 2211 | Database: [2]. Could not create database table [3]. |  |
| 2212 | Database: [2]. Database not in writable state. |  |
| 2213 | Database: [2]. Error saving database tables. |  |
| 2214 | Database: [2]. Error writing export file: [3]. |  |
| 2215 | Database: [2]. Cannot open import file: [3]. |  |
| 2216 | Database: [2]. Import file format error: [3], Line [4]. |  |
| 2217 | Database: [2]. Wrong state to CreateOutputDatabase [3]. |  |
| 2218 | Database: [2]. Table name not supplied. |  |
| 2219 | Database: [2]. Invalid Installer database format. |  |
| 2220 | Database: [2]. Invalid row/field data. |  |
| 2221 | Database: [2]. Code page conflict in import file: [3]. |  |
| 2222 | Database: [2]. Transform or merge code page [3] differs from database code page [4]. |  |
| 2223 | Database: [2]. Databases are the same. No transform generated. |  |
| 2224 | Database: [2]. GenerateTransform: Database corrupt. Table: [3]. |  |
| 2225 | Database: [2]. Transform: Cannot transform a temporary table. Table: [3]. |  |
| 2226 | Database: [2]. Transform failed. |  |
| 2227 | Database: [2]. Invalid identifier '[3]' in SQL query: [4]. |  |
| 2228 | Database: [2]. Unknown table '[3]' in SQL query: [4]. |  |
| 2229 | Database: [2]. Could not load table '[3]' in SQL query: [4]. |  |
| 2230 | Database: [2]. Repeated table '[3]' in SQL query: [4]. |  |
| 2231 | Database: [2]. Missing ')' in SQL query: [3]. |  |
| 2232 | Database: [2]. Unexpected token '[3]' in SQL query: [4]. |  |
| 2233 | Database: [2]. No columns in SELECT clause in SQL query: [3]. |  |
| 2234 | Database: [2]. No columns in ORDER BY clause in SQL query: [3]. |  |
| 2235 | Database: [2]. Column '[3]' not present or ambiguous in SQL query: [4]. |  |
| 2236 | Database: [2]. Invalid operator '[3]' in SQL query: [4]. |  |
| 2237 | Database: [2]. Invalid or missing query string: [3]. |  |
| 2238 | Database: [2]. Missing FROM clause in SQL query: [3]. |  |
| 2239 | Database: [2]. Insufficient values in INSERT SQL statement. |  |
| 2240 | Database: [2]. Missing update columns in UPDATE SQL statement. |  |
| 2241 | Database: [2]. Missing insert columns in INSERT SQL statement. |  |
| 2242 | Database: [2]. Column '[3]' repeated. |  |
| 2243 | Database: [2]. No primary columns defined for table creation. |  |
| 2244 | Database: [2]. Invalid type specifier '[3]' in SQL query [4]. |  |
| 2245 | IStorage::Stat failed with error [3]. |  |
| 2246 | Database: [2]. Invalid Installer transform format. |  |
| 2247 | Database: [2] Transform stream read/write failure. |  |
| 2248 | Database: [2] GenerateTransform/Merge: Column type in base table does not match reference table. Table: [3] Col #: [4]. |  |
| 2249 | Database: [2] GenerateTransform: More columns in base table than in reference table. Table: [3]. |  |
| 2250 | Database: [2] Transform: Cannot add existing row. Table: [3]. |  |
| 2251 | Database: [2] Transform: Cannot delete row that does not exist. Table: [3]. |  |
| 2252 | Database: [2] Transform: Cannot add existing table. Table: [3]. |  |
| 2253 | Database: [2] Transform: Cannot delete table that does not exist. Table: [3]. |  |
| 2254 | Database: [2] Transform: Cannot update row that does not exist. Table: [3]. |  |
| 2255 | Database: [2] Transform: Column with this name already exists. Table: [3] Col: [4]. |  |
| 2256 | Database: [2] GenerateTransform/Merge: Number of primary keys in base table does not match reference table. Table: [3]. |  |
| 2257 | Database: [2]. Intent to modify read only table: [3]. |  |
| 2258 | Database: [2]. Type mismatch in parameter: [3]. |  |
| 2259 | Database: [2] Table(s) Update failed | Queries must adhere to the restricted Windows Installer [SQL syntax](sql-syntax). |
| 2260 | Storage CopyTo failed. System error: [3]. |  |
| 2261 | Could not remove stream [2]. System error: [3]. |  |
| 2262 | Stream does not exist: [2]. System error: [3]. |  |
| 2263 | Could not open stream [2]. System error: [3]. |  |
| 2264 | Could not remove stream [2]. System error: [3]. |  |
| 2265 | Could not commit storage. System error: [3]. |  |
| 2266 | Could not rollback storage. System error: [3]. |  |
| 2267 | Could not delete storage [2]. System error: [3]. |  |
| 2268 | Database: [2]. Merge: There were merge conflicts reported in [3] tables. |  |
| 2269 | Database: [2]. Merge: The column count differed in the '[3]' table of the two databases. |  |
| 2270 | Database: [2]. GenerateTransform/Merge: Column name in base table does not match reference table. Table: [3] Col #: [4]. |  |
| 2271 | SummaryInformation write for transform failed. |  |
| 2272 | Database: [2]. MergeDatabase will not write any changes because the database is open read-only. |  |
| 2273 | Database: [2]. MergeDatabase: A reference to the base database was passed as the reference database. |  |
| 2274 | Database: [2]. MergeDatabase: Unable to write errors to Error table. Could be due to a non-nullable column in a predefined Error table. |  |
| 2275 | Database: [2]. Specified Modify [3] operation invalid for table joins. |  |
| 2276 | Database: [2]. Code page [3] not supported by the system. |  |
| 2277 | Database: [2]. Failed to save table [3]. |  |
| 2278 | Database: [2]. Exceeded number of expressions limit of 32 in WHERE clause of SQL query: [3]. |  |
| 2279 | Database: [2] Transform: Too many columns in base table [3]. |  |
| 2280 | Database: [2]. Could not create column [3] for table [4]. |  |
| 2281 | Could not rename stream [2]. System error: [3]. |  |
| 2282 | Stream name invalid [2]. |  |
| 2302 | Patch notify: [2] bytes patched to far. |  |
| 2303 | Error getting volume info. GetLastError: [2]. |  |
| 2304 | Error getting disk free space. GetLastError: [2]. Volume: [3]. |  |
| 2305 | Error waiting for patch thread. GetLastError: [2]. |  |
| 2306 | Could not create thread for patch application. GetLastError: [2]. |  |
| 2307 | Source file key name is null. |  |
| 2308 | Destination file name is null. |  |
| 2309 | Attempting to patch file [2] when patch already in progress. |  |
| 2310 | Attempting to continue patch when no patch is in progress. |  |
| 2315 | Missing path separator: [2]. |  |
| 2318 | File does not exist: [2]. |  |
| 2319 | Error setting file attribute: [3] GetLastError: [2]. |  |
| 2320 | File not writable: [2]. |  |
| 2321 | Error creating file: [2]. |  |
| 2322 | User canceled. |  |
| 2323 | Invalid file attribute. |  |
| 2324 | Could not open file: [3] GetLastError: [2]. |  |
| 2325 | Could not get file time for file: [3] GetLastError: [2]. |  |
| 2326 | Error in FileToDosDateTime. |  |
| 2327 | Could not remove directory: [3] GetLastError: [2]. |  |
| 2328 | Error getting file version info for file: [2]. |  |
| 2329 | Error deleting file: [3]. GetLastError: [2]. |  |
| 2330 | Error getting file attributes: [3]. GetLastError: [2]. |  |
| 2331 | Error loading library [2] or finding entry point [3]. |  |
| 2332 | Error getting file attributes. GetLastError: [2]. |  |
| 2333 | Error setting file attributes. GetLastError: [2]. |  |
| 2334 | Error converting file time to local time for file: [3]. GetLastError: [2]. |  |
| 2335 | Path: [2] is not a parent of [3]. |  |
| 2336 | Error creating temp file on path: [3]. GetLastError: [2]. |  |
| 2337 | Could not close file: [3] GetLastError: [2]. |  |
| 2338 | Could not update resource for file: [3] GetLastError: [2]. |  |
| 2339 | Could not set file time for file: [3] GetLastError: [2]. |  |
| 2340 | Could not update resource for file: [3], Missing resource. |  |
| 2341 | Could not update resource for file: [3], Resource too large. |  |
| 2342 | Could not update resource for file: [3] GetLastError: [2]. |  |
| 2343 | Specified path is empty. |  |
| 2344 | Could not find required file IMAGEHLP.DLL to validate file:[2]. |  |
| 2345 | [2]: File does not contain a valid checksum value. |  |
| 2347 | User ignore. |  |
| 2348 | Error attempting to read from cabinet stream. |  |
| 2349 | Copy resumed with different info. |  |
| 2350 | FDI server error |  |
| 2351 | File key '[2]' not found in cabinet '[3]'. The installation cannot continue. |  |
| 2352 | Could not initialize cabinet file server. The required file 'CABINET.DLL' may be missing. |  |
| 2353 | Not a cabinet. |  |
| 2354 | Cannot handle cabinet. |  |
| 2355 | Corrupt cabinet. |  |
| 2356 | Could not locate cabinet in stream: [2]. | When troubleshooting embedded streams, you may use [WiStream.vbs](manage-binary-streams) to list the streams and use [Msidb.exe](msidb-exe) to export the streams. |
| 2357 | Cannot set attributes. |  |
| 2358 | Error determining whether file is in-use: [3]. GetLastError: [2]. |  |
| 2359 | Unable to create the target file - file may be in use. |  |
| 2360 | Progress tick. |  |
| 2361 | Need next cabinet. |  |
| 2362 | Folder not found: [2]. |  |
| 2363 | Could not enumerate subfolders for folder: [2]. |  |
| 2364 | Bad enumeration constant in CreateCopier call. |  |
| 2365 | Could not BindImage exe file [2]. |  |
| 2366 | User failure. |  |
| 2367 | User abort. |  |
| 2368 | Failed to get network resource information. Error [2], network path [3]. Extended error: network provider [5], error code [4], error description [6]. |  |
| 2370 | Invalid CRC checksum value for [2] file.{ Its header says [3] for checksum, its computed value is [4].} |  |
| 2371 | Could not apply patch to file [2]. GetLastError: [3]. |  |
| 2372 | Patch file [2] is corrupt or of an invalid format. Attempting to patch file [3]. GetLastError: [4]. |  |
| 2373 | File [2] is not a valid patch file. |  |
| 2374 | File [2] is not a valid destination file for patch file [3]. |  |
| 2375 | Unknown patching error: [2]. |  |
| 2376 | Cabinet not found. |  |
| 2379 | Error opening file for read: [3] GetLastError: [2]. |  |
| 2380 | Error opening file for write: [3]. GetLastError: [2]. |  |
| 2381 | Directory does not exist: [2]. |  |
| 2382 | Drive not ready: [2]. |  |
| 2401 | 64-bit registry operation attempted on 32-bit operating system for key [2]. |  |
| 2402 | Out of memory. |  |
| 2501 | Could not create rollback script enumerator. |  |
| 2502 | Called InstallFinalize when no install in progress. |  |
| 2503 | Called RunScript when not marked in progress. |  |
| 2601 | Invalid value for property [2]: '[3]' |  |
| 2602 | The [2] table entry '[3]' has no associated entry in the Media table. |  |
| 2603 | Duplicate table name [2]. |  |
| 2604 | [2] Property undefined. |  |
| 2605 | Could not find server [2] in [3] or [4]. |  |
| 2606 | Value of property [2] is not a valid full path: '[3]'. |  |
| 2607 | Media table not found or empty (required for installation of files). |  |
| 2608 | Could not create security descriptor for object. Error: '[2]'. |  |
| 2609 | Attempt to migrate product settings before initialization. |  |
| 2611 | The file [2] is marked as compressed, but the associated media entry does not specify a cabinet. |  |
| 2612 | Stream not found in '[2]' column. Primary key: '[3]'. |  |
| 2613 | RemoveExistingProducts action sequenced incorrectly. |  |
| 2614 | Could not access IStorage object from installation package. |  |
| 2615 | Skipped unregistration of Module [2] due to source resolution failure. |  |
| 2616 | Companion file [2] parent missing. |  |
| 2617 | Shared component [2] not found in Component table. |  |
| 2618 | Isolated application component [2] not found in Component table. |  |
| 2619 | Isolated components [2], [3] not part of same feature. |  |
| 2620 | Key file of isolated application component [2] not in File table. |  |
| 2621 | Resource DLL or Resource ID information for shortcut [2] set incorrectly. | Available with Windows Installer version 4.0. |
| 2701 | The depth of a feature exceeds the acceptable tree depth of [2] levels. | The maximum depth of any feature is 16. This error is returned if a feature that exceeds the maximum depth exists. |
| 2702 | A Feature table record ([2]) references a non-existent parent in the Attributes field. |  |
| 2703 | Property name for root source path not defined: [2] |  |
| 2704 | Root directory property undefined: [2] |  |
| 2705 | Invalid table: [2]; Could not be linked as tree. |  |
| 2706 | Source paths not created. No path exists for entry [2] in Directory table. |  |
| 2707 | Target paths not created. No path exists for entry [2] in Directory table. |  |
| 2708 | No entries found in the file table. |  |
| 2709 | The specified Component name ('[2]') not found in Component table. |  |
| 2710 | The requested 'Select' state is illegal for this Component. |  |
| 2711 | The specified Feature name ('[2]') not found in Feature table. |  |
| 2712 | Invalid return from modeless dialog: [3], in action [2]. |  |
| 2713 | Null value in a non-nullable column ('[2]') in '[3]' column of the '[4]' table. |  |
| 2714 | Invalid value for default folder name: [2]. |  |
| 2715 | The specified File key ('[2]') not found in the File table. |  |
| 2716 | Could not create a random subcomponent name for component '[2]'. | May occur if the first 40 characters of two or more component names are identical. Ensure that the first 40 characters of component names are unique to the component. |
| 2717 | Bad action condition or error calling custom action '[2]'. |  |
| 2718 | Missing package name for product code '[2]'. |  |
| 2719 | Neither UNC nor drive letter path found in source '[2]'. |  |
| 2720 | Error opening source list key. Error: '[2]' |  |
| 2721 | Custom action [2] not found in Binary table stream. |  |
| 2722 | Custom action [2] not found in File table. |  |
| 2723 | Custom action [2] specifies unsupported type. |  |
| 2724 | The volume label '[2]' on the media you're running from does not match the label '[3]' given in the Media table. This is allowed only if you have only 1 entry in your Media table. |  |
| 2725 | Invalid database tables |  |
| 2726 | Action not found: [2]. |  |
| 2727 | The directory entry '[2]' does not exist in the Directory table. |  |
| 2728 | Table definition error: [2] |  |
| 2729 | Install engine not initialized. |  |
| 2730 | Bad value in database. Table: '[2]'; Primary key: '[3]'; Column: '[4]' |  |
| 2731 | Selection Manager not initialized. | The selection manager is responsible for determining component and feature states. It is initialized during the costing actions ( [CostInitialize action](costinitialize-action), [FileCost action](filecost-action), and [CostFinalize action](costfinalize-action).) A standard action or custom action made a call to a function requiring the selection manager before the initialization of the selection manager. This action should be sequenced after the costing actions. |
| 2732 | Directory Manager not initialized. | The directory manager is responsible for determining the target and source paths. It is initialized during the costing actions ([CostInitialize action](costinitialize-action), [FileCost action](filecost-action), and [CostFinalize action](costfinalize-action)). A standard action or custom action made a call to a function requiring the directory manager before the initialization of the directory manager. This action should be sequenced after the costing actions. |
| 2733 | Bad foreign key ('[2]') in '[3]' column of the '[4]' table. |  |
| 2734 | Invalid reinstall mode character. |  |
| 2735 | Custom action '[2]' has caused an unhandled exception and has been stopped. This may be the result of an internal error in the custom action, such as an access violation. | This error is caused by a custom action that is based on [Dynamic-Link Libraries](dynamic-link-libraries). When trouble-shooting the DLL you may need to use one or more of the tools described in [KB198038](https://support.microsoft.com). |
| 2736 | Generation of custom action temp file failed: [2]. | This error is caused by a custom action that is based on [Dynamic-Link Libraries](dynamic-link-libraries). When trouble-shooting the DLL you may need to use one or more of the tools described in [KB198038](https://support.microsoft.com). |
| 2737 | Could not access custom action [2], entry [3], library [4] | This error is caused by a custom action that is based on [Dynamic-Link Libraries](dynamic-link-libraries). When trouble-shooting the DLL you may need to use one or more of the tools described in [KB198038](https://support.microsoft.com). |
| 2738 | Could not access VBScript run time for custom action [2]. | This error is caused by a custom action that is based on [Dynamic-Link Libraries](dynamic-link-libraries). When trouble-shooting the DLL you may need to use one or more of the tools described in [KB198038](https://support.microsoft.com). |
| 2739 | Could not access JScript run time for custom action [2]. | This error is caused by a custom action that is based on [Dynamic-Link Libraries](dynamic-link-libraries). When trouble-shooting the DLL you may need to use one or more of the tools described in [KB198038](https://support.microsoft.com). |
| 2740 | Custom action [2] script error [3], [4]: [5] Line [6], Column [7], [8]. | This error is caused by a custom action that is based on [Dynamic-Link Libraries](dynamic-link-libraries). When trouble-shooting the DLL you may need to use one or more of the tools described in [KB198038](https://support.microsoft.com). |
| 2741 | Configuration information for product [2] is corrupt. Invalid info: [2]. | This error is caused by a custom action that is based on [Dynamic-Link Libraries](dynamic-link-libraries). When trouble-shooting the DLL you may need to use one or more of the tools described in [KB198038](https://support.microsoft.com). |
| 2742 | Marshaling to Server failed: [2]. | This error is caused by a custom action that is based on [Dynamic-Link Libraries](dynamic-link-libraries). When trouble-shooting the DLL you may need to use one or more of the tools described in [KB198038](https://support.microsoft.com). |
| 2743 | Could not execute custom action [2], location: [3], command: [4]. | This error is caused by a custom action that is based on [Dynamic-Link Libraries](dynamic-link-libraries). When trouble-shooting the DLL you may need to use one or more of the tools described in [KB198038](https://support.microsoft.com). |
| 2744 | EXE failed called by custom action [2], location: [3], command: [4]. | This error is caused by a custom action that is based on [Dynamic-Link Libraries](dynamic-link-libraries). When trouble-shooting the DLL you may need to use one or more of the tools described in [KB198038](https://support.microsoft.com). |
| 2745 | Transform [2] invalid for package [3]. Expected language [4], found language [5]. | The language ID that is specified by the [**ProductLanguage**](productlanguage) property must be contained in the [**Template Summary**](template-summary) property. Perform [package validation](package-validation) and check for [ICE80](ice80). |
| 2746 | Transform [2] invalid for package [3]. Expected product [4], found product [5]. |  |
| 2747 | Transform [2] invalid for package [3]. Expected product version &lt; [4], found product version [5]. |  |
| 2748 | Transform [2] invalid for package [3]. Expected product version &lt;= [4], found product version [5]. |  |
| 2749 | Transform [2] invalid for package [3]. Expected product version == [4], found product version [5]. |  |
| 2750 | Transform [2] invalid for package [3]. Expected product version &gt;= [4], found product version [5]. |  |
| 2751 | Transform [2] invalid for package [3]. Expected product version &gt; [4], found product version [5]. |  |
| 2752 | Could not open transform [2] stored as child storage of package [4]. |  |
| 2753 | The File '[2]' is not marked for installation. |  |
| 2754 | The File '[2]' is not a valid patch file. |  |
| 2755 | Server returned unexpected error [2] attempting to install package [3]. |  |
| 2756 | The property '[2]' was used as a directory property in one or more tables, but no value was ever assigned. |  |
| 2757 | Could not create summary info for transform [2]. |  |
| 2758 | Transform [2] does not contain an MSI version. |  |
| 2759 | Transform [2] version [3] incompatible with engine; Min: [4], Max: [5]. |  |
| 2760 | Transform [2] invalid for package [3]. Expected upgrade code [4], found [5]. |  |
| 2761 | Cannot begin transaction. Global mutex not properly initialized. |  |
| 2762 | Cannot write script record. Transaction not started. | The [InstallExecuteSequence](installexecutesequence-table) may have been authored incorrectly. Actions that change the system must be sequenced between the [InstallInitialize](installinitialize-action) and [InstallFinalize](installfinalize-action) actions. Perform [package validation](package-validation) and check for [ICE77](ice77). |
| 2763 | Cannot run script. Transaction not started. |  |
| 2765 | Assembly name missing from AssemblyName table : Component: [4]. |  |
| 2766 | The file [2] is an invalid MSI storage file. |  |
| 2767 | No more data{ while enumerating [2]}. |  |
| 2768 | Transform in patch package is invalid. |  |
| 2769 | Custom Action [2] did not close [3] MSIHANDLEs. | The [InstallExecuteSequence](installexecutesequence-table) may have been authored incorrectly. Actions that change the system must be sequenced between the [InstallInitialize](installinitialize-action) and [InstallFinalize](installfinalize-action) actions. Perform [package validation](package-validation) and check for [ICE77](ice77). |
| 2770 | Cached folder [2] not defined in internal cache folder table. |  |
| 2771 | Upgrade of feature [2] has a missing component. . | Available beginning with Windows Installer version 3.0. |
| 2772 | New upgrade feature [2] must be a leaf feature. | Available beginning with Windows Installer version 3.0. |
| 2801 | Unknown Message -- Type [2]. No action is taken. |  |
| 2802 | No publisher is found for the event [2]. |  |
| 2803 | Dialog View did not find a record for the dialog [2]. |  |
| 2804 | On activation of the control [3] on dialog [2] CMsiDialog failed to evaluate the condition [3]. |  |
| 2805 |  |  |
| 2806 | The dialog [2] failed to evaluate the condition [3]. |  |
| 2807 | The action [2] is not recognized. |  |
| 2808 | Default button is ill-defined on dialog [2]. |  |
| 2809 | On the dialog [2] the next control pointers do not form a cycle. There is a pointer from [3] to [4], but there is no further pointer. |  |
| 2810 | On the dialog [2] the next control pointers do not form a cycle. There is a pointer from both [3] and [5] to [4]. |  |
| 2811 | On dialog [2] control [3] has to take focus, but it is unable to do so. |  |
| 2812 | The event [2] is not recognized. |  |
| 2813 | The EndDialog event was called with the argument [2], but the dialog has a parent |  |
| 2814 | On the dialog [2] the control [3] names a nonexistent control [4] as the next control. |  |
| 2815 | ControlCondition table has a row without condition for the dialog [2]. |  |
| 2816 | The EventMapping table refers to an invalid control [4] on dialog [2] for the event [3]. |  |
| 2817 | The event [2] failed to set the attribute for the control [4] on dialog [3]. |  |
| 2818 | In the ControlEvent table EndDialog has an unrecognized argument [2]. |  |
| 2819 | Control [3] on dialog [2] needs a property linked to it. |  |
| 2820 | Attempted to initialize an already initialized handler. |  |
| 2821 | Attempted to initialize an already initialized dialog: [2]. |  |
| 2822 | No other method can be called on dialog [2] until all the controls are added. |  |
| 2823 | Attempted to initialize an already initialized control: [3] on dialog [2]. |  |
| 2824 | The dialog attribute [3] needs a record of at least [2] field(s). |  |
| 2825 | The control attribute [3] needs a record of at least [2] field(s). |  |
| 2826 | Control [3] on dialog [2] extends beyond the boundaries of the dialog [4] by [5] pixels. |  |
| 2827 | The button [4] on the radio button group [3] on dialog [2] extends beyond the boundaries of the group [5] by [6] pixels. |  |
| 2828 | Tried to remove control [3] from dialog [2], but the control is not part of the dialog. |  |
| 2829 | Attempt to use an uninitialized dialog. |  |
| 2830 | Attempt to use an uninitialized control on dialog [2]. |  |
| 2831 | The control [3] on dialog [2] does not support [5] the attribute [4]. |  |
| 2832 | The dialog [2] does not support the attribute [3]. |  |
| 2833 | Control [4] on dialog [3] ignored the message [2]. |  |
| 2834 | The next pointers on the dialog [2] do not form a single loop. |  |
| 2835 | The control [2] was not found on dialog [3]. |  |
| 2836 | The control [3] on the dialog [2] cannot take focus. |  |
| 2837 | The control [3] on dialog [2] wants the winproc to return [4]. |  |
| 2838 | The item [2] in the selection table has itself as a parent. |  |
| 2839 | Setting the property [2] failed. |  |
| 2840 | Error dialog name mismatch. |  |
| 2841 | No OK button was found on the error dialog. |  |
| 2842 | No text field was found on the error dialog. |  |
| 2843 | The ErrorString attribute is not supported for standard dialogs. |  |
| 2844 | Cannot execute an error dialog if the Errorstring is not set. |  |
| 2845 | The total width of the buttons exceeds the size of the error dialog. |  |
| 2846 | SetFocus did not find the required control on the error dialog. |  |
| 2847 | The control [3] on dialog [2] has both the icon and the bitmap style set. |  |
| 2848 | Tried to set control [3] as the default button on dialog [2], but the control does not exist. |  |
| 2849 | The control [3] on dialog [2] is of a type, that cannot be integer valued. |  |
| 2850 | Unrecognized volume type. |  |
| 2851 | The data for the icon [2] is not valid. |  |
| 2852 | At least one control has to be added to dialog [2] before it is used. |  |
| 2853 | Dialog [2] is a modeless dialog. The execute method should not be called on it. |  |
| 2854 | On the dialog [2] the control [3] is designated as first active control, but there is no such control. |  |
| 2855 | The radio button group [3] on dialog [2] has fewer than 2 buttons. |  |
| 2856 | Creating a second copy of the dialog [2]. |  |
| 2857 | The directory [2] is mentioned in the selection table but not found. |  |
| 2858 | The data for the bitmap [2] is not valid. |  |
| 2859 | Test error message. |  |
| 2860 | Cancel button is ill-defined on dialog [2]. |  |
| 2861 | The next pointers for the radio buttons on dialog [2] control [3] do not form a cycle. |  |
| 2862 | The attributes for the control [3] on dialog [2] do not define a valid icon size. Setting the size to 16. |  |
| 2863 | The control [3] on dialog [2] needs the icon [4] in size [5]x[5], but that size is not available. Loading the first available size. |  |
| 2864 | The control [3] on dialog [2] received a browse event, but there is no configurable directory for the present selection. Likely cause: browse button is not authored correctly. |  |
| 2865 | Control [3] on billboard [2] extends beyond the boundaries of the billboard [4] by [5] pixels. |  |
| 2866 | The dialog [2] is not allowed to return the argument [3]. |  |
| 2867 | The error dialog property is not set. |  |
| 2868 | The error dialog [2] does not have the error style bit set. |  |
| 2869 | The dialog [2] has the error style bit set, but is not an error dialog. |  |
| 2870 | The help string [4] for control [3] on dialog [2] does not contain the separator character. |  |
| 2871 | The [2] table is out of date: [3]. |  |
| 2872 | The argument of the CheckPath control event on dialog [2] is invalid. | Where "CheckPath" can be the [CheckTargetPath](checktargetpath-controlevent), [SetTargetPath](settargetpath-controlevent) or the [CheckExistingTargetPath](checkexistingtargetpath-controlevent) control events. |
| 2873 | On the dialog [2] the control [3] has an invalid string length limit: [4]. |  |
| 2874 | Changing the text font to [2] failed. |  |
| 2875 | Changing the text color to [2] failed. |  |
| 2876 | The control [3] on dialog [2] had to truncate the string: [4]. |  |
| 2877 | The binary data [2] was not found |  |
| 2878 | On the dialog [2] the control [3] has a possible value: [4]. This is an invalid or duplicate value. |  |
| 2879 | The control [3] on dialog [2] cannot parse the mask string: [4]. |  |
| 2880 | Do not perform the remaining control events. |  |
| 2881 | CMsiHandler initialization failed. |  |
| 2882 | Dialog window class registration failed. |  |
| 2883 | CreateNewDialog failed for the dialog [2]. |  |
| 2884 | Failed to create a window for the dialog [2]. |  |
| 2885 | Failed to create the control [3] on the dialog [2]. | This can be caused by attempting to display a dialog with a [Hyperlink](hyperlink-control) control using Windows Installer 4.5 or earlier. The Hyperlink control requires Windows Installer 5.0. In this case, author two versions of the dialog, one with the control and one without. Use conditional statements to display the dialog box without the control if the [**VersionMsi**](versionmsi) property is less than “5.00”. Display the dialog with the Hyperlink control if **VersionMsi** is greater than or equal to “5.00”. |
| 2886 | Creating the [2] table failed. |  |
| 2887 | Creating a cursor to the [2] table failed. |  |
| 2888 | Executing the [2] view failed. |  |
| 2889 | Creating the window for the control [3] on dialog [2] failed. |  |
| 2890 | The handler failed in creating an initialized dialog. |  |
| 2891 | Failed to destroy window for dialog [2]. |  |
| 2892 | [2] is an integer only control, [3] is not a valid integer value. |  |
| 2893 | The control [3] on dialog [2] can accept property values that are at most [5] characters long. The value [4] exceeds this limit, and has been truncated. |  |
| 2894 | Loading RICHED20.DLL failed. GetLastError() returned: [2]. |  |
| 2895 | Freeing RICHED20.DLL failed. GetLastError() returned: [2]. |  |
| 2896 | Executing action [2] failed. |  |
| 2897 | Failed to create any [2] font on this system. |  |
| 2898 | For [2] textstyle, the system created a '[3]' font, in [4] character set. |  |
| 2899 | Failed to create [2] textstyle. GetLastError() returned: [3]. |  |
| 2901 | Invalid parameter to operation [2]: Parameter [3]. |  |
| 2902 | Operation [2] called out of sequence. | May indicate that the [installation of Win32 assemblies](installation-of-win32-assemblies) was authored incorrectly. A Win32 side-by-side component may need a key path. |
| 2903 | The file [2] is missing. |  |
| 2904 | Could not BindImage file [2]. |  |
| 2905 | Could not read record from script file [2]. |  |
| 2906 | Missing header in script file [2]. |  |
| 2907 | Could not create secure security descriptor. Error: [2]. |  |
| 2908 | Could not register component [2]. |  |
| 2909 | Could not unregister component [2]. |  |
| 2910 | Could not determine user's security ID. |  |
| 2911 | Could not remove the folder [2]. |  |
| 2912 | Could not schedule file [2] for removal on restart. |  |
| 2919 | No cabinet specified for compressed file: [2]. |  |
| 2920 | Source directory not specified for file [2]. |  |
| 2924 | Script [2] version unsupported. Script version: [3], minimum version: [4], maximum version: [5]. |  |
| 2927 | ShellFolder id [2] is invalid. |  |
| 2928 | Exceeded maximum number of sources. Skipping source '[2]'. |  |
| 2929 | Could not determine publishing root. Error: [2]. |  |
| 2932 | Could not create file [2] from script data. Error: [3]. |  |
| 2933 | Could not initialize rollback script [2]. |  |
| 2934 | Could not secure transform [2]. Error [3]. |  |
| 2935 | Could not unsecure transform [2]. Error [3]. |  |
| 2936 | Could not find transform [2]. |  |
| 2937 | Windows Installer cannot install a system file protection catalog. Catalog: [2], Error: [3]. | Windows Installer protects critical system files. For more information, see [Using Windows Installer and Windows Resource Protection](windows-resource-protection-on-windows-vista). For Windows Me, see the [InstallSFPCatalogFile action](installsfpcatalogfile-action), the [FileSFPCatalog table](filesfpcatalog-table), and the [SFPCatalog table](sfpcatalog-table). |
| 2938 | Windows Installer cannot retrieve a system file protection catalog from the cache. Catalog: [2], Error: [3]. | Windows Installer protects critical system files. For more information, see [Using Windows Installer and Windows Resource Protection](windows-resource-protection-on-windows-vista). For Windows Me, see the [InstallSFPCatalogFile action](installsfpcatalogfile-action), the [FileSFPCatalog table](filesfpcatalog-table), and the [SFPCatalog table](sfpcatalog-table). |
| 2939 | Windows Installer cannot delete a system file protection catalog from the cache. Catalog: [2], Error: [3]. | Windows Installer protects critical system files. For more information, see [Using Windows Installer and Windows Resource Protection](windows-resource-protection-on-windows-vista). For Windows Me, see the [InstallSFPCatalogFile action](installsfpcatalogfile-action), the [FileSFPCatalog table](filesfpcatalog-table), and the [SFPCatalog table](sfpcatalog-table). |
| 2940 | Directory Manager not supplied for source resolution. |  |
| 2941 | Unable to compute the CRC for file [2]. |  |
| 2942 | BindImage action has not been executed on [2] file. |  |
| 2943 | This version of Windows does not support deploying 64-bit packages. The script [2] is for a 64-bit package. |  |
| 2944 | GetProductAssignmentType failed. |  |
| 2945 | Installation of ComPlus App [2] failed with error [3]. |  |
| 3001 | The patches in this list contain incorrect sequencing information: [2][3][4][5][6][7][8][9][10][11][12][13][14][15][16]. | Available beginning with Windows Installer version 3.0 |
| 3002 | Patch [2] contains invalid sequencing information. | Available beginning with Windows Installer version 3.0 |