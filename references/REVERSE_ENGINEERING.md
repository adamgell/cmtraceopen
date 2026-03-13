# CMTrace Reverse Engineering Analysis

Binary: `CMTrace.exe` v5.00.9078.1000
Type: PE32+ (64-bit) C++/CLI mixed-mode assembly
Size: 386,960 bytes (377 KB)
Namespace: `Microsoft.ConfigurationManagement.Toolkit.CMTrace`
PDB: `X:\bt\1116398\repo\out\retail-amd64\CMTrace_amd64\CMTrace_amd64.pdb`
Build: `CMTrace_x86.exe` (original filename, despite being 64-bit build)

---

## Window Class Hierarchy

```
SmsTraceWindow          (Main MDI frame window)
├── ReBarWindow32       (Toolbar container/rebar)
│   └── ToolbarWindow32 (Toolbar with highlight field)
├── MDICLIENT           (MDI client area)
│   └── SmsTraceChild   (Per-file child window)
│       ├── SysHeader32     (Column header control)
│       ├── SysListView32   (Main log list view)
│       └── SmsTraceDivider (Info pane splitter/divider)
└── msctls_statusbar32  (Status bar)
```

---

## Menu Structure (Extracted from PE Resources)

```
&File
├── &Open                    Ctrl+O     (ID=40001)
├── Op&en on Server...       Ctrl+Shift+O (ID=40016)
├── &Print...                Ctrl+P     (ID=40012)
├── ─────────────────
├── P&references...                     (ID=40018)
├── ─────────────────
└── Exit                     Alt+F4     (ID=40002)

&Tools
├── &Find...                 Ctrl+F     (ID=40011)
├── Find &Next               F3         (ID=40020)
├── Find &Previous           Shift+F3   (ID=40022)
├── &Copy to Clipboard       Ctrl+C     (ID=40003)
├── ─────────────────
├── &Highlight...                       (ID=40010)
├── Filte&r...                          (ID=40014)
├── Error &Lookup...         Ctrl+L     (ID=122)
├── ─────────────────
├── Pa&use                   Ctrl+U     (ID=40013)
├── Hide &Details            Ctrl+H     (ID=40015)
└── Hide &Info Pane                     (ID=40021)

&Window
├── &Cascade                            (ID=40008)
├── Tile &Horizontally                  (ID=40006)
└── Tile &Vertically                    (ID=40007)

&Help
└── &About Configuration Manager Trace Log Tool  F1  (ID=40005)
```

---

## Keyboard Accelerators (Extracted from PE Resources)

| Shortcut       | Command              | ID    |
|----------------|----------------------|-------|
| Ctrl+O         | Open                 | 40001 |
| Ctrl+Shift+O   | Open on Server       | 40016 |
| Ctrl+P         | Print                | 40012 |
| Ctrl+S         | Save As              | 40004 |
| Ctrl+L         | Error Lookup         | 122   |
| Ctrl+F         | Find                 | 40011 |
| F3             | Find Next            | 40020 |
| Shift+F3       | Find Previous        | 40022 |
| Ctrl+H         | Hide Details         | 40015 |
| Ctrl+U         | Pause                | 40013 |
| Ctrl+C         | Copy to Clipboard    | 40003 |
| F1             | About                | 40005 |
| Ctrl+D         | Time Delta           | 40019 |

---

## String Table (Extracted from PE Resources)

| ID | String |
|----|--------|
| 0  | Configuration Manager Trace Log Tool |
| 1  | Log Files (*.log)\|*.log\|Old Log Files (*.lo_)\|*.lo_\|All Files (*.*)\|*.*\| |
| 2  | Log Text |
| 3  | Component |
| 4  | Date/Time |
| 5  | Thread |
| 6  | Log Files (*.log)\|*.log\|Text Files (*.txt)\|*.txt\|All Files (*.*)\|*.*\| |
| 7  | log |
| 8  | No matches found |
| 9  | Do you want to make this program the default viewer for log files? |
| 10 | &Copy to Clipboard |
| 11 | The file %s either does not exist or could not be accessed. Do you want to continue anyway? |
| 12 | Select the site server whose logs you want to view |
| 13 | Preferences |
| 14 | Elapsed time is %luh %lum %lus %lums (%lu.%03lu seconds) |
| 16 | is equal to |
| 17 | is not equal to |
| 18 | contains |
| 19 | does not contain |
| 20 | is before |
| 21 | is after |
| 32 | An error occured trying to create the destination file |
| 33 | An error occured while writing to the destination file |
| 34 | There is insufficient memory to complete this operation |
| 35 | The path you have selected is invalid or is not an SMS site server |
| 36 | The name you have entered is invalid |
| 37 | The update interval cannot be less than 500 milliseconds |
| 38 | Cannot compare entries with that do not have a timestamp |
| 39 | Error not found |
| 40 | Windows Management (WMI) |
| 41 | Winhttp |
| 42 | Windows |
| 43 | %1 Source: %2 |
| 44 | Microsoft Endpoint Configuration Manager |
| 45 | Windows Update Agent |
| 46 | Version: %1 %2 |
| 47 | (32-bit) |
| 48 | (64-bit) |

### Toolbar Tooltip Strings

| ID    | String |
|-------|--------|
| 40001 | Open (Ctrl+O) |
| 40003 | Copy to Clipboard (Ctrl+C) |
| 40004 | Save As (Ctrl+S) |
| 40010 | Highlight |
| 40011 | Find (Ctrl+F) |
| 40012 | Print (Ctrl+P) |
| 40013 | Pause (Ctrl+U) |
| 40016 | Open on Server (Ctrl+Shift+O) |
| 40019 | Time Delta (Ctrl+D) |
| 40021 | Toggle Info Pane |

---

## Log Parsing Formats (Extracted from Binary)

### Format 1: Full CCM/SCCM Format (scanf patterns from binary)

**Primary pattern** (empty context):
```
<time="%02u:%02u:%02u.%03u%d" date="%02u-%02u-%04u" component="%100[^"]" context="" type="%u" thread="%u" file="%100[^"]"
```

**Secondary pattern** (non-empty context):
```
<time="%02u:%02u:%02u.%03u%d" date="%02u-%02u-%04u" component="%100[^"]" context="%*[^"]" type="%u" thread="%u" file="%100[^"]"
```

**Message extraction markers:**
- Start: `<![LOG[`  (binary also has `[<![LOG[` variant)
- End: `]LOG]!>`

**Parsed fields:**
- time: hours(u), minutes(u), seconds(u), milliseconds(u), timezone_offset(d)
- date: month(u), day(u), year(u)
- component: string up to 100 chars
- context: string (ignored with `%*`)
- type: unsigned int (1=Info, 2=Warning, 3=Error)
- thread: unsigned int
- file: string up to 100 chars

### Format 2: Simple/Legacy Format ($$< delimited)

**Timestamp format string:**
```
%02hu-%02hu-%04hu %02hu:%02hu:%02hu.%03hu%05ld
```
→ `MM-dd-yyyy HH:mm:ss.fff±TTTTT`

**Thread format:**
```
thread=%lu (0x%lX)
```

**Message format pattern:**
```
%s %s %hu %hu:%hu:%hu.%hu %hu %[a-zA-Z ]
```

### Severity Detection

**For CCM format:** Uses `type=` field directly (1/2/3)

**For simple format (text-based detection):**
- Searches for `"error"` (case-insensitive) → Red
- Searches for `"fail"` → Red (with `"failover"` exclusion check)
- Searches for `"warn"` → Yellow
- `" type="` substring check used to distinguish format 1 from format 2

---

## Color System

- Default highlight color: `FFFF00` (Yellow, RGB 255,255,0)
- Color stored as hex string: `%02X%02X%02X` format
- Error rows: Red background with yellow text (type=3)
- Warning rows: Yellow background (type=2)
- Highlight: Configurable color (default yellow)

---

## Registry Settings

**Key:** `HKCU\Software\Microsoft\Trace32`

| Value Name              | Type   | Description |
|-------------------------|--------|-------------|
| FilterText              | String | Current filter text |
| HighlightText           | String | Current highlight text |
| PrintOrientation        | DWORD  | Portrait/Landscape |
| FindText%u              | String | Recent find strings (numbered) |
| ColumnState             | Binary | Column widths/order |
| FilterTextClause        | DWORD  | Filter clause type |
| RefreshInterval         | DWORD  | Refresh interval |
| Column                  | DWORD  | Column visibility |
| FilterThreadClause      | DWORD  | Thread filter clause |
| HighlightCaseSensitive  | DWORD  | Case sensitivity flag |
| Update Interval         | DWORD  | Update interval in ms (min 500) |
| FilterComponent         | String | Component filter |
| PrintColumn             | Binary | Print column config |
| FilterTime              | Binary | Time filter |
| FilterTimeClause        | DWORD  | Time filter clause |
| FilterThread            | String | Thread filter |
| FilterComponentClause   | DWORD  | Component filter clause |
| Highlight Color         | String | Hex RGB color |
| Last Directory          | String | Last opened directory |
| Placement               | Binary | Window placement |
| Maximize                | DWORD  | Window maximized state |
| Ignore Existing Lines   | DWORD  | Ignore existing lines flag |

**File Association Keys:**
```
HKCU\Software\Classes\.log → Log.File
HKCU\Software\Classes\.lo_ → Log.File
HKCU\Software\Classes\Log.File\shell\open\command → "<path>" "%1"
```

**WinPE Detection:**
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\WinPE
```

---

## Filter System

Filter clauses (from string table):
- `is equal to` (ID=16)
- `is not equal to` (ID=17)
- `contains` (ID=18)
- `does not contain` (ID=19)
- `is before` (ID=20, time only)
- `is after` (ID=21, time only)

Filter dimensions:
- FilterText / FilterTextClause → Log Text column
- FilterComponent / FilterComponentClause → Component column
- FilterTime / FilterTimeClause → Date/Time column
- FilterThread / FilterThreadClause → Thread column

---

## Column Display Formats

```
Log Text:    %-*ws        (left-aligned, variable width, wide string)
Component:   %*ws         (right-aligned, variable width, wide string)
Date/Time:   %-*ws        (left-aligned, variable width, wide string)
Thread:      %-4lu (0x%04lX)  or  %lu (0x%04lX)
```

---

## Elapsed Time Display

Format: `Elapsed time is %luh %lum %lus %lums (%lu.%03lu seconds)`

Displayed in status bar. Shows elapsed time between:
- First entry → selected entry (single selection)
- First selected → last selected (range selection)

---

## Open on Server Feature

- Checks for `SMS_` prefix and `SMS_SITE` in share names
- Appends `\Logs` to construct log path
- Uses `WNetOpenEnumW` / `WNetCloseEnum` for network enumeration
- Uses `SHBrowseForFolderW` for folder selection

---

## Error Lookup System

Three sources (from string table IDs 40-42):
1. **Windows** (ID=42) - Uses `FormatMessageW` with system message table
2. **Windows Management (WMI)** (ID=40) - Loads `\wbem\wmiutils.dll`
3. **Winhttp** (ID=41) - Loads `\winhttp.dll`

Additionally contains embedded message table with **710 error codes** covering:
- Windows Update Agent errors (0x0024xxxx, 0x8024xxxx)
- ConfigMgr client errors (0x87D0xxxx)
- SCCM-specific errors (0x87D1xxxx)

---

## Fonts

- Info pane / monospace display: `Courier New`

---

## File Open Dialog

Two filter sets:
1. **Standard open:** `Log Files (*.log)|*.log|Old Log Files (*.lo_)|*.lo_|All Files (*.*)|*.*|`
2. **Save As:** `Log Files (*.log)|*.log|Text Files (*.txt)|*.txt|All Files (*.*)|*.*|`

Open dialog has two checkboxes:
- "Ignore Existing Lines" - only shows new entries
- "Merge selected files" - interleaves multiple files chronologically

---

## Drag and Drop

Uses `DragAcceptFiles` / `DragQueryFileW` for Windows Explorer drag-and-drop support.

---

## Timer System

Uses `SetTimer` / `KillTimer` for:
- Real-time log monitoring (default 500ms interval)
- File change detection

---

## DPI Awareness

Manifest declares: `<dpiAware>true</dpiAware>`

---

## Clipboard

Uses `OpenClipboard` / `EmptyClipboard` / `SetClipboardData` / `CloseClipboard`.
Format: Tab-separated values matching visible column order.

---

## Version Detection

Format string: `%u.%u.%04u.%04u` (major.minor.build.revision)
Uses `GetFileVersionInfoSizeW` / `GetFileVersionInfoW` / `VerQueryValueW`
