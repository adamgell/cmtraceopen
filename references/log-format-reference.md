# Windows Log Format Parsing Reference

**Purpose**: Exact line format specifications for building log parsers in IntuneCommander's CMTrace replacement tool. Each entry includes file location, encoding, line structure, regex pattern, rotation behavior, and implementation notes.

---

## 1. CBS.log — Component-Based Servicing

**Path**: `C:\Windows\Logs\CBS\CBS.log`
**Encoding**: UTF-8 (no BOM)
**Rotation**: At ~50-100 MB, renamed to `CbsPersist_YYYYMMDDHHMMSS.log`, then compressed to `.cab`. Three archived copies retained.

### Line Format

```
YYYY-MM-DD HH:MM:SS, <Level> <Component> <Hex_Sequence_Counter> <Message>
```

### Sample Lines

```
2026-03-09 14:22:31, Info                  CBS    Exec manager: processing started.  session: 30546354_2393949583
2026-03-09 14:22:31, Info                  CSI    00000001 [SR] Verifying 100 (0x00000064) components
2026-03-09 14:22:32, Error                 CBS    Failed to pin deployment while resolving. [HRESULT = 0x80070002]
2026-03-09 14:22:32, Info                  DPX    Started DPX phase: Commit
```

### Parsing Notes

- **Timestamp**: `yyyy-MM-dd HH:mm:ss` — 19 characters, always at position 0.
- **Level**: After the `, ` separator. Right-padded with spaces. Values: `Info`, `Error`, `Warning`, `Perf`.
- **Component**: Variable-width, right-padded. Common: `CBS`, `CSI`, `DPX`, `DISM`, `DIA`, `TI`, `SQM`.
- **Hex Counter**: CSI lines include `XXXXXXXX` hex counter (e.g., `00000001`); CBS/DPX lines do not.
- **[SR] Tag**: SFC entries tagged with `[SR]` — use this to filter SFC-specific entries.
- **Multi-line**: Some entries span multiple lines (component manifests). Lines without a timestamp are continuations of the previous entry.

### Regex

```regex
^(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}),\s+(Info|Error|Warning|Perf)\s+(CBS|CSI|DPX|DISM|DIA|TI|SQM)\s+(.+)$
```

---

## 2. dism.log — Deployment Image Servicing and Management

**Path**: `C:\Windows\Logs\DISM\dism.log`
**Encoding**: UTF-8 (no BOM)
**Rotation**: None. Appends indefinitely. Can grow to hundreds of MB.

### Line Format

```
YYYY-MM-DD HH:MM:SS, <Level> <Component> <Message> [<HRESULT>]
```

### Sample Lines

```
2026-03-09 10:15:22, Info                  DISM   DISM Package Manager: PID=5204 TID=7812 Processing command /Online /Cleanup-image /RestoreHealth - CPackageManagerCLIHandler::Private_ProcessPackageChange
2026-03-09 10:15:22, Info                  DISM   DISM.EXE: Image session has been closed. Reboot required=no.
2026-03-09 10:15:23, Error                 DISM   DISM Package Manager: PID=5204 TID=7812 Error in operation: source files could not be found. [HRESULT = 0x800f081f - CBS_E_SOURCE_MISSING]
```

### Parsing Notes

- **Identical format to CBS.log**. Same timestamp, level, component structure.
- Components: `DISM`, `DISM Package Manager`, `DISM OS Provider`, `DISM Image Session`.
- HRESULT codes appear at end of error lines in `[HRESULT = 0xNNNNNNNN]` format.
- DISM also writes to CBS.log simultaneously.

### Regex

Same as CBS.log — reuse the same parser.

---

## 3. setupapi.dev.log — Driver Installation

**Path**: `C:\Windows\INF\setupapi.dev.log`
**Encoding**: ANSI (system codepage)
**Rotation**: None built-in. Can grow very large (50+ MB over system lifetime).

### Line Format — Section-Based

This log uses a **section-delimited** format with `>>>` (section start) and `<<<` (section end) markers. This is fundamentally different from line-by-line logs.

### Structure

```
>>>  [Section Title - Instance Identifier]
>>>  Section start YYYY/MM/DD HH:MM:SS.mmm
     <prefix>: <message body>
     <prefix>: {<sub-operation>} HH:MM:SS.mmm
     <prefix>: {<sub-operation> - exit(0xNNNNNNNN)} HH:MM:SS.mmm
<<<  Section end YYYY/MM/DD HH:MM:SS.mmm
<<<  [Exit status: SUCCESS]
```

### Sample

```
>>>  [Device Install (Hardware initiated) - USB\VID_045E&PID_07A5\5&2F48C71&0&6]
>>>  Section start 2026/03/09 14:05:57.100
     ump: Creating Install Process: DrvInst.exe 14:05:57.100
     ndv: Retrieving device info...
     ndv: Setting device parameters...
     dvi: {Build Driver List} 14:05:57.115
     dvi:      Searching for hardware ID(s):
     dvi:           usb\vid_045e&pid_07a5&rev_0634
     dvi:           usb\vid_045e&pid_07a5
     dvi: {Build Driver List - exit(0x00000000)} 14:05:57.193
     ndv: Selecting best match from just Driver Store...
<<<  Section end 2026/03/09 14:05:58.220
<<<  [Exit status: SUCCESS]
```

### Parsing Notes

- **Section markers**: `>>>` starts, `<<<` ends. Always 5 leading spaces before the marker.
- **Section title**: In brackets, format `[Type - HardwareID]`. Types include: `Device Install (Hardware initiated)`, `Device Install (DiInstallDriver)`, `DIF_INSTALLDEVICE`, `Boot Session`.
- **Body prefixes**: 5 leading spaces + 3-4 char prefix + `:`. Common: `ump`, `ndv`, `dvi`, `inf`, `cpy`, `sto`, `sig`, `flq`.
- **Sub-operations**: Curly braces `{Operation}` and `{Operation - exit(0xHHHHHHHH)}`.
- **Timestamps**: Section boundaries use `YYYY/MM/DD HH:MM:SS.mmm`. Body lines may have `HH:MM:SS.mmm` at end.
- **Exit status**: `SUCCESS` or `FAILURE(0xHHHHHHHH)`.

### Regex (Section Start)

```regex
^>\s*\[(.+?)(?:\s-\s(.+))?\]\s*$
```

### Regex (Section Boundary Timestamps)

```regex
^[><]{3}\s+Section (?:start|end) (\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d{3})
```

---

## 4. setupapi.setup.log — OS/Application Setup

**Path**: `C:\Windows\INF\setupapi.setup.log`
**Encoding**: ANSI (system codepage)
**Rotation**: None.

### Format

**Identical section-based format to setupapi.dev.log** (`>>>` / `<<<`). Reuse the same parser. Section titles differ — focused on OS setup rather than hardware:

- `[Boot Session YYYY/MM/DD HH:MM:SS.mmm]`
- `[SetupCopyOEMInf - C:\Windows\INF\oem12.inf]`
- `[Setup Online Device Install ...]`

---

## 5. WindowsUpdate.log — Windows Update Traces

**Path**: Generated on demand to `C:\Users\<user>\Desktop\WindowsUpdate.log`
**Source ETLs**: `C:\Windows\Logs\WindowsUpdate\WindowsUpdate.*.etl`
**Generation**: `Get-WindowsUpdateLog` (PowerShell, requires SymbolServer access)
**Encoding**: UTF-8

### Line Format

```
YYYY/MM/DD HH:MM:SS.mmmmmmm PID  TID  <Component>  <Message>
```

### Sample Lines

```
2026/03/09 14:22:31.1234567 17892 5204  Agent           *START*  Finding updates [CallerId = AutomaticUpdates  Id = 1]
2026/03/09 14:22:31.2345678 17892 5204  Agent           Online = Yes; Interactive = No; AllowCachedResults = No; Ignore download priority = No
2026/03/09 14:22:32.3456789 17892 7812  DownloadManager Download job {GUID} for update (GUID) started
2026/03/09 14:22:33.4567890 17892 7812  Handler         FATAL: CBS called Error with 0x80070002,
```

### Parsing Notes

- **Timestamp**: 27 chars — `YYYY/MM/DD HH:MM:SS.nnnnnnn` (100-nanosecond precision).
- **PID/TID**: Space-separated integers after timestamp.
- **Component**: Right-padded, ~15 chars. Common: `Agent`, `Handler`, `DownloadManager`, `Setup`, `Misc`, `IdleTmr`, `Report`, `Driver`, `Service`, `SLS`, `EP`, `DataStore`, `Shared`, `ComApi`, `WuTask`, `PT`, `ProtocolTalker`.
- **Key markers**: `*START*` and `*END*` delimit logical operations. `*FAILED*` and `FATAL:` indicate errors.
- Since this file is decoded from ETL, it's not real-time and is generated as a one-time snapshot.

### Regex

```regex
^(\d{4}/\d{2}/\d{2}\s\d{2}:\d{2}:\d{2}\.\d{7})\s+(\d+)\s+(\d+)\s+(\S+)\s+(.+)$
```

---

## 6. pfirewall.log — Windows Firewall Traffic

**Path**: `C:\Windows\System32\LogFiles\Firewall\pfirewall.log`
**Encoding**: ASCII
**Rotation**: Rolls at configurable max size (default 4 MB). Old file: `pfirewall.log.old`.
**Default state**: **Logging disabled**. Must be enabled per profile (Domain/Private/Public).

### Format: W3C Extended Log File Format

```
#Version: 1.5
#Software: Microsoft Windows Firewall
#Time Format: Local
#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path
2026-03-09 14:35:22 ALLOW TCP 192.168.1.10 192.168.1.1 3249 80 60 S 12345678 0 64240 - - - SEND
2026-03-09 14:35:25 DROP UDP 10.0.0.5 8.8.8.8 50222 53 - - - - - - - - RECEIVE
```

### Parsing Notes

- **Header lines**: Start with `#`. Parse `#Fields:` to dynamically determine column order.
- **Data lines**: Space-delimited. Field count determined by `#Fields:` header.
- **Missing values**: Represented by `-` (hyphen).
- **Action values**: `ALLOW`, `DROP`, `OPEN`, `CLOSE`, `OPEN-INBOUND`, `INFO-EVENTS-LOST`.
- **Path values**: `SEND`, `RECEIVE`, `FORWARD`, `UNKNOWN`.
- **Protocol values**: `TCP`, `UDP`, `ICMP`, `ICMPv6`, and numeric protocol IDs.
- W3C format is self-describing — the `#Fields:` line IS the schema. Build a dynamic parser.

### Regex (data lines)

```regex
^(\d{4}-\d{2}-\d{2})\s(\d{2}:\d{2}:\d{2})\s(\S+)\s(\S+)\s(\S+)\s(\S+)\s(\S+)\s(\S+)\s(.+)$
```

Or split on whitespace after skipping `#` lines.

---

## 7. SrtTrail.txt — Startup Repair Trail

**Path**: `C:\Windows\System32\Logfiles\Srt\SrtTrail.txt`
**Encoding**: UTF-16 LE (with BOM)
**Rotation**: Overwritten each time Startup Repair runs.

### Format: Semi-Structured Plain Text

```
Startup Repair diagnosis and repair log
---------------------------
Last successful boot time: 3/8/2026 10:30:22 PM (GMT)
Number of repair attempts: 1

Session details
---------------------------
System Disk = \Device\Harddisk0
Windows directory = C:\Windows
AutoChk Run = 0
Number of root causes = 1

Test Performed:
---------------------------
Name: Check for updates
Result: Completed successfully. Error code = 0x0
Time taken = 0 ms

Test Performed:
---------------------------
Name: System disk test
Result: Completed successfully. Error code = 0x0
Time taken = 156 ms

Root cause found:
---------------------------
Boot critical file c:\windows\system32\drivers\vsock.sys is corrupt.

Repair action: File repair
Result: Failed. Error code = 0x57
```

### Parsing Notes

- **Not timestamp-per-line**: Uses section headers with dashed separators `---------------------------`.
- **Key-value pairs**: `Name:`, `Result:`, `Error code =`, `Time taken =`, `Root cause found:`, `Repair action:`.
- **Encoding warning**: UTF-16 LE — must handle BOM and wide chars.
- Parse as sections separated by dashed lines. Extract key-value pairs within each section.

---

## 8. PFRO.log — Pending File Rename Operations

**Path**: `C:\Windows\PFRO.log`
**Encoding**: Unicode (UTF-16 LE with BOM)
**Rotation**: Overwritten on each boot.

### Line Format

```
YYYY/MM/DD HH:MM:SS <Operation> <Path1> [-> <Path2>]
```

### Sample Lines

```
2026/03/09 06:12:01.234 Deleted file 'C:\Windows\Temp\tmp1234.tmp'.
2026/03/09 06:12:01.345 Renamed file 'C:\Windows\Temp\newdriver.sys' to 'C:\Windows\System32\drivers\olddriver.sys'.
2026/03/09 06:12:01.456 Could not delete file 'C:\ProgramData\Package Cache\{GUID}\setup.exe'. Error code=32 (0x00000020).
```

### Parsing Notes

- **Timestamp**: `YYYY/MM/DD HH:MM:SS.mmm`.
- **Operations**: `Deleted file`, `Renamed file`, `Could not delete file`, `Could not rename file`.
- **Error codes**: When operations fail, includes `Error code=N (0xNNNNNNNN)`.
- **Paths**: Single-quoted.
- **Encoding warning**: UTF-16 LE — same as SrtTrail.txt.
- Small file. Entire content describes boot-time file operations. Useful for tracking failed cleanup.

### Regex

```regex
^(\d{4}/\d{2}/\d{2}\s\d{2}:\d{2}:\d{2}\.\d{3})\s(.+)$
```

---

## 9. setuperr.log — OS Installation Errors

**Path**: `C:\Windows\Panther\setuperr.log` (also `C:\$Windows.~BT\Sources\Panther\setuperr.log`)
**Encoding**: ANSI / UTF-8 (depends on Windows version)
**Rotation**: None. Cleared at start of new setup session.

### Line Format

```
YYYY-MM-DD HH:MM:SS, Error                 <Component>  <Message>
```

### Sample

```
2026-03-09 08:45:12, Error                 SP     pSPRemoveFileFromSFP: Failed to remove. Error: 0x80070005 [gle=0x80070005]
2026-03-09 08:45:13, Error      [0x080831] MIG    Plugin {GUID}: Failed to apply with hr = 0x80070002
```

### Parsing Notes

- **Same CBS/DISM timestamp format**: `YYYY-MM-DD HH:MM:SS, Level`.
- **Error-only**: Contains only error-level entries. setupact.log has all levels.
- **Components**: `SP` (Setup Platform), `MIG` (Migration), `CONX` (Compat), `MOUPG` (MoSetup Upgrade), `PANTHR`, `IBS`.
- **Hex error codes**: Inline and in brackets `[gle=0x...]`.
- This is a strict subset of setupact.log — same parser works.

---

## 10. setupact.log — OS Installation Actions

**Path**: `C:\Windows\Panther\setupact.log` (also `C:\$Windows.~BT\Sources\Panther\setupact.log`)
**Encoding**: ANSI / UTF-8
**Rotation**: None. Cleared at start of new setup session.

### Line Format (CMTrace-Compatible)

```
YYYY-MM-DD HH:MM:SS, <Level> <pad> <Component>  <Message>
```

### Sample Lines

```
2026-03-09 08:44:01, Info                  SP     Starting SetupPlatform on host: Win32 with args: /Install
2026-03-09 08:44:02, Info                  CONX   pGetHostCSDBuildNumber: Host OS version: 10.0.19045.0
2026-03-09 08:44:03, Info                  MOUPG  SetupHost::Initialize: Mode = [0x1]
2026-03-09 08:44:05, Warning               MIG    COutOfProcPluginFactory::Create: CoCreateInstance failed; hr = 0x80080005
2026-03-09 08:44:10, Error                 SP     CSetupPlatform::ResurrectDriver: Failed. Error: 0x80070002
2026-03-09 08:44:12, Info      [0x0f0082]  PANTHR Callback_CommitModule: Completed phase - System
```

### Parsing Notes

- **Same format family as CBS.log** but with OS setup-specific components.
- **Level**: `Info`, `Warning`, `Error`. Right-padded with spaces.
- **Optional hex in brackets**: `[0xNNNNNN]` appears between level and component on some lines.
- **Components**: `SP`, `CONX`, `MOUPG`, `MIG`, `PANTHR`, `IBS`, `IBSLIB`, `CSI`, `DISM`, `Diag`.
- **Subpaths**: During feature updates, multiple copies exist across `C:\$Windows.~BT\Sources\Panther\`, `C:\Windows\Panther\`, `C:\$Windows.~BT\Sources\Rollback\`.

### Regex

```regex
^(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}),\s+(Info|Warning|Error)\s+(?:\[0x[0-9a-fA-F]+\]\s+)?(\S+)\s+(.+)$
```

---

## 11. MSI*.log — Windows Installer Logs

**Path**: `%TEMP%\MSI*.LOG` (policy-generated) or custom path via `/L*V`
**Encoding**: ANSI (system codepage), occasionally UTF-8
**Rotation**: New file per installation. Random 5-char suffix: `MSIab12c.LOG`.

### Line Format — Multi-Format (context-dependent)

MSI logs have **no single consistent line format**. They alternate between several patterns:

#### Action Lines
```
Action HH:MM:SS: ActionName.
Action start HH:MM:SS: ActionName.
Action ended HH:MM:SS: ActionName. Return value N.
```

#### MSI Engine Lines
```
MSI (s) (PID:TID) [HH:MM:SS:mmm]: <message>
MSI (c) (PID:TID) [HH:MM:SS:mmm]: <message>
```

Where `(s)` = server-side (elevated), `(c)` = client-side.

#### Property/Value Lines
```
Property(S): PropertyName = Value
Property(C): PropertyName = Value
```

#### Raw Output Lines
```
No prefix — custom action stdout/stderr
```

### Sample

```
=== Verbose logging started: 3/9/2026  14:22:31  Build type: SHIP UNICODE 5.00.10011.00  Calling process: C:\Windows\System32\msiexec.exe ===
MSI (s) (C8:0C) [14:22:31:234]: Resetting cached policy values
MSI (s) (C8:0C) [14:22:31:234]: Machine policy value 'Debug' is 0
Action start 14:22:32: InstallValidate.
MSI (s) (C8:0C) [14:22:32:456]: Feature: MyFeature; Installed: Absent;   Request: Local;   Action: Local
MSI (s) (C8:0C) [14:22:32:456]: Component: MyComp; Installed: Absent;   Request: Local;   Action: Local
Action ended 14:22:33: InstallFiles. Return value 1.
```

### Parsing Notes

- **Header line**: Starts with `=== Verbose logging started:` — extract date/time and msiexec caller.
- **Footer line**: `=== Verbose logging stopped:`.
- **Return values**: 0=no action, 1=success, 2=user cancel, 3=fatal error. Search for `Return value 3` to find failures.
- **PID:TID**: Hex format in parentheses (e.g., `(C8:0C)`).
- **Timestamp**: `[HH:MM:SS:mmm]` in brackets on MSI engine lines. `HH:MM:SS` on Action lines.
- **Multi-line**: Custom action output can be arbitrary text with no prefix.
- Best approach: classify each line by prefix pattern, then parse accordingly.

### Regex (MSI Engine Line)

```regex
^MSI\s\([sc]\)\s\(([0-9A-Fa-f]+:[0-9A-Fa-f]+)\)\s\[(\d{2}:\d{2}:\d{2}:\d{3})\]:\s(.+)$
```

### Regex (Action Line)

```regex
^Action\s(?:start\s|ended\s)?(\d{2}:\d{2}:\d{2}):\s(\w+)\.?\s?(?:Return value (\d)\.)?$
```

---

## 12. DirectX.log — DirectX Setup

**Path**: `C:\Windows\DirectX.log`
**Encoding**: ANSI
**Rotation**: Overwritten on each DirectX setup/update.

### Line Format

```
MM/DD/YYYY HH:MM:SS: <Component> - <Message>
```

### Sample

```
03/09/2026 14:22:31: dsetup32: DXDiag: Starting DirectX Setup
03/09/2026 14:22:31: dsetup32: DirectXSetupGetVersion returned 4.09.00.0904
03/09/2026 14:22:32: dxupdate: Installing: oem0.inf
03/09/2026 14:22:33: dxupdate: DirectX installation completed successfully.
```

### Parsing Notes

- **Timestamp**: `MM/DD/YYYY HH:MM:SS` (US date format) followed by `: `.
- **Component**: `dsetup32`, `dxupdate`, etc.
- **Separator**: ` - ` or `: ` between component and message.
- Relatively small file. Simple line-by-line parser.
- Largely legacy (DirectX is now serviced via Windows Update), but still written by some game/app installers.

### Regex

```regex
^(\d{2}/\d{2}/\d{4}\s\d{2}:\d{2}:\d{2}):\s(\w+):\s(.+)$
```

---

## 13. DPX.log — Data Package Expander

**Path**: `C:\Windows\Logs\DPX\setupact.log` and `C:\Windows\Logs\DPX\setuperr.log`
**Encoding**: ANSI / UTF-8
**Rotation**: None.

### Format

DPX (Data Package eXtraction) entries also appear **within CBS.log** with the `DPX` component prefix. The dedicated DPX logs in `C:\Windows\Logs\DPX\` follow the **same CBS.log format**:

```
YYYY-MM-DD HH:MM:SS, Info                  DPX    Started DPX phase: Commit
YYYY-MM-DD HH:MM:SS, Info                  DPX    DPX has been committed
YYYY-MM-DD HH:MM:SS, Error                 DPX    Failed to extract package. Error: 0x80070002
```

### Parsing Notes

- **Reuse CBS.log parser**. Identical line structure.
- DPX handles extraction and staging of update packages before CBS processes them.
- Phases: `Start`, `Commit`, `End`.

---

## 14. ReportingEvents.log — Windows Update Reporting

**Path**: `C:\Windows\SoftwareDistribution\ReportingEvents.log`
**Encoding**: ANSI / UTF-8
**Rotation**: None. Grows until SoftwareDistribution folder is cleared.

### Line Format

```
{<GUID>}	YYYY-MM-DD HH:MM:SS:mmm[+-]HHMM	<EventID>	<Category>	<Level>	<Agent>	<hr=0xNNNNNNNN>	<Message>
```

### Sample

```
{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}	2026-03-09 14:22:31:234+0500	1	182	101	{00000000-0000-0000-0000-000000000000}	0	0	AutomaticUpdates	Success	Content Install	Installation Successful: Windows successfully installed the following update: Security Update (KB5034441)
```

### Parsing Notes

- **Tab-delimited** (critical — not space-delimited).
- **Fields**: GUID, Timestamp (with timezone offset), numeric EventID, numeric Category, numeric Level, Update GUID, HRESULT, additional numeric, Agent name, Status, Operation type, Message text.
- **Timestamp includes timezone offset**: `+HHMM` or `-HHMM`.
- Quick scan file — fastest way to see WU scan/download/install history with result codes.
- Parse by splitting on `\t`.

---

## 15. WinSetup.log — Modern Setup Host

**Path**: `C:\$Windows.~BT\Sources\Panther\setupact.log` (same physical file as setupact during upgrades)
**Alternative**: `C:\Windows\Panther\NewOS\Panther\setupact.log` (post-first-reboot)
**Encoding**: ANSI / UTF-8

### Format

Modern Setup (Windows 10/11 feature updates) writes to setupact.log in the **same CBS/setupact format**. The key differentiator is the `MOUPG` (Modern Upgrade) component:

```
YYYY-MM-DD HH:MM:SS, Info                  MOUPG  SetupHost::Initialize: Mode = [0x1]
YYYY-MM-DD HH:MM:SS, Info                  MOUPG  SetupHost::Initialize: Scenario = [0x6]
YYYY-MM-DD HH:MM:SS, Info                  MOUPG  SetupHost: Setup build version is: 10.0.26100.1 (ge_release.240101-1200)
```

### Parsing Notes

- **Reuse setupact.log parser**. `MOUPG` component = Modern Setup operations.
- During upgrades, setupact.log content shifts across multiple directory locations at different phases:
  - **Downlevel**: `C:\$Windows.~BT\Sources\Panther\setupact.log`
  - **SafeOS/WinPE**: Same path, but running in WinPE
  - **First boot**: `C:\$Windows.~BT\Sources\Panther\setupact.log`
  - **Second boot**: `C:\Windows\Panther\setupact.log`
  - **Rollback**: `C:\$Windows.~BT\Sources\Rollback\setupact.log`
- `C:\$Windows.~WS\` is the staging working set (contains sources used by setup).

---

## 16. MoSetup.log — Media Creation Tool / Upgrade Assistant

**Path**: `C:\$Windows.~BT\Sources\Panther\setupact.log` (MoSetup entries are within setupact.log)
**Also**: `C:\Windows\Logs\MoSetup\BlueBox.log`
**Encoding**: UTF-8

### BlueBox.log Format

```
[HHMM] <Message>
```

### Sample

```
[1422] MOUPG Entering MoSetupPlatform::InitializeSelfUpdate
[1422] MOUPG SelfUpdate: Current version: 10.0.19041.1; Update version: 10.0.19045.2006
[1422] MOUPG FATAL: SelfUpdate check failed: hr = 0x80072EFD
```

### Parsing Notes

- **BlueBox.log**: Short-format log used when WU/WSUS triggers setup. `[HHMM]` is hour+minute, no seconds.
- **MoSetup entries in setupact.log**: Use `MOUPG` component — parsed with setupact.log regex.
- **Registry progress**: `HKLM\SYSTEM\Setup\MoSetup\volatile\SetupProgress` — binary 0-100 (volatile, only during upgrade).
- MoSetup is the modern orchestrator that replaces the legacy setup.exe flow.

---

## 17. Diagerr.xml / Diagwrn.xml — System Diagnostics

**Path**: `C:\$Windows.~BT\Sources\Panther\Diagerr.xml` and `C:\$Windows.~BT\Sources\Panther\Diagwrn.xml`
**Encoding**: UTF-8 with XML declaration
**Rotation**: Overwritten per setup session.

### Format: XML

```xml
<?xml version="1.0" encoding="utf-8"?>
<Collection>
  <Diagnostic>
    <DateTime>2026-03-09T14:22:31</DateTime>
    <Component>Compat</Component>
    <Level>Error</Level>
    <Message>Application block: AppName version 1.0 is not compatible</Message>
    <ErrorCode>0xC1900208</ErrorCode>
  </Diagnostic>
  <!-- ... more entries ... -->
</Collection>
```

### Parsing Notes

- **Diagerr.xml**: Error-level diagnostics from setup compatibility checks.
- **Diagwrn.xml**: Warning-level diagnostics.
- **Standard XML**: Use any XML parser. Each `<Diagnostic>` element is one entry.
- **Key fields**: `DateTime`, `Component`, `Level`, `Message`, `ErrorCode`.
- These are generated by the **compat scan** phase of Windows upgrades and contain app/driver blocks.

---

## 18. VSS Logs — Volume Shadow Copy Service

**There is no single flat VSS log file.** VSS diagnostics are distributed across:

### Event Log Channels

| Channel | Purpose |
|---|---|
| `Application` | VSS writer events (Event Source: `VSS`) |
| `System` | VSS service events |
| `Microsoft-Windows-NTFS/Operational` | Shadow copy storage operations |

### Key Event IDs (Application Log, Source: VSS)

| Event ID | Meaning |
|---|---|
| 8193 | VSS error — volume shadow copy operation failed |
| 8194 | VSS warning |
| 12289 | VSS backup started |
| 12290 | VSS backup completed |
| 12291 | VSS writer reported error |
| 12292 | Snapshot creation failed |

### Debug Tracing (ETW-based)

Enable via registry: `HKLM\System\CurrentControlSet\Services\VSS\Debug\Tracing` with DWORD `TraceLevel` = 0xFFFFFFFF. Traces go to `C:\Windows\Temp\VolSnap*.log` (format: plain text, variable structure).

### Parsing Notes

- **Primary source**: Event logs (EVTX). Use `Get-WinEvent -ProviderName VSS`.
- **Command-line diagnostics**: `vssadmin list writers`, `vssadmin list shadows`, `vssadmin list providers`.
- No standard flat-file log. For the tool's quick-access menu, open the Application event log filtered to Source=VSS.

---

## 19. WlanMgr.log — Wireless Networking (SCCM/ConfigMgr)

**Important distinction**: `WlanMgr.log` is a **Configuration Manager (SCCM/ConfigMgr) client log**, NOT a native Windows log. It exists only on machines with the ConfigMgr client installed.

**Path (if ConfigMgr client installed)**: `C:\Windows\CCM\Logs\WlanMgr.log`
**Format**: CMTrace format (identical to SCCM client logs).

### Native Windows Wi-Fi Logs (alternatives for non-ConfigMgr machines)

| Source | Path/Command | Format |
|---|---|---|
| WLAN AutoConfig event log | `Microsoft-Windows-WLAN-AutoConfig/Operational` | EVTX |
| netsh wlan report | `netsh wlan show wlanreport` → `C:\ProgramData\Microsoft\Windows\WlanReport\wlan-report-latest.html` | HTML |
| Wireless Diagnostics ETL | `C:\Windows\System32\LogFiles\WMI\WifiDiagLog.etl` | ETL |

### CMTrace Format (for ConfigMgr WlanMgr.log)

```
<![LOG[<message>]LOG]!><time="HH:MM:SS.mmm+offset" date="MM-DD-YYYY" component="WlanMgr" context="" type="N" thread="TID" file="sourcefile:line">
```

Where `type`: 1=Info, 2=Warning, 3=Error.

### Regex (CMTrace format)

```regex
<!\[LOG\[(.+?)\]LOG\]!><time="(\d{2}:\d{2}:\d{2}\.\d{3})[^"]*"\sdate="(\d{2}-\d{2}-\d{4})"\scomponent="([^"]+)"\scontext="[^"]*"\stype="(\d)"\sthread="(\d+)"\sfile="([^"]*)">
```

---

## 20. Shell.log — Explorer/Shell Events (SCCM/ConfigMgr)

**Same caveat as WlanMgr.log**: This is a **ConfigMgr client log** at `C:\Windows\CCM\Logs\` — not a native Windows log.

### CMTrace Format

Identical to WlanMgr.log above — same parser, different component name.

### Native Windows Shell/Explorer Logs (alternatives)

| Source | Location | Format |
|---|---|---|
| ShellExperienceHost logs | `Microsoft-Windows-Shell-Core/Operational` | EVTX |
| Explorer crash logs | `%LOCALAPPDATA%\CrashDumps\explorer.exe.*.dmp` | Minidump |
| Reliability Monitor | `Microsoft-Windows-Diagnostics-Performance/Operational` | EVTX |
| Application event log | Event Source: `Explorer`, `Application Error` | EVTX |

### Parsing Notes

- For IntuneCommander (non-ConfigMgr context), Shell/Explorer diagnostics are best accessed via Event Viewer channels, not flat files.
- If ConfigMgr client is present, use the CMTrace parser.

---

## Parser Implementation Summary

For IntuneCommander, the 20 logs reduce to **7 distinct parser types**:

| Parser Type | Logs Using It | Detection |
|---|---|---|
| **CBS/Panther** (`timestamp, Level Component Message`) | CBS.log, dism.log, DPX, setupact.log, setuperr.log, WinSetup/MoSetup entries | First line matches `YYYY-MM-DD HH:MM:SS, ` |
| **SetupAPI Section** (`>>>` / `<<<` blocks) | setupapi.dev.log, setupapi.setup.log | File contains `>>> ` at start of line |
| **W3C Extended** (header + space-delimited data) | pfirewall.log | `#Version:` and `#Fields:` in header |
| **MSI Mixed** (action lines + MSI engine lines) | MSI*.LOG | First line starts with `===` or contains `MSI (` |
| **CMTrace XML** (`<![LOG[` wrapper) | WlanMgr.log, Shell.log (ConfigMgr only), all IME logs | Contains `<![LOG[` |
| **Tab-Delimited** | ReportingEvents.log | Contains tab characters and GUID prefix |
| **XML** | Diagerr.xml, Diagwrn.xml | Starts with `<?xml` |
| **Key-Value / Section** (unique formats) | SrtTrail.txt (UTF-16, section-based), PFRO.log (UTF-16, timestamped ops), DirectX.log (US date), WindowsUpdate.log (7-digit precision) | Per-file detection needed |

### Auto-Detection Algorithm

```
1. Read first 512 bytes (handle UTF-16 BOM)
2. If starts with "<?xml" → XML parser
3. If contains "<![LOG[" → CMTrace parser
4. If contains "#Version:" or "#Fields:" → W3C parser
5. If contains ">>> " at line start → SetupAPI Section parser
6. If first line starts with "===" or contains "MSI (" → MSI parser
7. If first data line starts with "{" and contains \t → ReportingEvents (tab) parser
8. If matches "YYYY-MM-DD HH:MM:SS, " → CBS/Panther parser
9. If matches "YYYY/MM/DD HH:MM:SS.NNNNNNN" → WindowsUpdate.log parser
10. If matches "MM/DD/YYYY HH:MM:SS:" → DirectX parser
11. If matches "YYYY/MM/DD HH:MM:SS.NNN" → PFRO parser
12. Fallback → plain text viewer with line numbers
```
