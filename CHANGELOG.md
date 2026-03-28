# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [1.0.0] - 2026-03-28

### Highlights

First stable release. CMTrace Open 1.0.0 adds a Diagnostics Collection workspace (Windows-only) for gathering Intune device diagnostics, deeper Windows Setup log analysis with four new structured columns, a fix for the 4-hour timestamp display offset in Intune IME logs, and a TypeScript 6.0 upgrade.

### Added

- **Diagnostics Collection workspace** (Windows-only): New "Collect Diagnostics" command in the Tools menu opens a dialog with category presets (Enrollment, Win32 Apps, Policies, etc.), a full category tree for fine-grained selection, live progress tracking, and a completion summary with per-category gap detection.
- **GUID-to-app-name registry**: Consolidated App/GUID resolution with a serializable registry exposed to the frontend for richer app name display in the Intune workspace.
- **Panther parser — four new columns**: `result_code`, `gle_code`, `setup_phase`, and `operation_name` extracted from Windows Setup (`setupact.log` / `setuperr.log`) message text and surfaced as detail columns.
- **Panther parser — source and thread enrichment**: `source_file` populated from `[exe]` bracketed tags and `Class::Method(line):` patterns in message text; `thread` populated from DISM `TID=` fields.
- **InfoPane metadata row**: When a selected log entry has a result code, GLE code, setup phase, or operation name, a compact summary line is shown at the top of the detail pane.

### Fixed

- **IME log timestamp display** (4-hour offset): Intune IME logs omit the timezone offset from the `time=` field, causing timestamps to be stored as UTC and displayed offset by the local UTC difference (e.g., 4 hours early for EDT users). The parser now falls back to the machine's local timezone when no offset is present.
- **CCM/SCCM log timestamp display**: Timestamps in logs that embed a timezone offset (e.g., `+240` for UTC+4) are now correctly converted to UTC before display.

### Changed

- **TypeScript 6.0**: Frontend toolchain upgraded from TypeScript 5.9.3 to 6.0.2.

### Build

- Hardened Windows build prerequisites script (`Install-CMTraceOpenBuildPrereqs.ps1`) for fresh machines where Visual Studio is absent — resolves null-array crash and `vswhere.exe` not-found errors.
- Winget package detection now queries `winget list` once and checks all packages against a cached in-memory set, eliminating N individual lookups.

## [0.6.0] - 2026-03-24

### Highlights

Major UX overhaul and parser expansion. The log viewer now has dynamic columns derived from the detected parser, a severity icon column, resizable and reorderable columns, a collapsible sidebar, workspace dropdown, multi-file tabs, and a font family picker. Five new log parsers added. The Software Deployment workspace now analyzes folders for MSI/PSADT/Burn deployment outcomes.

### Added

- **Workspace dropdown**: Replaced 5 workspace buttons with a single dropdown selector.
- **Log file tabs**: Tab strip below the toolbar for switching between multiple open log files with overflow dropdown.
- **Dynamic columns**: Columns are now derived automatically from the detected parser — plain text shows only the message column, CCM shows component/dateTime/thread/sourceFile.
- **Severity icon column**: Colored dot (red/yellow/gray) as the leftmost column, always visible.
- **Timestamp-first layout**: Date/Time column now appears before Log Text by default.
- **Resizable columns**: Drag column header borders to resize any column, including Log Text. Widths persist.
- **Reorderable columns**: Drag column headers to reorder. Order persists.
- **Collapsible sidebar**: Chevron button or Ctrl+B to collapse/expand the sidebar. State persists.
- **Font family picker**: Choose any system font in the Accessibility dialog. Font applies to entire app and persists.
- **macOS Intune MDM Daemon parser**: Dedicated parser for pipe-delimited `/Library/Logs/Microsoft/Intune/IntuneMDMDaemon*.log` files. Extracts process, severity, thread, sub-component.
- **Windows DHCP Server parser**: Dedicated parser for `DhcpSrvLog-*.log` and `DhcpV6SrvLog-*.log` with IP Address, Host Name, and MAC Address columns.
- **WiX/Burn bootstrapper parser**: Dedicated parser for `[PID:TID][ISO-timestamp]sNNN:` format logs (vc_redist, .NET runtime, etc.).
- **MSI verbose log parser**: Handles ~12 line patterns including engine messages, action tracking, property dumps, and `MainEngineThread` return values.
- **PSADT Legacy format parser**: Parses `[timestamp] [section] [source] [severity] :: message` logs from PSAppDeployToolkit v4.
- **IME subsystem enrichment**: Extracts `[Subsystem]` prefixes (Win32App, PowerShell, Flighting, etc.) from IME log messages into the Source column.
- **Deployment workspace backend**: `analyze_deployment_folder` Rust command scans folders recursively, classifies format/outcome, extracts exit codes, generates error summaries with error code lookup.
- **PatchMyPC known sources**: Added PatchMyPC Logs Folder and PatchMyPC Install Logs to the Known Sources menu.
- **Batch file parsing**: Single IPC call parses all files in a folder via Rayon parallel processing.
- **Tab entry caching**: Parsed file entries cached in memory for instant tab switching (zero re-parse).
- **Folder load progress overlay**: Full-screen ProgressBar + Spinner during folder loading.

### Changed

- **Toolbar reorganization**: Moved Pause/Refresh/Streaming to sidebar footer, removed Highlight label, replaced native selects with Fluent UI Menu/Dropdown components, pushed Theme to far right.
- **Known Log Sources**: Menu dynamically populated from the full catalog instead of hardcoded single item.

### Performance

- **Zero-allocation severity detection**: Replaced `.to_lowercase()` with byte-level ASCII case folding — eliminates heap allocation per log line.
- **Cached thread display**: `format_thread_display()` cached with thread-local HashMap — ~15 allocations instead of ~30K per file.
- **Combined Simple parser regex**: Merged timestamp and thread regexes into single pass.
- **Error code pre-check**: Fast `"0x"` substring check before running regex on every log line.
- **Timestamped format caching**: Detected format reused for subsequent lines — avoids up to 3 wasted regex attempts per line.

### Fixed

- Dark mode fixes for Accessibility, Filter, ErrorLookup, About, and FileAssociation dialogs.
- Log row height calculation corrected to prevent overlap at larger font sizes.
- Tab strip overflow dropdown now works (was clipped by `overflow: hidden`).
- Sidebar routing for deployment and macOS workspaces (was falling through to DSRegCmd).

## [0.3.0] - 2026-03-13

### Highlights

CMTrace Open 0.3.0 expands the app from a log viewer with Intune diagnostics into a broader troubleshooting tool for Windows management and identity issues. This release adds a dedicated DSRegCmd troubleshooting workspace, supports startup file handling through Windows file association flows, and prepares signed Windows release artifacts for easier distribution in managed environments.

![main workspace of the dsregcmd space](references/dsregcmd1.png)

### Added

- Added a dedicated DSRegCmd troubleshooting workspace for `dsregcmd /status` analysis.
- Added live DSRegCmd capture support so local troubleshooting can collect command output directly from the app.
- Added support for loading DSRegCmd data from pasted text, standalone text captures, and evidence bundles.
- Added bundle-aware DSRegCmd source resolution so the app can recognize valid bundle roots, `evidence` folders, and `command-output` folders.
- Added registry-backed Windows Hello for Business evidence loading using PolicyManager exports and Windows policy hives.
- Added support for Microsoft policy hive correlation under PassportForWork locations such as `HKLM\SOFTWARE\Microsoft\Policies\PassportForWork` and `HKCU\SOFTWARE\Microsoft\Policies\PassportForWork`.
- Added richer DSRegCmd diagnostics including join posture interpretation, failure phase detection, capture confidence, PRT state, MDM signal evaluation, certificate checks, and NGC/Windows Hello context.
- Added a DSRegCmd troubleshooting guide in [DSREGCMD_TROUBLESHOOTING.md](DSREGCMD_TROUBLESHOOTING.md) with walkthroughs and screenshots for the new workspace.
- Added Windows runtime file association handling for `.log` and `.lo_` files.
- Added a standalone prompt flow that can offer to associate log files with CMTrace Open.
- Added startup file-path handoff so the app can consume an associated file path once on launch and route it through the normal open flow.
- Added signed Windows release packaging coverage in the release workflow for x64 and arm64 artifacts.

### Improved

- Improved support for UTF-16 registry export files so `reg.exe export` artifacts can be parsed reliably.
- Improved the startup experience for associated log-file opens by routing them through the same frontend source-loading flow used for other file opens.

### Documentation

- Added end-user documentation for the DSRegCmd troubleshooting workspace.
- Expanded the project’s troubleshooting story beyond log parsing to include device-identity and Windows Hello investigations.

### Notes For Upgraders

- Existing log-viewing and Intune analysis workflows remain intact.
- Windows users opening `.log` or `.lo_` files through Explorer can now route those files directly into CMTrace Open after association is enabled.
- DSRegCmd troubleshooting is most effective when using live capture or a complete evidence bundle that includes registry artifacts.
