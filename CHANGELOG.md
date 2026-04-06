# Changelog

All notable changes to this project will be documented in this file.

## [1.1.0] - 2026-04-05

### Added

- **Settings dialog** (replaces Accessibility dialog): Full settings UI with tabs for Appearance (themes, font size), Columns (visibility, ordering), Behavior (confirm tab close), Updates (auto-update toggle), and File Associations (Windows-only). Accessible via `Ctrl+,` or Window menu.
- **Context menu**: Right-click any log row for Copy Line, Copy Message, Jump to Line, Quick Filter by severity/component, Reveal in File Manager, and Error Lookup. Uses native Tauri menu popup for OS-native feel.
- **Event Log workspace** (Windows, feature-gated): Parse `.evtx` files and query live Windows Event Log channels. Supports file-based EVTX parsing with channel grouping, severity filtering, and correlation linking. Frontend workspace with channel sidebar, severity badges, and detail pane. Live queries use Win32 Event Log API (`EvtQuery`, `EvtRender`, `EvtFormatMessage`). "This Computer" auto-loads Application, System, Security, and Setup channels in parallel with progressive UI updates. Event Viewer-style nested tree sidebar (split on `-` and `/`) with resizable drag handle. Arrow key navigation, resizable detail pane, per-channel load/refresh buttons, and loading spinner with elapsed time in the status bar.
- **AppWorkload enrichment**: Parse "Get policies" JSON payloads in the log viewer to build GUID-to-app-name mappings. InfoPane shows resolved app names when log messages contain GUIDs, structured policy metadata cards, and decoded base64 PowerShell detection scripts via a lightweight syntax-highlighted code viewer.
- **Activity view**: New "Activity" toggle in the Intune timeline tab groups events by app into collapsible cards. Each card shows worst status, event count, duration, and event type badges. Expanded rows display parsed structured fields (intent, detection, applicability, reboot, GRS expired, enforcement) as colored tags with inline GUID resolution and word-wrapped detail messages.
- **GUID Registry dialog**: New Tools menu item showing a searchable table of all GUID-to-app-name mappings from the Intune analysis, with source confidence ranking (GraphApi > ApplicationName > Name > SetUpFilePath) and click-to-copy.
- **Microsoft Graph API integration** (Windows, opt-in): Resolve Intune app GUIDs to display names via Microsoft Graph API. Authenticates silently using WAM (Web Account Manager) with the device's existing Entra ID session — no app registration required. Gated behind Settings > Graph API toggle (off by default) with consent warnings. Pre-populate cache fetches all apps, remediation scripts, platform scripts, and shell scripts in one call. GUID Registry dialog shows entries in tabbed view (All/Apps/Scripts/Remediations) with publisher and category columns. Auto-connects on startup when enabled, with status indicator in the status bar.
- **SideCarScriptDetectionManager events**: Extract PowerShell script detection lifecycle events (start, complete, exit code, process ID) as standalone PowerShellScript events in the Intune timeline.
- **Resizable InfoPane**: Drag handle between the log list and detail pane allows resizing (min 80px, max 70% viewport).
- **Jump to Line**: Context menu action to jump to a specific line number in the log.
- **Reveal in File Manager**: Context menu action to open the source file's location in Finder/Explorer.
- **Quick Filter**: Context menu action to instantly filter by the selected row's severity or component.
- **Multi-file unified timeline**: Merge entries from multiple open log files into a single time-sorted view. Two entry points: "Merge Tabs..." button in the toolbar and "Merge into Timeline" button in the folder sidebar. Color-coded left borders distinguish source files. A legend bar provides per-file toggle visibility, correlation time window, and auto-correlate controls. Cross-file timestamp correlation highlights entries from other files within a configurable time window and shows them in the InfoPane with delta timestamps.
- **Session save/restore**: Save the current workspace state (open files, scroll positions, filters, merged tabs, workspace context) to a `.cmtrace` JSON file via File > Save Session (Ctrl+Shift+S). Restore via File > Open Session or Recent Sessions submenu. Files are integrity-checked with SHA-256 hashes — warns if files have changed or are missing since the session was saved. New `compute_file_hash` Rust backend command.
- **Log diff**: Compare two open log files side-by-side or in unified inline view. Fuzzy pattern matching normalizes GUIDs, timestamps, and long numbers so "same event, different instance" lines are recognized as matches. Stats bar shows common patterns vs. lines unique to each file. "Diff Tabs..." button in the toolbar opens a config dialog for source selection.
- **Sysmon EVTX workspace** (PR #72): Full Sysmon analysis workspace for Windows `.evtx` event log files.
  - **Rust backend** (`src-tauri/src/sysmon/`): EVTX parser that reads all events (no cap) and classifies them into 23 Sysmon event types — process creation (ID 1), network connections (ID 3), file operations (IDs 11, 15, 23), registry activity (IDs 12, 13, 14), DNS queries (ID 22), image loads (ID 7), driver loads (ID 6), WMI activity (IDs 19, 20, 21), and more. Extracts structured fields (process names, hashes, parent processes, network destinations, registry keys) from XML event data. Produces dashboard aggregations: timeline bucketing with auto-scaling resolution (minute/5-minute/hourly/daily based on time span), top-N ranked lists (processes, network destinations, DNS queries, registry keys), event type distribution, and security alert classification (high-severity events like process injection, credential access, driver loads). Config extraction from event IDs 4/16 with hash algorithm inference. Pre-allocated HashMaps for 100K+ event performance. 14 backend tests covering summary generation, timeline bucketing, top-N ranking, config extraction, and security classification.
  - **Frontend** (`src/components/sysmon/`): Four-tab workspace — Dashboard (metric cards, event type donut chart, timeline histogram, security alerts, top process/network/DNS/registry lists), Events (searchable table with severity filtering and TanStack Virtual scrolling), Summary (file metadata), Config (Sysmon configuration XML viewer). Theme-aware chart colors via Fluent UI tokens. Zustand store with analysis progress events matching the Intune workspace pattern.
  - **Integration**: Registered as "sysmon" workspace with in-workspace source picker — "Open .evtx Files" button and "This Computer" button (Windows) to query the live Sysmon event log. Toolbar workspace switcher, progress listener hook, `analyze_sysmon_logs` Tauri IPC command.
- **Intune failed app context**: Expanded failed AppWorkload context export with polished output for troubleshooting failed app deployments.

### Fixed

- **PR #82 review fixes**: Resolved merged-tab ID collisions by prefixing entry IDs with source file index. Session restore now persists recent sessions to `localStorage` on save. Correlation refresh no longer stalls when switching merged tabs. Diff view properly cleans up state on close.
- **Intune cross-file sorting** (PR #78): Unified timeline sorting across multiple Intune log files now sorts by datetime consistently, fixing out-of-order entries when merging rotated log files.
- **Code review fixes** (PR #81): Scroll sync no longer fights user interaction. Session restore validates file paths before loading. Merge entry deduplication uses stable sort. UTF-8 safety enforced in merge filename display. GUID casing normalized to lowercase for consistent lookups.
- **Rotated AppWorkload parsing**: Rotated AppWorkload files (e.g., `AppWorkload-20260401-160729.log`) now correctly parse as LogicalRecord framing instead of falling back to PhysicalLine. Changed IME filename detection from exact match to prefix match.
- **GUID extraction priority**: App GUID extraction now prefers "for app <GUID>" patterns over generic first-GUID matching, preventing user GUIDs from being used as app identifiers in StatusReport lines.
- **Tab close cleanup**: Closing the last tab now properly clears log content, filters, and UI state (#55).
- **Button types**: Added explicit `type="button"` to prevent unintended form submissions.
- **Sysmon feature gating**: Sysmon module properly gated behind `sysmon` feature flag to prevent compilation on non-Windows targets without the feature enabled. Fixed clippy warnings in sysmon module.
- **Graph API merge conflicts**: Resolved integration conflicts between Graph API GUID resolution and existing Intune pipeline code.
- **Session save silent failure**: Save Session no longer silently does nothing when no tabs are open — the save dialog always appears so workspace state and filters can still be saved.
- **Session restore with missing files**: Restore no longer bails entirely when saved files are missing — workspace state, filters, and available files are still restored.
- **Sysmon workspace not visible**: The Sysmon workspace was missing from `get_available_workspaces()` and never appeared in the workspace switcher. Added the `sysmon` feature gate.
- **Duplicate imports after merge**: Removed duplicate `use tauri::Manager` and `use graph_api::GraphAuthState` imports in `lib.rs`.

### Changed

- **Columns determined by parser**: Active columns are now derived from the detected parser format, not user toggles. Removed `hiddenColumns` from UI state.

### Security

- **CI workflow permissions**: Added explicit `contents: read` and `actions: read` permissions to CI workflow to follow least-privilege principle.

## [1.0.3] - 2026-03-31

### Added

- **IIS W3C log parser** (PR #69): Dedicated parser for IIS W3C Extended log format (`C:\inetpub\logs\LogFiles\W3SVC*`). Auto-detects from the `#Software: Microsoft Internet Information Services` header and dynamically maps fields from the `#Fields:` directive. Surfaces structured columns: Method, URI, Status, Client IP, Server IP, Time (ms), and User Agent. Derives row severity from HTTP status class (4xx → warning, 5xx → error). Added IIS Logs to Windows known sources.
- **Intune column sorting** (PR #73): Clickable column header sorting on the Download Stats table (Content, Size, Speed, DO %, Duration, Timestamp) and a sort dropdown with direction toggle on the Event Timeline (Time, Name, Type, Status, Duration). Backend pre-computes epoch timestamps for instant client-side sorting. Null values always sort last regardless of direction. Sort state resets on new analysis.
- **Lite build variant** (PR #68): Feature-gated build that keeps the core log viewer, parser stack, tailing, filtering, and error lookup while compiling out diagnostic workspaces (Intune, DSRegCmd, Deployment, Collector, macOS diagnostics) and their heavier dependencies. Built with `--no-default-features`. Frontend dynamically hides unavailable workspaces via a `get_available_workspaces` backend command. Separate `tauri.lite.conf.json` produces a "CMTrace Open Lite" branded app.

### Changed

- **Release signing** (PR #68): Windows codesign workflow now signs application binaries *before* bundling into NSIS and MSI installers, ensuring the installed EXE carries a valid signature. Previously only the outer installer packages were signed, causing ASR rules to block the extracted unsigned binary. MSI built via Master Packager Dev with integrated Azure Trusted Signing.

## [1.0.2] - 2026-03-29

### Added

- **Auto-update checking**: The app now checks for new releases on startup and displays an in-app update prompt when a newer version is available. Updates can be downloaded and installed without leaving the app. Powered by `tauri-plugin-updater` and `tauri-plugin-process`.

### Improved

- **App icon**: Replaced logo with a simplified flame icon on a transparent background for cleaner appearance across platforms.
- **Codebase quality**: Migrated 20 internal helper functions from `Result<_, String>` to typed `AppError`, consolidated all `eprintln`/`println` calls to `log::` macros, migrated 23 files from `once_cell::sync::Lazy` to `std::sync::OnceLock`, and decomposed large UI components (`getFactGroups`, `NewIntuneWorkspace`, `EvidenceBundleDialog`) into focused modules.
- **Performance**: Extracted and memoized `EventTimelineRow` component to reduce unnecessary re-renders in the Intune timeline.

### Fixed

- **Duration display bug**: Fixed incorrect duration calculation in timeline views.
- **Accessibility**: Improved color contrast and focus indicators across dark theme components.
- **Path traversal hardening**: Added validation to prevent path traversal in file handling.
- **CSS alpha values**: Fixed invalid CSS alpha channel values in several theme tokens.
- **CI configuration**: Updated `cargo-deny` config for v0.16+ and v0.17+ compatibility, added missing permissive licenses to the allow list, and suppressed unmaintained-crate advisories from Tauri transitive dependencies.

## [1.0.1] - 2026-03-28

### Fixed

- **Timestamp display offset**: Timestamps from logs written on machines in different timezones (e.g., UTC+8) now display correctly, matching the original CMTrace behavior. Previously, the app converted UTC epoch millis back to the viewer's local timezone, causing an 8-hour (or other) offset.
- **24h/12h time format refresh**: Date/time format preferences are now refreshed from the Windows registry when the app regains focus, so switching between 24-hour and AM/PM in Windows Settings takes effect without restarting the app.

## [1.0.0] - 2026-03-28

### Highlights

First stable release. Since v0.5.0, CMTrace Open has received a complete UX overhaul with eight themes, a multi-tab file browser, dynamic parser-aware columns, five new log parsers, an embedded 411-code error intelligence layer, a Software Deployment analysis workspace, a Windows Diagnostics Collection tool, multi-file open and drag-drop, an inline Ctrl+F find bar, timezone-correct timestamps across all parsers, and deeper Windows Setup and DSRegCmd analysis.

### Workspaces

- **Software Deployment workspace**: Analyze a deployment folder (MSI, PSADT, WiX/Burn logs) in one click. `analyze_deployment_folder` scans recursively, classifies each log's format and outcome, extracts exit codes, app name, version, deploy type, and timestamps, and generates per-entry error summaries with code lookups. Deployment errors appear as rich cards with an "Open in Log Viewer" button that scrolls directly to the offending line.
- **Diagnostics Collection workspace** (Windows-only): "Collect Diagnostics" in the Tools menu concurrently collects 32 log patterns, 61 registry keys, 42 event log channels, 6 file exports, and 30 command outputs across Intune, Autopilot, Networking, Security, BitLocker, Windows Update, ConfigMgr, and general categories. A preset picker (Full / Intune+Autopilot / Networking / Security / Quick) and a granular family-level tree let users scope the collection before running. Real-time progress events drive a visual overlay. A completion summary shows per-type artifact counts, total duration, and gap details; the resulting bundle folder opens directly into the log workspace with one click.
- **DSRegCmd — MDM enrollment cross-reference**: The workspace now reads scheduled tasks under `\Microsoft\Windows\EnterpriseMgmt\` and cross-references their GUIDs against `HKLM\SOFTWARE\Microsoft\Enrollments\{GUID}` (checking `EnrollmentState=1`). Devices that are genuinely enrolled but whose `dsregcmd /status` output lacks MDM URLs no longer trigger a false "enrollment missing" warning.

### Log Parsing

#### New parsers (since v0.5.0)

- **Windows DHCP Server**: Dedicated parser for `DhcpSrvLog-*.log` and `DhcpV6SrvLog-*.log`, detected via header signature. Surfaces IP Address, Host Name, and MAC Address as dedicated columns.
- **macOS Intune MDM Daemon**: Parses pipe-delimited `/Library/Logs/Microsoft/Intune/IntuneMDMDaemon*.log`. Extracts process, severity, thread, and sub-component.
- **WiX/Burn bootstrapper**: Handles `[PID:TID][ISO-timestamp]sNNN:` format logs (vc_redist, .NET runtime, etc.).
- **MSI verbose log**: Handles ~12 distinct line patterns — engine messages, action start/end, property dumps, and `MainEngineThread` return values. Embeds MSI exit code descriptions (1000–3002).
- **PSADT Legacy**: Parses `[timestamp] [section] [source] [severity] :: message` logs from PSAppDeployToolkit v4. Embeds PSADT exit codes (60001–60012).
- **Windows Registry export (.reg)**: Dedicated parser and viewer for `.reg` files exported by `regedit.exe`. Auto-detected via the `Windows Registry Editor Version 5.00` header. Supports REG_SZ, REG_DWORD, REG_QWORD, REG_BINARY, REG_EXPAND_SZ, REG_MULTI_SZ, REG_NONE, and delete markers. Hex line continuations and UTF-16LE encoded values are decoded automatically. Opens in a regedit-style two-pane viewer with a virtualized key tree (handles 22 MB+ files) and a value table showing Name, Type, and Data columns. Integrates into the tab system alongside log files. The file open dialog now includes a "Registry Files (*.reg)" filter.

#### Parser enrichment

- **Dynamic columns**: Column set is now auto-derived from the detected parser. Plain text shows only Message; CCM/IME shows Component, Date/Time, Thread, and Source; DHCP shows IP, Host, and MAC; etc. Details-mode columns can be toggled independently.
- **Severity icon column**: Colored dot (red/yellow/gray) as the leftmost column, always visible regardless of which other columns are shown.
- **Panther (Windows Setup) — four new detail columns**: `result_code`, `gle_code`, `setup_phase`, and `operation_name` extracted from `setupact.log` / `setuperr.log` message text and surfaced in the column grid and InfoPane.
- **Panther — source and thread enrichment**: `source_file` populated from `[exe.exe]` bracketed tags and `CClassName::MethodName(line):` patterns; `thread` populated from DISM `TID=` fields; `Perf`-level messages classified as Info.
- **IME subsystem enrichment**: `[Subsystem]` prefixes (Win32App, PowerShell, Flighting, etc.) extracted from IME log messages into the Source column.
- **InfoPane metadata row**: Entries with a result code, GLE code, setup phase, or operation name show a compact `Result | GLE | Phase | Op` line at the top of the detail pane.

#### Timestamp / timezone fixes

- **IME logs — 4-hour offset fixed**: IME logs write timestamps without a timezone suffix; the parser now falls back to the machine's local UTC offset instead of treating local time as UTC.
- **CCM/SCCM/Simple/ISO logs**: Embedded timezone offsets (e.g. `+240` for UTC-4) are now correctly applied when converting log-local time to UTC for display. Extreme or malformed offsets fall back safely to UTC.

### Error Intelligence

- **Inline error code highlighting**: After parsing, entries are scanned for `0x`-prefixed codes. Matching codes are underlined; selecting the entry shows the decoded description, category, and HRESULT facility breakdown in the InfoPane.
- **411-code error database**: Embedded database covers Windows/Win32 error codes, HRESULT facilities, ConfigMgr client errors (0x87D0xxxx / 0x87D1xxxx), and Windows Update agent codes (0x8024xxxx). Searchable via the Error Lookup dialog.
- **HRESULT decomposition**: WIN32 error codes are decomposed into facility + status for fallback lookup when not in the primary database.
- **Error Lookup dialog — rebuilt**: Replaced the native dialog with a Fluent UI panel that includes a search bar with live substring matching, result list, category badges, and lookup history.
- **Error code search IPC**: `search_error_codes` backend command with substring search exposed to the frontend.

### UI & Chrome

#### Themes

- **8 named themes**: Classic CMTrace, Dark, Light, Dracula, Nord, Solarized Dark, High Contrast, and Hotdog Stand — each with custom token palette and typography.
- **Toolbar theme picker**: Real-time theme switching from a dropdown in the upper-right toolbar.
- **Fluent UI token migration**: 86 hardcoded hex colors migrated to Fluent UI design tokens, enabling consistent dark-mode and theme support across all dialogs (Accessibility, Filter, Error Lookup, About, File Association).

#### Navigation & layout

- **Log file tabs**: A tab strip below the toolbar shows every open file. Switching tabs is instant (zero re-parse — entries are cached in memory). Overflow dropdown handles more than ~6 tabs. Tab count shown in the status bar.
- **Workspace dropdown**: Replaced the five standalone workspace buttons with a single compact dropdown.
- **Platform-aware workspaces**: On startup the app detects the host OS via `tauri-plugin-os` and filters the workspace list accordingly. macOS hides DSRegCmd and Deployment; Linux hides those plus diagnostics-only views. An invalid persisted workspace auto-corrects to Log Explorer.
- **Collapsible sidebar**: Chevron button or Ctrl+B collapses the sidebar to a 36 px icon strip. State persists across sessions.
- **Pause / Refresh / Streaming footer**: These controls moved from the toolbar into a dedicated sidebar footer, freeing toolbar space.

#### Columns

- **Resizable columns**: Drag any column header's right edge to resize. Minimum/maximum widths enforced. Widths persist to `localStorage`. Resize grab zone widened to 12 px with a visible grip indicator.
- **Reorderable columns**: Drag column headers left/right to reorder. Drop indicator shows the insertion point. Order persists.

#### Known Sources & menus

- **Dynamic Known Log Sources menu**: Populated at runtime from the full source catalog, grouped by Family → Group → Source. Platform-specific sources (Wi-Fi, Firewall on macOS; IME, security, deployment on Windows) are filtered per OS.
- **Wi-Fi and Firewall log sources** added for macOS.
- **PatchMyPC log sources** added for Windows.
- **Fluent UI menus**: Replaced native `<select>` elements in Open and Known Sources dropdowns with Fluent UI Menu/Dropdown for consistent styling and dark-mode support.
- **Bundle Summary** added to the Tools menu.

#### Font system

- **Font family picker**: Choose any system font in the Accessibility dialog. Selection applies to the entire app and persists. Powered by `font-kit` for cross-platform system font enumeration.
- **CSS custom property font system**: All hardcoded font strings replaced with `var(--font-family)` and centralized constants.

#### Miscellaneous UX

- **Show/Hide Details toggle**: Toolbar button hides detail-only columns while keeping severity, timestamp, and message visible.
- **App icon**: Updated to campfire logo with splash screen.
- **macOS code signing and notarization**: Release workflow signs and notarizes macOS artifacts for Gatekeeper compatibility.

### Search

- **Inline find bar** (Ctrl+F): A persistent find bar at the bottom of the log workspace replaces the old modal dialog. Features: live search-as-you-type with hit count; plain-text and regex mode with inline red error feedback for invalid patterns; match case toggle; Prev/Next navigation (F3 / Shift+F3 / Enter / Shift+Enter); Escape to close. Searches across all visible columns. Matches highlighted in all rows; current match uses selection highlight. Navigation finds the nearest match after the currently selected entry rather than always jumping to the first result. Debounced at 150 ms to prevent jank on fast typing.

### File Handling

- **Multi-file open**: The file open dialog accepts multiple files via Shift/Ctrl+click. All selected files are merged into a single aggregate view.
- **Multi-file drag-drop**: Drop multiple files at once to merge them (previously only the first was loaded).
- **CLI multi-file**: `cmtraceopen file1.log file2.log ...` opens all paths as a merged aggregate.
- **OS file association multi-file**: Opening multiple `.log` / `.lo_` files together via Explorer passes all paths to the app.
- Multi-file open is gated to the Log workspace; dropping files while in another workspace loads them without switching away.

### Performance

- **Zero-allocation severity detection**: Replaced `.to_lowercase()` with byte-level ASCII case folding — eliminates one heap allocation per log line.
- **Cached thread display**: `format_thread_display()` uses a thread-local `HashMap` — ~15 allocations per file instead of ~30 K.
- **Combined Simple parser regex**: Timestamp and thread regexes merged into a single pass.
- **Error code pre-check**: Fast `"0x"` substring scan before running the full regex on every line.
- **Timestamped format caching**: Detected sub-format reused for subsequent lines, avoiding up to 3 wasted regex attempts per line.
- **Batch folder parse**: Single IPC call parses all files in a folder via Rayon parallelism (replaces sequential per-file calls).
- **In-memory tab cache**: Parsed entries cached per file — tab switches are instant with zero re-parse.
- **Progressive folder load**: Batch size of 4 with a live progress bar and full-screen overlay keeps the UI responsive during large folder loads.
- **GUID lookup optimization**: DSRegCmd workspace precomputes a `Set`/`Map` for GUID lookups (O(1) per entry instead of O(n·m) scan).

### Fixed

- Log row scroll no longer jumps when clicking an already-visible row; suppression only activates when the click changes the selected entry.
- Tab strip overflow dropdown no longer clipped by `overflow: hidden`.
- Sidebar routing for Deployment and macOS workspaces (was falling through to DSRegCmd).
- Burn log classification: logs detected as Timestamped/Plain now re-classified as Burn when content matches.
- Burn exit code extraction: handles hex-format codes and surfaces previously-hidden unknown files.
- Deployment workspace: no longer navigates away when a folder is opened while already in the workspace.
- Auto-scroll behavior: only suppressed when a click changes selection; keyboard/programmatic navigation unaffected.
- `NeXTSTEP` payload parser: handles quoted keys, arrays-of-dicts, and nested arrays in macOS configuration profiles.
- `Invalid Date` display in the macOS diagnostics packages tab.
- macOS script classification: all `NSURLSession` task lifecycle events classified as noise; only summaries kept.
- False hex matches prevented in GUID error-code lookups.
- Clipboard read errors handled gracefully.
- Row height calculation corrected to prevent text overlap at larger font sizes.
- GUID-to-app-name deduplication: `download_stats` and `event_tracker` now share a single `GuidRegistry` source of truth, eliminating duplicate lookups and inconsistent app name resolution.
- `sort_unstable_by_key` used where clippy previously warned.

### Build & Dependencies

- **TypeScript 6.0**: Upgraded from 5.9.3 → 6.0.2; no source changes required.
- **macOS signing/notarization**: CI release workflow signs and notarizes macOS arm64 and x64 artifacts.
- **Windows build prerequisites script hardened** (`Install-CMTraceOpenBuildPrereqs.ps1`): fixes null-array crash and `vswhere.exe` not-found errors on machines without Visual Studio; `winget list` queried once and results cached in a `HashSet` (eliminates N per-package subprocess calls); tolerates "already installed" and "no applicable upgrade" winget exit codes; re-verifies and modifies the C++ workload if the initial install silently skipped components.
- `tauri-plugin-os` added for runtime platform detection.
- `font-kit` added for cross-platform system font enumeration.
- picomatch bumped 4.0.3 → 4.0.4.

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
