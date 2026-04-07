# Secure Boot Certificate Workspace — Design Spec

**Date:** 2026-04-07
**Status:** Draft
**Context:** Windows Secure Boot UEFI certificate transition (CA 2011 → CA 2023, deadline June 2026)
**Reference:** [blog.mindcore.dk — Secure Boot Certificate Update Intune](https://blog.mindcore.dk/2026/04/secure-boot-certificate-update-intune/)

## Overview

A dashboard-style workspace that analyzes Windows Secure Boot UEFI certificate transition readiness. Primary input is a live device scan on Windows that auto-discovers the Intune remediation log file. Cross-platform fallback allows importing a collected log file for remote troubleshooting. The workspace also supports running the detection and remediation scripts directly on the device.

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Scope | Focused on Secure Boot cert transition only | Immediate value for June 2026 deadline |
| Primary input | Live device scan (Windows) | Richest data source, auto-discovers log |
| Cross-platform | Log import fallback on all platforms | Helpdesk admins on Mac can review remote devices |
| Layout | Dashboard with fact groups (like DSRegCmd) | Consistent with existing workspace patterns |
| Diagnostics | Full prerequisite + stage + remediation + timeline | Comprehensive troubleshooting without external tools |
| Entry flow | Single "Analyze" with auto-detection | On Windows: scan + auto-discover log. Other: file dialog |
| Script execution | Bundled detect/remediate scripts run live | Turns viewer into active management tool |
| Collector | New `secureboot` family | Evidence bundles include Secure Boot state |

## Data Sources

### Live Scan (Windows only)

| Source | Data Provided |
|--------|--------------|
| Registry: `HKLM\SYSTEM\CurrentControlSet\Control\Secureboot` | `MicrosoftUpdateManagedOptIn`, `AvailableUpdates`, `UEFICA2023Status`, `UEFICA2023Error` |
| Registry: `HKLM\...\SecureBoot\Servicing` | `WindowsUEFICA2023Capable` (0=not in DB, 1=in DB, 2=booting from 2023) |
| Registry: `HKLM\...\SecureBoot\Servicing\DeviceAttributes` | OEM manufacturer, model, firmware version/date |
| Registry: `HKLM\...\SecureBoot\State` | `UEFISecureBootEnabled` (fallback check) |
| Registry: `HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection` | `AllowTelemetry` level |
| Registry: `HKLM\SOFTWARE\Mindcore\Secureboot` | `ManagedOptInDate` (fallback timer) |
| Registry: CBS/WU/SessionManager reboot indicators | Pending reboot detection |
| Service: `DiagTrack` | Running state, start type |
| WMI: `Win32_Tpm` | TPM version, enabled, activated |
| WMI: `Win32_EncryptableVolume` | BitLocker status, protection, key protectors |
| Scheduled Task: `\Microsoft\Windows\PI\Secure-Boot-Update` | Existence, last run, last result |
| Folder: `%SystemRoot%\System32\SecureBootUpdates\` | Payload `.bin` file presence and count |
| File: `%SystemRoot%\System32\WinCsFlags.exe` | WinCS availability |
| Confirm-SecureBootUEFI cmdlet | Secure Boot enabled state |

### Log File (all platforms)

**Path:** `%ProgramData%\Microsoft\IntuneManagementExtension\Logs\SecureBootCertificateUpdate.log`

**Format:** One line per entry, no multi-line records.

```
{yyyy-MM-dd HH:mm:ss} [{DETECT|REMEDIATE|SYSTEM}] [{INFO|WARNING|ERROR|SUCCESS}] {message}
```

**Parser regex:**
```
^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[(DETECT|REMEDIATE|SYSTEM)\] \[(INFO|WARNING|ERROR|SUCCESS)\] (.+)$
```

**Characteristics:**
- Encoding: UTF-8 (possible BOM on PS 5.1), CRLF line endings
- Max size: 4 MB with single `.old` rotation backup
- Lines per run: 10-80 (compliant exits early)
- Written by: `Detect-SecureBootCertificateUpdate.ps1` and `Remediate-SecureBootCertificateUpdate.ps1` (v4.0)
- Buffered writes: all lines flushed at end of each script execution

**Structured extraction from message text:**

| Pattern | What it captures |
|---------|-----------------|
| `Detection Result: NON-COMPLIANT - Stage {N} (exit 1)` | Stage determination per session |
| `Detection Result: COMPLIANT - Stage 5 (exit 0)` | Compliant state |
| `Detection Result: ERROR (exit 1)` | Script error |
| `Remediation Result: {OUTCOME} (exit {N})` | Remediation outcome |
| `========== DETECTION STARTED ==========` | Session boundary start |
| `========== DETECTION COMPLETED ==========` | Session boundary end |
| `========== REMEDIATION STARTED ==========` | Session boundary start |
| `========== REMEDIATION COMPLETED ==========` | Session boundary end |
| `--- Stage {N} Analysis ---` / `--- End Stage {N} Analysis ---` | Stage detail section |
| `---------- DIAGNOSTIC DATA ----------` | Diagnostic section boundary |
| `Fallback Timer: OptIn date={ts} \| Elapsed={N}d \| Threshold={N}d \| ...` | Fallback timer state |
| `MicrosoftUpdateManagedOptIn is SET to 0x{hex}` | Opt-in confirmation |
| `WindowsUEFICA2023Capable: {value}` | Certificate status |
| `AvailableUpdates: {value} (0x{hex})` | Update progress |
| `0x80070002`, `0x5944`, etc. | Error/status codes |

**Remediation result outcomes:** `SUCCESS`, `ALREADY_CONFIGURED`, `FALLBACK_WINCS`, `FALLBACK_APPLIED`, `FALLBACK_BLOCKED`, `FALLBACK_FAILED`, `FAILED`, `ERROR`

**Timeline construction:** Group lines by session (STARTED/COMPLETED markers), extract stage + result per session, compute inter-session duration for stall detection.

## Compliance Stages

| Stage | Name | Description |
|-------|------|-------------|
| 0 | Secure Boot Disabled | Secure Boot is disabled in BIOS/UEFI or device uses Legacy BIOS/MBR |
| 1 | Opt-in Not Configured | `MicrosoftUpdateManagedOptIn` not set to `0x5944` |
| 2 | Awaiting Windows Update | Opt-in configured, WU hasn't started certificate deployment |
| 3 | Update In Progress | Windows Update actively processing certificate updates |
| 4 | Pending Reboot | CA 2023 certificate enrolled in UEFI DB, reboot needed for new boot manager |
| 5 | Compliant | Booting from 2023-signed boot manager (`WindowsUEFICA2023Capable` == 2) |

## Dashboard Layout

### Status Banner (top)

Color-coded by compliance stage:
- **Green** — Stage 5 (compliant)
- **Amber** — Stages 2-4 (in progress)
- **Red** — Stage 0-1 (action required) or error

Displays: stage number + name, one-line description, scan timestamp, progress bar (0-5), "Rescan" button.

While a script is running, shows progress state with live stdout streaming.

### Stage Progress Bar

Horizontal 0→5 pipeline with filled/unfilled segments. Active stage pulses. Each segment labeled with short stage name.

### Fact Group Cards (3-column grid)

**Certificates:**
- UEFI CA 2023 — in DB / not in DB
- UEFI CA 2011 — present
- Boot Manager — 2011-signed / 2023-signed
- Capable Flag — 0 / 1 / 2

**System Health:**
- Secure Boot — enabled / disabled
- TPM — version, enabled/activated
- BitLocker — status, key escrow location
- Disk — GPT / MBR

**Configuration:**
- Opt-in Key — `0x5944` or not set
- Telemetry — level (must be >= 1)
- DiagTrack — running / stopped
- Scheduled Task — present / missing, last run result

On log-import-only mode, live-data fields show "Not available (log import only)" in muted text.

### Tabbed Detail Area

**Diagnostics tab** — Rule engine findings with severity icons and actionable recommendations. Sorted by severity (error > warning > info).

**Timeline tab** — Chronological events parsed from log file. Each entry: timestamp, script source badge (DETECT/REMEDIATE), level badge, message. Stage transitions and errors highlighted. Shows inter-session gaps for stall detection. Only populated when log data is available.

**Raw Data tab** — Full registry dump and service states as formatted text. Copyable for pasting into support tickets.

## Sidebar

Top to bottom:

1. **Quick Actions** (Windows only)
   - "Run Detection" button — always available
   - "Run Remediation" button — disabled until detection shows non-compliant, shows confirmation dialog before execution
   - "Rescan" button — live registry refresh without re-running scripts
2. **SourceSummaryCard** — badge: `secureboot`, title: "Secure Boot Certificates", subtitle: device name or log path, body: current stage text
3. **Data Source Indicator** — "Live Scan" / "Log Import" / "Live + Log" with timestamp. Script version when scripts have been run.
4. **Findings Summary** — Error/warning/info counts (clickable, jumps to Diagnostics tab)
5. **SourceStatusNotice** — Shown when analysis fails or scripts error out

## Diagnostic Rules Engine

~25 rules in three categories, each producing a `DiagnosticFinding { severity, rule_id, title, detail, recommendation }`.

### Prerequisite Rules

| Rule | Checks | Severity |
|------|--------|----------|
| `secure-boot-enabled` | Firmware Secure Boot state | Error if disabled |
| `telemetry-level` | `AllowTelemetry` >= 1 | Error if 0 ("Security" level blocks opt-in) |
| `diagtrack-service` | Service running + auto-start | Warning if stopped |
| `tpm-present` | WMI TPM status | Warning if missing/disabled |
| `bitlocker-escrow` | Volume encrypted + key protector type | Warning if active without Entra ID escrow |
| `disk-gpt` | Partition style | Error if MBR (UEFI requires GPT) |

### Stage Rules

| Rule | Checks | Severity |
|------|--------|----------|
| `optin-configured` | `MicrosoftUpdateManagedOptIn` == `0x5944` | Error if missing/wrong |
| `stage-stall` | Days at current stage vs threshold | Warning at 14d, Error at 30d |
| `payload-present` | `SecureBootUpdates\` folder + `.bin` files | Error if missing at Stage 2-3 |
| `scheduled-task-health` | Task existence + last result | Error if missing, Warning if failed |
| `uefi-ca-2023-status` | `WindowsUEFICA2023Capable` value | Info (0/1/2 display) |
| `boot-manager-signing` | Capable == 2 vs 1 | Warning if cert in DB but not booting from it |
| `pending-reboot` | CBS/WU/PendingFileRename indicators | Warning at Stage 4 |
| `error-code-present` | `UEFICA2023Error` value | Error with known-code lookup |
| `wincs-available` | `WinCsFlags.exe` existence | Info |
| `fallback-timer` | `ManagedOptInDate` + elapsed days | Info showing countdown/active state |

### Remediation Rules

| Rule | Condition | Recommendation |
|------|-----------|----------------|
| `fallback-eligible` | Stage 2-3 for 30+ days | "Fallback mechanism should activate automatically" |
| `fallback-active` | Days > threshold | "Run remediation script or wait for next cycle" |
| `missing-cumulative-update` | No payload folder + no scheduled task | "Install July 2024+ cumulative update" |
| `reboot-needed` | Stage 4, days > 2 | "Reboot to complete transition" |
| `csp-error-65000` | Error code match | "Switch to Intune Remediations, CSP has known bug" |
| `transient-staging-error` | Error 2147942750 / 0x8007070E | "Transient — clears after reboot at Stage 4→5" |
| `missing-payload-with-wincs` | No payloads but WinCS available | "WinCS can bypass payload dependency" |
| `wu-scan-stale` | Last WU scan > 7 days | "Run `usoclient StartScan` or check WSUS config" |
| `windows-10-eol` | OS caption contains "Windows 10" | "Windows 10 support ended October 2025" |

**Implementation:** Rust `Vec<Box<dyn DiagnosticRule>>` with `fn evaluate(&self, state: &SecureBootState) -> Option<DiagnosticFinding>`. Same pattern as DSRegCmd's rule engine.

## Live Script Execution

### Bundled Scripts

Both scripts embedded in the Rust binary via `include_str!()`:
- `Detect-SecureBootCertificateUpdate.ps1` (v4.0)
- `Remediate-SecureBootCertificateUpdate.ps1` (v4.0)

### Execution Flow

1. User clicks "Run Detection" or "Run Remediation" in sidebar
2. For remediation: confirmation dialog — "This will configure your device for Secure Boot certificate updates. Modifies registry keys under HKLM\\SYSTEM\\CurrentControlSet\\Control\\Secureboot. Continue?"
3. Backend writes embedded script to temp file
4. Spawns `powershell.exe -NoProfile -ExecutionPolicy Bypass -File {temp_path}`
5. Streams stdout via progress events to frontend
6. On completion: reads `SecureBootCertificateUpdate.log` for structured data
7. Re-runs live registry scan for current state
8. Merges all data, returns `SecureBootAnalysisResult`
9. Temp script file deleted
10. Dashboard refreshes with complete updated picture

### Safety

- Detection is read-only — no confirmation needed
- Remediation modifies registry — requires confirmation dialog
- Both require admin elevation (Tauri requests via manifest or UAC)
- "Run Remediation" disabled until detection shows non-compliant
- Script version displayed in sidebar ("Scripts v4.0")

## Collector Integration

### New Collection Family: `secureboot`

Added to the "Security" category in collection-categories.ts.

### Profile Items

**Registry exports:**

| ID | Path | File |
|----|------|------|
| `secureboot-registry` | `HKLM\SYSTEM\CurrentControlSet\Control\Secureboot` | `secureboot-config.reg` |
| `secureboot-servicing` | `HKLM\...\SecureBoot\Servicing` | `secureboot-servicing.reg` |

**Log collection:**

| ID | Source | Destination |
|----|--------|-------------|
| `secureboot-log` | `%ProgramData%\Microsoft\IntuneManagementExtension\Logs\SecureBootCertificateUpdate.log` | `logs/secureboot/` |
| `secureboot-log-old` | Same path with `.old` suffix | `logs/secureboot/` |

**Commands:**

| ID | Command | File | Timeout |
|----|---------|------|---------|
| `secureboot-detect` | Bundled detection script (embedded, written to temp) | `secureboot-detect-output.txt` | 60s |
| `secureboot-task-status` | `Get-ScheduledTaskInfo '\Microsoft\Windows\PI\Secure-Boot-Update'` | `secureboot-task-status.txt` | 15s |
| `secureboot-bitlocker` | `Get-BitLockerVolume -MountPoint $env:SystemDrive` | `secureboot-bitlocker.txt` | 15s |

### Embedded Script Collection

New artifact type `EmbeddedScript` in the collector engine: writes bundled script to temp file, executes via PowerShell, captures output, cleans up temp file. Reuses the same pattern as workspace live execution.

### Bundle Integration

When the Secure Boot workspace opens a collected evidence bundle, it looks for:
- `evidence/registry/secureboot-config.reg` and `secureboot-servicing.reg` → parse for fact groups
- `evidence/logs/secureboot/SecureBootCertificateUpdate.log` → parse for timeline
- `evidence/command-output/secureboot-detect-output.txt` → supplementary diagnostic data

## Backend Architecture

### Module: `src-tauri/src/secureboot/`

```
secureboot/
├── mod.rs              # Module exports
├── models.rs           # All serde-serializable types
├── scanner.rs          # Windows registry/service/WMI reader (#[cfg(windows)])
├── log_parser.rs       # Parse SecureBootCertificateUpdate.log (cross-platform)
├── rules.rs            # Diagnostic rule engine (~25 rules, cross-platform)
├── stage.rs            # Stage determination from raw data (cross-platform)
└── scripts.rs          # Embedded script execution (#[cfg(windows)])
```

### Key Types (`models.rs`)

- `SecureBootAnalysisResult` — top-level IPC return type
- `SecureBootState` — current device state (stage, all registry values, service states, cert status)
- `SecureBootTimeline` — `Vec<TimelineEntry>`
- `TimelineEntry` — `{ timestamp, source (Detect/Remediate/System), level, event_type, message, stage, error_code }`
- `DiagnosticFinding` — `{ severity, rule_id, title, detail, recommendation }`
- `SecureBootStage` — enum (Stage0..Stage5) with display names
- `DataSource` — enum `LiveScan | LogImport | Both`
- `ScriptExecutionResult` — `{ exit_code, stdout, log_entries }`

### Commands (`src-tauri/src/commands/secureboot.rs`)

| Command | Signature | Behavior |
|---------|-----------|----------|
| `analyze_secureboot` | `(path: Option<String>) -> Result<SecureBootAnalysisResult>` | Windows with no path: live scan + auto-discover log. With path: parse log only. Non-Windows: path required. |
| `rescan_secureboot` | `() -> Result<SecureBootAnalysisResult>` | Windows-only, live scan only, no log re-parse. |
| `run_secureboot_detection` | `(app: AppHandle) -> Result<SecureBootAnalysisResult>` | Execute bundled detect script, parse results, merge with live scan. Streams progress. |
| `run_secureboot_remediation` | `(app: AppHandle) -> Result<SecureBootAnalysisResult>` | Execute bundled remediate script, parse results, merge with live scan. Streams progress. |

### Feature Flag

```toml
# Cargo.toml
[features]
full = ["collector", "deployment", "dsregcmd", "event-log", "intune-diagnostics", "macos-diag", "secureboot", "sysmon"]
secureboot = []
```

Commands registered conditionally: `#[cfg(feature = "secureboot")]` in `lib.rs`.

## Frontend Architecture

### Workspace: `src/workspaces/secureboot/`

```
secureboot/
├── index.ts                        # WorkspaceDefinition
├── secureboot-store.ts             # Zustand store
├── types.ts                        # TypeScript types (mirrors Rust models)
├── SecureBootWorkspace.tsx          # Main dashboard component
├── SecureBootSidebar.tsx            # Sidebar with quick actions + source summary
├── StatusBanner.tsx                 # Color-coded stage banner + rescan
├── StageProgressBar.tsx             # Horizontal 0→5 pipeline
├── FactGroupCards.tsx               # 3-column grid (Certs, Health, Config)
├── DiagnosticsTab.tsx               # Rule findings with severity
├── TimelineTab.tsx                  # Chronological log events
└── RawDataTab.tsx                   # Registry dump for copy/paste
```

### WorkspaceDefinition

```typescript
{
  id: "secureboot",
  label: "Secure Boot Certificates",
  platforms: "all",
  fileFilters: [{ name: "Secure Boot Logs", extensions: ["log"] }],
  actionLabels: { file: "Open Log File", placeholder: "Analyze Secure Boot..." },
  onOpenSource: /* Windows: analyze_secureboot() no path. Other: file dialog → analyze_secureboot(path) */
}
```

### Store Shape

```typescript
{
  analysisState: { phase: "idle" | "analyzing" | "done" | "error", message, detail }
  result: SecureBootAnalysisResult | null
  dataSource: "live" | "log" | "both" | null
  activeTab: "diagnostics" | "timeline" | "raw"
  scriptRunning: "detect" | "remediate" | null
  // Actions
  beginAnalysis(), setResult(), failAnalysis()
  rescan(), runDetection(), runRemediation()
  setActiveTab()
}
```

### Command Wrappers (`src/lib/commands.ts`)

```typescript
analyzeSecureBoot(path?: string): Promise<SecureBootAnalysisResult>
rescanSecureBoot(): Promise<SecureBootAnalysisResult>
runSecureBootDetection(): Promise<SecureBootAnalysisResult>
runSecureBootRemediation(): Promise<SecureBootAnalysisResult>
```

### Registration

Add `securebootWorkspace` to `ALL_WORKSPACES` in `src/workspaces/registry.ts`.

## Error Codes Reference

| Value | Hex | Meaning |
|-------|-----|---------|
| 22852 | `0x5944` | `MicrosoftUpdateManagedOptIn` target value |
| 16384 | `0x4000` | `AvailableUpdates`: all certificates applied |
| 64 | `0x40` | `AvailableUpdates`: DB cert update (Step 1) |
| 256 | `0x100` | `AvailableUpdates`: boot manager update (Step 2) |
| 2147942402 | `0x80070002` | `ERROR_FILE_NOT_FOUND` — missing payload binaries |
| 2147942750 | `0x8007070E` | Transient boot manager staging error |

`WindowsUEFICA2023Capable` values: 0 = not in DB, 1 = in DB, 2 = booting from 2023 boot manager.

## Event Log IDs

Harvested from `Microsoft-Windows-Kernel-Boot/Operational` and `System`:
1036, 1043, 1044, 1045, 1801, 1808

## Out of Scope

- Broader firmware health monitoring (DBX revocation, other UEFI variables)
- Fleet-level compliance dashboards (this is single-device focused)
- Automatic remediation without user confirmation
- Script auto-update from GitHub (future consideration)
- WSUS/MECM deployment path (Intune-only for now)
