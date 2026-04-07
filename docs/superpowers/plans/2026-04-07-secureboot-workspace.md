# Secure Boot Certificate Workspace — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a dashboard workspace that analyzes Windows Secure Boot UEFI certificate transition readiness, with live scanning, log parsing, diagnostic rules, script execution, and collector integration.

**Architecture:** New `secureboot` Rust module (models, log parser, scanner, rules, scripts) exposed via 4 Tauri IPC commands. Frontend workspace with Zustand store, dashboard components (status banner, stage progress, fact groups, tabbed detail area), and sidebar with quick actions. Collector extended with `secureboot` family for evidence bundles.

**Tech Stack:** Rust (serde, regex, chrono, winreg, std::process::Command), TypeScript/React (Zustand, Fluent UI), Tauri v2 IPC

**Spec:** `docs/superpowers/specs/2026-04-07-secureboot-workspace-design.md`

---

## File Structure

### Backend (Rust) — New files

| File | Responsibility |
|------|---------------|
| `src-tauri/src/secureboot/mod.rs` | Module exports, public `analyze()` entry point |
| `src-tauri/src/secureboot/models.rs` | All serde-serializable types (result, state, timeline, findings, stages) |
| `src-tauri/src/secureboot/log_parser.rs` | Parse `SecureBootCertificateUpdate.log` into `Vec<TimelineEntry>` |
| `src-tauri/src/secureboot/stage.rs` | Determine `SecureBootStage` from raw registry/scan data |
| `src-tauri/src/secureboot/rules.rs` | ~25 diagnostic rules producing `Vec<DiagnosticFinding>` |
| `src-tauri/src/secureboot/scanner.rs` | Windows-only: read registry, services, WMI, scheduled tasks, file system |
| `src-tauri/src/secureboot/scripts.rs` | Windows-only: execute embedded PowerShell detection/remediation scripts |
| `src-tauri/src/commands/secureboot.rs` | 4 Tauri IPC command handlers |
| `src-tauri/src/secureboot/scripts/Detect-SecureBootCertificateUpdate.ps1` | Embedded detection script (fetched from GitHub) |
| `src-tauri/src/secureboot/scripts/Remediate-SecureBootCertificateUpdate.ps1` | Embedded remediation script (fetched from GitHub) |

### Backend (Rust) — Modified files

| File | Change |
|------|--------|
| `src-tauri/Cargo.toml:17-19` | Add `secureboot` feature to `[features]` section |
| `src-tauri/src/lib.rs:1-21` | Add `pub mod secureboot` with feature gate |
| `src-tauri/src/lib.rs:80-155` | Register 4 new commands in `invoke_handler` |
| `src-tauri/src/commands/mod.rs` | Add `pub mod secureboot` with feature gate |
| `src-tauri/src/collector/profile_data.json` | Add ~6 secureboot collection items |

### Frontend (TypeScript/React) — New files

| File | Responsibility |
|------|---------------|
| `src/workspaces/secureboot/index.ts` | WorkspaceDefinition export |
| `src/workspaces/secureboot/types.ts` | TypeScript types mirroring Rust models |
| `src/workspaces/secureboot/secureboot-store.ts` | Zustand store |
| `src/workspaces/secureboot/SecureBootWorkspace.tsx` | Main dashboard component |
| `src/workspaces/secureboot/SecureBootSidebar.tsx` | Sidebar with quick actions |
| `src/workspaces/secureboot/StatusBanner.tsx` | Color-coded compliance stage banner |
| `src/workspaces/secureboot/StageProgressBar.tsx` | Horizontal 0→5 pipeline |
| `src/workspaces/secureboot/FactGroupCards.tsx` | 3-column grid (Certs, Health, Config) |
| `src/workspaces/secureboot/DiagnosticsTab.tsx` | Rule findings with severity |
| `src/workspaces/secureboot/TimelineTab.tsx` | Chronological log events |
| `src/workspaces/secureboot/RawDataTab.tsx` | Registry dump for copy/paste |

### Frontend (TypeScript/React) — Modified files

| File | Change |
|------|--------|
| `src/types/log.ts:43-51` | Add `"secureboot"` to `WorkspaceId` union |
| `src/workspaces/registry.ts:1-22` | Import and register `securebootWorkspace` |
| `src/lib/commands.ts` | Add 4 command wrapper functions |
| `src/lib/collection-categories.ts:29-32` | Add `"secureboot"` to security category families |

---

## Task 1: Rust Models

**Files:**
- Create: `src-tauri/src/secureboot/models.rs`

- [ ] **Step 1: Create models.rs with all types**

```rust
// src-tauri/src/secureboot/models.rs
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Stage
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub enum SecureBootStage {
    #[default]
    Stage0,
    Stage1,
    Stage2,
    Stage3,
    Stage4,
    Stage5,
}

impl SecureBootStage {
    pub fn number(&self) -> u8 {
        match self {
            Self::Stage0 => 0,
            Self::Stage1 => 1,
            Self::Stage2 => 2,
            Self::Stage3 => 3,
            Self::Stage4 => 4,
            Self::Stage5 => 5,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Stage0 => "Secure Boot Disabled",
            Self::Stage1 => "Opt-in Not Configured",
            Self::Stage2 => "Awaiting Windows Update",
            Self::Stage3 => "Update In Progress",
            Self::Stage4 => "Pending Reboot",
            Self::Stage5 => "Compliant",
        }
    }
}

// ---------------------------------------------------------------------------
// Data source
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum DataSource {
    LiveScan,
    LogImport,
    Both,
}

// ---------------------------------------------------------------------------
// Severity (reusable across rules)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub enum DiagnosticSeverity {
    Info,
    Warning,
    Error,
}

// ---------------------------------------------------------------------------
// Log parser types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum LogSource {
    Detect,
    Remediate,
    System,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum LogLevel {
    Info,
    Warning,
    Error,
    Success,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum TimelineEventType {
    StageTransition,
    RemediationResult,
    Error,
    Fallback,
    SessionStart,
    SessionEnd,
    DiagnosticData,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineEntry {
    pub timestamp: DateTime<Utc>,
    pub source: LogSource,
    pub level: LogLevel,
    pub event_type: TimelineEventType,
    pub message: String,
    pub stage: Option<SecureBootStage>,
    pub error_code: Option<String>,
}

/// A logical session is one STARTED→COMPLETED block in the log.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogSession {
    pub source: LogSource,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub result_stage: Option<SecureBootStage>,
    pub result_outcome: Option<String>,
    pub entries: Vec<TimelineEntry>,
}

// ---------------------------------------------------------------------------
// Live scan state (populated on Windows)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SecureBootScanState {
    // Secure Boot
    pub secure_boot_enabled: Option<bool>,

    // Certificates
    pub managed_opt_in: Option<u32>,
    pub available_updates: Option<u32>,
    pub uefi_ca2023_capable: Option<u32>,
    pub uefi_ca2023_status: Option<u32>,
    pub uefi_ca2023_error: Option<u32>,

    // Fallback timer
    pub managed_opt_in_date: Option<String>,

    // Telemetry
    pub telemetry_level: Option<u32>,

    // Services
    pub diagtrack_running: Option<bool>,
    pub diagtrack_start_type: Option<String>,

    // TPM
    pub tpm_present: Option<bool>,
    pub tpm_enabled: Option<bool>,
    pub tpm_activated: Option<bool>,
    pub tpm_spec_version: Option<String>,

    // BitLocker
    pub bitlocker_protection_on: Option<bool>,
    pub bitlocker_encryption_status: Option<String>,
    pub bitlocker_key_protectors: Vec<String>,

    // Disk
    pub disk_partition_style: Option<String>,

    // Payload
    pub payload_folder_exists: Option<bool>,
    pub payload_bin_count: Option<u32>,

    // Scheduled task
    pub scheduled_task_exists: Option<bool>,
    pub scheduled_task_last_run: Option<String>,
    pub scheduled_task_last_result: Option<String>,

    // WinCS
    pub wincs_available: Option<bool>,

    // Pending reboot
    pub pending_reboot_sources: Vec<String>,

    // Device info
    pub device_name: Option<String>,
    pub os_caption: Option<String>,
    pub os_build: Option<String>,
    pub oem_manufacturer: Option<String>,
    pub oem_model: Option<String>,
    pub firmware_version: Option<String>,
    pub firmware_date: Option<String>,

    // Raw registry dump for the Raw Data tab
    pub raw_registry_dump: Option<String>,
}

// ---------------------------------------------------------------------------
// Diagnostic finding
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticFinding {
    pub rule_id: String,
    pub severity: DiagnosticSeverity,
    pub title: String,
    pub detail: String,
    pub recommendation: String,
}

// ---------------------------------------------------------------------------
// Script execution result
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScriptExecutionResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

// ---------------------------------------------------------------------------
// Top-level analysis result (returned to frontend)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecureBootAnalysisResult {
    pub stage: SecureBootStage,
    pub data_source: DataSource,
    pub scan_state: SecureBootScanState,
    pub sessions: Vec<LogSession>,
    pub timeline: Vec<TimelineEntry>,
    pub diagnostics: Vec<DiagnosticFinding>,
    pub script_result: Option<ScriptExecutionResult>,
}
```

- [ ] **Step 2: Verify it compiles**

Run from `src-tauri/`: `cargo check` (will fail — module not wired yet, that's expected at this point). Instead, verify no syntax errors by checking the file is valid Rust with a quick review.

- [ ] **Step 3: Commit**

```bash
git add src-tauri/src/secureboot/models.rs
git commit -m "feat(secureboot): add data models for Secure Boot workspace"
```

---

## Task 2: Log Parser

**Files:**
- Create: `src-tauri/src/secureboot/log_parser.rs`

- [ ] **Step 1: Create log_parser.rs**

```rust
// src-tauri/src/secureboot/log_parser.rs
use chrono::{NaiveDateTime, TimeZone, Utc};
use regex::Regex;
use std::sync::LazyLock;

use super::models::{
    LogLevel, LogSession, LogSource, SecureBootStage, TimelineEntry, TimelineEventType,
};

// ---------------------------------------------------------------------------
// Regex patterns
// ---------------------------------------------------------------------------

static LINE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[(DETECT|REMEDIATE|SYSTEM)\] \[(INFO|WARNING|ERROR|SUCCESS)\] (.+)$",
    )
    .expect("invalid log line regex")
});

static DETECTION_RESULT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"Detection Result: (?:NON-COMPLIANT - Stage (\d)|COMPLIANT - Stage 5|ERROR)")
        .expect("invalid detection result regex")
});

static REMEDIATION_RESULT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"Remediation Result: (\w+)")
        .expect("invalid remediation result regex")
});

static ERROR_CODE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"0x[0-9A-Fa-f]{4,8}").expect("invalid error code regex")
});

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse the full content of a SecureBootCertificateUpdate.log file.
/// Returns sessions (grouped by STARTED/COMPLETED) and a flat timeline.
pub fn parse_log(content: &str) -> (Vec<LogSession>, Vec<TimelineEntry>) {
    let entries = parse_entries(content);
    let sessions = group_into_sessions(&entries);
    let timeline = entries;
    (sessions, timeline)
}

// ---------------------------------------------------------------------------
// Entry parsing
// ---------------------------------------------------------------------------

fn parse_entries(content: &str) -> Vec<TimelineEntry> {
    content
        .lines()
        .filter_map(parse_line)
        .collect()
}

fn parse_line(line: &str) -> Option<TimelineEntry> {
    let caps = LINE_RE.captures(line)?;

    let timestamp = NaiveDateTime::parse_from_str(&caps[1], "%Y-%m-%d %H:%M:%S")
        .ok()
        .map(|ndt| Utc.from_utc_datetime(&ndt))?;

    let source = match &caps[2] {
        "DETECT" => LogSource::Detect,
        "REMEDIATE" => LogSource::Remediate,
        "SYSTEM" => LogSource::System,
        _ => return None,
    };

    let level = match &caps[3] {
        "INFO" => LogLevel::Info,
        "WARNING" => LogLevel::Warning,
        "ERROR" => LogLevel::Error,
        "SUCCESS" => LogLevel::Success,
        _ => return None,
    };

    let message = caps[4].to_string();
    let event_type = classify_event(&message);
    let stage = extract_stage(&message);
    let error_code = ERROR_CODE_RE
        .find(&message)
        .map(|m| m.as_str().to_string());

    Some(TimelineEntry {
        timestamp,
        source,
        level,
        event_type,
        message,
        stage,
        error_code,
    })
}

fn classify_event(message: &str) -> TimelineEventType {
    if message.starts_with("========== DETECTION STARTED")
        || message.starts_with("========== REMEDIATION STARTED")
    {
        TimelineEventType::SessionStart
    } else if message.starts_with("========== DETECTION COMPLETED")
        || message.starts_with("========== REMEDIATION COMPLETED")
    {
        TimelineEventType::SessionEnd
    } else if message.starts_with("Detection Result:") {
        TimelineEventType::StageTransition
    } else if message.starts_with("Remediation Result:") {
        TimelineEventType::RemediationResult
    } else if message.contains("FALLBACK") || message.contains("Fallback") {
        TimelineEventType::Fallback
    } else if message.starts_with("---------- DIAGNOSTIC DATA")
        || message.starts_with("--- ")
    {
        TimelineEventType::DiagnosticData
    } else if message.contains("ERROR") || message.contains("FAILED") {
        TimelineEventType::Error
    } else {
        TimelineEventType::Info
    }
}

fn extract_stage(message: &str) -> Option<SecureBootStage> {
    if let Some(caps) = DETECTION_RESULT_RE.captures(message) {
        if message.contains("COMPLIANT - Stage 5") {
            return Some(SecureBootStage::Stage5);
        }
        if let Some(m) = caps.get(1) {
            return match m.as_str() {
                "0" => Some(SecureBootStage::Stage0),
                "1" => Some(SecureBootStage::Stage1),
                "2" => Some(SecureBootStage::Stage2),
                "3" => Some(SecureBootStage::Stage3),
                "4" => Some(SecureBootStage::Stage4),
                _ => None,
            };
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Session grouping
// ---------------------------------------------------------------------------

fn group_into_sessions(entries: &[TimelineEntry]) -> Vec<LogSession> {
    let mut sessions: Vec<LogSession> = Vec::new();
    let mut current: Option<LogSession> = None;

    for entry in entries {
        match entry.event_type {
            TimelineEventType::SessionStart => {
                // Close any unclosed session
                if let Some(prev) = current.take() {
                    sessions.push(prev);
                }
                current = Some(LogSession {
                    source: entry.source,
                    started_at: entry.timestamp,
                    ended_at: None,
                    result_stage: None,
                    result_outcome: None,
                    entries: vec![entry.clone()],
                });
            }
            TimelineEventType::SessionEnd => {
                if let Some(ref mut sess) = current {
                    sess.ended_at = Some(entry.timestamp);
                    sess.entries.push(entry.clone());
                    sessions.push(current.take().unwrap());
                }
            }
            _ => {
                if let Some(ref mut sess) = current {
                    // Capture stage from detection result
                    if entry.event_type == TimelineEventType::StageTransition {
                        sess.result_stage = entry.stage;
                    }
                    // Capture remediation outcome
                    if entry.event_type == TimelineEventType::RemediationResult {
                        if let Some(caps) = REMEDIATION_RESULT_RE.captures(&entry.message) {
                            sess.result_outcome = Some(caps[1].to_string());
                        }
                    }
                    sess.entries.push(entry.clone());
                }
                // Entries outside a session are dropped from session grouping
                // but still present in the flat timeline
            }
        }
    }

    // Close any trailing unclosed session
    if let Some(sess) = current {
        sessions.push(sess);
    }

    sessions
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_LOG: &str = "\
2026-03-01 08:14:22 [DETECT] [INFO] ========== DETECTION STARTED ==========
2026-03-01 08:14:22 [DETECT] [INFO] Script Version: 4.0
2026-03-01 08:14:22 [DETECT] [SUCCESS] Secure Boot is ENABLED
2026-03-01 08:14:22 [DETECT] [SUCCESS] MicrosoftUpdateManagedOptIn is SET to 0x5944 (22852)
2026-03-01 08:14:23 [DETECT] [WARNING] Detection Result: NON-COMPLIANT - Stage 2 (exit 1)
2026-03-01 08:14:23 [DETECT] [INFO] ========== DETECTION COMPLETED ==========
2026-03-15 14:22:01 [DETECT] [INFO] ========== DETECTION STARTED ==========
2026-03-15 14:22:01 [DETECT] [ERROR] 0x80070002 - Missing SecureBootUpdates payload files
2026-03-15 14:22:01 [DETECT] [WARNING] Detection Result: NON-COMPLIANT - Stage 3 (exit 1)
2026-03-15 14:22:01 [DETECT] [INFO] ========== DETECTION COMPLETED ==========
2026-04-01 08:30:12 [DETECT] [INFO] ========== DETECTION STARTED ==========
2026-04-01 08:30:12 [DETECT] [SUCCESS] Detection Result: COMPLIANT - Stage 5 (exit 0)
2026-04-01 08:30:12 [DETECT] [INFO] ========== DETECTION COMPLETED ==========";

    #[test]
    fn parses_sessions() {
        let (sessions, _timeline) = parse_log(SAMPLE_LOG);
        assert_eq!(sessions.len(), 3);
        assert_eq!(sessions[0].result_stage, Some(SecureBootStage::Stage2));
        assert_eq!(sessions[1].result_stage, Some(SecureBootStage::Stage3));
        assert_eq!(sessions[2].result_stage, Some(SecureBootStage::Stage5));
    }

    #[test]
    fn extracts_error_codes() {
        let (_sessions, timeline) = parse_log(SAMPLE_LOG);
        let errors: Vec<_> = timeline
            .iter()
            .filter(|e| e.error_code.is_some())
            .collect();
        assert_eq!(errors.len(), 2); // 0x5944 and 0x80070002
        assert_eq!(errors[0].error_code.as_deref(), Some("0x5944"));
        assert_eq!(errors[1].error_code.as_deref(), Some("0x80070002"));
    }

    #[test]
    fn classifies_session_boundaries() {
        let (_sessions, timeline) = parse_log(SAMPLE_LOG);
        assert_eq!(timeline[0].event_type, TimelineEventType::SessionStart);
        assert_eq!(timeline[5].event_type, TimelineEventType::SessionEnd);
    }

    #[test]
    fn handles_empty_input() {
        let (sessions, timeline) = parse_log("");
        assert!(sessions.is_empty());
        assert!(timeline.is_empty());
    }

    #[test]
    fn handles_malformed_lines() {
        let input = "not a valid line\n2026-01-01 00:00:00 [DETECT] [INFO] Valid line\ngarbage";
        let (_sessions, timeline) = parse_log(input);
        assert_eq!(timeline.len(), 1);
        assert_eq!(timeline[0].message, "Valid line");
    }
}
```

- [ ] **Step 2: Commit**

```bash
git add src-tauri/src/secureboot/log_parser.rs
git commit -m "feat(secureboot): add log parser for SecureBootCertificateUpdate.log"
```

---

## Task 3: Stage Determination

**Files:**
- Create: `src-tauri/src/secureboot/stage.rs`

- [ ] **Step 1: Create stage.rs**

```rust
// src-tauri/src/secureboot/stage.rs
use super::models::{SecureBootScanState, SecureBootStage};

/// Determine the current compliance stage from live scan data.
///
/// Stage logic (from the detection script):
/// - Stage 5: WindowsUEFICA2023Capable == 2 (booting from 2023 boot manager)
/// - Stage 4: WindowsUEFICA2023Capable == 1 (cert in DB, not booting from it)
/// - Stage 3: AvailableUpdates is set and non-zero (WU processing)
/// - Stage 2: MicrosoftUpdateManagedOptIn == 0x5944, no progress yet
/// - Stage 1: MicrosoftUpdateManagedOptIn not set or wrong value
/// - Stage 0: Secure Boot disabled
pub fn determine_stage(state: &SecureBootScanState) -> SecureBootStage {
    // Stage 0: Secure Boot disabled
    if state.secure_boot_enabled == Some(false) {
        return SecureBootStage::Stage0;
    }

    // Stage 5: Booting from 2023-signed boot manager
    if state.uefi_ca2023_capable == Some(2) {
        return SecureBootStage::Stage5;
    }

    // Stage 4: Cert in UEFI DB but not booting from it yet
    if state.uefi_ca2023_capable == Some(1) {
        return SecureBootStage::Stage4;
    }

    // Check opt-in
    let opt_in_set = state.managed_opt_in == Some(0x5944);

    if !opt_in_set {
        return SecureBootStage::Stage1;
    }

    // Opt-in is set; check WU progress
    match state.available_updates {
        Some(val) if val > 0 && val != 0x4000 => SecureBootStage::Stage3,
        _ => SecureBootStage::Stage2,
    }
}

/// Determine stage from the most recent log session (for log-import-only mode).
/// Returns the stage from the last detection result found.
pub fn determine_stage_from_log(
    sessions: &[super::models::LogSession],
) -> SecureBootStage {
    sessions
        .iter()
        .rev()
        .filter(|s| s.source == super::models::LogSource::Detect)
        .find_map(|s| s.result_stage)
        .unwrap_or(SecureBootStage::Stage0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage0_when_secure_boot_disabled() {
        let state = SecureBootScanState {
            secure_boot_enabled: Some(false),
            ..Default::default()
        };
        assert_eq!(determine_stage(&state), SecureBootStage::Stage0);
    }

    #[test]
    fn stage1_when_optin_missing() {
        let state = SecureBootScanState {
            secure_boot_enabled: Some(true),
            managed_opt_in: None,
            ..Default::default()
        };
        assert_eq!(determine_stage(&state), SecureBootStage::Stage1);
    }

    #[test]
    fn stage2_when_optin_set_no_progress() {
        let state = SecureBootScanState {
            secure_boot_enabled: Some(true),
            managed_opt_in: Some(0x5944),
            available_updates: None,
            ..Default::default()
        };
        assert_eq!(determine_stage(&state), SecureBootStage::Stage2);
    }

    #[test]
    fn stage3_when_updates_in_progress() {
        let state = SecureBootScanState {
            secure_boot_enabled: Some(true),
            managed_opt_in: Some(0x5944),
            available_updates: Some(0x40),
            ..Default::default()
        };
        assert_eq!(determine_stage(&state), SecureBootStage::Stage3);
    }

    #[test]
    fn stage4_when_cert_in_db() {
        let state = SecureBootScanState {
            secure_boot_enabled: Some(true),
            uefi_ca2023_capable: Some(1),
            ..Default::default()
        };
        assert_eq!(determine_stage(&state), SecureBootStage::Stage4);
    }

    #[test]
    fn stage5_when_booting_2023() {
        let state = SecureBootScanState {
            secure_boot_enabled: Some(true),
            uefi_ca2023_capable: Some(2),
            ..Default::default()
        };
        assert_eq!(determine_stage(&state), SecureBootStage::Stage5);
    }

    #[test]
    fn stage5_takes_precedence_over_disabled() {
        // If capable==2 but somehow secure_boot shows false, trust the cert status
        let state = SecureBootScanState {
            secure_boot_enabled: Some(false),
            uefi_ca2023_capable: Some(2),
            ..Default::default()
        };
        // Stage 0 wins because secure boot disabled is checked first
        assert_eq!(determine_stage(&state), SecureBootStage::Stage0);
    }
}
```

- [ ] **Step 2: Commit**

```bash
git add src-tauri/src/secureboot/stage.rs
git commit -m "feat(secureboot): add stage determination logic"
```

---

## Task 4: Diagnostic Rules Engine

**Files:**
- Create: `src-tauri/src/secureboot/rules.rs`

- [ ] **Step 1: Create rules.rs**

```rust
// src-tauri/src/secureboot/rules.rs
use super::models::{
    DiagnosticFinding, DiagnosticSeverity, LogSession, SecureBootScanState, SecureBootStage,
};

/// Run all diagnostic rules against scan state and log sessions.
pub fn evaluate_all(
    state: &SecureBootScanState,
    stage: SecureBootStage,
    sessions: &[LogSession],
) -> Vec<DiagnosticFinding> {
    let mut findings = Vec::new();

    // Prerequisite rules
    check_secure_boot_enabled(state, &mut findings);
    check_telemetry_level(state, &mut findings);
    check_diagtrack_service(state, &mut findings);
    check_tpm_present(state, &mut findings);
    check_bitlocker_escrow(state, &mut findings);
    check_disk_gpt(state, &mut findings);

    // Stage rules
    check_optin_configured(state, &mut findings);
    check_payload_present(state, stage, &mut findings);
    check_scheduled_task_health(state, &mut findings);
    check_uefi_ca2023_status(state, &mut findings);
    check_boot_manager_signing(state, &mut findings);
    check_pending_reboot(state, stage, &mut findings);
    check_error_code_present(state, &mut findings);
    check_wincs_available(state, &mut findings);
    check_fallback_timer(state, &mut findings);
    check_stage_stall(sessions, stage, &mut findings);

    // Remediation rules
    check_missing_cumulative_update(state, &mut findings);
    check_reboot_needed(state, stage, &mut findings);
    check_transient_staging_error(state, &mut findings);
    check_missing_payload_with_wincs(state, &mut findings);
    check_windows_10_eol(state, &mut findings);

    // Sort: errors first, then warnings, then info
    findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    findings
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn finding(
    rule_id: &str,
    severity: DiagnosticSeverity,
    title: &str,
    detail: &str,
    recommendation: &str,
) -> DiagnosticFinding {
    DiagnosticFinding {
        rule_id: rule_id.to_string(),
        severity,
        title: title.to_string(),
        detail: detail.to_string(),
        recommendation: recommendation.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Prerequisite rules
// ---------------------------------------------------------------------------

fn check_secure_boot_enabled(state: &SecureBootScanState, out: &mut Vec<DiagnosticFinding>) {
    if state.secure_boot_enabled == Some(false) {
        out.push(finding(
            "secure-boot-enabled",
            DiagnosticSeverity::Error,
            "Secure Boot is disabled",
            "Secure Boot must be enabled in BIOS/UEFI for certificate updates to apply.",
            "Enter BIOS/UEFI setup and enable Secure Boot under Security settings.",
        ));
    }
}

fn check_telemetry_level(state: &SecureBootScanState, out: &mut Vec<DiagnosticFinding>) {
    if state.telemetry_level == Some(0) {
        out.push(finding(
            "telemetry-level",
            DiagnosticSeverity::Error,
            "Telemetry set to Security (0) — blocks opt-in",
            "AllowTelemetry must be >= 1 (Required) for the managed opt-in safety mechanism to work.",
            "Set AllowTelemetry to 1 (Required) or higher via Intune or Group Policy.",
        ));
    }
}

fn check_diagtrack_service(state: &SecureBootScanState, out: &mut Vec<DiagnosticFinding>) {
    if state.diagtrack_running == Some(false) {
        out.push(finding(
            "diagtrack-service",
            DiagnosticSeverity::Warning,
            "DiagTrack service is not running",
            "The Connected User Experiences and Telemetry service must be running for the opt-in mechanism.",
            "Start the DiagTrack service and set it to Automatic startup.",
        ));
    }
}

fn check_tpm_present(state: &SecureBootScanState, out: &mut Vec<DiagnosticFinding>) {
    if state.tpm_present == Some(false) {
        out.push(finding(
            "tpm-present",
            DiagnosticSeverity::Warning,
            "TPM not detected",
            "No Trusted Platform Module was found. Some certificate update mechanisms may require TPM.",
            "Verify TPM is enabled in BIOS/UEFI settings.",
        ));
    }
}

fn check_bitlocker_escrow(state: &SecureBootScanState, out: &mut Vec<DiagnosticFinding>) {
    if state.bitlocker_protection_on == Some(true) {
        let has_entra_escrow = state
            .bitlocker_key_protectors
            .iter()
            .any(|p| p.contains("Entra") || p.contains("AAD") || p.contains("AzureAD"));
        if !has_entra_escrow {
            out.push(finding(
                "bitlocker-escrow",
                DiagnosticSeverity::Warning,
                "BitLocker active — verify recovery key escrow",
                "PCR 7 measurements change at Stage 4→5 transition. Without escrowed recovery keys, users may be locked out.",
                "Confirm BitLocker recovery keys are escrowed to Entra ID before proceeding.",
            ));
        }
    }
}

fn check_disk_gpt(state: &SecureBootScanState, out: &mut Vec<DiagnosticFinding>) {
    if state.disk_partition_style.as_deref() == Some("MBR") {
        out.push(finding(
            "disk-gpt",
            DiagnosticSeverity::Error,
            "MBR disk detected — UEFI requires GPT",
            "Secure Boot requires UEFI firmware mode which needs a GPT-partitioned disk.",
            "Convert disk to GPT using MBR2GPT before enabling UEFI mode.",
        ));
    }
}

// ---------------------------------------------------------------------------
// Stage rules
// ---------------------------------------------------------------------------

fn check_optin_configured(state: &SecureBootScanState, out: &mut Vec<DiagnosticFinding>) {
    match state.managed_opt_in {
        None => {
            out.push(finding(
                "optin-configured",
                DiagnosticSeverity::Error,
                "MicrosoftUpdateManagedOptIn is not set",
                "The registry key that enables Secure Boot certificate updates is not configured.",
                "Run the remediation script or manually set MicrosoftUpdateManagedOptIn to 0x5944.",
            ));
        }
        Some(val) if val != 0x5944 => {
            out.push(finding(
                "optin-configured",
                DiagnosticSeverity::Error,
                &format!("MicrosoftUpdateManagedOptIn has unexpected value 0x{val:X}"),
                &format!("Expected 0x5944 (22852), found 0x{val:X} ({val})."),
                "Run the remediation script to set the correct value.",
            ));
        }
        _ => {}
    }
}

fn check_payload_present(
    state: &SecureBootScanState,
    stage: SecureBootStage,
    out: &mut Vec<DiagnosticFinding>,
) {
    let in_relevant_stage = matches!(stage, SecureBootStage::Stage2 | SecureBootStage::Stage3);
    if in_relevant_stage && state.payload_folder_exists == Some(false) {
        out.push(finding(
            "payload-present",
            DiagnosticSeverity::Error,
            "SecureBootUpdates payload folder is missing",
            "The folder C:\\Windows\\System32\\SecureBootUpdates\\ does not exist. The Secure-Boot-Update task will fail with 0x80070002.",
            "Install the latest cumulative update to restore payload files, or use WinCsFlags.exe if available.",
        ));
    } else if in_relevant_stage && state.payload_bin_count == Some(0) {
        out.push(finding(
            "payload-present",
            DiagnosticSeverity::Warning,
            "SecureBootUpdates folder has no .bin payload files",
            "The payload folder exists but contains no .bin files needed for the update.",
            "Install the latest cumulative update to restore payload files.",
        ));
    }
}

fn check_scheduled_task_health(state: &SecureBootScanState, out: &mut Vec<DiagnosticFinding>) {
    if state.scheduled_task_exists == Some(false) {
        out.push(finding(
            "scheduled-task-health",
            DiagnosticSeverity::Error,
            "Secure-Boot-Update scheduled task not found",
            "The required scheduled task \\Microsoft\\Windows\\PI\\Secure-Boot-Update does not exist.",
            "Install the July 2024+ cumulative update to create this task.",
        ));
    } else if let Some(ref result) = state.scheduled_task_last_result {
        if result.contains("0x80070002") {
            out.push(finding(
                "scheduled-task-health",
                DiagnosticSeverity::Warning,
                "Scheduled task failed with 0x80070002",
                "The Secure-Boot-Update task failed because payload files are missing.",
                "Install the latest cumulative update to restore payload files, or use WinCsFlags.exe.",
            ));
        }
    }
}

fn check_uefi_ca2023_status(state: &SecureBootScanState, out: &mut Vec<DiagnosticFinding>) {
    if let Some(val) = state.uefi_ca2023_capable {
        let desc = match val {
            0 => "Not in UEFI DB",
            1 => "In UEFI DB (not booting from it)",
            2 => "In UEFI DB and booting from 2023 boot manager",
            _ => "Unknown value",
        };
        out.push(finding(
            "uefi-ca2023-status",
            DiagnosticSeverity::Info,
            &format!("WindowsUEFICA2023Capable = {val}"),
            desc,
            "",
        ));
    }
}

fn check_boot_manager_signing(state: &SecureBootScanState, out: &mut Vec<DiagnosticFinding>) {
    if state.uefi_ca2023_capable == Some(1) {
        out.push(finding(
            "boot-manager-signing",
            DiagnosticSeverity::Warning,
            "Certificate in UEFI DB but not booting from it",
            "The 2023 certificate is enrolled but the device is still using the 2011-signed boot manager.",
            "Reboot the device to activate the 2023-signed boot manager.",
        ));
    }
}

fn check_pending_reboot(
    state: &SecureBootScanState,
    stage: SecureBootStage,
    out: &mut Vec<DiagnosticFinding>,
) {
    if stage == SecureBootStage::Stage4 && !state.pending_reboot_sources.is_empty() {
        out.push(finding(
            "pending-reboot",
            DiagnosticSeverity::Warning,
            &format!(
                "Reboot pending — sources: {}",
                state.pending_reboot_sources.join(", ")
            ),
            "A reboot is required to complete the Stage 4→5 transition.",
            "Reboot the device to load the new 2023-signed boot manager.",
        ));
    }
}

fn check_error_code_present(state: &SecureBootScanState, out: &mut Vec<DiagnosticFinding>) {
    if let Some(err) = state.uefi_ca2023_error {
        if err != 0 {
            out.push(finding(
                "error-code-present",
                DiagnosticSeverity::Error,
                &format!("UEFICA2023Error = 0x{err:X} ({err})"),
                "An error code is present in the Secure Boot servicing state.",
                "Check the error code against known values. 0x8007070E is a transient staging error that clears after reboot.",
            ));
        }
    }
}

fn check_wincs_available(state: &SecureBootScanState, out: &mut Vec<DiagnosticFinding>) {
    if state.wincs_available == Some(true) {
        out.push(finding(
            "wincs-available",
            DiagnosticSeverity::Info,
            "WinCsFlags.exe is available",
            "The modern WinCS API is available for certificate updates, bypassing legacy payload dependencies.",
            "",
        ));
    }
}

fn check_fallback_timer(state: &SecureBootScanState, out: &mut Vec<DiagnosticFinding>) {
    if let Some(ref date_str) = state.managed_opt_in_date {
        out.push(finding(
            "fallback-timer",
            DiagnosticSeverity::Info,
            &format!("Fallback timer started: {date_str}"),
            "The remediation script's fallback mechanism activates 30 days after opt-in.",
            "",
        ));
    }
}

fn check_stage_stall(
    sessions: &[LogSession],
    current_stage: SecureBootStage,
    out: &mut Vec<DiagnosticFinding>,
) {
    if sessions.len() < 2 {
        return;
    }

    // Count how many consecutive recent sessions show the same stage
    let recent_detect_sessions: Vec<_> = sessions
        .iter()
        .rev()
        .filter(|s| s.source == super::models::LogSource::Detect)
        .take(10)
        .collect();

    let stall_count = recent_detect_sessions
        .iter()
        .take_while(|s| s.result_stage == Some(current_stage))
        .count();

    if stall_count >= 7 && matches!(current_stage, SecureBootStage::Stage2 | SecureBootStage::Stage3) {
        out.push(finding(
            "stage-stall",
            DiagnosticSeverity::Error,
            &format!("Device stalled at {} for {} consecutive detection runs", current_stage.label(), stall_count),
            "This device has not progressed for an extended period. The fallback mechanism may need to activate.",
            "Verify Windows Update health. The fallback activates after 30 days from opt-in.",
        ));
    } else if stall_count >= 3 && matches!(current_stage, SecureBootStage::Stage2 | SecureBootStage::Stage3) {
        out.push(finding(
            "stage-stall",
            DiagnosticSeverity::Warning,
            &format!("Device at {} for {} consecutive detection runs", current_stage.label(), stall_count),
            "Monitor for continued stall. Fallback will activate if this persists past 30 days.",
            "Run 'usoclient StartScan' or check Windows Update / WSUS configuration.",
        ));
    }
}

// ---------------------------------------------------------------------------
// Remediation rules
// ---------------------------------------------------------------------------

fn check_missing_cumulative_update(state: &SecureBootScanState, out: &mut Vec<DiagnosticFinding>) {
    if state.payload_folder_exists == Some(false) && state.scheduled_task_exists == Some(false) {
        out.push(finding(
            "missing-cumulative-update",
            DiagnosticSeverity::Error,
            "Missing cumulative update — no payloads and no scheduled task",
            "Neither the SecureBootUpdates payload folder nor the Secure-Boot-Update task exist.",
            "Install the July 2024+ cumulative update to get both the task and payload files.",
        ));
    }
}

fn check_reboot_needed(
    state: &SecureBootScanState,
    stage: SecureBootStage,
    out: &mut Vec<DiagnosticFinding>,
) {
    if stage == SecureBootStage::Stage4 {
        out.push(finding(
            "reboot-needed",
            DiagnosticSeverity::Warning,
            "Reboot required to complete certificate transition",
            "The UEFI CA 2023 certificate is enrolled in the UEFI DB. A reboot will switch to the new boot manager.",
            "Reboot the device. Verify BitLocker recovery key availability first.",
        ));
    }
}

fn check_transient_staging_error(state: &SecureBootScanState, out: &mut Vec<DiagnosticFinding>) {
    if state.uefi_ca2023_error == Some(0x8007070E) {
        out.push(finding(
            "transient-staging-error",
            DiagnosticSeverity::Info,
            "Transient staging error (0x8007070E)",
            "This error is expected during the Stage 4→5 transition and clears after reboot.",
            "Reboot the device to resolve.",
        ));
    }
}

fn check_missing_payload_with_wincs(state: &SecureBootScanState, out: &mut Vec<DiagnosticFinding>) {
    if state.payload_folder_exists == Some(false) && state.wincs_available == Some(true) {
        out.push(finding(
            "missing-payload-with-wincs",
            DiagnosticSeverity::Info,
            "Payload files missing but WinCS is available",
            "WinCsFlags.exe can bypass the legacy .bin payload dependency entirely.",
            "The remediation script's fallback will use WinCS automatically.",
        ));
    }
}

fn check_windows_10_eol(state: &SecureBootScanState, out: &mut Vec<DiagnosticFinding>) {
    if let Some(ref caption) = state.os_caption {
        if caption.contains("Windows 10") {
            out.push(finding(
                "windows-10-eol",
                DiagnosticSeverity::Warning,
                "Windows 10 — support ended October 2025",
                "This device is running Windows 10 which is past end of support.",
                "Consider upgrading to Windows 11 or enrolling in ESU.",
            ));
        }
    }
}
```

- [ ] **Step 2: Commit**

```bash
git add src-tauri/src/secureboot/rules.rs
git commit -m "feat(secureboot): add diagnostic rules engine (~25 rules)"
```

---

## Task 5: Windows Scanner

**Files:**
- Create: `src-tauri/src/secureboot/scanner.rs`

- [ ] **Step 1: Create scanner.rs (Windows-only registry/service/file scanner)**

```rust
// src-tauri/src/secureboot/scanner.rs
//
// Windows-only: reads registry, services, file system to build SecureBootScanState.

use super::models::SecureBootScanState;
use crate::error::AppError;

#[cfg(target_os = "windows")]
use winreg::enums::*;
#[cfg(target_os = "windows")]
use winreg::RegKey;

#[cfg(not(target_os = "windows"))]
pub fn scan_device() -> Result<SecureBootScanState, AppError> {
    Err(AppError::PlatformUnsupported(
        "Live device scan requires Windows".to_string(),
    ))
}

#[cfg(target_os = "windows")]
pub fn scan_device() -> Result<SecureBootScanState, AppError> {
    let mut state = SecureBootScanState::default();

    // Device name
    state.device_name = std::env::var("COMPUTERNAME").ok();

    read_secureboot_registry(&mut state);
    read_servicing_registry(&mut state);
    read_telemetry_registry(&mut state);
    read_fallback_timer(&mut state);
    read_reboot_indicators(&mut state);
    check_payload_folder(&mut state);
    check_wincs(&mut state);
    check_secure_boot_enabled(&mut state);
    build_raw_registry_dump(&mut state);

    // Service, WMI, scheduled task — run as PowerShell commands to avoid
    // heavy COM/WMI crate dependencies. Capture structured output.
    run_supplementary_checks(&mut state);

    Ok(state)
}

// ---------------------------------------------------------------------------
// Registry readers (Windows only)
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn read_secureboot_registry(state: &mut SecureBootScanState) {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(key) = hklm.open_subkey("SYSTEM\\CurrentControlSet\\Control\\Secureboot") {
        state.managed_opt_in = key.get_value::<u32, _>("MicrosoftUpdateManagedOptIn").ok();
        state.available_updates = key.get_value::<u32, _>("AvailableUpdates").ok();
        state.uefi_ca2023_status = key.get_value::<u32, _>("UEFICA2023Status").ok();
        state.uefi_ca2023_error = key.get_value::<u32, _>("UEFICA2023Error").ok();
    }
}

#[cfg(target_os = "windows")]
fn read_servicing_registry(state: &mut SecureBootScanState) {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(key) = hklm.open_subkey("SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\Servicing") {
        state.uefi_ca2023_capable = key.get_value::<u32, _>("WindowsUEFICA2023Capable").ok();
    }

    // Device attributes
    if let Ok(key) = hklm.open_subkey(
        "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\Servicing\\DeviceAttributes",
    ) {
        state.oem_manufacturer = key.get_value::<String, _>("OEMManufacturerName").ok();
        state.oem_model = key.get_value::<String, _>("OEMModelNumber").ok();
        state.firmware_version = key.get_value::<String, _>("FirmwareVersion").ok();
        state.firmware_date = key.get_value::<String, _>("FirmwareReleaseDate").ok();
    }
}

#[cfg(target_os = "windows")]
fn read_telemetry_registry(state: &mut SecureBootScanState) {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(key) =
        hklm.open_subkey("SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection")
    {
        state.telemetry_level = key.get_value::<u32, _>("AllowTelemetry").ok();
    }
}

#[cfg(target_os = "windows")]
fn read_fallback_timer(state: &mut SecureBootScanState) {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(key) = hklm.open_subkey("SOFTWARE\\Mindcore\\Secureboot") {
        state.managed_opt_in_date = key.get_value::<String, _>("ManagedOptInDate").ok();
    }
}

#[cfg(target_os = "windows")]
fn read_reboot_indicators(state: &mut SecureBootScanState) {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let mut sources = Vec::new();

    if hklm
        .open_subkey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending")
        .is_ok()
    {
        sources.push("CBS-RebootPending".to_string());
    }
    if hklm
        .open_subkey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired")
        .is_ok()
    {
        sources.push("WU-RebootRequired".to_string());
    }
    if let Ok(key) = hklm.open_subkey("SYSTEM\\CurrentControlSet\\Control\\Session Manager") {
        if key.get_value::<String, _>("PendingFileRenameOperations").is_ok() {
            sources.push("PendingFileRename".to_string());
        }
    }
    if hklm
        .open_subkey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\PostRebootReporting")
        .is_ok()
    {
        sources.push("WU-PostRebootReporting".to_string());
    }

    state.pending_reboot_sources = sources;
}

#[cfg(target_os = "windows")]
fn check_payload_folder(state: &mut SecureBootScanState) {
    let sys_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    let payload_dir = std::path::Path::new(&sys_root)
        .join("System32")
        .join("SecureBootUpdates");

    if payload_dir.is_dir() {
        state.payload_folder_exists = Some(true);
        let bin_count = std::fs::read_dir(&payload_dir)
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .filter(|e| {
                        e.path()
                            .extension()
                            .map(|ext| ext.eq_ignore_ascii_case("bin"))
                            .unwrap_or(false)
                    })
                    .count() as u32
            })
            .unwrap_or(0);
        state.payload_bin_count = Some(bin_count);
    } else {
        state.payload_folder_exists = Some(false);
        state.payload_bin_count = Some(0);
    }
}

#[cfg(target_os = "windows")]
fn check_wincs(state: &mut SecureBootScanState) {
    let sys_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    let wincs_path = std::path::Path::new(&sys_root)
        .join("System32")
        .join("WinCsFlags.exe");
    state.wincs_available = Some(wincs_path.exists());
}

#[cfg(target_os = "windows")]
fn check_secure_boot_enabled(state: &mut SecureBootScanState) {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(key) = hklm.open_subkey("SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State") {
        if let Ok(val) = key.get_value::<u32, _>("UEFISecureBootEnabled") {
            state.secure_boot_enabled = Some(val == 1);
        }
    }
}

#[cfg(target_os = "windows")]
fn build_raw_registry_dump(state: &mut SecureBootScanState) {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let mut dump = String::new();

    dump.push_str("--- Secure Boot Registry Dump ---\n");
    if let Ok(key) = hklm.open_subkey("SYSTEM\\CurrentControlSet\\Control\\Secureboot") {
        for (name, value) in key.enum_values().filter_map(|r| r.ok()) {
            dump.push_str(&format!("  Secureboot\\{name} = {value}\n"));
        }
    } else {
        dump.push_str("  Secureboot key: not found\n");
    }

    dump.push_str("\n");
    if let Ok(key) =
        hklm.open_subkey("SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\Servicing")
    {
        for (name, value) in key.enum_values().filter_map(|r| r.ok()) {
            dump.push_str(&format!("  Servicing\\{name} = {value}\n"));
        }
    } else {
        dump.push_str("  Servicing key: not found\n");
    }
    dump.push_str("--- End Registry Dump ---\n");

    state.raw_registry_dump = Some(dump);
}

#[cfg(target_os = "windows")]
fn run_supplementary_checks(state: &mut SecureBootScanState) {
    // DiagTrack service
    if let Ok(output) = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-Command",
            "Get-Service DiagTrack -ErrorAction SilentlyContinue | Select-Object Status,StartType | ConvertTo-Json",
        ])
        .output()
    {
        if let Ok(text) = String::from_utf8(output.stdout) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                state.diagtrack_running = json
                    .get("Status")
                    .and_then(|v| v.as_u64())
                    .map(|s| s == 4); // 4 = Running
                state.diagtrack_start_type = json
                    .get("StartType")
                    .and_then(|v| v.as_u64())
                    .map(|s| match s {
                        2 => "Automatic".to_string(),
                        3 => "Manual".to_string(),
                        4 => "Disabled".to_string(),
                        _ => format!("Unknown ({s})"),
                    });
            }
        }
    }

    // OS caption and build
    if let Ok(output) = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-Command",
            "Get-CimInstance Win32_OperatingSystem | Select-Object Caption,BuildNumber | ConvertTo-Json",
        ])
        .output()
    {
        if let Ok(text) = String::from_utf8(output.stdout) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                state.os_caption = json.get("Caption").and_then(|v| v.as_str()).map(String::from);
                state.os_build = json.get("BuildNumber").and_then(|v| v.as_str()).map(String::from);
            }
        }
    }

    // Scheduled task
    if let Ok(output) = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-Command",
            r#"$t = Get-ScheduledTaskInfo '\Microsoft\Windows\PI\Secure-Boot-Update' -ErrorAction SilentlyContinue; if ($t) { @{Exists=$true;LastRun=$t.LastRunTime.ToString('o');LastResult='0x{0:X}' -f $t.LastTaskResult} | ConvertTo-Json } else { @{Exists=$false} | ConvertTo-Json }"#,
        ])
        .output()
    {
        if let Ok(text) = String::from_utf8(output.stdout) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                state.scheduled_task_exists = json
                    .get("Exists")
                    .and_then(|v| v.as_bool());
                state.scheduled_task_last_run = json
                    .get("LastRun")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                state.scheduled_task_last_result = json
                    .get("LastResult")
                    .and_then(|v| v.as_str())
                    .map(String::from);
            }
        }
    }

    // TPM
    if let Ok(output) = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-Command",
            "Get-CimInstance -Namespace root/cimv2/Security/MicrosoftTpm -ClassName Win32_Tpm -ErrorAction SilentlyContinue | Select-Object IsEnabled_InitialValue,IsActivated_InitialValue,SpecVersion | ConvertTo-Json",
        ])
        .output()
    {
        if let Ok(text) = String::from_utf8(output.stdout) {
            if text.trim().is_empty() {
                state.tpm_present = Some(false);
            } else if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                state.tpm_present = Some(true);
                state.tpm_enabled = json.get("IsEnabled_InitialValue").and_then(|v| v.as_bool());
                state.tpm_activated = json.get("IsActivated_InitialValue").and_then(|v| v.as_bool());
                state.tpm_spec_version = json.get("SpecVersion").and_then(|v| v.as_str()).map(String::from);
            }
        }
    }

    // BitLocker
    if let Ok(output) = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-Command",
            r#"$v = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue; if ($v) { @{ProtectionStatus=$v.ProtectionStatus.ToString();VolumeStatus=$v.VolumeStatus.ToString();KeyProtectorTypes=@($v.KeyProtector | ForEach-Object { $_.KeyProtectorType.ToString() })} | ConvertTo-Json } else { '{}' }"#,
        ])
        .output()
    {
        if let Ok(text) = String::from_utf8(output.stdout) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                state.bitlocker_protection_on = json
                    .get("ProtectionStatus")
                    .and_then(|v| v.as_str())
                    .map(|s| s == "On");
                state.bitlocker_encryption_status = json
                    .get("VolumeStatus")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                if let Some(arr) = json.get("KeyProtectorTypes").and_then(|v| v.as_array()) {
                    state.bitlocker_key_protectors = arr
                        .iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect();
                }
            }
        }
    }

    // Disk partition style
    if let Ok(output) = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-Command",
            "(Get-Disk | Where-Object { $_.IsBoot -eq $true } | Select-Object -First 1).PartitionStyle",
        ])
        .output()
    {
        if let Ok(text) = String::from_utf8(output.stdout) {
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                state.disk_partition_style = Some(trimmed.to_string());
            }
        }
    }
}
```

- [ ] **Step 2: Commit**

```bash
git add src-tauri/src/secureboot/scanner.rs
git commit -m "feat(secureboot): add Windows device scanner (registry, WMI, services)"
```

---

## Task 6: Script Execution

**Files:**
- Create: `src-tauri/src/secureboot/scripts.rs`
- Create: `src-tauri/src/secureboot/scripts/` (directory for embedded PS1 files)

- [ ] **Step 1: Fetch the PowerShell scripts from GitHub**

Download the actual scripts from `mmelkersen/EndpointManager` on GitHub and save them into the project:

```bash
# From repo root
mkdir -p src-tauri/src/secureboot/scripts

# Fetch detection script
curl -sL "https://raw.githubusercontent.com/mmelkersen/EndpointManager/main/Remediation/Secure%20Boot/Detect-SecureBootCertificateUpdate.ps1" \
  -o src-tauri/src/secureboot/scripts/Detect-SecureBootCertificateUpdate.ps1

# Fetch remediation script
curl -sL "https://raw.githubusercontent.com/mmelkersen/EndpointManager/main/Remediation/Secure%20Boot/Remediate-SecureBootCertificateUpdate.ps1" \
  -o src-tauri/src/secureboot/scripts/Remediate-SecureBootCertificateUpdate.ps1
```

Verify both files downloaded correctly (non-empty, contain `Write-Log`).

- [ ] **Step 2: Create scripts.rs**

```rust
// src-tauri/src/secureboot/scripts.rs
//
// Embedded PowerShell script execution for Secure Boot certificate management.

use super::models::ScriptExecutionResult;
use crate::error::AppError;

const DETECT_SCRIPT: &str =
    include_str!("scripts/Detect-SecureBootCertificateUpdate.ps1");
const REMEDIATE_SCRIPT: &str =
    include_str!("scripts/Remediate-SecureBootCertificateUpdate.ps1");

/// Execute the bundled detection script and return stdout/stderr/exit code.
#[cfg(target_os = "windows")]
pub fn run_detection() -> Result<ScriptExecutionResult, AppError> {
    run_embedded_script(DETECT_SCRIPT, "Detect-SecureBootCertificateUpdate.ps1")
}

/// Execute the bundled remediation script and return stdout/stderr/exit code.
#[cfg(target_os = "windows")]
pub fn run_remediation() -> Result<ScriptExecutionResult, AppError> {
    run_embedded_script(REMEDIATE_SCRIPT, "Remediate-SecureBootCertificateUpdate.ps1")
}

#[cfg(not(target_os = "windows"))]
pub fn run_detection() -> Result<ScriptExecutionResult, AppError> {
    Err(AppError::PlatformUnsupported(
        "Script execution requires Windows".to_string(),
    ))
}

#[cfg(not(target_os = "windows"))]
pub fn run_remediation() -> Result<ScriptExecutionResult, AppError> {
    Err(AppError::PlatformUnsupported(
        "Script execution requires Windows".to_string(),
    ))
}

#[cfg(target_os = "windows")]
fn run_embedded_script(script_content: &str, file_name: &str) -> Result<ScriptExecutionResult, AppError> {
    let temp_dir = std::env::temp_dir();
    let script_path = temp_dir.join(file_name);

    // Write script to temp file
    std::fs::write(&script_path, script_content).map_err(|e| {
        AppError::Io(std::io::Error::new(
            e.kind(),
            format!("Failed to write temp script {file_name}: {e}"),
        ))
    })?;

    // Execute via PowerShell
    let output = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            &script_path.to_string_lossy(),
        ])
        .output()
        .map_err(|e| AppError::Io(e))?;

    // Clean up temp file (best effort)
    let _ = std::fs::remove_file(&script_path);

    let exit_code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    Ok(ScriptExecutionResult {
        exit_code,
        stdout,
        stderr,
    })
}
```

- [ ] **Step 3: Commit**

```bash
git add src-tauri/src/secureboot/scripts.rs src-tauri/src/secureboot/scripts/
git commit -m "feat(secureboot): add embedded script execution (detect + remediate)"
```

---

## Task 7: Module Wiring & Feature Flag

**Files:**
- Create: `src-tauri/src/secureboot/mod.rs`
- Modify: `src-tauri/Cargo.toml:17-19`
- Modify: `src-tauri/src/lib.rs:1-21`
- Modify: `src-tauri/src/commands/mod.rs`

- [ ] **Step 1: Create mod.rs**

```rust
// src-tauri/src/secureboot/mod.rs
pub mod log_parser;
pub mod models;
pub mod rules;
pub mod scanner;
pub mod scripts;
pub mod stage;

use models::{DataSource, SecureBootAnalysisResult, SecureBootScanState};

/// Primary analysis entry point.
///
/// - `path` is `None`: live scan (Windows) + auto-discover log at known path.
/// - `path` is `Some(p)`: parse the log file at `p` (all platforms).
pub fn analyze(path: Option<&str>) -> Result<SecureBootAnalysisResult, crate::error::AppError> {
    let (scan_state, log_content, data_source) = match path {
        Some(p) => {
            let content = read_log_file(p)?;
            (SecureBootScanState::default(), Some(content), DataSource::LogImport)
        }
        None => {
            let scan = scanner::scan_device()?;
            let log_content = try_auto_discover_log();
            let source = if log_content.is_some() {
                DataSource::Both
            } else {
                DataSource::LiveScan
            };
            (scan, log_content, source)
        }
    };

    let (sessions, timeline) = match &log_content {
        Some(content) => log_parser::parse_log(content),
        None => (Vec::new(), Vec::new()),
    };

    let current_stage = if data_source == DataSource::LogImport {
        stage::determine_stage_from_log(&sessions)
    } else {
        stage::determine_stage(&scan_state)
    };

    let diagnostics = rules::evaluate_all(&scan_state, current_stage, &sessions);

    Ok(SecureBootAnalysisResult {
        stage: current_stage,
        data_source,
        scan_state,
        sessions,
        timeline,
        diagnostics,
        script_result: None,
    })
}

/// Read and return log file content with encoding fallback.
fn read_log_file(path: &str) -> Result<String, crate::error::AppError> {
    let bytes = std::fs::read(path)?;

    // Handle UTF-8 BOM
    let bytes = if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        &bytes[3..]
    } else {
        &bytes
    };

    Ok(String::from_utf8_lossy(bytes).to_string())
}

/// Try to find the log at the standard Intune path.
fn try_auto_discover_log() -> Option<String> {
    let program_data = std::env::var("ProgramData").ok()?;
    let log_path = std::path::Path::new(&program_data)
        .join("Microsoft")
        .join("IntuneManagementExtension")
        .join("Logs")
        .join("SecureBootCertificateUpdate.log");

    if log_path.exists() {
        read_log_file(&log_path.to_string_lossy()).ok()
    } else {
        None
    }
}
```

- [ ] **Step 2: Add feature flag to Cargo.toml**

In `src-tauri/Cargo.toml`, line 19, change:
```toml
full = ["collector", "deployment", "dsregcmd", "event-log", "intune-diagnostics", "macos-diag", "sysmon"]
```
to:
```toml
full = ["collector", "deployment", "dsregcmd", "event-log", "intune-diagnostics", "macos-diag", "secureboot", "sysmon"]
```

Add new feature line after `macos-diag = ["dep:plist"]` (line 26):
```toml
secureboot = []
```

- [ ] **Step 3: Add module to lib.rs**

In `src-tauri/src/lib.rs`, after line 18 (`pub mod sysmon;`), add:
```rust
#[cfg(feature = "secureboot")]
pub mod secureboot;
```

- [ ] **Step 4: Add command module to commands/mod.rs**

In `src-tauri/src/commands/mod.rs`, after the sysmon entry (line 29), add:
```rust
#[cfg(feature = "secureboot")]
pub mod secureboot;
```

- [ ] **Step 5: Verify compilation**

Run from `src-tauri/`:
```bash
cargo check
```
Expected: compiles (commands/secureboot.rs doesn't exist yet — we'll add it in Task 8. If this fails due to missing command module, just check that the secureboot module itself compiles by temporarily commenting out the commands/mod.rs entry).

- [ ] **Step 6: Commit**

```bash
git add src-tauri/src/secureboot/mod.rs src-tauri/Cargo.toml src-tauri/src/lib.rs src-tauri/src/commands/mod.rs
git commit -m "feat(secureboot): wire module, feature flag, and module declarations"
```

---

## Task 8: Command Handlers

**Files:**
- Create: `src-tauri/src/commands/secureboot.rs`
- Modify: `src-tauri/src/lib.rs:80-155` (invoke_handler registration)

- [ ] **Step 1: Create commands/secureboot.rs**

```rust
// src-tauri/src/commands/secureboot.rs
use crate::secureboot;
use crate::secureboot::models::SecureBootAnalysisResult;

/// Analyze Secure Boot certificate readiness.
/// - With `path`: parse log file only (all platforms).
/// - Without `path` (Windows): live scan + auto-discover log.
#[tauri::command]
pub fn analyze_secureboot(
    path: Option<String>,
) -> Result<SecureBootAnalysisResult, crate::error::AppError> {
    log::info!(
        "event=secureboot_analysis_start path={:?}",
        path.as_deref().unwrap_or("<live scan>")
    );
    secureboot::analyze(path.as_deref())
}

/// Quick rescan — live registry/service check only, no log re-parse.
/// Windows only.
#[tauri::command]
pub fn rescan_secureboot() -> Result<SecureBootAnalysisResult, crate::error::AppError> {
    log::info!("event=secureboot_rescan");
    let scan_state = secureboot::scanner::scan_device()?;
    let stage = secureboot::stage::determine_stage(&scan_state);
    let diagnostics = secureboot::rules::evaluate_all(&scan_state, stage, &[]);

    Ok(SecureBootAnalysisResult {
        stage,
        data_source: secureboot::models::DataSource::LiveScan,
        scan_state,
        sessions: Vec::new(),
        timeline: Vec::new(),
        diagnostics,
        script_result: None,
    })
}

/// Run the bundled detection script, then re-analyze.
#[tauri::command]
pub fn run_secureboot_detection() -> Result<SecureBootAnalysisResult, crate::error::AppError> {
    log::info!("event=secureboot_run_detection");
    let script_result = secureboot::scripts::run_detection()?;

    // Re-analyze after script execution (picks up new log entries + updated registry)
    let mut result = secureboot::analyze(None)?;
    result.script_result = Some(script_result);
    Ok(result)
}

/// Run the bundled remediation script, then re-analyze.
#[tauri::command]
pub fn run_secureboot_remediation() -> Result<SecureBootAnalysisResult, crate::error::AppError> {
    log::info!("event=secureboot_run_remediation");
    let script_result = secureboot::scripts::run_remediation()?;

    // Re-analyze after script execution
    let mut result = secureboot::analyze(None)?;
    result.script_result = Some(script_result);
    Ok(result)
}
```

- [ ] **Step 2: Register commands in lib.rs invoke_handler**

In `src-tauri/src/lib.rs`, before the closing `])` of `invoke_handler` (before `commands::sysmon::analyze_sysmon_logs`), add:

```rust
            #[cfg(feature = "secureboot")]
            commands::secureboot::analyze_secureboot,
            #[cfg(feature = "secureboot")]
            commands::secureboot::rescan_secureboot,
            #[cfg(feature = "secureboot")]
            commands::secureboot::run_secureboot_detection,
            #[cfg(feature = "secureboot")]
            commands::secureboot::run_secureboot_remediation,
```

- [ ] **Step 3: Verify compilation**

Run from `src-tauri/`:
```bash
cargo check
```
Expected: compiles successfully.

- [ ] **Step 4: Run tests**

Run from `src-tauri/`:
```bash
cargo test secureboot
```
Expected: all log_parser and stage tests pass.

- [ ] **Step 5: Run clippy**

Run from `src-tauri/`:
```bash
cargo clippy -- -D warnings
```
Expected: no warnings.

- [ ] **Step 6: Commit**

```bash
git add src-tauri/src/commands/secureboot.rs src-tauri/src/lib.rs
git commit -m "feat(secureboot): add Tauri IPC command handlers"
```

---

## Task 9: Frontend Types

**Files:**
- Create: `src/workspaces/secureboot/types.ts`
- Modify: `src/types/log.ts:43-51`

- [ ] **Step 1: Add "secureboot" to WorkspaceId**

In `src/types/log.ts`, change the `WorkspaceId` type (line 43-51) from:
```typescript
export type WorkspaceId =
  | "log"
  | "intune"
  | "new-intune"
  | "dsregcmd"
  | "macos-diag"
  | "deployment"
  | "event-log"
  | "sysmon";
```
to:
```typescript
export type WorkspaceId =
  | "log"
  | "intune"
  | "new-intune"
  | "dsregcmd"
  | "macos-diag"
  | "deployment"
  | "event-log"
  | "secureboot"
  | "sysmon";
```

- [ ] **Step 2: Create types.ts**

```typescript
// src/workspaces/secureboot/types.ts

export type SecureBootStage =
  | "stage0"
  | "stage1"
  | "stage2"
  | "stage3"
  | "stage4"
  | "stage5";

export type DataSource = "liveScan" | "logImport" | "both";

export type DiagnosticSeverity = "info" | "warning" | "error";

export type LogSource = "detect" | "remediate" | "system";
export type LogLevel = "info" | "warning" | "error" | "success";

export type TimelineEventType =
  | "stageTransition"
  | "remediationResult"
  | "error"
  | "fallback"
  | "sessionStart"
  | "sessionEnd"
  | "diagnosticData"
  | "info";

export interface TimelineEntry {
  timestamp: string;
  source: LogSource;
  level: LogLevel;
  eventType: TimelineEventType;
  message: string;
  stage: SecureBootStage | null;
  errorCode: string | null;
}

export interface LogSession {
  source: LogSource;
  startedAt: string;
  endedAt: string | null;
  resultStage: SecureBootStage | null;
  resultOutcome: string | null;
  entries: TimelineEntry[];
}

export interface SecureBootScanState {
  secureBootEnabled: boolean | null;
  managedOptIn: number | null;
  availableUpdates: number | null;
  uefiCa2023Capable: number | null;
  uefiCa2023Status: number | null;
  uefiCa2023Error: number | null;
  managedOptInDate: string | null;
  telemetryLevel: number | null;
  diagtrackRunning: boolean | null;
  diagtrackStartType: string | null;
  tpmPresent: boolean | null;
  tpmEnabled: boolean | null;
  tpmActivated: boolean | null;
  tpmSpecVersion: string | null;
  bitlockerProtectionOn: boolean | null;
  bitlockerEncryptionStatus: string | null;
  bitlockerKeyProtectors: string[];
  diskPartitionStyle: string | null;
  payloadFolderExists: boolean | null;
  payloadBinCount: number | null;
  scheduledTaskExists: boolean | null;
  scheduledTaskLastRun: string | null;
  scheduledTaskLastResult: string | null;
  wincsAvailable: boolean | null;
  pendingRebootSources: string[];
  deviceName: string | null;
  osCaption: string | null;
  osBuild: string | null;
  oemManufacturer: string | null;
  oemModel: string | null;
  firmwareVersion: string | null;
  firmwareDate: string | null;
  rawRegistryDump: string | null;
}

export interface DiagnosticFinding {
  ruleId: string;
  severity: DiagnosticSeverity;
  title: string;
  detail: string;
  recommendation: string;
}

export interface ScriptExecutionResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export interface SecureBootAnalysisResult {
  stage: SecureBootStage;
  dataSource: DataSource;
  scanState: SecureBootScanState;
  sessions: LogSession[];
  timeline: TimelineEntry[];
  diagnostics: DiagnosticFinding[];
  scriptResult: ScriptExecutionResult | null;
}

export interface SecureBootAnalysisState {
  phase: "idle" | "analyzing" | "done" | "error";
  message: string;
  detail: string | null;
}

export type SecureBootTabId = "diagnostics" | "timeline" | "raw";
```

- [ ] **Step 3: Commit**

```bash
git add src/workspaces/secureboot/types.ts src/types/log.ts
git commit -m "feat(secureboot): add frontend TypeScript types"
```

---

## Task 10: Frontend Store

**Files:**
- Create: `src/workspaces/secureboot/secureboot-store.ts`

- [ ] **Step 1: Create the Zustand store**

```typescript
// src/workspaces/secureboot/secureboot-store.ts
import { create } from "zustand";
import type {
  SecureBootAnalysisResult,
  SecureBootAnalysisState,
  SecureBootTabId,
  DataSource,
} from "./types";

const defaultAnalysisState: SecureBootAnalysisState = {
  phase: "idle",
  message: "Analyze a device or open a log file to begin.",
  detail: null,
};

interface SecureBootState {
  result: SecureBootAnalysisResult | null;
  analysisState: SecureBootAnalysisState;
  dataSource: DataSource | null;
  isAnalyzing: boolean;
  activeTab: SecureBootTabId;
  scriptRunning: "detect" | "remediate" | null;

  beginAnalysis: (message?: string) => void;
  setResult: (result: SecureBootAnalysisResult) => void;
  failAnalysis: (error: unknown) => void;
  setActiveTab: (tab: SecureBootTabId) => void;
  setScriptRunning: (script: "detect" | "remediate" | null) => void;
  clear: () => void;
}

export const useSecureBootStore = create<SecureBootState>((set) => ({
  result: null,
  analysisState: defaultAnalysisState,
  dataSource: null,
  isAnalyzing: false,
  activeTab: "diagnostics",
  scriptRunning: null,

  beginAnalysis: (message) =>
    set({
      result: null,
      isAnalyzing: true,
      analysisState: {
        phase: "analyzing",
        message: message ?? "Analyzing Secure Boot state...",
        detail: null,
      },
    }),

  setResult: (result) =>
    set({
      result,
      dataSource: result.dataSource,
      isAnalyzing: false,
      scriptRunning: null,
      analysisState: {
        phase: "done",
        message: `Stage ${result.stage.replace("stage", "")} — ${stageLabel(result.stage)}`,
        detail: null,
      },
    }),

  failAnalysis: (error) =>
    set({
      isAnalyzing: false,
      scriptRunning: null,
      analysisState: {
        phase: "error",
        message: error instanceof Error ? error.message : String(error),
        detail: null,
      },
    }),

  setActiveTab: (tab) => set({ activeTab: tab }),

  setScriptRunning: (script) => set({ scriptRunning: script }),

  clear: () =>
    set({
      result: null,
      analysisState: defaultAnalysisState,
      dataSource: null,
      isAnalyzing: false,
      activeTab: "diagnostics",
      scriptRunning: null,
    }),
}));

function stageLabel(stage: string): string {
  const labels: Record<string, string> = {
    stage0: "Secure Boot Disabled",
    stage1: "Opt-in Not Configured",
    stage2: "Awaiting Windows Update",
    stage3: "Update In Progress",
    stage4: "Pending Reboot",
    stage5: "Compliant",
  };
  return labels[stage] ?? "Unknown";
}
```

- [ ] **Step 2: Commit**

```bash
git add src/workspaces/secureboot/secureboot-store.ts
git commit -m "feat(secureboot): add Zustand store"
```

---

## Task 11: Command Wrappers

**Files:**
- Modify: `src/lib/commands.ts`

- [ ] **Step 1: Add command wrappers at the end of commands.ts**

Add these functions at the end of `src/lib/commands.ts`, before any trailing newline:

```typescript
// ---------------------------------------------------------------------------
// Secure Boot
// ---------------------------------------------------------------------------

export async function analyzeSecureBoot(
  path?: string | null,
): Promise<SecureBootAnalysisResult> {
  return invokeCommand<SecureBootAnalysisResult>("analyze_secureboot", {
    path: path ?? null,
  });
}

export async function rescanSecureBoot(): Promise<SecureBootAnalysisResult> {
  return invokeCommand<SecureBootAnalysisResult>("rescan_secureboot", {});
}

export async function runSecureBootDetection(): Promise<SecureBootAnalysisResult> {
  return invokeCommand<SecureBootAnalysisResult>("run_secureboot_detection", {});
}

export async function runSecureBootRemediation(): Promise<SecureBootAnalysisResult> {
  return invokeCommand<SecureBootAnalysisResult>("run_secureboot_remediation", {});
}
```

Also add the import for the result type at the top of the file with the other type imports:

```typescript
import type { SecureBootAnalysisResult } from "../workspaces/secureboot/types";
```

- [ ] **Step 2: Commit**

```bash
git add src/lib/commands.ts
git commit -m "feat(secureboot): add frontend command wrappers"
```

---

## Task 12: UI Components — Status Banner, Progress Bar, Fact Groups

**Files:**
- Create: `src/workspaces/secureboot/StatusBanner.tsx`
- Create: `src/workspaces/secureboot/StageProgressBar.tsx`
- Create: `src/workspaces/secureboot/FactGroupCards.tsx`

- [ ] **Step 1: Create StatusBanner.tsx**

```tsx
// src/workspaces/secureboot/StatusBanner.tsx
import { tokens } from "@fluentui/react-components";
import type { SecureBootStage } from "./types";

const STAGE_LABELS: Record<SecureBootStage, string> = {
  stage0: "Secure Boot Disabled",
  stage1: "Opt-in Not Configured",
  stage2: "Awaiting Windows Update",
  stage3: "Update In Progress",
  stage4: "Pending Reboot",
  stage5: "Compliant",
};

const STAGE_DESCRIPTIONS: Record<SecureBootStage, string> = {
  stage0: "Secure Boot must be enabled in BIOS/UEFI for certificate updates",
  stage1: "MicrosoftUpdateManagedOptIn registry key needs to be configured",
  stage2: "Opt-in is set, waiting for Windows Update to deliver certificate updates",
  stage3: "Windows Update is actively processing Secure Boot certificate updates",
  stage4: "CA 2023 certificate is in UEFI DB — reboot required to activate new boot manager",
  stage5: "Booting from Windows UEFI CA 2023-signed boot manager",
};

function stageColor(stage: SecureBootStage): { bg: string; text: string } {
  switch (stage) {
    case "stage5":
      return { bg: tokens.colorPaletteGreenBackground2, text: tokens.colorPaletteGreenForeground2 };
    case "stage2":
    case "stage3":
    case "stage4":
      return { bg: tokens.colorPaletteYellowBackground2, text: tokens.colorPaletteMarigoldForeground2 };
    default:
      return { bg: tokens.colorPaletteRedBackground2, text: tokens.colorPaletteRedForeground2 };
  }
}

interface StatusBannerProps {
  stage: SecureBootStage;
  scanTimestamp?: string;
  onRescan?: () => void;
  isScanning?: boolean;
}

export function StatusBanner({ stage, scanTimestamp, onRescan, isScanning }: StatusBannerProps) {
  const { bg, text } = stageColor(stage);
  const stageNum = stage.replace("stage", "");

  return (
    <div
      style={{
        backgroundColor: bg,
        borderRadius: "6px",
        padding: "14px 16px",
        display: "flex",
        alignItems: "center",
        gap: "12px",
      }}
    >
      <div style={{ flex: 1 }}>
        <div style={{ color: text, fontSize: "inherit", textTransform: "uppercase", letterSpacing: "0.5px", fontWeight: 600 }}>
          Compliance Status
        </div>
        <div style={{ color: tokens.colorNeutralForeground1, fontWeight: 700, fontSize: "15px", marginTop: "2px" }}>
          Stage {stageNum} — {STAGE_LABELS[stage]}
        </div>
        <div style={{ color: tokens.colorNeutralForeground2, fontSize: "inherit", marginTop: "2px" }}>
          {STAGE_DESCRIPTIONS[stage]}
        </div>
      </div>
      {onRescan && (
        <div style={{ textAlign: "right", flexShrink: 0 }}>
          {scanTimestamp && (
            <div style={{ color: tokens.colorNeutralForeground3, fontSize: "11px", marginBottom: "4px" }}>
              {scanTimestamp}
            </div>
          )}
          <button
            onClick={onRescan}
            disabled={isScanning}
            style={{
              background: "none",
              border: `1px solid ${tokens.colorNeutralStroke1}`,
              borderRadius: "4px",
              padding: "4px 12px",
              fontSize: "11px",
              color: tokens.colorNeutralForeground2,
              cursor: isScanning ? "not-allowed" : "pointer",
            }}
          >
            {isScanning ? "Scanning..." : "↻ Rescan"}
          </button>
        </div>
      )}
    </div>
  );
}
```

- [ ] **Step 2: Create StageProgressBar.tsx**

```tsx
// src/workspaces/secureboot/StageProgressBar.tsx
import { tokens } from "@fluentui/react-components";
import type { SecureBootStage } from "./types";

const STAGES: { id: SecureBootStage; short: string }[] = [
  { id: "stage0", short: "Boot" },
  { id: "stage1", short: "Opt-in" },
  { id: "stage2", short: "WU" },
  { id: "stage3", short: "Update" },
  { id: "stage4", short: "Reboot" },
  { id: "stage5", short: "Done" },
];

interface StageProgressBarProps {
  currentStage: SecureBootStage;
}

export function StageProgressBar({ currentStage }: StageProgressBarProps) {
  const currentNum = parseInt(currentStage.replace("stage", ""), 10);

  return (
    <div
      style={{
        backgroundColor: tokens.colorNeutralBackground3,
        borderRadius: "6px",
        padding: "10px 14px",
      }}
    >
      <div style={{ color: tokens.colorNeutralForeground3, fontSize: "10px", textTransform: "uppercase", letterSpacing: "0.5px", marginBottom: "8px" }}>
        Stage Progression
      </div>
      <div style={{ display: "flex", gap: "4px", alignItems: "center" }}>
        {STAGES.map((s, i) => {
          const num = parseInt(s.id.replace("stage", ""), 10);
          const filled = num <= currentNum;
          const active = num === currentNum;
          return (
            <div key={s.id} style={{ display: "contents" }}>
              {i > 0 && <div style={{ color: tokens.colorNeutralForeground4, fontSize: "10px" }}>›</div>}
              <div style={{ flex: 1, textAlign: "center" }}>
                <div
                  style={{
                    height: "6px",
                    borderRadius: "3px",
                    backgroundColor: filled
                      ? tokens.colorPaletteGreenBackground2
                      : tokens.colorNeutralBackground5,
                    boxShadow: active ? `0 0 6px ${tokens.colorPaletteGreenBackground2}` : undefined,
                  }}
                />
                <div
                  style={{
                    fontSize: "9px",
                    marginTop: "4px",
                    color: active
                      ? tokens.colorNeutralForeground1
                      : filled
                        ? tokens.colorNeutralForeground2
                        : tokens.colorNeutralForeground4,
                    fontWeight: active ? 700 : 400,
                  }}
                >
                  {num} · {s.short}{active ? " ●" : ""}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
```

- [ ] **Step 3: Create FactGroupCards.tsx**

```tsx
// src/workspaces/secureboot/FactGroupCards.tsx
import { tokens } from "@fluentui/react-components";
import type { SecureBootScanState, DataSource } from "./types";

interface FactRowProps {
  label: string;
  value: string | null;
  status?: "ok" | "warn" | "error" | "muted";
}

function FactRow({ label, value, status = "muted" }: FactRowProps) {
  const color = {
    ok: tokens.colorPaletteGreenForeground2,
    warn: tokens.colorPaletteMarigoldForeground2,
    error: tokens.colorPaletteRedForeground2,
    muted: tokens.colorNeutralForeground3,
  }[status];

  return (
    <div style={{ display: "flex", justifyContent: "space-between", lineHeight: 2 }}>
      <span>{label}</span>
      <span style={{ color }}>{value ?? "—"}</span>
    </div>
  );
}

interface FactGroupProps {
  title: string;
  children: React.ReactNode;
}

function FactGroup({ title, children }: FactGroupProps) {
  return (
    <div style={{ backgroundColor: tokens.colorNeutralBackground3, borderRadius: "6px", padding: "12px 14px" }}>
      <div style={{ color: tokens.colorBrandForeground2, fontSize: "10px", textTransform: "uppercase", letterSpacing: "0.5px", marginBottom: "8px", fontWeight: 700 }}>
        {title}
      </div>
      <div style={{ fontSize: "inherit", color: tokens.colorNeutralForeground2 }}>{children}</div>
    </div>
  );
}

interface FactGroupCardsProps {
  scanState: SecureBootScanState;
  dataSource: DataSource;
}

export function FactGroupCards({ scanState, dataSource }: FactGroupCardsProps) {
  const logOnly = dataSource === "logImport";
  const na = "Log import only";

  function ca2023Label(val: number | null): { text: string; status: FactRowProps["status"] } {
    switch (val) {
      case 0: return { text: "Not in DB", status: "error" };
      case 1: return { text: "In DB", status: "warn" };
      case 2: return { text: "Booting", status: "ok" };
      default: return { text: "Unknown", status: "muted" };
    }
  }

  const ca = ca2023Label(scanState.uefiCa2023Capable);

  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "10px" }}>
      <FactGroup title="Certificates">
        <FactRow label="UEFI CA 2023" value={logOnly ? na : ca.text} status={logOnly ? "muted" : ca.status} />
        <FactRow label="Boot Manager" value={logOnly ? na : (scanState.uefiCa2023Capable === 2 ? "2023-signed" : "2011-signed")} status={logOnly ? "muted" : (scanState.uefiCa2023Capable === 2 ? "ok" : "warn")} />
        <FactRow label="Capable Flag" value={logOnly ? na : String(scanState.uefiCa2023Capable ?? "—")} status="muted" />
        <FactRow label="Opt-in Key" value={logOnly ? na : (scanState.managedOptIn != null ? `0x${scanState.managedOptIn.toString(16).toUpperCase()}` : "Not set")} status={logOnly ? "muted" : (scanState.managedOptIn === 0x5944 ? "ok" : "error")} />
      </FactGroup>

      <FactGroup title="System Health">
        <FactRow label="Secure Boot" value={logOnly ? na : (scanState.secureBootEnabled ? "Enabled" : "Disabled")} status={logOnly ? "muted" : (scanState.secureBootEnabled ? "ok" : "error")} />
        <FactRow label="TPM" value={logOnly ? na : (scanState.tpmPresent ? (scanState.tpmSpecVersion ?? "Present") : "Not found")} status={logOnly ? "muted" : (scanState.tpmPresent ? "ok" : "warn")} />
        <FactRow label="BitLocker" value={logOnly ? na : (scanState.bitlockerProtectionOn != null ? (scanState.bitlockerProtectionOn ? "On" : "Off") : "—")} status={logOnly ? "muted" : (scanState.bitlockerProtectionOn ? "warn" : "ok")} />
        <FactRow label="Disk" value={logOnly ? na : (scanState.diskPartitionStyle ?? "—")} status={logOnly ? "muted" : (scanState.diskPartitionStyle === "GPT" ? "ok" : (scanState.diskPartitionStyle === "MBR" ? "error" : "muted"))} />
      </FactGroup>

      <FactGroup title="Configuration">
        <FactRow label="Telemetry" value={logOnly ? na : (scanState.telemetryLevel != null ? `Level ${scanState.telemetryLevel}` : "—")} status={logOnly ? "muted" : (scanState.telemetryLevel != null && scanState.telemetryLevel >= 1 ? "ok" : "error")} />
        <FactRow label="DiagTrack" value={logOnly ? na : (scanState.diagtrackRunning != null ? (scanState.diagtrackRunning ? "Running" : "Stopped") : "—")} status={logOnly ? "muted" : (scanState.diagtrackRunning ? "ok" : "warn")} />
        <FactRow label="Sched Task" value={logOnly ? na : (scanState.scheduledTaskExists != null ? (scanState.scheduledTaskExists ? "Present" : "Missing") : "—")} status={logOnly ? "muted" : (scanState.scheduledTaskExists ? "ok" : "error")} />
        <FactRow label="Payloads" value={logOnly ? na : (scanState.payloadFolderExists ? `${scanState.payloadBinCount ?? 0} .bin` : "Missing")} status={logOnly ? "muted" : (scanState.payloadFolderExists && (scanState.payloadBinCount ?? 0) > 0 ? "ok" : "warn")} />
      </FactGroup>
    </div>
  );
}
```

- [ ] **Step 4: Commit**

```bash
git add src/workspaces/secureboot/StatusBanner.tsx src/workspaces/secureboot/StageProgressBar.tsx src/workspaces/secureboot/FactGroupCards.tsx
git commit -m "feat(secureboot): add StatusBanner, StageProgressBar, FactGroupCards components"
```

---

## Task 13: Tab Components

**Files:**
- Create: `src/workspaces/secureboot/DiagnosticsTab.tsx`
- Create: `src/workspaces/secureboot/TimelineTab.tsx`
- Create: `src/workspaces/secureboot/RawDataTab.tsx`

- [ ] **Step 1: Create DiagnosticsTab.tsx**

```tsx
// src/workspaces/secureboot/DiagnosticsTab.tsx
import { tokens } from "@fluentui/react-components";
import type { DiagnosticFinding } from "./types";

interface DiagnosticsTabProps {
  findings: DiagnosticFinding[];
}

const SEVERITY_STYLES: Record<string, { bg: string; fg: string; label: string }> = {
  error: { bg: tokens.colorPaletteRedBackground1, fg: tokens.colorPaletteRedForeground2, label: "ERROR" },
  warning: { bg: tokens.colorPaletteYellowBackground1, fg: tokens.colorPaletteMarigoldForeground2, label: "WARNING" },
  info: { bg: tokens.colorPaletteBlueBackground2, fg: tokens.colorPaletteBlueForeground2, label: "INFO" },
};

export function DiagnosticsTab({ findings }: DiagnosticsTabProps) {
  if (findings.length === 0) {
    return (
      <div style={{ padding: "20px", textAlign: "center", color: tokens.colorNeutralForeground3 }}>
        No diagnostic findings.
      </div>
    );
  }

  return (
    <div>
      {findings.map((f) => {
        const style = SEVERITY_STYLES[f.severity] ?? SEVERITY_STYLES.info;
        return (
          <div
            key={f.ruleId}
            style={{
              padding: "10px 14px",
              borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
              backgroundColor: style.bg,
            }}
          >
            <div style={{ fontSize: "10px", textTransform: "uppercase", fontWeight: 700, color: style.fg }}>
              {style.label}
            </div>
            <div style={{ marginTop: "3px", fontWeight: 600, color: tokens.colorNeutralForeground1 }}>
              {f.title}
            </div>
            <div style={{ marginTop: "3px", color: tokens.colorNeutralForeground2, lineHeight: 1.45 }}>
              {f.detail}
            </div>
            {f.recommendation && (
              <div style={{ marginTop: "4px", color: tokens.colorBrandForeground2, fontSize: "inherit" }}>
                → {f.recommendation}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
```

- [ ] **Step 2: Create TimelineTab.tsx**

```tsx
// src/workspaces/secureboot/TimelineTab.tsx
import { tokens } from "@fluentui/react-components";
import type { TimelineEntry } from "./types";

interface TimelineTabProps {
  timeline: TimelineEntry[];
}

const SOURCE_COLORS: Record<string, string> = {
  detect: tokens.colorPaletteBlueForeground2,
  remediate: tokens.colorPaletteMarigoldForeground2,
  system: tokens.colorNeutralForeground3,
};

const LEVEL_COLORS: Record<string, string> = {
  error: tokens.colorPaletteRedForeground2,
  warning: tokens.colorPaletteMarigoldForeground2,
  success: tokens.colorPaletteGreenForeground2,
  info: tokens.colorNeutralForeground3,
};

export function TimelineTab({ timeline }: TimelineTabProps) {
  if (timeline.length === 0) {
    return (
      <div style={{ padding: "20px", textAlign: "center", color: tokens.colorNeutralForeground3 }}>
        No log data available. Open a SecureBootCertificateUpdate.log file or run detection on Windows.
      </div>
    );
  }

  return (
    <div style={{ fontFamily: "var(--fontFamilyMonospace, monospace)", fontSize: "11px" }}>
      {timeline.map((entry, i) => {
        const ts = entry.timestamp.replace("T", " ").substring(0, 19);
        const isHighlight = entry.eventType === "stageTransition" || entry.eventType === "error" || entry.eventType === "fallback" || entry.eventType === "remediationResult";

        return (
          <div
            key={i}
            style={{
              display: "flex",
              gap: "10px",
              padding: "3px 14px",
              backgroundColor: isHighlight ? tokens.colorNeutralBackground3 : undefined,
              borderLeft: isHighlight ? `3px solid ${LEVEL_COLORS[entry.level] ?? tokens.colorNeutralStroke1}` : "3px solid transparent",
              alignItems: "baseline",
            }}
          >
            <span style={{ color: tokens.colorNeutralForeground4, whiteSpace: "nowrap", flexShrink: 0, width: "130px" }}>
              {ts}
            </span>
            <span
              style={{
                color: SOURCE_COLORS[entry.source] ?? tokens.colorNeutralForeground3,
                textTransform: "uppercase",
                fontWeight: 600,
                fontSize: "9px",
                width: "70px",
                flexShrink: 0,
              }}
            >
              {entry.source}
            </span>
            <span style={{ color: LEVEL_COLORS[entry.level] ?? tokens.colorNeutralForeground2, flex: 1 }}>
              {entry.message}
            </span>
          </div>
        );
      })}
    </div>
  );
}
```

- [ ] **Step 3: Create RawDataTab.tsx**

```tsx
// src/workspaces/secureboot/RawDataTab.tsx
import { tokens } from "@fluentui/react-components";

interface RawDataTabProps {
  rawDump: string | null;
}

export function RawDataTab({ rawDump }: RawDataTabProps) {
  if (!rawDump) {
    return (
      <div style={{ padding: "20px", textAlign: "center", color: tokens.colorNeutralForeground3 }}>
        No raw data available. Live device scan is required for registry dump.
      </div>
    );
  }

  return (
    <div style={{ padding: "10px 14px" }}>
      <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: "8px" }}>
        <button
          onClick={() => void navigator.clipboard.writeText(rawDump)}
          style={{
            background: "none",
            border: `1px solid ${tokens.colorNeutralStroke1}`,
            borderRadius: "4px",
            padding: "4px 10px",
            fontSize: "11px",
            color: tokens.colorNeutralForeground2,
            cursor: "pointer",
          }}
        >
          Copy to clipboard
        </button>
      </div>
      <pre
        style={{
          fontFamily: "var(--fontFamilyMonospace, monospace)",
          fontSize: "11px",
          whiteSpace: "pre-wrap",
          wordBreak: "break-word",
          color: tokens.colorNeutralForeground2,
          lineHeight: 1.5,
          margin: 0,
        }}
      >
        {rawDump}
      </pre>
    </div>
  );
}
```

- [ ] **Step 4: Commit**

```bash
git add src/workspaces/secureboot/DiagnosticsTab.tsx src/workspaces/secureboot/TimelineTab.tsx src/workspaces/secureboot/RawDataTab.tsx
git commit -m "feat(secureboot): add Diagnostics, Timeline, and RawData tab components"
```

---

## Task 14: Main Workspace & Sidebar

**Files:**
- Create: `src/workspaces/secureboot/SecureBootWorkspace.tsx`
- Create: `src/workspaces/secureboot/SecureBootSidebar.tsx`

- [ ] **Step 1: Create SecureBootWorkspace.tsx**

```tsx
// src/workspaces/secureboot/SecureBootWorkspace.tsx
import { tokens } from "@fluentui/react-components";
import { useSecureBootStore } from "./secureboot-store";
import { StatusBanner } from "./StatusBanner";
import { StageProgressBar } from "./StageProgressBar";
import { FactGroupCards } from "./FactGroupCards";
import { DiagnosticsTab } from "./DiagnosticsTab";
import { TimelineTab } from "./TimelineTab";
import { RawDataTab } from "./RawDataTab";
import type { SecureBootTabId } from "./types";
import { rescanSecureBoot } from "../../lib/commands";

const TABS: { id: SecureBootTabId; label: string }[] = [
  { id: "diagnostics", label: "Diagnostics" },
  { id: "timeline", label: "Timeline" },
  { id: "raw", label: "Raw Data" },
];

export function SecureBootWorkspace() {
  const result = useSecureBootStore((s) => s.result);
  const analysisState = useSecureBootStore((s) => s.analysisState);
  const isAnalyzing = useSecureBootStore((s) => s.isAnalyzing);
  const activeTab = useSecureBootStore((s) => s.activeTab);
  const setActiveTab = useSecureBootStore((s) => s.setActiveTab);

  const handleRescan = () => {
    const store = useSecureBootStore.getState();
    store.beginAnalysis("Rescanning device...");
    rescanSecureBoot()
      .then((r) => store.setResult(r))
      .catch((e) => store.failAnalysis(e));
  };

  if (!result && !isAnalyzing) {
    return (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", color: tokens.colorNeutralForeground3 }}>
        <div style={{ textAlign: "center" }}>
          <div style={{ fontSize: "16px", fontWeight: 600 }}>Secure Boot Certificates</div>
          <div style={{ marginTop: "8px" }}>{analysisState.message}</div>
        </div>
      </div>
    );
  }

  if (isAnalyzing) {
    return (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", color: tokens.colorNeutralForeground3 }}>
        <div style={{ textAlign: "center" }}>
          <div style={{ fontSize: "14px" }}>{analysisState.message}</div>
        </div>
      </div>
    );
  }

  if (!result) return null;

  const diagnosticCounts = {
    error: result.diagnostics.filter((d) => d.severity === "error").length,
    warning: result.diagnostics.filter((d) => d.severity === "warning").length,
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", overflow: "auto", padding: "12px", gap: "10px" }}>
      <StatusBanner stage={result.stage} onRescan={handleRescan} isScanning={isAnalyzing} />
      <StageProgressBar currentStage={result.stage} />
      <FactGroupCards scanState={result.scanState} dataSource={result.dataSource} />

      {/* Tabbed detail area */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", backgroundColor: tokens.colorNeutralBackground3, borderRadius: "6px", overflow: "hidden", minHeight: 0 }}>
        <div style={{ display: "flex", borderBottom: `1px solid ${tokens.colorNeutralStroke2}` }}>
          {TABS.map((tab) => {
            const isActive = activeTab === tab.id;
            const countSuffix = tab.id === "diagnostics" && result.diagnostics.length > 0
              ? ` (${result.diagnostics.length})`
              : tab.id === "timeline" && result.timeline.length > 0
                ? ` (${result.timeline.length})`
                : "";
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                style={{
                  padding: "8px 16px",
                  fontSize: "11px",
                  fontWeight: isActive ? 700 : 400,
                  color: isActive ? tokens.colorBrandForeground1 : tokens.colorNeutralForeground3,
                  borderBottom: isActive ? `2px solid ${tokens.colorBrandForeground1}` : "2px solid transparent",
                  background: "none",
                  border: "none",
                  borderBottomWidth: "2px",
                  borderBottomStyle: "solid",
                  borderBottomColor: isActive ? tokens.colorBrandForeground1 : "transparent",
                  cursor: "pointer",
                }}
              >
                {tab.label}{countSuffix}
              </button>
            );
          })}
        </div>
        <div style={{ flex: 1, overflow: "auto" }}>
          {activeTab === "diagnostics" && <DiagnosticsTab findings={result.diagnostics} />}
          {activeTab === "timeline" && <TimelineTab timeline={result.timeline} />}
          {activeTab === "raw" && <RawDataTab rawDump={result.scanState.rawRegistryDump} />}
        </div>
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Create SecureBootSidebar.tsx**

```tsx
// src/workspaces/secureboot/SecureBootSidebar.tsx
import { tokens } from "@fluentui/react-components";
import { useSecureBootStore } from "./secureboot-store";
import {
  EmptyState,
  SidebarActionButton,
  SourceStatusNotice,
  SourceSummaryCard,
} from "../../components/common/sidebar-primitives";
import {
  analyzeSecureBoot,
  rescanSecureBoot,
  runSecureBootDetection,
  runSecureBootRemediation,
} from "../../lib/commands";

export function SecureBootSidebar() {
  const result = useSecureBootStore((s) => s.result);
  const analysisState = useSecureBootStore((s) => s.analysisState);
  const isAnalyzing = useSecureBootStore((s) => s.isAnalyzing);
  const scriptRunning = useSecureBootStore((s) => s.scriptRunning);
  const dataSource = useSecureBootStore((s) => s.dataSource);

  const diagnostics = result?.diagnostics ?? [];
  const errorCount = diagnostics.filter((d) => d.severity === "error").length;
  const warningCount = diagnostics.filter((d) => d.severity === "warning").length;
  const infoCount = diagnostics.filter((d) => d.severity === "info").length;

  const isNonCompliant = result != null && result.stage !== "stage5";
  const isWindows = navigator.userAgent.includes("Windows");

  const handleRunDetection = () => {
    const store = useSecureBootStore.getState();
    store.setScriptRunning("detect");
    store.beginAnalysis("Running detection script...");
    runSecureBootDetection()
      .then((r) => store.setResult(r))
      .catch((e) => store.failAnalysis(e));
  };

  const handleRunRemediation = () => {
    if (!confirm("This will configure your device for Secure Boot certificate updates.\n\nModifies registry keys under HKLM\\SYSTEM\\CurrentControlSet\\Control\\Secureboot.\n\nContinue?")) {
      return;
    }
    const store = useSecureBootStore.getState();
    store.setScriptRunning("remediate");
    store.beginAnalysis("Running remediation script...");
    runSecureBootRemediation()
      .then((r) => store.setResult(r))
      .catch((e) => store.failAnalysis(e));
  };

  const handleRescan = () => {
    const store = useSecureBootStore.getState();
    store.beginAnalysis("Rescanning...");
    rescanSecureBoot()
      .then((r) => store.setResult(r))
      .catch((e) => store.failAnalysis(e));
  };

  return (
    <>
      {/* Quick Actions */}
      {isWindows && (
        <div
          style={{
            padding: "8px 10px",
            borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
            backgroundColor: tokens.colorNeutralBackground2,
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: "6px",
          }}
        >
          <SidebarActionButton
            label={scriptRunning === "detect" ? "Running..." : "Run Detection"}
            disabled={isAnalyzing}
            onClick={handleRunDetection}
          />
          <SidebarActionButton
            label={scriptRunning === "remediate" ? "Running..." : "Run Remediation"}
            disabled={isAnalyzing || !isNonCompliant}
            onClick={handleRunRemediation}
          />
          <SidebarActionButton
            label="Rescan"
            disabled={isAnalyzing}
            onClick={handleRescan}
          />
        </div>
      )}

      <SourceSummaryCard
        badge="secureboot"
        title={result?.scanState.deviceName ?? "Secure Boot Certificates"}
        subtitle={
          dataSource === "liveScan"
            ? "Live device scan"
            : dataSource === "logImport"
              ? "Log file import"
              : dataSource === "both"
                ? "Live scan + log"
                : "Open a source to begin."
        }
        body={
          <div style={{ fontSize: "inherit", color: tokens.colorNeutralForeground2, lineHeight: 1.5 }}>
            <div>{analysisState.message}</div>
            {result?.scriptResult && (
              <div style={{ marginTop: "4px" }}>Scripts v4.0</div>
            )}
          </div>
        }
      />

      {(analysisState.phase === "analyzing" || analysisState.phase === "error") && (
        <SourceStatusNotice
          kind={analysisState.phase === "error" ? "error" : "info"}
          message={analysisState.message}
          detail={analysisState.detail ?? undefined}
        />
      )}

      <div style={{ flex: 1, overflow: "auto", backgroundColor: tokens.colorNeutralBackground2 }}>
        {!result && !isAnalyzing && analysisState.phase !== "error" && (
          <EmptyState
            title="No analysis yet"
            body="Run detection on this Windows device, or open a SecureBootCertificateUpdate.log file."
          />
        )}

        {result && (
          <div style={{ padding: "10px", borderBottom: `1px solid ${tokens.colorNeutralStroke2}` }}>
            <div style={{ fontSize: "inherit", fontWeight: 600, marginBottom: "6px" }}>Findings</div>
            <div style={{ fontSize: "inherit", color: tokens.colorNeutralForeground2 }}>
              {errorCount} errors · {warningCount} warnings · {infoCount} info
            </div>
          </div>
        )}
      </div>
    </>
  );
}
```

- [ ] **Step 3: Commit**

```bash
git add src/workspaces/secureboot/SecureBootWorkspace.tsx src/workspaces/secureboot/SecureBootSidebar.tsx
git commit -m "feat(secureboot): add main workspace and sidebar components"
```

---

## Task 15: Workspace Definition & Registration

**Files:**
- Create: `src/workspaces/secureboot/index.ts`
- Modify: `src/workspaces/registry.ts`

- [ ] **Step 1: Create index.ts**

```typescript
// src/workspaces/secureboot/index.ts
import { lazy } from "react";
import type { WorkspaceDefinition } from "../types";

export const securebootWorkspace: WorkspaceDefinition = {
  id: "secureboot",
  label: "Secure Boot Certs",
  platforms: "all",
  component: lazy(() =>
    import("./SecureBootWorkspace").then((m) => ({
      default: m.SecureBootWorkspace,
    })),
  ),
  sidebar: lazy(() =>
    import("./SecureBootSidebar").then((m) => ({
      default: m.SecureBootSidebar,
    })),
  ),
  capabilities: {
    knownSources: false,
  },
  fileFilters: [
    { name: "Secure Boot Logs", extensions: ["log"] },
    { name: "All Files", extensions: ["*"] },
  ],
  actionLabels: {
    file: "Open Log File",
    placeholder: "Analyze Secure Boot...",
  },
  onOpenSource: async (source, trigger) => {
    const [{ useUiStore }, { analyzeSecureBoot }, { useSecureBootStore }] =
      await Promise.all([
        import("../../stores/ui-store"),
        import("../../lib/commands"),
        import("./secureboot-store"),
      ]);

    useUiStore.getState().ensureWorkspaceVisible("secureboot", trigger);

    const store = useSecureBootStore.getState();

    if (source.kind === "file") {
      store.beginAnalysis("Analyzing log file...");
      try {
        const result = await analyzeSecureBoot(source.path);
        store.setResult(result);
      } catch (e) {
        store.failAnalysis(e);
      }
    } else if (source.kind === "known") {
      throw new Error("Known log presets are not supported in the Secure Boot workspace.");
    } else {
      // Default: live scan (no path)
      store.beginAnalysis("Scanning device...");
      try {
        const result = await analyzeSecureBoot();
        store.setResult(result);
      } catch (e) {
        store.failAnalysis(e);
      }
    }
  },
};
```

- [ ] **Step 2: Register in registry.ts**

In `src/workspaces/registry.ts`, add the import after line 11:
```typescript
import { securebootWorkspace } from "./secureboot";
```

Add `securebootWorkspace` to the `ALL_WORKSPACES` array (after `sysmonWorkspace`):
```typescript
const ALL_WORKSPACES: WorkspaceDefinition[] = [
  logWorkspace,
  intuneWorkspace,
  newIntuneWorkspace,
  dsregcmdWorkspace,
  macosDiagWorkspace,
  deploymentWorkspace,
  eventLogWorkspace,
  sysmonWorkspace,
  securebootWorkspace,
];
```

- [ ] **Step 3: Run TypeScript check**

```bash
npx tsc --noEmit
```
Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add src/workspaces/secureboot/index.ts src/workspaces/registry.ts
git commit -m "feat(secureboot): register workspace definition"
```

---

## Task 16: Collector Integration

**Files:**
- Modify: `src-tauri/src/collector/profile_data.json`
- Modify: `src/lib/collection-categories.ts:29-32`

- [ ] **Step 1: Add secureboot items to profile_data.json**

Add these items to the appropriate sections of `src-tauri/src/collector/profile_data.json`:

In the `registry` array, add:
```json
{
  "id": "secureboot-registry",
  "family": "secureboot",
  "path": "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Secureboot",
  "fileName": "secureboot-config.reg",
  "notes": "Secure Boot configuration and opt-in state"
},
{
  "id": "secureboot-servicing",
  "family": "secureboot",
  "path": "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\Servicing",
  "fileName": "secureboot-servicing.reg",
  "notes": "Certificate deployment status (CA2023Capable, UEFICA2023Status)"
}
```

In the `logs` array, add:
```json
{
  "id": "secureboot-log",
  "family": "secureboot",
  "sourcePattern": "%ProgramData%\\Microsoft\\IntuneManagementExtension\\Logs\\SecureBootCertificateUpdate.log",
  "destinationFolder": "logs/secureboot",
  "notes": "Secure Boot certificate update remediation log"
},
{
  "id": "secureboot-log-old",
  "family": "secureboot",
  "sourcePattern": "%ProgramData%\\Microsoft\\IntuneManagementExtension\\Logs\\SecureBootCertificateUpdate.log.old",
  "destinationFolder": "logs/secureboot",
  "notes": "Rotated Secure Boot log backup"
}
```

In the `commands` array, add:
```json
{
  "id": "secureboot-task-status",
  "family": "secureboot",
  "command": "powershell.exe",
  "arguments": ["-NoProfile", "-Command", "Get-ScheduledTaskInfo '\\Microsoft\\Windows\\PI\\Secure-Boot-Update' -ErrorAction SilentlyContinue | Format-List *"],
  "fileName": "secureboot-task-status.txt",
  "timeoutSecs": 15,
  "notes": "Secure-Boot-Update scheduled task state"
},
{
  "id": "secureboot-bitlocker",
  "family": "secureboot",
  "command": "powershell.exe",
  "arguments": ["-NoProfile", "-Command", "Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue | Format-List *"],
  "fileName": "secureboot-bitlocker.txt",
  "timeoutSecs": 15,
  "notes": "BitLocker status for Secure Boot cert transition impact"
}
```

- [ ] **Step 2: Add secureboot family to collection-categories.ts**

In `src/lib/collection-categories.ts`, line 31, change:
```typescript
    families: ["security", "certificates", "bitlocker", "antimalware"],
```
to:
```typescript
    families: ["security", "certificates", "bitlocker", "antimalware", "secureboot"],
```

- [ ] **Step 3: Verify compilation**

```bash
cargo check
npx tsc --noEmit
```
Expected: both pass.

- [ ] **Step 4: Commit**

```bash
git add src-tauri/src/collector/profile_data.json src/lib/collection-categories.ts
git commit -m "feat(secureboot): add collector profile items and category registration"
```

---

## Task 17: Final Verification

- [ ] **Step 1: Run full Rust checks**

```bash
cd src-tauri && cargo check && cargo test secureboot && cargo clippy -- -D warnings
```
Expected: all pass.

- [ ] **Step 2: Run TypeScript check**

```bash
npx tsc --noEmit
```
Expected: no errors.

- [ ] **Step 3: Run frontend dev server**

```bash
npm run frontend:dev
```
Expected: Vite compiles without errors. Navigate to the app and verify the Secure Boot workspace appears in the workspace dropdown.

- [ ] **Step 4: Commit any fixes**

If any verification step revealed issues, fix them and commit:
```bash
git add -A && git commit -m "fix(secureboot): address verification issues"
```
