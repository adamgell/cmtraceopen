use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// The six-stage Secure Boot certificate opt-in progression.
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
    pub fn number(self) -> u8 {
        match self {
            Self::Stage0 => 0,
            Self::Stage1 => 1,
            Self::Stage2 => 2,
            Self::Stage3 => 3,
            Self::Stage4 => 4,
            Self::Stage5 => 5,
        }
    }

    pub fn label(self) -> &'static str {
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

/// Where the analysis data originated from.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum DataSource {
    LiveScan,
    LogImport,
    Both,
}

/// Severity level for a diagnostic finding.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub enum DiagnosticSeverity {
    Info,
    Warning,
    Error,
}

/// Which log file a timeline entry originated from.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum LogSource {
    Detect,
    Remediate,
    System,
}

/// Severity/outcome level of a single log line.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum LogLevel {
    Info,
    Warning,
    Error,
    Success,
}

/// Category of a timeline event.
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

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

/// A single parsed log event placed on the timeline.
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

/// A contiguous run of log entries from a single log file invocation.
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

/// All raw values extracted from a live registry/WMI scan or log import.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SecureBootScanState {
    pub secure_boot_enabled: Option<bool>,

    // UEFI CA 2023 opt-in state
    pub managed_opt_in: Option<u32>,
    pub available_updates: Option<u32>,
    pub uefi_ca2023_capable: Option<u32>,
    pub uefi_ca2023_status: Option<u32>,
    pub uefi_ca2023_error: Option<u32>,
    pub managed_opt_in_date: Option<String>,

    // DiagTrack / telemetry
    pub telemetry_level: Option<u32>,
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
    #[serde(default)]
    pub bitlocker_key_protectors: Vec<String>,

    // Disk
    pub disk_partition_style: Option<String>,

    // Payload / task
    pub payload_folder_exists: Option<bool>,
    pub payload_bin_count: Option<u32>,
    pub scheduled_task_exists: Option<bool>,
    pub scheduled_task_last_run: Option<String>,
    pub scheduled_task_last_result: Option<String>,

    // WinCS
    pub wincs_available: Option<bool>,

    // Pending reboot
    #[serde(default)]
    pub pending_reboot_sources: Vec<String>,

    // Device / OS identity
    pub device_name: Option<String>,
    pub os_caption: Option<String>,
    pub os_build: Option<String>,
    pub oem_manufacturer: Option<String>,
    pub oem_model: Option<String>,
    pub firmware_version: Option<String>,
    pub firmware_date: Option<String>,

    // Raw dump for debugging
    pub raw_registry_dump: Option<String>,
}

/// A single actionable diagnostic finding produced by the rules engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticFinding {
    pub rule_id: String,
    pub severity: DiagnosticSeverity,
    pub title: String,
    pub detail: String,
    pub recommendation: String,
}

/// Raw output from a PowerShell/script execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScriptExecutionResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Top-level result returned from analysis to the frontend.
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
