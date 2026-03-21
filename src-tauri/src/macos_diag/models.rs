use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FdaStatus {
    Granted,
    NotGranted,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MacosDiagToolAvailability {
    pub profiles: bool,
    pub mdatp: bool,
    pub pkgutil: bool,
    pub log_command: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MacosDiagDirectoryStatus {
    pub intune_system_logs: bool,
    pub intune_user_logs: bool,
    pub company_portal_logs: bool,
    pub intune_scripts_logs: bool,
    pub defender_logs: bool,
    pub defender_diag: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MacosDiagEnvironment {
    pub macos_version: String,
    pub macos_build: String,
    pub full_disk_access: FdaStatus,
    pub tools: MacosDiagToolAvailability,
    pub directories: MacosDiagDirectoryStatus,
    pub summary: String,
}

// ---------------------------------------------------------------------------
// Log file scanning (shared by Intune & Defender tabs)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MacosLogFileEntry {
    pub path: String,
    pub file_name: String,
    pub size_bytes: u64,
    pub modified_unix_ms: Option<u64>,
    pub source_directory: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MacosIntuneLogScanResult {
    pub files: Vec<MacosLogFileEntry>,
    pub scanned_directories: Vec<String>,
    pub total_size_bytes: u64,
}

// ---------------------------------------------------------------------------
// Profiles & Enrollment
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MacosMdmPayload {
    pub payload_identifier: String,
    pub payload_display_name: Option<String>,
    pub payload_type: String,
    pub payload_uuid: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MacosMdmProfile {
    pub profile_identifier: String,
    pub profile_display_name: String,
    pub profile_organization: Option<String>,
    pub profile_type: Option<String>,
    pub profile_uuid: Option<String>,
    pub install_date: Option<String>,
    pub payloads: Vec<MacosMdmPayload>,
    pub is_managed: bool,
    pub verification_state: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MacosEnrollmentStatus {
    pub enrolled: bool,
    pub mdm_server: Option<String>,
    pub enrollment_type: Option<String>,
    pub raw_output: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MacosProfilesResult {
    pub profiles: Vec<MacosMdmProfile>,
    pub enrollment_status: MacosEnrollmentStatus,
    pub raw_output: String,
}

// ---------------------------------------------------------------------------
// Defender
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MacosDefenderHealthStatus {
    pub healthy: Option<bool>,
    pub health_issues: Vec<String>,
    pub real_time_protection_enabled: Option<bool>,
    pub definitions_status: Option<String>,
    pub engine_version: Option<String>,
    pub app_version: Option<String>,
    pub raw_output: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MacosDefenderResult {
    pub health: Option<MacosDefenderHealthStatus>,
    pub log_files: Vec<MacosLogFileEntry>,
    pub diag_files: Vec<MacosLogFileEntry>,
}

// ---------------------------------------------------------------------------
// Packages
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MacosPackageInfo {
    pub package_id: String,
    pub version: String,
    pub volume: Option<String>,
    pub location: Option<String>,
    pub install_time: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MacosPackageFiles {
    pub package_id: String,
    pub files: Vec<String>,
    pub file_count: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MacosPackagesResult {
    pub packages: Vec<MacosPackageInfo>,
    pub total_count: usize,
    pub microsoft_count: usize,
}

// ---------------------------------------------------------------------------
// Unified Log
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MacosUnifiedLogPreset {
    pub id: String,
    pub label: String,
    pub predicate: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MacosUnifiedLogEntry {
    pub timestamp: String,
    pub process: String,
    pub subsystem: Option<String>,
    pub category: Option<String>,
    pub level: String,
    pub message: String,
    pub pid: Option<u32>,
    pub tid: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MacosUnifiedLogTimeRange {
    pub start: String,
    pub end: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MacosUnifiedLogResult {
    pub entries: Vec<MacosUnifiedLogEntry>,
    pub total_matched: usize,
    pub capped: bool,
    pub result_cap: usize,
    pub predicate_used: String,
    pub time_range: Option<MacosUnifiedLogTimeRange>,
}
