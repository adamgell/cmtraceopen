use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::macos_diag::models::{FdaStatus, MacosLogFileEntry, MacosMdmProfile};

// NOTE: Several types in this module embed structs from `macos_diag::models`
// (FdaStatus, MacosLogFileEntry, MacosMdmProfile) that are `Serialize`-only.
// Those types are command-return-only — they never round-trip through IPC,
// so we deliberately do not derive `Deserialize` on the structs that hold them.

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JamfEnvironment {
    pub jamf_installed: bool,
    pub jamf_version: Option<String>,
    pub jss_url: Option<String>,
    pub last_check_in: Option<DateTime<Utc>>,
    pub mdm_profile_present: bool,
    pub mdm_organization: Option<String>,
    pub jamf_connect_installed: bool,
    pub jamf_connect_version: Option<String>,
    pub jamf_connect_idp: Option<String>,
    pub fda_status: FdaStatus,
    pub directories: JamfDirectoryStatus,
    pub summary: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JamfDirectoryStatus {
    pub jamf_log: bool,
    pub jamf_app_support: bool,
    pub jamf_receipts: bool,
    pub jamf_user_logs: bool,         // ~/Library/Logs/JAMF
    pub self_service_log: bool,       // ~/Library/Logs/JAMF/selfservice.log
    pub connect_log: bool,
    pub connect_user_logs: bool,
}

// Adjacently tagged so data-carrying variants cross IPC as
// `{"type":"policyId","value":"332"}` and unit variants as
// `{"type":"recurringCheckIn"}` — matching the discriminated unions in
// `src/workspaces/macos-jamf/types.ts`. Serde's default external tagging
// would emit a bare string / `{"policyId":"332"}`, which the frontend
// cannot read (it switches on `.type`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "value", rename_all = "camelCase")]
pub enum JamfPolicyTrigger {
    RecurringCheckIn,
    Event(String),
    Manual,
    Startup,
    Login,
    Logout,
    PolicyId(String),
    Other(String),
}

// Adjacently tagged — see the note on `JamfPolicyTrigger`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "value", rename_all = "camelCase")]
pub enum JamfPolicyResult {
    Success,
    Failure(String),
    InProgress,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JamfPolicyEvent {
    pub timestamp: DateTime<Utc>,
    pub trigger: JamfPolicyTrigger,
    pub policy_id: Option<String>,
    pub policy_name: Option<String>,
    pub result: JamfPolicyResult,
    pub duration_ms: Option<u64>,
    pub raw_line_offset: u64,
    pub raw_line: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JamfSelfServiceEvent {
    pub timestamp: DateTime<Utc>,
    pub action: String,
    pub item_name: Option<String>,
    pub result: Option<String>,
    pub raw_line: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JamfConnectEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub idp: Option<String>,
    pub user: Option<String>,
    pub message: String,
    pub raw_line: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JamfPolicyLogResult {
    pub events: Vec<JamfPolicyEvent>,
    pub total_lines: usize,
    pub unparsed_lines: usize,
    pub source_path: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JamfLogScanResult {
    pub files: Vec<MacosLogFileEntry>,
    pub scanned_directories: Vec<String>,
    pub total_size_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JamfProfilesResult {
    pub profiles: Vec<MacosMdmProfile>,
    pub matched_organization: Option<String>,
}
