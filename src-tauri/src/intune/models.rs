use std::collections::HashMap;

use serde::{ser::SerializeStruct, Deserialize, Serialize, Serializer};

use super::guid_registry::GuidRegistryEntry;

/// Artifact count summary retained from an evidence bundle manifest.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceBundleArtifactCounts {
    pub collected: u64,
    pub missing: u64,
    pub failed: u64,
    pub skipped: u64,
}

/// Metadata retained when Intune analysis is sourced from a collected evidence bundle.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceBundleMetadata {
    pub manifest_path: String,
    pub notes_path: Option<String>,
    pub evidence_root: Option<String>,
    #[serde(default)]
    pub primary_entry_points: Vec<String>,
    #[serde(default)]
    pub available_primary_entry_points: Vec<String>,
    pub bundle_id: Option<String>,
    pub bundle_label: Option<String>,
    pub created_utc: Option<String>,
    pub case_reference: Option<String>,
    pub summary: Option<String>,
    pub collector_profile: Option<String>,
    pub collector_version: Option<String>,
    pub collected_utc: Option<String>,
    pub device_name: Option<String>,
    pub primary_user: Option<String>,
    pub platform: Option<String>,
    pub os_version: Option<String>,
    pub tenant: Option<String>,
    pub artifact_counts: Option<EvidenceBundleArtifactCounts>,
}

/// Severity level for generated diagnostic guidance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IntuneDiagnosticSeverity {
    Info,
    Warning,
    Error,
}

/// Diagnostic category used to group related remediation guidance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IntuneDiagnosticCategory {
    Download,
    Install,
    Timeout,
    Script,
    Policy,
    State,
    General,
}

/// Priority used to order remediation guidance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IntuneRemediationPriority {
    Monitor,
    Medium,
    High,
    Immediate,
}

/// Deterministic diagnostic guidance derived from Intune analysis results.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntuneDiagnosticInsight {
    pub id: String,
    pub severity: IntuneDiagnosticSeverity,
    pub category: IntuneDiagnosticCategory,
    pub remediation_priority: IntuneRemediationPriority,
    pub title: String,
    pub summary: String,
    pub likely_cause: Option<String>,
    pub evidence: Vec<String>,
    pub next_checks: Vec<String>,
    #[serde(default)]
    pub suggested_fixes: Vec<String>,
    #[serde(default)]
    pub focus_areas: Vec<String>,
    #[serde(default)]
    pub affected_source_files: Vec<String>,
    #[serde(default)]
    pub related_error_codes: Vec<String>,
}

/// Type of Intune event detected from log analysis.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum IntuneEventType {
    Win32App,
    WinGetApp,
    PowerShellScript,
    Remediation,
    Esp,
    SyncSession,
    PolicyEvaluation,
    ContentDownload,
    Other,
}

/// Status of an Intune operation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum IntuneStatus {
    Success,
    Failed,
    InProgress,
    Pending,
    Timeout,
    Unknown,
}

/// A single Intune event extracted from log analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntuneEvent {
    /// Unique identifier for this event
    pub id: u64,
    /// Event type category
    pub event_type: IntuneEventType,
    /// Display name (resolved from GUID or extracted from context)
    pub name: String,
    /// GUID identifier if available
    pub guid: Option<String>,
    /// Status of the operation
    pub status: IntuneStatus,
    /// Timestamp of event start (ISO 8601 string)
    pub start_time: Option<String>,
    /// Timestamp of event end (ISO 8601 string)
    pub end_time: Option<String>,
    /// Duration in seconds
    pub duration_secs: Option<f64>,
    /// Error code if failed
    pub error_code: Option<String>,
    /// Additional detail message
    pub detail: String,
    /// Source log file path
    pub source_file: String,
    /// Line number in source file
    pub line_number: u32,
}

/// Download statistics for a content download event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadStat {
    /// Name or ID of the content
    pub content_id: String,
    /// Display name
    pub name: String,
    /// Total size in bytes
    pub size_bytes: u64,
    /// Download speed in bytes per second
    pub speed_bps: f64,
    /// Percentage downloaded via Delivery Optimization
    pub do_percentage: f64,
    /// Download duration in seconds
    pub duration_secs: f64,
    /// Whether download succeeded
    pub success: bool,
    /// Timestamp
    pub timestamp: Option<String>,
}

/// Inclusive timestamp bounds captured from analyzed content.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct IntuneTimestampBounds {
    pub first_timestamp: Option<String>,
    pub last_timestamp: Option<String>,
}

/// Coverage metrics for a single analyzed source file.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct IntuneDiagnosticsFileCoverage {
    pub file_path: String,
    pub event_count: u32,
    pub download_count: u32,
    pub timestamp_bounds: Option<IntuneTimestampBounds>,
    #[serde(default)]
    pub is_rotated_segment: bool,
    pub rotation_group: Option<String>,
}

/// Summary of which files and time ranges contributed to diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct IntuneDiagnosticsCoverage {
    #[serde(default)]
    pub files: Vec<IntuneDiagnosticsFileCoverage>,
    pub timestamp_bounds: Option<IntuneTimestampBounds>,
    #[serde(default)]
    pub has_rotated_logs: bool,
    pub dominant_source: Option<IntuneDominantSource>,
}

/// Primary source contributing to the current diagnostics result.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct IntuneDominantSource {
    pub file_path: String,
    pub event_count: u32,
    pub event_share: Option<f64>,
}

/// Confidence bucket for the generated diagnostics result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum IntuneDiagnosticsConfidenceLevel {
    #[default]
    Unknown,
    Low,
    Medium,
    High,
}

/// Confidence metadata for the generated diagnostics result.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct IntuneDiagnosticsConfidence {
    pub level: IntuneDiagnosticsConfidenceLevel,
    pub score: Option<f64>,
    #[serde(default)]
    pub reasons: Vec<String>,
}

/// Grouped repeated failures for follow-on diagnostics phases.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntuneRepeatedFailureGroup {
    pub id: String,
    pub name: String,
    pub event_type: IntuneEventType,
    pub error_code: Option<String>,
    pub occurrences: u32,
    pub timestamp_bounds: Option<IntuneTimestampBounds>,
    #[serde(default)]
    pub source_files: Vec<String>,
    #[serde(default)]
    pub sample_event_ids: Vec<u64>,
}

// ---------------------------------------------------------------------------
// Windows Event Log (EVTX) models
// ---------------------------------------------------------------------------

/// Severity level from a Windows Event Log record (`System.Level`).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EventLogSeverity {
    Critical,
    Error,
    Warning,
    Information,
    Verbose,
    Unknown,
}

impl EventLogSeverity {
    /// Map the numeric `Level` value from an EVTX record to a severity.
    pub fn from_level(level: u8) -> Self {
        match level {
            1 => Self::Critical,
            2 => Self::Error,
            3 => Self::Warning,
            4 => Self::Information,
            5 => Self::Verbose,
            _ => Self::Unknown,
        }
    }

    pub fn is_error_or_warning(&self) -> bool {
        matches!(self, Self::Critical | Self::Error | Self::Warning)
    }
}

/// Typed Windows Event Log channel corresponding to the curated channels
/// collected by the evidence profile.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EventLogChannel {
    DeviceManagementAdmin,
    DeviceManagementOperational,
    Autopilot,
    AadOperational,
    DeliveryOptimizationOperational,
    ManagementService,
    ProvisioningDiagnosticsAdmin,
    ShellCoreOperational,
    TimeServiceOperational,
    UserDeviceRegistrationAdmin,
    CryptoDpapiOperational,
    KerberosOperational,
    SystemLog,
    Other(String),
}

impl EventLogChannel {
    /// Map the full channel name string from an EVTX record to a typed variant.
    pub fn from_channel_string(raw: &str) -> Self {
        let lower = raw.to_ascii_lowercase();
        if lower.contains("devicemanagement")
            && lower.contains("/admin")
            && !lower.contains("/operational")
        {
            Self::DeviceManagementAdmin
        } else if lower.contains("devicemanagement") && lower.contains("/operational") {
            Self::DeviceManagementOperational
        } else if lower.contains("moderndeployment") && lower.contains("autopilot") {
            Self::Autopilot
        } else if lower.contains("-aad/operational") {
            Self::AadOperational
        } else if lower.contains("deliveryoptimization") && lower.contains("/operational") {
            Self::DeliveryOptimizationOperational
        } else if lower.contains("moderndeployment") && lower.contains("managementservice") {
            Self::ManagementService
        } else if lower.contains("provisioning-diagnostics") && lower.contains("/admin") {
            Self::ProvisioningDiagnosticsAdmin
        } else if lower.contains("shell-core") && lower.contains("/operational") {
            Self::ShellCoreOperational
        } else if lower.contains("time-service") && lower.contains("/operational") {
            Self::TimeServiceOperational
        } else if lower.contains("user device registration") && lower.contains("/admin") {
            Self::UserDeviceRegistrationAdmin
        } else if lower.contains("crypto-dpapi") && lower.contains("/operational") {
            Self::CryptoDpapiOperational
        } else if lower.contains("kerberos") && lower.contains("/operational") {
            Self::KerberosOperational
        } else if lower == "system" || lower.contains("system log") {
            Self::SystemLog
        } else if raw.is_empty() {
            Self::Other("Unknown".to_string())
        } else {
            Self::Other(raw.to_string())
        }
    }

    /// Short display name for UI badges and labels.
    pub fn display_name(&self) -> &str {
        match self {
            Self::DeviceManagementAdmin => "MDM Admin",
            Self::DeviceManagementOperational => "MDM Operational",
            Self::Autopilot => "Autopilot",
            Self::AadOperational => "AAD Operational",
            Self::DeliveryOptimizationOperational => "DO Operational",
            Self::ManagementService => "Management Service",
            Self::ProvisioningDiagnosticsAdmin => "Provisioning Admin",
            Self::ShellCoreOperational => "Shell Core",
            Self::TimeServiceOperational => "Time Service",
            Self::UserDeviceRegistrationAdmin => "User Device Reg",
            Self::CryptoDpapiOperational => "Crypto DPAPI",
            Self::KerberosOperational => "Kerberos",
            Self::SystemLog => "System",
            Self::Other(name) => name.as_str(),
        }
    }
}

/// A single parsed record from a Windows Event Log (.evtx) file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventLogEntry {
    /// Sequential ID across all parsed entries (chronological after sorting).
    pub id: u64,
    /// Typed channel enum.
    pub channel: EventLogChannel,
    /// Human-readable channel display name.
    pub channel_display: String,
    /// Provider name from `System.Provider`.
    pub provider: String,
    /// Windows Event ID.
    pub event_id: u32,
    /// Severity mapped from `System.Level`.
    pub severity: EventLogSeverity,
    /// ISO 8601 UTC timestamp.
    pub timestamp: String,
    /// Computer name from `System.Computer`.
    pub computer: Option<String>,
    /// Extracted message from EventData/UserData.
    pub message: String,
    /// Correlation activity ID from `System.Correlation`.
    pub correlation_activity_id: Option<String>,
    /// Path to the .evtx source file.
    pub source_file: String,
}

/// Per-channel summary rollup for the UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventLogChannelSummary {
    pub channel: EventLogChannel,
    pub channel_display: String,
    pub entry_count: u32,
    pub error_count: u32,
    pub warning_count: u32,
    pub timestamp_bounds: Option<IntuneTimestampBounds>,
    pub source_file: String,
}

/// The kind of deterministic correlation between an event log entry
/// and an IME-derived Intune event or diagnostic.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EventLogCorrelationKind {
    /// Temporal proximity within a contextually relevant channel.
    TimeWindowChannelMatch,
    /// Error code from an IME event appears in the event log message.
    ErrorCodeMatch,
    /// Enrollment/registration activity near ESP or sync events.
    EnrollmentContextMatch,
}

/// A deterministic link between an event log entry and an IME event or diagnostic.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventLogCorrelationLink {
    /// Points to `EventLogEntry.id`.
    pub event_log_entry_id: u64,
    /// Points to `IntuneEvent.id` when this is an event-level link.
    pub linked_intune_event_id: Option<u64>,
    /// Points to `IntuneDiagnosticInsight.id` when this is a diagnostic-level link.
    pub linked_diagnostic_id: Option<String>,
    /// Which correlation strategy produced this link.
    pub correlation_kind: EventLogCorrelationKind,
    /// Time gap in seconds between the linked items (for display/sorting).
    pub time_delta_secs: Option<f64>,
}

/// Source category for the current event log analysis payload.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum EventLogAnalysisSource {
    #[default]
    Bundle,
    Live,
}

/// Per-channel outcome status for a live Windows Event Log query.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum EventLogLiveQueryStatus {
    #[default]
    Success,
    Empty,
    Failed,
}

/// Per-channel metadata retained for a live Windows Event Log query attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventLogLiveQueryChannelResult {
    pub channel: EventLogChannel,
    pub channel_display: String,
    pub channel_path: String,
    pub source_file: String,
    pub status: EventLogLiveQueryStatus,
    pub entry_count: u32,
    pub error_message: Option<String>,
}

/// Live Windows Event Log query summary for UI status and empty-state behavior.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct EventLogLiveQueryMetadata {
    pub attempted_channel_count: u32,
    pub successful_channel_count: u32,
    pub channels_with_results_count: u32,
    pub failed_channel_count: u32,
    pub per_channel_entry_limit: u32,
    #[serde(default)]
    pub channels: Vec<EventLogLiveQueryChannelResult>,
}

/// Top-level container for all parsed and correlated Windows Event Log data.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct EventLogAnalysis {
    pub source_kind: EventLogAnalysisSource,
    pub entries: Vec<EventLogEntry>,
    pub channel_summaries: Vec<EventLogChannelSummary>,
    pub correlation_links: Vec<EventLogCorrelationLink>,
    pub parsed_file_count: u32,
    pub total_entry_count: u32,
    pub error_entry_count: u32,
    pub warning_entry_count: u32,
    pub timestamp_bounds: Option<IntuneTimestampBounds>,
    pub live_query: Option<EventLogLiveQueryMetadata>,
}

// ---------------------------------------------------------------------------
// Intune analysis result
// ---------------------------------------------------------------------------

/// Complete result of Intune log analysis.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntuneAnalysisResult {
    /// All detected events
    pub events: Vec<IntuneEvent>,
    /// Download statistics
    pub downloads: Vec<DownloadStat>,
    /// Summary counts
    pub summary: IntuneSummary,
    /// Deterministic diagnostic guidance.
    #[serde(default)]
    pub diagnostics: Vec<IntuneDiagnosticInsight>,
    /// Source path analyzed (file path or directory path)
    pub source_file: String,
    /// Expanded source files included in this result.
    #[serde(default)]
    pub source_files: Vec<String>,
    /// Coverage metadata behind the diagnostics contract.
    #[serde(default)]
    pub diagnostics_coverage: IntuneDiagnosticsCoverage,
    /// Confidence metadata behind the diagnostics contract.
    #[serde(default)]
    pub diagnostics_confidence: IntuneDiagnosticsConfidence,
    /// Grouped repeated failures behind the diagnostics contract.
    #[serde(default)]
    pub repeated_failures: Vec<IntuneRepeatedFailureGroup>,
    /// Bundle metadata retained when the analyzed path is an evidence bundle root.
    #[serde(default)]
    pub evidence_bundle: Option<EvidenceBundleMetadata>,
    /// Parsed and correlated Windows Event Log data from evidence bundle .evtx files.
    #[serde(default)]
    pub event_log_analysis: Option<EventLogAnalysis>,
    /// Global GUID→app-name registry for frontend display (tooltips, lookup panel).
    #[serde(default)]
    pub guid_registry: HashMap<String, GuidRegistryEntry>,
}

impl Serialize for IntuneAnalysisResult {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("IntuneAnalysisResult", 12)?;
        state.serialize_field("events", &self.events)?;
        state.serialize_field("downloads", &self.downloads)?;
        state.serialize_field("summary", &self.summary)?;
        state.serialize_field("diagnostics", &self.diagnostics)?;
        state.serialize_field("sourceFile", &self.source_file)?;
        state.serialize_field("sourceFiles", &self.source_files)?;
        state.serialize_field("diagnosticsCoverage", &self.diagnostics_coverage)?;
        state.serialize_field("diagnosticsConfidence", &self.diagnostics_confidence)?;
        state.serialize_field("repeatedFailures", &self.repeated_failures)?;
        state.serialize_field("evidenceBundle", &self.evidence_bundle)?;
        state.serialize_field("eventLogAnalysis", &self.event_log_analysis)?;
        state.serialize_field("guidRegistry", &self.guid_registry)?;
        state.end()
    }
}

/// Summary statistics from Intune analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntuneSummary {
    pub total_events: u32,
    pub win32_apps: u32,
    pub winget_apps: u32,
    pub scripts: u32,
    pub remediations: u32,
    pub succeeded: u32,
    pub failed: u32,
    pub in_progress: u32,
    pub pending: u32,
    pub timed_out: u32,
    pub total_downloads: u32,
    pub successful_downloads: u32,
    pub failed_downloads: u32,
    pub failed_scripts: u32,
    pub log_time_span: Option<String>,
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{
        EvidenceBundleArtifactCounts, EvidenceBundleMetadata, IntuneAnalysisResult,
        IntuneDiagnosticsConfidence, IntuneDiagnosticsCoverage, IntuneSummary,
    };

    #[test]
    fn intune_analysis_result_serializes_evidence_bundle_metadata() {
        let result = IntuneAnalysisResult {
            events: Vec::new(),
            downloads: Vec::new(),
            summary: IntuneSummary {
                total_events: 0,
                win32_apps: 0,
                winget_apps: 0,
                scripts: 0,
                remediations: 0,
                succeeded: 0,
                failed: 0,
                in_progress: 0,
                pending: 0,
                timed_out: 0,
                total_downloads: 0,
                successful_downloads: 0,
                failed_downloads: 0,
                failed_scripts: 0,
                log_time_span: None,
            },
            diagnostics: Vec::new(),
            source_file: "bundle-root".to_string(),
            source_files: Vec::new(),
            diagnostics_coverage: IntuneDiagnosticsCoverage::default(),
            diagnostics_confidence: IntuneDiagnosticsConfidence::default(),
            repeated_failures: Vec::new(),
            event_log_analysis: None,
            guid_registry: HashMap::new(),
            evidence_bundle: Some(EvidenceBundleMetadata {
                manifest_path: "bundle-root/manifest.json".to_string(),
                notes_path: Some("bundle-root/notes.md".to_string()),
                evidence_root: Some("bundle-root/evidence".to_string()),
                primary_entry_points: vec!["bundle-root/evidence/logs".to_string()],
                available_primary_entry_points: vec!["bundle-root/evidence/logs".to_string()],
                bundle_id: Some("CMTRACE-123".to_string()),
                bundle_label: Some("intune-endpoint-evidence".to_string()),
                created_utc: Some("2026-03-12T16:00:54Z".to_string()),
                case_reference: Some("case-123".to_string()),
                summary: Some("Collected bundle".to_string()),
                collector_profile: Some("intune-windows-endpoint-v1".to_string()),
                collector_version: Some("1.1.0".to_string()),
                collected_utc: Some("2026-03-12T16:00:54Z".to_string()),
                device_name: Some("GELL-VM-5879648".to_string()),
                primary_user: Some("AzureAD\\AdamGell".to_string()),
                platform: Some("Windows".to_string()),
                os_version: Some("Windows 11".to_string()),
                tenant: Some("CDWWorkspaceLab".to_string()),
                artifact_counts: Some(EvidenceBundleArtifactCounts {
                    collected: 55,
                    missing: 7,
                    failed: 2,
                    skipped: 0,
                }),
            }),
        };

        let value = serde_json::to_value(&result).expect("serialize result");

        assert_eq!(
            value["evidenceBundle"]["bundleId"].as_str(),
            Some("CMTRACE-123")
        );
        assert_eq!(
            value["evidenceBundle"]["artifactCounts"]["collected"].as_u64(),
            Some(55)
        );
    }
}
