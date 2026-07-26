use serde::{Deserialize, Deserializer, Serialize, Serializer};

macro_rules! raw_preserving_string_enum {
    (
        $(#[$meta:meta])*
        pub enum $name:ident {
            $($variant:ident => $wire_value:literal),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum $name {
            $($variant,)+
            Unknown(String),
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                let value = match self {
                    $(Self::$variant => $wire_value,)+
                    Self::Unknown(raw) => raw.as_str(),
                };

                serializer.serialize_str(value)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let raw = String::deserialize(deserializer)?;
                Ok(match raw.as_str() {
                    $($wire_value => Self::$variant,)+
                    _ => Self::Unknown(raw),
                })
            }
        }
    };
}

pub const ESP_DIAGNOSTICS_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EspScenario {
    Unknown,
    AutopilotV1,
    ExistingDeviceJson,
    EspOnly,
    AutopilotDevicePreparationV2,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EspPhase {
    NotStarted,
    DevicePreparation,
    DeviceSetup,
    AccountSetup,
    Completed,
    Failed,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EspTrackedKind {
    Msi,
    Office,
    ModernApp,
    Win32App,
    Policy,
    ScepCertificate,
    PlatformScript,
    DevicePreparationWorkload,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EspNormalizedStatus {
    NotStarted,
    NotInstalled,
    Initialized,
    Pending,
    Downloading,
    Downloaded,
    Installing,
    InProgress,
    Processed,
    Succeeded,
    Failed,
    Skipped,
    Uninstalled,
    RebootRequired,
    Cancelled,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EspArtifactStatus {
    Available,
    Missing,
    PermissionDenied,
    ParseFailed,
    Unsupported,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EspCorrelationConfidence {
    Exact,
    Strong,
    Temporal,
    Uncorrelated,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EspTimestampKind {
    Utc,
    Offset,
    Local,
    Unspecified,
    Invalid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EspSourceKind {
    Registry,
    Json,
    EventLog,
    ImeLog,
    DeploymentLog,
    Process,
    System,
    DeliveryOptimization,
    Graph,
    Coverage,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EspSensitivity {
    Public,
    Sensitive,
    Restricted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspClassifiedString {
    pub value: String,
    pub sensitivity: EspSensitivity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EspParseState {
    Parsed,
    Raw,
    Malformed,
    Unsupported,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EspSourceAccessState {
    Available,
    Missing,
    PermissionDenied,
    Failed,
    Unsupported,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EspScope {
    Device,
    User,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EspSessionKind {
    Classic,
    DevicePreparationV2,
}

raw_preserving_string_enum! {
    pub enum EspJoinMode {
        Entra => "entra",
        HybridEntra => "hybridEntra",
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EspFindingSeverity {
    Info,
    Warning,
    Error,
    Blocker,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EspFindingConfidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EspTimelineKind {
    ProfileDownload,
    OfflineDomainJoin,
    Registration,
    Workload,
    DeliveryOptimization,
    Coverage,
    Process,
    Other,
}

raw_preserving_string_enum! {
    pub enum EspGraphAssignmentIntent {
        Required => "required",
        Available => "available",
        Uninstall => "uninstall",
    }
}

raw_preserving_string_enum! {
    pub enum EspGraphTargetKind {
        AllDevices => "allDevices",
        AllUsers => "allUsers",
        Group => "group",
        Filter => "filter",
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EspGraphTargeting {
    Declared,
    Effective,
}

raw_preserving_string_enum! {
    pub enum EspGraphPolicyKind {
        DeviceConfiguration => "deviceConfiguration",
        Compliance => "compliance",
        ConfigurationPolicy => "configurationPolicy",
        ScepCertificate => "scepCertificate",
    }
}

raw_preserving_string_enum! {
    pub enum EspGraphScriptKind {
        PlatformScript => "platformScript",
        Remediation => "remediation",
    }
}

raw_preserving_string_enum! {
    pub enum EspGraphObservationSection {
        ManagedDevice => "managedDevice",
        AutopilotIdentity => "autopilotIdentity",
        DeploymentProfile => "deploymentProfile",
        EnrollmentConfiguration => "enrollmentConfiguration",
        App => "app",
        Policy => "policy",
        Script => "script",
    }
}

raw_preserving_string_enum! {
    pub enum EspGraphPolicyStatusDetailKind {
        App => "app",
        Policy => "policy",
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EspDeliveryOptimizationEventKind {
    DownloadStarted,
    DownloadCompleted,
}

raw_preserving_string_enum! {
    pub enum GraphSectionStatus {
        Available => "available",
        NotFound => "notFound",
        PermissionDenied => "permissionDenied",
        Failed => "failed",
        Skipped => "skipped",
        Cancelled => "cancelled",
    }
}

raw_preserving_string_enum! {
    pub enum GraphApiVersion {
        V1_0 => "v1.0",
        Beta => "beta",
        NotRequested => "notRequested",
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum EspRawStatus {
    Number(i64),
    Text(String),
    Other(serde_json::Value),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EspObservationValue {
    Text(String),
    Integer(i64),
    Unsigned(u64),
    Boolean(bool),
    StringList(Vec<String>),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EspSystemFact {
    OsVersion(String),
    OsBuild(String),
    Manufacturer(String),
    Model(String),
    SerialNumber(String),
    TpmVersion(String),
    Hostname(String),
    EntraDeviceId(String),
    TenantId(String),
    JoinMode(EspJoinMode),
    Elevation(EspElevationState),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspTimestamp {
    pub raw_text: String,
    pub original_offset: Option<String>,
    pub normalized_utc: Option<String>,
    pub kind: EspTimestampKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspEvidenceRef {
    pub evidence_id: String,
    pub source_artifact_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspRegistryProvenance {
    pub hive: String,
    pub key: String,
    pub value_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspEventProvenance {
    pub channel: String,
    pub event_id: u32,
    pub record_id: Option<u64>,
    pub named_data: Vec<EspNamedValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspEvidenceProvenance {
    pub source_kind: EspSourceKind,
    pub source_artifact_id: String,
    pub file_path: Option<String>,
    pub line_number: Option<u64>,
    pub record_number: Option<u64>,
    pub registry: Option<EspRegistryProvenance>,
    pub event: Option<EspEventProvenance>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspObservationContext {
    pub evidence_ref: EspEvidenceRef,
    pub provenance: EspEvidenceProvenance,
    pub source_timestamp: Option<EspTimestamp>,
    pub observed_at_utc: String,
    pub sensitivity: EspSensitivity,
    pub parse_state: EspParseState,
    pub access_state: EspSourceAccessState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspStatusDetail {
    pub raw: EspRawStatus,
    pub normalized: EspNormalizedStatus,
    pub display: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspStatus {
    pub raw: EspRawStatus,
    pub normalized: EspNormalizedStatus,
    pub display: String,
    pub detail: Option<EspStatusDetail>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspErrorCode {
    pub raw: String,
    pub decimal: Option<i64>,
    pub hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspNamedValue {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspElevationState {
    pub is_elevated: bool,
    pub restart_supported: bool,
    pub restricted_sources: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspIdentityEvidence {
    pub device_name: Option<String>,
    pub managed_device_id: Option<String>,
    pub entra_device_id: Option<String>,
    pub entdm_id: Option<EspClassifiedString>,
    pub tenant_id: Option<EspClassifiedString>,
    pub tenant_domain: Option<EspClassifiedString>,
    pub user_principal_name: Option<EspClassifiedString>,
    pub serial_number: Option<EspClassifiedString>,
    pub evidence: Vec<EspEvidenceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspOobeConfig {
    pub raw_mask: u64,
    pub skip_keyboard: bool,
    pub enable_patch_download: bool,
    pub skip_windows_upgrade_ux: bool,
    pub aad_tpm_required: bool,
    pub aad_device_authentication: bool,
    pub tpm_attestation: bool,
    pub skip_eula: bool,
    pub skip_oem_registration: bool,
    pub skip_express_settings: bool,
    pub disallow_admin: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspDevicePreparationEvidence {
    pub agent_download_timeout_seconds: Option<u64>,
    pub page_timeout_seconds: Option<u64>,
    pub allow_skip_on_failure: Option<bool>,
    pub allow_diagnostics: Option<bool>,
    pub script_ids: Vec<String>,
    pub evidence: Vec<EspEvidenceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspProfileEvidence {
    pub profile_name: Option<String>,
    pub deployment_profile_id: Option<String>,
    pub correlation_id: Option<String>,
    pub tenant_domain: Option<EspClassifiedString>,
    pub tenant_id: Option<EspClassifiedString>,
    pub oobe_config: Option<EspOobeConfig>,
    pub profile_download_time: Option<EspTimestamp>,
    pub join_mode: Option<EspJoinMode>,
    pub odj_applied: Option<bool>,
    pub skip_domain_connectivity_check: Option<bool>,
    pub device_preparation: Option<EspDevicePreparationEvidence>,
    pub evidence: Vec<EspEvidenceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspEnrollmentSettings {
    pub device_esp_enabled: Option<bool>,
    pub user_esp_enabled: Option<bool>,
    pub timeout_seconds: Option<u64>,
    pub blocking: Option<bool>,
    pub allow_reset: Option<bool>,
    pub allow_retry: Option<bool>,
    pub continue_anyway: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspEnrollmentEvidence {
    pub enrollment_id: String,
    pub provider_id: Option<String>,
    pub tenant_id: Option<EspClassifiedString>,
    pub user_principal_name: Option<EspClassifiedString>,
    pub entdm_id: Option<EspClassifiedString>,
    pub settings: EspEnrollmentSettings,
    pub evidence: Vec<EspEvidenceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspSession {
    pub session_id: String,
    pub kind: EspSessionKind,
    pub scope: EspScope,
    pub user_sid: Option<EspClassifiedString>,
    pub started_at: Option<EspTimestamp>,
    pub ended_at: Option<EspTimestamp>,
    pub phase: EspPhase,
    pub is_latest: bool,
    pub workload_ids: Vec<String>,
    pub evidence: Vec<EspEvidenceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspWorkloadTimestamps {
    pub first_observed: EspTimestamp,
    pub started: Option<EspTimestamp>,
    pub ended: Option<EspTimestamp>,
    pub last_updated: Option<EspTimestamp>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspWorkload {
    pub workload_id: String,
    pub session_id: String,
    pub kind: EspTrackedKind,
    pub scope: EspScope,
    pub raw_identifier: String,
    pub display_name: Option<String>,
    pub status: EspStatus,
    pub timestamps: EspWorkloadTimestamps,
    pub exit_code: Option<EspErrorCode>,
    pub enforcement_error_code: Option<EspErrorCode>,
    pub blocking: Option<bool>,
    pub evidence: Vec<EspEvidenceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspNodeCacheEntry {
    pub index: u64,
    pub node_uri: String,
    pub expected_value: Option<String>,
    pub sensitivity: EspSensitivity,
    pub evidence: Vec<EspEvidenceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspRegistrationEvent {
    pub event_id: u32,
    pub record_id: Option<u64>,
    pub status: EspStatus,
    pub message: String,
    pub timestamp: EspTimestamp,
    pub named_data: Vec<EspNamedValue>,
    pub evidence: Vec<EspEvidenceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspDeliveryOptimizationTransfer {
    pub transfer_id: String,
    pub kind: EspDeliveryOptimizationEventKind,
    pub content_id: Option<String>,
    pub app_id: Option<String>,
    pub timestamp: EspTimestamp,
    pub evidence: Vec<EspEvidenceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EspDeliveryOptimizationEvidence {
    pub download_http_bytes: u64,
    pub download_lan_bytes: u64,
    pub download_cache_host_bytes: u64,
    pub peer_share_percent: Option<f64>,
    pub connected_cache_share_percent: Option<f64>,
    pub transfers: Vec<EspDeliveryOptimizationTransfer>,
    pub evidence: Vec<EspEvidenceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspHardwareEvidence {
    pub os_version: Option<String>,
    pub os_build: Option<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub serial_number: Option<EspClassifiedString>,
    pub tpm_version: Option<String>,
    pub evidence: Vec<EspEvidenceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspTimelineEntry {
    pub entry_id: String,
    pub timestamp: EspTimestamp,
    pub kind: EspTimelineKind,
    pub title: String,
    pub detail: Option<String>,
    pub status: Option<EspStatus>,
    pub evidence: Vec<EspEvidenceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspDiagnosticFinding {
    pub finding_id: String,
    pub severity: EspFindingSeverity,
    pub confidence: EspFindingConfidence,
    pub title: String,
    pub summary: String,
    pub recommended_checks: Vec<String>,
    pub evidence: Vec<EspEvidenceRef>,
    pub coverage_gap_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspArtifactCoverage {
    pub artifact_id: String,
    pub family: String,
    pub status: EspArtifactStatus,
    pub detail: Option<String>,
    pub observed_at_utc: String,
    pub evidence: Vec<EspEvidenceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspRawEvidenceRecord {
    pub record_id: String,
    pub provenance: EspEvidenceProvenance,
    pub source_timestamp: Option<EspTimestamp>,
    pub observed_at_utc: String,
    pub raw_value: EspObservationValue,
    pub sensitivity: EspSensitivity,
    pub parse_state: EspParseState,
    pub access_state: EspSourceAccessState,
    pub evidence: Vec<EspEvidenceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspRegistryObservation {
    pub context: EspObservationContext,
    pub hive: String,
    pub key: String,
    pub value_name: String,
    pub value: EspObservationValue,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspJsonObservation {
    pub context: EspObservationContext,
    pub document_type: String,
    pub json_pointer: String,
    pub value: EspObservationValue,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspEventLogObservation {
    pub context: EspObservationContext,
    pub channel: String,
    pub event_id: u32,
    pub record_id: Option<u64>,
    pub named_data: Vec<EspNamedValue>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspImeObservation {
    pub context: EspObservationContext,
    pub component: Option<String>,
    pub message: String,
    pub app_id: Option<String>,
    pub status: Option<EspStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspDeploymentLogObservation {
    pub context: EspObservationContext,
    pub component: Option<String>,
    pub message: String,
    pub product_code: Option<String>,
    pub log_path: Option<String>,
    pub status: Option<EspStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspProcessObservation {
    pub context: EspObservationContext,
    pub pid: u32,
    pub process_start_time: EspTimestamp,
    pub parent_pid: Option<u32>,
    pub executable_name: String,
    pub sanitized_command_line: Option<String>,
    pub referenced_log_path: Option<String>,
    pub app_id: Option<String>,
    pub product_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspSystemObservation {
    pub context: EspObservationContext,
    pub fact: EspSystemFact,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspDeliveryOptimizationObservation {
    pub context: EspObservationContext,
    pub kind: EspDeliveryOptimizationEventKind,
    pub content_id: Option<String>,
    pub app_id: Option<String>,
    pub http_bytes: Option<u64>,
    pub lan_bytes: Option<u64>,
    pub cache_host_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspGraphObservation {
    pub context: EspObservationContext,
    pub section: EspGraphObservationSection,
    pub api_version: GraphApiVersion,
    pub record_id: String,
    pub display_name: Option<String>,
    pub status: Option<EspStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspInstallerCorrelation {
    pub correlation_id: String,
    pub workload_id: Option<String>,
    pub confidence: EspCorrelationConfidence,
    pub reason: String,
    pub candidate_workload_ids: Vec<String>,
    pub process_observations: Vec<EspProcessObservation>,
    pub evidence: Vec<EspEvidenceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EspDiagnosticsSnapshot {
    pub schema_version: u32,
    pub scenario: EspScenario,
    pub phase: EspPhase,
    pub generated_at_utc: String,
    pub elevation: EspElevationState,
    pub identity: EspIdentityEvidence,
    pub profile: Option<EspProfileEvidence>,
    pub enrollments: Vec<EspEnrollmentEvidence>,
    pub sessions: Vec<EspSession>,
    pub workloads: Vec<EspWorkload>,
    pub installer_correlations: Vec<EspInstallerCorrelation>,
    pub node_cache: Vec<EspNodeCacheEntry>,
    pub registration_events: Vec<EspRegistrationEvent>,
    pub delivery_optimization: Option<EspDeliveryOptimizationEvidence>,
    pub hardware: Option<EspHardwareEvidence>,
    pub activity: Vec<EspTimelineEntry>,
    pub findings: Vec<EspDiagnosticFinding>,
    pub coverage: Vec<EspArtifactCoverage>,
    pub raw_evidence: Vec<EspRawEvidenceRecord>,
    pub graph: Option<EspGraphOverlay>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GraphSectionError {
    pub code: String,
    pub message: String,
    pub request_id: Option<String>,
    pub blocked_by: Option<String>,
    pub retry_after_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GraphSection<T> {
    pub status: GraphSectionStatus,
    pub required_scope: Option<String>,
    pub api_version: GraphApiVersion,
    pub data: Option<T>,
    pub error: Option<GraphSectionError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspGraphManagedDevice {
    pub managed_device_id: String,
    pub entra_device_id: Option<String>,
    pub serial_number: Option<EspClassifiedString>,
    pub device_name: Option<String>,
    pub user_id: Option<String>,
    pub user_principal_name: Option<EspClassifiedString>,
    pub tenant_id: Option<EspClassifiedString>,
    pub evidence: Vec<EspEvidenceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspGraphDeviceMatch {
    pub selected: Option<EspGraphManagedDevice>,
    pub candidates: Vec<EspGraphManagedDevice>,
    pub match_basis: Option<String>,
    pub confidence: EspCorrelationConfidence,
    pub evidence: Vec<EspEvidenceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspGraphAutopilotIdentity {
    pub autopilot_device_id: String,
    pub entra_device_id: Option<String>,
    pub serial_number: Option<EspClassifiedString>,
    pub deployment_profile_id: Option<String>,
    pub group_tag: Option<String>,
    pub evidence: Vec<EspEvidenceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspGraphDeploymentProfile {
    pub profile_id: String,
    pub display_name: Option<String>,
    pub join_mode: Option<EspJoinMode>,
    pub selected_mobile_app_ids: Vec<String>,
    pub evidence: Vec<EspEvidenceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspGraphAssignment {
    pub assignment_id: String,
    pub target_id: Option<String>,
    pub filter_id: Option<String>,
    pub intent: EspGraphAssignmentIntent,
    pub target_kind: EspGraphTargetKind,
    pub targeting: EspGraphTargeting,
    pub evidence: Vec<EspEvidenceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspGraphPolicyStatusDetail {
    pub status_detail_id: String,
    pub related_object_id: Option<String>,
    pub display_name: Option<String>,
    pub kind: EspGraphPolicyStatusDetailKind,
    pub status: EspStatus,
    #[serde(default)]
    pub tracked_on_enrollment_status: Option<bool>,
    pub correlation_confidence: EspCorrelationConfidence,
    pub evidence: Vec<EspEvidenceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspGraphAutopilotEvent {
    pub event_id: String,
    pub managed_device_id: Option<String>,
    #[serde(default)]
    pub enrollment_configuration_id: Option<String>,
    pub event_time: Option<EspTimestamp>,
    pub deployment_state: EspStatus,
    pub policy_status_details: Vec<EspGraphPolicyStatusDetail>,
    pub evidence: Vec<EspEvidenceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspGraphEnrollmentConfiguration {
    pub configuration_id: String,
    pub display_name: Option<String>,
    #[serde(default)]
    pub show_installation_progress: Option<bool>,
    pub device_esp_enabled: Option<bool>,
    pub user_esp_enabled: Option<bool>,
    #[serde(default)]
    pub disable_user_status_tracking_after_first_user: Option<bool>,
    pub timeout_minutes: Option<u64>,
    pub selected_mobile_app_ids: Vec<String>,
    pub assignments: Vec<EspGraphAssignment>,
    pub evidence: Vec<EspEvidenceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspGraphAppRecord {
    pub app_id: String,
    pub display_name: Option<String>,
    pub tracked_on_enrollment_status: Option<bool>,
    pub status: Option<EspStatus>,
    pub intent_state: GraphSection<EspStatus>,
    pub assignments: Vec<EspGraphAssignment>,
    pub evidence: Vec<EspEvidenceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspGraphPolicyRecord {
    pub policy_id: String,
    pub display_name: Option<String>,
    pub kind: EspGraphPolicyKind,
    pub status: Option<EspStatus>,
    pub assignments: Vec<EspGraphAssignment>,
    pub evidence: Vec<EspEvidenceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspGraphScriptRecord {
    pub script_id: String,
    pub display_name: Option<String>,
    pub kind: EspGraphScriptKind,
    pub status: Option<EspStatus>,
    pub assignments: Vec<EspGraphAssignment>,
    pub evidence: Vec<EspEvidenceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EspGraphOverlay {
    pub request_id: String,
    pub requested_at_utc: String,
    pub device_match: GraphSection<EspGraphDeviceMatch>,
    pub autopilot_identity: GraphSection<EspGraphAutopilotIdentity>,
    pub deployment_profile: GraphSection<EspGraphDeploymentProfile>,
    pub intended_deployment_profile: GraphSection<EspGraphDeploymentProfile>,
    pub profile_assignments: GraphSection<Vec<EspGraphAssignment>>,
    pub autopilot_events: GraphSection<Vec<EspGraphAutopilotEvent>>,
    pub enrollment_configuration: GraphSection<EspGraphEnrollmentConfiguration>,
    pub apps: GraphSection<Vec<EspGraphAppRecord>>,
    pub policies: GraphSection<Vec<EspGraphPolicyRecord>>,
    pub scripts: GraphSection<Vec<EspGraphScriptRecord>>,
}
