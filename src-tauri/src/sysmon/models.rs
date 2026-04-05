use serde::{Deserialize, Serialize};

/// Sysmon event type mapped from EventID (1–29, 255).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SysmonEventType {
    ProcessCreate,
    FileCreateTime,
    NetworkConnect,
    ServiceStateChange,
    ProcessTerminate,
    DriverLoad,
    ImageLoad,
    CreateRemoteThread,
    RawAccessRead,
    ProcessAccess,
    FileCreate,
    RegistryAddOrDelete,
    RegistryValueSet,
    RegistryRename,
    FileCreateStreamHash,
    ConfigChange,
    PipeCreated,
    PipeConnected,
    WmiFilter,
    WmiConsumer,
    WmiBinding,
    DnsQuery,
    FileDelete,
    ClipboardChange,
    ProcessTampering,
    FileDeleteDetected,
    FileBlockExecutable,
    FileBlockShredding,
    FileExecutableDetected,
    Error,
    Unknown,
}

impl SysmonEventType {
    pub fn from_event_id(id: u32) -> Self {
        match id {
            1 => Self::ProcessCreate,
            2 => Self::FileCreateTime,
            3 => Self::NetworkConnect,
            4 => Self::ServiceStateChange,
            5 => Self::ProcessTerminate,
            6 => Self::DriverLoad,
            7 => Self::ImageLoad,
            8 => Self::CreateRemoteThread,
            9 => Self::RawAccessRead,
            10 => Self::ProcessAccess,
            11 => Self::FileCreate,
            12 => Self::RegistryAddOrDelete,
            13 => Self::RegistryValueSet,
            14 => Self::RegistryRename,
            15 => Self::FileCreateStreamHash,
            16 => Self::ConfigChange,
            17 => Self::PipeCreated,
            18 => Self::PipeConnected,
            19 => Self::WmiFilter,
            20 => Self::WmiConsumer,
            21 => Self::WmiBinding,
            22 => Self::DnsQuery,
            23 => Self::FileDelete,
            24 => Self::ClipboardChange,
            25 => Self::ProcessTampering,
            26 => Self::FileDeleteDetected,
            27 => Self::FileBlockExecutable,
            28 => Self::FileBlockShredding,
            29 => Self::FileExecutableDetected,
            255 => Self::Error,
            _ => Self::Unknown,
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            Self::ProcessCreate => "Process Create",
            Self::FileCreateTime => "File Create Time",
            Self::NetworkConnect => "Network Connect",
            Self::ServiceStateChange => "Service State Change",
            Self::ProcessTerminate => "Process Terminate",
            Self::DriverLoad => "Driver Load",
            Self::ImageLoad => "Image Load",
            Self::CreateRemoteThread => "Create Remote Thread",
            Self::RawAccessRead => "Raw Access Read",
            Self::ProcessAccess => "Process Access",
            Self::FileCreate => "File Create",
            Self::RegistryAddOrDelete => "Registry Add/Delete",
            Self::RegistryValueSet => "Registry Value Set",
            Self::RegistryRename => "Registry Rename",
            Self::FileCreateStreamHash => "File Stream Hash",
            Self::ConfigChange => "Config Change",
            Self::PipeCreated => "Pipe Created",
            Self::PipeConnected => "Pipe Connected",
            Self::WmiFilter => "WMI Filter",
            Self::WmiConsumer => "WMI Consumer",
            Self::WmiBinding => "WMI Binding",
            Self::DnsQuery => "DNS Query",
            Self::FileDelete => "File Delete (Archived)",
            Self::ClipboardChange => "Clipboard Change",
            Self::ProcessTampering => "Process Tampering",
            Self::FileDeleteDetected => "File Delete Detected",
            Self::FileBlockExecutable => "File Block Executable",
            Self::FileBlockShredding => "File Block Shredding",
            Self::FileExecutableDetected => "File Executable Detected",
            Self::Error => "Sysmon Error",
            Self::Unknown => "Unknown",
        }
    }
}

/// Severity derived from the Sysmon event type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SysmonSeverity {
    Info,
    Warning,
    Error,
}

/// A single parsed Sysmon event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SysmonEvent {
    /// Sequential ID for stable row identity.
    pub id: u64,
    /// Sysmon EventID (1–29, 255).
    pub event_id: u32,
    /// Typed event category.
    pub event_type: SysmonEventType,
    /// Display name for the event type.
    pub event_type_display: String,
    /// Severity level.
    pub severity: SysmonSeverity,
    /// ISO 8601 UTC timestamp from System.TimeCreated.
    pub timestamp: String,
    /// Unix timestamp in milliseconds for sorting.
    pub timestamp_ms: Option<i64>,
    /// Computer name from System.Computer.
    pub computer: Option<String>,
    /// EventRecordID from the EVTX record.
    pub record_id: u64,

    // --- Common Sysmon fields (populated per event type) ---

    /// RuleName from configuration match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_name: Option<String>,
    /// UtcTime from EventData (millisecond precision).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub utc_time: Option<String>,
    /// ProcessGuid — globally unique process identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_guid: Option<String>,
    /// ProcessId from EventData.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_id: Option<u32>,
    /// Image path (executable) for the process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// Command line used to start the process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    /// User account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Hashes (e.g. "SHA256=abc,MD5=def").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hashes: Option<String>,
    /// Parent image path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_image: Option<String>,
    /// Parent command line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_command_line: Option<String>,
    /// Parent ProcessId.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_process_id: Option<u32>,

    // --- File events ---

    /// Target file path (FileCreate, FileDelete, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_filename: Option<String>,

    // --- Network events ---

    /// Protocol (tcp/udp).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// Source IP address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
    /// Source port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_port: Option<u16>,
    /// Destination IP address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_ip: Option<String>,
    /// Destination port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<u16>,
    /// Destination hostname.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_hostname: Option<String>,

    // --- Registry events ---

    /// Registry target object path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_object: Option<String>,
    /// Registry value details.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,

    // --- DNS events ---

    /// DNS query name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_name: Option<String>,
    /// DNS query results (semicolon-delimited IPs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_results: Option<String>,

    // --- Process access ---

    /// Source image for ProcessAccess.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_image: Option<String>,
    /// Target image for ProcessAccess.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_image: Option<String>,
    /// Granted access mask.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub granted_access: Option<String>,

    /// Human-readable message built from key fields.
    pub message: String,

    /// Source .evtx file path.
    pub source_file: String,
}

/// Per-event-type count for the summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SysmonEventTypeCount {
    pub event_id: u32,
    pub event_type: SysmonEventType,
    pub display_name: String,
    pub count: u64,
}

/// Summary statistics for a Sysmon analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SysmonSummary {
    pub total_events: u64,
    pub event_type_counts: Vec<SysmonEventTypeCount>,
    pub unique_processes: u64,
    pub unique_computers: u64,
    pub earliest_timestamp: Option<String>,
    pub latest_timestamp: Option<String>,
    pub source_files: Vec<String>,
    pub parse_errors: u64,
}

/// Extracted Sysmon configuration metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SysmonConfig {
    /// Schema version (e.g. "4.82").
    pub schema_version: Option<String>,
    /// Hash algorithms configured (e.g. "SHA256,MD5").
    pub hash_algorithms: Option<String>,
    /// Whether the configuration was found.
    pub found: bool,
    /// Timestamp of the most recent config change event (EventID 16).
    pub last_config_change: Option<String>,
    /// Raw configuration XML if available from ConfigChange events.
    pub configuration_xml: Option<String>,
    /// Sysmon binary version if available from service state events (EventID 4).
    pub sysmon_version: Option<String>,
    /// Which event types are actively generating events (observed in data).
    pub active_event_types: Vec<SysmonEventTypeCount>,
}

/// A time-bucketed event count for timeline charts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimeBucket {
    /// ISO 8601 timestamp for the bucket start.
    pub timestamp: String,
    /// Unix ms timestamp for the bucket start.
    pub timestamp_ms: i64,
    /// Number of events in this bucket.
    pub count: u64,
}

/// A named item with a count, used for top-N rankings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RankedItem {
    pub name: String,
    pub count: u64,
}

/// Aggregated security alert statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecuritySummary {
    pub total_warnings: u64,
    pub total_errors: u64,
    pub events_by_type: Vec<RankedItem>,
}

/// Pre-computed dashboard aggregations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SysmonDashboardData {
    pub timeline_minute: Vec<TimeBucket>,
    pub timeline_hourly: Vec<TimeBucket>,
    pub timeline_daily: Vec<TimeBucket>,
    pub top_processes: Vec<RankedItem>,
    pub top_destinations: Vec<RankedItem>,
    pub top_ports: Vec<RankedItem>,
    pub top_dns_queries: Vec<RankedItem>,
    pub security_events: SecuritySummary,
    pub top_target_files: Vec<RankedItem>,
    pub top_registry_keys: Vec<RankedItem>,
}

/// Top-level result returned from the Sysmon analysis command.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SysmonAnalysisResult {
    /// All parsed Sysmon events, sorted by timestamp.
    pub events: Vec<SysmonEvent>,
    /// Summary statistics.
    pub summary: SysmonSummary,
    /// Extracted Sysmon configuration metadata.
    pub config: SysmonConfig,
    /// Pre-computed dashboard aggregations.
    pub dashboard: SysmonDashboardData,
    /// Source path that was analyzed.
    pub source_path: String,
}
