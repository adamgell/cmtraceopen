use serde::{Deserialize, Serialize};

/// Log entry severity level.
/// Maps directly to CMTrace's type field: 1=Info, 2=Warning, 3=Error
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Warning,
    Error,
}

/// Distinguishes the role of a CmtLog entry: regular log line, section divider, loop
/// iteration marker, or file header.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub enum EntryKind {
    #[default]
    Log,
    Section,
    Iteration,
    Header,
}

/// Which log format was detected/used to parse this entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogFormat {
    /// CCM/SCCM format: <![LOG[msg]LOG]!><time="..." date="..." ...>
    Ccm,
    /// Simple/legacy format: message$$<Component><timestamp><thread>
    Simple,
    /// Plain text (no structured format detected)
    Plain,
    /// Generic timestamped format (ISO 8601, slash-dates, syslog, time-only)
    Timestamped,
    /// Windows DNS Server debug log (dns.log)
    DnsDebug,
    /// Windows DNS Server analytical/audit EVTX log
    DnsAudit,
    /// CCM-style text lines with extended attributes (.cmtlog)
    CmtLog,
}

/// High-level parser selection resolved by the backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ParserKind {
    Ccm,
    Simple,
    Timestamped,
    Plain,
    IisW3c,
    Panther,
    Cbs,
    Dism,
    ReportingEvents,
    Msi,
    PsadtLegacy,
    IntuneMacOs,
    Dhcp,
    Burn,
    PatchMyPcDetection,
    Registry,
    SecureBootLog,
    DnsDebug,
    DnsAudit,
    CmtLog,
}

/// Concrete parser implementation currently used by the backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ParserImplementation {
    Ccm,
    Simple,
    GenericTimestamped,
    IisW3c,
    ReportingEvents,
    PlainText,
    Msi,
    PsadtLegacy,
    IntuneMacOs,
    Dhcp,
    Burn,
    PatchMyPcDetection,
    Registry,
    SecureBootLog,
    DnsDebug,
    DnsAudit,
    CmtLog,
}

/// How the backend arrived at the parser selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ParserProvenance {
    Dedicated,
    Heuristic,
    Fallback,
}

/// Approximate structure quality of the current parse path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ParseQuality {
    Structured,
    SemiStructured,
    TextFallback,
}

/// How input is framed before it is handed to a parser implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RecordFraming {
    PhysicalLine,
    LogicalRecord,
}

/// Slash-date interpretation used by timestamp-aware parsers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DateFieldOrder {
    MonthFirst,
    DayFirst,
}

/// Optional parser specialization layered on top of the base parser kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ParserSpecialization {
    Ime,
}

/// Rich parser selection metadata returned to the frontend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ParserSelectionInfo {
    pub parser: ParserKind,
    pub implementation: ParserImplementation,
    pub provenance: ParserProvenance,
    pub parse_quality: ParseQuality,
    pub record_framing: RecordFraming,
    pub date_order: Option<DateFieldOrder>,
    pub specialization: Option<ParserSpecialization>,
}

/// A single parsed log entry.
/// Field names use camelCase for direct JSON serialization to TypeScript.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry {
    /// Sequential ID for stable row identity
    pub id: u64,
    /// 1-based line number in the source file
    pub line_number: u32,
    /// The log message text
    pub message: String,
    /// Component name (up to 100 chars in CCM format)
    pub component: Option<String>,
    /// Unix timestamp in milliseconds (for sorting/merging)
    pub timestamp: Option<i64>,
    /// Formatted display string: "MM-dd-yyyy HH:mm:ss.fff"
    pub timestamp_display: Option<String>,
    /// Severity level
    pub severity: Severity,
    /// Thread ID as a number
    pub thread: Option<u32>,
    /// Thread display string: "N (0xNNNN)"
    pub thread_display: Option<String>,
    /// Source file attribute (CCM format only)
    pub source_file: Option<String>,
    /// Which format was used to parse this entry
    pub format: LogFormat,
    /// Path to the file this entry came from
    pub file_path: String,
    /// Timezone offset in minutes
    pub timezone_offset: Option<i32>,
    /// Spans of recognized error codes within the message text
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub error_code_spans: Vec<crate::error_db::lookup::ErrorCodeSpan>,
    /// IP address (DHCP logs)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    /// Host/device name (DHCP logs)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_name: Option<String>,
    /// MAC address (DHCP logs)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac_address: Option<String>,
    /// Primary result/error code extracted from the message (Panther logs)
    /// e.g. from "Result = 0x80070490", "Error: 0x80070002", "Status: 0xC000000F"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_code: Option<String>,
    /// GetLastError code from "[gle=0x...]" (Panther logs)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gle_code: Option<String>,
    /// Windows setup phase name (Panther logs)
    /// e.g. "SetupPhaseInstall", "SetupPhasePrepare", "SetupPhaseFinalize"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup_phase: Option<String>,
    /// Setup operation being executed or completed (Panther logs)
    /// e.g. "Apply Drivers", "Mount WIM file", "Set Language Settings"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_name: Option<String>,
    /// HTTP method (IIS W3C logs)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_method: Option<String>,
    /// URI stem/path (IIS W3C logs)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri_stem: Option<String>,
    /// URI query string without the leading '?' (IIS W3C logs)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri_query: Option<String>,
    /// HTTP response status code (IIS W3C logs)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    /// HTTP response sub-status code (IIS W3C logs)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub_status: Option<u16>,
    /// Request duration in milliseconds (IIS W3C logs)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_taken_ms: Option<u64>,
    /// Client/source IP address (IIS W3C logs)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,
    /// Server/listener IP address (IIS W3C logs)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_ip: Option<String>,
    /// HTTP user agent (IIS W3C logs)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    /// Server/listener port (IIS W3C logs)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_port: Option<u16>,
    /// Authenticated username (IIS W3C logs)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Win32 status code (IIS W3C logs)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub win32_status: Option<u32>,
    /// DNS query name, decoded from wire-format (DNS logs)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_name: Option<String>,
    /// DNS query type name: A, AAAA, SRV, etc. (DNS logs)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_type: Option<String>,
    /// DNS response code: NOERROR, NXDOMAIN, etc. (DNS logs)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_code: Option<String>,
    /// Packet direction: Snd or Rcv (DNS debug log)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_direction: Option<String>,
    /// Transport protocol: UDP or TCP (DNS debug log)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_protocol: Option<String>,
    /// Remote IP address, optionally with port (DNS logs)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
    /// DNS header flags as hex string (DNS debug log)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_flags: Option<String>,
    /// DNS event ID for EVTX-sourced entries (DNS audit)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_event_id: Option<u32>,
    /// DNS zone name (DNS audit)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone_name: Option<String>,
    // CmtLog extended fields
    /// Entry role — distinguishes sections, iterations, and headers from normal log lines
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_kind: Option<EntryKind>,
    /// WhatIf/simulation flag (CmtLog)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub whatif: Option<bool>,
    /// Section label for Section entries (CmtLog)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub section_name: Option<String>,
    /// Optional color hint associated with a section (CmtLog)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub section_color: Option<String>,
    /// Iteration identifier for Iteration entries (CmtLog)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iteration: Option<String>,
    /// Arbitrary tag list attached to a log entry (CmtLog)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

/// Result of parsing a complete log file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ParseResult {
    pub entries: Vec<LogEntry>,
    pub format_detected: LogFormat,
    pub parser_selection: ParserSelectionInfo,
    pub total_lines: u32,
    pub parse_errors: u32,
    pub file_path: String,
    pub file_size: u64,
    /// Byte offset where parsing ended — used as the starting point for tailing
    pub byte_offset: u64,
}

/// Per-file parse metadata for an aggregated folder open.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AggregateParsedFileResult {
    pub file_path: String,
    pub total_lines: u32,
    pub parse_errors: u32,
    pub file_size: u64,
    pub byte_offset: u64,
}

/// Result of parsing every file in a folder into one combined view.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AggregateParseResult {
    pub entries: Vec<LogEntry>,
    pub total_lines: u32,
    pub parse_errors: u32,
    pub folder_path: String,
    pub files: Vec<AggregateParsedFileResult>,
}
