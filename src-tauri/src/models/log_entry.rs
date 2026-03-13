use serde::{Deserialize, Serialize};

/// Log entry severity level.
/// Maps directly to CMTrace's type field: 1=Info, 2=Warning, 3=Error
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Warning,
    Error,
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
}

/// High-level parser selection resolved by the backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ParserKind {
    Ccm,
    Simple,
    Timestamped,
    Plain,
    Panther,
    Cbs,
    Dism,
    ReportingEvents,
}

/// Concrete parser implementation currently used by the backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ParserImplementation {
    Ccm,
    Simple,
    GenericTimestamped,
    ReportingEvents,
    PlainText,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
