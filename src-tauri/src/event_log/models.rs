use serde::{Deserialize, Serialize};

/// Identifies which part of an EVTX source could not be recovered.
///
/// A gap is not an empty result and is not evidence that the event did not occur. The parser
/// reports the readable records it can recover and attaches one of these kinds to every rejected
/// file, chunk, record, or rendered XML value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EvtxCoverageGapKind {
    Unsupported,
    AccessDenied,
    Missing,
    InvalidPattern,
    LimitReached,
    Empty,
    File,
    Chunk,
    Record,
    Xml,
    Limit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvtxCoverageGap {
    pub source: String,
    pub kind: EvtxCoverageGapKind,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_record_id: Option<u64>,
}

impl EvtxCoverageGap {
    pub fn new(source: impl Into<String>, kind: EvtxCoverageGapKind, reason: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            kind,
            reason: reason.into(),
            chunk_id: None,
            event_record_id: None,
        }
    }
}
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum U64Transport {
    Number(u64),
    Text(String),
}

fn deserialize_u64_transport<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match U64Transport::deserialize(deserializer)? {
        U64Transport::Number(value) => Ok(value),
        U64Transport::Text(value) => value.parse().map_err(serde::de::Error::custom),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvtxRecord {
    pub id: u64,
    #[serde(deserialize_with = "deserialize_u64_transport")]
    pub event_record_id: u64,
    /// Lossless decimal EventRecordID for IPC consumers that cannot represent all u64 values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_record_id_text: Option<String>,
    pub timestamp: String,
    pub timestamp_epoch: i64,
    pub provider: String,
    pub channel: String,
    pub event_id: u32,
    pub level: EvtxLevel,
    pub computer: String,
    pub message: String,
    #[serde(default)]
    pub event_data: Vec<EvtxField>,
    /// The provider's own XML.
    ///
    /// Defaulted so a caller can omit it. The export command receives records over IPC, and this
    /// field dominates the payload: only the XML and JSON formats read it, so sending it for a
    /// delimited export serialized every record's XML across the bridge for nothing.
    #[serde(default)]
    pub raw_xml: String,
    pub source_label: String,
    /// Provider-defined task grouping, when the event declares one.
    #[serde(default)]
    pub task: Option<u32>,
    /// Operation within the task, when the event declares one.
    #[serde(default)]
    pub opcode: Option<u32>,
    /// Emitting process, from `Execution/@ProcessID`.
    #[serde(default)]
    pub process_id: Option<u32>,
    /// Emitting thread, from `Execution/@ThreadID`.
    #[serde(default)]
    pub thread_id: Option<u32>,
    /// Security identifier from `Security/@UserID`.
    ///
    /// Kept as the raw SID. Resolving it to an account name needs `LookupAccountSidW` and a cache,
    /// and is only meaningful on a machine that knows the domain, so it is a separate concern.
    #[serde(default)]
    pub user_sid: Option<String>,
    /// Keyword bitmask as written by the provider, for example `0x8020000000000000`.
    #[serde(default)]
    pub keywords: Option<String>,
    /// Columns produced by an EvtxECmd map, empty when no map covers this event type.
    #[serde(default)]
    pub mapped: Vec<super::maps::MappedColumn>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvtxField {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvtxLevel {
    Critical,
    Error,
    Warning,
    Information,
    Verbose,
}

impl EvtxLevel {
    pub fn from_level_value(level: u8) -> Self {
        match level {
            1 => Self::Critical,
            2 => Self::Error,
            3 => Self::Warning,
            5 => Self::Verbose,
            _ => Self::Information,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvtxChannelInfo {
    pub name: String,
    pub event_count: u64,
    pub source_type: ChannelSourceType,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ChannelSourceType {
    Live,
    Remote { machine: String },
    File { path: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvtxParseResult {
    pub records: Vec<EvtxRecord>,
    pub channels: Vec<EvtxChannelInfo>,
    pub total_records: u64,
    pub parse_errors: u32,
    pub error_messages: Vec<String>,
    /// Every rejected source region, including parser errors that still allowed other records to
    /// be recovered. This is separate from `parse_errors` because an empty source and a reader
    /// limit are coverage gaps without being rejected records.
    #[serde(default)]
    pub coverage_gaps: Vec<EvtxCoverageGap>,
    #[serde(default)]
    pub coverage: Vec<super::parser::SourceCoverage>,
}

/// A provider that could not be captured while scanning the Windows publisher registry.
///
/// Capture continues to the next publisher, but the aggregate operation remains unsuccessful so
/// callers cannot mistake a partial database for complete coverage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProviderCaptureFailure {
    pub provider_name: String,
    pub error: String,
}
/// Delivery path used by a live channel tail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EvtxLiveMode {
    Subscription,
    Polling,
    Unsupported,
}

/// State returned when a live tail is started or stopped.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvtxTailStatus {
    pub request_id: String,
    pub channel: String,
    pub mode: EvtxLiveMode,
    pub active: bool,
    pub next_sequence: u64,
    pub coverage_gaps: Vec<String>,
}

/// Structured result for a destructive channel clear request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "status")]
pub enum EvtxClearStatus {
    Cleared,
    Cancelled,
    Denied { detail: String },
    Unavailable { detail: String },
    Empty,
    Unsupported { detail: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvtxClearResult {
    pub channel: String,
    pub result: EvtxClearStatus,
}
/// A normalized batch emitted by an active live tail.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvtxTailBatch {
    pub request_id: String,
    pub channel: String,
    pub sequence: u64,
    pub mode: EvtxLiveMode,
    pub records: Vec<EvtxRecord>,
    pub coverage_gaps: Vec<String>,
}
