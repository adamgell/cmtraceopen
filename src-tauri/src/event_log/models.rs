use serde::{Deserialize, Serialize};

/// Identifies which part of an EVTX source could not be recovered.
///
/// A gap is not an empty result and is not evidence that the event did not occur. The parser
/// reports the readable records it can recover and attaches one of these kinds to every rejected
/// file, chunk, record, or rendered XML value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EvtxCoverageGapKind {
    Unsupported,
    AccessDenied,
    Missing,
    InvalidPattern,
    LimitReached,
    Empty,
    File,
    /// A rejected, truncated, or zero-filled EVTX chunk. `chunk_id` identifies its region.
    Chunk,
    Record,
    Xml,
    Provider,
    Limit,
}

/// Native Windows API stage that could not produce a provider message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProviderMessageStage {
    OpenPublisherMetadata,
    FormatMessage,
}

impl ProviderMessageStage {
    pub fn api_name(self) -> &'static str {
        match self {
            Self::OpenPublisherMetadata => "EvtOpenPublisherMetadata",
            Self::FormatMessage => "EvtFormatMessage",
        }
    }
}

/// Typed native context for a provider-description coverage gap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderMessageCoverage {
    pub provider: String,
    pub stage: ProviderMessageStage,
    pub error_code: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum EvtxOriginKind {
    #[default]
    Event,
    Log,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_record_id_text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_message: Option<Box<ProviderMessageCoverage>>,
}

impl EvtxCoverageGap {
    pub fn new(
        source: impl Into<String>,
        kind: EvtxCoverageGapKind,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            source: source.into(),
            kind,
            reason: reason.into(),
            chunk_id: None,
            event_record_id: None,
            event_record_id_text: None,
            provider_message: None,
        }
    }

    pub fn set_event_record_id(&mut self, event_record_id: u64) {
        self.event_record_id = Some(event_record_id);
        self.event_record_id_text = Some(event_record_id.to_string());
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
    #[serde(default)]
    pub origin_kind: EvtxOriginKind,
    /// Provider-defined task grouping, when the event declares one.
    #[serde(default)]
    pub task: Option<u32>,
    /// Operation within the task, when the event declares one.
    #[serde(default)]
    pub opcode: Option<u32>,
    /// Emitting process, from `Execution/@ProcessID`.
    #[serde(default)]
    pub process_id: Option<u32>,
    /// Provider-declared correlation ActivityID from `System/Correlation`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activity_id: Option<String>,
    /// Provider-declared related ActivityID from `System/Correlation`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub related_activity_id: Option<String>,
    /// Session identifier promoted from explicit event XML/data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Device identifier promoted from explicit event XML/data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    /// User identifier promoted from explicit event XML/data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// Process start evidence from explicit event XML/data; paired with `process_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_start_time: Option<String>,
    /// Emitting thread, from `Execution/@ThreadID`.
    #[serde(default)]
    pub thread_id: Option<u32>,
    /// Security identifier from `Security/@UserID`.
    #[serde(default)]
    pub user_sid: Option<String>,
    /// Keyword bitmask as written by the provider.
    #[serde(default)]
    pub keywords: Option<String>,
    /// Columns produced by an EvtxECmd map, empty when no map covers this event type.
    #[serde(default)]
    pub mapped: Vec<super::maps::MappedColumn>,
}

pub(crate) const MAX_SAFE_EVENT_RECORD_ID: u64 = 9_007_199_254_740_991;

pub(crate) fn canonical_event_record_id_text(record: &EvtxRecord) -> String {
    record
        .event_record_id_text
        .as_deref()
        .filter(|value| {
            !value.is_empty()
                && value.bytes().all(|byte| byte.is_ascii_digit())
                && value.parse::<u64>().is_ok()
        })
        .filter(|value| {
            record.event_record_id > MAX_SAFE_EVENT_RECORD_ID
                || value.parse::<u64>().ok() == Some(record.event_record_id)
        })
        .map(str::to_owned)
        .unwrap_or_else(|| record.event_record_id.to_string())
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

/// What the Event Log service reports about a channel's configuration.
///
/// A channel that is switched off holds no events and the service refuses to read it, so asking
/// anyway produced a coverage-gap line per disabled channel: the machine those lines came from
/// carries 85 of them, and each line described the machine's configuration rather than anything
/// missing from the view.
///
/// `Unknown` is not a third answer to that question but the absence of one: the configuration could
/// not be opened or read, the channel has no configuration the service will answer for, or the
/// answer came from a path that never asked. It must never be read as `Disabled`, because that is
/// the state that removes a channel from the selection and from the initial load, and a channel
/// whose configuration could not be read is exactly the channel whose events must not be dropped
/// from the view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ChannelEnabledState {
    /// The service confirmed the channel is recording.
    Enabled,
    /// The service confirmed the channel is switched off.
    Disabled,
    /// The service did not report the channel's configuration.
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvtxChannelInfo {
    pub name: String,
    pub event_count: u64,
    pub source_type: ChannelSourceType,
    /// Whether the service reports the channel as recording.
    ///
    /// Defaulted to `Unknown`, never to `Enabled`: a payload that omits this field -- an older
    /// capture, or an enumeration that could not probe -- must not claim the channel is recording.
    /// The behaviour of the two is deliberately identical (listed, selected, acquired, because a
    /// probe that failed must never hide a channel that may be readable); what differs is the claim
    /// made about the machine, which is the whole reason the three states are kept apart.
    #[serde(default)]
    pub enabled_state: ChannelEnabledState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ChannelSourceType {
    Live,
    Remote { machine: String },
    File { path: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EvtxArchiveMemberKind {
    Evtx,
    Text,
    Registry,
    Binary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EvtxArchiveMemberOutcome {
    Parsed,
    Unsupported,
    Malformed,
    Duplicate,
    Limit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvtxArchiveMember {
    pub path: String,
    pub kind: EvtxArchiveMemberKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    pub outcome: EvtxArchiveMemberOutcome,
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
    #[serde(default)]
    pub archive_members: Vec<EvtxArchiveMember>,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// One enumerated channel entry as it arrives over IPC, with the state its producer wrote.
    ///
    /// Spelled as JSON text rather than built from the struct, so the test states the contract the
    /// frontend actually receives -- including the case where a payload carries no state at all.
    fn channel_payload(enabled_state: Option<&str>) -> String {
        match enabled_state {
            Some(state) => format!(
                r#"{{"name":"C","eventCount":0,"sourceType":"live","enabledState":"{state}"}}"#
            ),
            None => r#"{"name":"C","eventCount":0,"sourceType":"live"}"#.to_string(),
        }
    }

    fn parse(payload: &str) -> EvtxChannelInfo {
        serde_json::from_str(payload)
            .unwrap_or_else(|error| panic!("{payload} should parse as a channel entry: {error}"))
    }

    #[test]
    fn a_payload_that_omits_the_enabled_state_is_unknown_rather_than_enabled() {
        // `#[serde(default)]` on the field reads an omitted state through `Default`, and the enum's
        // `#[default]` is `Unknown`. This is the Rust half of the fail-open rule: a payload written
        // before the field existed, or an enumeration that never asked, must not claim the channel
        // is recording. Only `Unknown` can make that claim safely -- `Enabled` selects and acquires
        // identically while asserting something unproven about the machine.
        let observed = parse(&channel_payload(None));

        println!("{} -> {:?}", channel_payload(None), observed.enabled_state);
        assert_eq!(observed.enabled_state, ChannelEnabledState::Unknown);
        assert_eq!(ChannelEnabledState::default(), ChannelEnabledState::Unknown);

        // An absent state is written back as `unknown` on the next reply, never omitted and never
        // `enabled`: the field is part of the payload the frontend reads.
        let written = serde_json::to_string(&observed).expect("serializes");
        assert!(
            written.contains(r#""enabledState":"unknown""#),
            "an absent state is written as unknown: {written}"
        );
    }

    #[test]
    fn the_three_states_round_trip_through_their_wire_values() {
        for (wire, expected) in [
            ("enabled", ChannelEnabledState::Enabled),
            ("disabled", ChannelEnabledState::Disabled),
            ("unknown", ChannelEnabledState::Unknown),
        ] {
            let payload = channel_payload(Some(wire));
            let observed = parse(&payload);

            println!("{payload} -> {:?}", observed.enabled_state);
            assert_eq!(observed.enabled_state, expected, "{payload}");

            let written = serde_json::to_string(&observed).expect("serializes");
            assert!(
                written.contains(&format!(r#""enabledState":"{wire}""#)),
                "{wire} is written back as itself: {written}"
            );
            assert_eq!(parse(&written).enabled_state, expected);
        }
    }
}
