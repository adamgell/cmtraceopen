//! Named, ordered Windows Event Log acquisition for ESP diagnostics.

use std::collections::HashMap;
use std::path::PathBuf;

use cmtraceopen_parser::esp::{
    normalize_timestamp, EspEventLogObservation, EspEventProvenance, EspEvidenceProvenance,
    EspEvidenceRef, EspNamedValue, EspObservationContext, EspParseState, EspSensitivity,
    EspSourceAccessState, EspSourceKind,
};
use serde::{Deserialize, Serialize};

use crate::intune::evtx_parser::{parse_esp_evtx_file, EventLogProperty, ParsedEspEventRecord};

pub const REQUIRED_EVENT_IDS: &[u32] = &[
    72, 100, 101, 107, 109, 110, 111, 304, 306, 1905, 1906, 1920, 1922, 1924,
];
pub const ESP_EVENT_CHANNELS: &[&str] = &[
    "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin",
    "Microsoft-Windows-User Device Registration/Admin",
];
pub const MAX_ESP_EVENT_RECORDS_PER_CHANNEL: usize = 2_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventSourceError {
    Missing,
    PermissionDenied,
    Failed(String),
    Unsupported,
}

pub trait EventLogProvider {
    fn read_channel(
        &self,
        channel: &str,
        record_limit: usize,
    ) -> Result<Vec<ParsedEspEventRecord>, EventSourceError>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EventChannelEvidence {
    pub channel: String,
    pub access_state: EspSourceAccessState,
    pub record_count: usize,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct EventDeterministicFields {
    pub state: Option<String>,
    pub product_code: Option<String>,
    pub app_id: Option<String>,
    pub policy_id: Option<String>,
    pub result_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EventEvidenceObservation {
    pub observation: EspEventLogObservation,
    pub fields: EventDeterministicFields,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct EventEvidence {
    pub channels: Vec<EventChannelEvidence>,
    pub observations: Vec<EventEvidenceObservation>,
}

pub fn collect_event_evidence(
    provider: &impl EventLogProvider,
    observed_at_utc: &str,
) -> EventEvidence {
    let mut evidence = EventEvidence::default();

    for (channel_index, channel) in ESP_EVENT_CHANNELS.iter().enumerate() {
        match provider.read_channel(channel, MAX_ESP_EVENT_RECORDS_PER_CHANNEL) {
            Ok(records) => {
                let record_count = records.len();
                evidence.channels.push(EventChannelEvidence {
                    channel: (*channel).to_string(),
                    access_state: EspSourceAccessState::Available,
                    record_count,
                    detail: None,
                });
                for (record_index, record) in records
                    .into_iter()
                    .take(MAX_ESP_EVENT_RECORDS_PER_CHANNEL)
                    .enumerate()
                {
                    if REQUIRED_EVENT_IDS.binary_search(&record.event_id).is_err() {
                        continue;
                    }
                    evidence.observations.push(normalize_record(
                        record,
                        channel_index,
                        record_index,
                        observed_at_utc,
                    ));
                }
            }
            Err(error) => {
                let (access_state, detail) = access_state_for_error(error);
                evidence.channels.push(EventChannelEvidence {
                    channel: (*channel).to_string(),
                    access_state,
                    record_count: 0,
                    detail,
                });
            }
        }
    }

    evidence
}

pub fn collect_captured_evtx_files(
    paths: &[PathBuf],
    observed_at_utc: &str,
) -> Result<EventEvidence, EventSourceError> {
    let mut records_by_channel = HashMap::<String, Vec<ParsedEspEventRecord>>::new();
    for path in paths {
        let records = parse_esp_evtx_file(path).map_err(EventSourceError::Failed)?;
        for record in records {
            records_by_channel
                .entry(record.channel.clone())
                .or_default()
                .push(record);
        }
    }
    let provider = CapturedEventLogProvider { records_by_channel };
    Ok(collect_event_evidence(&provider, observed_at_utc))
}

fn normalize_record(
    record: ParsedEspEventRecord,
    channel_index: usize,
    record_index: usize,
    observed_at_utc: &str,
) -> EventEvidenceObservation {
    let named_data = record
        .event_data
        .iter()
        .map(|property| EspNamedValue {
            name: property.name.clone(),
            value: property.value.clone(),
        })
        .collect::<Vec<_>>();
    let source_artifact_id = record.source_file.clone();
    let evidence_ref = EspEvidenceRef {
        evidence_id: format!(
            "esp-event-{channel_index}-{}-{}",
            record.record_id.unwrap_or(record_index as u64),
            record.event_id
        ),
        source_artifact_id: source_artifact_id.clone(),
    };
    let sensitivity = event_sensitivity(&record.event_data);
    let fields = deterministic_fields(record.event_id, &record.event_data);
    let event_provenance = EspEventProvenance {
        channel: record.channel.clone(),
        event_id: record.event_id,
        record_id: record.record_id,
        named_data: named_data.clone(),
    };

    EventEvidenceObservation {
        observation: EspEventLogObservation {
            context: EspObservationContext {
                evidence_ref,
                provenance: EspEvidenceProvenance {
                    source_kind: EspSourceKind::EventLog,
                    source_artifact_id,
                    file_path: Some(record.source_file),
                    line_number: None,
                    record_number: record.record_id,
                    registry: None,
                    event: Some(event_provenance),
                },
                source_timestamp: Some(normalize_timestamp(&record.source_timestamp, None)),
                observed_at_utc: observed_at_utc.to_string(),
                sensitivity,
                parse_state: EspParseState::Parsed,
                access_state: EspSourceAccessState::Available,
            },
            channel: record.channel,
            event_id: record.event_id,
            record_id: record.record_id,
            named_data,
            message: record.message,
        },
        fields,
    }
}

fn deterministic_fields(
    event_id: u32,
    event_data: &[EventLogProperty],
) -> EventDeterministicFields {
    let named = |aliases: &[&str]| {
        event_data.iter().find_map(|property| {
            aliases
                .iter()
                .any(|alias| property.name.eq_ignore_ascii_case(alias))
                .then(|| property.value.clone())
        })
    };
    let positional = |index: usize| event_data.get(index).map(|value| value.value.clone());

    EventDeterministicFields {
        state: named(&["State", "ODJState", "Status"]).or_else(|| {
            matches!(event_id, 109 | 110)
                .then(|| positional(0))
                .flatten()
        }),
        product_code: named(&["ProductCode", "MsiProductCode"]).or_else(|| {
            matches!(event_id, 1905 | 1906 | 1920 | 1922 | 1924)
                .then(|| positional(if event_id == 1924 { 2 } else { 0 }))
                .flatten()
        }),
        app_id: named(&["AppId", "ApplicationId"]),
        policy_id: named(&["PolicyId", "PolicyGuid"]),
        result_code: named(&["ResultCode", "ErrorCode", "HResult"]),
    }
}

fn event_sensitivity(event_data: &[EventLogProperty]) -> EspSensitivity {
    if event_data.iter().any(|property| {
        let name = property.name.to_ascii_lowercase();
        ["upn", "sid", "tenant", "entdmid", "serial"]
            .iter()
            .any(|marker| name.contains(marker))
    }) {
        EspSensitivity::Sensitive
    } else {
        EspSensitivity::Public
    }
}

fn access_state_for_error(error: EventSourceError) -> (EspSourceAccessState, Option<String>) {
    match error {
        EventSourceError::Missing => (EspSourceAccessState::Missing, None),
        EventSourceError::PermissionDenied => (EspSourceAccessState::PermissionDenied, None),
        EventSourceError::Failed(detail) => (EspSourceAccessState::Failed, Some(detail)),
        EventSourceError::Unsupported => (EspSourceAccessState::Unsupported, None),
    }
}

struct CapturedEventLogProvider {
    records_by_channel: HashMap<String, Vec<ParsedEspEventRecord>>,
}

impl EventLogProvider for CapturedEventLogProvider {
    fn read_channel(
        &self,
        channel: &str,
        _record_limit: usize,
    ) -> Result<Vec<ParsedEspEventRecord>, EventSourceError> {
        self.records_by_channel
            .get(channel)
            .cloned()
            .ok_or(EventSourceError::Missing)
    }
}

#[cfg(target_os = "windows")]
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsEventLogProvider;

#[cfg(target_os = "windows")]
impl EventLogProvider for WindowsEventLogProvider {
    fn read_channel(
        &self,
        channel: &str,
        record_limit: usize,
    ) -> Result<Vec<ParsedEspEventRecord>, EventSourceError> {
        let query = crate::intune::eventlog_win32::query_live_channel(channel, record_limit)
            .map_err(|error| classify_live_error(&error.to_string()))?;
        Ok(query
            .records
            .into_iter()
            .filter_map(|record| {
                crate::intune::evtx_parser::parse_esp_event_xml(
                    &record.xml,
                    &record.source_file,
                    None,
                    record.rendered_message,
                    channel,
                )
            })
            .collect())
    }
}

#[cfg(target_os = "windows")]
pub fn collect_live_event_evidence(
    observed_at_utc: &str,
) -> Result<EventEvidence, EventSourceError> {
    Ok(collect_event_evidence(
        &WindowsEventLogProvider,
        observed_at_utc,
    ))
}

#[cfg(not(target_os = "windows"))]
pub fn collect_live_event_evidence(
    _observed_at_utc: &str,
) -> Result<EventEvidence, EventSourceError> {
    Err(EventSourceError::Unsupported)
}

#[cfg(target_os = "windows")]
fn classify_live_error(detail: &str) -> EventSourceError {
    let normalized = detail.to_ascii_lowercase();
    if normalized.contains("access is denied")
        || normalized.contains("access denied")
        || normalized.contains("0x80070005")
    {
        EventSourceError::PermissionDenied
    } else if normalized.contains("not found")
        || normalized.contains("does not exist")
        || normalized.contains("0x80070002")
    {
        EventSourceError::Missing
    } else {
        EventSourceError::Failed(detail.to_string())
    }
}
