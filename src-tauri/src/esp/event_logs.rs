//! Named, ordered Windows Event Log acquisition for ESP diagnostics.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use cmtraceopen_parser::esp::{
    normalize_timestamp, EspEventLogObservation, EspEventProvenance, EspEvidenceProvenance,
    EspEvidenceRef, EspNamedValue, EspObservationContext, EspParseState, EspSensitivity,
    EspSourceAccessState, EspSourceKind,
};
use serde::{Deserialize, Serialize};

use super::process::sanitize_command_line;

use crate::intune::evtx_parser::{
    parse_esp_evtx_file_bounded_with_limits, EventLogProperty, ParsedEspEventRecord,
    ParsedEspEvtxBatch, MAX_ESP_EVTX_RECORD_BYTES,
};

pub const REQUIRED_EVENT_IDS: &[u32] = &[
    72, 100, 101, 107, 109, 110, 111, 304, 306, 1905, 1906, 1920, 1922, 1924,
];
pub const ESP_EVENT_CHANNELS: &[&str] = &[
    "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin",
    "Microsoft-Windows-User Device Registration/Admin",
];
pub const MAX_ESP_EVENT_RECORDS_PER_CHANNEL: usize = 2_000;
pub const MAX_CAPTURED_EVTX_FILES: usize = 16;
pub const MAX_CAPTURED_EVENT_RECORDS_INSPECTED: usize = 50_000;
pub const MAX_CAPTURED_EVENT_RETAINED_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapturedEventAcquisitionLimits {
    pub max_files: usize,
    pub max_inspected_records: usize,
    pub max_record_bytes: usize,
    pub max_retained_bytes: usize,
    pub max_records_per_channel: usize,
}

impl Default for CapturedEventAcquisitionLimits {
    fn default() -> Self {
        Self {
            max_files: MAX_CAPTURED_EVTX_FILES,
            max_inspected_records: MAX_CAPTURED_EVENT_RECORDS_INSPECTED,
            max_record_bytes: MAX_ESP_EVTX_RECORD_BYTES,
            max_retained_bytes: MAX_CAPTURED_EVENT_RETAINED_BYTES,
            max_records_per_channel: MAX_ESP_EVENT_RECORDS_PER_CHANNEL,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventSourceError {
    Missing,
    PermissionDenied,
    Failed(String),
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventReadBatch {
    pub records: Vec<ParsedEspEventRecord>,
    pub completion: Result<(), EventSourceError>,
}

pub trait EventLogProvider {
    fn read_channel(
        &self,
        channel: &str,
        required_event_ids: &[u32],
        record_limit: usize,
    ) -> Result<Vec<ParsedEspEventRecord>, EventSourceError>;

    fn read_channel_bounded(
        &self,
        channel: &str,
        required_event_ids: &[u32],
        record_limit: usize,
    ) -> EventReadBatch {
        match self.read_channel(channel, required_event_ids, record_limit) {
            Ok(records) => EventReadBatch {
                records,
                completion: Ok(()),
            },
            Err(error) => EventReadBatch {
                records: Vec::new(),
                completion: Err(error),
            },
        }
    }
}

pub fn required_event_id_xpath() -> String {
    event_id_xpath(REQUIRED_EVENT_IDS)
}

fn event_id_xpath(event_ids: &[u32]) -> String {
    let event_ids = event_ids
        .iter()
        .map(|event_id| format!("EventID={event_id}"))
        .collect::<Vec<_>>()
        .join(" or ");
    format!("*[System[({event_ids})]]")
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapturedEventFileState {
    Available,
    InspectionLimitReached,
    RetentionLimitReached,
    Failed(EventSourceError),
    NotInspected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedEventFileOutcome {
    pub path: PathBuf,
    pub state: CapturedEventFileState,
    pub inspected_records: usize,
    pub rejected_records: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedEventEvidence {
    pub evidence: EventEvidence,
    pub files: Vec<CapturedEventFileOutcome>,
    pub inspected_records: usize,
    pub retained_records: usize,
    pub inspection_limit_reached: bool,
    pub retention_limit_reached: bool,
}

pub fn collect_event_evidence(
    provider: &impl EventLogProvider,
    observed_at_utc: &str,
) -> EventEvidence {
    let mut evidence = EventEvidence::default();

    for (channel_index, channel) in ESP_EVENT_CHANNELS.iter().enumerate() {
        let mut batch = provider.read_channel_bounded(
            channel,
            REQUIRED_EVENT_IDS,
            MAX_ESP_EVENT_RECORDS_PER_CHANNEL,
        );
        let mut records = batch
            .records
            .drain(..)
            .filter(|record| REQUIRED_EVENT_IDS.binary_search(&record.event_id).is_ok())
            .collect::<Vec<_>>();
        records.sort_by(compare_event_records);
        if records.len() > MAX_ESP_EVENT_RECORDS_PER_CHANNEL {
            records.truncate(MAX_ESP_EVENT_RECORDS_PER_CHANNEL);
            let detail = format!(
                "Event channel record budget of {} was exhausted.",
                MAX_ESP_EVENT_RECORDS_PER_CHANNEL
            );
            evidence.limitations.push(detail.clone());
            batch.completion = Err(EventSourceError::Failed(detail));
        }

        match batch.completion {
            Ok(()) => {
                let record_count = records.len();
                evidence.channels.push(EventChannelEvidence {
                    channel: (*channel).to_string(),
                    access_state: EspSourceAccessState::Available,
                    record_count,
                    detail: None,
                });
                for (record_index, record) in records.into_iter().enumerate() {
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
                if let Some(detail) = detail.as_ref() {
                    if !evidence.limitations.contains(detail) {
                        evidence.limitations.push(detail.clone());
                    }
                }
                let record_count = records.len();
                evidence.channels.push(EventChannelEvidence {
                    channel: (*channel).to_string(),
                    access_state,
                    record_count,
                    detail,
                });
                for (record_index, record) in records.into_iter().enumerate() {
                    evidence.observations.push(normalize_record(
                        record,
                        channel_index,
                        record_index,
                        observed_at_utc,
                    ));
                }
            }
        }
    }

    evidence
}

fn compare_event_records(
    left: &ParsedEspEventRecord,
    right: &ParsedEspEventRecord,
) -> std::cmp::Ordering {
    left.record_id
        .unwrap_or(u64::MAX)
        .cmp(&right.record_id.unwrap_or(u64::MAX))
        .then_with(|| left.event_id.cmp(&right.event_id))
        .then_with(|| left.source_timestamp.cmp(&right.source_timestamp))
        .then_with(|| left.source_file.cmp(&right.source_file))
}

pub fn collect_captured_evtx_files(
    paths: &[PathBuf],
    observed_at_utc: &str,
) -> Result<EventEvidence, EventSourceError> {
    collect_captured_evtx_files_with(
        paths,
        observed_at_utc,
        CapturedEventAcquisitionLimits::default(),
        parse_esp_evtx_file_bounded_with_limits,
    )
}

pub fn collect_captured_evtx_files_bounded(
    paths: &[PathBuf],
    observed_at_utc: &str,
    inspection_limit: usize,
    retention_limit: usize,
) -> CapturedEventEvidence {
    let mut limits = CapturedEventAcquisitionLimits::default();
    limits.max_inspected_records = limits.max_inspected_records.min(inspection_limit);
    collect_captured_evtx_files_bounded_with(
        paths,
        observed_at_utc,
        limits,
        retention_limit,
        parse_esp_evtx_file_bounded_with_limits,
    )
}

fn collect_captured_evtx_files_with<F>(
    paths: &[PathBuf],
    observed_at_utc: &str,
    limits: CapturedEventAcquisitionLimits,
    parse_file: F,
) -> Result<EventEvidence, EventSourceError>
where
    F: FnMut(&Path, usize, usize, usize) -> Result<ParsedEspEvtxBatch, String>,
{
    Ok(collect_captured_evtx_files_bounded_with(
        paths,
        observed_at_utc,
        limits,
        usize::MAX,
        parse_file,
    )
    .evidence)
}

fn collect_captured_evtx_files_bounded_with<F>(
    paths: &[PathBuf],
    observed_at_utc: &str,
    limits: CapturedEventAcquisitionLimits,
    retention_limit: usize,
    mut parse_file: F,
) -> CapturedEventEvidence
where
    F: FnMut(&Path, usize, usize, usize) -> Result<ParsedEspEvtxBatch, String>,
{
    let mut records_by_channel = HashMap::<String, Vec<ParsedEspEventRecord>>::new();
    let mut limitations = Vec::new();
    let mut sorted_paths = paths.to_vec();
    sorted_paths.sort();
    let mut files = Vec::with_capacity(sorted_paths.len());
    let mut eligible_records_by_file = HashMap::<String, usize>::new();
    let mut native_retention_by_file = HashMap::<String, bool>::new();
    let mut inspected_records = 0usize;
    let mut retained_records = 0usize;
    let mut inspection_limit_reached = false;
    let mut retention_limit_reached = false;
    let per_channel_byte_cap = limits
        .max_retained_bytes
        .checked_div(ESP_EVENT_CHANNELS.len())
        .unwrap_or(0);

    for (index, path) in sorted_paths.into_iter().enumerate() {
        if index >= limits.max_files {
            inspection_limit_reached = true;
            push_unique_limitation(
                &mut limitations,
                format!(
                    "Captured EVTX file budget of {} was exhausted.",
                    limits.max_files
                ),
            );
            files.push(CapturedEventFileOutcome {
                path,
                state: CapturedEventFileState::NotInspected,
                inspected_records: 0,
                rejected_records: 0,
            });
            continue;
        }
        let remaining_inspections = limits
            .max_inspected_records
            .saturating_sub(inspected_records);
        if remaining_inspections == 0 {
            inspection_limit_reached = true;
            push_unique_limitation(
                &mut limitations,
                format!(
                    "Captured EVTX inspection budget of {} records was exhausted.",
                    limits.max_inspected_records
                ),
            );
            files.push(CapturedEventFileOutcome {
                path,
                state: CapturedEventFileState::NotInspected,
                inspected_records: 0,
                rejected_records: 0,
            });
            continue;
        }
        let retained_bytes = records_by_channel.values().fold(0usize, |total, records| {
            total.saturating_add(retained_event_bytes(records))
        });
        let remaining_retained_bytes = limits.max_retained_bytes.saturating_sub(retained_bytes);
        let batch = match parse_file(
            path.as_path(),
            remaining_inspections,
            limits.max_record_bytes,
            remaining_retained_bytes,
        ) {
            Ok(batch) => batch,
            Err(detail) => {
                push_unique_limitation(
                    &mut limitations,
                    format!(
                        "Captured EVTX file {} could not be read: {detail}",
                        path.display()
                    ),
                );
                files.push(CapturedEventFileOutcome {
                    path,
                    state: CapturedEventFileState::Failed(EventSourceError::Failed(detail)),
                    inspected_records: 0,
                    rejected_records: 0,
                });
                continue;
            }
        };
        let file_inspected = batch.inspected_records.min(remaining_inspections);
        inspected_records = inspected_records.saturating_add(file_inspected);
        let file_rejected = batch
            .parse_failure_count
            .saturating_add(batch.oversized_record_count)
            .min(file_inspected);
        let file_inspection_limit_reached =
            batch.inspection_limit_reached || batch.inspected_records > remaining_inspections;
        if file_inspection_limit_reached {
            inspection_limit_reached = true;
            push_unique_limitation(
                &mut limitations,
                format!(
                    "Captured EVTX inspection budget of {} records was exhausted.",
                    limits.max_inspected_records
                ),
            );
        }
        if batch.parse_failure_count > 0 {
            push_unique_limitation(
                &mut limitations,
                format!(
                    "Captured EVTX file {} contained {} record(s) that could not be parsed.",
                    path.display(),
                    batch.parse_failure_count
                ),
            );
        }
        if batch.oversized_record_count > 0 {
            push_unique_limitation(
                &mut limitations,
                format!(
                    "Captured EVTX file {} contained {} record(s) above the {}-byte record limit.",
                    path.display(),
                    batch.oversized_record_count,
                    limits.max_record_bytes
                ),
            );
        }
        if batch.retained_byte_budget_exhausted {
            native_retention_by_file.insert(path.to_string_lossy().to_string(), true);
            push_unique_limitation(
                &mut limitations,
                format!(
                    "Captured EVTX retained-byte budget of {} was exhausted.",
                    limits.max_retained_bytes
                ),
            );
        }

        let mut file_retention_limit_reached = batch.retained_byte_budget_exhausted;
        for mut record in batch.records.into_iter().take(file_inspected) {
            if REQUIRED_EVENT_IDS.binary_search(&record.event_id).is_err() {
                continue;
            }
            let Some(channel) = ESP_EVENT_CHANNELS
                .iter()
                .find(|channel| record.channel.eq_ignore_ascii_case(channel))
                .copied()
            else {
                continue;
            };
            record.channel = channel.to_string();
            let file_identity = path.to_string_lossy().to_string();
            let eligible_count = eligible_records_by_file.entry(file_identity).or_insert(0);
            *eligible_count = eligible_count.saturating_add(1);
            if retained_records >= retention_limit {
                retention_limit_reached = true;
                file_retention_limit_reached = true;
                continue;
            }
            let records = records_by_channel.entry(channel.to_string()).or_default();
            let retained_before = records.len();
            records.push(record);
            records.sort_by(compare_event_records);
            if records.len() > limits.max_records_per_channel {
                records.pop();
                file_retention_limit_reached = true;
                push_unique_limitation(
                    &mut limitations,
                    format!(
                        "Captured EVTX record budget of {} was exhausted for {channel}.",
                        limits.max_records_per_channel
                    ),
                );
                continue;
            }
            while retained_event_bytes(records) > per_channel_byte_cap {
                records.pop();
                file_retention_limit_reached = true;
                push_unique_limitation(
                    &mut limitations,
                    format!(
                        "Captured EVTX retained-byte budget of {} was exhausted.",
                        limits.max_retained_bytes
                    ),
                );
            }
            if records.len() > retained_before {
                retained_records = retained_records.saturating_add(1);
            }
        }
        files.push(CapturedEventFileOutcome {
            path,
            state: if file_inspection_limit_reached {
                CapturedEventFileState::InspectionLimitReached
            } else if file_retention_limit_reached {
                CapturedEventFileState::RetentionLimitReached
            } else {
                CapturedEventFileState::Available
            },
            inspected_records: file_inspected,
            rejected_records: file_rejected,
        });
    }

    retained_records = records_by_channel.values().map(Vec::len).sum();
    let mut retained_records_by_file = HashMap::<String, usize>::new();
    for record in records_by_channel.values().flatten() {
        let retained = retained_records_by_file
            .entry(record.source_file.clone())
            .or_insert(0);
        *retained = retained.saturating_add(1);
    }
    for file in &mut files {
        if !matches!(
            file.state,
            CapturedEventFileState::Available | CapturedEventFileState::RetentionLimitReached
        ) {
            continue;
        }
        let identity = file.path.to_string_lossy().to_string();
        let eligible = eligible_records_by_file
            .get(&identity)
            .copied()
            .unwrap_or(0);
        let retained = retained_records_by_file
            .get(&identity)
            .copied()
            .unwrap_or(0);
        file.state = if native_retention_by_file
            .get(&identity)
            .copied()
            .unwrap_or(false)
            || retained < eligible
        {
            CapturedEventFileState::RetentionLimitReached
        } else {
            CapturedEventFileState::Available
        };
    }
    let provider = CapturedEventLogProvider {
        records_by_channel,
        partial_detail: (!limitations.is_empty()).then(|| limitations.join(" ")),
    };
    let mut evidence = collect_event_evidence(&provider, observed_at_utc);
    for limitation in limitations {
        push_unique_limitation(&mut evidence.limitations, limitation);
    }
    CapturedEventEvidence {
        evidence,
        files,
        inspected_records,
        retained_records,
        inspection_limit_reached,
        retention_limit_reached,
    }
}

fn retained_event_bytes(records: &[ParsedEspEventRecord]) -> usize {
    records.iter().fold(0usize, |total, record| {
        total.saturating_add(record_event_bytes(record))
    })
}

fn record_event_bytes(record: &ParsedEspEventRecord) -> usize {
    record.retained_bytes()
}

fn push_unique_limitation(limitations: &mut Vec<String>, detail: String) {
    if !limitations.contains(&detail) {
        limitations.push(detail);
    }
}

fn normalize_record(
    record: ParsedEspEventRecord,
    channel_index: usize,
    record_index: usize,
    observed_at_utc: &str,
) -> EventEvidenceObservation {
    let ParsedEspEventRecord {
        channel,
        event_id,
        record_id,
        source_timestamp,
        event_data,
        message,
        source_file,
        raw_xml: _,
    } = record;
    let event_data = event_data
        .into_iter()
        .map(|mut property| {
            if contains_hardware_identity_marker(&property.name)
                || contains_hardware_identity_marker(&property.value)
            {
                property.name = "Redacted".to_string();
                property.value = "[REDACTED]".to_string();
            } else {
                property.value = sanitize_command_line(&property.value);
            }
            property
        })
        .collect::<Vec<_>>();
    let message = message.and_then(|message| {
        (!contains_hardware_identity_marker(&message)).then(|| sanitize_command_line(&message))
    });
    let named_data = event_data
        .iter()
        .map(|property| EspNamedValue {
            name: property.name.clone(),
            value: property.value.clone(),
        })
        .collect::<Vec<_>>();
    let source_artifact_id = source_file.clone();
    let evidence_ref = EspEvidenceRef {
        evidence_id: format!(
            "esp-event-{channel_index}-{}-{}",
            record_id.unwrap_or(record_index as u64),
            event_id
        ),
        source_artifact_id: source_artifact_id.clone(),
    };
    let sensitivity = event_sensitivity(&event_data, message.as_deref());
    let fields = deterministic_fields(event_id, &event_data);
    let event_provenance = EspEventProvenance {
        channel: channel.clone(),
        event_id,
        record_id,
        named_data: named_data.clone(),
    };

    EventEvidenceObservation {
        observation: EspEventLogObservation {
            context: EspObservationContext {
                evidence_ref,
                provenance: EspEvidenceProvenance {
                    source_kind: EspSourceKind::EventLog,
                    source_artifact_id,
                    file_path: Some(source_file),
                    line_number: None,
                    record_number: record_id,
                    registry: None,
                    event: Some(event_provenance),
                },
                source_timestamp: Some(normalize_timestamp(&source_timestamp, None)),
                observed_at_utc: observed_at_utc.to_string(),
                sensitivity,
                parse_state: EspParseState::Parsed,
                access_state: EspSourceAccessState::Available,
            },
            channel,
            event_id,
            record_id,
            named_data,
            message,
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

fn event_sensitivity(event_data: &[EventLogProperty], message: Option<&str>) -> EspSensitivity {
    if event_data.iter().any(|property| {
        is_sensitive_event_field_name(&property.name)
            || contains_sensitive_identity_text(&property.name)
            || contains_sensitive_identity_text(&property.value)
    }) || message.is_some_and(contains_sensitive_identity_text)
    {
        EspSensitivity::Sensitive
    } else {
        EspSensitivity::Public
    }
}

fn contains_hardware_identity_marker(value: &str) -> bool {
    let normalized = value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    normalized.contains("hardwarehash") || normalized.contains("devicehardwaredata")
}

/// Detect identity content (email/UPN, Windows SID, tenant/serial/entdm
/// keywords) embedded in free text. Shared with registry sensitivity
/// classification so both event-log and registry evidence scan value DATA, not
/// just field names, with a single source of truth for the regex.
pub(crate) fn contains_sensitive_identity_text(value: &str) -> bool {
    static IDENTITY_TEXT: OnceLock<regex::Regex> = OnceLock::new();
    IDENTITY_TEXT
        .get_or_init(|| {
            regex::Regex::new(
                r"(?i)(?:[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}|(?:^|[^a-z0-9])s-1-(?:0x[0-9a-f]{1,12}|[0-9]{1,10})(?:-[0-9]{1,10}){1,15}(?:$|[^0-9])|(?:^|[^a-z0-9])(?:(?:azure[ _-]*ad|aad)[ _-]*tenant[ _-]*id|device[ _-]*serial[ _-]*(?:number|no)|upn|user[ _-]*principal[ _-]*name|user[ _-]*sid|tenant[ _-]*(?:id|domain)|ent[ _-]*dm[ _-]*id|serial[ _-]*(?:number|no))(?:$|[^a-z0-9]))",
            )
            .expect("constant event identity regex")
        })
        .is_match(value)
}

fn is_sensitive_event_field_name(value: &str) -> bool {
    let normalized = value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    matches!(
        normalized.as_str(),
        "upn"
            | "userprincipalname"
            | "sid"
            | "usersid"
            | "tenant"
            | "tenantid"
            | "tenantdomain"
            | "aadtenantid"
            | "azureadtenantid"
            | "aadtenantdomain"
            | "cloudassignedtenantid"
            | "cloudassignedtenantdomain"
            | "entdmid"
            | "serial"
            | "serialnumber"
            | "deviceserialnumber"
    )
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
    partial_detail: Option<String>,
}

impl EventLogProvider for CapturedEventLogProvider {
    fn read_channel(
        &self,
        channel: &str,
        required_event_ids: &[u32],
        _record_limit: usize,
    ) -> Result<Vec<ParsedEspEventRecord>, EventSourceError> {
        self.records_by_channel
            .get(channel)
            .cloned()
            .map(|records| {
                records
                    .into_iter()
                    .filter(|record| required_event_ids.contains(&record.event_id))
                    .collect()
            })
            .ok_or(EventSourceError::Missing)
    }

    fn read_channel_bounded(
        &self,
        channel: &str,
        required_event_ids: &[u32],
        record_limit: usize,
    ) -> EventReadBatch {
        let records = self
            .records_by_channel
            .get(channel)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|record| required_event_ids.binary_search(&record.event_id).is_ok())
            .take(record_limit)
            .collect();
        EventReadBatch {
            records,
            completion: if let Some(detail) = self.partial_detail.as_ref() {
                Err(EventSourceError::Failed(detail.clone()))
            } else if self.records_by_channel.contains_key(channel) {
                Ok(())
            } else {
                Err(EventSourceError::Missing)
            },
        }
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
        required_event_ids: &[u32],
        record_limit: usize,
    ) -> Result<Vec<ParsedEspEventRecord>, EventSourceError> {
        let batch = read_live_event_channel_batch(channel, required_event_ids, record_limit);
        batch.completion?;
        Ok(batch.records)
    }

    fn read_channel_bounded(
        &self,
        channel: &str,
        required_event_ids: &[u32],
        record_limit: usize,
    ) -> EventReadBatch {
        read_live_event_channel_batch(channel, required_event_ids, record_limit)
    }
}

#[cfg(target_os = "windows")]
fn read_live_event_channel_batch(
    channel: &str,
    required_event_ids: &[u32],
    record_limit: usize,
) -> EventReadBatch {
    let query = match crate::intune::eventlog_win32::query_live_channel_with_xpath(
        channel,
        &event_id_xpath(required_event_ids),
        record_limit,
    ) {
        Ok(query) => query,
        Err(error) => {
            return EventReadBatch {
                records: Vec::new(),
                completion: Err(classify_live_error_code(error.code, &error.message)),
            }
        }
    };
    let mut partial_details = query.partial_detail.into_iter().collect::<Vec<_>>();
    let mut parse_failure_count = 0usize;
    let records = query
        .records
        .into_iter()
        .filter_map(|record| {
            let parsed = crate::intune::evtx_parser::parse_esp_event_xml(
                &record.xml,
                &record.source_file,
                None,
                record.rendered_message,
                channel,
            );
            if parsed.is_none() {
                parse_failure_count += 1;
            }
            parsed
        })
        .collect();
    if parse_failure_count > 0 {
        partial_details.push(format!(
            "{parse_failure_count} Windows Event Log record(s) could not be parsed"
        ));
    }
    let completion = if partial_details.is_empty() {
        Ok(())
    } else {
        Err(EventSourceError::Failed(partial_details.join(". ")))
    };
    EventReadBatch {
        records,
        completion,
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

#[cfg(any(target_os = "windows", test))]
fn classify_live_error_code(code: Option<u32>, detail: &str) -> EventSourceError {
    if code.is_some_and(|code| windows_code_matches(code, 5)) {
        return EventSourceError::PermissionDenied;
    }
    if code.is_some_and(|code| {
        [2, 3, 15_007]
            .into_iter()
            .any(|expected| windows_code_matches(code, expected))
    }) {
        return EventSourceError::Missing;
    }

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

#[cfg(any(target_os = "windows", test))]
fn windows_code_matches(code: u32, win32_code: u32) -> bool {
    code == win32_code || code == (0x8007_0000 | win32_code)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    fn property(name: &str) -> EventLogProperty {
        EventLogProperty {
            name: name.to_string(),
            value: "sensitive-value-sentinel".to_string(),
        }
    }

    fn captured_record(record_id: u64, source_file: &str) -> ParsedEspEventRecord {
        ParsedEspEventRecord {
            channel: ESP_EVENT_CHANNELS[0].to_string(),
            event_id: REQUIRED_EVENT_IDS[0],
            record_id: Some(record_id),
            source_timestamp: format!("2026-07-16T12:00:{record_id:02}Z"),
            event_data: vec![EventLogProperty {
                name: "State".to_string(),
                value: format!("state-{record_id}"),
            }],
            message: Some(format!("message-{record_id}")),
            source_file: source_file.to_string(),
            raw_xml: format!("<Event id=\"{record_id}\" />"),
        }
    }

    #[test]
    fn live_event_errors_use_numeric_windows_codes_independent_of_message_locale() {
        let localized = "Der angegebene Kanal wurde nicht gefunden.";
        let cases = [
            (5, EventSourceError::PermissionDenied),
            (0x8007_0005, EventSourceError::PermissionDenied),
            (2, EventSourceError::Missing),
            (0x8007_0002, EventSourceError::Missing),
            (3, EventSourceError::Missing),
            (15_007, EventSourceError::Missing),
            (0x8007_3a9f, EventSourceError::Missing),
        ];

        for (code, expected) in cases {
            assert_eq!(
                classify_live_error_code(Some(code), localized),
                expected,
                "unexpected classification for Windows error 0x{code:08x}"
            );
        }
        assert_eq!(
            classify_live_error_code(Some(87), localized),
            EventSourceError::Failed(localized.to_string())
        );
    }

    #[test]
    fn captured_event_acquisition_bounds_files_inspection_records_and_bytes_before_collection() {
        let paths = ["c.evtx", "b.evtx", "a.evtx"].map(PathBuf::from).to_vec();
        let calls = RefCell::new(Vec::new());
        let limits = CapturedEventAcquisitionLimits {
            max_files: 2,
            max_inspected_records: 3,
            max_record_bytes: 1024,
            max_retained_bytes: 1024,
            max_records_per_channel: 2,
        };

        let evidence = collect_captured_evtx_files_with(
            &paths,
            "2026-07-16T12:01:00Z",
            limits,
            |path, inspection_limit, _max_record_bytes, _max_retained_bytes| {
                calls.borrow_mut().push((
                    path.file_name()
                        .expect("file name")
                        .to_string_lossy()
                        .to_string(),
                    inspection_limit,
                ));
                let name = path.file_name().expect("file name").to_string_lossy();
                let records = match name.as_ref() {
                    "a.evtx" => vec![captured_record(5, "a.evtx"), captured_record(1, "a.evtx")],
                    "b.evtx" => vec![captured_record(3, "b.evtx")],
                    _ => panic!("file budget allowed unexpected path {name}"),
                };
                Ok(crate::intune::evtx_parser::ParsedEspEvtxBatch {
                    records,
                    inspected_records: inspection_limit.min(2),
                    inspection_limit_reached: name == "b.evtx",
                    truncated: name == "b.evtx",
                    parse_failure_count: 0,
                    oversized_record_count: 0,
                    retained_byte_budget_exhausted: false,
                })
            },
        )
        .expect("bounded captured evidence");

        assert_eq!(
            calls.into_inner(),
            vec![("a.evtx".to_string(), 3), ("b.evtx".to_string(), 1)]
        );
        assert_eq!(evidence.observations.len(), 2);
        assert_eq!(
            evidence
                .observations
                .iter()
                .map(|record| record.observation.record_id)
                .collect::<Vec<_>>(),
            vec![Some(1), Some(3)]
        );
        assert_eq!(
            evidence.channels[0].access_state,
            EspSourceAccessState::Failed
        );
        assert!(evidence
            .limitations
            .iter()
            .any(|detail| detail.contains("file budget")));
        assert!(evidence
            .limitations
            .iter()
            .any(|detail| detail.contains("inspection budget")));
    }

    #[test]
    fn captured_event_acquisition_reports_retained_byte_truncation() {
        let evidence = collect_captured_evtx_files_with(
            &[PathBuf::from("bounded.evtx")],
            "2026-07-16T12:01:00Z",
            CapturedEventAcquisitionLimits {
                max_files: 1,
                max_inspected_records: 10,
                max_record_bytes: 1024,
                max_retained_bytes: 1,
                max_records_per_channel: 10,
            },
            |_path, inspection_limit, max_record_bytes, max_retained_bytes| {
                assert_eq!(inspection_limit, 10);
                assert_eq!(max_record_bytes, 1024);
                assert_eq!(max_retained_bytes, 1);
                Ok(ParsedEspEvtxBatch {
                    records: vec![captured_record(1, "bounded.evtx")],
                    inspected_records: 1,
                    inspection_limit_reached: false,
                    truncated: false,
                    parse_failure_count: 0,
                    oversized_record_count: 0,
                    retained_byte_budget_exhausted: false,
                })
            },
        )
        .expect("bounded captured evidence");

        assert!(evidence.observations.is_empty());
        assert_eq!(
            evidence.channels[0].access_state,
            EspSourceAccessState::Failed
        );
        assert!(evidence
            .limitations
            .iter()
            .any(|detail| detail.contains("retained-byte budget")));
    }

    #[test]
    fn captured_event_acquisition_preserves_valid_files_when_a_later_file_fails() {
        let evidence = collect_captured_evtx_files_with(
            &[
                PathBuf::from("a-valid.evtx"),
                PathBuf::from("b-malformed.evtx"),
            ],
            "2026-07-16T12:01:00Z",
            CapturedEventAcquisitionLimits::default(),
            |path, _inspection_limit, _max_record_bytes, _max_retained_bytes| {
                if path.ends_with("a-valid.evtx") {
                    Ok(ParsedEspEvtxBatch {
                        records: vec![captured_record(1, "a-valid.evtx")],
                        inspected_records: 1,
                        inspection_limit_reached: false,
                        truncated: false,
                        parse_failure_count: 0,
                        oversized_record_count: 0,
                        retained_byte_budget_exhausted: false,
                    })
                } else {
                    Err("malformed EVTX sentinel".to_string())
                }
            },
        )
        .expect("a malformed file must not erase earlier valid evidence");

        assert_eq!(evidence.observations.len(), 1);
        assert_eq!(evidence.observations[0].observation.record_id, Some(1));
        assert_eq!(
            evidence.channels[0].access_state,
            EspSourceAccessState::Failed
        );
        assert!(evidence.limitations.iter().any(|detail| {
            detail.contains("b-malformed.evtx") && detail.contains("malformed EVTX sentinel")
        }));
    }

    #[test]
    fn captured_event_acquisition_propagates_record_parse_failures_as_partial_coverage() {
        let evidence = collect_captured_evtx_files_with(
            &[PathBuf::from("partially-malformed.evtx")],
            "2026-07-16T13:01:00Z",
            CapturedEventAcquisitionLimits::default(),
            |_path, _inspection_limit, _max_record_bytes, _max_retained_bytes| {
                Ok(ParsedEspEvtxBatch {
                    records: vec![captured_record(1, "partially-malformed.evtx")],
                    inspected_records: 3,
                    inspection_limit_reached: false,
                    truncated: true,
                    parse_failure_count: 2,
                    oversized_record_count: 0,
                    retained_byte_budget_exhausted: false,
                })
            },
        )
        .expect("valid records must survive malformed neighbors");

        assert_eq!(evidence.observations.len(), 1);
        assert_eq!(evidence.observations[0].observation.record_id, Some(1));
        assert_eq!(
            evidence.channels[0].access_state,
            EspSourceAccessState::Failed
        );
        assert!(evidence.limitations.iter().any(|detail| {
            detail.contains("partially-malformed.evtx")
                && detail.contains('2')
                && detail.contains("could not be parsed")
        }));
    }

    #[test]
    fn captured_event_outcomes_share_global_inspection_and_retention_budgets() {
        let paths = ["first.evtx", "broken.evtx", "second.evtx", "unread.evtx"]
            .map(PathBuf::from)
            .to_vec();
        let calls = RefCell::new(Vec::<(String, usize)>::new());
        let outcome = collect_captured_evtx_files_bounded_with(
            &paths,
            "2026-07-16T06:30:00Z",
            CapturedEventAcquisitionLimits {
                max_files: 4,
                max_inspected_records: 5,
                max_record_bytes: 1024,
                max_retained_bytes: usize::MAX,
                max_records_per_channel: 5,
            },
            5,
            |path, remaining, _max_record_bytes, _remaining_bytes| {
                let name = path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .expect("fixture file name")
                    .to_string();
                calls.borrow_mut().push((name.clone(), remaining));
                match name.as_str() {
                    "first.evtx" => Ok(ParsedEspEvtxBatch {
                        records: (0..3)
                            .map(|index| captured_record(index, &path.to_string_lossy()))
                            .collect(),
                        inspected_records: 3,
                        truncated: false,
                        inspection_limit_reached: false,
                        parse_failure_count: 0,
                        oversized_record_count: 0,
                        retained_byte_budget_exhausted: false,
                    }),
                    "broken.evtx" => Err("malformed EVTX".to_string()),
                    "second.evtx" => Ok(ParsedEspEvtxBatch {
                        records: (3..5)
                            .map(|index| captured_record(index, &path.to_string_lossy()))
                            .collect(),
                        inspected_records: 2,
                        truncated: true,
                        inspection_limit_reached: true,
                        parse_failure_count: 0,
                        oversized_record_count: 0,
                        retained_byte_budget_exhausted: false,
                    }),
                    _ => panic!("inspection budget must stop before the final file"),
                }
            },
        );

        assert_eq!(
            calls.into_inner(),
            vec![
                ("broken.evtx".to_string(), 5),
                ("first.evtx".to_string(), 5),
                ("second.evtx".to_string(), 2),
            ]
        );
        assert_eq!(outcome.inspected_records, 5);
        assert_eq!(outcome.retained_records, 5);
        assert!(outcome.inspection_limit_reached);
        assert_eq!(outcome.evidence.observations.len(), 5);
        assert!(matches!(
            outcome.files[0].state,
            CapturedEventFileState::Failed(EventSourceError::Failed(_))
        ));
        assert_eq!(outcome.files[1].state, CapturedEventFileState::Available);
        assert_eq!(
            outcome.files[2].state,
            CapturedEventFileState::InspectionLimitReached
        );
        assert_eq!(outcome.files[3].state, CapturedEventFileState::NotInspected);
    }

    #[test]
    fn captured_event_outcomes_separate_retention_from_inspection_and_report_rejections() {
        let path = PathBuf::from("events.evtx");
        let outcome = collect_captured_evtx_files_bounded_with(
            std::slice::from_ref(&path),
            "2026-07-16T06:30:00Z",
            CapturedEventAcquisitionLimits {
                max_files: 1,
                max_inspected_records: 5,
                max_record_bytes: 1024,
                max_retained_bytes: usize::MAX,
                max_records_per_channel: 5,
            },
            2,
            |path, requested, _max_record_bytes, _remaining_bytes| {
                assert_eq!(requested, 5);
                Ok(ParsedEspEvtxBatch {
                    records: (0..4)
                        .map(|index| captured_record(index, &path.to_string_lossy()))
                        .collect(),
                    inspected_records: 5,
                    truncated: true,
                    inspection_limit_reached: false,
                    parse_failure_count: 1,
                    oversized_record_count: 0,
                    retained_byte_budget_exhausted: false,
                })
            },
        );

        assert_eq!(outcome.inspected_records, 5);
        assert_eq!(outcome.retained_records, 2);
        assert_eq!(outcome.evidence.observations.len(), 2);
        assert!(!outcome.inspection_limit_reached);
        assert!(outcome.retention_limit_reached);
        assert_eq!(outcome.files[0].rejected_records, 1);
        assert_eq!(
            outcome.files[0].state,
            CapturedEventFileState::RetentionLimitReached
        );
    }

    #[test]
    fn event_sensitivity_uses_exact_documented_field_names() {
        for sensitive in [
            "UserPrincipalName",
            "user-principal-name",
            "UPN",
            "UserSID",
            "user_sid",
            "TenantId",
            "CloudAssignedTenantDomain",
            "EntDMID",
            "SerialNumber",
        ] {
            assert_eq!(
                event_sensitivity(&[property(sensitive)], None),
                EspSensitivity::Sensitive,
                "documented event field was not classified as sensitive: {sensitive}"
            );
        }

        for ordinary in ["Outside", "NotASid", "Presidential", "SerializationMode"] {
            assert_eq!(
                event_sensitivity(&[property(ordinary)], None),
                EspSensitivity::Public,
                "ordinary event field was classified as sensitive: {ordinary}"
            );
        }
    }
}
