//! Reduce supplied normalized captures into observations, activities, coverage,
//! and findings.
//!
//! Ordering rule: records are emitted in the order the collector wrote them, and
//! `sequence` is retained as a separate field rather than used to sort. Apple's
//! unified log yields records whose timestamps are absent, offset-free, or
//! boot-relative, and a collector can restart its own counter across a rotation.
//! Re-sorting on either would reorder evidence, so the analyzer reports the
//! disagreement as a [`UnifiedLogSequenceAnomaly`] and leaves the order alone.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use chrono::{DateTime, SecondsFormat, Utc};
use regex::Regex;

use crate::intune::evidence::{
    IntuneAccessState, IntuneArtifactCoverage, IntuneArtifactStatus, IntuneErrorCode,
    IntuneEvidenceRef, IntuneObservationContext, IntuneParseState, IntuneProvenance,
    IntuneSensitivity, IntuneSourceKind, IntuneTimestamp, IntuneTimestampKind,
};

use super::models::*;
use super::predicate::{
    classify_relevance, predicate_descriptor, UnifiedLogPredicateDescriptor, UnifiedLogRelevance,
};
use super::rules::derive_findings;
use super::schema::{
    parse_capture_document, NormalizedUnifiedLogRecord, UnifiedLogCaptureMetadata,
    UnifiedLogRejectedLine,
};

/// Coverage family every artifact from this leaf reports under.
pub const UNIFIED_LOG_COVERAGE_FAMILY: &str = "companyPortalMacosUnifiedLog";

/// Reduce a bundle of supplied capture artifacts.
///
/// Pure: no clock, no filesystem, no process. Every `observedAtUtc` in the
/// result comes from the capture's own `collectedAtUtc`.
pub fn analyze_unified_log_bundle(inputs: &[UnifiedLogSourceInput]) -> UnifiedLogAnalysis {
    let mut analysis = UnifiedLogAnalysis {
        schema_version: UNIFIED_LOG_ANALYSIS_SCHEMA_VERSION,
        ..UnifiedLogAnalysis::default()
    };

    for input in inputs {
        reduce_artifact(input, &mut analysis);
    }

    analysis.activities = build_activities(&analysis.observations);
    analysis.findings = derive_findings(&analysis);
    analysis
}

fn reduce_artifact(input: &UnifiedLogSourceInput, analysis: &mut UnifiedLogAnalysis) {
    let parse = input
        .content
        .as_deref()
        .map(parse_capture_document)
        .unwrap_or_default();

    let capture = parse
        .document
        .as_ref()
        .map(|document| document.capture.clone())
        .unwrap_or_default();
    let records = parse
        .document
        .as_ref()
        .map(|document| document.records.as_slice())
        .unwrap_or_default();

    let observed_at_utc = capture.collected_at_utc.clone().unwrap_or_default();
    let access_state = access_state_for(input.capture_state);

    let mut relevant = 0u64;
    let first_observation = analysis.observations.len();

    for (position, record) in records.iter().enumerate() {
        let line_number = parse.record_lines.get(position).copied().flatten();
        let observation = reduce_record(
            input,
            record,
            position as u64,
            line_number,
            &observed_at_utc,
            access_state.clone(),
        );
        if observation.relevance.is_relevant() {
            relevant += 1;
        }
        analysis.observations.push(observation);
    }

    push_sequence_anomalies(
        &input.artifact_id,
        &analysis.observations[first_observation..],
        &mut analysis.sequence_anomalies,
    );

    let declared_predicate = declared_predicate(&capture);
    let analyzer_predicate = predicate_descriptor();
    let predicate_mismatch = declared_predicate.as_ref().is_some_and(|declared| {
        declared.predicate_id != analyzer_predicate.predicate_id
            || declared.predicate_version != analyzer_predicate.predicate_version
    });

    analysis.captures.push(UnifiedLogCaptureSummary {
        artifact_id: input.artifact_id.clone(),
        file_name: input.file_name.clone(),
        capture_state: input.capture_state,
        capture_id: capture.capture_id.clone(),
        declared_predicate,
        analyzer_predicate,
        predicate_mismatch,
        window: capture.window.clone(),
        collected_at_utc: capture.collected_at_utc.clone(),
        host_os_version: capture.host_os_version.clone(),
        company_portal_version: capture.company_portal_version.clone(),
        time_zone: capture.time_zone.clone(),
        boot_uuid: capture.boot_uuid.clone(),
        coverage: parse.document.as_ref().map(|_| capture.coverage.clone()),
        redaction: parse.document.as_ref().map(|_| capture.redaction.clone()),
        records_read: records.len() as u64,
        records_relevant: relevant,
        rejected: parse.rejected.clone(),
    });

    analysis.coverage.push(IntuneArtifactCoverage {
        artifact_id: input.artifact_id.clone(),
        family: UNIFIED_LOG_COVERAGE_FAMILY.to_owned(),
        status: artifact_status_for(input.capture_state),
        detail: Some(coverage_detail(input, records.len() as u64, relevant, &parse.rejected)),
        observed_at_utc,
        evidence: analysis.observations[first_observation..]
            .iter()
            .filter(|observation| observation.relevance.is_relevant())
            .map(|observation| observation.context.evidence_ref.clone())
            .collect(),
    });
}

/// The capture's own account of the rule it ran, when it stated one.
fn declared_predicate(capture: &UnifiedLogCaptureMetadata) -> Option<UnifiedLogPredicateDescriptor> {
    let predicate_id = capture.predicate_id.clone()?;
    Some(UnifiedLogPredicateDescriptor {
        predicate_id,
        predicate_version: capture.predicate_version.unwrap_or(0),
        predicate: capture.predicate.clone().unwrap_or_default(),
    })
}

fn coverage_detail(
    input: &UnifiedLogSourceInput,
    records_read: u64,
    relevant: u64,
    rejected: &[UnifiedLogRejectedLine],
) -> String {
    format!(
        "{}: {records_read} record(s) read, {relevant} matched {} v{}, {} rejected",
        input.file_name,
        super::predicate::COMPANY_PORTAL_PREDICATE_ID,
        super::predicate::COMPANY_PORTAL_PREDICATE_VERSION,
        rejected.len(),
    )
}

fn access_state_for(state: UnifiedLogCaptureState) -> IntuneAccessState {
    match state {
        UnifiedLogCaptureState::Captured => IntuneAccessState::Available,
        UnifiedLogCaptureState::Capped => IntuneAccessState::Capped,
        UnifiedLogCaptureState::Absent => IntuneAccessState::Missing,
        UnifiedLogCaptureState::AccessDenied => IntuneAccessState::PermissionDenied,
        UnifiedLogCaptureState::Skipped => IntuneAccessState::Skipped,
        UnifiedLogCaptureState::Unsupported => IntuneAccessState::Unsupported,
        UnifiedLogCaptureState::ParseFailed => IntuneAccessState::Failed,
    }
}

/// The mapping the fixture harness enforces between capture state and coverage.
fn artifact_status_for(state: UnifiedLogCaptureState) -> IntuneArtifactStatus {
    match state {
        UnifiedLogCaptureState::Captured => IntuneArtifactStatus::Available,
        UnifiedLogCaptureState::Capped => IntuneArtifactStatus::Capped,
        UnifiedLogCaptureState::Absent => IntuneArtifactStatus::Missing,
        UnifiedLogCaptureState::AccessDenied => IntuneArtifactStatus::PermissionDenied,
        UnifiedLogCaptureState::Skipped => IntuneArtifactStatus::Skipped,
        UnifiedLogCaptureState::Unsupported => IntuneArtifactStatus::Unsupported,
        UnifiedLogCaptureState::ParseFailed => IntuneArtifactStatus::ParseFailed,
    }
}

fn reduce_record(
    input: &UnifiedLogSourceInput,
    record: &NormalizedUnifiedLogRecord,
    position: u64,
    line_number: Option<u64>,
    observed_at_utc: &str,
    access_state: IntuneAccessState,
) -> UnifiedLogObservation {
    let observation_id = format!("{}:{}", input.artifact_id, position);
    let relevance = classify_relevance(record);
    let level = UnifiedLogLevel::from_message_type(record.message_type.as_ref());
    let source_timestamp = record
        .timestamp
        .as_deref()
        .map(|raw| parse_timestamp(raw, record.time_zone_offset.as_deref()));
    // True when nothing in the record anchors it to wall-clock time: no
    // timestamp at all, or one that stated no offset the capture could supply.
    // A record like this can still be ordered by sequence, but it cannot be
    // aligned with evidence from another source.
    let boot_relative_only = source_timestamp
        .as_ref()
        .map(|timestamp| timestamp.normalized_utc.is_none())
        .unwrap_or(true);

    let sensitivity = if record.event_message.is_some()
        || record.sender_image_path.is_some()
        || record.process_image_path.is_some()
    {
        // Unified-log messages and image paths routinely quote a UPN, a device
        // serial, a service URL, or a home-directory path.
        IntuneSensitivity::Sensitive
    } else {
        IntuneSensitivity::Public
    };

    let context = IntuneObservationContext {
        evidence_ref: IntuneEvidenceRef {
            evidence_id: observation_id.clone(),
            source_artifact_id: input.artifact_id.clone(),
        },
        provenance: IntuneProvenance {
            source_kind: IntuneSourceKind::UnifiedLog,
            source_artifact_id: input.artifact_id.clone(),
            // The collector's sanitized file name, never a device path: this
            // crate never sees one and must not invent one.
            file_path: Some(input.file_name.clone()),
            line_number,
            record_number: Some(record.sequence),
            registry: None,
            event: None,
        },
        source_timestamp,
        observed_at_utc: observed_at_utc.to_owned(),
        sensitivity,
        parse_state: IntuneParseState::Parsed,
        access_state,
    };

    UnifiedLogObservation {
        observation_id,
        context,
        sequence: record.sequence,
        source_position: position,
        relevance,
        activity_kind: classify_activity_kind(record, relevance),
        level,
        message_type: record.message_type.clone(),
        event_type: record.event_type.clone(),
        process: record.process.clone(),
        process_id: record.process_id,
        thread_id: record.thread_id,
        subsystem: record.subsystem.clone(),
        category: record.category.clone(),
        message: record.event_message.clone(),
        sender_image_path: record.sender_image_path.clone(),
        activity_identifier: record.activity_identifier,
        parent_activity_identifier: record.parent_activity_identifier,
        signpost_id: record.signpost_id,
        signpost_name: record.signpost_name.clone(),
        signpost_type: record.signpost_type.clone(),
        correlation_keys: correlation_keys(record),
        error: extract_error(record),
        apple_redacted_values: record.apple_redacted_values(),
        boot_relative_only,
        named_data: record.named_data.clone(),
    }
}

// ── Timestamps ──────────────────────────────────────────────────────────────

/// Normalize a source timestamp without inventing a timezone.
///
/// `normalized_utc` is populated **only** when the value carried its own offset,
/// or when the capture stated the device offset the value should be read in. A
/// bare wall-clock string with neither is left un-normalized: the only offset
/// available then belongs to the machine running the parser, and a UTC value
/// derived from it would silently differ per developer machine.
fn parse_timestamp(raw: &str, capture_offset: Option<&str>) -> IntuneTimestamp {
    let trimmed = raw.trim();

    if let Ok(parsed) = DateTime::parse_from_rfc3339(trimmed) {
        return offset_timestamp(raw, parsed);
    }
    for format in ["%Y-%m-%d %H:%M:%S%.f%z", "%Y-%m-%dT%H:%M:%S%.f%z"] {
        if let Ok(parsed) = DateTime::parse_from_str(trimmed, format) {
            return offset_timestamp(raw, parsed);
        }
    }

    // No offset in the value itself. The capture may still state the device's,
    // in which case the reading is source-accurate.
    if let Some(offset) = capture_offset {
        let combined = format!("{trimmed}{offset}");
        for format in ["%Y-%m-%d %H:%M:%S%.f%z", "%Y-%m-%dT%H:%M:%S%.f%z"] {
            if let Ok(parsed) = DateTime::parse_from_str(&combined, format) {
                return offset_timestamp(raw, parsed);
            }
        }
    }

    let kind = if chrono::NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%d %H:%M:%S%.f").is_ok()
        || chrono::NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%dT%H:%M:%S%.f").is_ok()
    {
        IntuneTimestampKind::Unspecified
    } else {
        IntuneTimestampKind::Invalid
    };

    IntuneTimestamp {
        raw_text: raw.to_owned(),
        original_offset: None,
        normalized_utc: None,
        kind,
    }
}

fn offset_timestamp(raw: &str, parsed: DateTime<chrono::FixedOffset>) -> IntuneTimestamp {
    let offset = parsed.offset().to_string();
    IntuneTimestamp {
        raw_text: raw.to_owned(),
        original_offset: Some(offset.clone()),
        normalized_utc: Some(
            parsed
                .with_timezone(&Utc)
                .to_rfc3339_opts(SecondsFormat::Micros, true),
        ),
        kind: if offset == "+00:00" {
            IntuneTimestampKind::Utc
        } else {
            IntuneTimestampKind::Offset
        },
    }
}

// ── Activity classification ─────────────────────────────────────────────────

/// Category markers, checked in order; the first hit wins.
///
/// The table is ordered from most specific workflow to least so that a category
/// such as `ProfileInstall` resolves to enrollment rather than to the app
/// installer, and `DeviceActions` to a device action rather than a generic one.
const CATEGORY_MARKERS: [(&str, UnifiedLogActivityKind); 22] = [
    ("startup", UnifiedLogActivityKind::ProcessStartup),
    ("launch", UnifiedLogActivityKind::ProcessStartup),
    ("lifecycle", UnifiedLogActivityKind::ProcessStartup),
    ("auth", UnifiedLogActivityKind::Authentication),
    ("signin", UnifiedLogActivityKind::Authentication),
    ("sso", UnifiedLogActivityKind::Authentication),
    ("token", UnifiedLogActivityKind::Authentication),
    ("enroll", UnifiedLogActivityKind::EnrollmentProfile),
    ("profile", UnifiedLogActivityKind::EnrollmentProfile),
    ("mdm", UnifiedLogActivityKind::EnrollmentProfile),
    ("compliance", UnifiedLogActivityKind::SyncCompliance),
    ("sync", UnifiedLogActivityKind::SyncCompliance),
    ("checkin", UnifiedLogActivityKind::SyncCompliance),
    ("device", UnifiedLogActivityKind::DeviceAction),
    ("catalog", UnifiedLogActivityKind::AppAction),
    ("install", UnifiedLogActivityKind::AppAction),
    ("app", UnifiedLogActivityKind::AppAction),
    ("network", UnifiedLogActivityKind::NetworkRequest),
    ("http", UnifiedLogActivityKind::NetworkRequest),
    ("graph", UnifiedLogActivityKind::NetworkRequest),
    ("diagnostic", UnifiedLogActivityKind::Diagnostics),
    ("telemetry", UnifiedLogActivityKind::Diagnostics),
];

/// Assign a workflow from the record's category.
///
/// Only relevant records are classified, and only from `category` — a field the
/// emitting binary controls. Classifying from message text would let any process
/// manufacture a Company Portal activity by writing the right words.
fn classify_activity_kind(
    record: &NormalizedUnifiedLogRecord,
    relevance: UnifiedLogRelevance,
) -> UnifiedLogActivityKind {
    if !relevance.is_relevant() {
        return UnifiedLogActivityKind::Unclassified;
    }
    let Some(category) = record.category.as_deref() else {
        return UnifiedLogActivityKind::Unclassified;
    };
    let category = category.to_ascii_lowercase();
    CATEGORY_MARKERS
        .iter()
        .find(|(marker, _)| category.contains(marker))
        .map(|(_, kind)| *kind)
        .unwrap_or(UnifiedLogActivityKind::Unclassified)
}

// ── Correlation ─────────────────────────────────────────────────────────────

/// Labelled identifier assignments inside a rendered message.
///
/// Anchored on an explicit label and a `:`/`=` separator. A bare GUID floating
/// in a message is not a correlation key: it could be a policy id, an app id, or
/// a tenant id, and joining on it would merge unrelated operations.
fn labelled_id_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r"(?i)\b(?P<label>client[-_ ]?request[-_ ]?id|correlation[-_ ]?id|request[-_ ]?id|session[-_ ]?id)\b\s*[:=]\s*(?P<value>[A-Za-z0-9][A-Za-z0-9._-]{7,})",
        )
        .expect("labelled identifier regex must compile")
    })
}

fn correlation_kind_for_label(label: &str) -> Option<UnifiedLogCorrelationKind> {
    let normalized = label
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect::<String>()
        .to_ascii_lowercase();
    match normalized.as_str() {
        "clientrequestid" | "requestid" => Some(UnifiedLogCorrelationKind::ClientRequestId),
        "correlationid" => Some(UnifiedLogCorrelationKind::CorrelationId),
        "sessionid" => Some(UnifiedLogCorrelationKind::SessionId),
        _ => None,
    }
}

/// Every explicit join key a record carries, de-duplicated and ordered.
fn correlation_keys(record: &NormalizedUnifiedLogRecord) -> Vec<UnifiedLogCorrelationKey> {
    let mut keys: std::collections::BTreeSet<UnifiedLogCorrelationKey> = Default::default();

    if let Some(activity) = record.activity_identifier {
        keys.insert(UnifiedLogCorrelationKey {
            kind: UnifiedLogCorrelationKind::Activity,
            value: activity.to_string(),
        });
    }
    if let Some(parent) = record.parent_activity_identifier {
        keys.insert(UnifiedLogCorrelationKey {
            kind: UnifiedLogCorrelationKind::ParentActivity,
            value: parent.to_string(),
        });
    }
    if let Some(signpost) = record.signpost_id {
        keys.insert(UnifiedLogCorrelationKey {
            kind: UnifiedLogCorrelationKind::Signpost,
            value: signpost.to_string(),
        });
    }

    for named in &record.named_data {
        if let Some(kind) = correlation_kind_for_label(&named.name) {
            keys.insert(UnifiedLogCorrelationKey {
                kind,
                value: named.value.clone(),
            });
        }
    }

    if let Some(message) = record.event_message.as_deref() {
        for captures in labelled_id_re().captures_iter(message) {
            let Some(kind) = correlation_kind_for_label(&captures["label"]) else {
                continue;
            };
            keys.insert(UnifiedLogCorrelationKey {
                kind,
                value: captures["value"].to_owned(),
            });
        }
    }

    keys.into_iter().collect()
}

// ── Error codes ─────────────────────────────────────────────────────────────

/// A labelled status/error token.
///
/// Labelled only: an unlabelled number in a message is as likely to be a byte
/// count as a status, and reporting it as an error code would fabricate a cause.
fn error_code_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r"(?i)\b(?:error|status|result|hresult|osstatus|nserror|code)\b[^0-9\-]{0,12}(?P<token>0x[0-9A-Fa-f]{1,16}|-?\d{1,10})",
        )
        .expect("error code regex must compile")
    })
}

fn extract_error(record: &NormalizedUnifiedLogRecord) -> Option<IntuneErrorCode> {
    let message = record.event_message.as_deref()?;
    let captures = error_code_re().captures(message)?;
    Some(error_code_from_token(&captures["token"]))
}

/// Keep the token verbatim and derive the other forms only when they are exact.
fn error_code_from_token(token: &str) -> IntuneErrorCode {
    let raw = token.to_owned();
    if let Some(digits) = token.strip_prefix("0x").or_else(|| token.strip_prefix("0X")) {
        let decimal = u64::from_str_radix(digits, 16)
            .ok()
            .and_then(|value| i64::try_from(value).ok());
        return IntuneErrorCode {
            raw,
            decimal,
            hex: Some(format!("0x{}", digits.to_ascii_uppercase())),
        };
    }
    let decimal = token.parse::<i64>().ok();
    let hex = decimal
        .and_then(|value| i32::try_from(value).ok())
        .map(|value| format!("0x{:08X}", value as u32));
    IntuneErrorCode { raw, decimal, hex }
}

// ── Sequence integrity ──────────────────────────────────────────────────────

fn push_sequence_anomalies(
    artifact_id: &str,
    observations: &[UnifiedLogObservation],
    anomalies: &mut Vec<UnifiedLogSequenceAnomaly>,
) {
    let mut by_sequence: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    let mut previous: Option<u64> = None;

    for observation in observations {
        by_sequence
            .entry(observation.sequence)
            .or_default()
            .push(observation.observation_id.clone());

        if previous.is_some_and(|previous| observation.sequence < previous) {
            anomalies.push(UnifiedLogSequenceAnomaly {
                kind: UnifiedLogSequenceAnomalyKind::OutOfOrder,
                artifact_id: artifact_id.to_owned(),
                sequence: observation.sequence,
                observation_ids: vec![observation.observation_id.clone()],
            });
        }
        previous = Some(observation.sequence);
    }

    for (sequence, observation_ids) in by_sequence {
        if observation_ids.len() > 1 {
            anomalies.push(UnifiedLogSequenceAnomaly {
                kind: UnifiedLogSequenceAnomalyKind::Duplicate,
                artifact_id: artifact_id.to_owned(),
                sequence,
                observation_ids,
            });
        }
    }
}

// ── Activities ──────────────────────────────────────────────────────────────

/// Group relevant observations by activity identifier.
///
/// Only the identifier decides membership. Two records that merely share an
/// instant are never grouped, and a record with no activity identifier joins
/// nothing at all.
fn build_activities(observations: &[UnifiedLogObservation]) -> Vec<UnifiedLogActivity> {
    let mut grouped: BTreeMap<u64, UnifiedLogActivity> = BTreeMap::new();

    for observation in observations
        .iter()
        .filter(|observation| observation.relevance.is_relevant())
    {
        let Some(identifier) = observation.activity_identifier else {
            continue;
        };
        let activity = grouped
            .entry(identifier)
            .or_insert_with(|| UnifiedLogActivity {
                activity_identifier: identifier,
                parent_activity_identifier: None,
                kind: UnifiedLogActivityKind::Unclassified,
                observation_ids: Vec::new(),
                signpost_ids: Vec::new(),
                highest_level: UnifiedLogLevel::Unknown,
            });

        activity
            .observation_ids
            .push(observation.observation_id.clone());
        if activity.parent_activity_identifier.is_none() {
            activity.parent_activity_identifier = observation.parent_activity_identifier;
        }
        if activity.kind == UnifiedLogActivityKind::Unclassified {
            activity.kind = observation.activity_kind;
        }
        if let Some(signpost) = observation.signpost_id {
            if !activity.signpost_ids.contains(&signpost) {
                activity.signpost_ids.push(signpost);
            }
        }
        activity.highest_level = activity.highest_level.max(observation.level);
    }

    grouped.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intune::evidence::IntuneNamedValue;

    #[test]
    fn a_timestamp_with_an_offset_normalizes_to_utc() {
        let timestamp = parse_timestamp("2026-07-14 09:15:02.123456-0700", None);
        assert_eq!(timestamp.original_offset.as_deref(), Some("-07:00"));
        assert_eq!(
            timestamp.normalized_utc.as_deref(),
            Some("2026-07-14T16:15:02.123456Z")
        );
        assert_eq!(timestamp.kind, IntuneTimestampKind::Offset);
    }

    #[test]
    fn a_timestamp_without_an_offset_is_not_normalized() {
        let timestamp = parse_timestamp("2026-07-14 09:15:02.123456", None);
        assert_eq!(timestamp.normalized_utc, None);
        assert_eq!(timestamp.original_offset, None);
        assert_eq!(timestamp.kind, IntuneTimestampKind::Unspecified);
        assert_eq!(timestamp.raw_text, "2026-07-14 09:15:02.123456");
    }

    #[test]
    fn the_capture_offset_rescues_a_timestamp_that_states_none() {
        let timestamp = parse_timestamp("2026-07-14 09:15:02.123456", Some("+0200"));
        assert_eq!(
            timestamp.normalized_utc.as_deref(),
            Some("2026-07-14T07:15:02.123456Z")
        );
        assert_eq!(timestamp.original_offset.as_deref(), Some("+02:00"));
    }

    #[test]
    fn an_unparseable_timestamp_keeps_its_raw_text() {
        let timestamp = parse_timestamp("boot+12.5s", None);
        assert_eq!(timestamp.kind, IntuneTimestampKind::Invalid);
        assert_eq!(timestamp.raw_text, "boot+12.5s");
        assert_eq!(timestamp.normalized_utc, None);
    }

    #[test]
    fn a_bare_guid_in_a_message_is_not_a_correlation_key() {
        let record = NormalizedUnifiedLogRecord {
            event_message: Some(
                "applied policy 11111111-2222-3333-4444-555555555555 successfully".to_owned(),
            ),
            ..Default::default()
        };
        assert!(correlation_keys(&record).is_empty());
    }

    #[test]
    fn a_labelled_request_id_is_a_correlation_key() {
        let record = NormalizedUnifiedLogRecord {
            event_message: Some(
                "POST /deviceManagement client-request-id: 9f2c1c8a-0001-4f2b-9a11-aabbccddeeff"
                    .to_owned(),
            ),
            ..Default::default()
        };
        let keys = correlation_keys(&record);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].kind, UnifiedLogCorrelationKind::ClientRequestId);
        assert_eq!(keys[0].value, "9f2c1c8a-0001-4f2b-9a11-aabbccddeeff");
    }

    #[test]
    fn named_data_supplies_correlation_keys_without_message_parsing() {
        let record = NormalizedUnifiedLogRecord {
            named_data: vec![IntuneNamedValue {
                name: "correlationId".to_owned(),
                value: "abc-123".to_owned(),
            }],
            ..Default::default()
        };
        let keys = correlation_keys(&record);
        assert_eq!(keys[0].kind, UnifiedLogCorrelationKind::CorrelationId);
    }

    #[test]
    fn an_unlabelled_number_is_not_read_as_an_error_code() {
        let record = NormalizedUnifiedLogRecord {
            event_message: Some("downloaded 4096 bytes".to_owned()),
            ..Default::default()
        };
        assert!(extract_error(&record).is_none());
    }

    #[test]
    fn a_labelled_hex_status_keeps_every_form() {
        let error = error_code_from_token("0x80070005");
        assert_eq!(error.raw, "0x80070005");
        assert_eq!(error.hex.as_deref(), Some("0x80070005"));
        assert_eq!(error.decimal, Some(2_147_942_405));
    }

    #[test]
    fn a_negative_decimal_status_derives_its_hex_form() {
        let error = error_code_from_token("-1009");
        assert_eq!(error.decimal, Some(-1009));
        assert_eq!(error.hex.as_deref(), Some("0xFFFFFC0F"));
    }

    #[test]
    fn an_unrelated_record_is_never_given_an_activity_kind() {
        let record = NormalizedUnifiedLogRecord {
            category: Some("Authentication".to_owned()),
            ..Default::default()
        };
        assert_eq!(
            classify_activity_kind(&record, UnifiedLogRelevance::Unrelated),
            UnifiedLogActivityKind::Unclassified
        );
    }

    #[test]
    fn a_profile_category_resolves_to_enrollment_not_to_the_app_installer() {
        let record = NormalizedUnifiedLogRecord {
            category: Some("ProfileInstall".to_owned()),
            ..Default::default()
        };
        assert_eq!(
            classify_activity_kind(&record, UnifiedLogRelevance::Direct),
            UnifiedLogActivityKind::EnrollmentProfile
        );
    }
}
