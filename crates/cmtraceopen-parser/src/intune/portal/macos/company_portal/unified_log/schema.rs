//! The versioned *normalized capture* contract this leaf consumes.
//!
//! Apple's unified log lives in a binary `.tracev3` store and is queried with
//! `log show`. Neither is reachable from this crate: `std::process` and
//! `std::fs` are excluded by the wasm32 invariant documented in `lib.rs`, and no
//! platform-neutral `.tracev3` decoder is an approved dependency. So the
//! boundary is drawn here.
//!
//! A macOS-only native adapter runs the query and emits the deterministic
//! document described below; the pure crate validates and reduces it. That split
//! is what makes this analyzer testable from fixtures with no device present,
//! and it is why [`parse_capture_document`] is the only entry point — there is
//! deliberately no code path in this module that could reach a `.tracev3` file.
//!
//! # Wire forms
//!
//! Both forms carry the same content and reduce identically.
//!
//! * **JSON document** — one object with a `records` array. Convenient when the
//!   whole capture is small enough to hold in memory.
//! * **NDJSON stream** — one JSON object per line, the first of which is the
//!   capture header. This is what a streaming collector writes, and it is the
//!   only form in which a single malformed line is recoverable.
//!
//! Which form a payload is in is decided by its content, never by a file name:
//! a whole-text parse that yields an object with no `recordType` discriminator
//! is the document form, and everything else is read line by line.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::intune::evidence::{intune_raw_preserving_string_enum, IntuneNamedValue};

/// Identifier of the normalized capture schema this build understands.
///
/// A payload declaring anything else is rejected wholesale rather than parsed
/// on a best-effort basis: a document from an unknown producer has unknown field
/// semantics, and guessing them would silently fabricate evidence.
pub const UNIFIED_LOG_SCHEMA_ID: &str =
    "com.cmtraceopen.intune.portal.macos.companyPortal.unifiedLog";

/// Version of the normalized capture schema this build understands.
///
/// Bump only on a breaking change. Adding an optional field, or a variant to a
/// raw-preserving enum, is additive and does not bump it.
pub const UNIFIED_LOG_SCHEMA_VERSION: u32 = 1;

intune_raw_preserving_string_enum! {
    /// Apple's message type for a log record.
    ///
    /// Apple has added message types across releases, so an unrecognized value
    /// round-trips verbatim instead of collapsing into a known level.
    pub enum UnifiedLogMessageType {
        Default => "default",
        Info => "info",
        Debug => "debug",
        Error => "error",
        Fault => "fault",
    }
}

intune_raw_preserving_string_enum! {
    /// Apple's event type for a record.
    ///
    /// Activity and signpost events are what carry the relationships this
    /// analyzer preserves; a plain `logEvent` carries none.
    pub enum UnifiedLogEventType {
        LogEvent => "logEvent",
        ActivityCreateEvent => "activityCreateEvent",
        ActivityTransitionEvent => "activityTransitionEvent",
        SignpostEvent => "signpostEvent",
        StateEvent => "stateEvent",
        TimesyncEvent => "timesyncEvent",
    }
}

intune_raw_preserving_string_enum! {
    /// Which end of a signpost interval a record represents.
    pub enum UnifiedLogSignpostType {
        Begin => "begin",
        End => "end",
        Event => "event",
    }
}

intune_raw_preserving_string_enum! {
    /// How complete the collector believes the capture is.
    ///
    /// `Capped` is distinct from `Complete` because the absence of a signal in a
    /// truncated capture proves nothing, and a finding derived from it must say
    /// so.
    pub enum UnifiedLogCaptureCompleteness {
        Complete => "complete",
        Capped => "capped",
        Partial => "partial",
        Empty => "empty",
    }
}

/// The window a capture covers.
///
/// All three fields are optional because `log show` accepts `--last 1h` (a
/// relative window with no stated endpoints) as readily as `--start`/`--end`.
/// Recording which one was used is what makes a capture reproducible.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct UnifiedLogCaptureWindow {
    pub start: Option<String>,
    pub end: Option<String>,
    /// The relative window expression, e.g. `1h`, when one was used.
    pub last: Option<String>,
}

/// What the collector's own redaction pass did before handing the records over.
///
/// This is separate from [`super::redaction`], which is this crate's export-time
/// projection. Knowing that the collector already masked values matters: a
/// message that arrives pre-masked is not evidence that the analyzer masked it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct UnifiedLogRedactionMetadata {
    pub applied: bool,
    pub policy_id: Option<String>,
    pub redacted_field_count: Option<u32>,
}

/// How much the capture saw, as the collector reported it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct UnifiedLogCaptureCoverage {
    pub completeness: UnifiedLogCaptureCompleteness,
    /// Records the predicate matched on the device.
    pub records_matched: Option<u64>,
    /// Records actually written to the payload. A smaller value than
    /// `records_matched` is the definition of a truncated capture.
    pub records_emitted: Option<u64>,
    pub detail: Option<String>,
}

impl Default for UnifiedLogCaptureCoverage {
    fn default() -> Self {
        Self {
            completeness: UnifiedLogCaptureCompleteness::Complete,
            records_matched: None,
            records_emitted: None,
            detail: None,
        }
    }
}

/// Everything needed to reproduce a capture and to judge what it could have seen.
///
/// `predicate` plus `predicate_id`/`predicate_version` are what the issue's
/// reproducibility requirement rests on: the literal query string is retained so
/// a human can re-run it, and the identifier/version pair names the *rule* that
/// produced it so a later build can tell whether the selection logic changed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct UnifiedLogCaptureMetadata {
    pub capture_id: Option<String>,
    pub predicate: Option<String>,
    pub predicate_id: Option<String>,
    pub predicate_version: Option<u32>,
    pub window: Option<UnifiedLogCaptureWindow>,
    /// When the collector ran, in UTC. This crate reads no clock, so every
    /// `observedAtUtc` in the output is derived from this value.
    pub collected_at_utc: Option<String>,
    pub host_os_version: Option<String>,
    pub company_portal_version: Option<String>,
    /// The device's timezone at capture time, used to interpret records whose
    /// own timestamps carry no offset.
    pub time_zone: Option<String>,
    /// Boot session the mach timestamps in this capture are relative to.
    pub boot_uuid: Option<String>,
    pub coverage: UnifiedLogCaptureCoverage,
    pub redaction: UnifiedLogRedactionMetadata,
    /// Collector fields this build does not model, carried verbatim.
    pub named_data: Vec<IntuneNamedValue>,
}

/// One Apple unified-log record, projected into a form this crate can consume.
///
/// Field choice follows what the analyzer actually keys on. `sequence` is the
/// collector's source ordinal and is the only ordering this module trusts:
/// unified-log timestamps can be absent, offset-free, or boot-relative, so
/// sorting on them would reorder evidence. `activity_identifier`,
/// `parent_activity_identifier`, and `signpost_id` are the *explicit*
/// relationships a merge is allowed to use. Everything unmodeled lands in
/// `named_data` so adding a typed field later is a widening change rather than a
/// re-parse.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct NormalizedUnifiedLogRecord {
    /// The collector's source ordinal. Records are emitted in this order.
    pub sequence: u64,
    /// The record's timestamp exactly as the source wrote it.
    pub timestamp: Option<String>,
    /// The device timezone offset, when the collector could state one.
    pub time_zone_offset: Option<String>,
    /// Mach continuous time. Boot-relative and meaningless without `boot_uuid`.
    pub mach_timestamp: Option<u64>,
    pub boot_uuid: Option<String>,
    pub process: Option<String>,
    pub process_image_path: Option<String>,
    pub process_id: Option<u32>,
    pub thread_id: Option<u64>,
    pub sender_image_path: Option<String>,
    /// Free-form reverse-DNS identifier. Left as a string rather than an enum:
    /// the value space is open by construction, and a string never drops one.
    pub subsystem: Option<String>,
    /// Free-form, for the same reason as `subsystem`.
    pub category: Option<String>,
    pub message_type: Option<UnifiedLogMessageType>,
    pub event_type: Option<UnifiedLogEventType>,
    pub activity_identifier: Option<u64>,
    pub parent_activity_identifier: Option<u64>,
    pub signpost_id: Option<u64>,
    pub signpost_name: Option<String>,
    pub signpost_type: Option<UnifiedLogSignpostType>,
    /// The rendered message.
    pub event_message: Option<String>,
    /// The unrendered `os_log` format string, when the collector kept it.
    pub format_string: Option<String>,
    /// How many values Apple's own privacy filter replaced with `<private>`.
    /// Derived from the message when the collector does not state it.
    pub redacted_value_count: Option<u32>,
    pub named_data: Vec<IntuneNamedValue>,
}

impl NormalizedUnifiedLogRecord {
    /// Values Apple's privacy filter masked before this record was ever written.
    ///
    /// The collector's count wins when it supplied one; otherwise the rendered
    /// message is counted. A record full of `<private>` is weak evidence, and
    /// the analyzer needs to know that without re-scanning the message later.
    pub fn apple_redacted_values(&self) -> u32 {
        self.redacted_value_count.unwrap_or_else(|| {
            self.event_message
                .as_deref()
                .map(|message| message.matches("<private>").count() as u32)
                .unwrap_or(0)
        })
    }
}

/// A whole capture in the JSON-document wire form.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct UnifiedLogCaptureDocument {
    /// Free-text collector notice, carried verbatim and never interpreted.
    pub notice: Option<String>,
    pub schema_id: String,
    pub schema_version: u32,
    pub capture: UnifiedLogCaptureMetadata,
    pub records: Vec<NormalizedUnifiedLogRecord>,
}

/// The NDJSON header line: a document with its records still to come.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase", default)]
struct UnifiedLogCaptureHeader {
    notice: Option<String>,
    schema_id: String,
    schema_version: u32,
    capture: UnifiedLogCaptureMetadata,
}

/// Why a line or payload could not be turned into evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum UnifiedLogRejectReason {
    /// The line was not valid JSON.
    MalformedJson,
    /// The payload declared a `schemaId` this build does not produce.
    UnknownSchema,
    /// The schema is ours but the major version is not one we can read.
    UnsupportedVersion,
    /// An NDJSON stream whose first line was not a capture header.
    MissingHeader,
    /// A line whose `recordType` discriminator is not one we handle.
    UnknownRecordType,
    /// The payload was empty.
    EmptyPayload,
}

/// One line, or one whole payload, that could not be read.
///
/// Rejections are returned rather than logged so that the reduction can cite
/// them: a malformed line is a coverage gap, and a finding derived from a
/// capture containing one must be able to say which line was lost.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UnifiedLogRejectedLine {
    /// 1-based line number, or `None` when the whole payload was rejected.
    pub line_number: Option<u64>,
    pub reason: UnifiedLogRejectReason,
    pub detail: String,
}

/// The result of reading one capture payload.
///
/// `document` is `None` only when nothing usable survived; a stream with a valid
/// header and one bad line still yields a document *and* a rejection, because
/// discarding the good records would lose evidence the operator already has.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnifiedLogParse {
    pub document: Option<UnifiedLogCaptureDocument>,
    pub rejected: Vec<UnifiedLogRejectedLine>,
    /// Source line number for each record in `document.records`, when the wire
    /// form had one. Positionally aligned with that vector.
    pub record_lines: Vec<Option<u64>>,
}

/// Read a normalized capture payload in either wire form.
///
/// Never fails: an unreadable payload comes back as rejections, which the
/// reducer turns into coverage rather than into silence.
pub fn parse_capture_document(text: &str) -> UnifiedLogParse {
    if text.trim().is_empty() {
        return UnifiedLogParse {
            document: None,
            rejected: vec![UnifiedLogRejectedLine {
                line_number: None,
                reason: UnifiedLogRejectReason::EmptyPayload,
                detail: "capture payload contained no content".to_owned(),
            }],
            record_lines: Vec::new(),
        };
    }

    match whole_text_document(text) {
        Some(value) => parse_json_document(value),
        None => parse_ndjson_stream(text),
    }
}

/// Decide the wire form from content alone.
///
/// A whole-text parse that yields an object settles it, unless that object
/// carries a `recordType` discriminator — which is how a one-line NDJSON stream
/// looks, and reading it as a document would drop its records.
fn whole_text_document(text: &str) -> Option<serde_json::Value> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let object = value.as_object()?;
    if object.contains_key("recordType") {
        return None;
    }
    Some(value)
}

fn parse_json_document(value: serde_json::Value) -> UnifiedLogParse {
    let document: UnifiedLogCaptureDocument = match serde_json::from_value(value) {
        Ok(document) => document,
        Err(error) => {
            return UnifiedLogParse {
                document: None,
                rejected: vec![UnifiedLogRejectedLine {
                    line_number: None,
                    reason: UnifiedLogRejectReason::MalformedJson,
                    detail: format!("capture document did not match the schema: {error}"),
                }],
                record_lines: Vec::new(),
            }
        }
    };

    if let Some(rejection) = schema_rejection(&document.schema_id, document.schema_version, None) {
        return UnifiedLogParse {
            document: None,
            rejected: vec![rejection],
            record_lines: Vec::new(),
        };
    }

    let record_lines = vec![None; document.records.len()];
    UnifiedLogParse {
        document: Some(document),
        rejected: Vec::new(),
        record_lines,
    }
}

fn parse_ndjson_stream(text: &str) -> UnifiedLogParse {
    let mut parse = UnifiedLogParse::default();
    let mut header: Option<UnifiedLogCaptureHeader> = None;
    let mut records = Vec::new();

    for (index, raw_line) in text.lines().enumerate() {
        let line_number = index as u64 + 1;
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }

        let value: serde_json::Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(error) => {
                parse.rejected.push(UnifiedLogRejectedLine {
                    line_number: Some(line_number),
                    reason: UnifiedLogRejectReason::MalformedJson,
                    detail: format!("line is not valid JSON: {error}"),
                });
                continue;
            }
        };

        let record_type = value
            .get("recordType")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned();

        match record_type.as_str() {
            "captureHeader" => match serde_json::from_value::<UnifiedLogCaptureHeader>(value) {
                Ok(parsed) => {
                    if let Some(rejection) = schema_rejection(
                        &parsed.schema_id,
                        parsed.schema_version,
                        Some(line_number),
                    ) {
                        parse.rejected.push(rejection);
                        // An unreadable header makes every following line
                        // uninterpretable, so stop rather than guess.
                        return parse;
                    }
                    header = Some(parsed);
                }
                Err(error) => {
                    parse.rejected.push(UnifiedLogRejectedLine {
                        line_number: Some(line_number),
                        reason: UnifiedLogRejectReason::MalformedJson,
                        detail: format!("capture header did not match the schema: {error}"),
                    });
                    return parse;
                }
            },
            "logRecord" => {
                if header.is_none() {
                    parse.rejected.push(UnifiedLogRejectedLine {
                        line_number: Some(line_number),
                        reason: UnifiedLogRejectReason::MissingHeader,
                        detail: "a log record appeared before the capture header".to_owned(),
                    });
                    continue;
                }
                match serde_json::from_value::<NormalizedUnifiedLogRecord>(value) {
                    Ok(record) => {
                        records.push(record);
                        parse.record_lines.push(Some(line_number));
                    }
                    Err(error) => parse.rejected.push(UnifiedLogRejectedLine {
                        line_number: Some(line_number),
                        reason: UnifiedLogRejectReason::MalformedJson,
                        detail: format!("record did not match the schema: {error}"),
                    }),
                }
            }
            other => parse.rejected.push(UnifiedLogRejectedLine {
                line_number: Some(line_number),
                reason: UnifiedLogRejectReason::UnknownRecordType,
                detail: format!("unhandled recordType {other:?}"),
            }),
        }
    }

    match header {
        Some(header) => {
            parse.document = Some(UnifiedLogCaptureDocument {
                notice: header.notice,
                schema_id: header.schema_id,
                schema_version: header.schema_version,
                capture: header.capture,
                records,
            });
        }
        None => {
            parse.record_lines.clear();
            parse.rejected.push(UnifiedLogRejectedLine {
                line_number: None,
                reason: UnifiedLogRejectReason::MissingHeader,
                detail: "the stream contained no capture header".to_owned(),
            });
        }
    }

    parse
}

fn schema_rejection(
    schema_id: &str,
    schema_version: u32,
    line_number: Option<u64>,
) -> Option<UnifiedLogRejectedLine> {
    if schema_id != UNIFIED_LOG_SCHEMA_ID {
        return Some(UnifiedLogRejectedLine {
            line_number,
            reason: UnifiedLogRejectReason::UnknownSchema,
            detail: format!(
                "schemaId {schema_id:?} is not {UNIFIED_LOG_SCHEMA_ID:?}; \
                 field semantics are unknown so the payload was not parsed"
            ),
        });
    }
    if schema_version != UNIFIED_LOG_SCHEMA_VERSION {
        return Some(UnifiedLogRejectedLine {
            line_number,
            reason: UnifiedLogRejectReason::UnsupportedVersion,
            detail: format!(
                "schemaVersion {schema_version} is not {UNIFIED_LOG_SCHEMA_VERSION}"
            ),
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = concat!(
        r#"{"recordType":"captureHeader","schemaId":"#,
        r#""com.cmtraceopen.intune.portal.macos.companyPortal.unifiedLog","schemaVersion":1,"#,
        r#""capture":{"predicateId":"companyPortalMacosV1","predicateVersion":1}}"#
    );

    #[test]
    fn an_ndjson_stream_reads_its_header_and_records() {
        let text = format!(
            "{HEADER}\n{}\n",
            r#"{"recordType":"logRecord","sequence":1,"subsystem":"com.microsoft.CompanyPortalMac"}"#
        );
        let parse = parse_capture_document(&text);
        let document = parse.document.expect("document");
        assert_eq!(document.records.len(), 1);
        assert_eq!(parse.record_lines, vec![Some(2)]);
        assert!(parse.rejected.is_empty());
    }

    #[test]
    fn a_malformed_line_is_rejected_without_discarding_the_good_records() {
        let text = format!(
            "{HEADER}\nnot json\n{}\n",
            r#"{"recordType":"logRecord","sequence":2}"#
        );
        let parse = parse_capture_document(&text);
        assert_eq!(parse.document.expect("document").records.len(), 1);
        assert_eq!(parse.rejected.len(), 1);
        assert_eq!(
            parse.rejected[0].reason,
            UnifiedLogRejectReason::MalformedJson
        );
        assert_eq!(parse.rejected[0].line_number, Some(2));
    }

    #[test]
    fn an_unknown_schema_id_rejects_the_whole_payload() {
        let text = r#"{"schemaId":"com.example.other","schemaVersion":1,"records":[{"sequence":1}]}"#;
        let parse = parse_capture_document(text);
        assert!(parse.document.is_none());
        assert_eq!(
            parse.rejected[0].reason,
            UnifiedLogRejectReason::UnknownSchema
        );
    }

    #[test]
    fn an_unsupported_version_rejects_the_whole_payload() {
        let text = format!(
            r#"{{"schemaId":"{UNIFIED_LOG_SCHEMA_ID}","schemaVersion":99,"records":[]}}"#
        );
        let parse = parse_capture_document(&text);
        assert!(parse.document.is_none());
        assert_eq!(
            parse.rejected[0].reason,
            UnifiedLogRejectReason::UnsupportedVersion
        );
    }

    #[test]
    fn a_stream_without_a_header_yields_no_document() {
        let text = format!("{}\n", r#"{"recordType":"logRecord","sequence":1}"#);
        let parse = parse_capture_document(&text);
        assert!(parse.document.is_none());
        assert!(parse
            .rejected
            .iter()
            .any(|entry| entry.reason == UnifiedLogRejectReason::MissingHeader));
    }

    #[test]
    fn an_empty_payload_is_rejected_rather_than_read_as_an_empty_capture() {
        let parse = parse_capture_document("   \n");
        assert!(parse.document.is_none());
        assert_eq!(
            parse.rejected[0].reason,
            UnifiedLogRejectReason::EmptyPayload
        );
    }

    #[test]
    fn message_types_round_trip_unknown_values_verbatim() {
        let decoded: UnifiedLogMessageType = serde_json::from_str("\"someFutureType\"").unwrap();
        assert_eq!(
            decoded,
            UnifiedLogMessageType::Unknown("someFutureType".to_owned())
        );
        assert_eq!(
            serde_json::to_string(&decoded).unwrap(),
            "\"someFutureType\""
        );
    }

    #[test]
    fn apple_redacted_values_are_counted_when_the_collector_omits_the_count() {
        let record = NormalizedUnifiedLogRecord {
            event_message: Some("signed in as <private> on <private>".to_owned()),
            ..Default::default()
        };
        assert_eq!(record.apple_redacted_values(), 2);
    }

    #[test]
    fn a_collector_supplied_redaction_count_wins_over_the_message_scan() {
        let record = NormalizedUnifiedLogRecord {
            event_message: Some("<private>".to_owned()),
            redacted_value_count: Some(7),
            ..Default::default()
        };
        assert_eq!(record.apple_redacted_values(), 7);
    }
}
