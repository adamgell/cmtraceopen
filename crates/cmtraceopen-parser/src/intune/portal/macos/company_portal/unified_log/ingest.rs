//! Validation of a supplied normalized capture into records plus coverage.
//!
//! The pure crate never collects. It accepts what a native macOS collector
//! produced, in either of two wire encodings of the same versioned schema:
//!
//! * **NDJSON** — one capture header object, then one record object per line.
//!   Chosen by the native adapter because `log show --style ndjson` streams.
//! * **JSON** — a single object with `capture` metadata and a `records` array.
//!
//! Both encodings carry the same fields and reduce to the same
//! [`PortalUnifiedLogCaptureSet`]. Anything the crate cannot interpret becomes
//! an explicit [`PortalCoverageEntry`]; nothing is discarded.

use std::collections::BTreeMap;

use chrono::{DateTime, NaiveDateTime};
use serde_json::{Map, Value};

use super::models::*;
use super::schema::*;

/// Longest verbatim excerpt retained for a malformed line.
const MAX_RAW_EXCERPT_BYTES: usize = 512;

/// Record fields the schema names. Everything else lands in `unknown_fields`.
const KNOWN_RECORD_KEYS: &[&str] = &[
    "sourceSequence",
    "timestamp",
    "timezoneName",
    "bootUuid",
    "machTimestamp",
    "timeSinceBootNs",
    "process",
    "processImagePath",
    "senderImagePath",
    "subsystem",
    "category",
    "messageType",
    "eventMessage",
    "processID",
    "processId",
    "threadID",
    "threadId",
    "activityIdentifier",
    "parentActivityIdentifier",
    "signpostID",
    "signpostId",
    "signpostName",
    "signpostType",
    "traceId",
    "requestId",
    "correlationId",
    "redaction",
];

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// Parses a normalized capture in either supported encoding.
///
/// Detection is structural, never by file name: a payload that parses whole as
/// a JSON object carrying `records`, or declaring a capture header, is the JSON
/// encoding; anything else is treated as NDJSON.
///
/// Routing on `records` alone was not enough. `parse_capture_json_object`
/// already treats an absent `records` key as an empty capture, but a
/// pretty-printed capture with no records never reached it: it fell through to
/// the NDJSON path, where every physical line of the pretty printing failed to
/// parse, and a well-formed empty capture was reported as a stream of malformed
/// records. The header test is the same one NDJSON framing uses, both keys
/// rather than `schemaId` alone, so the two encodings agree on what a header is.
pub fn parse_capture(input: &str) -> PortalUnifiedLogCaptureSet {
    if let Ok(Value::Object(root)) = serde_json::from_str::<Value>(input) {
        let declares_header = root.contains_key("schemaId") && root.contains_key("schemaVersion");
        if root.contains_key("records") || declares_header {
            return parse_capture_json_object(root);
        }
    }
    parse_capture_ndjson(input)
}

/// Parses the NDJSON encoding: capture header line, then one record per line.
pub fn parse_capture_ndjson(input: &str) -> PortalUnifiedLogCaptureSet {
    let mut builder = CaptureSetBuilder::default();
    let mut header: Option<Map<String, Value>> = None;
    let mut pending: Vec<Map<String, Value>> = Vec::new();

    for line in input.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // `stream_lines` counts record-bearing lines only, so the NDJSON and
        // JSON encodings of the same capture report identical stats.
        match serde_json::from_str::<Value>(trimmed) {
            Ok(Value::Object(obj)) => {
                // The header is the leading object, and it must look like a
                // header rather than merely mention `schemaId`. A record is free
                // to carry `schemaId` among its unknown fields, and on the old
                // test the first such record was lifted out of the stream and
                // treated as capture metadata, silently changing both the record
                // set and the reported stats. Requiring `schemaVersion` as well,
                // and refusing to accept a header once records have been seen,
                // means a stray field can no longer rewrite the capture.
                let looks_like_header =
                    obj.contains_key("schemaId") && obj.contains_key("schemaVersion");
                if header.is_none() && pending.is_empty() && looks_like_header {
                    header = Some(obj);
                } else {
                    builder.stats.stream_lines += 1;
                    pending.push(obj);
                }
            }
            Ok(other) => {
                builder.stats.stream_lines += 1;
                // The position is named in the detail rather than in
                // `stream_index`, which identifies a *parsed record* and has no
                // value here because no record was produced. See the field's
                // documentation for why the two are not the same number.
                let position = builder.stats.stream_lines;
                builder.push_malformed(
                    trimmed,
                    format!(
                        "stream line {position} is valid JSON but not an object (found {})",
                        json_type_name(&other)
                    ),
                );
            }
            Err(err) => {
                builder.stats.stream_lines += 1;
                let position = builder.stats.stream_lines;
                builder.push_malformed(
                    trimmed,
                    format!("stream line {position} is not valid JSON: {err}"),
                );
            }
        }
    }

    builder.finish(header, pending)
}

/// Parses the single-object JSON encoding.
pub fn parse_capture_json(input: &str) -> PortalUnifiedLogCaptureSet {
    match serde_json::from_str::<Value>(input) {
        Ok(Value::Object(root)) => parse_capture_json_object(root),
        Ok(other) => {
            let mut builder = CaptureSetBuilder::default();
            builder.push_unknown_schema(format!(
                "capture payload is not a JSON object (found {})",
                json_type_name(&other)
            ));
            builder.finish(None, Vec::new())
        }
        Err(err) => {
            let mut builder = CaptureSetBuilder::default();
            builder.push_unknown_schema(format!("capture payload is not valid JSON: {err}"));
            builder.finish(None, Vec::new())
        }
    }
}

fn parse_capture_json_object(mut root: Map<String, Value>) -> PortalUnifiedLogCaptureSet {
    let mut builder = CaptureSetBuilder::default();
    let records = root.remove("records").unwrap_or(Value::Null);

    let mut pending: Vec<Map<String, Value>> = Vec::new();
    match records {
        Value::Array(items) => {
            for item in items {
                builder.stats.stream_lines += 1;
                match item {
                    Value::Object(obj) => pending.push(obj),
                    other => {
                        let excerpt = other.to_string();
                        builder.push_malformed(
                            &excerpt,
                            format!(
                                "record entry is not a JSON object (found {})",
                                json_type_name(&other)
                            ),
                        );
                    }
                }
            }
        }
        Value::Null => {}
        other => {
            // The envelope is wrong, not a record. No stream line was read, so
            // charging this to `records_malformed` would invent a record.
            let excerpt = other.to_string();
            builder.push_malformed_capture_metadata(
                &excerpt,
                format!(
                    "`records` is not an array (found {})",
                    json_type_name(&other)
                ),
            );
        }
    }

    builder.finish(Some(root), pending)
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

#[derive(Default)]
struct CaptureSetBuilder {
    coverage: Vec<PortalCoverageEntry>,
    stats: PortalCaptureStats,
    next_coverage: usize,
}

impl CaptureSetBuilder {
    fn coverage_id(&mut self) -> String {
        let id = coverage_id(self.next_coverage);
        self.next_coverage += 1;
        id
    }

    fn push_coverage(
        &mut self,
        status: PortalCoverageStatus,
        scope: PortalCoverageScope,
        detail: String,
        stream_index: Option<u64>,
        raw_excerpt: Option<PortalClassifiedString>,
    ) {
        let coverage_id = self.coverage_id();
        self.coverage.push(PortalCoverageEntry {
            coverage_id,
            status,
            scope,
            detail,
            stream_index,
            raw_excerpt,
            evidence: Vec::new(),
        });
    }

    /// Records a defect in one record-bearing stream line.
    ///
    /// Only for input that was read as a record. `records_malformed` is read
    /// against `stream_lines` and `records_parsed` to answer how much of the
    /// record stream survived, so a defect in the capture's own description must
    /// use [`Self::push_malformed_capture_metadata`] instead.
    fn push_malformed(&mut self, raw: &str, detail: String) {
        self.stats.records_malformed += 1;
        self.push_coverage(
            PortalCoverageStatus::MalformedRecord,
            PortalCoverageScope::Record,
            detail,
            None,
            Some(PortalClassifiedString::sensitive(truncate_excerpt(raw))),
        );
    }

    fn push_unknown_schema(&mut self, detail: String) {
        self.push_coverage(
            PortalCoverageStatus::UnknownSchema,
            PortalCoverageScope::Capture,
            detail,
            None,
            None,
        );
    }

    /// Records a defect in the capture's own description, keeping the offending
    /// value verbatim and leaving the record counters alone.
    fn push_malformed_capture_metadata(&mut self, raw: &str, detail: String) {
        self.push_coverage(
            PortalCoverageStatus::UnknownSchema,
            PortalCoverageScope::Capture,
            detail,
            None,
            Some(PortalClassifiedString::sensitive(truncate_excerpt(raw))),
        );
    }

    fn finish(
        mut self,
        header: Option<Map<String, Value>>,
        pending: Vec<Map<String, Value>>,
    ) -> PortalUnifiedLogCaptureSet {
        let Some(header) = header else {
            self.push_unknown_schema(
                "capture header is missing; a capture must declare `schemaId` and `schemaVersion`"
                    .to_string(),
            );
            return self.into_unsupported(None, None, pending);
        };

        let schema_id = str_field(&header, "schemaId");
        // `as u32` truncates: a declared `schemaVersion` of 4294967297 wraps to
        // 1, passes the supported-version check, and an unknown schema is then
        // parsed as if it were v1. A value that does not fit is not version 1,
        // it is a version this build does not support, so it must stay `None`
        // and fall through to the unsupported path.
        let schema_version =
            u64_field(&header, "schemaVersion").and_then(|v| u32::try_from(v).ok());

        match schema_id.as_deref() {
            Some(id) if id == PORTAL_UNIFIED_LOG_SCHEMA_ID => {}
            Some(id) => {
                self.push_unknown_schema(format!(
                    "unknown capture schema `{id}`; expected `{PORTAL_UNIFIED_LOG_SCHEMA_ID}`"
                ));
                return self.into_unsupported(schema_id, schema_version, pending);
            }
            None => {
                self.push_unknown_schema("capture header does not declare `schemaId`".to_string());
                return self.into_unsupported(schema_id, schema_version, pending);
            }
        }

        let Some(version) = schema_version else {
            // `schema_version` is `None` for two different reasons, and a
            // support engineer needs to tell them apart from the coverage
            // detail alone: the field was absent, or it was present but too
            // large for `u32`. Reporting "does not declare" for a header that
            // plainly declares one sends the reader looking for the wrong thing.
            let declared = u64_field(&header, "schemaVersion");
            let detail = match declared {
                Some(raw) => format!(
                    "capture header declares `schemaVersion` {raw}, which is outside the \
                     representable range for a schema version; records are preserved unreduced"
                ),
                None => "capture header does not declare `schemaVersion`".to_string(),
            };
            self.push_coverage(
                PortalCoverageStatus::UnsupportedSchemaVersion,
                PortalCoverageScope::Capture,
                detail,
                None,
                None,
            );
            return self.into_unsupported(schema_id, None, pending);
        };

        if !is_supported_schema_version(version) {
            self.push_coverage(
                PortalCoverageStatus::UnsupportedSchemaVersion,
                PortalCoverageScope::Capture,
                format!(
                    "capture schema version {version} is outside the supported range \
                     {PORTAL_UNIFIED_LOG_MIN_SUPPORTED_SCHEMA_VERSION}..={PORTAL_UNIFIED_LOG_SCHEMA_VERSION}; \
                     records are preserved unreduced"
                ),
                None,
                None,
            );
            return self.into_unsupported(schema_id, schema_version, pending);
        }

        let capture = build_capture(&header, version);
        self.absorb_declared_stats(&header);
        self.absorb_declared_coverage(&header);

        let mut records = Vec::with_capacity(pending.len());
        let mut seen_sequences: BTreeMap<u64, u64> = BTreeMap::new();

        for (stream_index, obj) in pending.into_iter().enumerate() {
            let stream_index = stream_index as u64;
            let record = build_record(&obj, stream_index);

            match record.timestamp.kind {
                PortalTimestampKind::Local => self.push_coverage(
                    PortalCoverageStatus::DegradedTimestamp,
                    PortalCoverageScope::Record,
                    format!(
                        "record `{}` has wall-clock text with no UTC offset; \
                         it cannot be placed on an absolute timeline",
                        record.record_id
                    ),
                    Some(stream_index),
                    None,
                ),
                PortalTimestampKind::BootRelative => self.push_coverage(
                    PortalCoverageStatus::DegradedTimestamp,
                    PortalCoverageScope::Record,
                    format!(
                        "record `{}` carries boot-relative time only; \
                         wall-clock correlation requires the boot reference",
                        record.record_id
                    ),
                    Some(stream_index),
                    None,
                ),
                PortalTimestampKind::Invalid => self.push_coverage(
                    PortalCoverageStatus::DegradedTimestamp,
                    PortalCoverageScope::Record,
                    format!(
                        "record `{}` has timestamp text that could not be interpreted; \
                         the original text is preserved",
                        record.record_id
                    ),
                    Some(stream_index),
                    None,
                ),
                PortalTimestampKind::Unspecified => self.push_coverage(
                    PortalCoverageStatus::DegradedTimestamp,
                    PortalCoverageScope::Record,
                    format!("record `{}` supplied no timestamp", record.record_id),
                    Some(stream_index),
                    None,
                ),
                PortalTimestampKind::Utc | PortalTimestampKind::Offset => {}
            }

            if let Some(declared) = record.declared_sequence {
                if let Some(first) = seen_sequences.insert(declared, stream_index) {
                    seen_sequences.insert(declared, first);
                    self.push_coverage(
                        PortalCoverageStatus::DuplicateSequence,
                        PortalCoverageScope::Record,
                        format!(
                            "records at stream indexes {first} and {stream_index} both declare \
                             sequence {declared}; both are retained in exact source order"
                        ),
                        Some(stream_index),
                        None,
                    );
                }
            }

            records.push(record);
        }

        self.stats.records_parsed = records.len() as u64;

        PortalUnifiedLogCaptureSet {
            schema_id,
            schema_version,
            supported: true,
            capture: Some(capture),
            records,
            coverage: self.coverage,
            stats: self.stats,
            raw_unsupported: Vec::new(),
        }
    }

    fn into_unsupported(
        self,
        schema_id: Option<String>,
        schema_version: Option<u32>,
        pending: Vec<Map<String, Value>>,
    ) -> PortalUnifiedLogCaptureSet {
        let raw_unsupported = pending.into_iter().map(Value::Object).collect();
        PortalUnifiedLogCaptureSet {
            schema_id,
            schema_version,
            supported: false,
            capture: None,
            records: Vec::new(),
            coverage: self.coverage,
            stats: self.stats,
            raw_unsupported,
        }
    }

    fn absorb_declared_stats(&mut self, header: &Map<String, Value>) {
        let Some(Value::Object(stats)) = header.get("stats") else {
            return;
        };
        self.stats.total_matched = u64_field(stats, "totalMatched");
        self.stats.result_cap = u64_field(stats, "resultCap");
        self.stats.capped = bool_field(stats, "capped").unwrap_or(false);
    }

    fn absorb_declared_coverage(&mut self, header: &Map<String, Value>) {
        let Some(Value::Array(entries)) = header.get("coverage") else {
            return;
        };
        for entry in entries {
            let Value::Object(entry) = entry else {
                // This value came from the capture header, not from a record
                // line, so it is capture-scope coverage and must leave
                // `records_malformed` untouched.
                let excerpt = entry.to_string();
                self.push_malformed_capture_metadata(
                    &excerpt,
                    "capture coverage entry is not a JSON object".to_string(),
                );
                continue;
            };
            let status = match str_field(entry, "status").as_deref() {
                Some("available") => PortalCoverageStatus::Available,
                Some("capped") => PortalCoverageStatus::Capped,
                Some("skipped") => PortalCoverageStatus::Skipped,
                Some("permissionDenied") => PortalCoverageStatus::PermissionDenied,
                Some(other) => {
                    self.push_unknown_schema(format!(
                        "capture coverage entry declares unknown status `{other}`"
                    ));
                    continue;
                }
                None => {
                    self.push_unknown_schema(
                        "capture coverage entry does not declare `status`".to_string(),
                    );
                    continue;
                }
            };
            if status == PortalCoverageStatus::Capped {
                self.stats.capped = true;
            }
            let detail = str_field(entry, "detail").unwrap_or_else(|| {
                "collector reported a coverage state with no detail".to_string()
            });
            self.push_coverage(status, PortalCoverageScope::Capture, detail, None, None);
        }
    }
}

// ---------------------------------------------------------------------------
// Capture metadata
// ---------------------------------------------------------------------------

fn build_capture(header: &Map<String, Value>, version: u32) -> PortalUnifiedLogCapture {
    let predicate = match header.get("predicate") {
        Some(Value::Object(p)) => {
            let text = str_field(p, "predicateText").unwrap_or_default();
            PortalCapturePredicate {
                predicate_id: str_field(p, "predicateId"),
                matches_known_preset: is_known_capture_predicate(&text),
                predicate_text: text,
                // Not `as u32`: silently wrapping an out-of-range version would
                // report a predicate version the capture never declared.
                predicate_version: u64_field(p, "predicateVersion")
                    .and_then(|v| u32::try_from(v).ok()),
            }
        }
        _ => PortalCapturePredicate {
            predicate_id: None,
            predicate_text: String::new(),
            predicate_version: None,
            matches_known_preset: false,
        },
    };

    let window = match header.get("window") {
        Some(Value::Object(w)) => PortalCaptureWindow {
            start: str_field(w, "start").map(|s| normalize_timestamp(&s)),
            end: str_field(w, "end").map(|s| normalize_timestamp(&s)),
            last: str_field(w, "last"),
            timezone_name: str_field(w, "timezoneName"),
        },
        _ => PortalCaptureWindow {
            start: None,
            end: None,
            last: None,
            timezone_name: None,
        },
    };

    let host = match header.get("host") {
        Some(Value::Object(h)) => PortalCaptureHost {
            host_name: str_field(h, "hostName").map(PortalClassifiedString::sensitive),
            os_version: str_field(h, "osVersion"),
            os_build: str_field(h, "osBuild"),
            company_portal_version: str_field(h, "companyPortalVersion"),
            intune_agent_version: str_field(h, "intuneAgentVersion"),
        },
        _ => PortalCaptureHost {
            host_name: None,
            os_version: None,
            os_build: None,
            company_portal_version: None,
            intune_agent_version: None,
        },
    };

    let collector = match header.get("collector") {
        Some(Value::Object(c)) => PortalCollectorInfo {
            name: str_field(c, "name"),
            version: str_field(c, "version"),
        },
        _ => PortalCollectorInfo {
            name: None,
            version: None,
        },
    };

    let redaction = match header.get("redaction") {
        Some(Value::Object(r)) => PortalCaptureRedaction {
            applied: bool_field(r, "applied").unwrap_or(false),
            policy_id: str_field(r, "policyId"),
            placeholder_style: str_field(r, "placeholderStyle"),
        },
        _ => PortalCaptureRedaction::default(),
    };

    PortalUnifiedLogCapture {
        schema_id: PORTAL_UNIFIED_LOG_SCHEMA_ID.to_string(),
        schema_version: version,
        capture_id: str_field(header, "captureId").unwrap_or_else(|| "capture-unnamed".to_string()),
        predicate,
        selection_predicate_version: PORTAL_UNIFIED_LOG_SELECTION_PREDICATE_VERSION,
        window,
        host,
        collector,
        collected_at_utc: str_field(header, "collectedAtUtc"),
        redaction,
    }
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

fn build_record(obj: &Map<String, Value>, stream_index: u64) -> PortalUnifiedLogRecord {
    let process_image_path = str_field(obj, "processImagePath");
    let process = str_field(obj, "process")
        .or_else(|| {
            process_image_path
                .as_deref()
                .map(|path| path.rsplit('/').next().unwrap_or(path).to_string())
        })
        .unwrap_or_default();

    let boot_relative = PortalBootRelativeTime {
        boot_uuid: str_field(obj, "bootUuid"),
        mach_timestamp: u64_field(obj, "machTimestamp"),
        time_since_boot_ns: u64_field(obj, "timeSinceBootNs"),
    };

    let raw_timestamp = str_field(obj, "timestamp").unwrap_or_default();
    let timestamp = if raw_timestamp.trim().is_empty() {
        if boot_relative.mach_timestamp.is_some() || boot_relative.time_since_boot_ns.is_some() {
            PortalTimestamp {
                raw_text: String::new(),
                original_offset: None,
                normalized_utc: None,
                kind: PortalTimestampKind::BootRelative,
            }
        } else {
            PortalTimestamp::unspecified()
        }
    } else {
        normalize_timestamp(&raw_timestamp)
    };

    let raw_message_type = str_field(obj, "messageType").unwrap_or_default();
    let message_type = PortalMessageType {
        level: normalize_level(&raw_message_type),
        raw: raw_message_type,
    };

    let redaction = match obj.get("redaction") {
        Some(Value::Object(r)) => PortalRecordRedaction {
            applied: bool_field(r, "applied").unwrap_or(false),
            redacted_fields: match r.get("redactedFields") {
                Some(Value::Array(items)) => items
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect(),
                _ => Vec::new(),
            },
            policy_id: str_field(r, "policyId"),
        },
        _ => PortalRecordRedaction::default(),
    };

    let unknown_fields: BTreeMap<String, Value> = obj
        .iter()
        .filter(|(key, _)| !KNOWN_RECORD_KEYS.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();

    PortalUnifiedLogRecord {
        record_id: format!("ul-{stream_index:06}"),
        stream_index,
        declared_sequence: u64_field(obj, "sourceSequence"),
        timestamp,
        timezone_name: str_field(obj, "timezoneName"),
        boot_relative: (!boot_relative.is_empty()).then_some(boot_relative),
        process,
        process_image_path: process_image_path.map(PortalClassifiedString::sensitive),
        sender_image_path: str_field(obj, "senderImagePath").map(PortalClassifiedString::sensitive),
        subsystem: str_field(obj, "subsystem"),
        category: str_field(obj, "category"),
        message_type,
        event_message: PortalClassifiedString::sensitive(
            str_field(obj, "eventMessage").unwrap_or_default(),
        ),
        // Not `as u32`: a wrapped pid would silently name a different process.
        process_id: u64_field(obj, "processID")
            .or_else(|| u64_field(obj, "processId"))
            .and_then(|v| u32::try_from(v).ok()),
        thread_id: u64_field(obj, "threadID").or_else(|| u64_field(obj, "threadId")),
        activity: PortalActivityIds {
            activity_id: str_field(obj, "activityIdentifier"),
            parent_activity_id: str_field(obj, "parentActivityIdentifier"),
            signpost_id: str_field(obj, "signpostID").or_else(|| str_field(obj, "signpostId")),
            signpost_name: str_field(obj, "signpostName"),
            signpost_type: str_field(obj, "signpostType"),
            trace_id: str_field(obj, "traceId"),
            request_id: str_field(obj, "requestId"),
            correlation_id: str_field(obj, "correlationId"),
        },
        redaction,
        unknown_fields,
    }
}

/// Maps a unified-log `messageType` onto a normalized level.
pub fn normalize_level(raw: &str) -> PortalUnifiedLogLevel {
    match raw.trim().to_ascii_lowercase().as_str() {
        "debug" => PortalUnifiedLogLevel::Debug,
        "info" => PortalUnifiedLogLevel::Info,
        "default" => PortalUnifiedLogLevel::Default,
        "notice" => PortalUnifiedLogLevel::Notice,
        "warning" | "warn" => PortalUnifiedLogLevel::Warning,
        "error" => PortalUnifiedLogLevel::Error,
        "fault" => PortalUnifiedLogLevel::Fault,
        _ => PortalUnifiedLogLevel::Unknown,
    }
}

/// Normalizes a timestamp while always preserving its original text.
///
/// Accepts the `log show` form (`2026-07-15 07:00:00.123456-0500`) and RFC 3339.
/// Text with no offset stays [`PortalTimestampKind::Local`] and is never
/// silently promoted to UTC.
pub fn normalize_timestamp(raw: &str) -> PortalTimestamp {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return PortalTimestamp::unspecified();
    }

    for format in ["%Y-%m-%d %H:%M:%S%.f%z", "%Y-%m-%dT%H:%M:%S%.f%z"] {
        if let Ok(parsed) = DateTime::parse_from_str(trimmed, format) {
            return from_offset_datetime(raw, parsed);
        }
    }

    if let Ok(parsed) = DateTime::parse_from_rfc3339(trimmed) {
        return from_offset_datetime(raw, parsed);
    }

    for format in ["%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S%.f"] {
        if NaiveDateTime::parse_from_str(trimmed, format).is_ok() {
            return PortalTimestamp {
                raw_text: raw.to_string(),
                original_offset: None,
                normalized_utc: None,
                kind: PortalTimestampKind::Local,
            };
        }
    }

    PortalTimestamp {
        raw_text: raw.to_string(),
        original_offset: None,
        normalized_utc: None,
        kind: PortalTimestampKind::Invalid,
    }
}

fn from_offset_datetime(raw: &str, parsed: DateTime<chrono::FixedOffset>) -> PortalTimestamp {
    let offset_seconds = parsed.offset().local_minus_utc();
    let kind = if offset_seconds == 0 {
        PortalTimestampKind::Utc
    } else {
        PortalTimestampKind::Offset
    };
    PortalTimestamp {
        raw_text: raw.to_string(),
        original_offset: Some(format_offset(offset_seconds)),
        normalized_utc: Some(
            parsed
                .with_timezone(&chrono::Utc)
                .format("%Y-%m-%dT%H:%M:%S%.6fZ")
                .to_string(),
        ),
        kind,
    }
}

fn format_offset(offset_seconds: i32) -> String {
    if offset_seconds == 0 {
        return "Z".to_string();
    }
    let sign = if offset_seconds < 0 { '-' } else { '+' };
    let total = offset_seconds.abs();
    format!("{sign}{:02}:{:02}", total / 3600, (total % 3600) / 60)
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn str_field(obj: &Map<String, Value>, key: &str) -> Option<String> {
    obj.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn u64_field(obj: &Map<String, Value>, key: &str) -> Option<u64> {
    obj.get(key).and_then(Value::as_u64)
}

fn bool_field(obj: &Map<String, Value>, key: &str) -> Option<bool> {
    obj.get(key).and_then(Value::as_bool)
}

fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn truncate_excerpt(raw: &str) -> String {
    if raw.len() <= MAX_RAW_EXCERPT_BYTES {
        return raw.to_string();
    }
    let mut end = MAX_RAW_EXCERPT_BYTES;
    while end > 0 && !raw.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &raw[..end])
}
