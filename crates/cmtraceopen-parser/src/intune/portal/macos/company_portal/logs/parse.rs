//! Logical framing, record construction, coverage accounting, and the
//! `LogEntry`-compatible projection.

use super::classify::classify_component;
use super::detect::detect_company_portal_macos_log;
use super::grammar::{
    activity_id, app_version_support, decode_log_bytes, looks_like_record_start, parse_record_head,
    severity_from_letter, split_physical_lines, version_banner, PortalRecordHead,
};
use super::models::*;
use super::rotation::rotation_member_from_path;
use crate::models::log_entry::{LogEntry, LogFormat, Severity};

impl PortalLogSource {
    /// Describe an artifact by its path. The artifact id defaults to the path
    /// and the encoding to UTF-8; use the builder methods to override either.
    pub fn new(file_path: impl Into<String>) -> Self {
        let file_path = file_path.into();
        Self {
            source_artifact_id: file_path.clone(),
            file_path,
            encoding: PortalEncoding::Utf8,
        }
    }

    pub fn with_source_artifact_id(mut self, source_artifact_id: impl Into<String>) -> Self {
        self.source_artifact_id = source_artifact_id.into();
        self
    }

    pub fn with_encoding(mut self, encoding: PortalEncoding) -> Self {
        self.encoding = encoding;
        self
    }
}

/// A record under construction.
struct PendingRecord {
    state: PortalRecordState,
    head: Option<PortalRecordHead>,
    line_number: u32,
    lines: Vec<String>,
}

/// Parse already-decoded Company Portal macOS log text.
///
/// Records are produced only when detection confirms the artifact is a direct
/// Company Portal app log. For any other source kind the result carries the
/// detection verdict and an `UnsupportedSourceKind` coverage note, and no
/// records are invented. That note is added to whatever coverage was already
/// recorded, so a rejected artifact can also carry `EmptyInput` or, via
/// [`parse_company_portal_macos_log_bytes`], `EncodingFallback`.
pub fn parse_company_portal_macos_log(text: &str, source: &PortalLogSource) -> PortalLogParse {
    parse_with_notes(text, source, Vec::new())
}

/// Decode raw artifact bytes and parse them.
///
/// Encoding is taken from the byte stream (BOM-aware, Windows-1252 fallback) and
/// overrides `source.encoding`.
pub fn parse_company_portal_macos_log_bytes(
    bytes: &[u8],
    source: &PortalLogSource,
) -> PortalLogParse {
    let decoded = decode_log_bytes(bytes);
    let mut notes = Vec::new();
    if decoded.encoding == PortalEncoding::Windows1252Fallback {
        notes.push(PortalCoverageNote {
            kind: PortalCoverageKind::EncodingFallback,
            line_number: None,
            detail: "bytes were not valid UTF-8; decoded as Windows-1252".to_string(),
        });
    }
    if decoded.had_replacement_chars {
        notes.push(PortalCoverageNote {
            kind: PortalCoverageKind::EncodingFallback,
            line_number: None,
            detail: "decoding produced replacement characters; some bytes were undecodable"
                .to_string(),
        });
    }

    let source = source.clone().with_encoding(decoded.encoding);
    parse_with_notes(&decoded.text, &source, notes)
}

fn parse_with_notes(
    text: &str,
    source: &PortalLogSource,
    mut notes: Vec<PortalCoverageNote>,
) -> PortalLogParse {
    let detection = detect_company_portal_macos_log(text, Some(&source.file_path));
    let lines = split_physical_lines(text);
    let total_lines = lines.len() as u32;
    let rotation = rotation_member_from_path(&source.file_path);

    if total_lines == 0 {
        notes.push(PortalCoverageNote {
            kind: PortalCoverageKind::EmptyInput,
            line_number: None,
            detail: "artifact contained no lines".to_string(),
        });
    }

    if detection.source_kind != PortalSourceKind::CompanyPortalMacosAppLog {
        notes.push(PortalCoverageNote {
            kind: PortalCoverageKind::UnsupportedSourceKind,
            line_number: None,
            detail: format!(
                "detected {:?}; {} line(s) left unparsed by this module: {}",
                detection.source_kind,
                total_lines,
                detection.rejections.join("; ")
            ),
        });
        return PortalLogParse {
            schema_version: COMPANY_PORTAL_MACOS_LOG_SCHEMA_VERSION,
            source_artifact_id: source.source_artifact_id.clone(),
            file_path: source.file_path.clone(),
            encoding: source.encoding,
            rotation,
            detection,
            app_version: PortalAppVersion {
                raw_text: None,
                support: PortalVersionSupport::NotDeclared,
                source_line: None,
            },
            records: Vec::new(),
            coverage: PortalCoverage {
                total_lines,
                blank_lines: 0,
                covered_lines: 0,
                record_count: 0,
                parsed_record_count: 0,
                malformed_record_count: 0,
                unframed_record_count: 0,
                continuation_line_count: 0,
                notes,
            },
        };
    }

    let mut records: Vec<PortalLogRecord> = Vec::new();
    let mut pending: Option<PendingRecord> = None;
    let mut blank_lines: u32 = 0;
    let mut continuation_line_count: u32 = 0;
    let mut app_version = PortalAppVersion {
        raw_text: None,
        support: PortalVersionSupport::NotDeclared,
        source_line: None,
    };

    for (index, line) in lines.iter().enumerate() {
        let line_number = (index + 1) as u32;

        if let Some(head) = parse_record_head(line) {
            close_record(
                &mut pending,
                &mut records,
                &mut blank_lines,
                &mut continuation_line_count,
                source,
            );
            if app_version.raw_text.is_none() {
                if let Some(raw) = version_banner(&head.message) {
                    app_version = PortalAppVersion {
                        support: app_version_support(&raw),
                        raw_text: Some(raw),
                        source_line: Some(line_number),
                    };
                }
            }
            pending = Some(PendingRecord {
                state: PortalRecordState::Parsed,
                head: Some(head),
                line_number,
                lines: vec![(*line).to_string()],
            });
            continue;
        }

        if looks_like_record_start(line) {
            close_record(
                &mut pending,
                &mut records,
                &mut blank_lines,
                &mut continuation_line_count,
                source,
            );
            pending = Some(PendingRecord {
                state: PortalRecordState::Malformed,
                head: None,
                line_number,
                lines: vec![(*line).to_string()],
            });
            continue;
        }

        match pending.as_mut() {
            Some(open) => open.lines.push((*line).to_string()),
            None => {
                if line.trim().is_empty() {
                    blank_lines += 1;
                } else {
                    pending = Some(PendingRecord {
                        state: PortalRecordState::Unframed,
                        head: None,
                        line_number,
                        lines: vec![(*line).to_string()],
                    });
                }
            }
        }
    }
    close_record(
        &mut pending,
        &mut records,
        &mut blank_lines,
        &mut continuation_line_count,
        source,
    );

    for record in &records {
        match record.state {
            PortalRecordState::Malformed => notes.push(PortalCoverageNote {
                kind: PortalCoverageKind::MalformedRecord,
                line_number: Some(record.line_number),
                detail: "line starts a record but does not satisfy the record grammar; text preserved verbatim"
                    .to_string(),
            }),
            PortalRecordState::Unframed => notes.push(PortalCoverageNote {
                kind: PortalCoverageKind::UnframedLeadingText,
                line_number: Some(record.line_number),
                detail: "continuation text with no preceding record head; text preserved verbatim"
                    .to_string(),
            }),
            PortalRecordState::Parsed => {}
        }
    }

    match app_version.support {
        PortalVersionSupport::Unknown => notes.push(PortalCoverageNote {
            kind: PortalCoverageKind::UnknownAppVersion,
            line_number: app_version.source_line,
            detail: format!(
                "app version {} is outside the fixture-validated families {:?}; records parsed but reported as low confidence",
                app_version.raw_text.clone().unwrap_or_default(),
                VALIDATED_APP_VERSION_FAMILIES
            ),
        }),
        PortalVersionSupport::NotDeclared => notes.push(PortalCoverageNote {
            kind: PortalCoverageKind::MissingVersionBanner,
            line_number: None,
            detail: "artifact declares no Company Portal version banner".to_string(),
        }),
        PortalVersionSupport::Validated => {}
    }

    if detection.confidence == PortalDetectionConfidence::Low {
        notes.push(PortalCoverageNote {
            kind: PortalCoverageKind::LowConfidenceStructure,
            line_number: None,
            detail: format!(
                "{} of {} record starts satisfied the grammar",
                detection.record_head_lines, detection.record_start_lines
            ),
        });
    }

    let parsed_record_count = count_state(&records, PortalRecordState::Parsed);
    let malformed_record_count = count_state(&records, PortalRecordState::Malformed);
    let unframed_record_count = count_state(&records, PortalRecordState::Unframed);
    let covered_lines: u32 =
        records.iter().map(|record| record.line_span).sum::<u32>() + blank_lines;

    PortalLogParse {
        schema_version: COMPANY_PORTAL_MACOS_LOG_SCHEMA_VERSION,
        source_artifact_id: source.source_artifact_id.clone(),
        file_path: source.file_path.clone(),
        encoding: source.encoding,
        rotation,
        detection,
        app_version,
        coverage: PortalCoverage {
            total_lines,
            blank_lines,
            covered_lines,
            record_count: records.len() as u32,
            parsed_record_count,
            malformed_record_count,
            unframed_record_count,
            continuation_line_count,
            notes,
        },
        records,
    }
}

fn count_state(records: &[PortalLogRecord], state: PortalRecordState) -> u32 {
    records
        .iter()
        .filter(|record| record.state == state)
        .count() as u32
}

fn close_record(
    pending: &mut Option<PendingRecord>,
    records: &mut Vec<PortalLogRecord>,
    blank_lines: &mut u32,
    continuation_line_count: &mut u32,
    source: &PortalLogSource,
) {
    let Some(mut open) = pending.take() else {
        return;
    };

    // Trailing blank lines belong to the file, not to the record.
    while open.lines.len() > 1 && open.lines.last().is_some_and(|line| line.trim().is_empty()) {
        open.lines.pop();
        *blank_lines += 1;
    }
    *continuation_line_count += (open.lines.len() - 1) as u32;

    let record_index = records.len() as u64;
    let raw_text = open.lines.join("\n");
    let continuation_text = if open.lines.len() > 1 {
        Some(open.lines[1..].join("\n"))
    } else {
        None
    };

    let record = match open.head {
        Some(head) => {
            let message = match continuation_text {
                Some(rest) => format!("{}\n{}", head.message, rest),
                None => head.message.clone(),
            };
            PortalLogRecord {
                record_index,
                line_number: open.line_number,
                line_span: open.lines.len() as u32,
                state: PortalRecordState::Parsed,
                timestamp: Some(PortalTimestamp {
                    raw_text: head.raw_timestamp.clone(),
                    original_offset: None,
                    normalized_utc: None,
                    kind: PortalTimestampKind::Local,
                }),
                severity_letter: Some(head.severity_letter.clone()),
                severity: severity_from_letter(&head.severity_letter),
                process: Some(head.process.clone()),
                component: Some(head.component.clone()),
                thread_id: head.thread_id,
                activity_id: activity_id(&head.message).map(PortalClassifiedString::sensitive),
                message: PortalClassifiedString::sensitive(message),
                raw_text: PortalClassifiedString::sensitive(raw_text),
                category: classify_component(Some(head.component.as_str())),
                evidence_ref: evidence_ref(source, record_index),
            }
        }
        None => PortalLogRecord {
            record_index,
            line_number: open.line_number,
            line_span: open.lines.len() as u32,
            state: open.state,
            timestamp: None,
            severity_letter: None,
            // No structural severity field exists here, and message text is
            // never sniffed, so the neutral default is used.
            severity: Severity::Info,
            process: None,
            component: None,
            thread_id: None,
            activity_id: None,
            message: PortalClassifiedString::sensitive(raw_text.clone()),
            raw_text: PortalClassifiedString::sensitive(raw_text),
            category: PortalEvidenceCategory::Generic,
            evidence_ref: evidence_ref(source, record_index),
        },
    };

    records.push(record);
}

fn evidence_ref(source: &PortalLogSource, record_index: u64) -> PortalEvidenceRef {
    PortalEvidenceRef {
        evidence_id: format!("cp-macos-log-r{record_index:06}"),
        source_artifact_id: source.source_artifact_id.clone(),
    }
}

/// Project a parse into `LogEntry` values for the shared log view.
///
/// Field mapping mirrors [`crate::parser::intune_macos`] so Company Portal logs
/// render consistently with other macOS Intune logs: the structural process
/// field becomes `component`, and the structural component field becomes
/// `source_file`. Timestamps are wall-clock local with no offset in the source
/// and are treated as UTC for the sort key, exactly as the generic parser does.
pub fn to_log_entries(parse: &PortalLogParse) -> Vec<LogEntry> {
    parse
        .records
        .iter()
        .enumerate()
        .map(|(index, record)| {
            let mut entry = empty_log_entry(index as u64, record.line_number, &parse.file_path);
            match record.state {
                PortalRecordState::Parsed => {
                    entry.message = record.message.value.clone();
                    entry.component = record.process.clone();
                    entry.source_file = record.component.clone();
                    entry.severity = record.severity;
                    entry.thread = record.thread_id;
                    entry.thread_display = record
                        .thread_id
                        .map(crate::parser::ccm::format_thread_display);
                    entry.timestamp = record
                        .timestamp
                        .as_ref()
                        .and_then(|ts| timestamp_millis(&ts.raw_text));
                    entry.timestamp_display = record
                        .timestamp
                        .as_ref()
                        .map(|timestamp| display_timestamp(&timestamp.raw_text));
                    entry.format = LogFormat::Timestamped;
                }
                PortalRecordState::Malformed | PortalRecordState::Unframed => {
                    entry.message = record.raw_text.value.clone();
                    entry.severity = Severity::Info;
                    entry.format = LogFormat::Plain;
                }
            }
            entry
        })
        .collect()
}

/// `YYYY-MM-DD HH:MM:SS:mmm` (source form) to `YYYY-MM-DD HH:MM:SS.mmm`
/// (display form used by the other timestamped parsers).
fn display_timestamp(raw: &str) -> String {
    match raw.rfind(':') {
        Some(position) => format!("{}.{}", &raw[..position], &raw[position + 1..]),
        None => raw.to_string(),
    }
}

fn timestamp_millis(raw_timestamp: &str) -> Option<i64> {
    chrono::NaiveDateTime::parse_from_str(raw_timestamp, "%Y-%m-%d %H:%M:%S:%3f")
        .ok()
        .map(|dt| dt.and_utc().timestamp_millis())
}

fn empty_log_entry(id: u64, line_number: u32, file_path: &str) -> LogEntry {
    LogEntry {
        id,
        line_number,
        message: String::new(),
        component: None,
        timestamp: None,
        timestamp_display: None,
        severity: Severity::Info,
        thread: None,
        thread_display: None,
        source_file: None,
        format: LogFormat::Plain,
        file_path: file_path.to_string(),
        timezone_offset: None,
        error_code_spans: Vec::new(),
        ip_address: None,
        host_name: None,
        mac_address: None,
        result_code: None,
        gle_code: None,
        setup_phase: None,
        operation_name: None,
        http_method: None,
        uri_stem: None,
        uri_query: None,
        status_code: None,
        sub_status: None,
        time_taken_ms: None,
        client_ip: None,
        server_ip: None,
        user_agent: None,
        server_port: None,
        username: None,
        win32_status: None,
        query_name: None,
        query_type: None,
        response_code: None,
        dns_direction: None,
        dns_protocol: None,
        source_ip: None,
        dns_flags: None,
        dns_event_id: None,
        zone_name: None,
        entry_kind: None,
        whatif: None,
        section_name: None,
        section_color: None,
        iteration: None,
        tags: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE_PATH: &str = "/Users/x/Library/Logs/CompanyPortal/CompanyPortal.log";

    fn parse(text: &str) -> PortalLogParse {
        parse_company_portal_macos_log(text, &PortalLogSource::new(SOURCE_PATH))
    }

    #[test]
    fn continuations_attach_to_the_previous_record() {
        let text = "2026-05-12 08:15:02:900 | CompanyPortal | E | 1 | AppCatalogViewModel | failed\npayload line\n2026-05-12 08:15:03:010 | CompanyPortal | I | 1 | AppCatalogViewModel | retry\n";
        let parse = parse(text);
        assert_eq!(parse.records.len(), 2);
        assert_eq!(parse.records[0].line_span, 2);
        assert_eq!(parse.records[0].message.value, "failed\npayload line");
        assert_eq!(parse.coverage.continuation_line_count, 1);
        assert_eq!(parse.coverage.covered_lines, parse.coverage.total_lines);
    }

    #[test]
    fn every_line_is_accounted_for() {
        let text = "orphan continuation\n\n2026-05-12 08:16:00:120 | CompanyPortal | I | 1 | DeviceActionManager | ok\n2026-05-12 08:16:01:4 | CompanyPortal | I | 2\n";
        let parse = parse(text);
        assert_eq!(parse.coverage.total_lines, 4);
        assert_eq!(parse.coverage.covered_lines, 4);
        assert_eq!(parse.coverage.unframed_record_count, 1);
        assert_eq!(parse.coverage.malformed_record_count, 1);
        assert_eq!(parse.coverage.blank_lines, 1);
    }

    #[test]
    fn rejected_sources_produce_no_records() {
        let text = "2026-05-12 08:14:20:104 | IntuneMdmAgent | I | 1 | SyncActivityTracer | requested by CompanyPortal\n";
        let parse = parse(text);
        assert!(parse.records.is_empty());
        assert_eq!(parse.coverage.covered_lines, 0);
        assert!(parse
            .coverage
            .notes
            .iter()
            .any(|note| note.kind == PortalCoverageKind::UnsupportedSourceKind));
    }

    #[test]
    fn log_entries_mirror_the_generic_field_mapping() {
        let text =
            "2026-05-12 08:14:20:104 | CompanyPortal | E | 261481 | EnrollmentManager | boom\n";
        let parse = parse(text);
        let entries = to_log_entries(&parse);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].component.as_deref(), Some("CompanyPortal"));
        assert_eq!(entries[0].source_file.as_deref(), Some("EnrollmentManager"));
        assert_eq!(entries[0].severity, Severity::Error);
        assert_eq!(entries[0].thread, Some(261481));
        assert_eq!(
            entries[0].timestamp_display.as_deref(),
            Some("2026-05-12 08:14:20.104")
        );
        assert!(entries[0].timestamp.is_some());
    }
}
