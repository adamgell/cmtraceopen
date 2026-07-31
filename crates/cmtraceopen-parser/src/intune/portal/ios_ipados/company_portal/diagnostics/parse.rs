//! Detection and parsing of an imported Console plain-text export.
//!
//! # Record framing
//!
//! A record starts at a physical line that anchors on the timestamp column. Every following
//! line that does not anchor is a *continuation* of the current record: Console renders
//! multi-line payloads (exception backtraces, JSON bodies) as additional unprefixed lines.
//! Continuations are folded into the record message, counted, and covered by the record's
//! line span, so the mapping back to the source stays exact.
//!
//! # Conservative failure
//!
//! * unknown header layout -> records are preserved verbatim and marked
//!   [`PortalConsoleParseState::Unsupported`]; columns are not guessed;
//! * anchored line that fails column or timestamp validation ->
//!   [`PortalConsoleParseState::Malformed`], preserved, never attributed to Company Portal;
//! * copy boundaries -> [`PortalConsoleParseState::Truncated`] plus a coverage entry.

use std::sync::OnceLock;

use chrono::{DateTime, FixedOffset, NaiveDateTime, Utc};
use regex::Regex;

use super::classify::{classify_semantics, classify_source, parse_version_banner};
use super::layout::{
    detect_decimal_separator, registered_columns, resolve_header, HeaderResolution,
    FALLBACK_LAYOUT_ID,
};
use super::models::*;

/// Default artifact id used when the caller does not supply one.
pub const DEFAULT_SOURCE_ARTIFACT_ID: &str = "ios-console-export";

/// Fraction of non-empty lines that must anchor before header-less text is accepted as a
/// degraded Console export.
const HEADERLESS_ANCHOR_RATIO: f64 = 0.9;

// ---------------------------------------------------------------------------
// Line-level patterns
// ---------------------------------------------------------------------------

/// Loose record-start anchor.
///
/// Intentionally permissive so that a line with a *bad* timestamp still anchors as a record
/// and is reported as malformed, rather than being silently swallowed as a continuation of
/// the previous record.
fn anchor_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"^\d{4}-\d{2}-\d{2} \d{1,2}:\d{2}").expect("record anchor pattern must compile")
    })
}

/// Strict timestamp column grammar, with an optional numeric offset.
fn timestamp_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r"^(?P<naive>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[.,]\d{1,9})(?P<offset>[+-]\d{4})?",
        )
        .expect("timestamp column pattern must compile")
    })
}

/// The Apple message-body sub-grammar:
/// `Process: (Library) [subsystem:category] text`, where library and the bracketed pair are
/// both optional.
fn message_body_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r"^(?P<process>[^\s:]+): (?:\((?P<library>[^)]*)\) )?(?:\[(?P<subsystem>[^:\]]+):(?P<category>[^\]]+)\] )?(?P<text>.*)$",
        )
        .expect("message body pattern must compile")
    })
}

fn hex_id_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r"^0x[0-9a-fA-F]+").expect("hex id pattern must compile"))
}

fn word_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r"^[A-Za-z]+").expect("word pattern must compile"))
}

fn decimal_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r"^\d+").expect("decimal pattern must compile"))
}

fn token_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r"^\S+").expect("token pattern must compile"))
}

fn is_anchor(line: &str) -> bool {
    anchor_pattern().is_match(line)
}

/// Whether a line satisfies the whole default-layout column grammar with a valid instant.
///
/// Used only for header-less detection, where there is no header to confirm the shape.
fn matches_default_record_grammar(line: &str) -> bool {
    let Some(columns) = registered_columns(FALLBACK_LAYOUT_ID) else {
        return false;
    };
    let Some(extracted) = extract_columns(line, &columns) else {
        return false;
    };
    let timestamp = normalize_timestamp(
        extracted.timestamp_text.as_deref(),
        PortalConsoleDecimalSeparator::Dot,
    );
    !matches!(
        timestamp.kind,
        PortalTimestampKind::Invalid | PortalTimestampKind::Unknown
    )
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

/// Decide whether `content` is a Console plain-text export this module can parse.
///
/// Detection is content-structural. A path hint may select this parser as a candidate, but
/// only the header row plus record grammar confirm it.
pub fn detect_console_export(content: &str) -> PortalConsoleDetection {
    let lines: Vec<&str> = content.lines().collect();
    let Some((header_index, header_line)) = lines
        .iter()
        .enumerate()
        .find(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| (index, *line))
    else {
        return PortalConsoleDetection {
            outcome: PortalConsoleDetectionOutcome::NotConsoleExport,
            layout: None,
            reason: "input is empty".to_string(),
        };
    };

    let body: Vec<&str> = lines[header_index + 1..].to_vec();

    match resolve_header(header_line) {
        HeaderResolution::Registered {
            layout_id,
            columns,
            locale_hint,
        } => {
            if !body.iter().any(|line| is_anchor(line)) {
                return PortalConsoleDetection {
                    outcome: PortalConsoleDetectionOutcome::NotConsoleExport,
                    layout: None,
                    reason: "Console header row is present but no record anchors follow it"
                        .to_string(),
                };
            }
            PortalConsoleDetection {
                outcome: PortalConsoleDetectionOutcome::Supported,
                layout: Some(PortalConsoleLayout {
                    layout_id: layout_id.to_string(),
                    header_raw: header_line.to_string(),
                    columns,
                    decimal_separator: detect_decimal_separator(&body),
                    locale_hint,
                }),
                reason: format!("registered Console layout {layout_id}"),
            }
        }
        HeaderResolution::Unregistered { detail } => PortalConsoleDetection {
            outcome: PortalConsoleDetectionOutcome::UnsupportedLayout,
            layout: None,
            reason: detail,
        },
        HeaderResolution::NotAHeader => detect_headerless(&lines),
    }
}

/// Console-shaped records with no header row.
///
/// The documented workflow copies the header, so this is a degraded path: records are still
/// parsed with the default layout but the capture is reported as an unsupported layout so no
/// caller mistakes it for a confirmed export shape.
fn detect_headerless(lines: &[&str]) -> PortalConsoleDetection {
    let non_empty: Vec<&&str> = lines
        .iter()
        .filter(|line| !line.trim().is_empty())
        .collect();
    if non_empty.is_empty() {
        return PortalConsoleDetection {
            outcome: PortalConsoleDetectionOutcome::NotConsoleExport,
            layout: None,
            reason: "input is empty".to_string(),
        };
    }

    // The loose anchor is far too permissive to stand in for a header: plenty of ordinary
    // application logs start with `YYYY-MM-DD HH:MM`. Without a header row the *full*
    // default-layout column grammar must hold, otherwise this is not a Console export.
    let anchored = non_empty
        .iter()
        .filter(|line| matches_default_record_grammar(line))
        .count();
    let ratio = anchored as f64 / non_empty.len() as f64;

    if anchored == 0 || ratio < HEADERLESS_ANCHOR_RATIO {
        return PortalConsoleDetection {
            outcome: PortalConsoleDetectionOutcome::NotConsoleExport,
            layout: None,
            reason: "no Console header row and too few Console-shaped records".to_string(),
        };
    }

    let body: Vec<&str> = lines.to_vec();
    PortalConsoleDetection {
        outcome: PortalConsoleDetectionOutcome::UnsupportedLayout,
        layout: Some(PortalConsoleLayout {
            layout_id: FALLBACK_LAYOUT_ID.to_string(),
            header_raw: String::new(),
            columns: registered_columns(FALLBACK_LAYOUT_ID).unwrap_or_default(),
            decimal_separator: detect_decimal_separator(&body),
            locale_hint: None,
        }),
        reason: "Console-shaped records without a header row; assuming the default layout"
            .to_string(),
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse an imported Console plain-text export with the default artifact id.
pub fn parse_console_export(content: &str) -> PortalConsoleCapture {
    parse_console_export_with_artifact_id(content, DEFAULT_SOURCE_ARTIFACT_ID)
}

/// Parse an imported Console plain-text export, tagging evidence with `source_artifact_id`.
pub fn parse_console_export_with_artifact_id(
    content: &str,
    source_artifact_id: &str,
) -> PortalConsoleCapture {
    let detection = detect_console_export(content);
    let lines: Vec<&str> = content.lines().collect();
    let source_lines = lines.len();

    let mut capture = PortalConsoleCapture {
        schema_version: PORTAL_IOS_CONSOLE_SCHEMA_VERSION,
        source_artifact_id: source_artifact_id.to_string(),
        layout: detection.layout.clone(),
        detection: detection.clone(),
        ordering: PortalConsoleOrdering {
            confidence: PortalOrderingConfidence::Unordered,
            records_without_offset: 0,
            detail: "no parsed records".to_string(),
        },
        versions: PortalConsoleCaptureVersions {
            state: PortalConsoleVersionState::Unknown,
            company_portal_version: None,
            os_version: None,
            evidence: None,
        },
        records: Vec::new(),
        coverage: Vec::new(),
        totals: PortalConsoleTotals {
            source_lines,
            total_records: 0,
            company_portal_records: 0,
            other_process_records: 0,
            unattributed_records: 0,
            malformed_records: 0,
            truncated_records: 0,
        },
    };

    if detection.outcome == PortalConsoleDetectionOutcome::NotConsoleExport {
        return capture;
    }

    // Where the record body starts. A header-*shaped* first line is skipped even when its
    // layout is unregistered, because it is still a header and not record data.
    let header_index = lines
        .iter()
        .position(|line| !line.trim().is_empty())
        .filter(|&index| !matches!(resolve_header(lines[index]), HeaderResolution::NotAHeader));

    if header_index.is_none()
        && detection.outcome == PortalConsoleDetectionOutcome::UnsupportedLayout
    {
        capture.coverage.push(PortalConsoleCoverage {
            kind: PortalConsoleCoverageKind::HeaderMissing,
            first_line_number: 1,
            last_line_number: source_lines.max(1),
            detail: detection.reason.clone(),
            raw_text: String::new(),
        });
    }

    // An unregistered header means the column order is unknown, so columns are deliberately
    // not interpreted. Records are still framed and preserved losslessly.
    let layout_columns = capture
        .layout
        .as_ref()
        .map(|layout| layout.columns.clone())
        .unwrap_or_default();
    let interpret_columns = !layout_columns.is_empty();

    if !interpret_columns {
        capture.coverage.push(PortalConsoleCoverage {
            kind: PortalConsoleCoverageKind::UnsupportedLayout,
            first_line_number: 1,
            last_line_number: source_lines.max(1),
            detail: detection.reason.clone(),
            // An unregistered header leaves `detection.layout` and `capture.layout` both
            // `None`, so this entry is the only place the header row can survive. Discarding
            // it would drop the one input line that explains why the layout is unsupported,
            // which is exactly what coverage exists to prevent.
            raw_text: header_index
                .map(|index| lines[index].to_string())
                .unwrap_or_default(),
        });
    }

    let decimal_separator = capture
        .layout
        .as_ref()
        .map(|layout| layout.decimal_separator)
        .unwrap_or(PortalConsoleDecimalSeparator::Dot);

    let body_start = header_index.map_or(0, |index| index + 1);
    let ends_without_newline = !content.is_empty() && !content.ends_with('\n');

    let frames = frame_records(&lines, body_start);

    // Lines before the first anchor are the tail of a record whose start was not copied.
    if let Some(leading) = &frames.leading {
        capture.coverage.push(PortalConsoleCoverage {
            kind: PortalConsoleCoverageKind::TruncatedLeading,
            first_line_number: leading.first_line_number,
            last_line_number: leading.last_line_number,
            detail: "capture begins part-way through a record; the record start was not copied"
                .to_string(),
            raw_text: leading.raw_text.clone(),
        });
    }

    let frame_count = frames.records.len();
    for (record_index, frame) in frames.records.into_iter().enumerate() {
        let is_last = record_index + 1 == frame_count;
        let record = build_record(
            record_index,
            &frame,
            &layout_columns,
            interpret_columns,
            decimal_separator,
            source_artifact_id,
            is_last && ends_without_newline,
        );

        match record.parse_state {
            PortalConsoleParseState::Malformed => capture.coverage.push(PortalConsoleCoverage {
                kind: PortalConsoleCoverageKind::MalformedRecord,
                first_line_number: record.reference.first_line_number,
                last_line_number: record.reference.last_line_number,
                detail: "record anchored on the timestamp column but failed column validation"
                    .to_string(),
                raw_text: record.raw_text.clone(),
            }),
            PortalConsoleParseState::Truncated => capture.coverage.push(PortalConsoleCoverage {
                kind: PortalConsoleCoverageKind::TruncatedTrailing,
                first_line_number: record.reference.first_line_number,
                last_line_number: record.reference.last_line_number,
                detail: "capture ends part-way through a record; the record end was not copied"
                    .to_string(),
                raw_text: record.raw_text.clone(),
            }),
            _ => {}
        }

        capture.records.push(record);
    }

    apply_versions(&mut capture);
    apply_ordering(&mut capture);
    apply_totals(&mut capture);

    capture
}

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

struct Frame {
    first_line_number: usize,
    last_line_number: usize,
    head: String,
    continuations: Vec<String>,
    raw_text: String,
}

struct Frames {
    leading: Option<Frame>,
    records: Vec<Frame>,
}

/// Group physical lines into records: one anchored head line plus its continuations.
fn frame_records(lines: &[&str], body_start: usize) -> Frames {
    let mut leading: Option<Frame> = None;
    let mut records: Vec<Frame> = Vec::new();
    let mut current: Option<Frame> = None;
    let mut orphan: Vec<(usize, String)> = Vec::new();

    for (offset, line) in lines.iter().enumerate().skip(body_start) {
        let line_number = offset + 1;

        if is_anchor(line) {
            if let Some(frame) = current.take() {
                records.push(frame);
            }
            current = Some(Frame {
                first_line_number: line_number,
                last_line_number: line_number,
                head: (*line).to_string(),
                continuations: Vec::new(),
                raw_text: (*line).to_string(),
            });
            continue;
        }

        // Blank lines are copy artefacts. They neither terminate a record nor join it, so a
        // blank line inside a multi-line payload cannot split that payload into two records.
        // `totals.source_lines` still counts them, so nothing is hidden.
        if line.trim().is_empty() {
            continue;
        }

        match current.as_mut() {
            Some(frame) => {
                frame.last_line_number = line_number;
                frame.continuations.push((*line).to_string());
                frame.raw_text.push('\n');
                frame.raw_text.push_str(line);
            }
            // Only reachable before the first anchor, so these lines are always the tail of
            // a record whose start was not copied.
            None => orphan.push((line_number, (*line).to_string())),
        }
    }

    if let Some(frame) = current.take() {
        records.push(frame);
    }

    if !orphan.is_empty() {
        let first_line_number = orphan[0].0;
        let last_line_number = orphan[orphan.len() - 1].0;
        let raw_text = orphan
            .iter()
            .map(|(_, text)| text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        leading = Some(Frame {
            first_line_number,
            last_line_number,
            head: String::new(),
            continuations: Vec::new(),
            raw_text,
        });
    }

    Frames { leading, records }
}

// ---------------------------------------------------------------------------
// Column extraction
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Columns {
    timestamp_text: Option<String>,
    thread_id: Option<String>,
    level_raw: Option<String>,
    activity_id: Option<String>,
    pid: Option<u32>,
    ttl: Option<u32>,
    subsystem: Option<String>,
    category: Option<String>,
    process: Option<String>,
    library: Option<String>,
    message: String,
}

/// Consume the head line column by column, in the order the layout declares.
///
/// Returns `None` as soon as a column fails its grammar, which is what turns a bad line into
/// a malformed record instead of a silently mis-shifted one.
fn extract_columns(head: &str, layout: &[PortalConsoleColumn]) -> Option<Columns> {
    let mut rest = head;
    let mut columns = Columns::default();

    for (index, column) in layout.iter().enumerate() {
        rest = rest.trim_start();
        let is_last = index + 1 == layout.len();

        match column {
            PortalConsoleColumn::Timestamp => {
                let matched = timestamp_pattern().find(rest)?;
                columns.timestamp_text = Some(matched.as_str().to_string());
                rest = &rest[matched.end()..];
            }
            PortalConsoleColumn::Thread => {
                let matched = hex_id_pattern().find(rest)?;
                columns.thread_id = Some(matched.as_str().to_string());
                rest = &rest[matched.end()..];
            }
            PortalConsoleColumn::Type => {
                let matched = word_pattern().find(rest)?;
                columns.level_raw = Some(matched.as_str().to_string());
                rest = &rest[matched.end()..];
            }
            PortalConsoleColumn::Activity => {
                let matched = hex_id_pattern().find(rest)?;
                columns.activity_id = Some(matched.as_str().to_string());
                rest = &rest[matched.end()..];
            }
            PortalConsoleColumn::Pid => {
                let matched = decimal_pattern().find(rest)?;
                columns.pid = matched.as_str().parse().ok();
                columns.pid?;
                rest = &rest[matched.end()..];
            }
            PortalConsoleColumn::Ttl => {
                let matched = decimal_pattern().find(rest)?;
                columns.ttl = matched.as_str().parse().ok();
                columns.ttl?;
                rest = &rest[matched.end()..];
            }
            PortalConsoleColumn::Subsystem => {
                let matched = token_pattern().find(rest)?;
                columns.subsystem = Some(matched.as_str().to_string());
                rest = &rest[matched.end()..];
            }
            PortalConsoleColumn::Category => {
                let matched = token_pattern().find(rest)?;
                columns.category = Some(matched.as_str().to_string());
                rest = &rest[matched.end()..];
            }
            PortalConsoleColumn::Process => {
                let matched = token_pattern().find(rest)?;
                columns.process = Some(matched.as_str().to_string());
                rest = &rest[matched.end()..];
            }
            PortalConsoleColumn::Library => {
                let matched = token_pattern().find(rest)?;
                columns.library = Some(matched.as_str().to_string());
                rest = &rest[matched.end()..];
            }
            PortalConsoleColumn::Message => {
                columns.message = rest.to_string();
                rest = "";
            }
        }

        if is_last && !rest.is_empty() {
            // Whatever the layout did not name is still message text.
            columns.message = rest.trim_start().to_string();
        }
    }

    // Split the Apple message body sub-grammar. Explicit columns always win over values
    // recovered from the body.
    if let Some(captures) = message_body_pattern().captures(&columns.message.clone()) {
        columns
            .process
            .get_or_insert_with(|| captures["process"].to_string());
        if let Some(library) = captures.name("library") {
            columns
                .library
                .get_or_insert_with(|| library.as_str().to_string());
        }
        if let Some(subsystem) = captures.name("subsystem") {
            columns
                .subsystem
                .get_or_insert_with(|| subsystem.as_str().to_string());
        }
        if let Some(category) = captures.name("category") {
            columns
                .category
                .get_or_insert_with(|| category.as_str().to_string());
        }
        columns.message = captures["text"].to_string();
    }

    Some(columns)
}

// ---------------------------------------------------------------------------
// Record construction
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn build_record(
    record_index: usize,
    frame: &Frame,
    layout: &[PortalConsoleColumn],
    interpret_columns: bool,
    decimal_separator: PortalConsoleDecimalSeparator,
    source_artifact_id: &str,
    may_be_truncated: bool,
) -> PortalConsoleRecord {
    let reference = PortalConsoleRecordRef {
        record_index,
        first_line_number: frame.first_line_number,
        last_line_number: frame.last_line_number,
        evidence_ref: PortalEvidenceRef {
            evidence_id: format!("ios-console-record-{record_index:06}"),
            source_artifact_id: source_artifact_id.to_string(),
        },
    };

    let unparsed = |state: PortalConsoleParseState| PortalConsoleRecord {
        reference: reference.clone(),
        timestamp: PortalTimestamp {
            raw_text: frame.head.clone(),
            original_offset: None,
            normalized_utc: None,
            kind: PortalTimestampKind::Invalid,
        },
        thread_id: None,
        activity_id: None,
        pid: None,
        ttl: None,
        level: PortalConsoleLevel {
            raw: String::new(),
            normalized: PortalConsoleSeverity::Unknown,
        },
        source: PortalConsoleSource {
            process: None,
            library: None,
            subsystem: None,
            category: None,
            class: PortalConsoleSourceClass::Unattributed,
            signature: PortalConsoleSourceSignature::None,
        },
        message: PortalClassifiedString {
            value: frame.raw_text.clone(),
            sensitivity: PortalSensitivity::Sensitive,
        },
        continuation_line_count: frame.continuations.len(),
        parse_state: state,
        semantic: None,
        raw_text: frame.raw_text.clone(),
    };

    if !interpret_columns {
        return unparsed(PortalConsoleParseState::Unsupported);
    }

    let Some(columns) = extract_columns(&frame.head, layout) else {
        return unparsed(if may_be_truncated {
            PortalConsoleParseState::Truncated
        } else {
            PortalConsoleParseState::Malformed
        });
    };

    let timestamp = normalize_timestamp(columns.timestamp_text.as_deref(), decimal_separator);
    if timestamp.kind == PortalTimestampKind::Invalid {
        let mut record = unparsed(if may_be_truncated {
            PortalConsoleParseState::Truncated
        } else {
            PortalConsoleParseState::Malformed
        });
        record.timestamp = timestamp;
        return record;
    }

    let (class, signature) =
        classify_source(columns.process.as_deref(), columns.subsystem.as_deref());

    // Continuations belong to the record message verbatim.
    let mut message = columns.message.clone();
    for continuation in &frame.continuations {
        message.push('\n');
        message.push_str(continuation);
    }

    let semantic = classify_semantics(&class, columns.category.as_deref(), false);

    PortalConsoleRecord {
        reference,
        timestamp,
        thread_id: columns.thread_id,
        activity_id: columns.activity_id,
        pid: columns.pid,
        ttl: columns.ttl,
        level: normalize_level(columns.level_raw.as_deref()),
        source: PortalConsoleSource {
            process: columns.process,
            library: columns.library,
            subsystem: columns.subsystem,
            category: columns.category,
            class,
            signature,
        },
        message: PortalClassifiedString {
            value: message,
            sensitivity: PortalSensitivity::Sensitive,
        },
        continuation_line_count: frame.continuations.len(),
        parse_state: PortalConsoleParseState::Parsed,
        semantic,
        raw_text: frame.raw_text.clone(),
    }
}

fn normalize_level(raw: Option<&str>) -> PortalConsoleLevel {
    let raw = raw.unwrap_or_default();
    let normalized = match raw {
        "Debug" => PortalConsoleSeverity::Debug,
        "Info" => PortalConsoleSeverity::Info,
        "Default" => PortalConsoleSeverity::Default,
        "Error" => PortalConsoleSeverity::Error,
        "Fault" => PortalConsoleSeverity::Fault,
        "Activity" => PortalConsoleSeverity::Activity,
        _ => PortalConsoleSeverity::Unknown,
    };
    PortalConsoleLevel {
        raw: raw.to_string(),
        normalized,
    }
}

/// Normalize a Console timestamp.
///
/// A timestamp with no offset yields [`PortalTimestampKind::Local`] and a `None`
/// `normalized_utc`. It is *not* an error and is never defaulted to UTC, because doing so
/// would silently manufacture an instant that could be compared against server evidence.
fn normalize_timestamp(
    raw: Option<&str>,
    decimal_separator: PortalConsoleDecimalSeparator,
) -> PortalTimestamp {
    let Some(raw) = raw else {
        return PortalTimestamp {
            raw_text: String::new(),
            original_offset: None,
            normalized_utc: None,
            kind: PortalTimestampKind::Unknown,
        };
    };

    let Some(captures) = timestamp_pattern().captures(raw) else {
        return PortalTimestamp {
            raw_text: raw.to_string(),
            original_offset: None,
            normalized_utc: None,
            kind: PortalTimestampKind::Invalid,
        };
    };

    let mut naive_text = captures["naive"].to_string();
    if decimal_separator == PortalConsoleDecimalSeparator::Comma {
        naive_text = naive_text.replace(',', ".");
    }
    // Tolerate either separator regardless of the layout hint; the layout only decides which
    // one is expected, not which one is legal.
    naive_text = naive_text.replace(',', ".");

    let offset = captures
        .name("offset")
        .map(|value| value.as_str().to_string());

    match &offset {
        Some(offset_text) => {
            let combined = format!("{naive_text}{offset_text}");
            match DateTime::<FixedOffset>::parse_from_str(&combined, "%Y-%m-%d %H:%M:%S%.f%z") {
                Ok(parsed) => {
                    let kind = if parsed.offset().local_minus_utc() == 0 {
                        PortalTimestampKind::Utc
                    } else {
                        PortalTimestampKind::Offset
                    };
                    PortalTimestamp {
                        raw_text: raw.to_string(),
                        original_offset: offset,
                        normalized_utc: Some(
                            parsed
                                .with_timezone(&Utc)
                                .format("%Y-%m-%dT%H:%M:%S%.6fZ")
                                .to_string(),
                        ),
                        kind,
                    }
                }
                Err(_) => PortalTimestamp {
                    raw_text: raw.to_string(),
                    original_offset: offset,
                    normalized_utc: None,
                    kind: PortalTimestampKind::Invalid,
                },
            }
        }
        None => match NaiveDateTime::parse_from_str(&naive_text, "%Y-%m-%d %H:%M:%S%.f") {
            Ok(_) => PortalTimestamp {
                raw_text: raw.to_string(),
                original_offset: None,
                normalized_utc: None,
                kind: PortalTimestampKind::Local,
            },
            Err(_) => PortalTimestamp {
                raw_text: raw.to_string(),
                original_offset: None,
                normalized_utc: None,
                kind: PortalTimestampKind::Invalid,
            },
        },
    }
}

// ---------------------------------------------------------------------------
// Capture-level derivations
// ---------------------------------------------------------------------------

fn apply_versions(capture: &mut PortalConsoleCapture) {
    let banner = capture.records.iter().find_map(|record| {
        parse_version_banner(
            &record.source.class,
            record.source.category.as_deref(),
            &record.message.value,
        )
        .map(|banner| (banner, record.reference.evidence_ref.clone()))
    });

    if let Some((banner, evidence)) = banner {
        capture.versions = PortalConsoleCaptureVersions {
            state: PortalConsoleVersionState::Known,
            company_portal_version: Some(banner.company_portal_version),
            os_version: Some(banner.os_version),
            evidence: Some(evidence),
        };
    }

    // Semantic confidence is tied to whether a version was actually proven.
    let versions_known = capture.versions.state == PortalConsoleVersionState::Known;
    for record in &mut capture.records {
        record.semantic = classify_semantics(
            &record.source.class,
            record.source.category.as_deref(),
            versions_known,
        );
    }
}

fn apply_ordering(capture: &mut PortalConsoleCapture) {
    let parsed: Vec<&PortalConsoleRecord> = capture
        .records
        .iter()
        .filter(|record| record.parse_state == PortalConsoleParseState::Parsed)
        .collect();

    if parsed.is_empty() {
        capture.ordering = PortalConsoleOrdering {
            confidence: PortalOrderingConfidence::Unordered,
            records_without_offset: 0,
            detail: "no record produced a usable instant".to_string(),
        };
        return;
    }

    let without_offset = parsed
        .iter()
        .filter(|record| record.timestamp.normalized_utc.is_none())
        .count();

    capture.ordering = if without_offset == 0 {
        PortalConsoleOrdering {
            confidence: PortalOrderingConfidence::CrossSourceComparable,
            records_without_offset: 0,
            detail: "every parsed record carries an explicit UTC offset".to_string(),
        }
    } else {
        PortalConsoleOrdering {
            confidence: PortalOrderingConfidence::CaptureLocalOnly,
            records_without_offset: without_offset,
            detail: format!(
                "{without_offset} parsed record(s) carry no timezone; capture order is preserved but records must not be ordered against server or cloud sources"
            ),
        }
    };
}

fn apply_totals(capture: &mut PortalConsoleCapture) {
    let mut totals = PortalConsoleTotals {
        source_lines: capture.totals.source_lines,
        total_records: capture.records.len(),
        company_portal_records: 0,
        other_process_records: 0,
        unattributed_records: 0,
        malformed_records: 0,
        truncated_records: 0,
    };

    for record in &capture.records {
        match record.source.class {
            PortalConsoleSourceClass::CompanyPortal => totals.company_portal_records += 1,
            PortalConsoleSourceClass::OtherProcess => totals.other_process_records += 1,
            PortalConsoleSourceClass::Unattributed => totals.unattributed_records += 1,
        }
        match record.parse_state {
            PortalConsoleParseState::Malformed => totals.malformed_records += 1,
            PortalConsoleParseState::Truncated => totals.truncated_records += 1,
            _ => {}
        }
    }

    capture.totals = totals;
}
