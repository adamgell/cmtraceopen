//! CCM/SCCM format parser.
//!
//! Parses log lines in the format:
//!   <![LOG[message text]LOG]!><time="HH:mm:ss.fff+TZO" date="MM-dd-yyyy"
//!     component="Name" context="" type="N" thread="N" file="source.cpp">
//!
//! The regex patterns are derived directly from the scanf format strings
//! extracted from the CMTrace.exe binary (see REVERSE_ENGINEERING.md).

use chrono::{FixedOffset, TimeZone};
use regex::Regex;

use super::severity::detect_severity_from_text;
use crate::models::log_entry::{LogEntry, LogFormat, ParserSpecialization, Severity};
use std::sync::OnceLock;

const CCM_RECORD_OPENER: &str = "<![LOG[";

/// Compiled regex matching a complete CCM log line.
///
/// Based on the binary's scanf pattern:
///   <time="%02u:%02u:%02u.%03u%d" date="%02u-%02u-%04u"
///    component="%100[^"]" context="" type="%u" thread="%u" file="%100[^"]"
fn ccm_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(concat!(
            r#"<!\[LOG\[(?P<msg>[\s\S]*?)\]LOG\]!>"#,
            r#"<time="(?P<h>\d{1,2}):(?P<m>\d{1,2}):(?P<s>\d{1,2})\.(?P<time_tail>\d+(?:[+-]\d+)?)""#,
            r#"\s+date="(?P<mon>\d{1,2})-(?P<day>\d{1,2})-(?P<yr>\d{4})""#,
            r#"\s+component="(?P<comp>[^"]*)""#,
            r#"\s+context="(?P<context>[^"]*)""#,
            r#"\s+type="(?P<typ>\d)?""#,
            r#"\s+thread="(?P<thr>\d+)?""#,
            r#"(?:\s+file="(?P<file>[^"]*)")?>"#,
        ))
        .expect("CCM regex must compile")
    })
}

/// Parse a single CCM-format log line.
/// Returns None if the line doesn't match the CCM format.
fn parse_line(line: &str) -> Option<CcmParsed> {
    let caps = ccm_re().captures(line)?;
    let parsed = parse_captures(&caps)?;
    parsed.public_compatible.then_some(parsed)
}

struct CcmParsed {
    message: String,
    component: Option<String>,
    timestamp: Option<i64>,
    timestamp_display: Option<String>,
    severity: Severity,
    thread: u32,
    thread_display: Option<String>,
    source_file: Option<String>,
    timezone_offset: i32,
    context: Option<String>,
    timestamp_parse: CcmTimestampParse,
    public_compatible: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CcmTimestampParseState {
    NormalizedUtc,
    OffsetMissing,
    OffsetInvalid,
    TimestampMissing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CcmTimestampParse {
    pub original_display: Option<String>,
    pub offset_minutes: Option<i32>,
    pub utc_millis: Option<i64>,
    pub ordering_state: CcmTimestampParseState,
}

impl CcmTimestampParse {
    fn missing() -> Self {
        Self {
            original_display: None,
            offset_minutes: None,
            utc_millis: None,
            ordering_state: CcmTimestampParseState::TimestampMissing,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct CcmLogicalRecord {
    pub entry: LogEntry,
    pub context: Option<String>,
    pub line_start: u32,
    pub line_end: u32,
    pub timestamp: CcmTimestampParse,
}

impl CcmParsed {
    fn into_logical_record(
        self,
        id: u64,
        line_start: u32,
        line_end: u32,
        file_path: &str,
    ) -> CcmLogicalRecord {
        CcmLogicalRecord {
            entry: LogEntry {
                id,
                line_number: line_start,
                message: self.message,
                component: self.component,
                timestamp: self.timestamp,
                timestamp_display: self.timestamp_display,
                severity: self.severity,
                thread: Some(self.thread),
                thread_display: self.thread_display,
                source_file: self.source_file,
                format: LogFormat::Ccm,
                file_path: file_path.to_string(),
                timezone_offset: Some(self.timezone_offset),
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
            },
            context: self.context,
            line_start,
            line_end,
            timestamp: self.timestamp_parse,
        }
    }
}

pub(crate) fn truncate_subsecond_to_millis(value: &str) -> Option<u32> {
    if value.len() > 3 {
        value[..3].parse().ok()
    } else {
        value.parse().ok()
    }
}

/// Longest offset any real timezone uses, in minutes (UTC-14:00..UTC+14:00).
const MAX_UTC_OFFSET_MINUTES: u32 = 14 * 60;

/// Every timezone offset in current use is a whole number of quarter hours.
const UTC_OFFSET_STEP_MINUTES: u32 = 15;

/// Decide whether a signless digit run can be a source timezone offset.
///
/// The legacy grammar prints the offset with `%d`, so it never zero-pads and
/// never emits a sign for a positive value. A run that survives that shape
/// check still has to name an offset a machine can actually be configured
/// with; anything else is fractional-second text that happens to be numeric.
fn signless_offset_is_real(text: &str) -> bool {
    if text.starts_with('0') {
        return false;
    }

    text.parse::<u32>().is_ok_and(|minutes| {
        minutes <= MAX_UTC_OFFSET_MINUTES && minutes % UTC_OFFSET_STEP_MINUTES == 0
    })
}

/// Split CCM's fractional-second field from its optional timezone offset.
///
/// A signed offset is self-delimiting and is always taken at face value: the
/// sign is the source stating its own provenance, so an out-of-range signed
/// offset is reported as invalid rather than reinterpreted.
///
/// A signless tail is genuinely ambiguous. The documented legacy `%03u%d`
/// grammar emits three millisecond digits followed by an unsigned positive
/// offset, so `.000240` really is 0 ms at UTC+4; .NET writers instead emit
/// six- or seven-digit fractional seconds, so `.123456` is 123456
/// microseconds and carries no offset. Both shapes are six digits wide, and
/// digit width alone cannot tell them apart.
///
/// Two shipped implementations tried to tell them apart positionally and both
/// were wrong. The original greedy regex `(?P<ms>\d+)(?P<tz>[+-]*\d+)` gave
/// the last digit to the offset, so `.123456` became 123 ms at UTC+6 minutes.
/// Its replacement gave the last three digits to the offset whenever the tail
/// was exactly six wide, so `.123456` became 123 ms at UTC+456 minutes, a
/// silent 7h36m shift stamped `NormalizedUtc`. Do not add a third rule of
/// that kind: the split is decided by whether the candidate offset is a real
/// timezone offset, and a tail that fails that check keeps all of its digits
/// as fractional seconds and is reported as having no source offset.
fn split_ccm_time_tail(value: &str) -> (&str, Option<&str>) {
    if let Some(index) = value
        .as_bytes()
        .iter()
        .position(|byte| matches!(byte, b'+' | b'-'))
    {
        return (&value[..index], Some(&value[index..]));
    }

    // `%03u%d` with a three-digit offset is the only signless shape the
    // legacy grammar can produce that is not also plain fractional text.
    if value.len() == 6 && signless_offset_is_real(&value[3..]) {
        return (&value[..3], Some(&value[3..]));
    }

    (value, None)
}

/// Reproduce the pre-SCCM-spine public regex projection.
///
/// The legacy `(?P<ms>\d+)(?P<tz>[+-]*\d+)` captures greedily assigned the
/// final digit of an unsigned tail to `timezoneOffset`. Public `LogEntry`
/// callers retain that observable behavior; the SCCM envelope uses
/// `split_ccm_time_tail` above for corrected provenance.
fn split_legacy_public_time_tail(value: &str) -> Option<(&str, &str)> {
    if let Some(index) = value
        .as_bytes()
        .iter()
        .position(|byte| matches!(byte, b'+' | b'-'))
    {
        return (index > 0).then_some((&value[..index], &value[index..]));
    }

    let split_at = value.len().checked_sub(1)?;
    (split_at > 0).then_some((&value[..split_at], &value[split_at..]))
}

/// Convert a naive local datetime + optional timezone offset (in minutes) to UTC epoch millis.
/// Falls back to treating naive as UTC if the offset is invalid or overflows.
pub(crate) fn naive_to_utc_millis(
    naive: chrono::NaiveDateTime,
    offset_minutes: Option<i32>,
) -> i64 {
    offset_minutes
        .and_then(|offset| normalized_utc_millis(naive, offset))
        .unwrap_or_else(|| naive.and_utc().timestamp_millis())
}

fn normalized_utc_millis(naive: chrono::NaiveDateTime, offset_minutes: i32) -> Option<i64> {
    offset_minutes
        .checked_mul(60)
        .and_then(FixedOffset::east_opt)
        .and_then(|offset| offset.from_local_datetime(&naive).single())
        .map(|datetime| datetime.timestamp_millis())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_timestamp(
    month: u32,
    day: u32,
    year: i32,
    hour: u32,
    minute: u32,
    second: u32,
    millis: u32,
    timezone_offset: Option<i32>,
) -> (Option<i64>, Option<String>) {
    let timestamp = chrono::NaiveDate::from_ymd_opt(year, month, day)
        .and_then(|date| date.and_hms_milli_opt(hour, minute, second, millis))
        .map(|naive| naive_to_utc_millis(naive, timezone_offset));

    let timestamp_display = Some(format!(
        "{:02}-{:02}-{:04} {:02}:{:02}:{:02}.{:03}",
        month, day, year, hour, minute, second, millis
    ));

    (timestamp, timestamp_display)
}

pub(crate) fn severity_from_type_field(type_value: Option<u32>, message: &str) -> Severity {
    match type_value {
        Some(0) => Severity::Success, // CCM/PSADT type="0" — successful operation (OneTrace green tick)
        Some(2) => Severity::Warning,
        Some(3) => Severity::Error,
        Some(_) => Severity::Info, // includes type="1" and any unknown numeric type
        None => detect_severity_from_text(message), // type absent/empty — infer from message text
    }
}

/// Cache for thread display strings. Thread IDs repeat heavily in log files
/// (typically 5-20 unique threads across thousands of entries), so caching
/// avoids a `format!()` allocation per line.
pub(crate) fn format_thread_display(thread: u32) -> String {
    use std::cell::RefCell;
    use std::collections::HashMap;

    thread_local! {
        static CACHE: RefCell<HashMap<u32, String>> = RefCell::new(HashMap::new());
    }

    CACHE.with(|cache| {
        let mut map = cache.borrow_mut();
        map.entry(thread)
            .or_insert_with(|| format!("{} (0x{:04X})", thread, thread))
            .clone()
    })
}

pub fn parse_content(
    content: &str,
    file_path: &str,
    specialization: Option<ParserSpecialization>,
) -> (Vec<LogEntry>, u32) {
    match specialization {
        Some(ParserSpecialization::Ime) => {
            crate::intune::ime_parser::parse_ime_entries(content, file_path)
        }
        None => parse_content_multiline(content, file_path),
    }
}

/// Content-based multi-line CCM parser.
///
/// Runs the CCM regex over the entire file content so that records spanning
/// multiple physical lines (e.g. `<![LOG[line1\nline2]LOG]!><attrs>`) are
/// matched as a single logical record.  Text between matched records is
/// emitted as individual plain-text entries, preserving line numbers.
fn parse_content_multiline(content: &str, file_path: &str) -> (Vec<LogEntry>, u32) {
    let scan = scan_ccm_content(content, file_path, CcmScanMode::PublicProjection);
    (
        scan.records
            .into_iter()
            .map(|record| record.entry)
            .collect(),
        scan.errors,
    )
}

pub(crate) fn scan_logical_records(content: &str, file_path: &str) -> Vec<CcmLogicalRecord> {
    scan_ccm_content(content, file_path, CcmScanMode::SccmEvidence)
        .records
        .into_iter()
        .filter(|record| record.entry.format == LogFormat::Ccm)
        .collect()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CcmScanMode {
    PublicProjection,
    SccmEvidence,
}

struct CcmScan {
    records: Vec<CcmLogicalRecord>,
    errors: u32,
}

fn scan_ccm_content(content: &str, file_path: &str, mode: CcmScanMode) -> CcmScan {
    let line_starts = build_line_starts(content);
    let mut records = Vec::new();
    let mut errors = 0u32;
    let mut id_counter = 0u64;
    let mut cursor = 0usize;
    let mut search_cursor = 0usize;
    let mut matched_any = false;

    while let Some(caps) = ccm_re().captures_at(content, search_cursor) {
        let full_match = caps
            .get(0)
            .expect("CCM regex captures always include the full match");

        if newest_nested_opener(content, full_match.start(), full_match.end()).is_some()
            && mode == CcmScanMode::SccmEvidence
        {
            // A line-start opener inside a complete-looking multiline record
            // is byte-for-byte ambiguous: it can be a literal message token
            // or a recovery boundary after partial input. SCCM evidence must
            // not promote either interpretation. The public projection keeps
            // the legacy full-match result to preserve LogEntry compatibility.
            push_unmatched_plain(
                &content[cursor..full_match.end()],
                cursor,
                &line_starts,
                file_path,
                &mut records,
                &mut id_counter,
                &mut errors,
            );
            cursor = full_match.end();
            search_cursor = full_match.end();
            matched_any = true;
            continue;
        }

        // Emit unmatched text between the previous match and this one
        push_unmatched_plain(
            &content[cursor..full_match.start()],
            cursor,
            &line_starts,
            file_path,
            &mut records,
            &mut id_counter,
            &mut errors,
        );

        let line_start = line_number_for_offset(&line_starts, full_match.start());
        let line_end = line_number_for_offset(&line_starts, full_match.end().saturating_sub(1));
        if let Some(parsed) = parse_captures(&caps) {
            if parsed.public_compatible || mode == CcmScanMode::SccmEvidence {
                records
                    .push(parsed.into_logical_record(id_counter, line_start, line_end, file_path));
                id_counter += 1;
            } else {
                push_unmatched_plain(
                    full_match.as_str(),
                    full_match.start(),
                    &line_starts,
                    file_path,
                    &mut records,
                    &mut id_counter,
                    &mut errors,
                );
            }
        } else {
            push_unmatched_plain(
                full_match.as_str(),
                full_match.start(),
                &line_starts,
                file_path,
                &mut records,
                &mut id_counter,
                &mut errors,
            );
        }

        cursor = full_match.end();
        search_cursor = full_match.end();
        matched_any = true;
    }

    // Trailing unmatched text
    push_unmatched_plain(
        &content[cursor..],
        cursor,
        &line_starts,
        file_path,
        &mut records,
        &mut id_counter,
        &mut errors,
    );

    if !matched_any {
        let lines: Vec<&str> = content.lines().collect();
        let (entries, errors) = parse_lines(&lines, file_path);
        let records = entries
            .into_iter()
            .map(|entry| {
                let line = entry.line_number;
                CcmLogicalRecord {
                    entry,
                    context: None,
                    line_start: line,
                    line_end: line,
                    timestamp: CcmTimestampParse::missing(),
                }
            })
            .collect();
        return CcmScan { records, errors };
    }

    CcmScan { records, errors }
}

fn newest_nested_opener(
    content: &str,
    full_match_start: usize,
    full_match_end: usize,
) -> Option<usize> {
    // Only physical-line openers can delimit recovery records. Scan newest
    // first so an adversarial run of partial openers is discarded in one pass.
    let nested_search_start = full_match_start.checked_add(CCM_RECORD_OPENER.len())?;
    content
        .get(nested_search_start..full_match_end)?
        .rmatch_indices(CCM_RECORD_OPENER)
        .find_map(|(offset, _)| {
            let absolute = nested_search_start + offset;
            let starts_logical_line = absolute == 0
                || content
                    .as_bytes()
                    .get(absolute - 1)
                    .is_some_and(|previous| matches!(previous, b'\n' | b'\r'));
            starts_logical_line.then_some(absolute)
        })
}

/// Parse named captures from a CCM regex match into a CcmParsed struct.
fn parse_captures(caps: &regex::Captures<'_>) -> Option<CcmParsed> {
    let msg = caps.name("msg").map(|m| m.as_str().to_string())?;
    let h_text = caps.name("h")?.as_str();
    let m_text = caps.name("m")?.as_str();
    let s_text = caps.name("s")?.as_str();
    let h: u32 = h_text.parse().ok()?;
    let m: u32 = m_text.parse().ok()?;
    let s: u32 = s_text.parse().ok()?;
    let time_tail = caps.name("time_tail")?.as_str();
    let (ms_str, timezone_text) = split_ccm_time_tail(time_tail);
    let ms = truncate_subsecond_to_millis(ms_str)?;
    let parsed_timezone = timezone_text.and_then(|value| value.parse::<i32>().ok());
    let timezone_is_explicit = timezone_text.is_some();
    let mon_text = caps.name("mon")?.as_str();
    let day_text = caps.name("day")?.as_str();
    let yr_text = caps.name("yr")?.as_str();
    let mon: u32 = mon_text.parse().ok()?;
    let day: u32 = day_text.parse().ok()?;
    let yr: i32 = yr_text.parse().ok()?;
    let comp = caps.name("comp").map(|m| m.as_str().to_string());
    let context = caps.name("context").map(|m| m.as_str().to_string());
    // Preserve absent/empty/unparseable type as `None` so it falls back to
    // text-based detection. Coercing to `Some(0)` would misclassify neutral
    // lines as Success now that type="0" maps to Severity::Success.
    let typ: Option<u32> = caps.name("typ").and_then(|m| m.as_str().parse().ok());
    let thr: u32 = caps
        .name("thr")
        .and_then(|m| m.as_str().parse().ok())
        .unwrap_or(0);
    let file = caps.name("file").map(|m| m.as_str().to_string());

    let severity = severity_from_type_field(typ, &msg);
    let public_timestamp = split_legacy_public_time_tail(time_tail).and_then(
        |(public_ms_text, public_timezone_text)| {
            let public_ms = truncate_subsecond_to_millis(public_ms_text)?;
            let public_timezone = public_timezone_text.parse::<i32>().ok()?;
            let (timestamp, timestamp_display) =
                build_timestamp(mon, day, yr, h, m, s, public_ms, Some(public_timezone));
            Some((timestamp, timestamp_display, public_timezone))
        },
    );
    let public_compatible = public_timestamp.is_some();
    let (timestamp, timestamp_display, timezone_offset) = public_timestamp.unwrap_or_else(|| {
        let (timestamp, timestamp_display) =
            build_timestamp(mon, day, yr, h, m, s, ms, parsed_timezone);
        (
            timestamp,
            timestamp_display,
            parsed_timezone.unwrap_or_default(),
        )
    });
    let naive = chrono::NaiveDate::from_ymd_opt(yr, mon, day)
        .and_then(|date| date.and_hms_milli_opt(h, m, s, ms));
    let normalized_timestamp = if timezone_is_explicit {
        naive.and_then(|value| {
            parsed_timezone.and_then(|offset| normalized_utc_millis(value, offset))
        })
    } else {
        None
    };
    let ordering_state = if naive.is_none() {
        CcmTimestampParseState::TimestampMissing
    } else if !timezone_is_explicit {
        CcmTimestampParseState::OffsetMissing
    } else if normalized_timestamp.is_some() {
        CcmTimestampParseState::NormalizedUtc
    } else {
        CcmTimestampParseState::OffsetInvalid
    };
    let timestamp_parse = CcmTimestampParse {
        original_display: Some(format!(
            "{mon_text}-{day_text}-{yr_text} {h_text}:{m_text}:{s_text}.{ms_str}"
        )),
        offset_minutes: timezone_is_explicit.then_some(parsed_timezone).flatten(),
        utc_millis: normalized_timestamp,
        ordering_state,
    };
    let thread_display = Some(format_thread_display(thr));

    Some(CcmParsed {
        message: msg,
        component: comp,
        timestamp,
        timestamp_display,
        severity,
        thread: thr,
        thread_display,
        source_file: file,
        timezone_offset,
        context,
        timestamp_parse,
        public_compatible,
    })
}

fn build_line_starts(content: &str) -> Vec<usize> {
    let mut starts = vec![0];
    for (index, byte) in content.bytes().enumerate() {
        if byte == b'\n' {
            starts.push(index + 1);
        }
    }
    starts
}

fn line_number_for_offset(line_starts: &[usize], offset: usize) -> u32 {
    match line_starts.binary_search(&offset) {
        Ok(index) => (index + 1) as u32,
        Err(index) => index as u32,
    }
}

/// Emit each non-empty physical line in `segment` as a plain-text envelope.
fn push_unmatched_plain(
    segment: &str,
    base_offset: usize,
    line_starts: &[usize],
    file_path: &str,
    records: &mut Vec<CcmLogicalRecord>,
    id_counter: &mut u64,
    errors: &mut u32,
) {
    let mut local_offset = 0usize;
    for piece in segment.split_inclusive('\n') {
        let line = piece.trim_end_matches(['\r', '\n']);
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            let line_number = line_number_for_offset(line_starts, base_offset + local_offset);
            let entry = LogEntry {
                id: *id_counter,
                line_number,
                message: trimmed.to_string(),
                component: None,
                timestamp: None,
                timestamp_display: None,
                severity: detect_severity_from_text(trimmed),
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
            };
            records.push(CcmLogicalRecord {
                entry,
                context: None,
                line_start: line_number,
                line_end: line_number,
                timestamp: CcmTimestampParse::missing(),
            });
            *id_counter += 1;
            *errors += 1;
        }
        local_offset += piece.len();
    }
}

pub fn parse_lines_with_specialization(
    lines: &[&str],
    file_path: &str,
    specialization: Option<ParserSpecialization>,
) -> (Vec<LogEntry>, u32) {
    // Always join lines and use content-based parsing for multi-line support
    parse_content(&lines.join("\n"), file_path, specialization)
}

/// Parse all lines as CCM format.
/// Returns (entries, parse_error_count).
pub fn parse_lines(lines: &[&str], file_path: &str) -> (Vec<LogEntry>, u32) {
    let mut entries = Vec::with_capacity(lines.len());
    let mut errors = 0u32;
    let mut id_counter = 0u64;

    for (i, line) in lines.iter().enumerate() {
        if line.trim().is_empty() {
            continue;
        }

        match parse_line(line) {
            Some(parsed) => {
                let line_number = (i + 1) as u32;
                entries.push(
                    parsed
                        .into_logical_record(id_counter, line_number, line_number, file_path)
                        .entry,
                );
                id_counter += 1;
            }
            None => {
                // Line didn't match CCM format — treat as plain text continuation
                // or standalone plain text entry
                entries.push(LogEntry {
                    id: id_counter,
                    line_number: (i + 1) as u32,
                    message: line.to_string(),
                    component: None,
                    timestamp: None,
                    timestamp_display: None,
                    severity: detect_severity_from_text(line),
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
                });
                id_counter += 1;
                errors += 1;
            }
        }
    }

    (entries, errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ccm_line() {
        let line = r#"<![LOG[Successfully connected to \\server\share]LOG]!><time="08:06:34.590-060" date="09-02-2016" component="ContentTransferManager" context="" type="1" thread="3692" file="datatransfer.cpp">"#;
        let parsed = parse_line(line).expect("should parse");
        assert_eq!(parsed.message, r"Successfully connected to \\server\share");
        assert_eq!(parsed.component.as_deref(), Some("ContentTransferManager"));
        assert_eq!(parsed.severity, Severity::Info);
        assert_eq!(parsed.thread, 3692);
        assert_eq!(parsed.source_file.as_deref(), Some("datatransfer.cpp"));
        assert_eq!(parsed.timezone_offset, -60);
        assert_eq!(
            parsed.timestamp_display.as_deref(),
            Some("09-02-2016 08:06:34.590")
        );
        // 08:06:34.590 in UTC-1 == 09:06:34.590 UTC
        let expected_ts = FixedOffset::east_opt(-60 * 60)
            .unwrap()
            .from_local_datetime(
                &chrono::NaiveDate::from_ymd_opt(2016, 9, 2)
                    .unwrap()
                    .and_hms_milli_opt(8, 6, 34, 590)
                    .unwrap(),
            )
            .single()
            .unwrap()
            .timestamp_millis();
        assert_eq!(parsed.timestamp, Some(expected_ts));
    }

    #[test]
    fn test_build_timestamp_utc_offset() {
        // +000 offset: naive time equals UTC
        let (ts_utc, _) = build_timestamp(1, 1, 2024, 10, 0, 0, 0, Some(0));
        let expected_utc = chrono::NaiveDate::from_ymd_opt(2024, 1, 1)
            .unwrap()
            .and_hms_milli_opt(10, 0, 0, 0)
            .unwrap()
            .and_utc()
            .timestamp_millis();
        assert_eq!(ts_utc, Some(expected_utc));

        // -240 offset (UTC-4 / EST): 10:00 local == 14:00 UTC
        let (ts_est, _) = build_timestamp(1, 1, 2024, 10, 0, 0, 0, Some(-240));
        let expected_est = chrono::NaiveDate::from_ymd_opt(2024, 1, 1)
            .unwrap()
            .and_hms_milli_opt(14, 0, 0, 0)
            .unwrap()
            .and_utc()
            .timestamp_millis();
        assert_eq!(ts_est, Some(expected_est));

        // +240 offset (UTC+4): 10:00 local == 06:00 UTC
        let (ts_plus4, _) = build_timestamp(1, 1, 2024, 10, 0, 0, 0, Some(240));
        let expected_plus4 = chrono::NaiveDate::from_ymd_opt(2024, 1, 1)
            .unwrap()
            .and_hms_milli_opt(6, 0, 0, 0)
            .unwrap()
            .and_utc()
            .timestamp_millis();
        assert_eq!(ts_plus4, Some(expected_plus4));
    }

    #[test]
    fn test_parse_ccm_error() {
        let line = r#"<![LOG[Failed to download content. Error 0x80070005]LOG]!><time="14:30:45.123+000" date="11-15-2023" component="ContentAccess" context="" type="3" thread="4480" file="contentaccess.cpp">"#;
        let parsed = parse_line(line).expect("should parse");
        assert_eq!(parsed.severity, Severity::Error);
        assert_eq!(parsed.component.as_deref(), Some("ContentAccess"));
    }

    #[test]
    fn test_parse_ccm_warning() {
        let line = r#"<![LOG[Retrying request]LOG]!><time="10:00:00.000+000" date="01-01-2024" component="Test" context="" type="2" thread="100" file="">"#;
        let parsed = parse_line(line).expect("should parse");
        assert_eq!(parsed.severity, Severity::Warning);
    }

    #[test]
    fn test_parse_ccm_empty_type_and_thread_default_to_zero() {
        let line = r#"<![LOG[Performing Install steps...]LOG]!><time="10:28:53.264+000" date="04-05-2026" component="install_config.ps1:103" context="" type="" thread="" file="test.ps1">"#;

        let (entries, parse_errors) = parse_lines(&[line], "example.log");

        assert_eq!(parse_errors, 0);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].format, LogFormat::Ccm);
        assert_eq!(entries[0].severity, Severity::Info);
        assert_eq!(entries[0].thread, Some(0));
        assert_eq!(entries[0].thread_display.as_deref(), Some("0 (0x0000)"));
        assert_eq!(entries[0].source_file.as_deref(), Some("test.ps1"));
    }

    #[test]
    fn test_parse_ccm_type_0_maps_to_success() {
        let line = r#"<![LOG[Installation completed successfully]LOG]!><time="10:28:53.264+000" date="04-05-2026" component="install.ps1:10" context="" type="0" thread="42" file="install.ps1">"#;

        let (entries, parse_errors) = parse_lines(&[line], "example.log");

        assert_eq!(parse_errors, 0);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].severity, Severity::Success);
    }

    #[test]
    fn test_severity_from_type_field_mapping() {
        // Explicit CCM type values map directly.
        assert_eq!(
            severity_from_type_field(Some(0), "anything"),
            Severity::Success
        );
        assert_eq!(
            severity_from_type_field(Some(1), "anything"),
            Severity::Info
        );
        assert_eq!(
            severity_from_type_field(Some(2), "anything"),
            Severity::Warning
        );
        assert_eq!(
            severity_from_type_field(Some(3), "anything"),
            Severity::Error
        );
        // Unknown numeric type falls back to Info.
        assert_eq!(
            severity_from_type_field(Some(99), "anything"),
            Severity::Info
        );
        // Absent type infers from message text — a neutral message must NOT
        // be coerced to Success (the latent unwrap_or(0) bug).
        assert_eq!(
            severity_from_type_field(None, "Performing install steps"),
            Severity::Info
        );
        assert_eq!(
            severity_from_type_field(None, "Operation failed"),
            Severity::Error
        );
    }

    #[test]
    fn test_severity_from_text() {
        assert_eq!(
            detect_severity_from_text("An error occurred"),
            Severity::Error
        );
        assert_eq!(
            detect_severity_from_text("Connection failed"),
            Severity::Error
        );
        assert_eq!(
            detect_severity_from_text("Failover to backup"),
            Severity::Info
        );
        assert_eq!(
            detect_severity_from_text("Warning: low disk"),
            Severity::Warning
        );
        assert_eq!(detect_severity_from_text("All good"), Severity::Info);
    }

    #[test]
    fn test_parse_lines_with_ime_specialization_preserves_logical_records() {
        let lines = [
            r#"<![LOG[Powershell execution is done, exitCode = 1]LOG]!><time="11:16:37.3093207" date="3-12-2026" component="HealthScripts" context="" type="1" thread="50" file="">"#,
            r#"<![LOG[[HS] err output = Downloaded profile payload is not valid JSON."#,
            r#"At C:\Windows\IMECache\HealthScripts\script.ps1:457 char:9"#,
            r#"]LOG]!><time="11:16:42.3322734" date="3-12-2026" component="HealthScripts" context="" type="3" thread="50" file="">"#,
        ];

        let (entries, parse_errors) = parse_lines_with_specialization(
            &lines,
            "HealthScripts.log",
            Some(ParserSpecialization::Ime),
        );

        assert_eq!(parse_errors, 0);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].format, LogFormat::Ccm);
        assert_eq!(entries[1].line_number, 2);
        assert!(entries[1]
            .message
            .contains("Downloaded profile payload is not valid JSON"));
        assert!(entries[1]
            .message
            .contains("At C:\\Windows\\IMECache\\HealthScripts\\script.ps1:457 char:9"));
    }

    #[test]
    fn test_build_timestamp_none_offset_treats_as_utc() {
        let (ts, _) = build_timestamp(1, 1, 2024, 10, 0, 0, 0, None);
        let expected = chrono::NaiveDate::from_ymd_opt(2024, 1, 1)
            .unwrap()
            .and_hms_milli_opt(10, 0, 0, 0)
            .unwrap()
            .and_utc()
            .timestamp_millis();
        assert_eq!(ts, Some(expected));
    }

    #[test]
    fn test_build_timestamp_midnight_crossing_offset() {
        // 01:00 local at UTC+3 = 22:00 UTC on the previous day
        let (ts, _) = build_timestamp(1, 2, 2024, 1, 0, 0, 0, Some(180));
        let expected = chrono::NaiveDate::from_ymd_opt(2024, 1, 1)
            .unwrap()
            .and_hms_milli_opt(22, 0, 0, 0)
            .unwrap()
            .and_utc()
            .timestamp_millis();
        assert_eq!(ts, Some(expected));
    }

    #[test]
    fn test_build_timestamp_extreme_offset_falls_back_to_utc() {
        // Offset of 99999 minutes would overflow FixedOffset range.
        // Should fall back to treating naive as UTC, not return None.
        let (ts, display) = build_timestamp(1, 1, 2024, 10, 0, 0, 0, Some(99999));
        let expected_utc = chrono::NaiveDate::from_ymd_opt(2024, 1, 1)
            .unwrap()
            .and_hms_milli_opt(10, 0, 0, 0)
            .unwrap()
            .and_utc()
            .timestamp_millis();
        assert_eq!(
            ts,
            Some(expected_utc),
            "extreme offset should fall back to UTC"
        );
        assert!(display.is_some(), "display should always be present");
    }

    #[test]
    fn logical_scanner_retains_multiline_metadata() {
        let text = concat!(
            "<![LOG[Policy request completed for assignment\n",
            "{11111111-1111-1111-1111-111111111111}]LOG]!>",
            "<time=\"10:00:00.000-240\" date=\"07-30-2026\" ",
            "component=\"PolicyAgent\" context=\"NT AUTHORITY\\SYSTEM\" ",
            "type=\"1\" thread=\"42\" file=\"policyagent.cpp\">"
        );

        let records = scan_logical_records(text, "PolicyAgent.log");

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].line_start, 1);
        assert_eq!(records[0].line_end, 2);
        assert_eq!(records[0].context.as_deref(), Some(r"NT AUTHORITY\SYSTEM"));
        assert_eq!(
            records[0].timestamp.original_display.as_deref(),
            Some("07-30-2026 10:00:00.000")
        );
        assert_eq!(records[0].timestamp.offset_minutes, Some(-240));
        assert_eq!(
            records[0].timestamp.ordering_state,
            CcmTimestampParseState::NormalizedUtc
        );
        assert!(records[0].timestamp.utc_millis.is_some());
    }

    #[test]
    fn logical_scanner_treats_line_start_opener_inside_multiline_message_as_ambiguous() {
        for newline in ["\n", "\r\n"] {
            let text = format!(
                concat!(
                    "<![LOG[first line{newline}",
                    "<![LOG[literal at continuation start]LOG]!>",
                    "<time=\"10:00:00.000-240\" date=\"07-30-2026\" ",
                    "component=\"PolicyAgent\" context=\"\" type=\"1\" thread=\"42\">"
                ),
                newline = newline,
            );

            assert!(
                scan_logical_records(&text, "PolicyAgent.log").is_empty(),
                "{newline:?} physical-line ambiguity must remain coverage-only"
            );
        }
    }

    #[test]
    fn public_projection_keeps_multiline_line_start_literal_opener_as_one_log_entry() {
        for newline in ["\n", "\r\n"] {
            let text = format!(
                concat!(
                    "<![LOG[first line{newline}",
                    "<![LOG[literal at continuation start]LOG]!>",
                    "<time=\"10:00:00.000-240\" date=\"07-30-2026\" ",
                    "component=\"PolicyAgent\" context=\"\" type=\"1\" thread=\"42\">"
                ),
                newline = newline,
            );

            let (entries, errors) = parse_content(&text, "PolicyAgent.log", None);

            assert_eq!(errors, 0, "{newline:?} public parse must remain compatible");
            assert_eq!(entries.len(), 1, "{newline:?} must remain one LogEntry");
            assert_eq!(entries[0].format, LogFormat::Ccm);
            assert_eq!(
                entries[0].message,
                format!("first line{newline}<![LOG[literal at continuation start")
            );
        }
    }

    #[test]
    fn logical_scanner_keeps_same_line_literal_opener_in_one_complete_record() {
        let text = concat!(
            "<![LOG[Diagnostic text retained a literal <![LOG[ token]LOG]!>",
            "<time=\"10:00:00.000-240\" date=\"07-30-2026\" ",
            "component=\"PolicyAgent\" context=\"\" type=\"1\" thread=\"42\">"
        );

        let records = scan_logical_records(text, "PolicyAgent.log");

        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].entry.message,
            "Diagnostic text retained a literal <![LOG[ token"
        );
        assert_eq!(records[0].line_start, 1);
        assert_eq!(records[0].line_end, 1);
    }

    #[test]
    fn ambiguity_recovery_selects_the_newest_physical_line_opener() {
        let partial_prefix = "<![LOG[partial\n".repeat(4_096);
        let text = format!(
            concat!(
                "{partial_prefix}<![LOG[complete record]LOG]!><time=\"10:00:00.000-240\" ",
                "date=\"07-30-2026\" component=\"PolicyAgent\" context=\"\" ",
                "type=\"1\" thread=\"42\">"
            ),
            partial_prefix = partial_prefix,
        );
        let full_match = ccm_re()
            .find(&text)
            .expect("the partial prefix and terminal close form one complete-looking match");

        assert_eq!(
            newest_nested_opener(&text, full_match.start(), full_match.end()),
            text.rfind("<![LOG["),
            "recovery must jump to the newest nested opener in one scan"
        );
        assert!(
            scan_logical_records(&text, "PolicyAgent.log").is_empty(),
            "the adversarial ambiguous segment must remain coverage-only"
        );
    }

    fn logical_record_for_time_tail(tail: &str) -> CcmLogicalRecord {
        let text = format!(
            concat!(
                r#"<![LOG[Tail {tail}]LOG]!><time="10:00:00.{tail}" date="07-30-2026" "#,
                r#"component="PolicyAgent" context="" type="1" thread="42" file="policyagent.cpp">"#
            ),
            tail = tail
        );
        let mut records = scan_logical_records(&text, "PolicyAgent.log");
        assert_eq!(records.len(), 1, "tail {tail}: expected one logical record");
        records.remove(0)
    }

    /// Frozen answers for every shape of CCM fractional-second tail.
    ///
    /// Two shipped implementations resolved this ambiguity by counting digits
    /// and both were wrong (see `split_ccm_time_tail`). This table is the
    /// regression barrier: it pins the fractional text, the millisecond value,
    /// the source offset, and the ordering confidence for unsigned tails of
    /// one to eight digits and for their signed counterparts. Change a row
    /// only with a documented grammar reason, never to let a new heuristic
    /// pass.
    #[test]
    fn ccm_time_tail_ambiguity_table_is_frozen() {
        use CcmTimestampParseState::{NormalizedUtc, OffsetInvalid, OffsetMissing};

        // (time tail, fractional text, milliseconds, source offset, ordering state)
        let cases: [(&str, &str, u32, Option<i32>, CcmTimestampParseState); 26] = [
            // Unsigned tails that cannot be `%03u%d`: no trailing run of
            // digits reads as a real UTC offset, so they stay fractional and
            // the record is never promoted to UTC-normalized ordering.
            ("1", "1", 1, None, OffsetMissing),
            ("12", "12", 12, None, OffsetMissing),
            ("123", "123", 123, None, OffsetMissing),
            // `%d` prints a zero offset as "0", so a four-digit tail is not
            // evidence of one; downgrade instead of guessing.
            ("1234", "1234", 123, None, OffsetMissing),
            ("12345", "12345", 123, None, OffsetMissing),
            // Microsecond precision. 456 is not a UTC offset.
            ("123456", "123456", 123, None, OffsetMissing),
            // `%d` never zero-pads, so "045" is fractional text and not +45.
            ("123045", "123045", 123, None, OffsetMissing),
            // Same rule: a padded zero offset always arrives signed ("+000").
            ("123000", "123000", 123, None, OffsetMissing),
            // 481 minutes is not a whole quarter hour.
            ("123481", "123481", 123, None, OffsetMissing),
            // 900 minutes exceeds UTC+14:00.
            ("123900", "123900", 123, None, OffsetMissing),
            // Unsigned tails that are genuine `%03u%d` records: three
            // millisecond digits followed by a positive offset.
            ("000240", "000", 0, Some(240), NormalizedUtc),
            ("123480", "123", 123, Some(480), NormalizedUtc),
            ("123840", "123", 123, Some(840), NormalizedUtc),
            ("123105", "123", 123, Some(105), NormalizedUtc),
            // IME writes seven fractional digits, never an offset.
            ("1234567", "1234567", 123, None, OffsetMissing),
            ("12345678", "12345678", 123, None, OffsetMissing),
            // Signed tails are self-delimiting: the sign is the source's own
            // statement of provenance and is never screened for plausibility.
            ("123+480", "123", 123, Some(480), NormalizedUtc),
            ("123-240", "123", 123, Some(-240), NormalizedUtc),
            ("000+000", "000", 0, Some(0), NormalizedUtc),
            ("123+481", "123", 123, Some(481), NormalizedUtc),
            ("123+0", "123", 123, Some(0), NormalizedUtc),
            ("1+2", "1", 1, Some(2), NormalizedUtc),
            ("123456+480", "123456", 123, Some(480), NormalizedUtc),
            ("1234567-060", "1234567", 123, Some(-60), NormalizedUtc),
            // Out-of-range signed offsets stay reported and stay uncomparable.
            ("123+99999", "123", 123, Some(99999), OffsetInvalid),
            ("123-99999", "123", 123, Some(-99999), OffsetInvalid),
        ];

        for (tail, fraction_text, millis, offset_minutes, ordering_state) in cases {
            let (split_fraction, split_offset) = split_ccm_time_tail(tail);
            assert_eq!(
                split_fraction, fraction_text,
                "tail {tail}: fractional text"
            );
            assert_eq!(
                split_offset.is_some(),
                offset_minutes.is_some(),
                "tail {tail}: offset presence"
            );
            assert_eq!(
                truncate_subsecond_to_millis(split_fraction),
                Some(millis),
                "tail {tail}: milliseconds"
            );

            let record = logical_record_for_time_tail(tail);
            let timestamp = &record.timestamp;
            assert_eq!(
                timestamp.original_display,
                Some(format!("07-30-2026 10:00:00.{fraction_text}")),
                "tail {tail}: original display"
            );
            assert_eq!(
                timestamp.offset_minutes, offset_minutes,
                "tail {tail}: source offset"
            );
            assert_eq!(
                timestamp.ordering_state, ordering_state,
                "tail {tail}: ordering state"
            );

            let naive = chrono::NaiveDate::from_ymd_opt(2026, 7, 30)
                .unwrap()
                .and_hms_milli_opt(10, 0, 0, millis)
                .unwrap();
            let expected_utc =
                offset_minutes.and_then(|minutes| normalized_utc_millis(naive, minutes));
            assert_eq!(
                timestamp.utc_millis, expected_utc,
                "tail {tail}: normalized utc"
            );
            assert_eq!(
                timestamp.utc_millis.is_some(),
                ordering_state == NormalizedUtc,
                "tail {tail}: utc millis must exist exactly when ordering is normalized"
            );
        }
    }

    /// Both shipped attempts fabricated an offset from a microsecond tail.
    #[test]
    fn ccm_time_tail_rejects_both_historical_offset_bugs() {
        let timestamp = logical_record_for_time_tail("123456").timestamp;

        assert_ne!(
            timestamp.offset_minutes,
            Some(6),
            "greedy-regex attempt read the final digit as the offset"
        );
        assert_ne!(
            timestamp.offset_minutes,
            Some(456),
            "digit-count attempt read the final three digits as the offset"
        );
        assert_eq!(timestamp.offset_minutes, None);
        assert_eq!(
            timestamp.ordering_state,
            CcmTimestampParseState::OffsetMissing
        );
        assert_eq!(timestamp.utc_millis, None);
    }
}
