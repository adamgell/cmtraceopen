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
        r#"<time="(?P<h>\d{1,2}):(?P<m>\d{1,2}):(?P<s>\d{1,2})\.(?P<ms>\d+)(?P<tz>[+-]*\d+)""#,
        r#"\s+date="(?P<mon>\d{1,2})-(?P<day>\d{1,2})-(?P<yr>\d{4})""#,
        r#"\s+component="(?P<comp>[^"]*)""#,
        r#"\s+context="[^"]*""#,
        r#"\s+type="(?P<typ>\d)""#,
        r#"\s+thread="(?P<thr>\d+)""#,
        r#"(?:\s+file="(?P<file>[^"]*)")?>"#,
    ))
    .expect("CCM regex must compile")
})
}

/// Parse a single CCM-format log line.
/// Returns None if the line doesn't match the CCM format.
fn parse_line(line: &str) -> Option<CcmParsed> {
    let caps = ccm_re().captures(line)?;
    parse_captures(&caps)
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
}

pub(crate) fn truncate_subsecond_to_millis(value: &str) -> Option<u32> {
    if value.len() > 3 {
        value[..3].parse().ok()
    } else {
        value.parse().ok()
    }
}

/// Convert a naive local datetime + optional timezone offset (in minutes) to UTC epoch millis.
/// Falls back to treating naive as UTC if the offset is invalid or overflows.
pub(crate) fn naive_to_utc_millis(naive: chrono::NaiveDateTime, offset_minutes: Option<i32>) -> i64 {
    if let Some(offset_minutes) = offset_minutes {
        offset_minutes
            .checked_mul(60)
            .and_then(FixedOffset::east_opt)
            .and_then(|offset| offset.from_local_datetime(&naive).single())
            .map(|dt| dt.timestamp_millis())
            .unwrap_or_else(|| naive.and_utc().timestamp_millis())
    } else {
        naive.and_utc().timestamp_millis()
    }
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
        Some(0) => Severity::Info, // PSADT v4 Success type — treated as Info
        Some(2) => Severity::Warning,
        Some(3) => Severity::Error,
        Some(_) => Severity::Info,
        None => detect_severity_from_text(message),
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
        Some(ParserSpecialization::Ime) => crate::intune::ime_parser::parse_ime_entries(content, file_path),
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
    let line_starts = build_line_starts(content);
    let mut entries: Vec<LogEntry> = Vec::new();
    let mut errors = 0u32;
    let mut id_counter = 0u64;
    let mut cursor = 0usize;
    let mut matched_any = false;

    for caps in ccm_re().captures_iter(content) {
        let Some(full_match) = caps.get(0) else {
            continue;
        };

        // Emit unmatched text between the previous match and this one
        push_unmatched_plain(
            &content[cursor..full_match.start()],
            cursor,
            &line_starts,
            file_path,
            &mut entries,
            &mut id_counter,
            &mut errors,
        );

        // Parse the matched CCM record
        let line_number = line_number_for_offset(&line_starts, full_match.start());
        if let Some(parsed) = parse_captures(&caps) {
            entries.push(LogEntry {
                id: id_counter,
                line_number,
                message: parsed.message,
                component: parsed.component,
                timestamp: parsed.timestamp,
                timestamp_display: parsed.timestamp_display,
                severity: parsed.severity,
                thread: Some(parsed.thread),
                thread_display: parsed.thread_display,
                source_file: parsed.source_file,
                format: LogFormat::Ccm,
                file_path: file_path.to_string(),
                timezone_offset: Some(parsed.timezone_offset),
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
        } else {
            push_unmatched_plain(
                full_match.as_str(),
                full_match.start(),
                &line_starts,
                file_path,
                &mut entries,
                &mut id_counter,
                &mut errors,
            );
        }

        cursor = full_match.end();
        matched_any = true;
    }

    // Trailing unmatched text
    push_unmatched_plain(
        &content[cursor..],
        cursor,
        &line_starts,
        file_path,
        &mut entries,
        &mut id_counter,
        &mut errors,
    );

    if !matched_any {
        // No CCM records found at all — fall back to line-by-line
        let lines: Vec<&str> = content.lines().collect();
        return parse_lines(&lines, file_path);
    }

    (entries, errors)
}

/// Parse named captures from a CCM regex match into a CcmParsed struct.
fn parse_captures(caps: &regex::Captures<'_>) -> Option<CcmParsed> {
    let msg = caps.name("msg").map(|m| m.as_str().to_string())?;
    let h: u32 = caps.name("h")?.as_str().parse().ok()?;
    let m: u32 = caps.name("m")?.as_str().parse().ok()?;
    let s: u32 = caps.name("s")?.as_str().parse().ok()?;
    let ms_str = caps.name("ms")?.as_str();
    let ms = truncate_subsecond_to_millis(ms_str)?;
    let tz: i32 = caps.name("tz")?.as_str().parse().ok()?;
    let mon: u32 = caps.name("mon")?.as_str().parse().ok()?;
    let day: u32 = caps.name("day")?.as_str().parse().ok()?;
    let yr: i32 = caps.name("yr")?.as_str().parse().ok()?;
    let comp = caps.name("comp").map(|m| m.as_str().to_string());
    let typ: u32 = caps.name("typ")?.as_str().parse().ok()?;
    let thr: u32 = caps.name("thr")?.as_str().parse().ok()?;
    let file = caps.name("file").map(|m| m.as_str().to_string());

    let severity = severity_from_type_field(Some(typ), &msg);
    let (timestamp, timestamp_display) = build_timestamp(mon, day, yr, h, m, s, ms, Some(tz));
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
        timezone_offset: tz,
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

/// Emit each non-empty physical line in `segment` as a plain-text LogEntry.
fn push_unmatched_plain(
    segment: &str,
    base_offset: usize,
    line_starts: &[usize],
    file_path: &str,
    entries: &mut Vec<LogEntry>,
    id_counter: &mut u64,
    errors: &mut u32,
) {
    let mut local_offset = 0usize;
    for piece in segment.split_inclusive('\n') {
        let line = piece.trim_end_matches(['\r', '\n']);
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            entries.push(LogEntry {
                id: *id_counter,
                line_number: line_number_for_offset(line_starts, base_offset + local_offset),
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
                entries.push(LogEntry {
                    id: id_counter,
                    line_number: (i + 1) as u32,
                    message: parsed.message,
                    component: parsed.component,
                    timestamp: parsed.timestamp,
                    timestamp_display: parsed.timestamp_display,
                    severity: parsed.severity,
                    thread: Some(parsed.thread),
                    thread_display: parsed.thread_display,
                    source_file: parsed.source_file,
                    format: LogFormat::Ccm,
                    file_path: file_path.to_string(),
                    timezone_offset: Some(parsed.timezone_offset),
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
        assert!(entries[1].message.contains("Downloaded profile payload is not valid JSON"));
        assert!(entries[1].message.contains("At C:\\Windows\\IMECache\\HealthScripts\\script.ps1:457 char:9"));
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
        assert_eq!(ts, Some(expected_utc), "extreme offset should fall back to UTC");
        assert!(display.is_some(), "display should always be present");
    }
}
