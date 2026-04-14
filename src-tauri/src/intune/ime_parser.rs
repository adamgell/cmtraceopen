use chrono::{FixedOffset, Local, LocalResult, TimeZone, Utc};
use regex::Regex;

use crate::models::log_entry::{LogEntry, LogFormat, Severity};
use crate::parser::ccm::{build_timestamp, format_thread_display, severity_from_type_field};
use crate::parser::severity::detect_severity_from_text;
use std::sync::OnceLock;

/// A parsed IME log line with extracted timestamp and message.
#[derive(Debug, Clone)]
pub struct ImeLine {
    pub line_number: u32,
    pub timestamp: Option<String>,
    pub timestamp_utc: Option<String>,
    pub message: String,
    pub component: Option<String>,
}

fn ime_record_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(r#"<!\[LOG\[(?P<msg>[\s\S]*?)\]LOG\]!><(?P<attrs>[^>]*)>"#)
        .expect("IME record regex must compile")
})
}

/// Regex for simple timestamped log lines (fallback format):
/// YYYY-MM-DD HH:MM:SS.fff message
fn simple_ts_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(r#"^(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[\.\d]*)\s+(?P<msg>.+)$"#)
        .expect("IME fallback timestamp regex must compile")
})
}

#[derive(Debug, Clone)]
struct ParsedImeRecord {
    line: ImeLine,
    timestamp_millis: Option<i64>,
    timestamp_display: Option<String>,
    severity: Severity,
    thread: Option<u32>,
    thread_display: Option<String>,
    source_file: Option<String>,
    timezone_offset: Option<i32>,
    format: LogFormat,
}

#[derive(Debug, Default, Clone, Copy)]
struct ParsedImeAttrs<'a> {
    component: Option<&'a str>,
    source_file: Option<&'a str>,
    thread: Option<u32>,
    type_value: Option<u32>,
    date: Option<&'a str>,
    time: Option<&'a str>,
}

/// Parse IME log content into structured logical records.
pub fn parse_ime_content(content: &str) -> Vec<ImeLine> {
    let parsed = parse_ime_records(content);
    parsed.entries.into_iter().map(|entry| entry.line).collect()
}

/// Parse IME log content into shared log entries while preserving logical records.
pub fn parse_ime_entries(content: &str, file_path: &str) -> (Vec<LogEntry>, u32) {
    let parsed = parse_ime_records(content);
    let entries = parsed
        .entries
        .into_iter()
        .enumerate()
        .map(|(id, entry)| LogEntry {
            id: id as u64,
            line_number: entry.line.line_number,
            message: entry.line.message,
            component: entry.line.component,
            timestamp: entry.timestamp_millis,
            timestamp_display: entry.timestamp_display,
            severity: entry.severity,
            thread: entry.thread,
            thread_display: entry.thread_display,
            source_file: entry.source_file,
            format: entry.format,
            file_path: file_path.to_string(),
            timezone_offset: entry.timezone_offset,
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
        })
        .collect();

    // Post-process: extract [Subsystem] prefix from message into source_file
    // when the CCM file="" attribute is empty (common in IME logs).
    let entries = enrich_subsystem_source(entries);

    (entries, parsed.parse_errors)
}

/// Extract `[SubSystem]` prefix from IME log messages and populate `source_file`
/// when it is empty. This surfaces the sub-component in the "Source" column.
///
/// Examples:
/// - `[Win32App] Starting app check in` → source_file = "Win32App"
/// - `[Win32App][Win32AppDownloadExecutor] Execution completed` → source_file = "Win32App"
/// - `[PowerShell] Script parameters tamper validation` → source_file = "PowerShell"
fn enrich_subsystem_source(mut entries: Vec<LogEntry>) -> Vec<LogEntry> {
    for entry in &mut entries {
        if entry.source_file.is_some() {
            continue;
        }
        if let Some(subsystem) = extract_subsystem_prefix(&entry.message) {
            entry.source_file = Some(subsystem);
        }
    }
    entries
}

/// Extract the first `[Name]` prefix from a message string.
/// Returns the name without brackets, or None if no prefix found.
fn extract_subsystem_prefix(message: &str) -> Option<String> {
    let msg = message.trim_start();
    if !msg.starts_with('[') {
        return None;
    }
    let end = msg.find(']')?;
    let name = &msg[1..end];
    // Skip if it looks like a GUID or timestamp rather than a subsystem name
    if name.contains('-') && name.len() > 20 {
        return None;
    }
    if name.is_empty() {
        return None;
    }
    Some(name.to_string())
}

struct ParsedImeChunk {
    entries: Vec<ParsedImeRecord>,
    parse_errors: u32,
}

fn parse_ime_records(content: &str) -> ParsedImeChunk {
    let line_starts = build_line_starts(content);
    let mut entries = Vec::with_capacity(line_starts.len());
    let mut parse_errors = 0u32;
    let mut cursor = 0usize;
    let mut matched_any = false;

    for caps in ime_record_re().captures_iter(content) {
        let Some(full_match) = caps.get(0) else {
            continue;
        };

        push_unmatched_segment(
            &content[cursor..full_match.start()],
            cursor,
            &line_starts,
            &mut entries,
            &mut parse_errors,
        );

        if let Some(record) = parse_record(&caps, full_match.start(), &line_starts) {
            entries.push(record);
        } else {
            push_unmatched_segment(
                full_match.as_str(),
                full_match.start(),
                &line_starts,
                &mut entries,
                &mut parse_errors,
            );
        }

        cursor = full_match.end();
        matched_any = true;
    }

    push_unmatched_segment(
        &content[cursor..],
        cursor,
        &line_starts,
        &mut entries,
        &mut parse_errors,
    );

    if matched_any {
        ParsedImeChunk {
            entries,
            parse_errors,
        }
    } else {
        parse_fallback_lines(content)
    }
}

fn parse_record(
    caps: &regex::Captures<'_>,
    offset: usize,
    line_starts: &[usize],
) -> Option<ParsedImeRecord> {
    let message = caps.name("msg")?.as_str().to_string();
    let attrs = parse_attributes(caps.name("attrs")?.as_str());
    let component = attrs
        .component
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let source_file = attrs
        .source_file
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let thread = attrs.thread;
    let thread_display = thread.map(format_thread_display);
    let severity = severity_from_type_field(attrs.type_value, &message);
    let (timestamp_millis, timestamp_display, timezone_offset, line_timestamp, line_timestamp_utc) =
        parse_timestamp_fields(attrs.date, attrs.time);

    Some(ParsedImeRecord {
        line: ImeLine {
            line_number: line_number_for_offset(line_starts, offset),
            timestamp: line_timestamp,
            timestamp_utc: line_timestamp_utc,
            message,
            component,
        },
        timestamp_millis,
        timestamp_display,
        severity,
        thread,
        thread_display,
        source_file,
        timezone_offset,
        format: LogFormat::Ccm,
    })
}

fn parse_attributes(attrs: &str) -> ParsedImeAttrs<'_> {
    let bytes = attrs.as_bytes();
    let mut index = 0usize;
    let mut parsed = ParsedImeAttrs::default();

    while index < bytes.len() {
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }

        let key_start = index;
        while index < bytes.len() && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
        {
            index += 1;
        }

        if key_start == index {
            index += 1;
            continue;
        }

        if index + 1 >= bytes.len() || bytes[index] != b'=' || bytes[index + 1] != b'"' {
            while index < bytes.len() && !bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            continue;
        }

        let key = &attrs[key_start..index];
        index += 2;

        let value_start = index;
        while index < bytes.len() && bytes[index] != b'"' {
            index += 1;
        }

        if index >= bytes.len() {
            break;
        }

        let value = &attrs[value_start..index];
        match_attribute(&mut parsed, key, value);
        index += 1;
    }

    parsed
}

#[expect(clippy::type_complexity, reason = "tuple return avoids extra struct for internal parsing")]
fn parse_timestamp_fields(
    date: Option<&str>,
    time: Option<&str>,
) -> (
    Option<i64>,
    Option<String>,
    Option<i32>,
    Option<String>,
    Option<String>,
) {
    let Some(date) = date else {
        return (None, None, None, None, None);
    };
    let Some(time) = time else {
        return (None, None, None, None, None);
    };

    let Some((month, day, year)) = parse_date(date) else {
        return (None, None, None, None, None);
    };
    let Some((hour, minute, second, millis, timezone_offset)) = parse_time(time) else {
        return (None, None, None, None, None);
    };

    // When no timezone offset is embedded in the log (the norm for IME logs),
    // fall back to the machine's current local UTC offset so the display column
    // shows the correct local time rather than treating local time as UTC.
    let effective_tz = timezone_offset.or_else(|| {
        let offset_secs = chrono::Local::now().offset().local_minus_utc();
        offset_secs.checked_div(60)
    });

    let (timestamp_millis, timestamp_display) =
        build_timestamp(month, day, year, hour, minute, second, millis, effective_tz);
    let line_timestamp = timestamp_display.clone();
    let line_timestamp_utc = build_utc_timestamp(
        month,
        day,
        year,
        hour,
        minute,
        second,
        millis,
        timezone_offset,
    );

    (
        timestamp_millis,
        timestamp_display,
        timezone_offset,
        line_timestamp,
        line_timestamp_utc,
    )
}

#[expect(clippy::too_many_arguments, reason = "timestamp construction keeps calendar fields explicit")]
fn build_utc_timestamp(
    month: u32,
    day: u32,
    year: i32,
    hour: u32,
    minute: u32,
    second: u32,
    millis: u32,
    timezone_offset: Option<i32>,
) -> Option<String> {
    let naive = chrono::NaiveDate::from_ymd_opt(year, month, day)?
        .and_hms_milli_opt(hour, minute, second, millis)?;

    let utc_value = if let Some(offset_minutes) = timezone_offset {
        offset_minutes
            .checked_mul(60)
            .and_then(FixedOffset::east_opt)
            .and_then(|offset| offset.from_local_datetime(&naive).single())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|| naive.and_utc())
    } else {
        match Local.from_local_datetime(&naive) {
            LocalResult::Single(local_value) => local_value.with_timezone(&Utc),
            LocalResult::Ambiguous(local_value, _) => local_value.with_timezone(&Utc),
            LocalResult::None => naive.and_utc(),
        }
    };

    Some(utc_value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
}

fn parse_fallback_timestamp_utc(value: &str) -> Option<String> {
    let naive = chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S%.f").ok()?;
    let local_value = match Local.from_local_datetime(&naive) {
        LocalResult::Single(local_value) => local_value,
        LocalResult::Ambiguous(local_value, _) => local_value,
        LocalResult::None => return None,
    };

    Some(
        local_value
            .with_timezone(&Utc)
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    )
}

fn parse_date(date: &str) -> Option<(u32, u32, i32)> {
    let (month, remainder) = date.split_once('-')?;
    let (day, year) = remainder.split_once('-')?;
    Some((
        parse_ascii_u32(month)?,
        parse_ascii_u32(day)?,
        parse_ascii_i32(year)?,
    ))
}

fn parse_time(time: &str) -> Option<(u32, u32, u32, u32, Option<i32>)> {
    let timezone_start = find_timezone_start(time);
    let (time_value, timezone_value) = match timezone_start {
        Some(index) => (&time[..index], Some(&time[index..])),
        None => (time, None),
    };
    let (hour, remainder) = time_value.split_once(':')?;
    let (minute, second_and_fraction) = remainder.split_once(':')?;
    let (second, fraction) = second_and_fraction
        .split_once('.')
        .map_or((second_and_fraction, ""), |(seconds, fraction)| {
            (seconds, fraction)
        });
    let millis = if fraction.is_empty() {
        0
    } else {
        truncate_fraction_to_millis(fraction)?
    };

    Some((
        parse_ascii_u32(hour)?,
        parse_ascii_u32(minute)?,
        parse_ascii_u32(second)?,
        millis,
        timezone_value.and_then(parse_timezone_offset),
    ))
}

fn parse_timezone_offset(value: &str) -> Option<i32> {
    if value.eq_ignore_ascii_case("z") {
        return Some(0);
    }

    if value.contains(':') {
        let sign = if value.starts_with('-') { -1 } else { 1 };
        let trimmed = value.trim_start_matches(['+', '-']);
        let (hours, minutes) = trimmed.split_once(':')?;
        let hours = parse_ascii_i32(hours)?;
        let minutes = parse_ascii_i32(minutes)?;
        return Some(sign * ((hours * 60) + minutes));
    }

    parse_ascii_i32(value)
}

fn match_attribute<'a>(parsed: &mut ParsedImeAttrs<'a>, key: &str, value: &'a str) {
    if key.eq_ignore_ascii_case("component") {
        parsed.component = Some(value);
    } else if key.eq_ignore_ascii_case("file") {
        parsed.source_file = Some(value);
    } else if key.eq_ignore_ascii_case("thread") {
        parsed.thread = parse_ascii_u32(value);
    } else if key.eq_ignore_ascii_case("type") {
        parsed.type_value = parse_ascii_u32(value);
    } else if key.eq_ignore_ascii_case("date") {
        parsed.date = Some(value);
    } else if key.eq_ignore_ascii_case("time") {
        parsed.time = Some(value);
    }
}

fn find_timezone_start(time: &str) -> Option<usize> {
    let bytes = time.as_bytes();
    for (index, value) in bytes.iter().enumerate().skip(1) {
        if matches!(*value, b'+' | b'-') {
            return Some(index);
        }
    }

    None
}

fn truncate_fraction_to_millis(value: &str) -> Option<u32> {
    let mut millis = 0u32;
    let mut digits = 0u8;

    for byte in value.bytes() {
        if !byte.is_ascii_digit() {
            return None;
        }

        if digits < 3 {
            millis = (millis * 10) + u32::from(byte - b'0');
            digits += 1;
        }
    }

    while digits < 3 {
        millis *= 10;
        digits += 1;
    }

    Some(millis)
}

fn parse_ascii_u32(value: &str) -> Option<u32> {
    if value.is_empty() {
        return None;
    }

    let mut parsed = 0u32;
    for byte in value.bytes() {
        if !byte.is_ascii_digit() {
            return None;
        }

        parsed = parsed
            .checked_mul(10)?
            .checked_add(u32::from(byte - b'0'))?;
    }

    Some(parsed)
}

fn parse_ascii_i32(value: &str) -> Option<i32> {
    let bytes = value.as_bytes();
    if bytes.is_empty() {
        return None;
    }

    let (sign, digits) = match bytes[0] {
        b'+' => (1i32, &value[1..]),
        b'-' => (-1i32, &value[1..]),
        _ => (1i32, value),
    };

    let parsed = parse_ascii_u32(digits)? as i32;
    parsed.checked_mul(sign)
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

fn push_unmatched_segment(
    segment: &str,
    base_offset: usize,
    line_starts: &[usize],
    entries: &mut Vec<ParsedImeRecord>,
    parse_errors: &mut u32,
) {
    let mut local_offset = 0usize;

    for piece in segment.split_inclusive('\n') {
        let line = piece.trim_end_matches(['\r', '\n']);
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            entries.push(ParsedImeRecord {
                line: ImeLine {
                    line_number: line_number_for_offset(line_starts, base_offset + local_offset),
                    timestamp: None,
                    timestamp_utc: None,
                    message: trimmed.to_string(),
                    component: None,
                },
                timestamp_millis: None,
                timestamp_display: None,
                severity: detect_severity_from_text(trimmed),
                thread: None,
                thread_display: None,
                source_file: None,
                timezone_offset: None,
                format: LogFormat::Plain,
            });
            *parse_errors += 1;
        }
        local_offset += piece.len();
    }
}

fn parse_fallback_lines(content: &str) -> ParsedImeChunk {
    let mut entries = Vec::new();

    for (index, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some(caps) = simple_ts_re().captures(trimmed) {
            let timestamp = caps.name("ts").map(|value| value.as_str().to_string());
            let timestamp_utc = timestamp.as_deref().and_then(parse_fallback_timestamp_utc);
            let message = caps
                .name("msg")
                .map(|value| value.as_str().to_string())
                .unwrap_or_default();
            entries.push(ParsedImeRecord {
                line: ImeLine {
                    line_number: (index + 1) as u32,
                    timestamp: timestamp.clone(),
                    timestamp_utc,
                    message: message.clone(),
                    component: None,
                },
                timestamp_millis: None,
                timestamp_display: timestamp,
                severity: detect_severity_from_text(&message),
                thread: None,
                thread_display: None,
                source_file: None,
                timezone_offset: None,
                format: LogFormat::Plain,
            });
        } else {
            entries.push(ParsedImeRecord {
                line: ImeLine {
                    line_number: (index + 1) as u32,
                    timestamp: None,
                    timestamp_utc: None,
                    message: trimmed.to_string(),
                    component: None,
                },
                timestamp_millis: None,
                timestamp_display: None,
                severity: detect_severity_from_text(trimmed),
                thread: None,
                thread_display: None,
                source_file: None,
                timezone_offset: None,
                format: LogFormat::Plain,
            });
        }
    }

    ParsedImeChunk {
        parse_errors: 0,
        entries,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ime_content_preserves_logical_record_start_lines() {
        let content = concat!(
            "<![LOG[First record]LOG]!><time=\"11:16:37.3093207\" date=\"3-12-2026\" component=\"HealthScripts\" context=\"\" type=\"1\" thread=\"50\" file=\"\">\n",
            "<![LOG[Second line one\n",
            "Second line two]LOG]!><time=\"11:16:42.3322734\" date=\"3-12-2026\" component=\"HealthScripts\" context=\"\" type=\"3\" thread=\"50\" file=\"\">\n",
            "<![LOG[Third record]LOG]!><time=\"11:16:43.0000000\" date=\"3-12-2026\" component=\"HealthScripts\" context=\"\" type=\"1\" thread=\"50\" file=\"\">"
        );

        let lines = parse_ime_content(content);
        let expected_utc = parse_fallback_timestamp_utc("2026-03-12 11:16:37.309");

        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0].line_number, 1);
        assert_eq!(lines[1].line_number, 2);
        assert_eq!(lines[2].line_number, 4);
        assert_eq!(lines[1].message, "Second line one\nSecond line two");
        assert_eq!(lines[0].timestamp_utc, expected_utc);
    }

    #[test]
    fn test_parse_ime_entries_preserves_truncated_tail_as_plain_text() {
        let content = concat!(
            "<![LOG[Client Health evaluation starts.]LOG]!><time=\"23:00:10.6893636\" date=\"11-12-2025\" component=\"ClientHealth\" context=\"\" type=\"1\" thread=\"1\" file=\"\">\n",
            "\n",
            "<![LOG[OnStart, public cloud env.]LOG]!><time=\"23:00:11.4573058\" date=\"11-12-2025\" component=\"ClientHealth\" context=\"\" type=\"1\" thread=\"1\" file=\"\">\n",
            "<![LOG[Set MdmDeviceCertificate : 3788C1E384FDCB3F173A3222CB4191883A94224E]LOG]!><time=\"23:00"
        );

        let (entries, parse_errors) = parse_ime_entries(content, "ClientHealth.log");

        assert_eq!(parse_errors, 1);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].line_number, 1);
        assert_eq!(entries[1].line_number, 3);
        assert_eq!(entries[2].line_number, 4);
        assert_eq!(entries[2].format, LogFormat::Plain);
        assert!(entries[2].message.contains("Set MdmDeviceCertificate"));
    }

    #[test]
    fn test_parse_ime_entries_parses_attributes_without_regex_map_overhead() {
        let content = "<![LOG[Case-insensitive attribute parse]LOG]!><THREAD=\"50\" TYPE=\"3\" context=\"\" COMPONENT=\"HealthScripts\" DATE=\"3-12-2026\" TIME=\"11:16:42.3322734\" FILE=\"script.ps1\">";

        let (entries, parse_errors) = parse_ime_entries(content, "HealthScripts.log");

        assert_eq!(parse_errors, 0);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].component.as_deref(), Some("HealthScripts"));
        assert_eq!(entries[0].thread, Some(50));
        assert_eq!(entries[0].source_file.as_deref(), Some("script.ps1"));
        assert_eq!(entries[0].severity, Severity::Error);
        assert_eq!(
            entries[0].timestamp_display.as_deref(),
            Some("03-12-2026 11:16:42.332")
        );
    }

    #[test]
    fn test_parse_ime_content_normalizes_timezone_offset_to_utc() {
        let content = "<![LOG[Timezone aware]LOG]!><time=\"08:06:34.590-060\" date=\"09-02-2016\" component=\"ContentTransferManager\" context=\"\" type=\"1\" thread=\"3692\" file=\"datatransfer.cpp\">";

        let lines = parse_ime_content(content);

        assert_eq!(lines.len(), 1);
        assert_eq!(
            lines[0].timestamp_utc.as_deref(),
            Some("2016-09-02T09:06:34.590Z")
        );
    }

    #[test]
    fn test_build_utc_timestamp_extreme_offset_falls_back() {
        // Extreme offset should fall back to UTC-as-local, not return None
        let result = super::build_utc_timestamp(1, 1, 2024, 10, 0, 0, 0, Some(99999));
        assert!(result.is_some(), "extreme offset should fall back, not return None");
        assert_eq!(result.unwrap(), "2024-01-01T10:00:00.000Z");
    }

    /// IME logs typically omit the timezone offset from the time field.
    /// Verify that the local-time fallback is applied so the stored UTC millis
    /// differ from a naive UTC interpretation by the machine's current offset.
    #[test]
    fn test_no_timezone_in_time_field_uses_local_fallback() {
        // A record whose time= field has no +/- suffix (typical IME format)
        let content = "<![LOG[EMS Agent Started]LOG]!><time=\"00:22:30.000\" date=\"3-27-2026\" component=\"IntuneManagementExtension\" context=\"\" type=\"1\" thread=\"1\" file=\"\">";

        let (entries, _) = parse_ime_entries(content, "IntuneManagementExtension.log");
        assert_eq!(entries.len(), 1);

        let ts = entries[0].timestamp.expect("timestamp should be set");

        // Compute what the timestamp would be if naive time were treated as UTC (the old bug).
        let naive_utc = chrono::NaiveDate::from_ymd_opt(2026, 3, 27)
            .unwrap()
            .and_hms_milli_opt(0, 22, 30, 0)
            .unwrap()
            .and_utc()
            .timestamp_millis();

        // Compute what the timestamp should be with the local-timezone fallback.
        let local_offset_mins = chrono::Local::now().offset().local_minus_utc() / 60;
        let expected = crate::parser::ccm::naive_to_utc_millis(
            chrono::NaiveDate::from_ymd_opt(2026, 3, 27)
                .unwrap()
                .and_hms_milli_opt(0, 22, 30, 0)
                .unwrap(),
            Some(local_offset_mins),
        );

        assert_eq!(ts, expected, "timestamp should use local-timezone fallback");

        // If the machine is not UTC, the stored value must differ from the naive-UTC value.
        if local_offset_mins != 0 {
            assert_ne!(
                ts, naive_utc,
                "timestamp must not treat naive local time as UTC when offset is non-zero"
            );
        }
    }
}
