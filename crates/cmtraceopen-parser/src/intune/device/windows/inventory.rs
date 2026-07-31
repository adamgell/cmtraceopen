//! Parsers for the Windows Device Inventory log dialects.

use chrono::{DateTime, NaiveDateTime};
use regex::{Captures, Regex};
use std::sync::OnceLock;

use crate::models::log_entry::{LogEntry, LogFormat, Severity};

/// The known Windows Device Inventory log dialects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceInventoryLogDialect {
    Harvester,
    InventoryAdaptor,
    RotationFailure,
}

/// Pure framing result for incrementally collected Device Inventory records.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct LogicalRecordFramingResult {
    /// Records made complete by a later header or by the pending-size bound.
    pub completed_records: Vec<String>,
    /// The newest record, retained so a later append can add continuations.
    pub pending_record: Option<String>,
    /// Number of records force-completed because they reached the size bound.
    pub overflow_count: u32,
}

/// Add complete physical lines to a pending Device Inventory logical record.
///
/// Header recognition intentionally stays in this pure parser module so tailing
/// and whole-file parsing share the same dialect regexes. The caller owns
/// time-based flushing of `pending_record`.
pub fn frame_logical_records(
    dialect: DeviceInventoryLogDialect,
    mut pending_record: Option<String>,
    new_lines: &[&str],
    max_pending_bytes: usize,
) -> LogicalRecordFramingResult {
    assert!(
        max_pending_bytes >= 4,
        "logical record bound must fit one UTF-8 scalar"
    );

    let mut completed_records = Vec::new();
    let mut overflow_count = 0u32;

    for raw_line in new_lines {
        let line = raw_line.trim_end_matches('\r');
        if is_record_header(dialect, line) {
            if let Some(record) = pending_record.take() {
                completed_records.push(record);
            }
        }

        match pending_record.as_mut() {
            Some(record) => {
                record.push('\n');
                record.push_str(line);
            }
            None => pending_record = Some(line.to_string()),
        }

        while pending_record
            .as_ref()
            .is_some_and(|record| record.len() > max_pending_bytes)
        {
            let mut record = pending_record
                .take()
                .expect("oversized pending record must exist");
            let split_at = previous_char_boundary(&record, max_pending_bytes);
            let remainder = record.split_off(split_at);
            completed_records.push(record);
            overflow_count = overflow_count.saturating_add(1);
            pending_record = (!remainder.is_empty()).then_some(remainder);
        }
    }

    LogicalRecordFramingResult {
        completed_records,
        pending_record,
        overflow_count,
    }
}

fn is_record_header(dialect: DeviceInventoryLogDialect, line: &str) -> bool {
    match dialect {
        DeviceInventoryLogDialect::Harvester => harvester_re().is_match(line),
        DeviceInventoryLogDialect::InventoryAdaptor => adaptor_re().is_match(line),
        DeviceInventoryLogDialect::RotationFailure => rotation_re().is_match(line),
    }
}

fn previous_char_boundary(text: &str, maximum: usize) -> usize {
    let mut boundary = maximum.min(text.len());
    while !text.is_char_boundary(boundary) {
        boundary -= 1;
    }
    boundary
}

#[derive(Default)]
struct EntryMetadata {
    timestamp: Option<i64>,
    timestamp_display: Option<String>,
    thread: Option<u32>,
    thread_display: Option<String>,
    timezone_offset: Option<i32>,
}

fn harvester_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"^(?P<date>\d{1,2}/\d{1,2}/\d{4}) (?P<time>\d{1,2}:\d{2}:\d{2} [AP]M) \[(?P<level>Information|Warning|Error)\] (?P<message>.*)$")
            .expect("Device Inventory Harvester regex must compile")
    })
}

fn adaptor_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"^\[(?P<timestamp>[A-Z][a-z]{2} [A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2} \d{4})\]\[(?P<pid>\d+)\] - (?P<message>.*)$")
            .expect("Device Inventory Adaptor regex must compile")
    })
}

fn rotation_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T[^ ]+) (?P<message>.*)$")
            .expect("Device Inventory rotation regex must compile")
    })
}

/// Detect a Device Inventory dialect from log content and an optional filename hint.
///
/// A filename can lower the Harvester or Adaptor confidence threshold to one matching
/// header, but it is never sufficient without a matching content header.
pub fn detect_dialect(file_path: &str, content: &str) -> Option<DeviceInventoryLogDialect> {
    let harvester_headers = count_headers(content, harvester_re());
    if harvester_headers >= 2
        || (harvester_headers >= 1 && has_filename_hint(file_path, "intuneinventoryharvesterlog"))
    {
        return Some(DeviceInventoryLogDialect::Harvester);
    }

    let adaptor_headers = count_headers(content, adaptor_re());
    if adaptor_headers >= 2
        || (adaptor_headers >= 1 && has_filename_hint(file_path, "inventoryadaptor"))
    {
        return Some(DeviceInventoryLogDialect::InventoryAdaptor);
    }

    if has_rotation_failure_signature(content) {
        return Some(DeviceInventoryLogDialect::RotationFailure);
    }

    None
}

/// Parse a complete Device Inventory log using the already-selected dialect.
pub fn parse_content(
    file_path: &str,
    content: &str,
    dialect: DeviceInventoryLogDialect,
) -> (Vec<LogEntry>, u32) {
    let mut records: Vec<LogEntry> = Vec::new();
    let mut parse_errors = 0;

    for (index, raw_line) in content.lines().enumerate() {
        let line_number = (index + 1) as u32;
        let line = raw_line.trim_end_matches('\r');
        if line.is_empty() {
            if let Some(previous) = records.last_mut() {
                previous.message.push('\n');
            }
            continue;
        }

        let parsed = match dialect {
            DeviceInventoryLogDialect::Harvester => harvester_re()
                .captures(line)
                .map(|caps| parse_harvester(&caps, line_number)),
            DeviceInventoryLogDialect::InventoryAdaptor => adaptor_re()
                .captures(line)
                .map(|caps| parse_adaptor(&caps, line_number)),
            DeviceInventoryLogDialect::RotationFailure => rotation_re()
                .captures(line)
                .map(|caps| parse_rotation(&caps, line_number)),
        };

        if let Some((record, timestamp_valid)) = parsed {
            if !timestamp_valid {
                parse_errors += 1;
            }
            records.push(record);
        } else if matches!(dialect, DeviceInventoryLogDialect::Harvester)
            && looks_like_harvester_record(line)
        {
            records.push(orphan_record(line, line_number));
        } else if let Some(previous) = records.last_mut() {
            previous.message.push('\n');
            previous.message.push_str(line);
        } else {
            records.push(orphan_record(line, line_number));
        }
    }

    let entries = records
        .into_iter()
        .enumerate()
        .map(|(id, mut record)| {
            record.id = id as u64;
            record.file_path = file_path.to_string();
            record
        })
        .collect();

    (entries, parse_errors)
}

fn count_headers(content: &str, regex: &Regex) -> usize {
    content
        .lines()
        .map(|line| line.trim_end_matches('\r'))
        .filter(|line| regex.is_match(line))
        .count()
}

fn has_rotation_failure_signature(content: &str) -> bool {
    content
        .lines()
        .map(|line| line.trim_end_matches('\r'))
        .filter_map(|line| rotation_re().captures(line))
        .any(|captures| {
            captures.name("message").is_some_and(|message| {
                message
                    .as_str()
                    .contains("Failed to rotate Device Inventory")
            })
        })
}

fn has_filename_hint(file_path: &str, expected_stem: &str) -> bool {
    file_path
        .rsplit(['/', '\\'])
        .next()
        .is_some_and(|name| name.to_ascii_lowercase().contains(expected_stem))
}

fn looks_like_harvester_record(line: &str) -> bool {
    line.starts_with(|character: char| character.is_ascii_digit()) && line.contains(" [")
}

fn parse_harvester(caps: &Captures<'_>, line_number: u32) -> (LogEntry, bool) {
    let date = caps.name("date").expect("date capture").as_str();
    let time = caps.name("time").expect("time capture").as_str();
    let timestamp =
        NaiveDateTime::parse_from_str(&format!("{date} {time}"), "%m/%d/%Y %I:%M:%S %p").ok();
    let valid = timestamp.is_some();
    let message = caps.name("message").expect("message capture").as_str();
    let severity = match caps.name("level").expect("level capture").as_str() {
        "Information" => Severity::Info,
        "Warning" => Severity::Warning,
        "Error" => Severity::Error,
        _ => unreachable!("regex restricts Device Inventory Harvester levels"),
    };

    (
        log_entry(
            line_number,
            message,
            severity,
            EntryMetadata {
                timestamp: timestamp.map(|value| value.and_utc().timestamp_millis()),
                timestamp_display: timestamp
                    .map(|value| value.format("%m-%d-%Y %H:%M:%S.000").to_string()),
                ..EntryMetadata::default()
            },
        ),
        valid,
    )
}

fn parse_adaptor(caps: &Captures<'_>, line_number: u32) -> (LogEntry, bool) {
    let timestamp_text = caps.name("timestamp").expect("timestamp capture").as_str();
    let timestamp = NaiveDateTime::parse_from_str(timestamp_text, "%a %b %e %H:%M:%S %Y").ok();
    let valid = timestamp.is_some();
    let pid = caps
        .name("pid")
        .expect("pid capture")
        .as_str()
        .parse::<u32>()
        .expect("regex-restricted PID must parse");
    let message = caps.name("message").expect("message capture").as_str();

    (
        log_entry(
            line_number,
            message,
            Severity::Info,
            EntryMetadata {
                timestamp: timestamp.map(|value| value.and_utc().timestamp_millis()),
                timestamp_display: timestamp
                    .map(|value| value.format("%Y-%m-%d %H:%M:%S.000").to_string()),
                thread: Some(pid),
                thread_display: Some(format!("{pid} (0x{pid:X})")),
                ..EntryMetadata::default()
            },
        ),
        valid,
    )
}

fn parse_rotation(caps: &Captures<'_>, line_number: u32) -> (LogEntry, bool) {
    let timestamp_text = caps.name("timestamp").expect("timestamp capture").as_str();
    let timestamp = DateTime::parse_from_rfc3339(timestamp_text).ok();
    let valid = timestamp.is_some();
    let message = caps.name("message").expect("message capture").as_str();
    let timezone_offset = timestamp.map(|value| value.offset().local_minus_utc() / 60);

    (
        log_entry(
            line_number,
            message,
            Severity::Error,
            EntryMetadata {
                timestamp: timestamp.map(|value| value.timestamp_millis()),
                timestamp_display: timestamp
                    .map(|value| value.format("%Y-%m-%d %H:%M:%S%.3f").to_string()),
                timezone_offset,
                ..EntryMetadata::default()
            },
        ),
        valid,
    )
}

fn orphan_record(message: &str, line_number: u32) -> LogEntry {
    log_entry(
        line_number,
        message,
        Severity::Info,
        EntryMetadata::default(),
    )
}

fn log_entry(
    line_number: u32,
    message: &str,
    severity: Severity,
    metadata: EntryMetadata,
) -> LogEntry {
    LogEntry {
        id: 0,
        line_number,
        message: message.to_string(),
        component: None,
        timestamp: metadata.timestamp,
        timestamp_display: metadata.timestamp_display,
        severity,
        thread: metadata.thread,
        thread_display: metadata.thread_display,
        source_file: None,
        format: LogFormat::Timestamped,
        file_path: String::new(),
        timezone_offset: metadata.timezone_offset,
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

    const ADAPTOR_HEADER: &str = "[Thu Jul 30 13:05:02 2026][8604] - Adapter result:";
    const NEXT_ADAPTOR_HEADER: &str = "[Thu Jul 30 13:05:03 2026][8604] - Completed action.";

    #[test]
    fn logical_framing_flushes_previous_record_on_new_valid_header() {
        let first = frame_logical_records(
            DeviceInventoryLogDialect::InventoryAdaptor,
            None,
            &[ADAPTOR_HEADER],
            1024,
        );
        assert!(first.completed_records.is_empty());

        let second = frame_logical_records(
            DeviceInventoryLogDialect::InventoryAdaptor,
            first.pending_record,
            &[
                r#"{"Status":200,"Data":{"Example":"value"}}"#,
                NEXT_ADAPTOR_HEADER,
            ],
            1024,
        );

        assert_eq!(
            second.completed_records,
            vec![format!(
                "{ADAPTOR_HEADER}\n{}",
                r#"{"Status":200,"Data":{"Example":"value"}}"#
            )]
        );
        assert_eq!(second.pending_record.as_deref(), Some(NEXT_ADAPTOR_HEADER));
        assert_eq!(second.overflow_count, 0);
    }

    #[test]
    fn logical_framing_overflow_is_bounded_counted_and_lossless() {
        let max_pending_bytes = ADAPTOR_HEADER.len() + 8;
        let continuation = "continuation-0123456789";
        let expected = format!("{ADAPTOR_HEADER}\n{continuation}");

        let framed = frame_logical_records(
            DeviceInventoryLogDialect::InventoryAdaptor,
            None,
            &[ADAPTOR_HEADER, continuation],
            max_pending_bytes,
        );

        assert_eq!(framed.overflow_count, 1);
        assert!(framed
            .completed_records
            .iter()
            .all(|record| record.len() <= max_pending_bytes));
        assert!(framed
            .pending_record
            .as_ref()
            .is_none_or(|record| record.len() <= max_pending_bytes));

        let reconstructed = framed
            .completed_records
            .iter()
            .chain(framed.pending_record.iter())
            .cloned()
            .collect::<String>();
        assert_eq!(reconstructed, expected);
    }
}
