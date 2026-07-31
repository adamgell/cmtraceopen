//! Parsers for the Windows Device Inventory log dialects.

use chrono::{DateTime, NaiveDateTime};
use regex::{Captures, Regex};
use std::sync::OnceLock;

use crate::models::log_entry::{LogEntry, LogFormat, Severity};

/// The known Windows Device Inventory log dialects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceInventoryLogDialect {
    Harvester,
    Adaptor,
    RotationFailure,
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
pub fn detect_dialect(content: &str, file_path: &str) -> Option<DeviceInventoryLogDialect> {
    let harvester_headers = count_headers(content, harvester_re());
    if harvester_headers >= 2
        || (harvester_headers >= 1 && has_filename_hint(file_path, "intuneinventoryharvesterlog"))
    {
        return Some(DeviceInventoryLogDialect::Harvester);
    }

    let adaptor_headers = count_headers(content, adaptor_re());
    if adaptor_headers >= 2
        || (adaptor_headers >= 1 && has_filename_hint(file_path, "intuneinventoryadapterlog"))
    {
        return Some(DeviceInventoryLogDialect::Adaptor);
    }

    if count_headers(content, rotation_re()) >= 1 {
        return Some(DeviceInventoryLogDialect::RotationFailure);
    }

    None
}

/// Parse a complete Device Inventory log using the already-selected dialect.
pub fn parse_content(
    content: &str,
    file_path: &str,
    dialect: DeviceInventoryLogDialect,
) -> (Vec<LogEntry>, u32) {
    let mut records = Vec::new();
    let mut parse_errors = 0;

    for (index, raw_line) in content.lines().enumerate() {
        let line_number = (index + 1) as u32;
        let line = raw_line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }

        let parsed = match dialect {
            DeviceInventoryLogDialect::Harvester => harvester_re()
                .captures(line)
                .map(|caps| parse_harvester(&caps, line_number)),
            DeviceInventoryLogDialect::Adaptor => adaptor_re()
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
