use once_cell::sync::Lazy;
use regex::Regex;

use super::severity::detect_severity_from_text;
use crate::models::log_entry::{LogEntry, LogFormat, Severity};

static GUID_FIELD_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$")
        .unwrap()
});

static TIMESTAMP_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"^(\d{4})[-/](\d{2})[-/](\d{2})\s+(\d{2}):(\d{2}):(\d{2})(?:(?::|\.)(\d{1,7}))?$",
    )
    .unwrap()
});

pub fn matches_reporting_events_record(line: &str) -> bool {
    let fields: Vec<&str> = line.split('\t').collect();
    if fields.len() < 11 {
        return false;
    }

    GUID_FIELD_RE.is_match(fields[0].trim()) && parse_timestamp(fields[1].trim()).is_some()
}

pub fn parse_lines(lines: &[&str], file_path: &str) -> (Vec<LogEntry>, u32) {
    let mut entries = Vec::new();
    let mut parse_errors = 0;
    let mut next_id = 0;

    for (index, line) in lines.iter().enumerate() {
        let trimmed_end = line.trim_end();
        if trimmed_end.trim().is_empty() {
            continue;
        }

        if let Some(mut entry) = parse_line(trimmed_end, file_path) {
            entry.id = next_id;
            entry.line_number = (index + 1) as u32;
            entries.push(entry);
        } else {
            entries.push(fallback_entry(next_id, (index + 1) as u32, trimmed_end, file_path));
            parse_errors += 1;
        }

        next_id += 1;
    }

    (entries, parse_errors)
}

fn parse_line(line: &str, file_path: &str) -> Option<LogEntry> {
    let fields: Vec<&str> = line.split('\t').collect();
    if fields.len() < 11 {
        return None;
    }

    let record_guid = normalize_field(fields[0])?;
    if !GUID_FIELD_RE.is_match(record_guid) {
        return None;
    }

    let (timestamp, timestamp_display) = parse_timestamp(fields[1].trim())?;
    let event_id = normalize_field(fields[2]);
    let category = normalize_field(fields[3]);
    let level = normalize_field(fields[4]);
    let update_guid = normalize_field(fields[5]);
    let hresult = normalize_field(fields[6]);
    let agent = normalize_field(fields[7]);
    let status = normalize_field(fields[8]);
    let operation = normalize_field(fields[9]);
    let detail = join_message_fields(&fields[10..]);

    let component = agent
        .map(|value| value.to_string())
        .or_else(|| category.map(|value| value.to_string()));

    let message = build_message(
        record_guid,
        event_id,
        category,
        update_guid,
        hresult,
        status,
        operation,
        &detail,
    );

    let severity = determine_severity(level, status, operation, &detail, hresult);

    Some(LogEntry {
        id: 0,
        line_number: 0,
        message,
        component,
        timestamp: Some(timestamp),
        timestamp_display: Some(timestamp_display),
        severity,
        thread: None,
        thread_display: None,
        source_file: None,
        format: LogFormat::Timestamped,
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
    })
}

fn parse_timestamp(value: &str) -> Option<(i64, String)> {
    let caps = TIMESTAMP_RE.captures(value)?;

    let year: i32 = caps.get(1)?.as_str().parse().ok()?;
    let month: u32 = caps.get(2)?.as_str().parse().ok()?;
    let day: u32 = caps.get(3)?.as_str().parse().ok()?;
    let hour: u32 = caps.get(4)?.as_str().parse().ok()?;
    let minute: u32 = caps.get(5)?.as_str().parse().ok()?;
    let second: u32 = caps.get(6)?.as_str().parse().ok()?;
    let millis = parse_fractional_millis(caps.get(7).map(|m| m.as_str()));

    let parsed = chrono::NaiveDate::from_ymd_opt(year, month, day)
        .and_then(|date| date.and_hms_milli_opt(hour, minute, second, millis))?;

    Some((
        parsed.and_utc().timestamp_millis(),
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
            year, month, day, hour, minute, second, millis
        ),
    ))
}

fn parse_fractional_millis(value: Option<&str>) -> u32 {
    match value {
        Some(raw) => {
            let padded = format!("{:0<3}", raw);
            padded[..3].parse::<u32>().unwrap_or(0)
        }
        None => 0,
    }
}

#[allow(clippy::too_many_arguments)]
fn build_message(
    record_guid: &str,
    event_id: Option<&str>,
    category: Option<&str>,
    update_guid: Option<&str>,
    hresult: Option<&str>,
    status: Option<&str>,
    operation: Option<&str>,
    detail: &str,
) -> String {
    let mut parts = Vec::new();

    if let Some(status) = status {
        parts.push(status.to_string());
    }

    if let Some(operation) = operation {
        parts.push(operation.to_string());
    }

    if !detail.is_empty() {
        parts.push(detail.to_string());
    }

    if let Some(hresult) = hresult.filter(|value| !is_zero_hresult(value)) {
        parts.push(format!("HRESULT {}", hresult));
    }

    if let Some(event_id) = event_id {
        parts.push(format!("EventId {}", event_id));
    }

    if let Some(category) = category {
        parts.push(format!("Category {}", category));
    }

    if let Some(update_guid) = update_guid.filter(|value| !is_placeholder_guid(value)) {
        parts.push(format!("Update {}", update_guid));
    }

    parts.push(format!("Record {}", record_guid));

    parts.join(" | ")
}

fn determine_severity(
    level: Option<&str>,
    status: Option<&str>,
    operation: Option<&str>,
    detail: &str,
    hresult: Option<&str>,
) -> Severity {
    if let Some(level) = level {
        let normalized = level.trim().to_ascii_lowercase();
        if matches!(normalized.as_str(), "3" | "error" | "failed" | "failure") {
            return Severity::Error;
        }
        if matches!(normalized.as_str(), "2" | "warning" | "warn") {
            return Severity::Warning;
        }
    }

    if let Some(status) = status {
        let normalized = status.trim().to_ascii_lowercase();
        if normalized.contains("fail") || normalized.contains("error") {
            return Severity::Error;
        }
        if normalized.contains("warn") {
            return Severity::Warning;
        }
    }

    if hresult.is_some_and(|value| !is_zero_hresult(value)) {
        return Severity::Error;
    }

    let combined = [operation.unwrap_or(""), detail]
        .join(" ")
        .trim()
        .to_string();
    detect_severity_from_text(&combined)
}

fn normalize_field(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == "-" {
        None
    } else {
        Some(trimmed)
    }
}

fn join_message_fields(fields: &[&str]) -> String {
    fields
        .iter()
        .map(|field| field.trim())
        .filter(|field| !field.is_empty())
        .collect::<Vec<_>>()
        .join("\t")
}

fn is_zero_hresult(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    matches!(normalized.as_str(), "0" | "0x0" | "0x00000000")
}

fn is_placeholder_guid(value: &str) -> bool {
    value.eq_ignore_ascii_case("{00000000-0000-0000-0000-000000000000}")
}

fn fallback_entry(id: u64, line_number: u32, line: &str, file_path: &str) -> LogEntry {
    LogEntry {
        id,
        line_number,
        message: line.trim_end().to_string(),
        component: None,
        timestamp: None,
        timestamp_display: None,
        severity: detect_severity_from_text(line),
        thread: None,
        thread_display: None,
        source_file: None,
        format: LogFormat::Timestamped,
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matches_reporting_events_record() {
        assert!(matches_reporting_events_record(
            "{11111111-1111-1111-1111-111111111111}\t2024-01-15 08:00:00:123\t1\tSoftware Update\t1\t{22222222-2222-2222-2222-222222222222}\t0x00000000\tWindows Update Agent\tSuccess\tInstallation\tInstallation Successful: KB5034123"
        ));
        assert!(!matches_reporting_events_record("plain text"));
    }

    #[test]
    fn test_parse_lines_parses_structured_rows() {
        let lines = [
            "{11111111-1111-1111-1111-111111111111}\t2024-01-15 08:00:00:123\t1\tSoftware Update\t1\t{22222222-2222-2222-2222-222222222222}\t0x00000000\tWindows Update Agent\tSuccess\tInstallation\tInstallation Successful: KB5034123",
            "{33333333-3333-3333-3333-333333333333}\t2024-01-15 08:05:00:456\t2\tSoftware Update\t3\t{44444444-4444-4444-4444-444444444444}\t0x80240022\tWindows Update Agent\tFailure\tInstallation\tInstallation failed for KB5034441",
        ];

        let (entries, parse_errors) = parse_lines(&lines, "C:/Windows/SoftwareDistribution/ReportingEvents.log");

        assert_eq!(parse_errors, 0);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].component.as_deref(), Some("Windows Update Agent"));
        assert_eq!(entries[0].timestamp_display.as_deref(), Some("2024-01-15 08:00:00.123"));
        assert!(entries[0].message.contains("Success | Installation"));
        assert_eq!(entries[1].severity, Severity::Error);
        assert!(entries[1].message.contains("HRESULT 0x80240022"));
    }

    #[test]
    fn test_parse_lines_keeps_fallback_for_malformed_rows() {
        let lines = [
            "{11111111-1111-1111-1111-111111111111}\t2024-01-15 08:00:00:123\t1\tSoftware Update\t1\t{22222222-2222-2222-2222-222222222222}\t0x00000000\tWindows Update Agent\tSuccess\tInstallation\tInstallation Successful: KB5034123",
            "{33333333-3333-3333-3333-333333333333}\tnot-a-timestamp\t2\tSoftware Update\t3\t{44444444-4444-4444-4444-444444444444}\t0x80240022\tWindows Update Agent\tFailure\tInstallation\tInstallation failed for KB5034441",
            "orphan raw line",
            "{55555555-5555-5555-5555-555555555555}\t2024-01-15 08:10:00:789\t3\tSoftware Update\t2\t{66666666-6666-6666-6666-666666666666}\t0x00000000\tWindows Update Agent\tWarning\tScan\tRetry required",
        ];

        let (entries, parse_errors) = parse_lines(&lines, "C:/Windows/SoftwareDistribution/ReportingEvents.log");

        assert_eq!(parse_errors, 2);
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[1].message, lines[1]);
        assert_eq!(entries[2].message, "orphan raw line");
        assert_eq!(entries[3].severity, Severity::Warning);
        assert_eq!(entries[3].line_number, 4);
    }
}