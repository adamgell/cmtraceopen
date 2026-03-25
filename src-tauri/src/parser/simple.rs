//! Simple/legacy format parser.
//!
//! Parses log lines in the format:
//!   message text$$<ComponentName><MM-dd-yyyy HH:mm:ss.fff+TTTTT><thread=N (0xNNNN)>
//!
//! This format has no type/severity field — severity is detected by
//! searching for "error", "fail" (excluding "failover"), and "warn"
//! in the message text, matching CMTrace's binary behavior.

use once_cell::sync::Lazy;
use regex::Regex;

use super::ccm::format_thread_display;
use super::severity::detect_severity_from_text;
use crate::models::log_entry::{LogEntry, LogFormat, Severity};

/// Combined regex for timestamp and thread portions in a single pass.
/// Matches: <MM-dd-yyyy HH:mm:ss.fff±TTTTT><thread=N (0xNNNN)>
/// The thread group is optional to handle lines without thread info.
static META_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(concat!(
        r#"<(\d{1,2})-(\d{1,2})-(\d{4})\s+(\d{1,2}):(\d{1,2}):(\d{1,2})\.(\d+)([+-]?\d+)>"#,
        r#"(?:<thread=(\d+)(?:\s*\(0x[0-9a-fA-F]+\))?>)?"#,
    ))
    .expect("Simple metadata regex must compile")
});

/// Parse a single simple-format log line.
fn parse_line(line: &str) -> Option<SimpleParsed> {
    // Split on "$$<" — everything before is the message
    let dollar_pos = line.find("$$<")?;
    let message = line[..dollar_pos].trim_end().to_string();
    let metadata = &line[dollar_pos + 3..]; // skip "$$<"

    // Extract component: first <...> block
    let comp_end = metadata.find('>')?;
    let component = metadata[..comp_end].to_string();
    let rest = &metadata[comp_end + 1..];

    // Single regex pass extracts both timestamp and thread
    let caps = META_RE.captures(rest)?;
    let mon: u32 = caps.get(1)?.as_str().parse().ok()?;
    let day: u32 = caps.get(2)?.as_str().parse().ok()?;
    let yr: i32 = caps.get(3)?.as_str().parse().ok()?;
    let h: u32 = caps.get(4)?.as_str().parse().ok()?;
    let m: u32 = caps.get(5)?.as_str().parse().ok()?;
    let s: u32 = caps.get(6)?.as_str().parse().ok()?;
    let ms_str = caps.get(7)?.as_str();
    let ms: u32 = if ms_str.len() > 3 {
        ms_str[..3].parse().ok()?
    } else {
        ms_str.parse().ok()?
    };
    let tz: i32 = caps.get(8)?.as_str().parse().ok()?;

    // Thread is optional (captured by the combined regex)
    let thread = caps
        .get(9)
        .and_then(|m| m.as_str().parse::<u32>().ok());

    let timestamp = chrono::NaiveDate::from_ymd_opt(yr, mon, day)
        .and_then(|d| d.and_hms_milli_opt(h, m, s, ms))
        .map(|dt| dt.and_utc().timestamp_millis());

    let timestamp_display = Some(format!(
        "{:02}-{:02}-{:04} {:02}:{:02}:{:02}.{:03}",
        mon, day, yr, h, m, s, ms
    ));

    // Reuse cached thread display from ccm module
    let thread_display = thread.map(format_thread_display);

    // Text-based severity detection (no type field in simple format)
    let severity = detect_severity_from_text(&message);

    Some(SimpleParsed {
        message,
        component,
        timestamp,
        timestamp_display,
        severity,
        thread,
        thread_display,
        timezone_offset: tz,
    })
}

struct SimpleParsed {
    message: String,
    component: String,
    timestamp: Option<i64>,
    timestamp_display: Option<String>,
    severity: Severity,
    thread: Option<u32>,
    thread_display: Option<String>,
    timezone_offset: i32,
}

/// Parse all lines as simple format.
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
                    component: Some(parsed.component),
                    timestamp: parsed.timestamp,
                    timestamp_display: parsed.timestamp_display,
                    severity: parsed.severity,
                    thread: parsed.thread,
                    thread_display: parsed.thread_display,
                    source_file: None,
                    format: LogFormat::Simple,
                    file_path: file_path.to_string(),
                    timezone_offset: Some(parsed.timezone_offset),
                    error_code_spans: Vec::new(),
                    ip_address: None,
                    host_name: None,
                    mac_address: None,
                });
                id_counter += 1;
            }
            None => {
                // Doesn't match simple format — treat as plain text
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
    fn test_parse_simple_line() {
        let line = r#"Sending status message (MessageID = 500). $$<SMS_HIERARCHY_MANAGER><07-15-2023 09:12:45.332+240><thread=4116 (0x1014)>"#;
        let parsed = parse_line(line).expect("should parse");
        assert_eq!(parsed.message, "Sending status message (MessageID = 500).");
        assert_eq!(parsed.component, "SMS_HIERARCHY_MANAGER");
        assert_eq!(parsed.thread, Some(4116));
        assert_eq!(parsed.severity, Severity::Info);
        assert_eq!(parsed.timezone_offset, 240);
    }

    #[test]
    fn test_parse_simple_error() {
        let line = r#"An error occurred during processing $$<TestComp><01-01-2024 10:00:00.000+000><thread=100>"#;
        let parsed = parse_line(line).expect("should parse");
        assert_eq!(parsed.severity, Severity::Error);
    }
}
