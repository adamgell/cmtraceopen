use once_cell::sync::Lazy;
use regex::Regex;

use super::severity::detect_severity_from_text;
use crate::models::log_entry::{LogEntry, LogFormat, Severity};

static PANTHER_PREFIX_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},").unwrap()
});

static PANTHER_HEADER_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"^(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2}),\s+(Info|Warning|Error|Fatal Error|Perf)\s+(?:(\[0x[0-9A-Fa-f]+\])\s+)?(?:([A-Z][A-Z0-9_.-]{1,31})\s+)?(.*)$",
    )
    .unwrap()
});

static PANTHER_RELAXED_HEADER_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"^(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2}),\s+([A-Za-z][A-Za-z0-9_-]{1,31})\s+(?:(\[0x[0-9A-Fa-f]+\])\s+)?(?:([A-Z][A-Z0-9_.-]{1,31})\s+)?(.*)$",
    )
    .unwrap()
});

struct PendingEntry {
    entry: LogEntry,
    start_line: u32,
}

pub fn matches_panther_record(line: &str) -> bool {
    PANTHER_HEADER_RE.is_match(line)
}

pub fn parse_lines(lines: &[&str], file_path: &str) -> (Vec<LogEntry>, u32) {
    let mut entries = Vec::new();
    let mut parse_errors = 0;
    let mut next_id = 0;
    let mut pending: Option<PendingEntry> = None;

    for (index, line) in lines.iter().enumerate() {
        let line_number = (index + 1) as u32;

        if let Some(entry) = parse_header(line, file_path) {
            flush_pending(&mut entries, &mut pending, &mut next_id);
            pending = Some(PendingEntry {
                entry,
                start_line: line_number,
            });
            continue;
        }

        if PANTHER_PREFIX_RE.is_match(line) {
            flush_pending(&mut entries, &mut pending, &mut next_id);
            entries.push(fallback_entry(next_id, line_number, line, file_path));
            next_id += 1;
            parse_errors += 1;
            continue;
        }

        let trimmed_end = line.trim_end();
        if trimmed_end.is_empty() {
            continue;
        }

        if let Some(pending_entry) = pending.as_mut() {
            if !pending_entry.entry.message.is_empty() {
                pending_entry.entry.message.push('\n');
            }
            pending_entry.entry.message.push_str(trimmed_end);
        } else {
            entries.push(fallback_entry(next_id, line_number, trimmed_end, file_path));
            next_id += 1;
            parse_errors += 1;
        }
    }

    flush_pending(&mut entries, &mut pending, &mut next_id);

    (entries, parse_errors)
}

fn parse_header(line: &str, file_path: &str) -> Option<LogEntry> {
    if let Some(caps) = PANTHER_HEADER_RE.captures(line) {
        return build_entry_from_caps(&caps, file_path);
    }

    let caps = PANTHER_RELAXED_HEADER_RE.captures(line)?;
    build_entry_from_caps(&caps, file_path)
}

fn build_entry_from_caps(caps: &regex::Captures<'_>, file_path: &str) -> Option<LogEntry> {

    let year: i32 = caps.get(1)?.as_str().parse().ok()?;
    let month: u32 = caps.get(2)?.as_str().parse().ok()?;
    let day: u32 = caps.get(3)?.as_str().parse().ok()?;
    let hour: u32 = caps.get(4)?.as_str().parse().ok()?;
    let minute: u32 = caps.get(5)?.as_str().parse().ok()?;
    let second: u32 = caps.get(6)?.as_str().parse().ok()?;
    let level = caps.get(7)?.as_str();
    let code = caps.get(8).map(|m| m.as_str());
    let component = caps.get(9).map(|m| m.as_str().to_string());
    let raw_message = caps.get(10).map(|m| m.as_str()).unwrap_or("").trim_end();
    let message = match code {
        Some(code) if raw_message.is_empty() => code.to_string(),
        Some(code) => format!("{} {}", code, raw_message),
        None => raw_message.to_string(),
    };

    let timestamp = chrono::NaiveDate::from_ymd_opt(year, month, day)
        .and_then(|date| date.and_hms_opt(hour, minute, second))
        .map(|dt| dt.and_utc().timestamp_millis());

    Some(LogEntry {
        id: 0,
        line_number: 0,
        message,
        component,
        timestamp,
        timestamp_display: Some(format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.000",
            year, month, day, hour, minute, second
        )),
        severity: severity_from_level(level, raw_message),
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
    })
}

fn severity_from_level(level: &str, message: &str) -> Severity {
    match level {
        "Error" | "Fatal Error" => Severity::Error,
        "Warning" => Severity::Warning,
        _ => detect_severity_from_text(message),
    }
}

fn flush_pending(entries: &mut Vec<LogEntry>, pending: &mut Option<PendingEntry>, next_id: &mut u64) {
    if let Some(mut pending_entry) = pending.take() {
        pending_entry.entry.id = *next_id;
        pending_entry.entry.line_number = pending_entry.start_line;
        entries.push(pending_entry.entry);
        *next_id += 1;
    }
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matches_panther_record() {
        assert!(matches_panther_record(
            "2024-01-15 08:00:00, Info [0x080489] MIG Setting system object filter context (System)"
        ));
        assert!(!matches_panther_record("plain text"));
    }

    #[test]
    fn test_parse_lines_groups_continuations() {
        let lines = [
            "2024-01-15 08:00:00, Info [0x080489] MIG Gather started",
            "Additional migration detail",
            "    indented continuation",
            "2024-01-15 08:00:05, Warning SP Retry required",
        ];

        let (entries, parse_errors) = parse_lines(&lines, "C:/Windows/Panther/setupact.log");

        assert_eq!(parse_errors, 0);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].component.as_deref(), Some("MIG"));
        assert_eq!(entries[0].message, "[0x080489] Gather started\nAdditional migration detail\n    indented continuation");
        assert_eq!(entries[0].line_number, 1);
        assert_eq!(entries[1].severity, Severity::Warning);
    }

    #[test]
    fn test_parse_lines_salvages_structural_segments_with_unexpected_levels() {
        let lines = [
            "orphan preamble",
            "2024-01-15 08:00:00, Info SP Setup started",
            "continuation detail",
            "2024-01-15 08:00:01, UnexpectedLevel SP malformed header",
            "2024-01-15 08:00:02, Error SP Setup failed",
        ];

        let (entries, parse_errors) = parse_lines(&lines, "C:/Windows/Panther/setuperr.log");

        assert_eq!(parse_errors, 1);
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].message, "orphan preamble");
        assert_eq!(entries[1].message, "Setup started\ncontinuation detail");
        assert_eq!(entries[2].message, "malformed header");
        assert_eq!(entries[2].component.as_deref(), Some("SP"));
        assert_eq!(entries[3].severity, Severity::Error);
        assert_eq!(entries[3].component.as_deref(), Some("SP"));
    }

    #[test]
    fn test_parse_lines_handles_missing_component() {
        let lines = ["2024-01-15 08:00:08, Error                  Gather failed. Last error: 0x00000000"];

        let (entries, parse_errors) = parse_lines(&lines, "C:/Windows/Panther/setupact.log");

        assert_eq!(parse_errors, 0);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].component.is_none());
        assert_eq!(entries[0].severity, Severity::Error);
    }
}