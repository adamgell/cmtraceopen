use regex::Regex;

use super::severity::detect_severity_from_text;
use crate::models::log_entry::{LogEntry, LogFormat, Severity};
use std::sync::OnceLock;

fn dism_prefix_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},").unwrap())
}

fn dism_header_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(
        r"^(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2}),\s+(Info|Warning|Error|Perf|Verbose|Debug)\s+([A-Za-z][A-Za-z0-9_.-]{1,31})\s+(.*)$",
    )
    .unwrap()
})
}

fn dism_relaxed_header_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(
        r"^(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2}),\s+([A-Za-z][A-Za-z0-9_-]{1,31})\s+([A-Za-z][A-Za-z0-9_.-]{1,31})\s+(.*)$",
    )
    .unwrap()
})
}

struct PendingEntry {
    entry: LogEntry,
    start_line: u32,
}

pub fn matches_dism_record(line: &str) -> bool {
    let Some(caps) = dism_header_re().captures(line) else {
        return false;
    };

    caps.get(8)
        .map(|m| m.as_str().to_ascii_uppercase().starts_with("DISM"))
        .unwrap_or(false)
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

        if dism_prefix_re().is_match(line) {
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
    if let Some(caps) = dism_header_re().captures(line) {
        return build_entry_from_caps(&caps, file_path);
    }

    let caps = dism_relaxed_header_re().captures(line)?;
    let component = caps.get(8)?.as_str().to_ascii_uppercase();
    if !component.starts_with("DISM") {
        return None;
    }

    build_entry_from_caps(&caps, file_path)
}

fn build_entry_from_caps(caps: &regex::Captures<'_>, file_path: &str) -> Option<LogEntry> {
    let component = caps.get(8)?.as_str().to_string();
    if !component.to_ascii_uppercase().starts_with("DISM") {
        return None;
    }

    let year: i32 = caps.get(1)?.as_str().parse().ok()?;
    let month: u32 = caps.get(2)?.as_str().parse().ok()?;
    let day: u32 = caps.get(3)?.as_str().parse().ok()?;
    let hour: u32 = caps.get(4)?.as_str().parse().ok()?;
    let minute: u32 = caps.get(5)?.as_str().parse().ok()?;
    let second: u32 = caps.get(6)?.as_str().parse().ok()?;
    let level = caps.get(7)?.as_str();
    let message = caps
        .get(9)
        .map(|m| m.as_str())
        .unwrap_or("")
        .trim_end()
        .to_string();

    let timestamp = chrono::NaiveDate::from_ymd_opt(year, month, day)
        .and_then(|date| date.and_hms_opt(hour, minute, second))
        .map(|dt| dt.and_utc().timestamp_millis());

    Some(LogEntry {
        id: 0,
        line_number: 0,
        message,
        component: Some(component),
        timestamp,
        timestamp_display: Some(format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.000",
            year, month, day, hour, minute, second
        )),
        severity: severity_from_level(level, caps.get(9).map(|m| m.as_str()).unwrap_or("")),
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

fn severity_from_level(level: &str, message: &str) -> Severity {
    match level {
        "Error" => Severity::Error,
        "Warning" => Severity::Warning,
        "Info" | "Perf" | "Verbose" | "Debug" => Severity::Info,
        _ => detect_severity_from_text(message),
    }
}

fn flush_pending(
    entries: &mut Vec<LogEntry>,
    pending: &mut Option<PendingEntry>,
    next_id: &mut u64,
) {
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
    fn test_matches_dism_record() {
        assert!(matches_dism_record(
            "2024-01-15 08:00:00, Info                  DISM   DISM Package Manager: Processing package"
        ));
        assert!(!matches_dism_record(
            "2024-01-15 08:00:00, Info                  CBS    Exec: Processing package"
        ));
    }

    #[test]
    fn test_parse_lines_groups_continuations() {
        let lines = [
            "2024-01-15 08:00:00, Info                  DISM   DISM Provider Store: PID=100 TID=200 loaded provider",
            "Continuation detail",
            "2024-01-15 08:00:05, Warning               DISM   DISM Package Manager: Retry required",
        ];

        let (entries, parse_errors) = parse_lines(&lines, "C:/Windows/Logs/DISM/dism.log");

        assert_eq!(parse_errors, 0);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].component.as_deref(), Some("DISM"));
        assert_eq!(
            entries[0].message,
            "DISM Provider Store: PID=100 TID=200 loaded provider\nContinuation detail"
        );
        assert_eq!(entries[1].severity, Severity::Warning);
    }

    #[test]
    fn test_parse_lines_salvages_structural_segments_with_unexpected_levels() {
        let lines = [
            "orphan preamble",
            "2024-01-15 08:00:00, Info                  DISM   DISM Package Manager: Processing package",
            "Continuation detail",
            "2024-01-15 08:00:01, UnexpectedLevel       DISM   malformed header",
            "2024-01-15 08:00:02, Error                 DISM   DISM Package Manager: Failed finalizing changes",
        ];

        let (entries, parse_errors) = parse_lines(&lines, "C:/Windows/Logs/DISM/dism.log");

        assert_eq!(parse_errors, 1);
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].message, "orphan preamble");
        assert_eq!(
            entries[1].message,
            "DISM Package Manager: Processing package\nContinuation detail"
        );
        assert_eq!(entries[2].message, "malformed header");
        assert_eq!(entries[2].component.as_deref(), Some("DISM"));
        assert_eq!(entries[3].severity, Severity::Error);
        assert_eq!(entries[3].component.as_deref(), Some("DISM"));
    }
}
