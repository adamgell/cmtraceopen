//! macOS Intune MDM Daemon log parser.
//!
//! Parses pipe-delimited log lines in the format:
//!   YYYY-MM-DD HH:MM:SS:mmm | Process | Severity | ThreadID | SubComponent | Message
//!
//! Example:
//!   2026-03-23 12:51:11:888 | IntuneMDM-Daemon | I | 11054604 | SyncActivityTracer | Reporting results Context: network observer

use once_cell::sync::Lazy;
use regex::Regex;

use crate::models::log_entry::{LogEntry, LogFormat, Severity};

/// Regex matching the pipe-delimited macOS Intune log format.
/// Groups: year, month, day, hour, minute, second, millis, process, severity, thread, subcomponent, message
static INTUNE_MACOS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(concat!(
        r"^(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2}):(\d{3})",
        r"\s*\|\s*([^|]+?)\s*",   // process
        r"\|\s*([A-Z])\s*",       // severity letter
        r"\|\s*(\d+)\s*",         // thread ID
        r"\|\s*([^|]+?)\s*",      // sub-component
        r"\|\s*(.*)",              // message (rest of line)
    ))
    .expect("Intune macOS regex must compile")
});

/// Check if a line matches the macOS Intune pipe-delimited format (used by detect.rs).
pub fn matches_intune_macos(line: &str) -> bool {
    INTUNE_MACOS_RE.is_match(line)
}

fn severity_from_letter(letter: &str) -> Severity {
    match letter {
        "E" => Severity::Error,
        "W" => Severity::Warning,
        _ => Severity::Info,
    }
}

/// Parse all lines as macOS Intune pipe-delimited format.
pub fn parse_lines(lines: &[&str], file_path: &str) -> (Vec<LogEntry>, u32) {
    let mut entries = Vec::with_capacity(lines.len());
    let mut parse_errors: u32 = 0;
    let mut id: u64 = 0;

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some(caps) = INTUNE_MACOS_RE.captures(trimmed) {
            let yr: i32 = caps.get(1).unwrap().as_str().parse().unwrap_or(2024);
            let mon: u32 = caps.get(2).unwrap().as_str().parse().unwrap_or(1);
            let day: u32 = caps.get(3).unwrap().as_str().parse().unwrap_or(1);
            let h: u32 = caps.get(4).unwrap().as_str().parse().unwrap_or(0);
            let m: u32 = caps.get(5).unwrap().as_str().parse().unwrap_or(0);
            let s: u32 = caps.get(6).unwrap().as_str().parse().unwrap_or(0);
            let ms: u32 = caps.get(7).unwrap().as_str().parse().unwrap_or(0);

            let component = caps.get(8).map(|m| m.as_str().trim().to_string());
            let severity_str = caps.get(9).map(|m| m.as_str()).unwrap_or("I");
            let thread: Option<u32> = caps.get(10).and_then(|m| m.as_str().parse().ok());
            let source_file = caps.get(11).map(|m| m.as_str().trim().to_string());
            let message = caps
                .get(12)
                .map(|m| m.as_str().trim().to_string())
                .unwrap_or_default();

            let severity = severity_from_letter(severity_str);

            let timestamp = chrono::NaiveDate::from_ymd_opt(yr, mon, day)
                .and_then(|d| d.and_hms_milli_opt(h, m, s, ms))
                .map(|dt| dt.and_utc().timestamp_millis());

            let timestamp_display = Some(format!(
                "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
                yr, mon, day, h, m, s, ms
            ));

            let thread_display = thread.map(super::ccm::format_thread_display);

            entries.push(LogEntry {
                id,
                line_number: (i + 1) as u32,
                message,
                component,
                timestamp,
                timestamp_display,
                severity,
                thread,
                thread_display,
                source_file,
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
            });
        } else {
            // Non-matching line (e.g., continuation/JSON dump) — plain text
            entries.push(LogEntry {
                id,
                line_number: (i + 1) as u32,
                message: trimmed.to_string(),
                component: None,
                timestamp: None,
                timestamp_display: None,
                severity: super::severity::detect_severity_from_text(trimmed),
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
            });
            parse_errors += 1;
        }
        id += 1;
    }

    (entries, parse_errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_intune_macos_line() {
        let lines = vec![
            "2026-03-23 12:51:11:888 | IntuneMDM-Daemon | I | 11054604 | SyncActivityTracer | Reporting results Context: network observer",
        ];
        let (entries, errors) = parse_lines(&lines, "test.log");
        assert_eq!(errors, 0);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].component.as_deref(), Some("IntuneMDM-Daemon"));
        assert_eq!(entries[0].severity, Severity::Info);
        assert_eq!(entries[0].thread, Some(11054604));
        assert_eq!(
            entries[0].message,
            "Reporting results Context: network observer"
        );
        assert!(entries[0].source_file.as_deref() == Some("SyncActivityTracer"));
    }

    #[test]
    fn test_parse_error_severity() {
        let lines = vec![
            "2026-03-23 12:51:11:888 | IntuneMDM-Daemon | E | 100 | AppInstaller | Installation failed",
        ];
        let (entries, _) = parse_lines(&lines, "test.log");
        assert_eq!(entries[0].severity, Severity::Error);
    }

    #[test]
    fn test_parse_warning_severity() {
        let lines = vec![
            "2026-03-23 12:51:11:888 | IntuneMDM-Daemon | W | 100 | AppInstaller | Retry needed",
        ];
        let (entries, _) = parse_lines(&lines, "test.log");
        assert_eq!(entries[0].severity, Severity::Warning);
    }

    #[test]
    fn test_matches_intune_macos() {
        assert!(matches_intune_macos(
            "2026-03-23 12:51:11:888 | IntuneMDM-Daemon | I | 11054604 | SyncActivityTracer | test"
        ));
        assert!(!matches_intune_macos("Just plain text"));
        assert!(!matches_intune_macos(
            "2024-01-15T14:30:00Z Error: connection refused"
        ));
    }
}
