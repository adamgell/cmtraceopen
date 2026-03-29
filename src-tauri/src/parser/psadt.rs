//! PSADT Legacy format parser.
//!
//! Parses log lines produced by PSAppDeployToolkit v4 with `LogStyle = 'Legacy'`:
//!   [2024-12-24 14:44:13.658] [Install] [Start-ADTMsiProcess] [Error] :: Message text here
//!
//! Fields extracted:
//!   1. timestamp  (yyyy-MM-dd HH:mm:ss.fff)
//!   2. section    (Initialization, Pre-Install, Install, Post-Install, Finalization)
//!   3. source     (PSADT function name, e.g. Close-ADTSession)
//!   4. severity   (Info, Warning, Error, Success)
//!   5. message    (everything after `:: `)

use regex::Regex;

use super::severity::detect_severity_from_text;
use crate::models::log_entry::{LogEntry, LogFormat, Severity};
use std::sync::OnceLock;

/// Full PSADT Legacy line regex.
fn psadt_line_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(
        r"^\[(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\.\d{3})\]\s\[([^\]]+)\]\s\[([^\]]+)\]\s\[(\w+)\]\s::\s(.*)$",
    )
    .expect("PSADT Legacy line regex must compile")
})
}

/// Lightweight prefix check for detection (avoids running the full regex).
fn psadt_prefix_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(r"^\[\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\.\d{3}\]\s\[")
        .expect("PSADT prefix regex must compile")
})
}

/// Known PSADT section names.
static KNOWN_SECTIONS: &[&str] = &[
    "Initialization",
    "Pre-Install",
    "Install",
    "Post-Install",
    "Finalization",
];

/// Known PSADT function names.
static KNOWN_FUNCTIONS: &[&str] = &[
    "Open-ADTSession",
    "Close-ADTSession",
    "Start-ADTMsiProcess",
];

/// Map the PSADT severity token to a `Severity` variant.
fn map_severity(token: &str) -> Severity {
    match token {
        "Error" => Severity::Error,
        "Warning" | "Warn" => Severity::Warning,
        // "Info", "Information", "Success", or anything else → Info
        _ => Severity::Info,
    }
}

/// Parse a single PSADT Legacy format line.
fn parse_line(line: &str) -> Option<PsadtParsed> {
    let caps = psadt_line_re().captures(line)?;

    let ts_str = caps.get(1)?.as_str();
    let section = caps.get(2)?.as_str();
    let source = caps.get(3)?.as_str();
    let sev_token = caps.get(4)?.as_str();
    let message = caps.get(5)?.as_str();

    // Parse timestamp with chrono
    let ndt = chrono::NaiveDateTime::parse_from_str(ts_str, "%Y-%m-%d %H:%M:%S%.3f").ok()?;
    let timestamp = ndt.and_utc().timestamp_millis();

    // Format display as MM-dd-yyyy HH:mm:ss.fff
    let timestamp_display = format!(
        "{:02}-{:02}-{:04} {:02}:{:02}:{:02}.{:03}",
        ndt.month(),
        ndt.day(),
        ndt.year(),
        ndt.hour(),
        ndt.minute(),
        ndt.second(),
        ndt.and_utc().timestamp_subsec_millis()
    );

    Some(PsadtParsed {
        timestamp,
        timestamp_display,
        section: section.to_string(),
        source: source.to_string(),
        severity: map_severity(sev_token),
        message: message.to_string(),
    })
}

struct PsadtParsed {
    timestamp: i64,
    timestamp_display: String,
    section: String,
    source: String,
    severity: Severity,
    message: String,
}

// Need these for the timestamp formatting in parse_line
use chrono::{Datelike, Timelike};

/// Parse all lines as PSADT Legacy format.
/// Lines that don't match the format fall back to plain text entries with
/// text-based severity detection.
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
                    component: Some(parsed.section),
                    timestamp: Some(parsed.timestamp),
                    timestamp_display: Some(parsed.timestamp_display),
                    severity: parsed.severity,
                    thread: None,
                    thread_display: None,
                    source_file: Some(parsed.source),
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
                id_counter += 1;
            }
            None => {
                // Doesn't match PSADT format — treat as plain text
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
                });
                id_counter += 1;
                errors += 1;
            }
        }
    }

    (entries, errors)
}

/// Detection helper: returns a weight indicating how likely the line is PSADT Legacy format.
///
/// Weight breakdown:
/// - Full bracketed timestamp prefix `[yyyy-MM-dd HH:mm:ss.fff] [` → 3
/// - Known section name (e.g. `[Initialization]`) → +1
/// - Known PSADT function name (e.g. `[Open-ADTSession]`) → +1
/// - Banner delimiter (10+ asterisks in a bracketed line) → 2
pub fn matches_psadt_legacy_content(line: &str) -> u32 {
    let mut weight = 0u32;

    // Check for the bracketed timestamp prefix
    if psadt_prefix_re().is_match(line) {
        weight += 3;

        // Check for known section names
        for section in KNOWN_SECTIONS {
            let bracketed = format!("[{}]", section);
            if line.contains(&bracketed) {
                weight += 1;
                break;
            }
        }

        // Check for known PSADT function names
        for func in KNOWN_FUNCTIONS {
            let bracketed = format!("[{}]", func);
            if line.contains(&bracketed) {
                weight += 1;
                break;
            }
        }

        // Check for banner delimiter (10+ asterisks)
        if line.contains("**********") {
            weight += 2;
        }
    }

    weight
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_info_line() {
        let line =
            "[2024-12-24 14:44:13.658] [Finalization] [Close-ADTSession] [Info] :: Message text here";
        let parsed = parse_line(line).expect("should parse");
        assert_eq!(parsed.message, "Message text here");
        assert_eq!(parsed.section, "Finalization");
        assert_eq!(parsed.source, "Close-ADTSession");
        assert_eq!(parsed.severity, Severity::Info);
        assert_eq!(parsed.timestamp_display, "12-24-2024 14:44:13.658");
    }

    #[test]
    fn test_parse_error_line() {
        let line = "[2024-12-24 14:44:13.700] [Install] [Start-ADTMsiProcess] [Error] :: MSI installation failed. [Exit code: 1603]";
        let parsed = parse_line(line).expect("should parse");
        assert_eq!(
            parsed.message,
            "MSI installation failed. [Exit code: 1603]"
        );
        assert_eq!(parsed.section, "Install");
        assert_eq!(parsed.source, "Start-ADTMsiProcess");
        assert_eq!(parsed.severity, Severity::Error);
    }

    #[test]
    fn test_parse_warning_line() {
        let line =
            "[2024-12-24 14:44:14.000] [Pre-Install] [Test-Function] [Warning] :: Something is off";
        let parsed = parse_line(line).expect("should parse");
        assert_eq!(parsed.severity, Severity::Warning);
        assert_eq!(parsed.section, "Pre-Install");
    }

    #[test]
    fn test_parse_success_maps_to_info() {
        let line = "[2024-12-24 14:44:14.000] [Post-Install] [Test-Function] [Success] :: All good";
        let parsed = parse_line(line).expect("should parse");
        assert_eq!(parsed.severity, Severity::Info);
    }

    #[test]
    fn test_parse_banner_line() {
        let line = "[2024-12-24 14:44:13.658] [Initialization] [Open-ADTSession] [Info] :: *******************************************************************************";
        let parsed = parse_line(line).expect("should parse");
        assert_eq!(parsed.severity, Severity::Info);
        assert!(parsed.message.contains("***"));
    }

    #[test]
    fn test_parse_lines_mixed() {
        let lines = vec![
            "[2024-12-24 14:44:13.658] [Finalization] [Close-ADTSession] [Info] :: Session closed",
            "Some random non-matching line",
            "[2024-12-24 14:44:13.700] [Install] [Start-ADTMsiProcess] [Error] :: MSI failed",
        ];
        let (entries, errors) = parse_lines(&lines, "test.log");
        assert_eq!(entries.len(), 3);
        assert_eq!(errors, 1);

        // First entry: structured
        assert_eq!(entries[0].component.as_deref(), Some("Finalization"));
        assert_eq!(entries[0].source_file.as_deref(), Some("Close-ADTSession"));
        assert_eq!(entries[0].severity, Severity::Info);
        assert_eq!(entries[0].format, LogFormat::Timestamped);

        // Second entry: plain fallback
        assert_eq!(entries[1].message, "Some random non-matching line");
        assert_eq!(entries[1].format, LogFormat::Plain);
        assert!(entries[1].component.is_none());

        // Third entry: structured error
        assert_eq!(entries[2].severity, Severity::Error);
        assert_eq!(entries[2].component.as_deref(), Some("Install"));
    }

    #[test]
    fn test_parse_lines_skips_empty() {
        let lines = vec!["", "  ", "[2024-12-24 14:44:13.658] [Install] [Func] [Info] :: msg"];
        let (entries, errors) = parse_lines(&lines, "test.log");
        assert_eq!(entries.len(), 1);
        assert_eq!(errors, 0);
    }

    #[test]
    fn test_parse_lines_file_path_propagated() {
        let lines =
            vec!["[2024-12-24 14:44:13.658] [Install] [Func] [Info] :: msg"];
        let (entries, _) = parse_lines(&lines, "/path/to/deploy.log");
        assert_eq!(entries[0].file_path, "/path/to/deploy.log");
    }

    #[test]
    fn test_timestamp_to_millis() {
        let line =
            "[2024-12-24 14:44:13.658] [Install] [Func] [Info] :: msg";
        let parsed = parse_line(line).expect("should parse");
        // 2024-12-24 14:44:13.658 UTC → verify it's a reasonable millis value
        assert!(parsed.timestamp > 0);
        // Rough check: 2024-12-24 is around epoch millis 1735000000000
        assert!(parsed.timestamp > 1_735_000_000_000);
        assert!(parsed.timestamp < 1_736_000_000_000);
    }

    // Detection tests

    #[test]
    fn test_matches_full_line() {
        let line =
            "[2024-12-24 14:44:13.658] [Finalization] [Close-ADTSession] [Info] :: Message text";
        let weight = matches_psadt_legacy_content(line);
        // 3 (prefix) + 1 (known section) + 1 (known function) = 5
        assert_eq!(weight, 5);
    }

    #[test]
    fn test_matches_unknown_section_and_function() {
        let line =
            "[2024-12-24 14:44:13.658] [CustomSection] [Custom-Function] [Info] :: Some message";
        let weight = matches_psadt_legacy_content(line);
        // 3 (prefix only, no known section or function)
        assert_eq!(weight, 3);
    }

    #[test]
    fn test_matches_banner_line() {
        let line = "[2024-12-24 14:44:13.658] [Initialization] [Open-ADTSession] [Info] :: *******************************************************************************";
        let weight = matches_psadt_legacy_content(line);
        // 3 (prefix) + 1 (known section) + 1 (known function) + 2 (banner) = 7
        assert_eq!(weight, 7);
    }

    #[test]
    fn test_matches_non_psadt_line() {
        let weight = matches_psadt_legacy_content("Just a plain text line");
        assert_eq!(weight, 0);
    }

    #[test]
    fn test_matches_similar_but_not_psadt() {
        // Has a bracketed timestamp but wrong format
        let weight = matches_psadt_legacy_content("[2024-12-24] Some log message");
        assert_eq!(weight, 0);
    }
}
