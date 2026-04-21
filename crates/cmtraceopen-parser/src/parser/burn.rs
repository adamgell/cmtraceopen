//! WiX/Burn bootstrapper log parser.
//!
//! Parses log lines in the format:
//!   [PID:TID][YYYY-MM-DDTHH:MM:SS]sNNN: message
//!
//! Where s = severity letter (i=info, w=warning, e=error), NNN = message code.
//!
//! Examples:
//!   [07A4:0CBC][2025-11-25T01:55:42]i001: Burn v3.14.1.8722, Windows v10.0
//!   [07A4:0CBC][2025-11-25T01:55:42]e000: Error 0x80070005: Failed to ...

use regex::Regex;

use crate::models::log_entry::{LogEntry, LogFormat, Severity};
use std::sync::OnceLock;

/// Regex matching the WiX/Burn bootstrapper log format.
/// Groups: pid(hex), tid(hex), timestamp(ISO), severity(letter), code(3digits), message
fn burn_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(concat!(
        r"^\[([0-9A-Fa-f]+):([0-9A-Fa-f]+)\]",       // [PID:TID]
        r"\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\]", // [ISO timestamp]
        r"([iew])(\d{3}):\s*(.*)",                       // severity + code + message
    ))
    .expect("Burn regex must compile")
})
}

/// Check if a line matches the WiX/Burn format (used by detect.rs).
pub fn matches_burn_record(line: &str) -> bool {
    burn_re().is_match(line)
}

fn severity_from_letter(letter: &str) -> Severity {
    match letter {
        "e" => Severity::Error,
        "w" => Severity::Warning,
        _ => Severity::Info,
    }
}

/// Parse all lines as WiX/Burn bootstrapper format.
pub fn parse_lines(lines: &[&str], file_path: &str) -> (Vec<LogEntry>, u32) {
    let mut entries = Vec::with_capacity(lines.len());
    let mut parse_errors: u32 = 0;
    let mut id: u64 = 0;

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some(caps) = burn_re().captures(trimmed) {
            let pid_hex = caps.get(1).unwrap().as_str();
            let tid_hex = caps.get(2).unwrap().as_str();
            let ts_str = caps.get(3).unwrap().as_str();
            let sev_letter = caps.get(4).unwrap().as_str();
            let msg_code = caps.get(5).unwrap().as_str();
            let message = caps.get(6).map(|m| m.as_str().to_string()).unwrap_or_default();

            let pid = u32::from_str_radix(pid_hex, 16).unwrap_or(0);
            let tid = u32::from_str_radix(tid_hex, 16).unwrap_or(0);
            let severity = severity_from_letter(sev_letter);

            // Parse ISO timestamp: YYYY-MM-DDTHH:MM:SS
            let timestamp = chrono::NaiveDateTime::parse_from_str(ts_str, "%Y-%m-%dT%H:%M:%S")
                .ok()
                .map(|dt| dt.and_utc().timestamp_millis());

            let timestamp_display = ts_str
                .replace('T', " ")
                .parse::<String>()
                .ok()
                .map(|s| format!("{}.000", s));

            let thread_display = Some(format!("{:04X}:{:04X}", pid, tid));
            let component = Some(format!("{}{}", sev_letter, msg_code));

            entries.push(LogEntry {
                id,
                line_number: (i + 1) as u32,
                message,
                component,
                timestamp,
                timestamp_display,
                severity,
                thread: Some(pid),
                thread_display,
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
        } else {
            // Non-matching line — plain text fallback
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
    fn test_parse_info_line() {
        let lines = vec![
            "[07A4:0CBC][2025-11-25T01:55:42]i001: Burn v3.14.1.8722, Windows v10.0 (Build 26100: Service Pack 0)",
        ];
        let (entries, errors) = parse_lines(&lines, "test.log");
        assert_eq!(errors, 0);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].severity, Severity::Info);
        assert_eq!(entries[0].component.as_deref(), Some("i001"));
        assert_eq!(entries[0].thread_display.as_deref(), Some("07A4:0CBC"));
        assert!(entries[0].message.contains("Burn v3.14.1.8722"));
    }

    #[test]
    fn test_parse_error_line() {
        let lines = vec![
            "[1234:5678][2025-11-25T01:55:42]e000: Error 0x80070005: Access denied",
        ];
        let (entries, _) = parse_lines(&lines, "test.log");
        assert_eq!(entries[0].severity, Severity::Error);
        assert_eq!(entries[0].component.as_deref(), Some("e000"));
        assert!(entries[0].message.contains("Access denied"));
    }

    #[test]
    fn test_parse_warning_line() {
        let lines = vec![
            "[ABCD:EF01][2025-11-25T02:00:00]w000: Ignoring failure to set variable",
        ];
        let (entries, _) = parse_lines(&lines, "test.log");
        assert_eq!(entries[0].severity, Severity::Warning);
        assert_eq!(entries[0].component.as_deref(), Some("w000"));
    }

    #[test]
    fn test_matches_burn_record() {
        assert!(matches_burn_record(
            "[07A4:0CBC][2025-11-25T01:55:42]i001: Burn started"
        ));
        assert!(!matches_burn_record("Just plain text"));
        assert!(!matches_burn_record(
            "2024-01-15T14:30:00Z Error: connection refused"
        ));
    }

    #[test]
    fn test_pid_tid_parsing() {
        let lines = vec![
            "[07A4:0CBC][2025-11-25T01:55:42]i000: test",
        ];
        let (entries, _) = parse_lines(&lines, "test.log");
        assert_eq!(entries[0].thread, Some(0x07A4));
        assert_eq!(entries[0].thread_display.as_deref(), Some("07A4:0CBC"));
    }
}
