//! Secure Boot certificate update log parser.
//!
//! Parses log lines in the format:
//!   YYYY-MM-DD HH:MM:SS [SCRIPTNAME] [LEVEL] Message
//!
//! Where LEVEL is one of: INFO, WARNING, ERROR, SUCCESS, SYSTEM.
//!
//! Examples:
//!   2026-04-07 11:25:47 [DETECT] [INFO] ========== DETECTION STARTED ==========
//!   2026-04-07 11:25:48 [DETECT] [WARNING] MicrosoftUpdateManagedOptIn is NOT SET
//!   2026-04-07 11:25:48 [DETECT] [SUCCESS] Secure Boot is ENABLED

use regex::Regex;

use crate::models::log_entry::{LogEntry, LogFormat, Severity};
use std::sync::OnceLock;

/// Regex matching the SecureBoot certificate update log format.
/// Groups: timestamp, script_name, level, message
fn secureboot_log_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(concat!(
            r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", // timestamp
            r" \[(\w+)\]",                                // [SCRIPTNAME]
            r" \[(INFO|WARNING|ERROR|SUCCESS|SYSTEM)\]",  // [LEVEL]
            r" (.*)",                                      // message
        ))
        .expect("SecureBoot log regex must compile")
    })
}

/// Check if a line matches the SecureBoot certificate update log format.
pub fn matches_secureboot_log_record(line: &str) -> bool {
    secureboot_log_re().is_match(line)
}

fn severity_from_level(level: &str) -> Severity {
    match level {
        "ERROR" => Severity::Error,
        "WARNING" => Severity::Warning,
        _ => Severity::Info,
    }
}

/// Parse all lines as SecureBoot certificate update log format.
pub fn parse_lines(lines: &[&str], file_path: &str) -> (Vec<LogEntry>, u32) {
    let mut entries = Vec::with_capacity(lines.len());
    let mut parse_errors: u32 = 0;
    let mut id: u64 = 0;

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some(caps) = secureboot_log_re().captures(trimmed) {
            let ts_str = caps.get(1).unwrap().as_str();
            let script_name = caps.get(2).unwrap().as_str();
            let level = caps.get(3).unwrap().as_str();
            let message = caps.get(4).map(|m| m.as_str().to_string()).unwrap_or_default();

            let severity = severity_from_level(level);

            let timestamp =
                chrono::NaiveDateTime::parse_from_str(ts_str, "%Y-%m-%d %H:%M:%S")
                    .ok()
                    .map(|dt| dt.and_utc().timestamp_millis());

            let timestamp_display = Some(format!("{}.000", ts_str));

            entries.push(LogEntry {
                id,
                line_number: (i + 1) as u32,
                message,
                component: Some(script_name.to_string()),
                timestamp,
                timestamp_display,
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
            "2026-04-07 11:25:47 [DETECT] [INFO] ========== DETECTION STARTED ==========",
        ];
        let (entries, errors) = parse_lines(&lines, "SecureBootCertificateUpdate.log");
        assert_eq!(errors, 0);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].severity, Severity::Info);
        assert_eq!(entries[0].component.as_deref(), Some("DETECT"));
        assert!(entries[0].message.contains("DETECTION STARTED"));
        assert_eq!(
            entries[0].timestamp_display.as_deref(),
            Some("2026-04-07 11:25:47.000")
        );
    }

    #[test]
    fn test_parse_warning_line() {
        let lines = vec![
            "2026-04-07 11:25:48 [DETECT] [WARNING] MicrosoftUpdateManagedOptIn is NOT SET or 0",
        ];
        let (entries, errors) = parse_lines(&lines, "SecureBootCertificateUpdate.log");
        assert_eq!(errors, 0);
        assert_eq!(entries[0].severity, Severity::Warning);
        assert_eq!(entries[0].component.as_deref(), Some("DETECT"));
    }

    #[test]
    fn test_parse_success_line() {
        let lines = vec![
            "2026-04-07 11:25:48 [DETECT] [SUCCESS] Secure Boot is ENABLED",
        ];
        let (entries, errors) = parse_lines(&lines, "SecureBootCertificateUpdate.log");
        assert_eq!(errors, 0);
        assert_eq!(entries[0].severity, Severity::Info);
        assert_eq!(entries[0].component.as_deref(), Some("DETECT"));
    }

    #[test]
    fn test_parse_error_line() {
        let lines = vec![
            "2026-04-07 11:25:48 [REMEDIATE] [ERROR] Failed to set registry value",
        ];
        let (entries, errors) = parse_lines(&lines, "SecureBootCertificateUpdate.log");
        assert_eq!(errors, 0);
        assert_eq!(entries[0].severity, Severity::Error);
        assert_eq!(entries[0].component.as_deref(), Some("REMEDIATE"));
    }

    #[test]
    fn test_matches_secureboot_log_record() {
        assert!(matches_secureboot_log_record(
            "2026-04-07 11:25:47 [DETECT] [INFO] test"
        ));
        assert!(matches_secureboot_log_record(
            "2026-04-07 11:25:48 [SYSTEM] [WARNING] test"
        ));
        assert!(!matches_secureboot_log_record("Just plain text"));
        assert!(!matches_secureboot_log_record(
            "2024-01-15 14:30:00 some generic timestamped line"
        ));
    }

    #[test]
    fn test_parse_multiple_lines() {
        let lines = vec![
            "2026-04-07 11:25:47 [DETECT] [INFO] Script Version: 4.0",
            "2026-04-07 11:25:48 [DETECT] [SUCCESS] Secure Boot is ENABLED",
            "2026-04-07 11:25:48 [DETECT] [WARNING] MicrosoftUpdateManagedOptIn is NOT SET",
            "2026-04-07 11:25:48 [DETECT] [INFO] Detection Result: NON-COMPLIANT",
        ];
        let (entries, errors) = parse_lines(&lines, "SecureBootCertificateUpdate.log");
        assert_eq!(errors, 0);
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].severity, Severity::Info);
        assert_eq!(entries[1].severity, Severity::Info);
        assert_eq!(entries[2].severity, Severity::Warning);
        assert_eq!(entries[3].severity, Severity::Info);
    }
}
