//! PatchMyPC detection/requirement script log parser.
//!
//! Parses tilde-delimited detection script log lines:
//!   MM/DD/YYYY HH:MM:SS~[AppName Version]~[Found:True|False]~[Purpose:Detection|Requirement]~[Context:HOST$)]~[Hive:...]
//!
//! These files are typically UTF-16LE encoded; the encoding layer handles
//! decoding before lines reach this parser.

use regex::Regex;
use std::sync::OnceLock;

use crate::models::log_entry::{LogEntry, LogFormat, Severity};

/// Regex matching PatchMyPC detection log lines.
/// Groups: timestamp, app_info, found_status, purpose, context, hive
fn detection_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(concat!(
            r"^(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})", // timestamp
            r"~\[([^\]]*)\]",                               // ~[app info]
            r"~\[Found:(True|False)\]",                     // ~[Found:T/F]
            r"~\[Purpose:([^\]]*)\]",                       // ~[Purpose:...]
            r"(?:~\[Context:([^\]]*)\])?",                  // ~[Context:...] (optional)
            r"(?:~\[Hive:([^\]]*)\])?",                     // ~[Hive:...] (optional)
        ))
        .expect("PatchMyPC detection regex must compile")
    })
}

/// Check if a line matches the PatchMyPC detection format (used by detect.rs).
pub fn matches_patchmypc_detection_record(line: &str) -> bool {
    detection_re().is_match(line)
}

/// Parse all lines as PatchMyPC detection/requirement script format.
pub fn parse_lines(lines: &[&str], file_path: &str) -> (Vec<LogEntry>, u32) {
    let mut entries = Vec::with_capacity(lines.len());
    let mut parse_errors: u32 = 0;
    let mut id: u64 = 0;

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some(caps) = detection_re().captures(trimmed) {
            let ts_str = caps.get(1).unwrap().as_str();
            let app_info = caps.get(2).unwrap().as_str().to_string();
            let found = caps.get(3).unwrap().as_str();
            let purpose = caps.get(4).unwrap().as_str();
            let context = caps.get(5).map(|m| m.as_str().to_string());
            let _hive = caps.get(6).map(|m| m.as_str());

            // Found:True → Info, Found:False → Warning
            let severity = if found == "True" {
                Severity::Info
            } else {
                Severity::Warning
            };

            // Parse timestamp: MM/DD/YYYY HH:MM:SS
            let timestamp =
                chrono::NaiveDateTime::parse_from_str(ts_str, "%m/%d/%Y %H:%M:%S")
                    .ok()
                    .map(|dt| dt.and_utc().timestamp_millis());

            let timestamp_display = Some(ts_str.to_string());

            // Build a readable message
            let message = format!(
                "[{}] {} — Found:{}",
                purpose, app_info, found
            );

            let component = Some("PatchMyPC".to_string());

            // Extract hostname from context (strip trailing "$)" if present)
            let host_name = context.as_ref().map(|c| {
                c.trim_end_matches(')')
                    .trim_end_matches('$')
                    .to_string()
            });

            entries.push(LogEntry {
                id,
                line_number: (i + 1) as u32,
                message,
                component,
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
                host_name,
                mac_address: None,
                result_code: None,
                gle_code: None,
                setup_phase: None,
                operation_name: Some(purpose.to_string()),
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
    fn test_matches_detection_record() {
        assert!(matches_patchmypc_detection_record(
            r#"04/07/2026 22:57:20~[7-Zip*x64* {23170f69-40c1-2702-2501-000001000000} 25.01]~[Found:False]~[Purpose:Detection]~[Context:GELL-1060D7ABC7$)]~[Hive:HKLM:\software\microsoft\windows\currentversion\uninstall\*]"#
        ));
        assert!(!matches_patchmypc_detection_record("Just plain text"));
        assert!(!matches_patchmypc_detection_record(
            "<![LOG[some CCM log]LOG]!><time=\"12:00:00\" date=\"01-01-2025\">"
        ));
    }

    #[test]
    fn test_parse_found_false() {
        let lines = vec![
            r#"04/07/2026 22:57:20~[7-Zip*x64* {23170f69-40c1-2702-2501-000001000000} 25.01]~[Found:False]~[Purpose:Detection]~[Context:GELL-1060D7ABC7$)]~[Hive:HKLM:\software\microsoft\windows\currentversion\uninstall\*]"#,
        ];
        let (entries, errors) = parse_lines(&lines, "test.log");
        assert_eq!(errors, 0);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].severity, Severity::Warning);
        assert!(entries[0].message.contains("7-Zip"));
        assert!(entries[0].message.contains("Found:False"));
        assert_eq!(entries[0].component.as_deref(), Some("PatchMyPC"));
        assert_eq!(entries[0].host_name.as_deref(), Some("GELL-1060D7ABC7"));
        assert_eq!(entries[0].operation_name.as_deref(), Some("Detection"));
        assert!(entries[0].timestamp.is_some());
    }

    #[test]
    fn test_parse_found_true() {
        let lines = vec![
            r#"04/07/2026 22:58:50~[7-Zip 25.01 (x64 edition) {23170f69-40c1-2702-2501-000001000000}]~[Found:True]~[Purpose:Detection]~[Context:GELL-1060D7ABC7$)]~[Hive:HKLM:\software\microsoft\windows\currentversion\uninstall\*]"#,
        ];
        let (entries, errors) = parse_lines(&lines, "test.log");
        assert_eq!(errors, 0);
        assert_eq!(entries[0].severity, Severity::Info);
        assert!(entries[0].message.contains("Found:True"));
    }

    #[test]
    fn test_parse_requirement_purpose() {
        let lines = vec![
            r#"04/07/2026 23:42:21~[Microsoft OneDrive* 26.032.0217.0003]~[Found:False]~[Purpose:Requirement]~[Context:GELL-1060D7ABC7$)]~[Hive:HKLM:\software\microsoft\windows\currentversion\uninstall\*]"#,
        ];
        let (entries, _) = parse_lines(&lines, "test.log");
        assert_eq!(entries[0].operation_name.as_deref(), Some("Requirement"));
    }
}
