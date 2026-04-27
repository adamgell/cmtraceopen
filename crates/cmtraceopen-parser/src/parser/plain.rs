//! Plain text fallback parser.
//!
//! Used when no structured format (CCM, Simple, or Timestamped) is detected.
//! Each line becomes a LogEntry with text-based severity detection.

use super::severity::detect_severity_from_text;
use crate::models::log_entry::{LogEntry, LogFormat};

/// Parse all lines as plain text.
pub fn parse_lines(lines: &[&str], file_path: &str) -> (Vec<LogEntry>, u32) {
    let mut entries = Vec::with_capacity(lines.len());

    for (i, line) in lines.iter().enumerate() {
        if line.trim().is_empty() {
            continue;
        }

        let severity = detect_severity_from_text(line);

        entries.push(LogEntry {
            id: i as u64,
            line_number: (i + 1) as u32,
            message: line.to_string(),
            component: None,
            timestamp: None,
            timestamp_display: None,
            severity,
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
    }

    // Plain text never has parse errors (every line is valid)
    (entries, 0)
}
