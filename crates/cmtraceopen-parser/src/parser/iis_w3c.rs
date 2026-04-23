//! IIS W3C Extended log parser.
//!
//! IIS logs are self-describing via a `#Fields:` header that lists the columns
//! present in subsequent space-delimited rows.

use crate::models::log_entry::{LogEntry, LogFormat, Severity};

/// Check if a line looks like an IIS W3C data row with leading date + time tokens.
pub fn matches_iis_w3c_record(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return false;
    }

    let mut parts = trimmed.split_whitespace();
    match (parts.next(), parts.next()) {
        (Some(date), Some(time)) => is_w3c_date(date) && is_w3c_time(time),
        _ => false,
    }
}

/// Check if a line is an IIS-specific W3C Extended-format header directive.
///
/// Real IIS W3C logs open with a header block; this predicate recognises the
/// IIS-specific directives so the classifier can require an authoritative
/// signal before dispatching to the IIS parser. Generic `#Version: 1.0` is
/// deliberately excluded — many tools emit it, and on its own it cannot
/// disambiguate IIS from, e.g., other W3C-flavoured logs.
///
/// We accept:
/// - `#Software: Microsoft Internet Information Services ...`
/// - `#Fields: ...` whose column list carries an IIS Extended-format
///   fingerprint (minimally `date time s-ip cs-method` or
///   `date time s-sitename s-computername`, or any header whose first three
///   listed columns are `date time s-*|cs-*`).
///
/// Being conservative here is fine: a false-negative on an exotic header
/// shape is recoverable (path hint or direct `#Software:` line will still
/// classify correctly), while a false-positive on installer logs is exactly
/// the bug we are fixing.
pub fn looks_like_iis_w3c_header(line: &str) -> bool {
    let trimmed = line.trim();
    if !trimmed.starts_with('#') {
        return false;
    }

    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("#software: microsoft internet information services") {
        return true;
    }

    if let Some(rest) = trimmed.strip_prefix("#Fields:") {
        return fields_header_is_iis_like(rest);
    }

    false
}

fn fields_header_is_iis_like(fields: &str) -> bool {
    let tokens: Vec<&str> = fields.split_whitespace().collect();
    if tokens.len() < 3 {
        return false;
    }

    // Must lead with `date time`, the W3C Extended-format convention IIS uses.
    if !tokens[0].eq_ignore_ascii_case("date") || !tokens[1].eq_ignore_ascii_case("time") {
        return false;
    }

    // After `date time`, look for any IIS-specific column prefix.
    // `s-ip`, `cs-method`, `s-sitename`, `s-computername`, `cs-uri-stem`, etc.
    // all start with `s-` or `cs(`/`cs-` — generic W3C-ish "date time something"
    // logs from non-IIS sources will not carry these prefixes.
    tokens[2..].iter().any(|token| {
        let lowered = token.to_ascii_lowercase();
        lowered.starts_with("s-")
            || lowered.starts_with("cs-")
            || lowered.starts_with("cs(")
            || lowered.starts_with("sc-")
            || lowered.starts_with("sc(")
            || lowered == "c-ip"
            || lowered == "s-ip"
    })
}

fn is_w3c_date(value: &str) -> bool {
    value.len() == 10
        && value.as_bytes().get(4) == Some(&b'-')
        && value.as_bytes().get(7) == Some(&b'-')
        && value
            .bytes()
            .enumerate()
            .all(|(idx, b)| matches!(idx, 4 | 7) || b.is_ascii_digit())
}

fn is_w3c_time(value: &str) -> bool {
    value.len() == 8
        && value.as_bytes().get(2) == Some(&b':')
        && value.as_bytes().get(5) == Some(&b':')
        && value
            .bytes()
            .enumerate()
            .all(|(idx, b)| matches!(idx, 2 | 5) || b.is_ascii_digit())
}

fn parse_w3c_datetime(date: Option<&str>, time: Option<&str>) -> (Option<i64>, Option<String>) {
    let (Some(date), Some(time)) = (date, time) else {
        return (None, None);
    };

    let timestamp =
        chrono::NaiveDateTime::parse_from_str(&format!("{date} {time}"), "%Y-%m-%d %H:%M:%S")
            .ok()
            .map(|dt| dt.and_utc().timestamp_millis());

    (timestamp, Some(format!("{date} {time}")))
}

fn parse_optional_u16(value: Option<&str>) -> Option<u16> {
    value
        .and_then(|v| normalize_field(v))
        .and_then(|v| v.parse().ok())
}

fn parse_optional_u32(value: Option<&str>) -> Option<u32> {
    value
        .and_then(|v| normalize_field(v))
        .and_then(|v| v.parse().ok())
}

fn parse_optional_u64(value: Option<&str>) -> Option<u64> {
    value
        .and_then(|v| normalize_field(v))
        .and_then(|v| v.parse().ok())
}

fn normalize_field(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == "-" {
        None
    } else {
        Some(trimmed)
    }
}

fn severity_from_status(status_code: Option<u16>) -> Severity {
    match status_code.unwrap_or_default() {
        400..=499 => Severity::Warning,
        500..=599 => Severity::Error,
        _ => Severity::Info,
    }
}

fn malformed_entry(id: u64, line_number: u32, line: &str, file_path: &str) -> LogEntry {
    LogEntry {
        id,
        line_number,
        message: line.to_string(),
        component: None,
        timestamp: None,
        timestamp_display: None,
        severity: Severity::Info,
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
    }
}

/// Parse all lines of an IIS W3C Extended log file.
pub fn parse_lines(lines: &[&str], file_path: &str) -> (Vec<LogEntry>, u32) {
    let mut entries = Vec::with_capacity(lines.len());
    let mut parse_errors = 0u32;
    let mut id = 0u64;
    let mut fields: Vec<String> = Vec::new();

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some(raw_fields) = trimmed.strip_prefix("#Fields:") {
            fields = raw_fields
                .split_whitespace()
                .map(ToString::to_string)
                .collect();
            continue;
        }

        if trimmed.starts_with('#') {
            continue;
        }

        if !matches_iis_w3c_record(trimmed) || fields.is_empty() {
            entries.push(malformed_entry(id, (i + 1) as u32, trimmed, file_path));
            parse_errors += 1;
            id += 1;
            continue;
        }

        let values: Vec<&str> = trimmed.split_whitespace().collect();
        if values.len() < fields.len() {
            entries.push(malformed_entry(id, (i + 1) as u32, trimmed, file_path));
            parse_errors += 1;
            id += 1;
            continue;
        }

        let value_for = |token: &str| -> Option<&str> {
            fields
                .iter()
                .position(|field| field == token)
                .and_then(|idx| values.get(idx).copied())
        };

        let (timestamp, timestamp_display) =
            parse_w3c_datetime(value_for("date"), value_for("time"));
        let http_method =
            normalize_field(value_for("cs-method").unwrap_or_default()).map(ToString::to_string);
        let uri_stem =
            normalize_field(value_for("cs-uri-stem").unwrap_or_default()).map(ToString::to_string);
        let uri_query =
            normalize_field(value_for("cs-uri-query").unwrap_or_default()).map(ToString::to_string);
        let status_code = parse_optional_u16(value_for("sc-status"));
        let sub_status = parse_optional_u16(value_for("sc-substatus"));
        let time_taken_ms = parse_optional_u64(value_for("time-taken"));
        let client_ip =
            normalize_field(value_for("c-ip").unwrap_or_default()).map(ToString::to_string);
        let server_ip =
            normalize_field(value_for("s-ip").unwrap_or_default()).map(ToString::to_string);
        let user_agent = normalize_field(value_for("cs(User-Agent)").unwrap_or_default())
            .map(|v| v.replace('+', " "));
        let server_port = parse_optional_u16(value_for("s-port"));
        let username =
            normalize_field(value_for("cs-username").unwrap_or_default()).map(ToString::to_string);
        let win32_status = parse_optional_u32(value_for("sc-win32-status"));
        let severity = severity_from_status(status_code);

        let uri_display = match (uri_stem.as_deref(), uri_query.as_deref()) {
            (Some(stem), Some(query)) => format!("{stem}?{query}"),
            (Some(stem), None) => stem.to_string(),
            _ => "-".to_string(),
        };
        let method_display = http_method.as_deref().unwrap_or("-");
        let status_display = status_code
            .map(|code| code.to_string())
            .unwrap_or_else(|| "-".to_string());
        let message = format!("{method_display} {uri_display} → {status_display}");

        entries.push(LogEntry {
            id,
            line_number: (i + 1) as u32,
            message,
            component: None,
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
            http_method,
            uri_stem,
            uri_query,
            status_code,
            sub_status,
            time_taken_ms,
            client_ip,
            server_ip,
            user_agent,
            server_port,
            username,
            win32_status,
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
        id += 1;
    }

    (entries, parse_errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matches_iis_w3c_record() {
        assert!(matches_iis_w3c_record(
            "2026-03-29 18:48:23 10.0.0.5 GET /default.htm - 443 - 203.0.113.10 Mozilla/5.0 200 0 0 12"
        ));
        assert!(!matches_iis_w3c_record(
            "#Software: Microsoft Internet Information Services 10.0"
        ));
        assert!(!matches_iis_w3c_record("not a log line"));
    }

    #[test]
    fn test_looks_like_iis_w3c_header_accepts_software_directive() {
        assert!(looks_like_iis_w3c_header(
            "#Software: Microsoft Internet Information Services 10.0"
        ));
        assert!(looks_like_iis_w3c_header(
            "   #Software: Microsoft Internet Information Services 7.5"
        ));
    }

    #[test]
    fn test_looks_like_iis_w3c_header_accepts_iis_fields_directive() {
        assert!(looks_like_iis_w3c_header(
            "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status sc-substatus sc-win32-status time-taken"
        ));
        assert!(looks_like_iis_w3c_header(
            "#Fields: date time s-sitename s-computername s-ip cs-method cs-uri-stem"
        ));
    }

    #[test]
    fn test_looks_like_iis_w3c_header_rejects_generic_version_and_data() {
        // `#Version: 1.0` on its own is too generic to trust.
        assert!(!looks_like_iis_w3c_header("#Version: 1.0"));
        // Data rows are not headers.
        assert!(!looks_like_iis_w3c_header(
            "2026-03-29 18:48:23 10.0.0.5 GET /default.htm - 443 - 203.0.113.10 Mozilla/5.0 200 0 0 12"
        ));
        // Non-IIS fields (e.g. `#Fields: date time level msg`) should not match.
        assert!(!looks_like_iis_w3c_header(
            "#Fields: date time level msg"
        ));
    }

    #[test]
    fn test_parse_iis_w3c_with_dynamic_fields() {
        let lines = vec![
            "#Software: Microsoft Internet Information Services 10.0",
            "#Version: 1.0",
            "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status sc-substatus sc-win32-status time-taken",
            "2026-03-29 18:48:23 10.0.0.5 GET /default.htm - 443 - 203.0.113.10 Mozilla/5.0 200 0 0 12",
            "2026-03-29 18:48:24 10.0.0.5 POST /api/devices id=42 443 CONTOSO\\\\alice 203.0.113.11 curl/8.7.1 404 7 2 35",
        ];

        let (entries, errors) = parse_lines(&lines, "u_ex260329.log");

        assert_eq!(errors, 0);
        assert_eq!(entries.len(), 2);

        let first = &entries[0];
        assert_eq!(first.message, "GET /default.htm → 200");
        assert_eq!(first.severity, Severity::Info);
        assert_eq!(first.server_ip.as_deref(), Some("10.0.0.5"));
        assert_eq!(first.client_ip.as_deref(), Some("203.0.113.10"));
        assert_eq!(first.http_method.as_deref(), Some("GET"));
        assert_eq!(first.uri_stem.as_deref(), Some("/default.htm"));
        assert_eq!(first.status_code, Some(200));
        assert_eq!(first.time_taken_ms, Some(12));

        let second = &entries[1];
        assert_eq!(second.message, "POST /api/devices?id=42 → 404");
        assert_eq!(second.severity, Severity::Warning);
        assert_eq!(second.username.as_deref(), Some(r"CONTOSO\\alice"));
        assert_eq!(second.sub_status, Some(7));
        assert_eq!(second.win32_status, Some(2));
    }

    #[test]
    fn test_parse_iis_w3c_malformed_row_falls_back() {
        let lines = vec![
            "#Fields: date time s-ip cs-method cs-uri-stem sc-status",
            "2026-03-29 18:48:23 10.0.0.5 GET /default.htm",
        ];

        let (entries, errors) = parse_lines(&lines, "u_ex260329.log");

        assert_eq!(errors, 1);
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].message,
            "2026-03-29 18:48:23 10.0.0.5 GET /default.htm"
        );
        assert!(entries[0].server_ip.is_none());
    }
}
