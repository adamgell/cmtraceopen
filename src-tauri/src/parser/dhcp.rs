//! Windows DHCP Server log parser.
//!
//! Parses CSV-format DHCP server logs (DhcpSrvLog-*.log and DhcpV6SrvLog-*.log).
//!
//! Format (after header block):
//!   ID,Date,Time,Description,IP Address,Host Name,MAC Address,User Name,
//!   TransactionID,QResult,Probationtime,CorrelationID,Dhcid,
//!   VendorClass(Hex),VendorClass(ASCII),UserClass(Hex),UserClass(ASCII),
//!   RelayAgentInformation,DnsRegError

use crate::models::log_entry::{LogEntry, LogFormat, Severity};

/// Check if a line looks like a DHCP data row (starts with a number followed by comma and date).
pub fn matches_dhcp_record(line: &str) -> bool {
    let trimmed = line.trim();
    // Must start with digits, then comma, then MM/DD/YY date
    if let Some(comma_pos) = trimmed.find(',') {
        let id_part = &trimmed[..comma_pos];
        let after = &trimmed[comma_pos + 1..];
        id_part.chars().all(|c| c.is_ascii_digit())
            && !id_part.is_empty()
            && after.len() >= 8
            && after.as_bytes()[2] == b'/'
    } else {
        false
    }
}

/// Derive severity from DHCP event ID.
fn severity_from_event_id(event_id: u32) -> Severity {
    match event_id {
        // Errors: pool exhausted, lease denied, DNS update failed
        14 | 15 | 31 | 34 | 35 => Severity::Error,
        // Warnings: IP in use, lease expired, packet dropped
        13 | 17 | 33 | 36 => Severity::Warning,
        // Everything else is info (started, renewed, released, DNS success, etc.)
        _ => Severity::Info,
    }
}

/// Format a MAC address with colons: AABBCCDDEEFF → AA:BB:CC:DD:EE:FF
fn format_mac(raw: &str) -> String {
    let clean: String = raw.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if clean.len() == 12 {
        format!(
            "{}:{}:{}:{}:{}:{}",
            &clean[0..2],
            &clean[2..4],
            &clean[4..6],
            &clean[6..8],
            &clean[8..10],
            &clean[10..12]
        )
    } else {
        raw.to_string()
    }
}

/// Parse all lines of a DHCP log file.
/// Skips the header block (non-CSV preamble lines).
pub fn parse_lines(lines: &[&str], file_path: &str) -> (Vec<LogEntry>, u32) {
    let mut entries = Vec::with_capacity(lines.len());
    let mut parse_errors: u32 = 0;
    let mut id: u64 = 0;

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Skip header lines (non-CSV preamble)
        if !matches_dhcp_record(trimmed) {
            continue;
        }

        // Split CSV fields
        let fields: Vec<&str> = trimmed.splitn(19, ',').collect();
        if fields.len() < 4 {
            parse_errors += 1;
            entries.push(LogEntry {
                id,
                line_number: (i + 1) as u32,
                message: trimmed.to_string(),
                component: None,
                timestamp: None,
                timestamp_display: None,
                severity: Severity::Info,
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
            id += 1;
            continue;
        }

        let event_id: u32 = fields[0].trim().parse().unwrap_or(0);
        let date_str = fields[1].trim();
        let time_str = fields[2].trim();
        let description = fields[3].trim();
        let ip_address = fields.get(4).map(|s| s.trim()).filter(|s| !s.is_empty());
        let host_name = fields.get(5).map(|s| s.trim()).filter(|s| !s.is_empty());
        let mac_address = fields.get(6).map(|s| s.trim()).filter(|s| !s.is_empty());

        // Parse date: MM/DD/YY
        let (timestamp, timestamp_display) = parse_dhcp_datetime(date_str, time_str);
        let severity = severity_from_event_id(event_id);

        // Build message: "EventID - Description"
        let message = format!("{} - {}", event_id, description);

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
            ip_address: ip_address.map(|s| s.to_string()),
            host_name: host_name.map(|s| s.to_string()),
            mac_address: mac_address.map(format_mac),
        });
        id += 1;
    }

    (entries, parse_errors)
}

/// Parse DHCP date (MM/DD/YY) and time (HH:MM:SS) into timestamp.
fn parse_dhcp_datetime(date: &str, time: &str) -> (Option<i64>, Option<String>) {
    let date_parts: Vec<&str> = date.split('/').collect();
    let time_parts: Vec<&str> = time.split(':').collect();

    if date_parts.len() != 3 || time_parts.len() < 3 {
        return (None, Some(format!("{} {}", date, time)));
    }

    let mon: u32 = date_parts[0].parse().unwrap_or(1);
    let day: u32 = date_parts[1].parse().unwrap_or(1);
    let yr_short: i32 = date_parts[2].parse().unwrap_or(0);
    let yr = if yr_short < 100 { 2000 + yr_short } else { yr_short };

    let h: u32 = time_parts[0].parse().unwrap_or(0);
    let m: u32 = time_parts[1].parse().unwrap_or(0);
    let s: u32 = time_parts[2].parse().unwrap_or(0);

    let timestamp = chrono::NaiveDate::from_ymd_opt(yr, mon, day)
        .and_then(|d| d.and_hms_opt(h, m, s))
        .map(|dt| dt.and_utc().timestamp_millis());

    let display = Some(format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        yr, mon, day, h, m, s
    ));

    (timestamp, display)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dhcp_renew() {
        let lines = vec![
            "11,03/23/26,18:31:38,Renew,192.168.2.116,deco-XE75.home.gell.one,54AF97F8352B,,79241796,0,,,,0x756468637020312E32322E31,udhcp 1.22.1,,,,0",
        ];
        let (entries, errors) = parse_lines(&lines, "test.log");
        assert_eq!(errors, 0);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].message, "11 - Renew");
        assert_eq!(entries[0].severity, Severity::Info);
        assert_eq!(entries[0].ip_address.as_deref(), Some("192.168.2.116"));
        assert_eq!(
            entries[0].host_name.as_deref(),
            Some("deco-XE75.home.gell.one")
        );
        assert_eq!(
            entries[0].mac_address.as_deref(),
            Some("54:AF:97:F8:35:2B")
        );
    }

    #[test]
    fn test_parse_dhcp_dns_failure() {
        let lines = vec![
            "31,03/23/26,18:31:28,DNS Update Failed,192.168.2.69,Fi Series 3 Base.home,10B41DB40CC0,,3978033648,0,6,,,,,,,,,9560",
        ];
        let (entries, _) = parse_lines(&lines, "test.log");
        assert_eq!(entries[0].severity, Severity::Error);
        assert_eq!(entries[0].message, "31 - DNS Update Failed");
    }

    #[test]
    fn test_parse_dhcp_pool_exhausted() {
        let lines = vec![
            "14,03/23/26,10:00:00,Pool exhausted,,,,,0,6,,,,,,,,,0",
        ];
        let (entries, _) = parse_lines(&lines, "test.log");
        assert_eq!(entries[0].severity, Severity::Error);
        assert!(entries[0].ip_address.is_none());
    }

    #[test]
    fn test_skip_header_lines() {
        let lines = vec![
            "\t\tMicrosoft DHCP Service Activity Log",
            "",
            "Event ID  Meaning",
            "00\tThe log was started.",
            "ID,Date,Time,Description,IP Address,Host Name,...",
            "11,03/23/26,18:00:00,Renew,192.168.1.1,test,,,,0,6,,,,,,,,,0",
        ];
        let (entries, _) = parse_lines(&lines, "test.log");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ip_address.as_deref(), Some("192.168.1.1"));
    }

    #[test]
    fn test_matches_dhcp_record() {
        assert!(matches_dhcp_record(
            "11,03/23/26,18:31:38,Renew,192.168.2.116,test,AABB,,0,6,,,,,,,,,0"
        ));
        assert!(!matches_dhcp_record("Event ID  Meaning"));
        assert!(!matches_dhcp_record(
            "ID,Date,Time,Description,IP Address"
        ));
        assert!(!matches_dhcp_record(""));
    }

    #[test]
    fn test_format_mac() {
        assert_eq!(format_mac("54AF97F8352B"), "54:AF:97:F8:35:2B");
        assert_eq!(format_mac("AABB"), "AABB"); // too short, return as-is
    }
}
