//! Windows DNS Server debug log parser.
//!
//! Parses PACKET summary lines from DNS debug logs (`dns.log`).
//! These text files start with a ~29-line header, followed by PACKET lines
//! and optional multi-line detail sections.
//!
//! Example PACKET line:
//! ```text
//! 4/11/2026 3:29:17 PM 0294 PACKET  000002DAEC36D650 UDP Rcv 127.0.0.1       d07e   Q [0001   D   NOERROR] SOA    (4)home(4)gell(3)one(0)
//! ```

use super::dns_types;
use super::timestamped::DateOrder;
use crate::models::log_entry::{LogEntry, LogFormat};
use regex::Regex;
use std::sync::OnceLock;

/// Regex for PACKET summary lines in DNS debug logs.
///
/// Groups:
///  1: timestamp string (everything before the thread hex)
///  2: thread hex (e.g. "0294")
///  3: memory address
///  4: protocol (UDP/TCP)
///  5: direction (Snd/Rcv)
///  6: remote IP
///  7: transaction ID hex
///  8: R flag (present on responses, absent on queries)
///  9: opcode (Q=query, N=notify, U=update, ?)
/// 10: flags+rcode bracket contents (e.g. "0001   D   NOERROR")
/// 11: query type (A, AAAA, SOA, etc.)
/// 12: query name in wire format
fn packet_line_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r"^(.+?)\s+([0-9A-Fa-f]{4})\s+PACKET\s+([0-9A-Fa-f]+)\s+(UDP|TCP)\s+(Snd|Rcv)\s+(\S+)\s+([0-9A-Fa-f]{4})\s+(R\s+|)([QNU?])\s+\[([^\]]+)\]\s+(\S+)\s+(.*)$"
        )
        .expect("packet_line_re: DNS debug PACKET line pattern must compile")
    })
}

/// Regex to extract port from detail section: `Remote addr X.X.X.X, port NNNNN`
fn detail_port_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"Remote addr\s+\S+,\s+port\s+(\d+)")
            .expect("detail_port_re: DNS detail port extraction pattern must compile")
    })
}

/// Fast pre-check: returns true if this line looks like a DNS debug PACKET line.
pub fn matches_dns_debug_record(line: &str) -> bool {
    // Fast string check before running the regex
    if !line.contains("PACKET") {
        return false;
    }
    packet_line_re().is_match(line)
}

/// Parse DNS debug log lines into `LogEntry` values.
///
/// Uses `LogicalRecord` framing: a PACKET line starts a new record,
/// subsequent non-PACKET lines (detail sections) append to it.
/// Header lines (before the first PACKET) and blank lines are skipped.
pub fn parse_lines(
    lines: &[&str],
    file_path: &str,
    date_order: DateOrder,
) -> (Vec<LogEntry>, u32) {
    let mut entries = Vec::with_capacity(lines.len() / 2);
    let mut parse_errors: u32 = 0;
    let mut next_id: u64 = 0;
    let mut pending: Option<PendingEntry> = None;

    for (index, line) in lines.iter().enumerate() {
        let line_number = (index + 1) as u32;
        let trimmed = line.trim();

        if trimmed.is_empty() {
            continue;
        }

        // Try to parse as a PACKET line
        if let Some(entry) = parse_packet_line(trimmed, file_path, date_order) {
            // Flush any pending entry
            flush_pending(&mut entries, &mut pending, &mut next_id);
            pending = Some(PendingEntry {
                entry,
                start_line: line_number,
            });
            continue;
        }

        // Line contains "PACKET" but failed structured parsing — count as a parse error
        if trimmed.contains("PACKET") {
            parse_errors += 1;
        }

        // Not a PACKET line — if we have a pending entry, this is a detail line
        if let Some(ref mut pending_entry) = pending {
            // Check for port in detail section
            if let Some(caps) = detail_port_re().captures(trimmed) {
                if let Some(port_str) = caps.get(1) {
                    let port = port_str.as_str();
                    // Append port to source_ip
                    if let Some(ref ip) = pending_entry.entry.source_ip {
                        if !ip.contains(':') {
                            pending_entry.entry.source_ip =
                                Some(format!("{}:{}", ip, port));
                        }
                    }
                }
            }

            // Append detail text to message
            if !pending_entry.entry.message.is_empty() {
                pending_entry.entry.message.push('\n');
            }
            pending_entry.entry.message.push_str(trimmed);
        }
        // If no pending entry, this is a header line — skip it
    }

    // Flush final pending entry
    flush_pending(&mut entries, &mut pending, &mut next_id);

    (entries, parse_errors)
}

struct PendingEntry {
    entry: LogEntry,
    start_line: u32,
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

/// Parse a single PACKET line into a LogEntry.
fn parse_packet_line(line: &str, file_path: &str, date_order: DateOrder) -> Option<LogEntry> {
    let caps = packet_line_re().captures(line)?;

    let timestamp_str = caps.get(1)?.as_str().trim();
    let thread_hex = caps.get(2)?.as_str();
    // _memory_addr = caps.get(3)
    let protocol = caps.get(4)?.as_str();
    let direction = caps.get(5)?.as_str();
    let remote_ip = caps.get(6)?.as_str().trim();
    // _txn_id = caps.get(7)
    // _r_flag = caps.get(8) — present on responses
    // _opcode = caps.get(9)
    let flags_rcode = caps.get(10)?.as_str();
    let query_type_str = caps.get(11)?.as_str().trim();
    let query_name_raw = caps.get(12)?.as_str().trim();

    // Parse thread hex to decimal
    let thread_val = u32::from_str_radix(thread_hex, 16).unwrap_or(0);
    let thread_display = format!("{} (0x{})", thread_val, thread_hex);

    // Parse flags and rcode from bracket contents
    // Format: "HHHH CCCC RCODE" with variable whitespace
    // Examples: "0001   D   NOERROR", "8085 A DR  NOERROR", "02a8      SERVFAIL"
    let (flags_hex, rcode) = parse_flags_rcode(flags_rcode);

    // Decode query name
    let query_name = dns_types::decode_query_name(query_name_raw);

    // Map rcode to severity
    let severity = dns_types::rcode_to_severity(&rcode);

    // Parse timestamp
    let (timestamp, timestamp_display) = parse_dns_timestamp(timestamp_str, date_order);

    // Build message: "[Rcv] [UDP] home.gell.one (A) → NOERROR"
    let message = format!(
        "[{}] [{}] {} ({}) \u{2192} {}",
        direction, protocol, query_name, query_type_str, rcode
    );

    Some(LogEntry {
        id: 0,
        line_number: 0,
        message,
        component: None,
        timestamp,
        timestamp_display,
        severity,
        thread: Some(thread_val),
        thread_display: Some(thread_display),
        source_file: None,
        format: LogFormat::DnsDebug,
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
        query_name: if query_name.is_empty() {
            None
        } else {
            Some(query_name)
        },
        query_type: Some(query_type_str.to_string()),
        response_code: Some(rcode),
        dns_direction: Some(direction.to_string()),
        dns_protocol: Some(protocol.to_string()),
        source_ip: Some(remote_ip.to_string()),
        dns_flags: Some(format!("0x{}", flags_hex)),
        dns_event_id: None,
        zone_name: None,
        entry_kind: None,
        whatif: None,
        section_name: None,
        section_color: None,
        iteration: None,
        tags: None,
    })
}

/// Parse the flags+rcode section from inside brackets.
///
/// The format is: `HHHH [flags] RCODE` with variable spacing.
/// Examples:
///   "0001   D   NOERROR"
///   "8085 A DR  NOERROR"
///   "8385 A DR NXDOMAIN"
///   "02a8      SERVFAIL"
///   "0028       NOERROR"
///   "8081   DR  NOERROR"
fn parse_flags_rcode(s: &str) -> (String, String) {
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.is_empty() {
        return (String::new(), "UNKNOWN".to_string());
    }

    let flags_hex = parts[0].to_string();
    // The RCODE is always the last token
    let rcode = parts.last().unwrap_or(&"UNKNOWN").to_string();

    (flags_hex, rcode)
}

/// Parse DNS debug log timestamps.
///
/// Three locale variants are handled:
///   US:  M/d/yyyy h:mm:ss AM/PM  (12-hour)
///   EU:  dd/MM/yyyy HH:mm:ss     (24-hour)
///   ISO: yyyyMMdd HH:mm:ss
///
/// The `date_order` parameter resolves MM/DD vs DD/MM ambiguity for slash dates.
fn parse_dns_timestamp(s: &str, date_order: DateOrder) -> (Option<i64>, Option<String>) {
    // Try to split into date part and time part
    // US format has AM/PM at the end, so we need to handle that

    let trimmed = s.trim();

    // Check for ISO format: yyyyMMdd HH:mm:ss
    // Strict validation: positions 0..8 must all be digits and position 8 must be a space.
    if trimmed.len() >= 15 {
        let bytes = trimmed.as_bytes();
        if bytes[0..8].iter().all(|b| b.is_ascii_digit()) && bytes[8] == b' ' {
            return parse_iso_timestamp(trimmed);
        }
    }

    // Slash-delimited date: M/d/yyyy or dd/MM/yyyy
    if let Some(space_pos) = trimmed.find(' ') {
        let date_part = &trimmed[..space_pos];
        let time_part = &trimmed[space_pos + 1..];

        let date_fields: Vec<&str> = date_part.split('/').collect();
        if date_fields.len() != 3 {
            return (None, Some(trimmed.to_string()));
        }

        let field1: u32 = date_fields[0].parse().unwrap_or(0);
        let field2: u32 = date_fields[1].parse().unwrap_or(0);
        let year: i32 = date_fields[2].parse().unwrap_or(0);

        let (month, day) = match date_order {
            DateOrder::MonthFirst => (field1, field2),
            DateOrder::DayFirst => (field2, field1),
        };

        // Parse time: "3:29:17 PM" or "15:29:17"
        let (hour, minute, second) = parse_time_component(time_part);

        let timestamp = chrono::NaiveDate::from_ymd_opt(year, month, day)
            .and_then(|d| d.and_hms_opt(hour, minute, second))
            .map(|dt| dt.and_utc().timestamp_millis());

        let display = Some(format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            year, month, day, hour, minute, second
        ));

        return (timestamp, display);
    }

    (None, Some(trimmed.to_string()))
}

/// Parse ISO timestamp: yyyyMMdd HH:mm:ss
fn parse_iso_timestamp(s: &str) -> (Option<i64>, Option<String>) {
    if s.len() < 15 {
        return (None, Some(s.to_string()));
    }

    let year: i32 = s[0..4].parse().unwrap_or(0);
    let month: u32 = s[4..6].parse().unwrap_or(0);
    let day: u32 = s[6..8].parse().unwrap_or(0);

    // Skip space at index 8
    let time_str = &s[9..];
    let time_parts: Vec<&str> = time_str.split(':').collect();
    if time_parts.len() < 3 {
        return (None, Some(s.to_string()));
    }

    let hour: u32 = time_parts[0].parse().unwrap_or(0);
    let minute: u32 = time_parts[1].parse().unwrap_or(0);
    let second: u32 = time_parts[2].parse().unwrap_or(0);

    let timestamp = chrono::NaiveDate::from_ymd_opt(year, month, day)
        .and_then(|d| d.and_hms_opt(hour, minute, second))
        .map(|dt| dt.and_utc().timestamp_millis());

    let display = Some(format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        year, month, day, hour, minute, second
    ));

    (timestamp, display)
}

/// Parse a time component that may be 12-hour (with AM/PM) or 24-hour.
fn parse_time_component(s: &str) -> (u32, u32, u32) {
    let upper = s.trim().to_uppercase();
    let is_pm = upper.contains("PM");
    let is_am = upper.contains("AM");

    // Strip AM/PM
    let time_only = upper
        .replace("AM", "")
        .replace("PM", "")
        .trim()
        .to_string();

    let parts: Vec<&str> = time_only.split(':').collect();
    if parts.len() < 3 {
        return (0, 0, 0);
    }

    let mut hour: u32 = parts[0].trim().parse().unwrap_or(0);
    let minute: u32 = parts[1].trim().parse().unwrap_or(0);
    let second: u32 = parts[2].trim().parse().unwrap_or(0);

    if is_pm || is_am {
        // 12-hour format conversion
        if is_pm && hour != 12 {
            hour += 12;
        } else if is_am && hour == 12 {
            hour = 0;
        }
    }

    (hour, minute, second)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::log_entry::Severity;

    #[test]
    fn test_matches_packet_line() {
        let line = "4/11/2026 3:29:17 PM 0294 PACKET  000002DAEC36D650 UDP Rcv 127.0.0.1       d07e   Q [0001   D   NOERROR] SOA    (4)home(4)gell(3)one(0)";
        assert!(matches_dns_debug_record(line));
    }

    #[test]
    fn test_does_not_match_header() {
        assert!(!matches_dns_debug_record(
            "DNS Server log file creation at 4/11/2026 3:29:00 PM"
        ));
        assert!(!matches_dns_debug_record("Log file wrap:"));
        assert!(!matches_dns_debug_record("Message logging key (for packets - other items use a subset):"));
    }

    #[test]
    fn test_does_not_match_detail_line() {
        assert!(!matches_dns_debug_record(
            "  Socket = 884"
        ));
        assert!(!matches_dns_debug_record(
            "  Remote addr 127.0.0.1, port 54159"
        ));
        assert!(!matches_dns_debug_record(
            "UDP question info at 000002DAEC36D650"
        ));
    }

    #[test]
    fn test_parse_basic_query_response_pair() {
        let lines = vec![
            "4/11/2026 3:29:17 PM 0294 PACKET  000002DAEC36D650 UDP Rcv 127.0.0.1       d07e   Q [0001   D   NOERROR] SOA    (4)home(4)gell(3)one(0)",
            "4/11/2026 3:29:17 PM 0294 PACKET  000002DAEC36D650 UDP Snd 127.0.0.1       d07e R Q [8085 A DR  NOERROR] SOA    (4)home(4)gell(3)one(0)",
        ];
        let line_refs: Vec<&str> = lines.iter().map(|s| s.as_ref()).collect();
        let (entries, errors) = parse_lines(&line_refs, "dns.log", DateOrder::MonthFirst);

        assert_eq!(errors, 0);
        assert_eq!(entries.len(), 2);

        // First entry: query (Rcv)
        assert_eq!(entries[0].dns_direction.as_deref(), Some("Rcv"));
        assert_eq!(entries[0].dns_protocol.as_deref(), Some("UDP"));
        assert_eq!(entries[0].query_name.as_deref(), Some("home.gell.one"));
        assert_eq!(entries[0].query_type.as_deref(), Some("SOA"));
        assert_eq!(entries[0].response_code.as_deref(), Some("NOERROR"));
        assert_eq!(entries[0].severity, Severity::Info);
        assert_eq!(entries[0].format, LogFormat::DnsDebug);
        assert!(entries[0].message.contains("[Rcv]"));
        assert!(entries[0].message.contains("[UDP]"));
        assert!(entries[0].message.contains("home.gell.one"));
        assert!(entries[0].message.contains("\u{2192}"));
        assert!(entries[0].message.contains("NOERROR"));

        // Second entry: response (Snd)
        assert_eq!(entries[1].dns_direction.as_deref(), Some("Snd"));
        assert_eq!(entries[1].dns_protocol.as_deref(), Some("UDP"));
        assert_eq!(entries[1].query_name.as_deref(), Some("home.gell.one"));
    }

    #[test]
    fn test_parse_with_detail_section_extracts_port() {
        let lines = vec![
            "4/11/2026 3:29:17 PM 0294 PACKET  000002DAEC36D650 UDP Rcv 127.0.0.1       d07e   Q [0001   D   NOERROR] SOA    (4)home(4)gell(3)one(0)",
            "UDP question info at 000002DAEC36D650",
            "  Socket = 884",
            "  Remote addr 127.0.0.1, port 54159",
            "  Time Query=1714823, Queued=0, Expire=0",
        ];
        let line_refs: Vec<&str> = lines.iter().map(|s| s.as_ref()).collect();
        let (entries, errors) = parse_lines(&line_refs, "dns.log", DateOrder::MonthFirst);

        assert_eq!(errors, 0);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].source_ip.as_deref(), Some("127.0.0.1:54159"));
    }

    #[test]
    fn test_parse_severity_mapping() {
        let lines = vec![
            "4/11/2026 8:34:00 PM 0294 PACKET  000002DAEF3AFDC0 UDP Snd 127.0.0.1       3c8a R Q [8385 A DR NXDOMAIN] A      (4)HOME(4)home(4)gell(3)one(0)",
            "4/11/2026 3:29:17 PM 0294 PACKET  000002DAEC3680D0 UDP Snd 192.168.2.9     7822 R U [02a8      SERVFAIL] SOA    (4)home(4)gell(3)one(0)",
        ];
        let line_refs: Vec<&str> = lines.iter().map(|s| s.as_ref()).collect();
        let (entries, _) = parse_lines(&line_refs, "dns.log", DateOrder::MonthFirst);

        assert_eq!(entries[0].severity, Severity::Warning); // NXDOMAIN
        assert_eq!(entries[1].severity, Severity::Error); // SERVFAIL
    }

    #[test]
    fn test_parse_skips_header() {
        let lines = vec![
            "DNS Server log file creation at 4/11/2026 3:29:00 PM",
            "Log file wrap:",
            "Message logging key (for packets - other items use a subset):",
            "",
            "4/11/2026 3:29:17 PM 0294 PACKET  000002DAEC36D650 UDP Rcv 127.0.0.1       d07e   Q [0001   D   NOERROR] SOA    (4)home(4)gell(3)one(0)",
        ];
        let line_refs: Vec<&str> = lines.iter().map(|s| s.as_ref()).collect();
        let (entries, errors) = parse_lines(&line_refs, "dns.log", DateOrder::MonthFirst);

        assert_eq!(errors, 0);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].query_name.as_deref(), Some("home.gell.one"));
    }

    #[test]
    fn test_parse_thread_display() {
        let lines = vec![
            "4/11/2026 3:29:17 PM 0294 PACKET  000002DAEC36D650 UDP Rcv 127.0.0.1       d07e   Q [0001   D   NOERROR] SOA    (4)home(4)gell(3)one(0)",
        ];
        let line_refs: Vec<&str> = lines.iter().map(|s| s.as_ref()).collect();
        let (entries, _) = parse_lines(&line_refs, "dns.log", DateOrder::MonthFirst);

        assert_eq!(entries[0].thread, Some(660));
        assert_eq!(
            entries[0].thread_display.as_deref(),
            Some("660 (0x0294)")
        );
    }

    #[test]
    fn test_parse_us_timestamp() {
        let lines = vec![
            "4/11/2026 3:29:17 PM 0294 PACKET  000002DAEC36D650 UDP Rcv 127.0.0.1       d07e   Q [0001   D   NOERROR] SOA    (4)home(4)gell(3)one(0)",
        ];
        let line_refs: Vec<&str> = lines.iter().map(|s| s.as_ref()).collect();
        let (entries, _) = parse_lines(&line_refs, "dns.log", DateOrder::MonthFirst);

        assert_eq!(
            entries[0].timestamp_display.as_deref(),
            Some("2026-04-11 15:29:17")
        );
    }

    #[test]
    fn test_parse_dynamic_update_opcode() {
        let lines = vec![
            "4/11/2026 3:29:17 PM 0294 PACKET  000002DAEC3680D0 UDP Rcv 192.168.2.9     7822   U [0028       NOERROR] SOA    (4)home(4)gell(3)one(0)",
        ];
        let line_refs: Vec<&str> = lines.iter().map(|s| s.as_ref()).collect();
        let (entries, errors) = parse_lines(&line_refs, "dns.log", DateOrder::MonthFirst);

        assert_eq!(errors, 0);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].dns_direction.as_deref(), Some("Rcv"));
        assert_eq!(entries[0].response_code.as_deref(), Some("NOERROR"));
    }

    #[test]
    fn test_parse_root_query() {
        let lines = vec![
            "4/11/2026 8:33:19 PM 0294 PACKET  000002DAECB28D10 UDP Snd 192.168.2.9     131a R Q [8081   DR  NOERROR] NS     (0)",
        ];
        let line_refs: Vec<&str> = lines.iter().map(|s| s.as_ref()).collect();
        let (entries, errors) = parse_lines(&line_refs, "dns.log", DateOrder::MonthFirst);

        assert_eq!(errors, 0);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].query_name.as_deref(), Some("."));
    }
}
