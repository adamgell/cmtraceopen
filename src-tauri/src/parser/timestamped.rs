use crate::parser::ccm::naive_to_utc_millis;
use regex::Regex;

use super::severity::detect_severity_from_text;
use crate::models::log_entry::{LogEntry, LogFormat};
use std::sync::OnceLock;

/// Controls whether slash-date fields are interpreted as MM/DD or DD/MM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum DateOrder {
    /// US style: first field is month (MM/DD/YYYY)
    #[default]
    MonthFirst,
    /// European style: first field is day (DD/MM/YYYY)
    DayFirst,
}

// ---------------------------------------------------------------------------
// Lazy-compiled regex patterns
// ---------------------------------------------------------------------------

/// ISO 8601: 2024-01-15T14:30:00.123Z or 2024-01-15 14:30:00,456+05:30
fn iso_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(
        r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{1,2}):(\d{2}):(\d{2})([.,]\d+)?(Z|[+-]\d{2}:?\d{2})?\s*(.*)"
    ).unwrap()
})
}

/// Slash-date: 01/15/2024 14:30:00.123 or 1/15/2024 2:30:00 PM
fn slash_date_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(
        r"^(\d{1,2})/(\d{1,2})/(\d{4})\s+(\d{1,2}):(\d{2}):(\d{2})(\.\d+)?(\s*[AaPp][Mm])?\s+(.*)",
    )
    .unwrap()
})
}

/// Syslog: Jan 15 14:30:00 hostname ...
fn syslog_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(
        r"^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(.*)"
    ).unwrap()
})
}

/// Time-only: 14:30:00.123 message...
fn time_only_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r"^(\d{2}):(\d{2}):(\d{2})([.,]\d+)?\s+(.*)").unwrap())
}

// ---------------------------------------------------------------------------
// Public API — matches same pattern as ccm/simple/plain parsers
// ---------------------------------------------------------------------------

/// Which timestamp pattern matched — used to try the same pattern first on subsequent lines.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TimestampFormat {
    Iso,
    SlashDate,
    Syslog,
    TimeOnly,
}

/// Try a specific pattern first, then fall back to the full search.
fn parse_line_with_hint(
    line: &str,
    date_order: DateOrder,
    hint: Option<TimestampFormat>,
) -> Option<(LogEntry, TimestampFormat)> {
    // Try the hinted format first (common case: same format as previous line)
    if let Some(fmt) = hint {
        if let Some(entry) = match fmt {
            TimestampFormat::Iso => try_iso(line),
            TimestampFormat::SlashDate => try_slash_date(line, date_order),
            TimestampFormat::Syslog => try_syslog(line),
            TimestampFormat::TimeOnly => try_time_only(line),
        } {
            return Some((entry, fmt));
        }
    }

    // Full search in priority order
    if let Some(entry) = try_iso(line) {
        return Some((entry, TimestampFormat::Iso));
    }
    if let Some(entry) = try_slash_date(line, date_order) {
        return Some((entry, TimestampFormat::SlashDate));
    }
    if let Some(entry) = try_syslog(line) {
        return Some((entry, TimestampFormat::Syslog));
    }
    if let Some(entry) = try_time_only(line) {
        return Some((entry, TimestampFormat::TimeOnly));
    }
    None
}

/// Parse all lines, extracting timestamps where possible.
/// Lines that don't match any timestamp pattern are included as plain-text entries.
/// Caches the detected format from the first match and tries it first on subsequent
/// lines, avoiding up to 3 wasted regex attempts per line.
pub fn parse_lines(lines: &[&str], file_path: &str, date_order: DateOrder) -> (Vec<LogEntry>, u32) {
    let mut entries = Vec::with_capacity(lines.len());
    let mut parse_errors: u32 = 0;
    let mut id: u64 = 0;
    let mut format_hint: Option<TimestampFormat> = None;

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some((mut entry, fmt)) = parse_line_with_hint(trimmed, date_order, format_hint) {
            entry.id = id;
            entry.line_number = (i + 1) as u32;
            entry.file_path = file_path.to_string();
            entries.push(entry);
            format_hint = Some(fmt);
        } else {
            // Fallback: treat as plain text with severity detection
            entries.push(LogEntry {
                id,
                line_number: (i + 1) as u32,
                message: trimmed.to_string(),
                component: None,
                timestamp: None,
                timestamp_display: None,
                severity: detect_severity_from_text(trimmed),
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
            });
            parse_errors += 1;
        }
        id += 1;
    }

    (entries, parse_errors)
}

// ---------------------------------------------------------------------------
// Internal — try each pattern in priority order
// ---------------------------------------------------------------------------

#[cfg(test)]
fn parse_line(line: &str, date_order: DateOrder) -> Option<LogEntry> {
    parse_line_with_hint(line, date_order, None).map(|(entry, _)| entry)
}

/// Check whether a line matches any supported timestamp pattern (used by detect.rs).
pub fn matches_any_timestamp(line: &str) -> bool {
    iso_re().is_match(line)
        || slash_date_re().is_match(line)
        || syslog_re().is_match(line)
        || time_only_re().is_match(line)
}

/// Check whether a slash-date line has first field > 12, indicating day-first order.
pub fn slash_date_first_field(line: &str) -> Option<u32> {
    slash_date_re()
        .captures(line)
        .and_then(|caps| caps.get(1).and_then(|m| m.as_str().parse::<u32>().ok()))
}

// ---------------------------------------------------------------------------
// Pattern matchers
// ---------------------------------------------------------------------------

fn try_iso(line: &str) -> Option<LogEntry> {
    let caps = iso_re().captures(line)?;

    let yr: i32 = caps.get(1)?.as_str().parse().ok()?;
    let mon: u32 = caps.get(2)?.as_str().parse().ok()?;
    let day: u32 = caps.get(3)?.as_str().parse().ok()?;
    let h: u32 = caps.get(4)?.as_str().parse().ok()?;
    let m: u32 = caps.get(5)?.as_str().parse().ok()?;
    let s: u32 = caps.get(6)?.as_str().parse().ok()?;

    let ms = parse_fractional_millis(caps.get(7).map(|m| m.as_str()));
    let tz_offset = parse_tz_offset(caps.get(8).map(|m| m.as_str()));
    let message = caps
        .get(9)
        .map(|m| m.as_str().to_string())
        .unwrap_or_default();

    let timestamp = chrono::NaiveDate::from_ymd_opt(yr, mon, day)
        .and_then(|d| d.and_hms_milli_opt(h, m, s, ms))
        .map(|naive| naive_to_utc_millis(naive, tz_offset));

    let timestamp_display = Some(format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
        yr, mon, day, h, m, s, ms
    ));

    let severity = detect_severity_from_text(&message);

    Some(LogEntry {
        id: 0,
        line_number: 0,
        message,
        component: None,
        timestamp,
        timestamp_display,
        severity,
        thread: None,
        thread_display: None,
        source_file: None,
        format: LogFormat::Timestamped,
        file_path: String::new(),
        timezone_offset: tz_offset,
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

fn try_slash_date(line: &str, date_order: DateOrder) -> Option<LogEntry> {
    let caps = slash_date_re().captures(line)?;

    let field1: u32 = caps.get(1)?.as_str().parse().ok()?;
    let field2: u32 = caps.get(2)?.as_str().parse().ok()?;
    let yr: i32 = caps.get(3)?.as_str().parse().ok()?;

    let (mon, day) = match date_order {
        DateOrder::MonthFirst => (field1, field2),
        DateOrder::DayFirst => (field2, field1),
    };

    let mut h: u32 = caps.get(4)?.as_str().parse().ok()?;
    let m: u32 = caps.get(5)?.as_str().parse().ok()?;
    let s: u32 = caps.get(6)?.as_str().parse().ok()?;

    let ms = parse_fractional_millis(caps.get(7).map(|m| m.as_str()));

    // Handle AM/PM
    if let Some(ampm) = caps.get(8) {
        let ampm_str = ampm.as_str().trim().to_uppercase();
        if ampm_str == "PM" && h < 12 {
            h += 12;
        } else if ampm_str == "AM" && h == 12 {
            h = 0;
        }
    }

    let message = caps
        .get(9)
        .map(|m| m.as_str().to_string())
        .unwrap_or_default();

    let timestamp = chrono::NaiveDate::from_ymd_opt(yr, mon, day)
        .and_then(|d| d.and_hms_milli_opt(h, m, s, ms))
        .map(|dt| dt.and_utc().timestamp_millis());

    let timestamp_display = Some(format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
        yr, mon, day, h, m, s, ms
    ));

    let severity = detect_severity_from_text(&message);

    Some(LogEntry {
        id: 0,
        line_number: 0,
        message,
        component: None,
        timestamp,
        timestamp_display,
        severity,
        thread: None,
        thread_display: None,
        source_file: None,
        format: LogFormat::Timestamped,
        file_path: String::new(),
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

fn try_syslog(line: &str) -> Option<LogEntry> {
    let caps = syslog_re().captures(line)?;

    let month_str = caps.get(1)?.as_str();
    let day: u32 = caps.get(2)?.as_str().parse().ok()?;
    let h: u32 = caps.get(3)?.as_str().parse().ok()?;
    let m: u32 = caps.get(4)?.as_str().parse().ok()?;
    let s: u32 = caps.get(5)?.as_str().parse().ok()?;
    let message = caps
        .get(6)
        .map(|m| m.as_str().to_string())
        .unwrap_or_default();

    let mon = month_name_to_number(month_str)?;
    let yr = chrono::Local::now()
        .format("%Y")
        .to_string()
        .parse::<i32>()
        .unwrap_or(2024);

    let timestamp = chrono::NaiveDate::from_ymd_opt(yr, mon, day)
        .and_then(|d| d.and_hms_opt(h, m, s))
        .map(|dt| dt.and_utc().timestamp_millis());

    let timestamp_display = Some(format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.000",
        yr, mon, day, h, m, s
    ));

    let severity = detect_severity_from_text(&message);

    Some(LogEntry {
        id: 0,
        line_number: 0,
        message,
        component: None,
        timestamp,
        timestamp_display,
        severity,
        thread: None,
        thread_display: None,
        source_file: None,
        format: LogFormat::Timestamped,
        file_path: String::new(),
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

fn try_time_only(line: &str) -> Option<LogEntry> {
    let caps = time_only_re().captures(line)?;

    let h: u32 = caps.get(1)?.as_str().parse().ok()?;
    let m: u32 = caps.get(2)?.as_str().parse().ok()?;
    let s: u32 = caps.get(3)?.as_str().parse().ok()?;
    let ms = parse_fractional_millis(caps.get(4).map(|m| m.as_str()));
    let message = caps
        .get(5)
        .map(|m| m.as_str().to_string())
        .unwrap_or_default();

    // Validate time values
    if h >= 24 || m >= 60 || s >= 60 {
        return None;
    }

    let timestamp_display = Some(format!("{:02}:{:02}:{:02}.{:03}", h, m, s, ms));

    let severity = detect_severity_from_text(&message);

    Some(LogEntry {
        id: 0,
        line_number: 0,
        message,
        component: None,
        timestamp: None, // No date → no unix timestamp
        timestamp_display,
        severity,
        thread: None,
        thread_display: None,
        source_file: None,
        format: LogFormat::Timestamped,
        file_path: String::new(),
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse fractional seconds like ".123", ",456789" → milliseconds (truncated to 3 digits).
fn parse_fractional_millis(frac: Option<&str>) -> u32 {
    match frac {
        Some(s) => {
            // Strip leading '.' or ','
            let digits = s.trim_start_matches(['.', ',']);
            // Pad or truncate to 3 digits
            let padded = format!("{:0<3}", digits);
            padded[..3].parse::<u32>().unwrap_or(0)
        }
        None => 0,
    }
}

/// Parse timezone offset string → minutes.
/// Examples: "Z" → Some(0), "+05:30" → Some(330), "-08:00" → Some(-480), "+0530" → Some(330)
fn parse_tz_offset(tz: Option<&str>) -> Option<i32> {
    match tz {
        None => None,
        Some("Z") | Some("z") => Some(0),
        Some(s) => {
            let sign: i32 = if s.starts_with('-') { -1 } else { 1 };
            let digits = s.trim_start_matches(['+', '-']);
            let clean = digits.replace(':', "");
            if clean.len() >= 4 {
                let hours: i32 = clean[..2].parse().ok()?;
                let mins: i32 = clean[2..4].parse().ok()?;
                Some(sign * (hours * 60 + mins))
            } else {
                None
            }
        }
    }
}

fn month_name_to_number(name: &str) -> Option<u32> {
    match name {
        "Jan" => Some(1),
        "Feb" => Some(2),
        "Mar" => Some(3),
        "Apr" => Some(4),
        "May" => Some(5),
        "Jun" => Some(6),
        "Jul" => Some(7),
        "Aug" => Some(8),
        "Sep" => Some(9),
        "Oct" => Some(10),
        "Nov" => Some(11),
        "Dec" => Some(12),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::log_entry::Severity;
    use chrono::FixedOffset;
    use chrono::TimeZone;

    #[test]
    fn test_iso_with_z() {
        let entry = parse_line(
            "2024-01-15T14:30:00.123Z Error: connection refused",
            DateOrder::MonthFirst,
        )
        .unwrap();
        assert_eq!(
            entry.timestamp_display.as_deref(),
            Some("2024-01-15 14:30:00.123")
        );
        assert!(entry.message.contains("connection refused"));
        assert_eq!(entry.severity, Severity::Error);
        assert_eq!(entry.timezone_offset, Some(0));
    }

    #[test]
    fn test_iso_with_offset() {
        let entry = parse_line(
            "2024-01-15T14:30:00.000+05:30 Starting service",
            DateOrder::MonthFirst,
        )
        .unwrap();
        assert_eq!(entry.timezone_offset, Some(330));
        assert_eq!(entry.severity, Severity::Info);
        // Verify the epoch millis are correct: 14:30 at UTC+5:30 = 09:00 UTC
        let expected_ts = FixedOffset::east_opt(330 * 60)
            .unwrap()
            .from_local_datetime(
                &chrono::NaiveDate::from_ymd_opt(2024, 1, 15)
                    .unwrap()
                    .and_hms_milli_opt(14, 30, 0, 0)
                    .unwrap(),
            )
            .single()
            .unwrap()
            .timestamp_millis();
        assert_eq!(entry.timestamp, Some(expected_ts));
    }

    #[test]
    fn test_iso_space_separator() {
        let entry = parse_line(
            "2024-01-15 14:30:00,456 WARNING: disk space low",
            DateOrder::MonthFirst,
        )
        .unwrap();
        assert_eq!(
            entry.timestamp_display.as_deref(),
            Some("2024-01-15 14:30:00.456")
        );
        assert_eq!(entry.severity, Severity::Warning);
    }

    #[test]
    fn test_iso_no_fractional() {
        let entry = parse_line("2024-01-15T14:30:00 Ready", DateOrder::MonthFirst).unwrap();
        assert_eq!(
            entry.timestamp_display.as_deref(),
            Some("2024-01-15 14:30:00.000")
        );
    }

    #[test]
    fn test_us_date() {
        let entry = parse_line(
            "01/15/2024 14:30:00 Processing request",
            DateOrder::MonthFirst,
        )
        .unwrap();
        assert_eq!(
            entry.timestamp_display.as_deref(),
            Some("2024-01-15 14:30:00.000")
        );
    }

    #[test]
    fn test_us_date_with_ampm() {
        let entry =
            parse_line("1/15/2024 2:30:00 PM Task completed", DateOrder::MonthFirst).unwrap();
        assert_eq!(
            entry.timestamp_display.as_deref(),
            Some("2024-01-15 14:30:00.000")
        );
    }

    #[test]
    fn test_eu_date() {
        let entry = parse_line(
            "15/01/2024 14:30:00 Processing request",
            DateOrder::DayFirst,
        )
        .unwrap();
        assert_eq!(
            entry.timestamp_display.as_deref(),
            Some("2024-01-15 14:30:00.000")
        );
    }

    #[test]
    fn test_syslog() {
        let entry = parse_line(
            "Jan 15 14:30:00 myhost kernel: NIC Link is Up",
            DateOrder::MonthFirst,
        )
        .unwrap();
        assert!(entry
            .timestamp_display
            .as_deref()
            .unwrap()
            .contains("14:30:00"));
        assert!(entry.message.contains("myhost"));
        assert_eq!(entry.format, LogFormat::Timestamped);
    }

    #[test]
    fn test_time_only() {
        let entry = parse_line("14:30:00.123 Initializing module", DateOrder::MonthFirst).unwrap();
        assert!(entry.timestamp.is_none());
        assert_eq!(entry.timestamp_display.as_deref(), Some("14:30:00.123"));
    }

    #[test]
    fn test_no_timestamp() {
        assert!(parse_line("Just some plain text", DateOrder::MonthFirst).is_none());
    }

    #[test]
    fn test_am_midnight() {
        let entry = parse_line(
            "1/15/2024 12:30:00 AM Midnight event",
            DateOrder::MonthFirst,
        )
        .unwrap();
        // 12 AM = 0 hours
        assert_eq!(
            entry.timestamp_display.as_deref(),
            Some("2024-01-15 00:30:00.000")
        );
    }

    #[test]
    fn test_parse_fractional_millis_helper() {
        assert_eq!(parse_fractional_millis(Some(".123")), 123);
        assert_eq!(parse_fractional_millis(Some(",456789")), 456);
        assert_eq!(parse_fractional_millis(Some(".1")), 100);
        assert_eq!(parse_fractional_millis(None), 0);
    }

    #[test]
    fn test_parse_tz_offset_helper() {
        assert_eq!(parse_tz_offset(Some("Z")), Some(0));
        assert_eq!(parse_tz_offset(Some("+05:30")), Some(330));
        assert_eq!(parse_tz_offset(Some("-0800")), Some(-480));
        assert_eq!(parse_tz_offset(None), None);
    }

    #[test]
    fn test_matches_any_timestamp() {
        assert!(matches_any_timestamp("2024-01-15T14:30:00Z Starting"));
        assert!(matches_any_timestamp("01/15/2024 14:30:00 Test"));
        assert!(matches_any_timestamp("Jan 15 14:30:00 syslog message"));
        assert!(matches_any_timestamp("14:30:00 time only"));
        assert!(!matches_any_timestamp("Just plain text"));
    }

    #[test]
    fn test_slash_date_first_field() {
        assert_eq!(slash_date_first_field("25/01/2024 14:30:00 test"), Some(25));
        assert_eq!(slash_date_first_field("01/15/2024 14:30:00 test"), Some(1));
        assert_eq!(slash_date_first_field("plain text"), None);
    }

    #[test]
    fn test_invalid_time_only_rejected() {
        // 25:00:00 is not a valid time
        assert!(parse_line("25:00:00 invalid time", DateOrder::MonthFirst).is_none());
    }
}
