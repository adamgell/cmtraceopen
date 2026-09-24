use chrono::{FixedOffset, TimeZone};
use regex::Regex;
use std::sync::LazyLock;

use super::severity::detect_severity_from_text;
use crate::models::log_entry::{LogEntry, LogFormat, Severity};

/// Fields every record carries, from the record GUID through the status. Only
/// the operation, message, and trailing agent token follow them, and a record
/// may carry neither an operation nor a message.
const FIXED_FIELD_COUNT: usize = 11;

static GUID_FIELD_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$")
        .expect("record GUID regex must compile")
});

/// `YYYY-MM-DD HH:MM:SS[.mmm][+HHMM]`.
///
/// Real ReportingEvents.log files write the millisecond group with either `.`
/// or `:` (both appear inside one file) and always append the writing machine's
/// offset, so a record without one is treated as a zoneless wall clock rather
/// than promoted to UTC (#657).
static TIMESTAMP_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^([0-9]{4})-([0-9]{2})-([0-9]{2})[ T]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:[.:]([0-9]{1,7}))?(Z|[+-][0-9]{2}:?[0-9]{2})?$",
    )
    .expect("timestamp regex must compile")
});

/// The opaque token the update agent appends to a record, for example
/// `2cKOY/iJXE+rbVlS.3.0.0.3.0`. It is not reader-facing text, so it is dropped
/// instead of being mistaken for a message.
static AGENT_TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z0-9+/]{8,}\.[0-9][0-9.]*$").expect("token regex must compile")
});

pub fn matches_reporting_events_record(line: &str) -> bool {
    let fields: Vec<&str> = line.split('\t').collect();
    if fields.len() < FIXED_FIELD_COUNT {
        return false;
    }

    GUID_FIELD_RE.is_match(fields[0].trim()) && parse_timestamp(fields[1].trim()).is_some()
}

pub fn parse_lines(lines: &[&str], file_path: &str) -> (Vec<LogEntry>, u32) {
    let mut entries = Vec::new();
    let mut parse_errors = 0;
    let mut next_id = 0;

    for (index, line) in lines.iter().enumerate() {
        let trimmed_end = line.trim_end();
        if trimmed_end.trim().is_empty() {
            continue;
        }

        if let Some(mut entry) = parse_line(trimmed_end, file_path) {
            entry.id = next_id;
            entry.line_number = (index + 1) as u32;
            entries.push(entry);
        } else {
            entries.push(fallback_entry(
                next_id,
                (index + 1) as u32,
                trimmed_end,
                file_path,
            ));
            parse_errors += 1;
        }

        next_id += 1;
    }

    (entries, parse_errors)
}

fn parse_line(line: &str, file_path: &str) -> Option<LogEntry> {
    let fields: Vec<&str> = line.split('\t').collect();
    if fields.len() < FIXED_FIELD_COUNT {
        return None;
    }

    let record_guid = normalize_field(fields[0])?;
    if !GUID_FIELD_RE.is_match(record_guid) {
        return None;
    }

    let (timestamp, timestamp_display, timezone_offset) = parse_timestamp(fields[1].trim())?;
    let event_id = normalize_field(fields[3]);
    let event_name = normalize_event_name(fields[4]);
    let update_guid = normalize_field(fields[6]).filter(|value| !is_placeholder_guid(value));
    let result_code = parse_result_code(fields[8]);
    let provider = normalize_field(fields[9]).filter(|value| !is_null_token(value));
    let status = normalize_field(fields[10]);

    let mut tail: Vec<&str> = fields[FIXED_FIELD_COUNT..].to_vec();
    if tail
        .last()
        .is_some_and(|value| AGENT_TOKEN_RE.is_match(value.trim()))
    {
        tail.pop();
    }
    let operation = tail.first().and_then(|value| normalize_field(value));
    let detail = join_message_fields(tail.get(1..).unwrap_or_default());

    let message = build_message(
        status,
        event_name,
        operation,
        &detail,
        result_code.as_ref().map(|(text, _)| text.as_str()),
        update_guid,
        event_id,
    );

    let severity = determine_severity(
        status,
        event_name,
        operation,
        &detail,
        result_code.as_ref().and_then(|(_, code)| *code),
    );

    Some(LogEntry {
        id: 0,
        line_number: 0,
        message,
        component: provider.map(str::to_string),
        timestamp: Some(timestamp),
        timestamp_display: Some(timestamp_display),
        severity,
        thread: None,
        thread_display: None,
        source_file: None,
        format: LogFormat::Timestamped,
        file_path: file_path.to_string(),
        timezone_offset,
        error_code_spans: Vec::new(),
        ip_address: None,
        host_name: None,
        mac_address: None,
        result_code: result_code.map(|(text, _)| text),
        gle_code: None,
        setup_phase: None,
        operation_name: operation.map(str::to_string),
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
    })
}

/// Parsed epoch, display text, and the offset the record carried in minutes.
fn parse_timestamp(value: &str) -> Option<(i64, String, Option<i32>)> {
    let caps = TIMESTAMP_RE.captures(value)?;

    let year: i32 = caps.get(1)?.as_str().parse().ok()?;
    let month: u32 = caps.get(2)?.as_str().parse().ok()?;
    let day: u32 = caps.get(3)?.as_str().parse().ok()?;
    let hour: u32 = caps.get(4)?.as_str().parse().ok()?;
    let minute: u32 = caps.get(5)?.as_str().parse().ok()?;
    let second: u32 = caps.get(6)?.as_str().parse().ok()?;
    let millis = parse_fractional_millis(caps.get(7).map(|m| m.as_str()));

    let naive = chrono::NaiveDate::from_ymd_opt(year, month, day)
        .and_then(|date| date.and_hms_milli_opt(hour, minute, second, millis))?;

    let offset = match caps.get(8) {
        Some(value) => Some(parse_offset(value.as_str())?),
        None => None,
    };

    let timestamp = match offset {
        Some(minutes) => FixedOffset::east_opt(minutes.checked_mul(60)?)?
            .from_local_datetime(&naive)
            .single()?
            .timestamp_millis(),
        // A record without an offset is a zoneless wall clock; resolving it as
        // UTC is what put these rows hours away from their own text.
        None => super::local_wall_clock_millis(naive)?,
    };

    Some((
        timestamp,
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
            year, month, day, hour, minute, second, millis
        ),
        offset,
    ))
}

/// `+HHMM`, `+HH:MM`, or `Z`, as minutes east of UTC.
fn parse_offset(value: &str) -> Option<i32> {
    let trimmed = value.trim();
    if trimmed.eq_ignore_ascii_case("z") {
        return Some(0);
    }

    let (sign, rest) = match trimmed.as_bytes().first()? {
        b'+' => (1, &trimmed[1..]),
        b'-' => (-1, &trimmed[1..]),
        _ => return None,
    };
    let digits: String = rest
        .chars()
        .filter(|character| character.is_ascii_digit())
        .collect();
    if digits.len() != 4 {
        return None;
    }

    let hours: i32 = digits[..2].parse().ok()?;
    let minutes: i32 = digits[2..].parse().ok()?;
    Some(sign * (hours.checked_mul(60)? + minutes))
}

fn parse_fractional_millis(value: Option<&str>) -> u32 {
    match value {
        Some(raw) => {
            let padded = format!("{:0<3}", raw);
            padded[..3].parse::<u32>().unwrap_or(0)
        }
        None => 0,
    }
}

/// The event name without its brackets, or `None` for the `[(null)]` records
/// the agent writes when it has no name to report.
fn normalize_event_name(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    let without_brackets = trimmed
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(trimmed);

    normalize_field(without_brackets).filter(|name| !is_null_token(name))
}

/// The result code for display and the numeric value it stands for.
///
/// Real files write the code without the `0x` prefix (`240005` for
/// `0x00240005`), so the digits are read as hexadecimal and rendered in the form
/// the error database and message highlighting both expect. A zero code is
/// reported as absence; a value this parser cannot read is kept exactly as the
/// record wrote it rather than dropped.
fn parse_result_code(value: &str) -> Option<(String, Option<u32>)> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    let digits = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);

    match u32::from_str_radix(digits, 16) {
        Ok(0) => None,
        Ok(code) => Some((format!("0x{code:08X}"), Some(code))),
        Err(_) => Some((trimmed.to_string(), None)),
    }
}

#[allow(clippy::too_many_arguments)]
fn build_message(
    status: Option<&str>,
    event_name: Option<&str>,
    operation: Option<&str>,
    detail: &str,
    result_code: Option<&str>,
    update_guid: Option<&str>,
    event_id: Option<&str>,
) -> String {
    let mut parts = Vec::new();

    if let Some(status) = status {
        parts.push(status.to_string());
    }

    if let Some(event_name) = event_name {
        parts.push(event_name.to_string());
    }

    if let Some(operation) = operation {
        parts.push(operation.to_string());
    }

    if !detail.is_empty() {
        parts.push(detail.to_string());
    }

    if let Some(result_code) = result_code {
        parts.push(format!("HRESULT {result_code}"));
    }

    if let Some(event_id) = event_id {
        parts.push(format!("EventId {event_id}"));
    }

    if let Some(update_guid) = update_guid {
        parts.push(format!("Update {update_guid}"));
    }

    parts.join(" | ")
}

fn determine_severity(
    status: Option<&str>,
    event_name: Option<&str>,
    operation: Option<&str>,
    detail: &str,
    result_code: Option<u32>,
) -> Severity {
    // The status field is the agent's own verdict, so it outranks anything the
    // message text suggests.
    if let Some(status) = status {
        match status.trim().to_ascii_lowercase().as_str() {
            "success" => return Severity::Success,
            "failure" | "failed" | "error" => return Severity::Error,
            "warning" | "warn" => return Severity::Warning,
            _ => {}
        }
    }

    // An HRESULT with the severity bit set is a failure even when the status
    // field is missing or unhelpful. WU_S_* codes leave the bit clear, so an
    // outstanding restart stays what it is: a completed operation.
    if result_code.is_some_and(|code| code & 0x8000_0000 != 0) {
        return Severity::Error;
    }

    if event_name.is_some_and(|name| name.to_ascii_uppercase().contains("FAIL")) {
        return Severity::Error;
    }

    detect_severity_from_text(&[operation.unwrap_or(""), detail].join(" "))
}

fn normalize_field(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == "-" {
        None
    } else {
        Some(trimmed)
    }
}

fn is_null_token(value: &str) -> bool {
    value.trim().eq_ignore_ascii_case("(null)")
}

fn join_message_fields(fields: &[&str]) -> String {
    fields
        .iter()
        .map(|field| field.trim())
        .filter(|field| !field.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_placeholder_guid(value: &str) -> bool {
    value.eq_ignore_ascii_case("{00000000-0000-0000-0000-000000000000}")
}

fn fallback_entry(id: u64, line_number: u32, line: &str, file_path: &str) -> LogEntry {
    LogEntry {
        id,
        line_number,
        message: line.trim_end().to_string(),
        component: None,
        timestamp: None,
        timestamp_display: None,
        severity: detect_severity_from_text(line),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Real records carry the writing machine's offset and use either `.` or `:`
    /// before the millisecond group, and the agent appends an opaque token.
    const INSTALL_SUCCEEDED: &str = "{11111111-1111-1111-1111-111111111111}\t2024-01-15 08:00:00.123-0500\t1\t183\t[AGENT_INSTALLING_SUCCEEDED]\t101\t{22222222-2222-2222-2222-222222222222}\t1\t0\tWindows Update Agent\tSuccess\tContent Install\tInstallation Successful: Windows successfully installed the following update: Security Update (KB5034123)\tAAAAAAAAAAAAAAAA.1.0.0.3.0";
    const DOWNLOAD_FAILED: &str = "{33333333-3333-3333-3333-333333333333}\t2024-01-15 08:05:00:456-0500\t1\t162\t[AGENT_DOWNLOAD_FAILED]\t101\t{44444444-4444-4444-4444-444444444444}\t1\t80240022\tWindows Update Agent\tFailure\tContent Download\tDownload failed for KB5034441\tBBBBBBBBBBBBBBBB.1.0.0.5.1";
    const INSTALL_PENDING: &str = "{55555555-5555-5555-5555-555555555555}\t2024-01-15 08:10:00:789-0500\t1\t201\t[AGENT_INSTALLING_PENDING]\t101\t{66666666-6666-6666-6666-666666666666}\t1\t240005\tWindows Update Agent\tSuccess\tContent Install\tInstallation pending.\tCCCCCCCCCCCCCCCC.1.0.0.7.0";
    const PROGRESS_WITHOUT_TAIL: &str = "{77777777-7777-7777-7777-777777777777}\t2024-01-15 08:12:00.000-0500\t1\t170\t[(null)]\t101\t{88888888-8888-8888-8888-888888888888}\t0\t0\t(null)\tUnknown\tDDDDDDDDDDDDDDDD.1.0.0.8.1.0";

    #[test]
    fn test_matches_a_real_record_carrying_an_offset() {
        assert!(matches_reporting_events_record(INSTALL_SUCCEEDED));
        assert!(matches_reporting_events_record(DOWNLOAD_FAILED));
        assert!(!matches_reporting_events_record("plain text"));
    }

    #[test]
    fn test_parses_the_real_field_order_into_reader_facing_fields() {
        let (entries, parse_errors) = parse_lines(
            &[INSTALL_SUCCEEDED],
            "C:/Windows/SoftwareDistribution/ReportingEvents.log",
        );

        assert_eq!(parse_errors, 0);
        assert_eq!(entries.len(), 1);

        let entry = &entries[0];
        // The provider is the component, not an "event id" or category token.
        assert_eq!(entry.component.as_deref(), Some("Windows Update Agent"));
        assert_eq!(entry.operation_name.as_deref(), Some("Content Install"));
        // `183` is the event id and the event name carries the story.
        assert!(entry.message.contains("AGENT_INSTALLING_SUCCEEDED"));
        assert!(entry
            .message
            .contains("Installation Successful: Windows successfully installed"));
        assert!(entry.message.contains("EventId 183"));
        // The agent's token is not reader-facing text.
        assert!(!entry.message.contains("AAAAAAAAAAAAAAAA"));
        assert_eq!(entry.result_code, None);
        assert_eq!(entry.severity, Severity::Success);
    }

    #[test]
    fn test_timestamp_uses_the_offset_the_record_carried() {
        let (entries, _) = parse_lines(
            &[INSTALL_SUCCEEDED],
            "C:/Windows/SoftwareDistribution/ReportingEvents.log",
        );

        let entry = &entries[0];
        // 08:00:00.123 at -05:00 is 13:00:00.123 UTC.
        assert_eq!(entry.timezone_offset, Some(-300));
        assert_eq!(
            entry.timestamp_display.as_deref(),
            Some("2024-01-15 08:00:00.123")
        );
        assert_eq!(
            chrono::DateTime::from_timestamp_millis(entry.timestamp.expect("timestamp"))
                .expect("valid instant")
                .to_rfc3339(),
            "2024-01-15T13:00:00.123+00:00"
        );
    }

    #[test]
    fn test_display_matches_the_other_parsers_so_one_column_reads_alike() {
        let (entries, _) = parse_lines(
            &[DOWNLOAD_FAILED],
            "C:/Windows/SoftwareDistribution/ReportingEvents.log",
        );

        // `:` before the millisecond group is normalised to the `.` form the
        // Date/Time column already renders for every other log.
        assert_eq!(
            entries[0].timestamp_display.as_deref(),
            Some("2024-01-15 08:05:00.456")
        );
    }

    #[test]
    fn test_status_field_decides_severity() {
        let (entries, _) = parse_lines(
            &[INSTALL_SUCCEEDED, DOWNLOAD_FAILED, INSTALL_PENDING],
            "C:/Windows/SoftwareDistribution/ReportingEvents.log",
        );

        assert_eq!(entries[0].severity, Severity::Success);
        assert_eq!(entries[1].severity, Severity::Error);
        // WU_S_REBOOT_REQUIRED is a completed operation awaiting a restart, and
        // it stays visible as its own code rather than as a failure.
        assert_eq!(entries[2].severity, Severity::Success);
        assert_eq!(entries[2].result_code.as_deref(), Some("0x00240005"));
        assert!(entries[1].message.contains("HRESULT 0x80240022"));
    }

    #[test]
    fn test_a_record_without_an_operation_or_message_still_parses() {
        let (entries, parse_errors) = parse_lines(
            &[PROGRESS_WITHOUT_TAIL],
            "C:/Windows/SoftwareDistribution/ReportingEvents.log",
        );

        assert_eq!(parse_errors, 0);
        let entry = &entries[0];
        // `(null)` provider and `[(null)]` event name are absence, not text.
        assert_eq!(entry.component, None);
        assert_eq!(entry.operation_name, None);
        assert_eq!(entry.severity, Severity::Info);
        assert!(entry.message.contains("Unknown"));
    }

    #[test]
    fn test_parse_lines_keeps_fallback_for_malformed_rows() {
        let malformed = "{33333333-3333-3333-3333-333333333333}\tnot-a-timestamp\t1\t162\t[AGENT_DOWNLOAD_FAILED]\t101\t{44444444-4444-4444-4444-444444444444}\t1\t80240022\tWindows Update Agent\tFailure\tContent Download\tDownload failed for KB5034441";
        let warning = "{99999999-9999-9999-9999-999999999999}\t2024-01-15 08:15:00:000-0500\t1\t147\t[AGENT_DETECTION_FINISHED]\t101\t{00000000-0000-0000-0000-000000000000}\t0\t0\tWindows Update Agent\tWarning\tScan\tRetry required";

        let (entries, parse_errors) = parse_lines(
            &[INSTALL_SUCCEEDED, malformed, "orphan raw line", warning],
            "C:/Windows/SoftwareDistribution/ReportingEvents.log",
        );

        assert_eq!(parse_errors, 2);
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[1].message, malformed);
        assert_eq!(entries[2].message, "orphan raw line");
        assert_eq!(entries[3].severity, Severity::Warning);
        assert_eq!(entries[3].line_number, 4);
    }

    #[test]
    fn test_an_unreadable_result_code_is_kept_as_written() {
        // A value the parser cannot read as a code is still evidence, so it
        // reaches the record and the message verbatim instead of disappearing.
        let odd = "{33333333-3333-3333-3333-333333333333}\t2024-01-15 08:20:00.000-0500\t1\t162\t[AGENT_DOWNLOAD_FAILED]\t101\t{44444444-4444-4444-4444-444444444444}\t1\tnot-a-code\tWindows Update Agent\tFailure\tContent Download\tDownload failed.\tBBBBBBBBBBBBBBBB.1.0.0.5.1";

        let (entries, parse_errors) = parse_lines(
            &[odd],
            "C:/Windows/SoftwareDistribution/ReportingEvents.log",
        );

        assert_eq!(parse_errors, 0);
        assert_eq!(entries[0].result_code.as_deref(), Some("not-a-code"));
        assert!(entries[0].message.contains("HRESULT not-a-code"));
    }

    #[test]
    fn test_a_record_without_an_offset_is_not_promoted_to_utc() {
        let zoneless = "{11111111-1111-1111-1111-111111111111}\t2024-01-15 08:00:00.123\t1\t183\t[AGENT_INSTALLING_SUCCEEDED]\t101\t{22222222-2222-2222-2222-222222222222}\t1\t0\tWindows Update Agent\tSuccess\tContent Install\tInstalled.\tAAAAAAAAAAAAAAAA.1.0.0.3.0";

        let (entries, parse_errors) = parse_lines(
            &[zoneless],
            "C:/Windows/SoftwareDistribution/ReportingEvents.log",
        );

        assert_eq!(parse_errors, 0);
        assert_eq!(entries[0].timezone_offset, None);
        assert_eq!(
            entries[0].timestamp_display.as_deref(),
            Some("2024-01-15 08:00:00.123")
        );
        // The epoch renders back to the record's own text in local time, which
        // is what keeps the Date/Time column and the time range in agreement.
        let rendered = chrono::Local
            .timestamp_millis_opt(entries[0].timestamp.expect("timestamp"))
            .single()
            .expect("local instant");
        assert_eq!(
            rendered.naive_local().to_string(),
            "2024-01-15 08:00:00.123"
        );
    }
}
