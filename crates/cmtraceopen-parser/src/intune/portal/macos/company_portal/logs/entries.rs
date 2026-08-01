//! `LogEntry` projection of direct Company Portal application logs.
//!
//! The viewer consumes [`LogEntry`], so a dedicated parser has to produce one
//! per logical record. The signature mirrors every other parser in this
//! repository — `(entries, parse_error_count)` — so this can be wired into
//! `crate::parser` without a bespoke call shape.
//!
//! One record is one entry, continuations included. An exception trace stays
//! attached to the line that raised it rather than becoming four unattributed
//! plain-text rows, which is the whole point of logical framing.

use crate::models::log_entry::{LogEntry, LogFormat, Severity};

use super::grammar::{frame_records, FramedRecord};
use super::models::CompanyPortalSeverity;

/// Map a structural severity to the viewer's severity.
///
/// Verbose and debug collapse into `Info` because [`Severity`] has no quieter
/// level; the original token is still available on the record in
/// [`super::CompanyPortalLogRecord::severity_token`], so nothing is lost.
fn viewer_severity(severity: &CompanyPortalSeverity) -> Severity {
    match severity {
        CompanyPortalSeverity::Verbose
        | CompanyPortalSeverity::Debug
        | CompanyPortalSeverity::Info => Severity::Info,
        CompanyPortalSeverity::Warning => Severity::Warning,
        CompanyPortalSeverity::Error | CompanyPortalSeverity::Fatal => Severity::Error,
        // An unrecognized token is not evidence of a failure. Guessing from the
        // message text here would contradict the structural field the record
        // actually carries.
        CompanyPortalSeverity::Unknown(_) => Severity::Info,
    }
}

/// Parse already-split lines as direct Company Portal application log records.
///
/// Returns the entries and the number of records this build could not
/// decompose. A record it could not read is still emitted, carrying its exact
/// source text, so nothing disappears from the viewer.
pub fn parse_lines(lines: &[&str], file_path: &str) -> (Vec<LogEntry>, u32) {
    parse_content(&lines.join("\n"), file_path)
}

/// Parse whole artifact text as direct Company Portal application log records.
pub fn parse_content(content: &str, file_path: &str) -> (Vec<LogEntry>, u32) {
    let framed = frame_records(content);
    let mut entries = Vec::with_capacity(framed.len());
    let mut parse_errors = 0u32;

    for (index, record) in framed.iter().enumerate() {
        entries.push(entry_from_framed(record, index as u64, file_path));
        if !record.is_recognized() {
            parse_errors += 1;
        }
    }

    (entries, parse_errors)
}

fn entry_from_framed(record: &FramedRecord, id: u64, file_path: &str) -> LogEntry {
    let mut entry = blank_entry(id, record.line_number as u32, file_path);
    entry.message = record.message();

    let Some(fields) = &record.fields else {
        entry.format = LogFormat::Plain;
        entry.severity = crate::parser::severity::detect_severity_from_text(&entry.message);
        return entry;
    };

    let timestamp = &fields.timestamp;
    entry.component = Some(fields.process.clone());
    entry.source_file = Some(fields.subsystem.clone());
    entry.thread = fields.thread_token.parse().ok();
    entry.thread_display = entry.thread.map(crate::parser::ccm::format_thread_display);
    entry.severity = CompanyPortalSeverity::from_token(&fields.severity_token)
        .as_ref()
        .map_or(Severity::Info, viewer_severity);
    entry.timezone_offset = timestamp.offset_minutes;

    // The viewer sorts on `timestamp`, so every entry needs one even when the
    // record stated no offset. The honest, offset-only normalization lives on
    // the observation in `super::reducer`; this field is a sort key, not a
    // claim about the record's timezone.
    let naive = chrono::NaiveDate::from_ymd_opt(timestamp.year, timestamp.month, timestamp.day)
        .and_then(|date| {
            date.and_hms_milli_opt(
                timestamp.hour,
                timestamp.minute,
                timestamp.second,
                timestamp.millisecond,
            )
        });
    entry.timestamp = naive.map(|value| {
        let offset = i64::from(timestamp.offset_minutes.unwrap_or(0));
        (value - chrono::Duration::minutes(offset))
            .and_utc()
            .timestamp_millis()
    });
    entry.timestamp_display = naive.map(|value| value.format("%Y-%m-%d %H:%M:%S%.3f").to_string());

    entry
}

fn blank_entry(id: u64, line_number: u32, file_path: &str) -> LogEntry {
    LogEntry {
        id,
        line_number,
        message: String::new(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_basic_record_projects_every_structural_field() {
        let (entries, errors) = parse_content(
            "2026-03-12 09:14:22:301 | CompanyPortal | W | 8412 | Catalog | retrying\n",
            "CompanyPortal.log",
        );
        assert_eq!(errors, 0);
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.component.as_deref(), Some("CompanyPortal"));
        assert_eq!(entry.source_file.as_deref(), Some("Catalog"));
        assert_eq!(entry.severity, Severity::Warning);
        assert_eq!(entry.thread, Some(8412));
        assert_eq!(entry.message, "retrying");
        assert_eq!(
            entry.timestamp_display.as_deref(),
            Some("2026-03-12 09:14:22.301")
        );
        assert_eq!(entry.line_number, 1);
    }

    #[test]
    fn a_multiline_record_is_one_entry() {
        let (entries, errors) = parse_content(
            concat!(
                "2026-03-12 09:14:22:301 | CompanyPortal | E | 1 | Catalog | install failed\n",
                "Domain=CPError Code=42\n",
                "  at CompanyPortal.Catalog.install()\n",
            ),
            "CompanyPortal.log",
        );
        assert_eq!(errors, 0);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].message.contains("Domain=CPError Code=42"));
        assert!(entries[0]
            .message
            .contains("at CompanyPortal.Catalog.install()"));
    }

    #[test]
    fn an_offset_shifts_the_sort_key_and_is_reported() {
        let (with_offset, _) = parse_content(
            "2026-03-12 09:14:22:301-0700 | CompanyPortal | I | 1 | Catalog | x\n",
            "CompanyPortal.log",
        );
        let (without_offset, _) = parse_content(
            "2026-03-12 09:14:22:301 | CompanyPortal | I | 1 | Catalog | x\n",
            "CompanyPortal.log",
        );
        assert_eq!(with_offset[0].timezone_offset, Some(-420));
        assert_eq!(without_offset[0].timezone_offset, None);
        assert_eq!(
            with_offset[0].timestamp.unwrap() - without_offset[0].timestamp.unwrap(),
            7 * 60 * 60 * 1000
        );
    }

    #[test]
    fn an_unreadable_record_is_counted_but_still_shown_in_full() {
        let (entries, errors) = parse_content(
            concat!(
                "2026-03-12 09:14:22:301 | CompanyPortal | I | 1 | Catalog | good\n",
                "2026-03-12 09:14:23:000 | CompanyPortal | I\n",
            ),
            "CompanyPortal.log",
        );
        assert_eq!(errors, 1);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].format, LogFormat::Plain);
        assert_eq!(
            entries[1].message,
            "2026-03-12 09:14:23:000 | CompanyPortal | I"
        );
    }

    #[test]
    fn the_line_based_and_content_based_entry_points_agree() {
        let lines = [
            "2026-03-12 09:14:22:301 | CompanyPortal | I | 1 | Catalog | a",
            "2026-03-12 09:14:23:000 | CompanyPortal | I | 1 | Catalog | b",
        ];
        let (from_lines, _) = parse_lines(&lines, "CompanyPortal.log");
        let (from_content, _) = parse_content(&lines.join("\n"), "CompanyPortal.log");
        assert_eq!(from_lines.len(), from_content.len());
        assert_eq!(from_lines[1].message, from_content[1].message);
    }

    #[test]
    fn an_unrecognized_severity_token_does_not_become_an_error() {
        let (entries, errors) = parse_content(
            "2026-03-12 09:14:22:301 | CompanyPortal | N | 1 | Catalog | failed to reach service\n",
            "CompanyPortal.log",
        );
        assert_eq!(errors, 0);
        assert_eq!(entries[0].severity, Severity::Info);
    }
}
