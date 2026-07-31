//! `LogEntry` projection for the log viewer.
//!
//! This is the local-rendering path, so message text is never redacted here —
//! the viewer has to show the file the user opened. Export/evidence callers use
//! `parse_log_document`, which redacts by default.
//!
//! # Field mapping
//!
//! `LogEntry` has no column for a record category, scenario, sequence, or
//! activity id, and forcing them into unrelated columns (`thread`,
//! `operationName`, …) would assert semantics the evidence does not support.
//! Those fields therefore live in [`super::CompanyPortalLogRecord`] only, and
//! the viewer entry carries the four things it does have columns for:
//! timestamp, severity, component, and message.

use chrono::DateTime;

use super::framing::{frame_records, join_lines, FramedRecord, FramedRecordKind};
use super::grammar::CompanyPortalRecordFields;
use super::models::CompanyPortalSeverityLevel;
use crate::models::log_entry::{LogEntry, LogFormat, Severity};
use crate::parser::severity::detect_severity_from_text;

/// Parse lines already framed by the pipeline as Company Portal Windows logs.
pub fn parse_lines(lines: &[&str], file_path: &str) -> (Vec<LogEntry>, u32) {
    let framed = frame_records(lines);
    let mut entries = Vec::with_capacity(framed.len());
    let mut parse_errors: u32 = 0;

    for (id, record) in framed.iter().enumerate() {
        if record.is_parse_error() {
            parse_errors += 1;
        }
        entries.push(build_entry(id as u64, record, file_path));
    }

    (entries, parse_errors)
}

fn build_entry(id: u64, framed: &FramedRecord<'_>, file_path: &str) -> LogEntry {
    match &framed.kind {
        FramedRecordKind::Record(fields) => parsed_entry(id, framed, fields, file_path),
        // Nothing validated, so nothing is claimed: the record's original text
        // becomes the message and the derived columns stay empty.
        FramedRecordKind::Malformed | FramedRecordKind::Orphaned => {
            let message = framed.raw_text();
            let severity = detect_severity_from_text(&message);
            empty_entry(
                id,
                framed.line_number,
                message,
                LogFormat::Plain,
                severity,
                file_path,
            )
        }
    }
}

fn parsed_entry(
    id: u64,
    framed: &FramedRecord<'_>,
    fields: &CompanyPortalRecordFields,
    file_path: &str,
) -> LogEntry {
    let message = join_lines(&fields.message, &framed.continuations);

    let mut entry = empty_entry(
        id,
        framed.line_number,
        message,
        LogFormat::Timestamped,
        Severity::Info,
        file_path,
    );

    // A present, known severity token always wins; an unrecognized token is the
    // only case that defers to keyword inference on the message.
    entry.severity = match fields.severity.level {
        CompanyPortalSeverityLevel::Verbose | CompanyPortalSeverityLevel::Information => {
            Severity::Info
        }
        CompanyPortalSeverityLevel::Warning => Severity::Warning,
        CompanyPortalSeverityLevel::Error | CompanyPortalSeverityLevel::Critical => Severity::Error,
        CompanyPortalSeverityLevel::Unknown => detect_severity_from_text(&entry.message),
    };

    // The leading `[Component Name]` is the emitting component and is far more
    // useful than the category token; the category is the fallback when the
    // message does not open with a bracket. The bracket stays in the message —
    // stripping it could not be reversed exactly, and messages must stay
    // lossless.
    entry.component = Some(
        fields
            .component
            .clone()
            .unwrap_or_else(|| fields.category.clone()),
    );

    if let Ok(parsed) = DateTime::parse_from_rfc3339(&fields.timestamp.raw_text) {
        entry.timestamp = Some(parsed.timestamp_millis());
        let utc = parsed.naive_utc();
        // Millisecond display precision matches every other parser's column;
        // the full 100 ns tick is kept in the evidence document.
        entry.timestamp_display = Some(utc.format("%Y-%m-%d %H:%M:%S%.3f").to_string());
        // Field 1 always carries a trailing `Z`.
        entry.timezone_offset = Some(0);
    }

    entry
}

fn empty_entry(
    id: u64,
    line_number: u32,
    message: String,
    format: LogFormat,
    severity: Severity,
    file_path: &str,
) -> LogEntry {
    LogEntry {
        id,
        line_number,
        message,
        component: None,
        timestamp: None,
        timestamp_display: None,
        severity,
        thread: None,
        thread_display: None,
        source_file: None,
        format,
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

    const FILE: &str = "Log_1.log";

    fn record(severity: &str, message: &str) -> String {
        format!(
            "2024-11-15T16:50:07.2850341Z  {severity}  Event  None  0  \
             1487dc30-3bb0-46bf-98ee-76771bd9953e  12-0-0  {message}"
        )
    }

    #[test]
    fn dedicated_severity_beats_keyword_inference() {
        // "failed" would infer Error, but the record says INFO.
        let line = record("INFO", "[Sync] the previous attempt failed and was retried");
        let (entries, errors) = parse_lines(&[&line], FILE);

        assert_eq!(errors, 0);
        assert_eq!(entries[0].severity, Severity::Info);
    }

    #[test]
    fn every_known_severity_token_maps_to_a_level() {
        for (token, expected) in [
            ("VERBOSE", Severity::Info),
            ("DEBUG", Severity::Info),
            ("INFO", Severity::Info),
            ("WARN", Severity::Warning),
            ("WARNING", Severity::Warning),
            ("ERROR", Severity::Error),
            ("CRITICAL", Severity::Error),
            ("FATAL", Severity::Error),
        ] {
            let line = record(token, "[Sync] state change");
            let (entries, _) = parse_lines(&[&line], FILE);
            assert_eq!(entries[0].severity, expected, "{token}");
        }
    }

    #[test]
    fn unknown_severity_token_falls_back_to_keyword_inference() {
        let line = record("NOTICE", "[Sync] the request failed");
        let (entries, errors) = parse_lines(&[&line], FILE);

        assert_eq!(errors, 0);
        assert_eq!(entries[0].severity, Severity::Error);
    }

    #[test]
    fn component_prefers_the_bracket_and_falls_back_to_the_category() {
        let bracketed = record("INFO", "[Configuration Manager Trace Listener] querying");
        let (entries, _) = parse_lines(&[&bracketed], FILE);
        assert_eq!(
            entries[0].component.as_deref(),
            Some("Configuration Manager Trace Listener")
        );

        let bare = record("INFO", "querying without a bracket");
        let (entries, _) = parse_lines(&[&bare], FILE);
        assert_eq!(entries[0].component.as_deref(), Some("Event"));
    }

    #[test]
    fn timestamp_is_read_as_utc_with_millisecond_display() {
        let line = record("INFO", "[Sync] started");
        let (entries, _) = parse_lines(&[&line], FILE);

        assert_eq!(
            entries[0].timestamp_display.as_deref(),
            Some("2024-11-15 16:50:07.285")
        );
        assert_eq!(entries[0].timezone_offset, Some(0));
        assert_eq!(
            entries[0].timestamp,
            Some(
                DateTime::parse_from_rfc3339("2024-11-15T16:50:07.2850341Z")
                    .unwrap()
                    .timestamp_millis()
            )
        );
    }

    #[test]
    fn thread_is_never_derived_from_the_sequence_field() {
        let line = "2024-11-15T16:50:07.2850341Z  INFO  Event  None  4271  1487dc30-3bb0-46bf-98ee-76771bd9953e  12-0-0  [Sync] started";
        let (entries, _) = parse_lines(&[line], FILE);

        assert_eq!(entries[0].thread, None);
        assert_eq!(entries[0].thread_display, None);
    }

    #[test]
    fn a_malformed_record_is_preserved_verbatim_as_a_parse_error() {
        let line = "2024-13-45T99:99:99.0000000Z  INFO  Event  None  0  1487dc30-3bb0-46bf-98ee-76771bd9953e  12-0-0  impossible instant";
        let (entries, errors) = parse_lines(&[line], FILE);

        assert_eq!(errors, 1);
        assert_eq!(entries[0].message, line);
        assert_eq!(entries[0].format, LogFormat::Plain);
        assert!(entries[0].timestamp.is_none());
        assert!(entries[0].timestamp_display.is_none());
        assert!(entries[0].component.is_none());
    }

    #[test]
    fn continuation_lines_join_the_record_and_line_numbers_stay_on_the_head() {
        let head = record("ERROR", "[Install] request rejected");
        let lines = vec![
            head.as_str(),
            "System.Net.Http.HttpRequestException: 403",
            "   at Microsoft.Management.Services.PortalClient.SendAsync()",
        ];
        let (entries, errors) = parse_lines(&lines, FILE);

        assert_eq!(errors, 0);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].line_number, 1);
        assert_eq!(
            entries[0].message,
            "[Install] request rejected\nSystem.Net.Http.HttpRequestException: 403\n   at Microsoft.Management.Services.PortalClient.SendAsync()"
        );
    }

    #[test]
    fn entry_ids_are_contiguous_across_mixed_records() {
        let good = record("INFO", "[Sync] ok");
        let lines = vec![
            "orphaned tail of a rotated file",
            good.as_str(),
            "2024-13-45T99:99:99.0000000Z  INFO  Event  None  0  1487dc30-3bb0-46bf-98ee-76771bd9953e  12-0-0  bad",
        ];
        let (entries, errors) = parse_lines(&lines, FILE);

        assert_eq!(errors, 2);
        assert_eq!(
            entries.iter().map(|entry| entry.id).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.line_number)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }
}
