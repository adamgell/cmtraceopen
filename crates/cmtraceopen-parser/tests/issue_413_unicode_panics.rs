//! Regressions for https://github.com/adamgell/cmtraceopen/issues/413.
//!
//! Rust regex `\d` includes Unicode decimal digits. These log grammars only
//! accept ASCII digits, and several parsers slice captured numeric fields by
//! byte offset. Malformed input must be rejected or preserved as text, never
//! promoted to a fabricated structured timestamp.

use cmtraceopen_parser::{
    intune::{event_tracker, guid_registry::GuidRegistry, ime_parser},
    models::log_entry::{LogFormat, ParseResult, ParserImplementation},
    parser::{self, ResolvedParser},
};

fn parse(content: &str, path: &str) -> (ParseResult, ResolvedParser) {
    parser::parse_content(content, path, content.len() as u64)
}

fn assert_preserved_without_timestamp(
    entry: &cmtraceopen_parser::models::log_entry::LogEntry,
    raw: &str,
) {
    assert_eq!(entry.message, raw);
    assert_eq!(entry.timestamp, None);
    assert_eq!(entry.timestamp_display, None);
    assert_eq!(entry.component, None);
}

#[test]
fn timestamped_parser_preserves_invalid_digits_and_valid_unicode_payload() {
    let valid = [
        "14:30:00.123 Café structured ✓",
        "14:30:01.456 Résumé structured",
    ];
    let invalid = "14:30:00.١٢ 日本語 payload";
    let content = format!("{}\n{}\n{invalid}", valid[0], valid[1]);
    let (result, selection) = parse(&content, "timestamped.log");

    assert_eq!(
        selection.implementation,
        ParserImplementation::GenericTimestamped
    );
    assert_eq!(result.parse_errors, 1);
    assert_eq!(result.entries.len(), 3);
    assert_eq!(result.entries[0].format, LogFormat::Timestamped);
    assert_eq!(result.entries[0].message, "Café structured ✓");
    assert!(result.entries[0].timestamp_display.is_some());
    assert_eq!(result.entries[1].message, "Résumé structured");
    assert_eq!(result.entries[2].format, LogFormat::Timestamped);
    assert_preserved_without_timestamp(&result.entries[2], invalid);
}

#[test]
fn simple_parser_preserves_invalid_digits_and_valid_unicode_payload() {
    let valid = "Café structured ✓$$<Component><01-15-2024 14:30:00.123+000><thread=42>";
    let invalid = "日本語 payload$$<Component><01-15-2024 14:30:00.١٢+000><thread=42>";
    let content = format!("{valid}\n{invalid}");
    let (result, selection) = parse(&content, "simple.log");

    assert_eq!(selection.implementation, ParserImplementation::Simple);
    assert_eq!(result.parse_errors, 1);
    assert_eq!(result.entries.len(), 2);
    assert_eq!(result.entries[0].format, LogFormat::Simple);
    assert_eq!(result.entries[0].message, "Café structured ✓");
    assert!(result.entries[0].timestamp_display.is_some());
    assert_eq!(result.entries[1].format, LogFormat::Plain);
    assert_preserved_without_timestamp(&result.entries[1], invalid);
}

#[test]
fn ccm_parser_preserves_invalid_digits_and_valid_unicode_payload() {
    let valid = r#"<![LOG[Café structured ✓]LOG]!><time="14:30:00.123+000" date="01-15-2024" component="Component" context="" type="1" thread="42" file="example.cpp">"#;
    let invalid = r#"<![LOG[日本語 payload]LOG]!><time="14:30:00.12١" date="01-15-2024" component="Component" context="" type="1" thread="42" file="example.cpp">"#;
    let content = format!("{valid}\n{invalid}");
    let (result, selection) = parse(&content, "example.log");

    assert_eq!(selection.implementation, ParserImplementation::Ccm);
    assert!(result.parse_errors >= 1);
    let structured = result
        .entries
        .iter()
        .find(|entry| entry.format == LogFormat::Ccm)
        .expect("valid CCM record remains structured");
    assert_eq!(structured.message, "Café structured ✓");
    assert!(structured.timestamp_display.is_some());
    let preserved = result
        .entries
        .iter()
        .find(|entry| entry.message == invalid)
        .expect("invalid CCM record survives verbatim");
    assert_eq!(preserved.format, LogFormat::Plain);
    assert_preserved_without_timestamp(preserved, invalid);
}

#[test]
fn cmtlog_parser_preserves_invalid_digits_and_valid_unicode_payload() {
    let valid = r##"<![LOG[Café header ✓]LOG]!><time="14:30:00.123+000" date="01-15-2024" component="__HEADER__" context="" type="1" thread="42" file="example.ps1" color="#123456">"##;
    let invalid = r##"<![LOG[日本語 payload]LOG]!><time="14:30:00.١٢+000" date="01-15-2024" component="__HEADER__" context="" type="1" thread="42" file="example.ps1" color="#123456">"##;
    let content = format!("{valid}\n{invalid}");
    let (result, selection) = parse(&content, "example.log");

    assert_eq!(selection.implementation, ParserImplementation::CmtLog);
    assert_eq!(result.parse_errors, 1);
    assert_eq!(result.entries.len(), 2);
    assert_eq!(result.entries[0].format, LogFormat::CmtLog);
    assert_eq!(result.entries[0].message, "Café header ✓");
    assert!(result.entries[0].timestamp_display.is_some());
    assert_eq!(result.entries[1].format, LogFormat::CmtLog);
    assert_preserved_without_timestamp(&result.entries[1], invalid);
}

fn reporting_events_line(timestamp: &str, detail: &str) -> String {
    format!(
        "{{11111111-1111-1111-1111-111111111111}}\t{timestamp}\t1\tSoftware Update\t1\t{{22222222-2222-2222-2222-222222222222}}\t0x00000000\tWindows Update Agent\tSuccess\tInstallation\t{detail}"
    )
}

#[test]
fn reporting_events_detection_and_parser_preserve_invalid_digits_and_unicode_payload() {
    let invalid = reporting_events_line("2024-01-15 08:00:00.١٢", "日本語 payload");
    assert!(!parser::reporting_events::matches_reporting_events_record(
        &invalid
    ));
    let (invalid_only, invalid_selection) = parse(
        &invalid,
        "C:/Windows/SoftwareDistribution/ReportingEvents.log",
    );
    assert_eq!(
        invalid_selection.implementation,
        ParserImplementation::PlainText
    );
    assert_eq!(invalid_only.entries.len(), 1);
    assert_eq!(invalid_only.entries[0].format, LogFormat::Plain);
    assert_preserved_without_timestamp(&invalid_only.entries[0], &invalid);

    let valid = reporting_events_line("2024-01-15 08:00:00.123", "Café detail ✓");
    let content = format!("{valid}\n{invalid}");
    let (result, selection) = parse(
        &content,
        "C:/Windows/SoftwareDistribution/ReportingEvents.log",
    );
    assert_eq!(
        selection.implementation,
        ParserImplementation::ReportingEvents
    );
    assert_eq!(result.parse_errors, 1);
    assert_eq!(result.entries.len(), 2);
    assert!(result.entries[0].message.contains("Café detail ✓"));
    assert!(result.entries[0].timestamp_display.is_some());
    assert_eq!(result.entries[1].format, LogFormat::Timestamped);
    assert_preserved_without_timestamp(&result.entries[1], &invalid);
}

#[test]
fn dns_wire_names_preserve_valid_unicode_and_reject_mid_character_lengths() {
    assert_eq!(parser::dns_types::decode_query_name("(2)é(1)a"), "é.a");
    assert_eq!(parser::dns_types::decode_query_name("é(1)a"), "a");
    assert_eq!(parser::dns_types::decode_query_name("(1)é"), "");
}

#[test]
fn intune_event_tracking_preserves_unicode_payload_and_rejects_unicode_counts() {
    let valid = r#"<![LOG[Computing delta inventory...Done. Add count = 2, Modify count = 0, Delete count = 2 — Café ✓]LOG]!><time="14:30:00.123+000" date="01-15-2024" component="IntuneManagementExtension" context="" type="1" thread="42" file="example.cpp">"#;
    let invalid = r#"<![LOG[Computing delta inventory...Done. Add count = ١, Modify count = ٢, Delete count = ٣ — 日本語 payload]LOG]!><time="14:30:01.123+000" date="01-15-2024" component="IntuneManagementExtension" context="" type="1" thread="42" file="example.cpp">"#;
    let content = format!("{valid}\n{invalid}");
    let lines = ime_parser::parse_ime_content(&content);
    let events = event_tracker::extract_events(
        &lines,
        "C:/Logs/Win32AppInventory.log",
        &GuidRegistry::new(),
    );

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].name, "Win32AppInventory Delta (+2 ~0 -2)");
    assert!(events[0].detail.contains("Café ✓"));
    assert!(!events[0].detail.contains("日本語 payload"));
}
