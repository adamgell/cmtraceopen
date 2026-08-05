//! Regressions for https://github.com/adamgell/cmtraceopen/issues/413.
//!
//! Rust regex `\d` includes Unicode decimal digits. These log grammars only
//! accept ASCII digits, and several parsers slice captured numeric fields by
//! byte offset. Malformed input must be rejected or preserved as text, never
//! panic.

use cmtraceopen_parser::{
    intune::{event_tracker, guid_registry::GuidRegistry, ime_parser},
    parser,
};

fn parse(content: &str, path: &str) {
    let (result, _) = parser::parse_content(content, path, content.len() as u64);
    let _ = result.entries;
}

#[test]
fn public_log_parsers_reject_unicode_decimal_fields_without_panicking() {
    parse("14:30:00.١٢ timestamped", "timestamped.log");
    parse(
        "message$$<Component><01-15-2024 14:30:00.١٢+000><thread=42>",
        "simple.log",
    );
    parse(
        r#"<![LOG[Unicode decimal tail]LOG]!><time="14:30:00.12١" date="01-15-2024" component="Component" context="" type="1" thread="42" file="example.cpp">"#,
        "example.log",
    );
}

#[test]
fn reporting_events_detection_rejects_unicode_decimal_fraction_without_panicking() {
    let line = concat!(
        "{11111111-1111-1111-1111-111111111111}\t",
        "2024-01-15 08:00:00.١٢\t1\tSoftware Update\t1\t",
        "{22222222-2222-2222-2222-222222222222}\t0x00000000\t",
        "Windows Update Agent\tSuccess\tInstallation\tdetail"
    );

    assert!(!parser::reporting_events::matches_reporting_events_record(
        line
    ));
    parse(line, "C:/Windows/SoftwareDistribution/ReportingEvents.log");
}

#[test]
fn dns_wire_names_handle_unicode_text_and_mid_character_lengths_without_panicking() {
    assert_eq!(parser::dns_types::decode_query_name("é(1)a"), "a");
    assert_eq!(parser::dns_types::decode_query_name("(1)é"), "");
}

#[test]
fn intune_event_tracking_rejects_unicode_decimal_values_without_panicking() {
    let content = r#"<![LOG[Computing delta inventory...Done. Add count = ١, Modify count = ٢, Delete count = ٣]LOG]!><time="14:30:00.123+000" date="01-15-2024" component="IntuneManagementExtension" context="" type="1" thread="42" file="example.cpp">"#;
    let lines = ime_parser::parse_ime_content(content);
    let _ = event_tracker::extract_events(
        &lines,
        "C:/Logs/Win32AppInventory.log",
        &GuidRegistry::new(),
    );
}
