//! Regression for https://github.com/adamgell/cmtraceopen/issues/413
//!
//! `regex`'s `\d` matches Unicode Nd. Byte-indexed slices of those captures
//! panic on multi-byte digit characters. This suite pins the public surface:
//! untrusted input must never crash the pure parser crate.

use cmtraceopen_parser::parser;

#[test]
fn public_parse_content_survives_non_ascii_ccm_time_tails() {
    let tails = ["١٢٣", "123١", "12١٢", "1234١"];
    for tail in tails {
        let content = format!(
            r#"<![LOG[NonASCII {tail}]LOG]!><time="10:00:00.{tail}" date="07-30-2026" component="PolicyAgent" context="" type="1" thread="42" file="policyagent.cpp">"#
        );
        let (result, _) = parser::parse_content(&content, "PolicyAgent.log", content.len() as u64);
        // No panic is the contract; a non-match is acceptable.
        let _ = result.entries;
    }
}

#[test]
fn public_parse_content_survives_non_ascii_timestamped_fraction() {
    let content = "14:30:00.١٢ starting work\n2024-01-15T14:30:00.123+०१:२३ offset line\n";
    let (result, _) = parser::parse_content(content, "app.log", content.len() as u64);
    let _ = result.entries;
}

#[test]
fn public_parse_content_survives_non_ascii_reporting_events_detection() {
    let guid = "{11111111-1111-1111-1111-111111111111}";
    let line = format!(
        "{guid}\t2024-01-15 08:00:00.١٢\t1\tSoftware Update\t1\t{{22222222-2222-2222-2222-222222222222}}\t0x00000000\tWindows Update Agent\tSuccess\tInstallation\tdetail"
    );
    let (result, _) = parser::parse_content(
        &line,
        "C:/Windows/SoftwareDistribution/ReportingEvents.log",
        line.len() as u64,
    );
    let _ = result.entries;
}

#[test]
fn public_parse_content_survives_non_ascii_simple_fraction() {
    let content = "message$$<Comp><1-1-2024 1:1:1.١٢+0><thread=1 (0x0001)>";
    let (result, _) = parser::parse_content(content, "simple.log", content.len() as u64);
    let _ = result.entries;
}
