//! Independently authored synthetic acceptance for #814. See fixtures/issue_814/README.md.
use cmtraceopen_parser::{
    models::log_entry::{ParseResult, ParserImplementation, Severity},
    parser,
};
const FIREWALL: &str = include_str!("fixtures/issue_814/firewall-local-18-fields.log");
const IIS: &str = include_str!("fixtures/issue_814/iis-w3c-control.log");
fn parse(s: &str) -> ParseResult {
    parser::parse_content(s, "invented.log", s.len() as u64).0
}
fn prefix(n: usize) -> String {
    FIREWALL.lines().take(5 + n).collect::<Vec<_>>().join("\n")
}
#[test]
fn firewall_short_files_detect_dedicated() {
    for n in 0..=3 {
        let result = parse(&prefix(n));
        assert_eq!(
            serde_json::to_value(result.parser_selection.implementation).unwrap(),
            "windowsFirewall"
        );
        assert_eq!(result.entries.len(), n);
        assert_eq!(result.parse_errors, 0);
    }
}
#[test]
fn firewall_rows_preserve_all_fields() {
    let result = parse(FIREWALL);
    for (entry, raw) in result.entries.iter().zip(FIREWALL.lines().skip(5)) {
        let fw = entry.firewall.as_ref().expect("dedicated firewall payload");
        assert_eq!(fw.raw_line, raw);
        assert_eq!(fw.fields.len(), 18);
        assert_eq!(
            fw.fields
                .iter()
                .map(|f| f.value.as_deref().unwrap())
                .collect::<Vec<_>>(),
            raw.split_whitespace().collect::<Vec<_>>()
        );
        assert_eq!(entry.severity, Severity::Info);
        assert!(entry.thread.is_none());
        assert!(entry.http_method.is_none());
        assert_ne!(entry.message, "- - → -");
    }
    assert_eq!(result.entries.len(), 3);
}
#[test]
fn firewall_local_time_has_no_epoch() {
    let result = parse(FIREWALL);
    for entry in &result.entries {
        assert_eq!(entry.timestamp, None);
        assert_eq!(entry.timezone_offset, None);
    }
    assert_eq!(
        result.entries[0].timestamp_display.as_deref(),
        Some("2042-04-05 06:07:09")
    );
}
#[test]
fn genuine_iis_remains_iis() {
    let result = parse(IIS);
    assert_eq!(
        result.parser_selection.implementation,
        ParserImplementation::IisW3c
    );
    assert_eq!(result.parse_errors, 0);
    assert_eq!(result.entries.len(), 3);
    assert!(result.entries[0].http_method.is_some());
}

#[test]
fn firewall_headerless_short_files_and_padding_use_normal_api() {
    for count in 1..=3 {
        let rows = FIREWALL
            .lines()
            .skip(5)
            .take(count)
            .collect::<Vec<_>>()
            .join("\n");
        for text in [
            rows.clone(),
            rows.lines()
                .map(|s| s.rsplit_once(' ').unwrap().0)
                .collect::<Vec<_>>()
                .join("\n"),
        ] {
            let result = parse(&text);
            assert_eq!(result.entries.len(), count);
            assert_eq!(result.parse_errors, 0);
            assert!(result
                .entries
                .iter()
                .all(|e| e.firewall.is_some() && e.timestamp.is_none()));
        }
    }
    for size in [1, 4096, 1024 * 1024] {
        let result = parse(&("\0".repeat(size) + FIREWALL));
        assert_eq!(result.entries.len(), 3);
        assert_eq!(result.firewall_coverage.unwrap().padding.count, size as u64);
        assert_eq!(result.parse_errors, 0);
    }
}
#[test]
fn firewall_payload_must_survive_normal_parser_api() {
    let result = parse(FIREWALL);
    assert_eq!(result.entries.len(), 3);
    assert!(result.entries[0].message.contains("192.0.2.11:54001"));
    assert!(result.entries[1].message.contains("[2001:db8:20::22]:53"));
}
#[test]
fn firewall_local_dst_shaped_strings_and_loss_rows_are_preserved() {
    let header = FIREWALL.lines().take(5).collect::<Vec<_>>().join("\n") + "\n";
    let first = FIREWALL.lines().nth(5).unwrap();
    for value in ["2042-03-30 02:30:00", "2042-10-26 01:30:00"] {
        let row = first.replace("2042-04-05 06:07:09", value);
        let r = parse(&(header.clone() + &row + "\n" + &row));
        assert!(r
            .entries
            .iter()
            .all(|e| e.timestamp.is_none() && e.timestamp_display.as_deref() == Some(value)));
    }
    let loss = "2042-04-05 06:07:13 INFO-EVENTS-LOST - - - - - - - - - - - - 23 -";
    let r = parse(&(header + loss));
    assert_eq!(r.parse_errors, 0);
    assert_eq!(r.entries[0].severity, Severity::Warning);
    assert_eq!(r.firewall_coverage.unwrap().lost_events.count, 23);
}
#[test]
fn firewall_meaningful_probe_crosses_old_twenty_line_limit_without_filename_guessing() {
    let r = parse(&("# invented preamble\n".repeat(20) + FIREWALL));
    assert_eq!(r.entries.len(), 3);
    assert_eq!(r.parse_errors, 0);
    assert!(r.entries[0].firewall.is_some());
    let unrelated =
        "2042-04-05 06:07:09 invented unrelated text\n2042-04-05 06:07:10 another message";
    let (r, _) = parser::parse_content(unrelated, "pfirewall.log", unrelated.len() as u64);
    assert!(r.entries.iter().all(|e| e.firewall.is_none()));
}
