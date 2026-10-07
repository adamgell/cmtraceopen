use cmtraceopen_parser::{
    models::{firewall::*, log_entry::Severity},
    parser::windows_firewall::*,
};
const FIXTURE: &str = include_str!("fixtures/issue_814/firewall-local-18-fields.log");
fn row() -> &'static str {
    FIXTURE.lines().nth(5).unwrap()
}
fn context() -> FirewallContext {
    let mut c = FirewallContext::default();
    for l in FIXTURE.lines().take(5) {
        c.directive(l);
    }
    c
}
#[test]
fn firewall_probe_is_distinct_and_bounded() {
    assert!(probe(FIXTURE));
    assert!(probe(row()));
    assert!(probe("#sOfTwArE: Microsoft Windows Firewall"));
    assert!(!probe(include_str!(
        "fixtures/issue_814/iis-w3c-control.log"
    )));
    assert!(!probe("2042-04-05 06:07:09 unrelated arbitrary payload"));
    assert!(!probe(&row().replace("192.0.2.11", "not-an-ip")));
    assert!(probe(&format!("{}{}", "preamble\n".repeat(20), row())));
    assert!(probe(&format!("{}{}", "preamble\n".repeat(127), row())));
    assert!(!probe(&format!("{}{}", "preamble\n".repeat(128), row())));
    assert!(probe(&format!("{}{}", "\0".repeat(1024 * 1024), row())));
    assert!(!probe(&format!("{}\n{}", "x".repeat(65_536), row())));
}
#[test]
fn firewall_schema_replaces_invalidates_and_resets() {
    let mut c = context();
    let r = parse_record(row(), &c, 0, 6, "synthetic.log");
    assert_eq!(
        r.entry.firewall.as_ref().unwrap().field("src-ip"),
        Some("192.0.2.11")
    );
    c.directive("#Fields: action time date future");
    let r = parse_record(
        "OBSERVE 01:02:03 2042-03-04 Invented",
        &c,
        1,
        8,
        "synthetic.log",
    );
    let f = r.entry.firewall.unwrap();
    assert_eq!(f.field("future"), Some("Invented"));
    assert_eq!(f.declared_fields, vec!["action", "time", "date", "future"]);
    c.directive("#Fields: action action");
    assert!(c.declared_fields.is_none());
    assert_eq!(
        parse_record("OBSERVE x", &c, 2, 10, "")
            .entry
            .firewall
            .unwrap()
            .record_kind,
        FirewallRecordKind::Malformed
    );
    c.directive("#Time Format: UTC");
    assert_eq!(c.time_basis, FirewallTimeBasis::Utc);
    c.directive("#Software: Microsoft Windows Firewall");
    assert_eq!(c.time_basis, FirewallTimeBasis::Unknown);
    assert!(c.declared_fields.is_none());
}
#[test]
fn firewall_arity_loss_and_missing_pid_are_unambiguous() {
    let c = context();
    let loss = "2042-04-05 06:07:13 INFO-EVENTS-LOST - - - - - - - - - - - - 23 -";
    let r = parse_record(loss, &c, 0, 1, "");
    assert_eq!(r.entry.severity, Severity::Warning);
    assert_eq!(r.coverage.lost_events.count, 23);
    assert_eq!(r.entry.firewall.unwrap().fields.last().unwrap().value, None);
    assert_eq!(r.coverage.parse_errors(), 0);
    let short = row().rsplit_once(' ').unwrap().0;
    assert_eq!(parse_record(short, &c, 0, 1, "").coverage.parse_errors(), 1);
    assert_eq!(
        parse_record(short, &FirewallContext::default(), 0, 1, "")
            .entry
            .firewall
            .unwrap()
            .schema_origin,
        FirewallSchemaOrigin::Canonical
    );
    for value in ["-", "nonsense", "18446744073709551616"] {
        let r = parse_record(&loss.replace(" 23 ", &format!(" {value} ")), &c, 0, 1, "");
        assert_eq!(r.coverage.unknown_loss_count.count, 1);
        assert_eq!(r.coverage.parse_errors(), 0);
    }
}
#[test]
fn firewall_preserves_local_unknown_invalid_and_utc_time() {
    let mut c = context();
    for directive in ["Local", "invented-zone"] {
        c.directive(&format!("#Time Format: {directive}"));
        let r = parse_record(row(), &c, 0, 1, "");
        assert_eq!(r.entry.timestamp, None);
        assert_eq!(r.entry.timezone_offset, None);
        assert_eq!(
            r.entry.timestamp_display.as_deref(),
            Some("2042-04-05 06:07:09")
        );
    }
    c.directive("#Time Format: UTC");
    let epoch = row().replace("2042-04-05 06:07:09", "1970-01-01 00:00:00");
    let r = parse_record(&epoch, &c, 0, 1, "");
    assert_eq!(r.entry.timestamp, Some(0));
    assert_eq!(r.entry.timezone_offset, Some(0));
    let invalid = row().replace("2042-04-05", "2042-99-99");
    let r = parse_record(&invalid, &c, 0, 1, "");
    assert_eq!(r.entry.timestamp, None);
    assert!(r.entry.timestamp_display.unwrap().starts_with("2042-99-99"));
}
#[test]
fn firewall_protocols_endpoints_and_unknowns_preserve_original_values() {
    let c = context();
    for raw in FIXTURE.lines().skip(5).chain(std::iter::once(
        "2042-04-05 06:07:12 ALLOW 47 198.51.100.51 203.0.113.61 - - 44 - - - - - - - SEND 8801",
    )) {
        let r = parse_record(raw, &c, 0, 1, "");
        assert_eq!(r.entry.severity, Severity::Info);
        assert!(r.entry.thread.is_none());
        assert_eq!(r.entry.firewall.as_ref().unwrap().raw_line, raw);
        assert!(!r.entry.message.contains(":0"));
        if raw.contains("2001:db8") {
            assert!(r.entry.message.contains("[2001:db8:10::11]:54002"));
        }
    }
    let r = parse_record(&row().replace("ALLOW", "OBSERVE"), &c, 0, 1, "");
    assert_eq!(r.entry.severity, Severity::Info);
    assert!(r.entry.message.contains("OBSERVE"));
}
