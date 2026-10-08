use cmtraceopen_parser::models::{firewall::*, log_entry::LogEntry};

#[test]
fn firewall_wire_round_trips_missing_vs_hyphen() {
    let original = FirewallRecord {
        raw_line: "-".into(),
        declared_fields: vec!["info".into(), "pid".into()],
        fields: vec![
            FirewallField {
                name: "info".into(),
                value: Some("-".into()),
            },
            FirewallField {
                name: "pid".into(),
                value: None,
            },
        ],
        schema_origin: FirewallSchemaOrigin::Header,
        time_basis: FirewallTimeBasis::Local,
        record_kind: FirewallRecordKind::EventsLost,
        truncated: false,
    };
    let json = serde_json::to_value(&original).unwrap();
    assert_eq!(json["schemaOrigin"], "header");
    assert_eq!(json["recordKind"], "eventsLost");
    let decoded: FirewallRecord = serde_json::from_value(json).unwrap();
    assert_eq!(decoded, original);
    assert_eq!(decoded.fields[0].value.as_deref(), Some("-"));
    assert_eq!(decoded.fields[1].value, None);
}

#[test]
fn firewall_wire_preserves_unknown_field_order() {
    let json = serde_json::json!({"rawLine":"Invented 00042", "declaredFields":["future","pid"],
      "fields":[{"name":"future","value":"Invented"},{"name":"pid","value":"00042"}],
      "schemaOrigin":"header", "timeBasis":"unknown", "recordKind":"traffic", "truncated":false});
    let row: FirewallRecord = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(serde_json::to_value(row).unwrap(), json);
}

#[test]
fn ordinary_entry_omits_firewall_payload() {
    assert!(serde_json::to_value(LogEntry::default())
        .unwrap()
        .get("firewall")
        .is_none());
}

#[test]
fn firewall_coverage_keeps_large_counts_exact_and_samples_bounded() {
    let mut coverage = FirewallCoverage::default();
    for line in 1..=20 {
        coverage.loss_events.add(u64::MAX, line);
    }
    assert_eq!(coverage.loss_events.count, u64::MAX);
    assert_eq!(coverage.loss_events.lines.len(), 8);
    let json = serde_json::to_value(&coverage).unwrap();
    assert_eq!(json["lossEvents"]["count"], u64::MAX.to_string());
    assert_eq!(
        serde_json::from_value::<FirewallCoverage>(json).unwrap(),
        coverage
    );
}
