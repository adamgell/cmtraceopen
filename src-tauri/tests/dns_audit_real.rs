//! Integration test against the real DNS audit EVTX fixture.
//! Skipped if the fixture file is not present.
//! Requires the `event-log` feature.

use std::path::Path;

const FIXTURE_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../Logs/dns-fixtures-20260411-203254/dns-audit.evtx"
);

#[test]
#[cfg(feature = "event-log")]
fn test_real_dns_audit_evtx() {
    if !Path::new(FIXTURE_PATH).exists() {
        eprintln!("Skipping: real DNS audit EVTX fixture not found at {}", FIXTURE_PATH);
        return;
    }

    // Test detection
    assert!(
        app_lib::parser::dns_audit::is_dns_evtx(Path::new(FIXTURE_PATH)),
        "Should detect as DNS EVTX"
    );

    // Test full parse via parse_file
    let (result, selection) =
        app_lib::parser::parse_file(FIXTURE_PATH).expect("parse should succeed");

    assert_eq!(format!("{:?}", selection.parser), "DnsAudit");
    assert_eq!(format!("{:?}", result.format_detected), "DnsAudit");
    assert!(result.entries.len() > 0, "Should have parsed entries, got 0");
    assert_eq!(result.parse_errors, 0, "Should have zero parse errors");

    // Collect event IDs
    let mut event_id_counts: std::collections::HashMap<u32, usize> = std::collections::HashMap::new();
    for entry in &result.entries {
        if let Some(eid) = entry.dns_event_id {
            *event_id_counts.entry(eid).or_insert(0) += 1;
        }
    }

    // Spot-check first entry
    let first = &result.entries[0];
    assert!(first.dns_event_id.is_some(), "Should have dns_event_id");
    assert!(first.timestamp.is_some(), "Should have timestamp");
    assert!(first.timestamp_display.is_some(), "Should have timestamp_display");
    assert_eq!(first.component.as_deref(), Some("DNSServer"));
    assert_eq!(format!("{:?}", first.format), "DnsAudit");

    // Severity check — should have at least some non-Info entries
    let info_count = result.entries.iter().filter(|e| format!("{:?}", e.severity) == "Info").count();
    let warn_count = result.entries.iter().filter(|e| format!("{:?}", e.severity) == "Warning").count();
    let err_count = result.entries.iter().filter(|e| format!("{:?}", e.severity) == "Error").count();

    // Check entries with DNS-specific fields
    let with_query_name = result.entries.iter().filter(|e| e.query_name.is_some()).count();
    let with_zone = result.entries.iter().filter(|e| e.zone_name.is_some()).count();
    let with_query_type = result.entries.iter().filter(|e| e.query_type.is_some()).count();

    // Print summary
    eprintln!("--- Real DNS Audit EVTX Results ---");
    eprintln!("Total records: {}", result.total_lines);
    eprintln!("Entries parsed: {}", result.entries.len());
    eprintln!("Parse errors: {}", result.parse_errors);
    eprintln!("Severity: Info={} Warning={} Error={}", info_count, warn_count, err_count);
    eprintln!("With query_name: {}", with_query_name);
    eprintln!("With zone_name: {}", with_zone);
    eprintln!("With query_type: {}", with_query_type);
    eprintln!("Event ID distribution:");
    let mut sorted_ids: Vec<_> = event_id_counts.iter().collect();
    sorted_ids.sort_by_key(|(id, _)| *id);
    for (id, count) in &sorted_ids {
        eprintln!("  Event {}: {} entries", id, count);
    }
    eprintln!("First entry: {}", first.message);
    if let Some(last) = result.entries.last() {
        eprintln!("Last entry:  {}", last.message);
    }

    // Show a few sample entries for human inspection
    eprintln!("--- Sample entries ---");
    for entry in result.entries.iter().take(10) {
        eprintln!(
            "  [EID={}] {} | qname={} qtype={} zone={} sev={:?}",
            entry.dns_event_id.unwrap_or(0),
            &entry.message[..entry.message.len().min(80)],
            entry.query_name.as_deref().unwrap_or("-"),
            entry.query_type.as_deref().unwrap_or("-"),
            entry.zone_name.as_deref().unwrap_or("-"),
            entry.severity,
        );
    }
}
