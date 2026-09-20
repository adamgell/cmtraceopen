//! Integration test against the real DNS audit EVTX fixture.
//!
//! The capture carries real hostnames and query traffic, so it lives outside the repo. Point
//! `CMTRACE_EVTX_FIXTURE` at an .evtx file to request it explicitly; a local capture at the
//! hardcoded developer path also runs when present. Without either, the test passes vacuously and
//! announces that with an unmistakable banner, so a skipped run can never read as a verified one.
//!
//!     CMTRACE_EVTX_FIXTURE=~/logs/dns-audit.evtx cargo test --features event-log --test dns_audit_real
//!
//! Requires the `event-log` feature.
#![cfg(feature = "event-log")]

use std::path::{Path, PathBuf};

/// Hardcoded convenience path for a developer who keeps the capture in the standard location.
const FIXTURE_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../Logs/dns-fixtures-20260411-203254/dns-audit.evtx"
);

/// Resolves the fixture. An explicitly supplied `CMTRACE_EVTX_FIXTURE` that is unusable fails the
/// test; a vacuous run (nothing to read) is announced, never reported as an ordinary pass.
fn fixture() -> Option<PathBuf> {
    if let Some(raw) = std::env::var_os("CMTRACE_EVTX_FIXTURE") {
        let path = PathBuf::from(raw);
        assert!(
            path.is_file(),
            "CMTRACE_EVTX_FIXTURE is set but {} is not a file",
            path.display()
        );
        return Some(path);
    }
    let local = Path::new(FIXTURE_PATH);
    if local.is_file() {
        return Some(local.to_path_buf());
    }
    eprintln!(
        "SKIP: CMTRACE_EVTX_FIXTURE is not set and the local fixture {} is absent, \
         so nothing in this file actually ran. Point CMTRACE_EVTX_FIXTURE at an .evtx file \
         to exercise the real DNS audit parse path.",
        FIXTURE_PATH
    );
    None
}

#[test]
fn real_dns_audit_evtx_smoke_when_local_fixture_exists() {
    let Some(path) = fixture() else { return };

    // Test detection
    assert!(
        app_lib::parser::dns_audit::is_dns_evtx(&path),
        "Should detect as DNS EVTX"
    );

    // Test full parse via parse_file
    let (result, selection) =
        app_lib::parser::parse_file(path.to_str().expect("fixture path is valid UTF-8"))
            .expect("parse should succeed");

    assert_eq!(format!("{:?}", selection.parser), "DnsAudit");
    assert_eq!(format!("{:?}", result.format_detected), "DnsAudit");
    assert!(
        !result.entries.is_empty(),
        "Should have parsed entries, got 0"
    );
    assert_eq!(result.parse_errors, 0, "Should have zero parse errors");

    // Collect event IDs
    let mut event_id_counts: std::collections::HashMap<u32, usize> =
        std::collections::HashMap::new();
    for entry in &result.entries {
        if let Some(eid) = entry.dns_event_id {
            *event_id_counts.entry(eid).or_insert(0) += 1;
        }
    }

    // Spot-check first entry
    let first = &result.entries[0];
    assert!(first.dns_event_id.is_some(), "Should have dns_event_id");
    assert!(first.timestamp.is_some(), "Should have timestamp");
    assert!(
        first.timestamp_display.is_some(),
        "Should have timestamp_display"
    );
    assert_eq!(first.component.as_deref(), Some("DNSServer"));
    assert_eq!(format!("{:?}", first.format), "DnsAudit");

    // Severity check — should have at least some non-Info entries
    let info_count = result
        .entries
        .iter()
        .filter(|e| format!("{:?}", e.severity) == "Info")
        .count();
    let warn_count = result
        .entries
        .iter()
        .filter(|e| format!("{:?}", e.severity) == "Warning")
        .count();
    let err_count = result
        .entries
        .iter()
        .filter(|e| format!("{:?}", e.severity) == "Error")
        .count();

    // Check entries with DNS-specific fields
    let with_query_name = result
        .entries
        .iter()
        .filter(|e| e.query_name.is_some())
        .count();
    let with_zone = result
        .entries
        .iter()
        .filter(|e| e.zone_name.is_some())
        .count();
    let with_query_type = result
        .entries
        .iter()
        .filter(|e| e.query_type.is_some())
        .count();

    // Print summary
    eprintln!("--- Real DNS Audit EVTX Results ---");
    eprintln!("Total records: {}", result.total_lines);
    eprintln!("Entries parsed: {}", result.entries.len());
    eprintln!("Parse errors: {}", result.parse_errors);
    eprintln!(
        "Severity: Info={} Warning={} Error={}",
        info_count, warn_count, err_count
    );
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
