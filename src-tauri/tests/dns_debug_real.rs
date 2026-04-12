//! Integration test against the real DNS debug log fixture.
//! Skipped if the fixture file is not present.

use std::path::Path;

const FIXTURE_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../Logs/dns-fixtures-20260411-203254/DNSServer_debug.log"
);

#[test]
fn test_real_dns_debug_log() {
    if !Path::new(FIXTURE_PATH).exists() {
        eprintln!("Skipping: real DNS fixture not found at {}", FIXTURE_PATH);
        return;
    }

    let (result, selection) =
        app_lib::parser::parse_file(FIXTURE_PATH).expect("parse should succeed");

    // Format detection
    assert_eq!(
        format!("{:?}", selection.parser),
        "DnsDebug",
        "Should detect as DnsDebug"
    );
    assert_eq!(
        format!("{:?}", result.format_detected),
        "DnsDebug",
        "Format should be DnsDebug"
    );

    // Should have parsed entries (the file has 3174 PACKET lines)
    assert!(
        result.entries.len() > 3000,
        "Expected 3000+ entries, got {}",
        result.entries.len()
    );
    assert_eq!(result.parse_errors, 0, "Should have zero parse errors");

    // Spot-check first entry
    let first = &result.entries[0];
    assert_eq!(first.query_name.as_deref(), Some("home.gell.one"));
    assert_eq!(first.query_type.as_deref(), Some("SOA"));
    assert_eq!(first.response_code.as_deref(), Some("NOERROR"));
    assert_eq!(first.dns_direction.as_deref(), Some("Rcv"));
    assert_eq!(first.dns_protocol.as_deref(), Some("UDP"));
    assert!(first.source_ip.is_some());
    assert!(first.timestamp.is_some());
    assert_eq!(format!("{:?}", first.severity), "Info");

    // Check severity distribution
    let warnings = result
        .entries
        .iter()
        .filter(|e| format!("{:?}", e.severity) == "Warning")
        .count();
    let errors = result
        .entries
        .iter()
        .filter(|e| format!("{:?}", e.severity) == "Error")
        .count();

    assert!(warnings > 0, "Should have NXDOMAIN warnings");
    assert!(errors > 0, "Should have SERVFAIL errors");

    // Print summary
    eprintln!("--- Real DNS Debug Log Results ---");
    eprintln!("Total lines: {}", result.total_lines);
    eprintln!("Entries parsed: {}", result.entries.len());
    eprintln!("Parse errors: {}", result.parse_errors);
    eprintln!("Warnings (NXDOMAIN): {}", warnings);
    eprintln!("Errors (SERVFAIL): {}", errors);
    eprintln!("First: {}", result.entries[0].message);
    eprintln!("Last:  {}", result.entries.last().unwrap().message);

    // Port extraction from detail sections
    let with_port = result
        .entries
        .iter()
        .filter(|e| {
            e.source_ip
                .as_deref()
                .map(|ip| ip.contains(':'))
                .unwrap_or(false)
        })
        .count();
    eprintln!("Entries with port extracted: {}", with_port);
}
