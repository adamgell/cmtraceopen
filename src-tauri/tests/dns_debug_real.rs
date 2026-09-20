//! Integration test against the real DNS debug log fixture.
//!
//! The capture carries real hostnames and query traffic, so it lives outside the repo. Point
//! `CMTRACE_DNS_DEBUG_FIXTURE` at the log to request it explicitly; a local capture at the
//! hardcoded developer path also runs when present. Without either, the test passes vacuously and
//! announces that with an unmistakable banner, so a skipped run can never read as a verified one.
//!
//!     CMTRACE_DNS_DEBUG_FIXTURE=~/logs/DNSServer_debug.log cargo test --test dns_debug_real

use std::path::{Path, PathBuf};

/// Hardcoded convenience path for a developer who keeps the capture in the standard location.
const FIXTURE_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../Logs/dns-fixtures-20260411-203254/DNSServer_debug.log"
);

/// Resolves the fixture. An explicitly supplied `CMTRACE_DNS_DEBUG_FIXTURE` that is unusable fails
/// the test; a vacuous run (nothing to read) is announced, never reported as an ordinary pass.
fn fixture() -> Option<PathBuf> {
    if let Some(raw) = std::env::var_os("CMTRACE_DNS_DEBUG_FIXTURE") {
        let path = PathBuf::from(raw);
        assert!(
            path.is_file(),
            "CMTRACE_DNS_DEBUG_FIXTURE is set but {} is not a file",
            path.display()
        );
        return Some(path);
    }
    let local = Path::new(FIXTURE_PATH);
    if local.is_file() {
        return Some(local.to_path_buf());
    }
    eprintln!(
        "SKIP: CMTRACE_DNS_DEBUG_FIXTURE is not set and the local fixture {} is absent, \
         so nothing in this file actually ran. Point CMTRACE_DNS_DEBUG_FIXTURE at the captured \
         debug log to exercise the real DNS debug parse path.",
        FIXTURE_PATH
    );
    None
}

#[test]
fn test_real_dns_debug_log() {
    let Some(path) = fixture() else { return };

    let (result, selection) =
        app_lib::parser::parse_file(path.to_str().expect("fixture path is valid UTF-8"))
            .expect("parse should succeed");

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
