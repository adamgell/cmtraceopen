//! Runs the JAMF parsers against logs captured from a real JAMF-managed Mac.
//!
//! The captured data contains real organizational details (JSS hostname,
//! account names, deployed security agents), so it lives outside the repo.
//! Point `JAMF_DEV_FIXTURES` at an unpacked `jamf-dev-fixtures` directory to
//! run these; without it every test here passes vacuously, so CI is unaffected.
//!
//!     JAMF_DEV_FIXTURES=~/jamf-dev-fixtures cargo test --test jamf_real_fixtures
//!
//! Assertions are floors and invariants, not exact counts, so a re-captured
//! fixture set does not break them.

#![cfg(all(feature = "macos-diag", target_os = "macos"))]

use std::path::PathBuf;

use app_lib::jamf::models::{JamfPolicyResult, JamfPolicyTrigger};
use app_lib::jamf::policy_log::parse_policy_log_impl;
use app_lib::jamf::self_service::parse_self_service_log_impl;
use app_lib::macos_diag::profiles::parse_system_profiler_plist;

fn fixture_dir() -> Option<PathBuf> {
    let dir = PathBuf::from(std::env::var_os("JAMF_DEV_FIXTURES")?);
    assert!(
        dir.is_dir(),
        "JAMF_DEV_FIXTURES is set but {} is not a directory",
        dir.display()
    );
    Some(dir)
}

#[test]
fn policy_log_parses_every_line() {
    let Some(dir) = fixture_dir() else { return };
    let result = parse_policy_log_impl(&dir.join("logs/jamf.log")).expect("parse");

    assert!(
        result.total_lines > 1000,
        "captured log should be substantial, got {} lines",
        result.total_lines
    );
    // Every line of the captured log matches the syslog line shape. If a
    // re-capture introduces a new shape, this failing is the point.
    assert_eq!(
        result.unparsed_lines, 0,
        "{} of {} real lines did not parse",
        result.unparsed_lines, result.total_lines
    );

    let executions = result
        .events
        .iter()
        .filter(|e| matches!(&e.trigger, JamfPolicyTrigger::Other(k) if k == "execute"))
        .count();
    assert!(executions >= 10, "expected policy runs, got {executions}");

    let with_duration = result
        .events
        .iter()
        .filter(|e| e.duration_ms.is_some())
        .count();
    assert!(
        with_duration > 0,
        "policy executions should get durations from same-PID pairing"
    );

    assert!(
        result
            .events
            .iter()
            .any(|e| matches!(e.trigger, JamfPolicyTrigger::RecurringCheckIn)),
        "a managed Mac's log must contain recurring check-ins"
    );
    assert!(
        result
            .events
            .iter()
            .any(|e| matches!(e.result, JamfPolicyResult::Success)),
        "expected at least one successful package install"
    );
}

#[test]
fn policy_log_timestamps_are_plausible_and_ordered() {
    let Some(dir) = fixture_dir() else { return };
    let result = parse_policy_log_impl(&dir.join("logs/jamf.log")).expect("parse");

    // The year is inferred from file mtime and Dec→Jan wraps are repaired, so
    // the whole capture must land in a sane window rather than 1970 or +1y.
    let now = chrono::Utc::now();
    for e in &result.events {
        assert!(
            e.timestamp <= now + chrono::Duration::days(1),
            "future timestamp {} in {}",
            e.timestamp,
            e.raw_line
        );
        assert!(
            e.timestamp > now - chrono::Duration::days(730),
            "implausibly old timestamp {} in {}",
            e.timestamp,
            e.raw_line
        );
    }
    for pair in result.events.windows(2) {
        assert!(
            pair[0].timestamp <= pair[1].timestamp,
            "events out of order: {} then {}",
            pair[0].raw_line,
            pair[1].raw_line
        );
    }
}

#[test]
fn self_service_log_yields_user_actions() {
    let Some(dir) = fixture_dir() else { return };
    let events = parse_self_service_log_impl(&dir.join("logs/selfservice.log")).expect("parse");

    assert!(!events.is_empty(), "real selfservice.log produced no events");
    assert!(
        events.iter().any(|e| e.action == "triggerPolicy"),
        "capture is known to contain Self Service-initiated installs"
    );
    assert!(
        events.iter().any(|e| e.action == "launch"),
        "capture is known to contain an app launch"
    );
    assert!(
        events
            .iter()
            .any(|e| e.action == "connectivity" && e.result.as_deref() == Some("active")),
        "capture is known to reach the active connectivity state"
    );
}

#[test]
fn self_service_debug_log_parses_without_choking_on_continuations() {
    let Some(dir) = fixture_dir() else { return };
    let events =
        parse_self_service_log_impl(&dir.join("logs/selfservice_debug.log")).expect("parse");

    // The debug log interleaves timestamped lines with continuation lines
    // (request/response bodies). Continuations drop; events survive.
    assert!(
        events.len() > 100,
        "debug capture should yield many events, got {}",
        events.len()
    );
    assert!(events.iter().any(|e| e.action == "triggerPolicy"));
}

#[test]
fn captured_profiles_xml_parses_and_filters_to_jamf() {
    let Some(dir) = fixture_dir() else { return };
    let xml = std::fs::read(dir.join("reference/configuration-profiles.xml")).expect("read xml");

    let profiles = parse_system_profiler_plist(&xml);
    assert!(
        profiles.len() >= 30,
        "reference capture has 32 profiles, parsed {}",
        profiles.len()
    );

    // Device-scoped profiles are the large majority on a managed Mac; a
    // regression to first-section-only parsing would collapse this to 1.
    assert!(
        profiles.len() > 5,
        "device-scoped section was likely dropped: {} profiles",
        profiles.len()
    );

    let filtered = app_lib::jamf::profiles::filter_jamf_profiles_impl(profiles, None)
        .expect("filter");
    assert!(
        !filtered.profiles.is_empty(),
        "payload-prefix matching found no JAMF profiles in a JAMF capture"
    );
    for p in &filtered.profiles {
        assert!(
            !p.payloads.is_empty(),
            "profile {} matched without payloads",
            p.profile_identifier
        );
    }
}
