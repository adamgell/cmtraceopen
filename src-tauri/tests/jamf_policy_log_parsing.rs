#![cfg(feature = "macos-diag")]

use std::path::Path;

use app_lib::jamf::models::{JamfPolicyResult, JamfPolicyTrigger};
use app_lib::jamf::policy_log::parse_policy_log_impl;

const BASIC: &str = "tests/fixtures/jamf_policy_log_basic.log";
const ERRORS: &str = "tests/fixtures/jamf_policy_log_errors.log";

#[test]
fn parses_recurring_check_in() {
    let result = parse_policy_log_impl(Path::new(BASIC)).expect("parse");
    let check_ins: Vec<_> = result
        .events
        .iter()
        .filter(|e| matches!(e.trigger, JamfPolicyTrigger::RecurringCheckIn))
        .collect();
    assert!(
        check_ins.len() >= 2,
        "expected multiple recurring check-ins, got {}",
        check_ins.len()
    );
}

#[test]
fn parses_executing_policy_with_name() {
    let result = parse_policy_log_impl(Path::new(BASIC)).expect("parse");
    let chrome = result
        .events
        .iter()
        .find(|e| e.policy_name.as_deref() == Some("Google Chrome Installer"))
        .expect("expected Google Chrome Installer policy");
    assert!(matches!(
        chrome.result,
        JamfPolicyResult::Success | JamfPolicyResult::Unknown | JamfPolicyResult::InProgress
    ));
}

#[test]
fn parses_policy_id_check() {
    let result = parse_policy_log_impl(Path::new(BASIC)).expect("parse");
    let by_id = result
        .events
        .iter()
        .find(|e| matches!(&e.trigger, JamfPolicyTrigger::PolicyId(id) if id == "332"))
        .expect("expected PolicyId(332) trigger");
    assert!(by_id.policy_id.as_deref() == Some("332"));
}

#[test]
fn parses_recon_error() {
    let result = parse_policy_log_impl(Path::new(ERRORS)).expect("parse");
    let err = result
        .events
        .iter()
        .find(|e| matches!(&e.result, JamfPolicyResult::Failure(msg) if msg.contains("recon")))
        .expect("expected a recon failure event");
    assert!(matches!(err.trigger, JamfPolicyTrigger::Other(_)));
}

#[test]
fn unparsed_lines_counted() {
    let result = parse_policy_log_impl(Path::new(BASIC)).expect("parse");
    assert_eq!(result.total_lines, result.events.len() + result.unparsed_lines);
}

#[test]
fn policy_executions_carry_an_elapsed_time() {
    let result = parse_policy_log_impl(Path::new(BASIC)).expect("parse");

    let executions: Vec<_> = result
        .events
        .iter()
        .filter(|e| e.policy_name.is_some())
        .collect();
    assert!(!executions.is_empty(), "fixture should execute policies");

    // "Executing Policy Google Chrome Installer" at 13:23:04 is followed at
    // 13:23:29 by the last line of the same jamf[92532] invocation.
    let chrome = executions
        .iter()
        .find(|e| e.policy_name.as_deref() == Some("Google Chrome Installer"))
        .expect("chrome policy");
    assert_eq!(chrome.duration_ms, Some(25_000));

    // A policy that is the only event of its invocation has nothing to measure
    // against and must stay None rather than reporting zero.
    let reboot = executions
        .iter()
        .find(|e| e.policy_name.as_deref() == Some("Reboot Popup (Weekly)"))
        .expect("reboot policy");
    assert_eq!(reboot.duration_ms, None);
}

#[test]
fn a_recycled_pid_does_not_extend_an_earlier_policy() {
    // Same PID, but a different invocation days later. Pairing the two would
    // report a multi-day policy run.
    let log = "\
Wed Apr 29 13:23:04 host jamf[100]: Executing Policy Chrome
Wed Apr 29 13:23:09 host jamf[100]: Checking for patches...
Wed Apr 29 13:24:00 host jamf[200]: Checking for patches...
Fri May 01 09:00:00 host jamf[100]: Checking for policies triggered by \"startup\" for user \"a\"...
";
    let path = std::env::temp_dir().join("cmtrace_jamf_pid_reuse.log");
    std::fs::write(&path, log).expect("write");

    let result = parse_policy_log_impl(&path).expect("parse");
    let chrome = result
        .events
        .iter()
        .find(|e| e.policy_name.as_deref() == Some("Chrome"))
        .expect("chrome policy");

    // Bounded by its own invocation's last line (13:23:09), not the May 1 reuse.
    assert_eq!(chrome.duration_ms, Some(5_000));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn non_execution_events_have_no_elapsed_time() {
    let result = parse_policy_log_impl(Path::new(BASIC)).expect("parse");
    for event in &result.events {
        if event.policy_name.is_none() {
            assert_eq!(
                event.duration_ms, None,
                "only policy executions are timed: {}",
                event.raw_line
            );
        }
    }
}

#[test]
fn missing_file_returns_error() {
    let err = parse_policy_log_impl(Path::new("/nonexistent/jamf.log"));
    assert!(err.is_err());
}
