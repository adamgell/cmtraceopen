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
fn missing_file_returns_error() {
    let err = parse_policy_log_impl(Path::new("/nonexistent/jamf.log"));
    assert!(err.is_err());
}
