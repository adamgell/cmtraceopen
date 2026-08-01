#![cfg(feature = "macos-diag")]

//! Wire-format contract for the JAMF workspace IPC boundary.
//!
//! The frontend consumes these payloads as TypeScript discriminated unions
//! (`src/workspaces/macos-jamf/types.ts`) and switches on `.type`. `tsc`
//! cannot verify the Rust side, and the Rust unit tests exercise the enums
//! directly without ever serializing them — so nothing else in the suite
//! catches a tagging change. These assertions are the contract.

use app_lib::jamf::models::{JamfPolicyResult, JamfPolicyTrigger};

fn json(v: &impl serde::Serialize) -> String {
    serde_json::to_string(v).expect("serialize")
}

#[test]
fn policy_trigger_unit_variants_are_internally_tagged() {
    assert_eq!(
        json(&JamfPolicyTrigger::RecurringCheckIn),
        r#"{"type":"recurringCheckIn"}"#
    );
    assert_eq!(json(&JamfPolicyTrigger::Manual), r#"{"type":"manual"}"#);
    assert_eq!(json(&JamfPolicyTrigger::Startup), r#"{"type":"startup"}"#);
    assert_eq!(json(&JamfPolicyTrigger::Login), r#"{"type":"login"}"#);
    assert_eq!(json(&JamfPolicyTrigger::Logout), r#"{"type":"logout"}"#);
}

#[test]
fn policy_trigger_data_variants_carry_a_value_field() {
    assert_eq!(
        json(&JamfPolicyTrigger::PolicyId("332".into())),
        r#"{"type":"policyId","value":"332"}"#
    );
    assert_eq!(
        json(&JamfPolicyTrigger::Event("custom-trigger".into())),
        r#"{"type":"event","value":"custom-trigger"}"#
    );
    assert_eq!(
        json(&JamfPolicyTrigger::Other("info".into())),
        r#"{"type":"other","value":"info"}"#
    );
}

#[test]
fn policy_result_matches_the_typescript_union() {
    assert_eq!(json(&JamfPolicyResult::Success), r#"{"type":"success"}"#);
    assert_eq!(json(&JamfPolicyResult::InProgress), r#"{"type":"inProgress"}"#);
    assert_eq!(json(&JamfPolicyResult::Unknown), r#"{"type":"unknown"}"#);
    assert_eq!(
        json(&JamfPolicyResult::Failure("Error running recon".into())),
        r#"{"type":"failure","value":"Error running recon"}"#
    );
}

#[test]
fn policy_enums_round_trip() {
    for t in [
        JamfPolicyTrigger::RecurringCheckIn,
        JamfPolicyTrigger::PolicyId("332".into()),
        JamfPolicyTrigger::Other("info".into()),
    ] {
        let back: JamfPolicyTrigger = serde_json::from_str(&json(&t)).expect("round trip");
        assert_eq!(back, t);
    }
    for r in [
        JamfPolicyResult::Success,
        JamfPolicyResult::Failure("boom".into()),
    ] {
        let back: JamfPolicyResult = serde_json::from_str(&json(&r)).expect("round trip");
        assert_eq!(back, r);
    }
}
