//! Focused fixture matrix for `intune::apps::windows::scripts`.
//!
//! Each scenario directory holds a `manifest.json` naming its artifacts, the
//! artifact contents themselves, and an `expected.json` describing the contract
//! the reduction must satisfy. The expectations are written out rather than
//! snapshotted so a reviewer can see what each scenario is asserting and why.
//!
//! One scenario additionally carries `expected-full.json`: a complete golden of
//! the redacted export projection, which is what pins the serialized shape.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use cmtraceopen_parser::intune::apps::windows::scripts::{
    analyze_script_bundle, redacted_export_projection, ScriptAnalysis, ScriptSourceInput,
};
use serde_json::Value;

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/intune/windows/scripts")
}

fn read_json(path: &Path) -> Value {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()))
}

fn load_scenario(scenario: &str) -> (ScriptAnalysis, Value) {
    let dir = fixtures_root().join(scenario);
    let manifest = read_json(&dir.join("manifest.json"));
    let expected = read_json(&dir.join("expected.json"));

    let inputs: Vec<ScriptSourceInput> = manifest["artifacts"]
        .as_array()
        .expect("manifest.artifacts must be an array")
        .iter()
        .map(|artifact| {
            let content_file = artifact["contentFile"].as_str().expect("contentFile");
            ScriptSourceInput {
                artifact_id: artifact["artifactId"]
                    .as_str()
                    .expect("artifactId")
                    .to_string(),
                file_name: artifact["fileName"].as_str().expect("fileName").to_string(),
                file_path: artifact["filePath"].as_str().map(str::to_string),
                content: fs::read_to_string(dir.join(content_file))
                    .unwrap_or_else(|error| panic!("failed to read {content_file}: {error}")),
            }
        })
        .collect();

    (analyze_script_bundle(&inputs), expected)
}

/// Compare the reduction against the scenario's stated contract.
fn assert_scenario(scenario: &str) -> ScriptAnalysis {
    let (analysis, expected) = load_scenario(scenario);
    let value = serde_json::to_value(&analysis).expect("analysis must serialize");

    let expected_transactions = expected["transactions"].as_array().expect("transactions");
    let actual_transactions = value["transactions"].as_array().expect("transactions");

    assert_eq!(
        actual_transactions.len(),
        expected_transactions.len(),
        "{scenario}: transaction count. actual keys: {:?}",
        actual_transactions
            .iter()
            .map(|t| &t["key"])
            .collect::<Vec<_>>()
    );

    for (index, (actual, want)) in actual_transactions
        .iter()
        .zip(expected_transactions)
        .enumerate()
    {
        let at = format!("{scenario}[{index}]");
        assert_eq!(
            actual["key"]["policyId"], want["policyId"],
            "{at}: policyId"
        );
        assert_eq!(actual["key"]["runId"], want["runId"], "{at}: runId");
        assert_eq!(actual["key"]["context"], want["context"], "{at}: context");
        assert_eq!(actual["state"], want["state"], "{at}: state");
        assert_eq!(
            actual["lastConfirmedPhase"], want["lastConfirmedPhase"],
            "{at}: lastConfirmedPhase"
        );
        assert_eq!(actual["attempts"], want["attempts"], "{at}: attempts");
        assert_eq!(actual["confidence"], want["confidence"], "{at}: confidence");
        assert_eq!(actual["bitness"], want["bitness"], "{at}: bitness");
        assert_eq!(
            actual["nextEvidenceRequest"], want["nextEvidenceRequest"],
            "{at}: nextEvidenceRequest"
        );

        match want["exitDecimal"].as_i64() {
            Some(code) => {
                assert_eq!(
                    actual["exitToken"]["decimal"].as_i64(),
                    Some(code),
                    "{at}: exit decimal"
                );
                assert_eq!(
                    actual["exitToken"]["rawText"], want["exitRaw"],
                    "{at}: exit raw text"
                );
            }
            None => assert!(
                actual["exitToken"].is_null(),
                "{at}: expected no exit token, got {}",
                actual["exitToken"]
            ),
        }

        // Every transaction must cite the records it was built from.
        assert!(
            !actual["evidence"].as_array().expect("evidence").is_empty(),
            "{at}: a transaction must cite evidence"
        );
        assert_eq!(
            actual["evidence"].as_array().unwrap().len(),
            actual["observations"].as_array().unwrap().len(),
            "{at}: evidence and observations must stay in step"
        );
    }

    assert_eq!(
        value["unkeyedObservations"].as_array().unwrap().len() as u64,
        expected["unkeyedObservationCount"].as_u64().unwrap(),
        "{scenario}: unkeyed observation count"
    );

    let coverage = &expected["coverage"];
    assert_eq!(
        value["coverage"]["missingExpectedSources"], coverage["missingExpectedSources"],
        "{scenario}: missing expected sources"
    );
    assert_eq!(
        value["coverage"]["unknownVersionObserved"], coverage["unknownVersionObserved"],
        "{scenario}: unknown version flag"
    );

    if let Some(rule) = expected.get("messageMustContain") {
        let id = rule["observationId"].as_str().expect("observationId");
        let text = rule["text"].as_str().expect("text");
        let observation = analysis
            .observations
            .iter()
            .find(|observation| observation.observation_id == id)
            .unwrap_or_else(|| panic!("{scenario}: no observation {id}"));
        assert!(
            observation.message.value.contains(text),
            "{scenario}: observation {id} lost {text:?}; got {:?}",
            observation.message.value
        );
    }

    if let Some(rule) = expected.get("timestampMustBe") {
        let id = rule["observationId"].as_str().expect("observationId");
        let observation = analysis
            .observations
            .iter()
            .find(|observation| observation.observation_id == id)
            .unwrap_or_else(|| panic!("{scenario}: no observation {id}"));
        let timestamp = observation
            .timestamp
            .as_ref()
            .unwrap_or_else(|| panic!("{scenario}: observation {id} has no timestamp"));
        assert_eq!(
            timestamp.original_offset.as_deref(),
            rule["originalOffset"].as_str(),
            "{scenario}: original offset"
        );
        assert_eq!(
            timestamp.normalized_utc.as_deref(),
            rule["normalizedUtc"].as_str(),
            "{scenario}: normalized utc"
        );
    }

    if let Some(forbidden) = expected.get("redactionMustNotContain") {
        let redacted = redacted_export_projection(&analysis);
        let text = serde_json::to_string(&redacted).expect("redacted analysis must serialize");
        for needle in forbidden.as_array().expect("redactionMustNotContain") {
            let needle = needle.as_str().expect("needle");
            assert!(
                !text.contains(needle),
                "{scenario}: redacted export still contains {needle:?}"
            );
        }
    }

    if let Some(required) = expected.get("redactionMustContain") {
        let redacted = redacted_export_projection(&analysis);
        let text = serde_json::to_string(&redacted).expect("redacted analysis must serialize");
        for needle in required.as_array().expect("redactionMustContain") {
            let needle = needle.as_str().expect("needle");
            assert!(
                text.contains(needle),
                "{scenario}: redacted export dropped correlation key {needle:?}"
            );
        }
    }

    analysis
}

// -- The required fixture matrix -------------------------------------------

#[test]
fn successful_device_context_script_and_successful_report() {
    assert_scenario("success-device-context");
}

#[test]
fn successful_user_context_script() {
    assert_scenario("success-user-context");
}

#[test]
fn nonzero_exit_with_retained_output() {
    assert_scenario("nonzero-exit-with-output");
}

#[test]
fn nonzero_exit_without_retained_output_requests_the_output_artifact() {
    assert_scenario("nonzero-exit-without-output");
}

#[test]
fn process_launch_failure() {
    assert_scenario("launch-failure");
}

#[test]
fn execution_timeout() {
    assert_scenario("timeout");
}

#[test]
fn three_retries_followed_by_success() {
    assert_scenario("three-retries-then-success");
}

#[test]
fn retries_exhausted() {
    assert_scenario("retries-exhausted");
}

#[test]
fn execution_success_with_reporting_failure() {
    assert_scenario("execution-success-report-failure");
}

#[test]
fn policy_received_with_no_execution_evidence() {
    assert_scenario("policy-received-no-execution");
}

#[test]
fn two_scripts_in_the_same_minute_stay_separate() {
    let analysis = assert_scenario("two-scripts-same-minute");

    // The point of the scenario: no observation is shared between the two.
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for transaction in &analysis.transactions {
        for observation in &transaction.observations {
            assert!(
                seen.insert(observation.as_str()),
                "observation {observation} was claimed by two transactions"
            );
        }
    }
}

#[test]
fn multiline_ccm_record_stays_one_logical_record() {
    assert_scenario("multiline-ccm-record");
}

#[test]
fn rotation_boundary_leaves_an_unkeyed_tail() {
    let analysis = assert_scenario("rotation-boundary");
    assert_eq!(
        analysis.unkeyed_observations,
        vec!["agent:1".to_string()],
        "the orphaned completion record must remain visible and unkeyed"
    );
}

#[test]
fn unknown_agent_version_lowers_confidence_and_raises_coverage() {
    assert_scenario("unknown-agent-version");
}

#[test]
fn privacy_fixture_redacts_deterministically() {
    let analysis = assert_scenario("privacy-redaction");

    // Determinism: the same input must produce byte-identical exports.
    let first = serde_json::to_string(&redacted_export_projection(&analysis)).unwrap();
    let second = serde_json::to_string(&redacted_export_projection(&analysis)).unwrap();
    assert_eq!(first, second, "redacted export must be deterministic");
}

#[test]
fn an_unrecognised_record_demotes_only_its_own_transaction() {
    assert_scenario("multi-policy-partial-unknown-version");
}

#[test]
fn a_record_stating_its_own_offset_yields_a_trustworthy_utc_value() {
    assert_scenario("explicit-timezone-offset");
}

/// A record with no embedded offset must not report a UTC value, because the
/// only one available would be derived from the parsing machine's timezone.
/// Without this rule the golden below would differ per developer machine.
#[test]
fn a_record_without_an_offset_reports_no_normalized_utc() {
    let (analysis, _) = load_scenario("success-device-context");
    for observation in &analysis.observations {
        let timestamp = observation.timestamp.as_ref().expect("timestamp");
        assert!(
            !timestamp.raw_text.is_empty(),
            "raw timestamp text must always survive"
        );
        assert_eq!(
            timestamp.normalized_utc, None,
            "{} invented a UTC value from a record with no offset",
            observation.observation_id
        );
        assert_eq!(timestamp.original_offset, None);
    }
}

// -- Cross-cutting contract -------------------------------------------------

#[test]
fn redacted_export_projection_is_idempotent() {
    let (analysis, _) = load_scenario("privacy-redaction");
    let once = redacted_export_projection(&analysis);
    let twice = redacted_export_projection(&once);
    assert_eq!(
        serde_json::to_value(&once).unwrap(),
        serde_json::to_value(&twice).unwrap()
    );
}

#[test]
fn analysis_serialization_is_camel_case_and_stable() {
    let (analysis, _) = load_scenario("success-device-context");
    let value = serde_json::to_value(&analysis).unwrap();

    for key in [
        "transactions",
        "observations",
        "unkeyedObservations",
        "coverage",
    ] {
        assert!(value.get(key).is_some(), "missing top-level key {key}");
    }
    let transaction = &value["transactions"][0];
    for key in [
        "key",
        "displayName",
        "bitness",
        "observations",
        "lastConfirmedPhase",
        "state",
        "exitToken",
        "attempts",
        "confidence",
        "evidence",
        "nextEvidenceRequest",
    ] {
        assert!(
            transaction.get(key).is_some(),
            "missing transaction key {key}"
        );
    }
}

/// Full golden of the redacted export for one representative scenario.
///
/// Regenerate with `UPDATE_SCRIPT_GOLDEN=1 cargo test --locked -p
/// cmtraceopen-parser --test intune_windows_scripts` and review the diff.
#[test]
fn redacted_export_matches_the_golden() {
    let (analysis, _) = load_scenario("success-device-context");
    let redacted = redacted_export_projection(&analysis);
    let actual = serde_json::to_string_pretty(&redacted).expect("serialize") + "\n";

    let golden = fixtures_root().join("success-device-context/expected-full.json");
    if std::env::var("UPDATE_SCRIPT_GOLDEN").is_ok() {
        fs::write(&golden, &actual).expect("write golden");
        return;
    }

    let expected = fs::read_to_string(&golden).expect("golden must exist; see this test's docs");
    assert_eq!(actual, expected, "redacted export golden drifted");
}
