//! Focused fixture matrix for `intune::apps::windows::remediations`.
//!
//! Each scenario directory holds a `manifest.json` naming its artifacts, the
//! artifact contents, and an `expected.json` describing the contract the
//! reduction must satisfy. Expectations are written out rather than snapshotted
//! so a reviewer can see what each scenario asserts and why.
//!
//! `detection-compliant-remediation-skipped` additionally carries
//! `expected-full.json`: a complete golden of the redacted export projection,
//! which pins the serialized shape.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use cmtraceopen_parser::intune::apps::windows::remediations::{
    analyze_remediation_bundle, redacted_export_projection, RemediationAnalysis,
    RemediationSourceInput,
};
use serde_json::Value;

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/intune/windows/remediations")
}

fn read_json(path: &Path) -> Value {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()))
}

fn load_scenario(scenario: &str) -> (RemediationAnalysis, Value) {
    let dir = fixtures_root().join(scenario);
    let manifest = read_json(&dir.join("manifest.json"));
    let expected = read_json(&dir.join("expected.json"));

    let inputs: Vec<RemediationSourceInput> = manifest["artifacts"]
        .as_array()
        .expect("manifest.artifacts must be an array")
        .iter()
        .map(|artifact| {
            let content_file = artifact["contentFile"].as_str().expect("contentFile");
            RemediationSourceInput {
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

    (analyze_remediation_bundle(&inputs), expected)
}

fn assert_scenario(scenario: &str) -> RemediationAnalysis {
    let (analysis, expected) = load_scenario(scenario);
    let value = serde_json::to_value(&analysis).expect("analysis must serialize");

    let want_transactions = expected["transactions"].as_array().expect("transactions");
    let got_transactions = value["transactions"].as_array().expect("transactions");

    assert_eq!(
        got_transactions.len(),
        want_transactions.len(),
        "{scenario}: transaction count. actual keys: {:?}",
        got_transactions
            .iter()
            .map(|t| &t["key"])
            .collect::<Vec<_>>()
    );

    for (index, (got, want)) in got_transactions.iter().zip(want_transactions).enumerate() {
        let at = format!("{scenario}[{index}]");
        assert_eq!(got["key"]["policyId"], want["policyId"], "{at}: policyId");
        assert_eq!(got["key"]["runId"], want["runId"], "{at}: runId");
        assert_eq!(
            got["key"]["invocation"], want["invocation"],
            "{at}: invocation"
        );
        assert_eq!(
            got["detection"]["state"], want["detectionState"],
            "{at}: detection state"
        );
        assert_eq!(
            got["remediation"]["state"], want["remediationState"],
            "{at}: remediation state"
        );
        assert_eq!(got["report"], want["report"], "{at}: report state");
        assert_eq!(got["attempts"], want["attempts"], "{at}: attempts");
        assert_eq!(got["confidence"], want["confidence"], "{at}: confidence");
        assert_eq!(
            got["nextEvidenceRequest"], want["nextEvidenceRequest"],
            "{at}: nextEvidenceRequest"
        );

        match want["postDetectionState"].as_str() {
            Some(state) => assert_eq!(
                got["postDetection"]["state"], state,
                "{at}: post-detection state"
            ),
            None => assert!(
                got["postDetection"].is_null(),
                "{at}: expected no post-detection stage, got {}",
                got["postDetection"]
            ),
        }

        // Stage-scoped exit tokens: each must name its own stage, and a stage
        // with no token must not borrow the other stage's.
        for (stage_key, want_key, stage_name) in [
            ("detection", "detectionExitDecimal", "detection"),
            ("remediation", "remediationExitDecimal", "remediation"),
        ] {
            match want[want_key].as_i64() {
                Some(code) => {
                    assert_eq!(
                        got[stage_key]["exitToken"]["decimal"].as_i64(),
                        Some(code),
                        "{at}: {stage_name} exit decimal"
                    );
                    assert_eq!(
                        got[stage_key]["exitToken"]["stage"], stage_name,
                        "{at}: {stage_name} exit token must name its own stage"
                    );
                }
                None => assert!(
                    got[stage_key]["exitToken"].is_null(),
                    "{at}: expected no {stage_name} exit token, got {}",
                    got[stage_key]["exitToken"]
                ),
            }
        }

        assert!(
            !got["evidence"].as_array().expect("evidence").is_empty(),
            "{at}: a transaction must cite evidence"
        );
    }

    assert_eq!(
        value["unkeyedObservations"].as_array().unwrap().len() as u64,
        expected["unkeyedObservationCount"].as_u64().unwrap(),
        "{scenario}: unkeyed observation count"
    );

    let coverage = &expected["coverage"];
    for key in [
        "missingExpectedSources",
        "unknownVersionObserved",
        "malformedPayloads",
    ] {
        assert_eq!(
            value["coverage"][key], coverage[key],
            "{scenario}: coverage.{key}"
        );
    }

    if let Some(rule) = expected.get("payloadMustBe") {
        let id = rule["observationId"].as_str().expect("observationId");
        let want_parsed = rule["parsed"].as_bool().expect("parsed");
        let payload = analysis
            .transactions
            .iter()
            .flat_map(|transaction| &transaction.payloads)
            .find(|payload| {
                format!(
                    "{}:{}",
                    payload.evidence.artifact_id, payload.evidence.record_number
                ) == id
            })
            .unwrap_or_else(|| panic!("{scenario}: no payload on {id}"));
        assert_eq!(payload.parsed, want_parsed, "{scenario}: payload parsed");
    }

    if let Some(forbidden) = expected.get("redactionMustNotContain") {
        let text = serde_json::to_string(&redacted_export_projection(&analysis)).unwrap();
        for needle in forbidden.as_array().expect("redactionMustNotContain") {
            let needle = needle.as_str().expect("needle");
            assert!(
                !text.contains(needle),
                "{scenario}: redacted export still contains {needle:?}"
            );
        }
    }

    if let Some(required) = expected.get("redactionMustContain") {
        let text = serde_json::to_string(&redacted_export_projection(&analysis)).unwrap();
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
fn detection_compliant_and_remediation_correctly_skipped() {
    let analysis = assert_scenario("detection-compliant-remediation-skipped");
    // "Skipped" is a stronger claim than "not started": it says detection
    // proved there was nothing to do.
    assert!(analysis.transactions[0].remediation.exit_token.is_none());
}

#[test]
fn remediation_succeeds_and_post_state_is_compliant() {
    assert_scenario("remediation-succeeds-post-state-compliant");
}

#[test]
fn remediation_exits_nonzero() {
    assert_scenario("remediation-exits-nonzero");
}

#[test]
fn detection_launch_failure() {
    assert_scenario("detection-launch-failure");
}

#[test]
fn detection_timeout() {
    assert_scenario("detection-timeout");
}

#[test]
fn remediation_launch_failure() {
    assert_scenario("remediation-launch-failure");
}

#[test]
fn remediation_timeout() {
    assert_scenario("remediation-timeout");
}

#[test]
fn remediation_succeeds_but_post_state_remains_noncompliant() {
    assert_scenario("remediation-succeeds-post-state-noncompliant");
}

#[test]
fn execution_completes_but_report_fails() {
    assert_scenario("execution-completes-report-fails");
}

#[test]
fn scheduled_and_on_demand_runs_stay_separate() {
    let analysis = assert_scenario("scheduled-and-on-demand-kept-separate");
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for transaction in &analysis.transactions {
        for observation in &transaction.observations {
            assert!(
                seen.insert(observation.as_str()),
                "observation {observation} was claimed by two runs"
            );
        }
    }
}

#[test]
fn retry_sequence_lands_on_the_final_attempt() {
    assert_scenario("retry-sequence");
}

#[test]
fn missing_agent_executor_log_is_coverage() {
    assert_scenario("missing-agent-executor");
}

#[test]
fn missing_health_scripts_log_stages_nothing() {
    let analysis = assert_scenario("missing-health-scripts");
    // Without the orchestrator there is no stage, so the exit code in
    // AgentExecutor.log cannot terminate detection or remediation.
    assert!(analysis.transactions.is_empty());
    assert!(analysis
        .observations
        .iter()
        .all(|observation| observation.exit_token.is_none()));
}

#[test]
fn malformed_embedded_payload_is_reported_not_repaired() {
    assert_scenario("malformed-embedded-payload");
}

#[test]
fn rotation_boundary_leaves_an_unkeyed_tail() {
    assert_scenario("rotation-boundary");
}

#[test]
fn same_minute_distinct_policies_stay_separate() {
    assert_scenario("same-minute-distinct-policies");
}

#[test]
fn privacy_fixture_redacts_deterministically() {
    let analysis = assert_scenario("privacy-redaction");
    let first = serde_json::to_string(&redacted_export_projection(&analysis)).unwrap();
    let second = serde_json::to_string(&redacted_export_projection(&analysis)).unwrap();
    assert_eq!(first, second, "redacted export must be deterministic");
}

/// The agent reuses CCM thread numbers. A record that arrives on a reused
/// thread after a run has already reported must not inherit that run's key and
/// overwrite an outcome that was already terminal.
#[test]
fn a_stray_record_on_a_reused_thread_cannot_overwrite_a_reported_run() {
    let analysis = assert_scenario("thread-reuse-after-report");
    assert_eq!(analysis.transactions.len(), 1);
    assert_eq!(
        analysis.unkeyed_observations,
        vec!["hs:5".to_string()],
        "the stray completion must stay visible and unkeyed"
    );
}

/// A detection that failed or timed out ended the run. Remediation is
/// legitimately absent, so it must never be requested -- doing so would
/// contradict the confidence rule that calls these complete stories.
#[test]
fn a_terminal_detection_never_requests_remediation_records() {
    assert_scenario("detection-timeout-with-retained-artifact");
}

/// A completion whose code could not be read proves the stage ran, but it must
/// not erase a result an earlier readable code already established.
#[test]
fn a_later_unreadable_completion_does_not_erase_a_determined_result() {
    let analysis = assert_scenario("later-completion-without-readable-code");
    assert!(analysis.transactions[0].detection.exit_token.is_some());
}

// -- Cross-cutting contract -------------------------------------------------

/// The property the whole module rests on: `0` means "compliant" from
/// detection and "succeeded" from remediation, so a token must always name the
/// stage it came from and must never appear on the other stage.
#[test]
fn exit_tokens_never_cross_stages() {
    for scenario in [
        "remediation-succeeds-post-state-compliant",
        "remediation-exits-nonzero",
        "remediation-succeeds-post-state-noncompliant",
        "retry-sequence",
    ] {
        let (analysis, _) = load_scenario(scenario);
        for transaction in &analysis.transactions {
            if let Some(token) = &transaction.detection.exit_token {
                assert_eq!(
                    token.stage,
                    cmtraceopen_parser::intune::apps::windows::remediations::RemediationStage::Detection,
                    "{scenario}: detection carried a non-detection token"
                );
            }
            if let Some(token) = &transaction.remediation.exit_token {
                assert_eq!(
                    token.stage,
                    cmtraceopen_parser::intune::apps::windows::remediations::RemediationStage::Remediation,
                    "{scenario}: remediation carried a non-remediation token"
                );
            }
        }
    }
}

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

/// A record with no embedded offset must not report a UTC value, because the
/// only one available would come from the parsing machine's timezone. Without
/// this the golden below would differ per developer machine.
#[test]
fn a_record_without_an_offset_reports_no_normalized_utc() {
    let (analysis, _) = load_scenario("detection-compliant-remediation-skipped");
    for observation in &analysis.observations {
        let timestamp = observation.timestamp.as_ref().expect("timestamp");
        assert!(!timestamp.raw_text.is_empty());
        assert_eq!(timestamp.normalized_utc, None);
        assert_eq!(timestamp.original_offset, None);
    }
}

#[test]
fn analysis_serialization_is_camel_case_and_stable() {
    let (analysis, _) = load_scenario("remediation-succeeds-post-state-compliant");
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
        "detection",
        "remediation",
        "postDetection",
        "report",
        "attempts",
        "confidence",
        "payloads",
        "observations",
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
/// Regenerate with `UPDATE_REMEDIATION_GOLDEN=1 cargo test --locked -p
/// cmtraceopen-parser --test intune_windows_remediations` and review the diff.
#[test]
fn redacted_export_matches_the_golden() {
    let (analysis, _) = load_scenario("detection-compliant-remediation-skipped");
    let redacted = redacted_export_projection(&analysis);
    let actual = serde_json::to_string_pretty(&redacted).expect("serialize") + "\n";

    let golden = fixtures_root().join("detection-compliant-remediation-skipped/expected-full.json");
    if std::env::var("UPDATE_REMEDIATION_GOLDEN").is_ok() {
        fs::write(&golden, &actual).expect("write golden");
        return;
    }

    let expected = fs::read_to_string(&golden).expect("golden must exist; see this test's docs");
    assert_eq!(actual, expected, "redacted export golden drifted");
}
