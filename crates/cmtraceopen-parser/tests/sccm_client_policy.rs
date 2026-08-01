use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use cmtraceopen_parser::sccm::{
    analyze_client_policy, declared_source_catalog, normalize_ccm_artifact, SccmArtifact,
    SccmArtifactFamily, SccmCoverageState, SccmNormalizedBundle, SccmRole, SccmRotation,
    SccmTimeOrderingState,
};
use serde::Deserialize;
use serde_json::{json, Value};

const FIXTURE_ROOT: &str = "tests/fixtures/sccm/client/policy";
const SCENARIOS: &[&str] = &[
    "complete",
    "request-auth-failure",
    "download-failure",
    "persist-failure",
    "scheduler-deferred",
    "evaluation-failure",
    "reporting-failure",
    "rotation-split",
    "malformed",
    "incomplete",
    "gate-c-contradictory",
    "recovery",
    "multiline",
    "contradictory-offset",
];

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureManifest {
    artifacts: Vec<FixtureArtifact>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureArtifact {
    artifact_id: String,
    role: String,
    capture_state: String,
    encoding: Option<String>,
    original_basename: String,
    sanitized_source_path: Option<String>,
    rotation: FixtureRotation,
    source_version: Option<String>,
    captured_utc: Option<String>,
    relative_path: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureRotation {
    kind: String,
    value: Option<Value>,
}

fn fixture_directory(scenario: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(FIXTURE_ROOT)
        .join(scenario)
}

fn load_json(path: &Path) -> Value {
    serde_json::from_str(&fs::read_to_string(path).expect("fixture JSON must be readable"))
        .expect("fixture JSON must be valid")
}

fn coverage_state(value: &str) -> SccmCoverageState {
    match value {
        "captured" => SccmCoverageState::Captured,
        "partial" => SccmCoverageState::Partial,
        "absent" => SccmCoverageState::Absent,
        "accessDenied" => SccmCoverageState::AccessDenied,
        "capped" => SccmCoverageState::Capped,
        "skipped" => SccmCoverageState::Skipped,
        "unsupported" => SccmCoverageState::Unsupported,
        "parseFailed" => SccmCoverageState::ParseFailed,
        other => panic!("unsupported fixture coverage state {other}"),
    }
}

fn rotation(value: &FixtureRotation) -> SccmRotation {
    match value.kind.as_str() {
        "current" => SccmRotation::Current,
        "lo" | "loUnderscore" => SccmRotation::LoUnderscore,
        "numbered" => SccmRotation::Numbered(
            value
                .value
                .as_ref()
                .and_then(Value::as_u64)
                .and_then(|number| u32::try_from(number).ok())
                .expect("numbered rotation must contain a u32"),
        ),
        "timestamped" => SccmRotation::Timestamped(
            value
                .value
                .as_ref()
                .and_then(Value::as_str)
                .expect("timestamped rotation must contain a string")
                .to_owned(),
        ),
        other => panic!("unsupported fixture rotation {other}"),
    }
}

fn load_bundle(scenario: &str) -> SccmNormalizedBundle {
    let directory = fixture_directory(scenario);
    let manifest: FixtureManifest =
        serde_json::from_value(load_json(&directory.join("manifest.json")))
            .expect("fixture manifest must match its declared contract");

    let mut artifacts = Vec::new();
    let mut evidence = Vec::new();
    for source in manifest.artifacts {
        assert_eq!(source.role, "client", "policy fixtures must be client-only");
        let artifact = SccmArtifact {
            artifact_id: source.artifact_id,
            display_name: source.original_basename,
            original_path: source.sanitized_source_path,
            host: None,
            role: SccmRole::Client,
            configmgr_version: source.source_version,
            collected_at_utc: source.captured_utc,
            rotation: rotation(&source.rotation),
            coverage: coverage_state(&source.capture_state),
            encoding: source.encoding,
        };

        if let Some(relative_path) = source.relative_path {
            let content = fs::read_to_string(directory.join(relative_path))
                .expect("captured policy evidence must be readable UTF-8");
            evidence.extend(normalize_ccm_artifact(artifact.clone(), &content));
        }
        artifacts.push(artifact);
    }

    artifacts.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
    evidence.sort_by(|left, right| left.evidence_id.cmp(&right.evidence_id));
    SccmNormalizedBundle {
        artifacts,
        evidence,
    }
}

fn expected_transaction_projection(expected: &Value) -> Vec<Value> {
    expected["transactions"]
        .as_array()
        .expect("expected transactions must be an array")
        .iter()
        .map(|transaction| {
            json!({
                "transactionId": transaction["transactionId"],
                "phase": transaction["phase"],
                "state": transaction["state"],
                "lastSuccessfulPhase": transaction["lastSuccessfulPhase"],
                "classification": transaction["classification"],
                "confidence": transaction["confidence"],
                "coverageGapArtifactIds": transaction["coverageGapArtifactIds"],
                "nextArtifactLogicalId": transaction["nextArtifact"]["logicalArtifactId"],
            })
        })
        .collect()
}

fn actual_transaction_projection(analysis: &Value) -> Vec<Value> {
    analysis["transactions"]
        .as_array()
        .expect("analysis transactions must be an array")
        .iter()
        .map(|transaction| {
            json!({
                "transactionId": transaction["transactionId"],
                "phase": transaction["phase"],
                "state": transaction["state"],
                "lastSuccessfulPhase": transaction["lastSuccessfulPhase"],
                "classification": transaction["classification"],
                "confidence": transaction["confidence"],
                "coverageGapArtifactIds": transaction["coverageGapArtifactIds"],
                "nextArtifactLogicalId": transaction["nextArtifacts"]
                    .as_array()
                    .and_then(|requests| requests.first())
                    .map(|request| request["logicalId"].clone())
                    .unwrap_or(Value::Null),
            })
        })
        .collect()
}

fn reference_is_within_expected_ranges(reference: &Value, expected_ranges: &[Value]) -> bool {
    let Some(artifact_id) = reference["artifactId"].as_str() else {
        return false;
    };
    let Some(line_start) = reference["lineStart"].as_u64() else {
        return false;
    };
    let Some(line_end) = reference["lineEnd"].as_u64() else {
        return false;
    };

    expected_ranges.iter().any(|expected_reference| {
        expected_reference["artifactId"].as_str() == Some(artifact_id)
            && expected_reference["startLine"]
                .as_u64()
                .is_some_and(|start| start <= line_start)
            && expected_reference["endLine"]
                .as_u64()
                .is_some_and(|end| line_end <= end)
    })
}

fn assert_transaction_evidence_is_within_expected_ranges(
    scenario: &str,
    analysis: &Value,
    expected: &Value,
) {
    let expected_by_id = expected["transactions"]
        .as_array()
        .expect("expected transactions must be an array")
        .iter()
        .map(|transaction| {
            (
                transaction["transactionId"]
                    .as_str()
                    .expect("expected transaction ID")
                    .to_owned(),
                transaction,
            )
        })
        .collect::<BTreeMap<_, _>>();

    for transaction in analysis["transactions"]
        .as_array()
        .expect("analysis transactions must be an array")
    {
        let transaction_id = transaction["transactionId"]
            .as_str()
            .expect("analysis transaction ID");
        let expected_transaction = expected_by_id
            .get(transaction_id)
            .unwrap_or_else(|| panic!("{scenario}: unexpected transaction {transaction_id}"));
        let expected_ranges = expected_transaction["evidence"]
            .as_array()
            .expect("expected evidence must be an array");

        let mut observed_artifacts = BTreeSet::new();
        for reference in transaction["evidence"]
            .as_array()
            .expect("analysis evidence must be an array")
        {
            let artifact_id = reference["artifactId"]
                .as_str()
                .expect("analysis artifact ID");
            assert!(
                reference_is_within_expected_ranges(reference, expected_ranges),
                "{scenario}: {transaction_id} emitted an uncited range in {artifact_id}"
            );
            observed_artifacts.insert(artifact_id);
        }

        for expected_reference in expected_ranges {
            let artifact_id = expected_reference["artifactId"]
                .as_str()
                .expect("expected artifact ID");
            assert!(
                observed_artifacts.contains(artifact_id),
                "{scenario}: {transaction_id} omitted expected artifact {artifact_id}"
            );
        }
    }
}

fn assert_transaction_keys_and_counterpart_match_contract(
    scenario: &str,
    analysis: &Value,
    expected: &Value,
) {
    let actual_by_id = analysis["transactions"]
        .as_array()
        .expect("analysis transactions")
        .iter()
        .map(|transaction| {
            (
                transaction["transactionId"]
                    .as_str()
                    .expect("transaction ID"),
                transaction,
            )
        })
        .collect::<BTreeMap<_, _>>();

    for expected_transaction in expected["transactions"]
        .as_array()
        .expect("expected transactions")
    {
        let transaction_id = expected_transaction["transactionId"]
            .as_str()
            .expect("expected transaction ID");
        let actual = actual_by_id
            .get(transaction_id)
            .unwrap_or_else(|| panic!("{scenario}: missing transaction {transaction_id}"));
        let expected_key = &expected_transaction["key"];
        assert_eq!(
            actual["key"],
            json!({
                "assignmentId": expected_key["assignmentId"],
                "policyId": expected_key["policyId"],
                "requestId": expected_key["requestId"],
                "clientHandle": expected_key["clientHandle"],
                "siteCode": expected_key["siteCode"],
                "managementPointHostHandle": expected_key["managementPointHostHandle"],
                "extractionProfileId": expected_key["extractionProfileId"],
            }),
            "{scenario}: {transaction_id} key"
        );

        let expected_counterpart = &expected_transaction["counterpartReadyFact"];
        assert_eq!(
            actual["counterpartReadyFact"]["phase"], expected_counterpart["phase"],
            "{scenario}: {transaction_id} counterpart phase"
        );
        assert_eq!(
            actual["counterpartReadyFact"]["extractionProfileId"],
            expected_counterpart["extractionProfileId"],
            "{scenario}: {transaction_id} counterpart profile"
        );
        assert!(
            reference_is_within_expected_ranges(
                &actual["counterpartReadyFact"]["evidence"],
                std::slice::from_ref(&expected_counterpart["evidence"]),
            ),
            "{scenario}: {transaction_id} counterpart evidence"
        );
    }
}

fn source_local_projection(value: &Value, next_field: &str) -> Vec<Value> {
    value["sourceLocalObservations"]
        .as_array()
        .expect("source-local observations")
        .iter()
        .map(|observation| {
            let next_logical_id = if next_field == "nextArtifact" {
                observation["nextArtifact"]["logicalArtifactId"].clone()
            } else {
                observation["nextArtifacts"]
                    .as_array()
                    .and_then(|requests| requests.first())
                    .map(|request| request["logicalId"].clone())
                    .unwrap_or(Value::Null)
            };
            json!({
                "observationId": observation["observationId"],
                "phase": observation["phase"],
                "state": observation["state"],
                "classification": observation["classification"],
                "confidence": observation["confidence"],
                "correlationEligible": observation["correlationEligible"],
                "nextArtifactLogicalId": next_logical_id,
            })
        })
        .collect()
}

fn assert_source_local_evidence_is_within_expected_ranges(
    scenario: &str,
    analysis: &Value,
    expected: &Value,
) {
    let actual_by_id = analysis["sourceLocalObservations"]
        .as_array()
        .expect("source-local observations")
        .iter()
        .map(|observation| {
            (
                observation["observationId"]
                    .as_str()
                    .expect("observation ID"),
                observation,
            )
        })
        .collect::<BTreeMap<_, _>>();

    for expected_observation in expected["sourceLocalObservations"]
        .as_array()
        .expect("expected source-local observations")
    {
        let observation_id = expected_observation["observationId"]
            .as_str()
            .expect("expected observation ID");
        let actual = actual_by_id
            .get(observation_id)
            .unwrap_or_else(|| panic!("{scenario}: missing observation {observation_id}"));
        let expected_ranges = expected_observation["evidence"]
            .as_array()
            .expect("expected observation evidence");
        let actual_references = actual["evidence"].as_array().expect("observation evidence");
        assert!(
            actual_references
                .iter()
                .all(|reference| reference_is_within_expected_ranges(reference, expected_ranges)),
            "{scenario}: {observation_id} emitted uncited evidence"
        );
        for expected_reference in expected_ranges {
            assert!(
                actual_references.iter().any(|reference| {
                    reference["artifactId"] == expected_reference["artifactId"]
                }),
                "{scenario}: {observation_id} omitted expected evidence"
            );
        }
    }
}

fn finding_signature(class: &str, confidence: &str, next_group: Option<&str>) -> String {
    format!("{class}|{confidence}|{}", next_group.unwrap_or("<none>"))
}

fn expected_finding_signatures(expected: &Value) -> Vec<String> {
    let mut signatures = expected["findings"]
        .as_array()
        .expect("expected findings")
        .iter()
        .map(|finding| {
            let class = match finding["class"].as_str().expect("finding class") {
                "contradictoryEvidence" | "lowConfidenceSymptom" => "symptom",
                class => class,
            };
            let confidence = match finding["confidence"].as_str().expect("finding confidence") {
                "medium" => "moderate",
                confidence => confidence,
            };
            finding_signature(
                class,
                confidence,
                finding["nextArtifact"]["logicalArtifactId"].as_str(),
            )
        })
        .collect::<Vec<_>>();
    signatures.sort();
    signatures
}

fn actual_finding_signatures(analysis: &Value) -> Vec<String> {
    let mut signatures = analysis["findings"]
        .as_array()
        .expect("analysis findings")
        .iter()
        .map(|finding| {
            assert_eq!(finding["phase"], "policy");
            assert_eq!(finding["role"], "client");
            let mut groups = finding["nextArtifacts"]
                .as_array()
                .expect("finding requests")
                .iter()
                .filter_map(|request| match request["logicalId"].as_str()? {
                    "clientLocation" => Some("client-location"),
                    "policyAgent" => Some("client-policy-agent"),
                    "ciAgent" | "stateMessage" => Some("client-policy-state"),
                    _ => None,
                })
                .collect::<BTreeSet<_>>();
            assert!(groups.len() <= 1, "one finding requested unrelated groups");
            finding_signature(
                finding["class"].as_str().expect("finding class"),
                finding["confidence"].as_str().expect("finding confidence"),
                groups.pop_first(),
            )
        })
        .collect::<Vec<_>>();
    signatures.sort();
    signatures
}

fn assert_findings_are_cited_and_conservative(analysis: &Value) {
    for finding in analysis["findings"].as_array().expect("analysis findings") {
        let evidence = finding["evidence"].as_array().expect("finding evidence");
        let terminal = finding["terminalEvidence"]
            .as_array()
            .expect("terminal evidence");
        let gaps = finding["coverageGaps"]
            .as_array()
            .expect("finding coverage gaps");
        let requests = finding["nextArtifacts"]
            .as_array()
            .expect("finding requests");

        for terminal_reference in terminal {
            assert!(
                evidence.contains(&terminal_reference["reference"]),
                "terminal evidence must also be cited"
            );
        }
        match finding["class"].as_str().expect("finding class") {
            "confirmedFailure" if finding["confidence"] == "high" => {
                assert!(
                    !terminal.is_empty(),
                    "high confirmed failure needs terminal evidence"
                );
            }
            "insufficientEvidence" => {
                assert!(!gaps.is_empty(), "insufficient evidence needs a gap");
                assert!(
                    !requests.is_empty(),
                    "insufficient evidence needs a request"
                );
            }
            _ => {}
        }
    }
}

#[test]
fn policy_reducer_matches_the_frozen_terminal_and_coverage_contracts() {
    for scenario in SCENARIOS {
        let directory = fixture_directory(scenario);
        let expected = load_json(&directory.join("expected.json"));
        let analysis = serde_json::to_value(analyze_client_policy(&load_bundle(scenario)))
            .expect("policy analysis must serialize");

        assert_eq!(analysis["schemaVersion"], 1, "{scenario}");
        assert_eq!(analysis["workflow"], "policy", "{scenario}");
        assert_eq!(
            actual_transaction_projection(&analysis),
            expected_transaction_projection(&expected),
            "{scenario}"
        );
        assert_transaction_evidence_is_within_expected_ranges(scenario, &analysis, &expected);
        assert_transaction_keys_and_counterpart_match_contract(scenario, &analysis, &expected);

        assert_eq!(
            source_local_projection(&analysis, "nextArtifacts"),
            source_local_projection(&expected, "nextArtifact"),
            "{scenario}"
        );
        assert_source_local_evidence_is_within_expected_ranges(scenario, &analysis, &expected);
        assert_eq!(
            analysis["findings"]
                .as_array()
                .expect("analysis findings")
                .len(),
            expected["findings"]
                .as_array()
                .expect("expected findings")
                .len(),
            "{scenario}"
        );
        assert_eq!(
            actual_finding_signatures(&analysis),
            expected_finding_signatures(&expected),
            "{scenario}: finding semantics"
        );
        assert_findings_are_cited_and_conservative(&analysis);
        assert!(
            !serde_json::to_string(&analysis)
                .expect("analysis JSON")
                .to_ascii_lowercase()
                .contains("root cause"),
            "{scenario}: client-only output must not claim an MP root cause"
        );
    }
}

#[test]
fn policy_analysis_is_deterministic_under_bundle_reordering() {
    for scenario in SCENARIOS {
        let bundle = load_bundle(scenario);
        let expected =
            serde_json::to_string(&analyze_client_policy(&bundle)).expect("analysis JSON");

        let mut reordered = bundle.clone();
        reordered.artifacts.reverse();
        reordered.evidence.reverse();
        let actual =
            serde_json::to_string(&analyze_client_policy(&reordered)).expect("analysis JSON");
        assert_eq!(actual, expected, "{scenario}");
    }
}

fn combine_bundles(
    mut left: SccmNormalizedBundle,
    mut right: SccmNormalizedBundle,
) -> SccmNormalizedBundle {
    left.artifacts.append(&mut right.artifacts);
    left.evidence.append(&mut right.evidence);
    left.artifacts
        .sort_by(|a, b| a.artifact_id.cmp(&b.artifact_id));
    left.evidence
        .sort_by(|a, b| a.evidence_id.cmp(&b.evidence_id));
    left
}

#[test]
fn policy_failure_requires_a_nonzero_terminal_result() {
    let mut bundle = load_bundle("request-auth-failure");
    let failed = bundle
        .evidence
        .iter_mut()
        .find(|evidence| evidence.message.contains("failed terminal"))
        .expect("request failure evidence");
    failed.message = failed.message.replace("Result=0x80070005", "Status=0");

    let analysis = serde_json::to_value(analyze_client_policy(&bundle)).expect("analysis JSON");
    assert!(
        analysis["transactions"]
            .as_array()
            .expect("transactions")
            .is_empty(),
        "a successful status token cannot substantiate a terminal failure"
    );
    assert_eq!(
        analysis["sourceLocalObservations"][0]["correlationEligible"],
        false
    );
}

#[test]
fn policy_cross_artifact_phase_time_inversion_is_contradictory() {
    let mut bundle = load_bundle("complete");
    let request_utc = bundle
        .evidence
        .iter()
        .find(|evidence| evidence.message.contains("Request succeeded"))
        .and_then(|evidence| evidence.timestamp.utc_millis)
        .expect("request UTC");
    let report = bundle
        .evidence
        .iter_mut()
        .find(|evidence| evidence.message.contains("Report succeeded"))
        .expect("report evidence");
    report.timestamp.utc_millis = Some(request_utc - 1);

    let analysis = serde_json::to_value(analyze_client_policy(&bundle)).expect("analysis JSON");
    let transaction = &analysis["transactions"][0];
    assert_eq!(transaction["state"], "contradictory");
    assert_eq!(transaction["classification"], "contradictoryEvidence");
    assert_eq!(transaction["confidence"], "low");
}

#[test]
fn policy_missing_or_unknown_profile_never_emits_an_exact_transaction() {
    for version in [None, Some("5.00.CALLER.0000")] {
        let mut bundle = load_bundle("complete");
        for artifact in &mut bundle.artifacts {
            artifact.configmgr_version = version.map(str::to_owned);
        }

        let analysis = serde_json::to_value(analyze_client_policy(&bundle)).expect("analysis JSON");
        assert!(
            analysis["transactions"]
                .as_array()
                .expect("transactions")
                .is_empty(),
            "{version:?} must not emit an exact transaction"
        );
        assert!(analysis["sourceLocalObservations"]
            .as_array()
            .expect("source-local observations")
            .iter()
            .all(|observation| observation["correlationEligible"] == false));
    }
}

#[test]
fn policy_unsafe_client_handle_is_rejected_and_not_exported() {
    let mut bundle = load_bundle("complete");
    let request = bundle
        .evidence
        .iter_mut()
        .find(|evidence| evidence.message.contains("Request succeeded"))
        .expect("request evidence");
    request.message = request
        .message
        .replace("safe:client:policy-11", "Adam.Gell");
    for artifact in &mut bundle.artifacts {
        artifact.original_path = Some(r"C:\Users\Adam.Gell\PolicyAgent.log".to_owned());
    }

    let serialized = serde_json::to_string(&analyze_client_policy(&bundle)).expect("analysis JSON");
    assert!(!serialized.contains("Adam.Gell"));
    let analysis: Value = serde_json::from_str(&serialized).expect("analysis value");
    assert!(analysis["transactions"]
        .as_array()
        .expect("transactions")
        .is_empty());
}

#[test]
fn policy_partial_required_source_never_proves_success() {
    let mut bundle = load_bundle("complete");
    let state_artifact = bundle
        .artifacts
        .iter_mut()
        .find(|artifact| artifact.display_name == "StateMessage.log")
        .expect("state-message artifact");
    state_artifact.coverage = SccmCoverageState::Partial;

    let analysis = serde_json::to_value(analyze_client_policy(&bundle)).expect("analysis JSON");
    let transaction = &analysis["transactions"][0];
    assert_ne!(transaction["state"], "succeeded");
    assert_ne!(transaction["confidence"], "high");
    assert!(analysis["coverageGaps"]
        .as_array()
        .expect("coverage gaps")
        .iter()
        .any(|gap| gap["coverage"] == "partial"));
}

#[test]
fn policy_unrelated_assignment_failure_does_not_change_the_target() {
    let bundle = combine_bundles(load_bundle("complete"), load_bundle("download-failure"));
    let analysis = serde_json::to_value(analyze_client_policy(&bundle)).expect("analysis JSON");
    let transactions = analysis["transactions"].as_array().expect("transactions");
    assert_eq!(transactions.len(), 2);

    let complete = transactions
        .iter()
        .find(|transaction| {
            transaction["transactionId"] == "policy:assignment:11111111-1111-1111-1111-111111111111"
        })
        .expect("complete transaction");
    assert_eq!(complete["state"], "succeeded");
    assert_eq!(complete["confidence"], "high");
}

#[test]
fn policy_same_timestamp_different_keys_stay_separate() {
    let mut bundle = combine_bundles(load_bundle("complete"), load_bundle("download-failure"));
    for evidence in &mut bundle.evidence {
        evidence.timestamp.utc_millis = Some(1_785_379_200_000);
    }

    let analysis = serde_json::to_value(analyze_client_policy(&bundle)).expect("analysis JSON");
    let transaction_ids = analysis["transactions"]
        .as_array()
        .expect("transactions")
        .iter()
        .map(|transaction| {
            transaction["transactionId"]
                .as_str()
                .expect("transaction ID")
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(transaction_ids.len(), 2);
}

#[test]
fn policy_output_contains_no_raw_messages_paths_or_execution_context() {
    let bundle = load_bundle("complete");
    let serialized = serde_json::to_string(&analyze_client_policy(&bundle)).expect("analysis JSON");
    for prohibited in [
        "SYNTHETIC FIXTURE",
        "synthetic.cc",
        "SYNTHETIC://",
        "executionContext",
        "Request succeeded",
    ] {
        assert!(
            !serialized.contains(prohibited),
            "public analysis leaked {prohibited}"
        );
    }
}

#[test]
fn policy_catalog_declares_the_state_sources_used_by_the_reducer() {
    let policy_sources = declared_source_catalog()
        .into_iter()
        .filter(|source| {
            source.role == SccmRole::Client && source.family == SccmArtifactFamily::ClientPolicy
        })
        .map(|source| (source.basename, source.logical_name))
        .collect::<BTreeSet<_>>();

    for expected in [
        ("CIAgent.log", "ciAgent"),
        ("CIDownloader.log", "ciDownloader"),
        ("StateMessage.log", "stateMessage"),
        ("StatusAgent.log", "statusAgent"),
    ] {
        let expected = (expected.0.to_owned(), expected.1.to_owned());
        assert!(
            policy_sources.contains(&expected),
            "missing policy source {expected:?}"
        );
    }
}

#[test]
fn policy_phase_from_the_wrong_source_is_only_a_local_observation() {
    let mut bundle = load_bundle("complete");
    let evaluate_artifact = bundle
        .artifacts
        .iter_mut()
        .find(|artifact| artifact.display_name == "CIAgent.log")
        .expect("evaluation artifact");
    evaluate_artifact.display_name = "StateMessage.log".to_owned();

    let analysis = serde_json::to_value(analyze_client_policy(&bundle)).expect("analysis JSON");
    let transaction = &analysis["transactions"][0];
    assert_eq!(transaction["state"], "incomplete");
    assert_ne!(transaction["confidence"], "high");
    assert!(analysis["sourceLocalObservations"]
        .as_array()
        .expect("source-local observations")
        .iter()
        .all(|observation| observation["correlationEligible"] == false));
}

fn request_message_mutation(scenario: &str, mutate: impl Fn(&str) -> String) -> Value {
    let mut bundle = load_bundle(scenario);
    let request = bundle
        .evidence
        .iter_mut()
        .find(|evidence| evidence.message.contains("Request succeeded"))
        .expect("request evidence");
    request.message = mutate(&request.message);
    serde_json::to_value(analyze_client_policy(&bundle)).expect("analysis JSON")
}

#[test]
fn policy_duplicate_required_key_labels_never_emit_an_exact_transaction() {
    for (label, equivalent, conflicting) in [
        (
            "AssignmentId",
            "AssignmentId={11111111-1111-1111-1111-111111111111}",
            "AssignmentId={99999999-9999-9999-9999-999999999999}",
        ),
        (
            "PolicyId",
            "PolicyId={aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}",
            "PolicyId={99999999-9999-9999-9999-999999999999}",
        ),
        (
            "RequestId",
            "RequestId={27111111-1111-1111-1111-111111111111}",
            "RequestId={99999999-9999-9999-9999-999999999999}",
        ),
        (
            "ClientHandle",
            "ClientHandle=safe:client:policy-11",
            "ClientHandle=safe:client:policy-99",
        ),
        ("SiteCode", "SiteCode=LAB", "SiteCode=ZZZ"),
        (
            "SelectedManagementPointHostHandle",
            "SelectedManagementPointHostHandle=safe:mp:lab-mp-01",
            "SelectedManagementPointHostHandle=safe:mp:lab-mp-99",
        ),
    ] {
        for duplicate in [equivalent, conflicting] {
            let analysis =
                request_message_mutation("complete", |message| format!("{message} {duplicate}"));
            assert!(
                analysis["transactions"]
                    .as_array()
                    .expect("transactions")
                    .is_empty(),
                "a duplicated {label} label must fail closed, not resolve by first match"
            );
        }
    }
}

#[test]
fn policy_embedded_key_labels_are_never_admitted_as_required_keys() {
    let analysis = request_message_mutation("complete", |message| {
        message.replace("RequestId=", "NotRequestId=")
    });
    assert!(
        analysis["transactions"]
            .as_array()
            .expect("transactions")
            .is_empty(),
        "NotRequestId must not satisfy the required RequestId key"
    );
}

#[test]
fn policy_compound_phase_markers_are_never_exact_phase_evidence() {
    let analysis = request_message_mutation("complete", |message| {
        message.replace("Request succeeded", "not-Request succeeded-ish")
    });
    assert!(
        analysis["transactions"]
            .as_array()
            .expect("transactions")
            .is_empty(),
        "a compound marker must not be admitted as an exact phase outcome"
    );
}

fn analysis_json(bundle: &SccmNormalizedBundle) -> Value {
    serde_json::to_value(analyze_client_policy(bundle)).expect("analysis JSON")
}

fn reversed_bundle(bundle: &SccmNormalizedBundle) -> SccmNormalizedBundle {
    let mut reversed = bundle.clone();
    reversed.artifacts.reverse();
    reversed.evidence.reverse();
    reversed
}

#[test]
fn policy_conflicting_facts_at_one_evidence_identity_are_quarantined() {
    let mut bundle = load_bundle("complete");
    let report = bundle
        .evidence
        .iter()
        .find(|evidence| evidence.message.contains("Report succeeded"))
        .cloned()
        .expect("report evidence");

    let mut collision = report.clone();
    collision.message = collision.message.replace(
        "Report succeeded",
        "Report failed terminal Result=0x80070005",
    );
    assert_eq!(
        collision.reference, report.reference,
        "the probe must reuse one logical evidence identity"
    );
    bundle.evidence.push(collision);

    let forward = analysis_json(&bundle);
    let reversed = analysis_json(&reversed_bundle(&bundle));
    assert_eq!(
        forward, reversed,
        "opposite terminal facts at one evidence identity must not be resolved by input order"
    );

    let transaction = &forward["transactions"][0];
    assert_ne!(transaction["state"], "succeeded");
    assert_ne!(transaction["state"], "failed");
    assert_ne!(transaction["confidence"], "high");
}

#[test]
fn policy_later_same_artifact_success_recovers_a_deferred_phase() {
    let mut bundle = load_bundle("complete");
    let scheduled = bundle
        .evidence
        .iter_mut()
        .find(|evidence| evidence.message.contains("Schedule succeeded"))
        .expect("schedule evidence");
    let deferred_millis = scheduled
        .timestamp
        .utc_millis
        .map(|millis| millis - 1_000)
        .expect("schedule UTC");
    scheduled.reference.line_start = Some(2);
    scheduled.reference.line_end = Some(2);
    let mut deferred = scheduled.clone();

    deferred.message = deferred
        .message
        .replace("Schedule succeeded", "Schedule deferred");
    deferred.evidence_id = format!("{}:deferred", deferred.evidence_id);
    deferred.reference.entry_id = format!("{}:deferred", deferred.reference.entry_id);
    deferred.reference.line_start = Some(1);
    deferred.reference.line_end = Some(1);
    deferred.timestamp.utc_millis = Some(deferred_millis);
    bundle.evidence.push(deferred);

    let forward = analysis_json(&bundle);
    assert_eq!(
        forward,
        analysis_json(&reversed_bundle(&bundle)),
        "same-artifact recovery must not depend on input order"
    );

    let transaction = &forward["transactions"][0];
    assert_eq!(transaction["state"], "succeeded");
    assert_eq!(transaction["lastSuccessfulPhase"], "report");
    assert_eq!(transaction["confidence"], "high");
}

#[test]
fn policy_unusable_cross_artifact_time_never_proves_an_ordered_sequence() {
    for ordering_state in [
        SccmTimeOrderingState::OffsetInvalid,
        SccmTimeOrderingState::OffsetMissing,
        SccmTimeOrderingState::TimestampMissing,
    ] {
        let mut bundle = load_bundle("complete");
        for evidence in &mut bundle.evidence {
            evidence.timestamp.utc_millis = None;
            evidence.timestamp.ordering_state = ordering_state.clone();
        }

        let analysis = analysis_json(&bundle);
        let transaction = &analysis["transactions"][0];
        assert_ne!(
            transaction["state"], "succeeded",
            "{ordering_state:?} cannot prove an ordered request-to-report path"
        );
        assert_ne!(
            transaction["confidence"], "high",
            "{ordering_state:?} cannot carry high confidence"
        );
        assert_eq!(
            transaction["lastSuccessfulPhase"],
            Value::Null,
            "{ordering_state:?} cannot claim a last successful phase across sources"
        );
        let requests = analysis["artifactRequests"]
            .as_array()
            .expect("artifact requests");
        assert_eq!(
            requests.len(),
            1,
            "{ordering_state:?} must ask once, for the earliest source that broke the chain"
        );
        assert_eq!(requests[0]["logicalId"], "client-policy-agent");
        assert!(
            requests[0]["reason"]
                .as_str()
                .expect("request reason")
                .contains("timestamp offset"),
            "the request must name unusable time provenance, not a missing phase, got {:?}",
            requests[0]["reason"]
        );

        // A finding never mixes unrelated logical groups.
        for finding in analysis["findings"].as_array().expect("findings") {
            let groups = finding["nextArtifacts"]
                .as_array()
                .expect("finding requests")
                .iter()
                .filter_map(|request| match request["logicalId"].as_str()? {
                    "clientLocation" => Some("client-location"),
                    "policyAgent" => Some("client-policy-agent"),
                    "ciAgent" | "stateMessage" => Some("client-policy-state"),
                    _ => None,
                })
                .collect::<BTreeSet<_>>();
            assert!(
                groups.len() <= 1,
                "{ordering_state:?}: one finding requested unrelated groups {groups:?}"
            );
        }
    }
}

#[test]
fn policy_same_artifact_sequence_survives_unusable_time() {
    let mut bundle = load_bundle("download-failure");
    for evidence in &mut bundle.evidence {
        evidence.timestamp.utc_millis = None;
        evidence.timestamp.ordering_state = SccmTimeOrderingState::OffsetInvalid;
    }

    let analysis = analysis_json(&bundle);
    let transaction = &analysis["transactions"][0];
    assert_eq!(
        transaction["state"], "failed",
        "source-local order still orders a single-artifact sequence"
    );
    assert_eq!(transaction["classification"], "confirmedFailure");
}

#[test]
fn policy_captured_sibling_never_erases_an_explicit_coverage_gap() {
    for (state, expected) in [
        (SccmCoverageState::AccessDenied, "accessDenied"),
        (SccmCoverageState::Capped, "capped"),
        (SccmCoverageState::Skipped, "skipped"),
        (SccmCoverageState::Unsupported, "unsupported"),
        (SccmCoverageState::ParseFailed, "parseFailed"),
        (SccmCoverageState::Absent, "absent"),
    ] {
        let mut bundle = load_bundle("complete");
        let report = bundle
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.display_name == "StateMessage.log")
            .expect("state-message artifact");
        let report_id = report.artifact_id.clone();
        report.coverage = state.clone();

        // The CIAgent sibling in the same logical group stays captured.
        let analysis = analysis_json(&bundle);
        let gaps = analysis["coverageGaps"]
            .as_array()
            .expect("coverage gaps")
            .clone();

        assert!(
            gaps.iter()
                .any(|gap| gap["artifactId"] == report_id.as_str() && gap["coverage"] == expected),
            "{state:?} must stay observable on its own source, got {gaps:?}"
        );
        assert!(
            !gaps.iter().any(|gap| gap["coverage"] == "partial"),
            "{state:?} must not be replaced by a synthesized partial gap"
        );
    }
}

#[test]
fn policy_cross_role_artifact_id_collision_never_admits_by_vector_order() {
    let mut bundle = load_bundle("complete");
    let mut shadow = bundle
        .artifacts
        .iter()
        .find(|artifact| artifact.display_name == "PolicyAgent.log")
        .cloned()
        .expect("policy agent artifact");
    shadow.role = SccmRole::ManagementPoint;
    shadow.display_name = "mpcontrol.log".to_owned();
    bundle.artifacts.push(shadow);

    let forward = analysis_json(&bundle);
    assert_eq!(
        forward,
        analysis_json(&reversed_bundle(&bundle)),
        "an out-of-scope artifact reusing a client artifact id must not decide admission by order"
    );

    let transaction = &forward["transactions"][0];
    assert_eq!(
        transaction["state"], "succeeded",
        "the client artifact keeps its own evidence"
    );
    assert_eq!(transaction["confidence"], "high");
}

#[test]
fn policy_recovery_requires_the_same_validated_assignment_key() {
    let mut bundle = load_bundle("recovery");
    let later_success = bundle
        .evidence
        .iter_mut()
        .find(|evidence| evidence.message.contains("Download succeeded"))
        .expect("recovery success");
    later_success.message = later_success.message.replace(
        "23232323-2323-2323-2323-232323232323",
        "33333333-3333-3333-3333-333333333333",
    );

    let analysis = serde_json::to_value(analyze_client_policy(&bundle)).expect("analysis JSON");
    let failed = analysis["transactions"]
        .as_array()
        .expect("transactions")
        .iter()
        .find(|transaction| {
            transaction["transactionId"] == "policy:assignment:23232323-2323-2323-2323-232323232323"
        })
        .expect("original assignment transaction");
    assert_eq!(failed["state"], "failed");
    assert_eq!(failed["classification"], "confirmedFailure");
}
