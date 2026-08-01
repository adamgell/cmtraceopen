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
fn policy_duplicate_key_labels_are_ambiguous_after_any_non_word_character() {
    // A left word boundary is not the value-terminator set. Every character
    // that cannot be part of a label must start a countable occurrence.
    for prefix in [
        '[', '(', '=', '/', '#', '|', '{', '*', '@', '!', '+', ':', ')', '}', '"', '\'', ',', ';',
        ']', '<', ' ',
    ] {
        let analysis = request_message_mutation("complete", |message| {
            format!("{message} context={prefix}RequestId={{99999999-9999-9999-9999-999999999999}}")
        });
        assert!(
            analysis["transactions"]
                .as_array()
                .expect("transactions")
                .is_empty(),
            "a second RequestId after {prefix:?} must be counted as ambiguity"
        );
    }
}

#[test]
fn policy_word_characters_never_start_a_key_label() {
    // The mirror of the case above: a label welded onto a preceding word is
    // not an occurrence, so it must not be counted as ambiguity either.
    for prefix in ["Not", "caf\u{e9}", "sub_", "sub-", "9"] {
        let analysis = request_message_mutation("complete", |message| {
            format!("{message} {prefix}RequestId={{99999999-9999-9999-9999-999999999999}}")
        });
        assert_eq!(
            analysis["transactions"]
                .as_array()
                .expect("transactions")
                .len(),
            1,
            "{prefix}RequestId is not an occurrence of RequestId"
        );
    }
}

#[test]
fn policy_phase_markers_respect_multibyte_word_characters() {
    let analysis = request_message_mutation("complete", |message| {
        message.replace("Request succeeded", "caf\u{e9}Request succeeded")
    });
    assert!(
        analysis["transactions"]
            .as_array()
            .expect("transactions")
            .is_empty(),
        "a marker welded onto a multibyte word is not an exact marker"
    );
}

#[test]
fn policy_phase_markers_still_match_before_sentence_punctuation() {
    let analysis = request_message_mutation("complete", |message| {
        message.replace("Request succeeded", "Request succeeded.")
    });
    assert_eq!(
        analysis["transactions"][0]["state"], "succeeded",
        "a trailing period separates the marker, it does not extend the word"
    );
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

fn out_of_scope_sibling(basename: &str, coverage: SccmCoverageState) -> SccmArtifact {
    SccmArtifact {
        artifact_id: format!("out-of-scope-{basename}"),
        display_name: basename.to_owned(),
        original_path: None,
        host: None,
        role: SccmRole::ManagementPoint,
        configmgr_version: Some("5.00.TEST.0000".to_owned()),
        collected_at_utc: None,
        rotation: SccmRotation::Current,
        coverage,
        encoding: Some("utf-8".to_owned()),
    }
}

#[test]
fn policy_out_of_scope_artifact_never_answers_a_client_coverage_question() {
    let baseline = analysis_json(&load_bundle("request-auth-failure"));
    let baseline_transaction = baseline["transactions"][0].clone();
    let baseline_gaps = baseline["coverageGaps"].clone();
    let baseline_requests = baseline["artifactRequests"].clone();
    assert_eq!(
        baseline_transaction["confidence"], "medium",
        "the client-only bundle is capped by its own missing client-location"
    );

    // A captured out-of-scope sibling must not answer the question, and an
    // unavailable one must not invent a gap the client bundle never had.
    for coverage in [SccmCoverageState::Captured, SccmCoverageState::AccessDenied] {
        let mut bundle = load_bundle("request-auth-failure");
        bundle.artifacts.push(out_of_scope_sibling(
            "LocationServices.log",
            coverage.clone(),
        ));

        let analysis = analysis_json(&bundle);
        assert_eq!(
            analysis["transactions"][0], baseline_transaction,
            "{coverage:?} out-of-scope sibling changed the client verdict"
        );
        assert_eq!(
            analysis["coverageGaps"], baseline_gaps,
            "{coverage:?} out-of-scope sibling changed the client coverage gaps"
        );
        assert_eq!(
            analysis["artifactRequests"], baseline_requests,
            "{coverage:?} out-of-scope sibling changed the client artifact requests"
        );
    }
}

#[test]
fn policy_duplicate_client_artifact_id_is_never_resolved_by_vector_order() {
    let mut bundle = load_bundle("complete");
    let mut clash = bundle
        .artifacts
        .iter()
        .find(|artifact| artifact.display_name == "PolicyAgent.log")
        .cloned()
        .expect("policy agent artifact");
    // Same role, same id, different identity: the map cannot pick an authority.
    clash.display_name = "CIDownloader.log".to_owned();
    clash.coverage = SccmCoverageState::AccessDenied;
    bundle.artifacts.push(clash);

    let forward = analysis_json(&bundle);
    assert_eq!(
        forward,
        analysis_json(&reversed_bundle(&bundle)),
        "a duplicate client artifact id must not be resolved by vector order"
    );

    let transactions = forward["transactions"].as_array().expect("transactions");
    assert!(
        transactions
            .iter()
            .all(|transaction| transaction["confidence"] != "high"),
        "an ambiguous artifact id cannot authorize a high-confidence verdict"
    );
    assert!(
        !forward["sourceLocalObservations"]
            .as_array()
            .expect("source-local observations")
            .is_empty(),
        "the ambiguous id must stay observable rather than vanish"
    );
}

#[test]
fn policy_identical_duplicate_client_artifact_entries_are_harmless() {
    let mut bundle = load_bundle("complete");
    let twin = bundle
        .artifacts
        .iter()
        .find(|artifact| artifact.display_name == "PolicyAgent.log")
        .cloned()
        .expect("policy agent artifact");
    bundle.artifacts.push(twin);

    let analysis = analysis_json(&bundle);
    assert_eq!(
        analysis["transactions"][0]["state"], "succeeded",
        "an exactly repeated artifact entry is not an ambiguity"
    );
    assert_eq!(analysis["transactions"][0]["confidence"], "high");
}

fn unavailable_client_sibling(basename: &str, coverage: SccmCoverageState) -> SccmArtifact {
    SccmArtifact {
        artifact_id: format!("policy-complete-sibling-{basename}"),
        display_name: basename.to_owned(),
        original_path: None,
        host: None,
        role: SccmRole::Client,
        configmgr_version: Some("5.00.TEST.0000".to_owned()),
        collected_at_utc: None,
        rotation: SccmRotation::Current,
        coverage,
        encoding: Some("utf-8".to_owned()),
    }
}

#[test]
fn policy_unavailable_sibling_stays_observable_when_the_chain_succeeds() {
    for (coverage, expected) in [
        (SccmCoverageState::AccessDenied, "accessDenied"),
        (SccmCoverageState::Capped, "capped"),
        (SccmCoverageState::Skipped, "skipped"),
        (SccmCoverageState::Unsupported, "unsupported"),
        (SccmCoverageState::ParseFailed, "parseFailed"),
        (SccmCoverageState::Partial, "partial"),
        (SccmCoverageState::Absent, "absent"),
    ] {
        let mut bundle = load_bundle("complete");
        let sibling = unavailable_client_sibling("StatusAgent.log", coverage.clone());
        let sibling_id = sibling.artifact_id.clone();
        bundle.artifacts.push(sibling);

        let analysis = analysis_json(&bundle);
        // The transaction still succeeds; the gap is a non-outcome, not a veto.
        assert_eq!(
            analysis["transactions"][0]["state"], "succeeded",
            "{coverage:?} sibling must not veto a proven chain"
        );
        let gaps = analysis["coverageGaps"]
            .as_array()
            .expect("coverage gaps")
            .clone();
        assert!(
            gaps.iter()
                .any(|gap| gap["artifactId"] == sibling_id.as_str() && gap["coverage"] == expected),
            "{coverage:?} must remain observable even when nothing failed, got {gaps:?}"
        );
    }
}

#[test]
fn policy_fully_captured_bundle_reports_no_coverage_gap() {
    let analysis = analysis_json(&load_bundle("complete"));
    assert_eq!(analysis["transactions"][0]["state"], "succeeded");
    assert!(
        analysis["coverageGaps"]
            .as_array()
            .expect("coverage gaps")
            .is_empty(),
        "a fully captured bundle must not invent a gap"
    );
}

fn request_reasons(analysis: &Value) -> Vec<String> {
    analysis["artifactRequests"]
        .as_array()
        .expect("artifact requests")
        .iter()
        .map(|request| {
            request["reason"]
                .as_str()
                .expect("request reason")
                .to_owned()
        })
        .collect()
}

#[test]
fn policy_missing_phase_is_never_requested_as_a_deferred_retry() {
    let mut bundle = load_bundle("complete");
    bundle
        .evidence
        .retain(|evidence| !evidence.message.contains("Schedule succeeded"));

    let analysis = analysis_json(&bundle);
    assert_eq!(analysis["transactions"][0]["state"], "incomplete");
    let reasons = request_reasons(&analysis);
    assert!(
        !reasons.is_empty(),
        "a missing phase must still ask for the source"
    );
    assert!(
        reasons.iter().all(|reason| !reason.contains("deferred")),
        "nothing is deferred when the phase is absent, got {reasons:?}"
    );
}

#[test]
fn policy_deferred_phase_still_asks_for_the_deferred_retry() {
    let reasons = request_reasons(&analysis_json(&load_bundle("scheduler-deferred")));
    assert!(
        reasons.iter().any(|reason| reason.contains("deferred")),
        "a genuinely deferred phase keeps its own wording, got {reasons:?}"
    );
}

#[test]
fn policy_time_contradiction_asks_for_usable_timestamps() {
    let reasons = request_reasons(&analysis_json(&load_bundle("contradictory-offset")));
    assert!(
        reasons
            .iter()
            .any(|reason| reason.contains("timestamp offset")),
        "a contradiction caused by unusable time must ask for usable time, got {reasons:?}"
    );
}

#[test]
fn policy_non_failure_marker_with_a_terminal_result_is_never_phase_evidence() {
    // The mirror of `policy_failure_requires_a_nonzero_terminal_result`. A
    // marker and an explicit terminal code that disagree cannot both be read.
    for (marker, terminal) in [
        ("Report succeeded", "Result=0x80070005"),
        ("Request succeeded", "Result=0x80070005"),
        ("Evaluate succeeded", "hr=0x80070005"),
        ("Persist succeeded", "[gle=0x80070005]"),
    ] {
        let mut bundle = load_bundle("complete");
        let record = bundle
            .evidence
            .iter_mut()
            .find(|evidence| evidence.message.contains(marker))
            .unwrap_or_else(|| panic!("{marker} evidence"));
        record.message = format!("{} {terminal}", record.message);

        let analysis = analysis_json(&bundle);
        let transaction = &analysis["transactions"][0];
        assert_ne!(
            transaction["state"], "succeeded",
            "{marker} with {terminal} cannot prove a completed chain"
        );
        assert_ne!(
            transaction["confidence"], "high",
            "{marker} with {terminal} cannot carry high confidence"
        );
    }
}

#[test]
fn policy_deferred_marker_with_a_terminal_result_is_never_phase_evidence() {
    let mut bundle = load_bundle("scheduler-deferred");
    let deferred = bundle
        .evidence
        .iter_mut()
        .find(|evidence| evidence.message.contains("Schedule deferred"))
        .expect("deferred evidence");
    deferred.message = format!("{} Result=0x80070005", deferred.message);

    let analysis = analysis_json(&bundle);
    let transaction = &analysis["transactions"][0];
    assert_ne!(
        transaction["state"], "deferred",
        "a deferral carrying a terminal failure code contradicts its own marker"
    );
    assert_ne!(transaction["confidence"], "high");
}

fn clone_evidence_over_lines(
    bundle: &mut SccmNormalizedBundle,
    marker: &str,
    replacement: &str,
    line_start: u32,
    line_end: u32,
) {
    let mut clone = bundle
        .evidence
        .iter()
        .find(|evidence| evidence.message.contains(marker))
        .cloned()
        .unwrap_or_else(|| panic!("{marker} evidence"));
    clone.message = clone.message.replace(marker, replacement);
    clone.evidence_id = format!("{}:overlap", clone.evidence_id);
    clone.reference.entry_id = format!("{}:overlap", clone.reference.entry_id);
    clone.reference.line_start = Some(line_start);
    clone.reference.line_end = Some(line_end);
    bundle.evidence.push(clone);
}

#[test]
fn policy_overlapping_evidence_ranges_never_prove_a_phase() {
    let mut bundle = load_bundle("complete");
    // The shipped Report record is StateMessage 1-1. A second record over 1-2
    // is not a second logical record, it is the same physical line claimed
    // twice, so neither claim can be trusted.
    clone_evidence_over_lines(
        &mut bundle,
        "Report succeeded",
        "Report failed terminal Result=0x80070005",
        1,
        2,
    );

    let forward = analysis_json(&bundle);
    assert_eq!(
        forward,
        analysis_json(&reversed_bundle(&bundle)),
        "overlapping physical ranges must not be resolved by input order"
    );

    let transaction = &forward["transactions"][0];
    assert_ne!(
        transaction["state"], "failed",
        "a wider overlapping range must not outrank the record it overlaps"
    );
    assert_ne!(transaction["state"], "succeeded");
    assert_ne!(transaction["confidence"], "high");
}

#[test]
fn policy_one_physical_line_never_proves_two_phases() {
    let mut bundle = load_bundle("complete");
    // PolicyAgent carries Request on line 1 and Download on line 2. A Persist
    // claim spanning 2-3 would prove two phases from one physical line.
    clone_evidence_over_lines(&mut bundle, "Download succeeded", "Persist succeeded", 2, 3);

    let forward = analysis_json(&bundle);
    assert_eq!(
        forward,
        analysis_json(&reversed_bundle(&bundle)),
        "overlapping phase claims must not be resolved by input order"
    );
    assert_ne!(
        forward["transactions"][0]["state"], "succeeded",
        "one physical line cannot prove two phases"
    );
    assert_ne!(forward["transactions"][0]["confidence"], "high");
}

#[test]
fn policy_uncollected_client_location_never_outranks_a_recorded_absence() {
    let recorded = analysis_json(&load_bundle("request-auth-failure"));
    assert_eq!(recorded["transactions"][0]["confidence"], "medium");

    // Same capture, minus the one artifact that records the absence. Deleting
    // information can only widen what is unknown, never narrow it.
    let mut bundle = load_bundle("request-auth-failure");
    bundle
        .artifacts
        .retain(|artifact| artifact.display_name != "ClientLocation.log");
    let uncollected = analysis_json(&bundle);

    let transaction = &uncollected["transactions"][0];
    assert_eq!(
        transaction["confidence"], "medium",
        "an entirely uncollected client-location group cannot beat a recorded absence"
    );
    assert_eq!(
        transaction["coverageGapArtifactIds"],
        json!(["client-location"]),
        "a group nobody collected is still a coverage gap"
    );
    assert!(
        transaction["nextArtifacts"]
            .as_array()
            .expect("transaction requests")
            .iter()
            .any(|request| request["logicalId"] == "client-location"),
        "the only actionable repair must survive the missing placeholder"
    );
    assert_eq!(
        uncollected["findings"][0]["confidence"], "moderate",
        "the finding cannot be more certain than the transaction"
    );
}

fn evaluate_failure_past_a_missing_download() -> SccmNormalizedBundle {
    let mut bundle = load_bundle("complete");
    bundle.evidence.retain(|evidence| {
        evidence.message.contains("Request succeeded") || evidence.message.contains("Evaluate")
    });
    let evaluate = bundle
        .evidence
        .iter_mut()
        .find(|evidence| evidence.message.contains("Evaluate succeeded"))
        .expect("evaluate evidence");
    evaluate.message = evaluate.message.replace(
        "Evaluate succeeded",
        "Evaluate failed terminal Result=0x80070005",
    );
    bundle
}

#[test]
fn policy_terminal_failure_past_a_missing_phase_is_never_discarded() {
    let bundle = evaluate_failure_past_a_missing_download();
    let failure_artifact = bundle
        .evidence
        .iter()
        .find(|evidence| evidence.message.contains("Evaluate failed terminal"))
        .map(|evidence| evidence.reference.artifact_id.clone())
        .expect("evaluate failure artifact");

    let analysis = analysis_json(&bundle);
    assert_eq!(
        analysis["transactions"][0]["phase"], "request",
        "the chain still stops at the first missing phase"
    );

    let observations = analysis["sourceLocalObservations"]
        .as_array()
        .expect("source-local observations");
    assert!(
        observations.iter().any(|observation| {
            observation["evidence"]
                .as_array()
                .expect("observation evidence")
                .iter()
                .any(|reference| reference["artifactId"] == failure_artifact.as_str())
        }),
        "a confirmed terminal failure the chain could not reach must stay observable, got {observations:?}"
    );
    assert!(
        analysis["findings"]
            .as_array()
            .expect("findings")
            .iter()
            .any(|finding| {
                finding["severity"] == "Error"
                    && finding["class"] == "confirmedFailure"
                    && finding["terminalEvidence"]
                        .as_array()
                        .expect("terminal evidence")
                        .iter()
                        .any(|terminal| {
                            terminal["reference"]["artifactId"] == failure_artifact.as_str()
                        })
            }),
        "an unreached terminal failure must not be reported only as an evidence gap"
    );
    assert!(
        observations
            .iter()
            .all(|observation| observation["correlationEligible"] == false),
        "a record the chain could not reach is never correlation eligible"
    );
}

#[test]
fn policy_unreached_terminal_failure_is_order_independent() {
    let bundle = evaluate_failure_past_a_missing_download();
    assert_eq!(
        analysis_json(&bundle),
        analysis_json(&reversed_bundle(&bundle)),
        "an unreached terminal failure must not depend on input order"
    );
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
