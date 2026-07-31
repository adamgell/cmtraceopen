use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use cmtraceopen_parser::sccm::{
    analyze_client_policy, normalize_ccm_artifact, SccmArtifact, SccmCoverageState,
    SccmNormalizedBundle, SccmRole, SccmRotation,
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
            let line_start = reference["lineStart"]
                .as_u64()
                .expect("analysis line start");
            let line_end = reference["lineEnd"].as_u64().expect("analysis line end");
            assert!(
                expected_ranges.iter().any(|expected_reference| {
                    expected_reference["artifactId"].as_str() == Some(artifact_id)
                        && expected_reference["startLine"]
                            .as_u64()
                            .is_some_and(|start| start <= line_start)
                        && expected_reference["endLine"]
                            .as_u64()
                            .is_some_and(|end| line_end <= end)
                }),
                "{scenario}: {transaction_id} emitted an uncited range {artifact_id}:{line_start}-{line_end}"
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

        assert_eq!(
            analysis["sourceLocalObservations"]
                .as_array()
                .expect("source-local observations")
                .len(),
            expected["sourceLocalObservations"]
                .as_array()
                .expect("expected source-local observations")
                .len(),
            "{scenario}"
        );
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
