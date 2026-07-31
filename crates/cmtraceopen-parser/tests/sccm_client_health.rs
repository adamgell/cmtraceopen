use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use cmtraceopen_parser::sccm::{
    analyze_client_health, normalize_ccm_artifact, SccmArtifact, SccmCoverageState,
    SccmNormalizedBundle, SccmRole, SccmRotation,
};
use serde::Deserialize;
use serde_json::{json, Value};

const FIXTURE_ROOT: &str = "tests/fixtures/sccm/client/health";
const SCENARIOS: &[&str] = &[
    "success",
    "setup-failure",
    "identity-failure",
    "no-site-or-mp",
    "transport-failure",
    "contradictory",
    "rotation-boundary",
    "malformed",
    "incomplete",
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
        assert_eq!(source.role, "client", "health fixtures must be client-only");
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
                .expect("captured health evidence must be readable UTF-8");
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

fn expected_finding_projection(expected: &Value) -> Vec<Value> {
    expected["findings"]
        .as_array()
        .expect("expected findings")
        .iter()
        .map(|finding| {
            json!({
                "findingId": finding["findingId"],
                "healthPhase": finding["phase"],
                "class": finding["class"],
                "confidence": finding["confidence"],
                "coverageGapArtifactIds": finding["coverageGapArtifactIds"],
                "nextArtifactLogicalId": finding["nextArtifacts"]
                    .as_array()
                    .and_then(|requests| requests.first())
                    .map(|request| request["logicalArtifactId"].clone())
                    .unwrap_or(Value::Null),
            })
        })
        .collect()
}

fn source_group_for_request(logical_id: &str) -> Option<&'static str> {
    match logical_id {
        "ccmSetup" => Some("client-ccmsetup"),
        "ccmEval" | "ccmExec" | "ccmRestart" => Some("client-evaluation"),
        "clientIdManagerStartup" => Some("client-identity"),
        "clientLocation" | "locationServices" | "ccmMessaging" => Some("client-location"),
        _ => None,
    }
}

fn actual_finding_projection(analysis: &Value) -> Vec<Value> {
    analysis["findings"]
        .as_array()
        .expect("analysis findings")
        .iter()
        .map(|finding| {
            let next_group = finding["nextArtifacts"]
                .as_array()
                .and_then(|requests| requests.first())
                .and_then(|request| request["logicalId"].as_str())
                .and_then(source_group_for_request);
            let mut gap_ids = finding["coverageGaps"]
                .as_array()
                .expect("coverage gaps")
                .iter()
                .map(|gap| gap["artifactId"].clone())
                .collect::<Vec<_>>();
            gap_ids.sort_by_key(Value::to_string);
            json!({
                "findingId": finding["findingId"],
                "healthPhase": finding["healthPhase"],
                "class": finding["class"],
                "confidence": finding["confidence"],
                "coverageGapArtifactIds": gap_ids,
                "nextArtifactLogicalId": next_group,
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
            && expected_reference["lineStart"]
                .as_u64()
                .is_some_and(|start| start <= line_start)
            && expected_reference["lineEnd"]
                .as_u64()
                .is_some_and(|end| line_end <= end)
    })
}

fn assert_finding_evidence_matches_contract(scenario: &str, analysis: &Value, expected: &Value) {
    let expected_by_id = expected["findings"]
        .as_array()
        .expect("expected findings")
        .iter()
        .map(|finding| {
            (
                finding["findingId"].as_str().expect("expected finding ID"),
                finding,
            )
        })
        .collect::<BTreeMap<_, _>>();

    for finding in analysis["findings"].as_array().expect("analysis findings") {
        let finding_id = finding["findingId"].as_str().expect("finding ID");
        let expected_finding = expected_by_id
            .get(finding_id)
            .unwrap_or_else(|| panic!("{scenario}: unexpected finding {finding_id}"));
        let expected_ranges = expected_finding["fixtureEvidence"]
            .as_array()
            .expect("expected evidence");
        let evidence = finding["evidence"].as_array().expect("finding evidence");
        assert!(
            evidence
                .iter()
                .all(|reference| reference_is_within_expected_ranges(reference, expected_ranges)),
            "{scenario}: {finding_id} emitted uncited evidence"
        );
        for expected_reference in expected_ranges {
            assert!(
                evidence.iter().any(|reference| {
                    reference["artifactId"] == expected_reference["artifactId"]
                }),
                "{scenario}: {finding_id} omitted expected evidence"
            );
        }

        let terminal = finding["terminalEvidence"]
            .as_array()
            .expect("terminal evidence");
        if finding["class"] == "confirmedFailure" && finding["confidence"] == "high" {
            assert!(
                !terminal.is_empty(),
                "{scenario}: high failure needs terminal evidence"
            );
        }
        for terminal_reference in terminal {
            assert!(
                evidence.contains(&terminal_reference["reference"]),
                "{scenario}: terminal evidence must also be cited"
            );
        }
    }
}

#[test]
fn health_reducer_matches_the_frozen_phase_and_coverage_contracts() {
    for scenario in SCENARIOS {
        let expected = load_json(&fixture_directory(scenario).join("expected.json"));
        let analysis = serde_json::to_value(analyze_client_health(&load_bundle(scenario)))
            .expect("health analysis must serialize");

        assert_eq!(analysis["schemaVersion"], 1, "{scenario}");
        assert_eq!(analysis["workflow"], "health", "{scenario}");
        assert_eq!(
            analysis["lastSuccessfulPhase"], expected["lastSuccessfulPhase"],
            "{scenario}"
        );
        assert_eq!(
            actual_finding_projection(&analysis),
            expected_finding_projection(&expected),
            "{scenario}"
        );
        assert_finding_evidence_matches_contract(scenario, &analysis, &expected);

        let serialized = serde_json::to_string(&analysis).expect("analysis JSON");
        for prohibited in [
            "SYNTHETIC FIXTURE",
            "synthetic.cc",
            "SYNTHETIC://",
            "executionContext",
            "root cause",
            "server-side failure",
        ] {
            assert!(
                !serialized.contains(prohibited),
                "{scenario}: public analysis leaked or claimed {prohibited}"
            );
        }
    }
}

#[test]
fn health_analysis_is_deterministic_under_bundle_reordering() {
    for scenario in SCENARIOS {
        let bundle = load_bundle(scenario);
        let expected =
            serde_json::to_string(&analyze_client_health(&bundle)).expect("analysis JSON");

        let mut reordered = bundle.clone();
        reordered.artifacts.reverse();
        reordered.evidence.reverse();
        let actual =
            serde_json::to_string(&analyze_client_health(&reordered)).expect("analysis JSON");
        assert_eq!(actual, expected, "{scenario}");
    }
}
