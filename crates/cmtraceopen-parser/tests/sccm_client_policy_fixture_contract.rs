use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

const FIXTURE_ROOT: &str = "tests/fixtures/sccm/client/policy";
const SCENARIOS: &[&str] = &[
    "complete",
    "contradictory-offset",
    "download-failure",
    "evaluation-failure",
    "gate-c-contradictory",
    "incomplete",
    "malformed",
    "multiline",
    "persist-failure",
    "recovery",
    "reporting-failure",
    "request-auth-failure",
    "rotation-split",
    "scheduler-deferred",
];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURE_ROOT)
}

fn read_json(scenario: &str, name: &str) -> Value {
    serde_json::from_str(
        &fs::read_to_string(root().join(scenario).join(name)).expect("fixture is readable"),
    )
    .expect("fixture is valid JSON")
}

#[test]
fn preparation_corpus_is_closed_and_self_identifying() {
    let actual = fs::read_dir(root())
        .expect("fixture root")
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_dir())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual,
        SCENARIOS
            .iter()
            .map(|scenario| (*scenario).to_owned())
            .collect()
    );
    for scenario in SCENARIOS {
        let manifest = read_json(scenario, "manifest.json");
        let expected = read_json(scenario, "expected.json");
        assert_eq!(manifest["sccmManifestVersion"], 1, "{scenario}");
        assert_eq!(manifest["proposalOnly"], true, "{scenario}");
        assert_eq!(manifest["syntheticFixture"], true, "{scenario}");
        assert_eq!(manifest["bundle"]["role"], "client", "{scenario}");
        assert_eq!(manifest["bundle"]["workflow"], "policy", "{scenario}");
        assert_eq!(expected["scenario"], *scenario, "{scenario}");
        assert_eq!(expected["workflow"], "policy", "{scenario}");
        assert_eq!(
            expected["contractState"], "proposedPending318",
            "{scenario}"
        );
        assert_eq!(
            expected["stateChain"],
            serde_json::json!(["request", "download", "persist", "schedule", "evaluate", "report"]),
            "{scenario}"
        );
    }
}

#[test]
fn preparation_evidence_ranges_resolve_to_declared_physical_artifacts() {
    for scenario in SCENARIOS {
        let manifest = read_json(scenario, "manifest.json");
        let expected = read_json(scenario, "expected.json");
        let artifacts = manifest["artifacts"]
            .as_array()
            .expect("artifacts")
            .iter()
            .map(|artifact| {
                let artifact_id = artifact["artifactId"].as_str().expect("artifact id");
                let relative_path = artifact["relativePath"].as_str();
                let line_count = relative_path.map_or(0, |relative_path| {
                    fs::read_to_string(root().join(scenario).join(relative_path))
                        .expect("declared payload")
                        .lines()
                        .count()
                });
                (artifact_id.to_owned(), line_count)
            })
            .collect::<BTreeMap<_, _>>();

        for reference in evidence_references(&expected) {
            let artifact_id = reference["artifactId"].as_str().expect("artifact id");
            let start = reference["startLine"].as_u64().expect("start line");
            let end = reference["endLine"].as_u64().expect("end line");
            assert!(start > 0 && start <= end, "{scenario}: {reference}");
            assert!(
                end <= u64::try_from(*artifacts.get(artifact_id).expect("declared artifact"))
                    .expect("line count"),
                "{scenario}: {reference}"
            );
        }
    }
}

#[test]
fn preparation_matrix_covers_required_states_without_cross_side_claims() {
    let expected = SCENARIOS
        .iter()
        .map(|scenario| ((*scenario).to_owned(), read_json(scenario, "expected.json")))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        expected["complete"]["transactions"][0]["state"],
        "succeeded"
    );
    assert_eq!(
        expected["download-failure"]["transactions"][0]["classification"],
        "confirmedFailure"
    );
    assert_eq!(
        expected["scheduler-deferred"]["transactions"][0]["state"],
        "deferred"
    );
    assert_eq!(
        expected["gate-c-contradictory"]["transactions"][0]["state"],
        "contradictory"
    );
    assert_eq!(
        expected["malformed"]["extractionProfile"]["selectionState"],
        "unvalidatedVersion"
    );
    assert!(expected["rotation-split"]["transactions"]
        .as_array()
        .expect("transactions")
        .is_empty());
    for (scenario, expected) in expected {
        assert_eq!(
            expected["analysisContract"]["crossSideCorrelationPerformed"], false,
            "{scenario}"
        );
        assert_eq!(
            expected["correlationHandoff"]["timeOnlyEligible"], false,
            "{scenario}"
        );
        assert_eq!(
            expected["correlationHandoff"]["bundleCaptureHostUsedAsManagementPointEvidence"], false,
            "{scenario}"
        );
    }
}

fn evidence_references(expected: &Value) -> Vec<&Value> {
    let mut references = Vec::new();
    for collection in ["transactions", "sourceLocalObservations", "findings"] {
        for item in expected[collection].as_array().into_iter().flatten() {
            references.extend(item["evidence"].as_array().into_iter().flatten());
        }
    }
    references
}
