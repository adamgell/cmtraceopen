use std::fs;
use std::path::{Path, PathBuf};

use cmtraceopen_parser::sccm::server::windows::{
    analyze_management_point_from_server_intake, assess_server_intake,
    SccmManagementPointIntakeError, SccmServerArtifactPayload,
};
use cmtraceopen_parser::sccm::SccmCoverageState;
use serde_json::Value;

const FIXTURE_ROOT: &str = "tests/fixtures/sccm/server/management-point";
const SYNTHETIC_MP_SOURCE_VERSION: &str = "5.00.TEST";

fn fixture_directory(scenario: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(FIXTURE_ROOT)
        .join(scenario)
}

fn canonical_intake() -> cmtraceopen_parser::sccm::server::windows::SccmServerIntakeAssessment {
    let directory = fixture_directory("canonical-intake-policy-scope");
    let manifest_json = fs::read_to_string(directory.join("manifest.json"))
        .expect("canonical MP fixture manifest must be readable");
    let manifest: Value = serde_json::from_str(&manifest_json)
        .expect("canonical MP fixture manifest must be valid JSON");
    let payloads = manifest["artifacts"]
        .as_array()
        .expect("canonical MP fixture artifacts")
        .iter()
        .filter_map(|artifact| {
            let relative_path = artifact["relativePath"].as_str()?;
            Some(SccmServerArtifactPayload {
                manifest_artifact_id: artifact["artifactId"]
                    .as_str()
                    .expect("canonical MP artifact ID")
                    .to_owned(),
                bytes: fs::read(directory.join(relative_path))
                    .expect("canonical MP fixture payload must be readable"),
            })
        })
        .collect::<Vec<_>>();
    assess_server_intake(&manifest_json, &payloads)
        .expect("canonical MP fixture must satisfy server intake")
}

#[test]
fn canonical_intake_adapter_derives_assessed_mp_evidence_and_fails_closed() {
    let assessment = canonical_intake();
    let analysis = analyze_management_point_from_server_intake(&assessment)
        .expect("complete canonical MP source must enter the reducer");

    assert!(analysis.transactions.is_empty());
    assert!(!analysis.cross_side_correlation_performed);
    assert_eq!(analysis.source_local_observations.len(), 1);
    assert!(analysis.source_local_observations[0]
        .evidence
        .iter()
        .all(|reference| reference.artifact_id == "mp-policy-current"));

    let mut capped = assessment;
    capped.artifacts[0].state = SccmCoverageState::Capped;
    capped.artifacts[0].truncated = Some(true);
    capped.artifacts[0].fragment_complete = Some(false);
    assert!(matches!(
        analyze_management_point_from_server_intake(&capped),
        Err(SccmManagementPointIntakeError::SourceMismatch { artifact_id })
            if artifact_id == "management-point-intake-projection"
    ));
}

#[test]
fn selected_management_point_profile_prefixes_admit_exact_synthetic_versions() {
    let fixture_root = Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURE_ROOT);
    let mut checked_artifacts = 0;

    for entry in fs::read_dir(&fixture_root).expect("MP fixture root must be readable") {
        let scenario_directory = entry
            .expect("MP fixture directory entry must be readable")
            .path();
        if !scenario_directory.is_dir() {
            continue;
        }

        let expected: Value = serde_json::from_str(
            &fs::read_to_string(scenario_directory.join("expected.json"))
                .expect("MP expected fixture must be readable"),
        )
        .expect("MP expected fixture must be valid JSON");
        let profile = &expected["extractionProfile"];
        let selected = matches!(
            profile["selectionState"].as_str(),
            Some("selected" | "selectedNoCompatibleTransaction")
        );
        if !selected {
            continue;
        }

        let expected_artifacts = expected["artifactProvenance"]
            .as_array()
            .expect("MP expected artifact provenance must be an array");
        let exact_version_artifacts = expected_artifacts
            .iter()
            .filter(|artifact| artifact["sourceVersion"] == SYNTHETIC_MP_SOURCE_VERSION)
            .collect::<Vec<_>>();
        if exact_version_artifacts.is_empty() {
            continue;
        }

        assert_eq!(
            profile["sourceVersionPrefix"].as_str(),
            Some(SYNTHETIC_MP_SOURCE_VERSION),
            "{}: selected synthetic profile must admit its exact source version",
            scenario_directory.display()
        );

        let manifest: Value = serde_json::from_str(
            &fs::read_to_string(scenario_directory.join("manifest.json"))
                .expect("MP manifest fixture must be readable"),
        )
        .expect("MP manifest fixture must be valid JSON");
        let manifest_artifacts = manifest["artifacts"]
            .as_array()
            .expect("MP manifest artifacts must be an array");
        for expected_artifact in exact_version_artifacts {
            let artifact_id = expected_artifact["artifactId"]
                .as_str()
                .expect("MP expected artifact ID must be a string");
            let manifest_artifact = manifest_artifacts
                .iter()
                .find(|artifact| artifact["artifactId"] == artifact_id)
                .expect("MP expected artifact must exist in its manifest");
            assert_eq!(
                manifest_artifact["sourceVersion"].as_str(),
                Some(SYNTHETIC_MP_SOURCE_VERSION),
                "{}: {artifact_id} must retain the exact admitted ConfigMgr version",
                scenario_directory.display()
            );
            checked_artifacts += 1;
        }
    }

    assert!(
        checked_artifacts > 0,
        "the contract must exercise at least one selected exact synthetic MP artifact"
    );
}
