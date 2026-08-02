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
const SYNTHETIC_MP_PROFILE_ID: &str = "mp-server-5.00.test-v1";
const EXPECTED_MP_FIXTURE_SCENARIOS: usize = 9;
const SELECTED_MP_FIXTURE_SCENARIOS: usize = 8;
const SELECTED_MP_FIXTURE_ARTIFACTS: usize = 22;

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
    let mut expected_scenarios = 0;
    let mut selected_scenarios = 0;
    let mut selected_artifacts = 0;

    for entry in fs::read_dir(&fixture_root).expect("MP fixture root must be readable") {
        let scenario_directory = entry
            .expect("MP fixture directory entry must be readable")
            .path();
        if !scenario_directory.is_dir() {
            continue;
        }
        let expected_path = scenario_directory.join("expected.json");
        if !expected_path.is_file() {
            continue;
        }
        expected_scenarios += 1;

        let expected: Value = serde_json::from_str(
            &fs::read_to_string(expected_path).expect("MP expected fixture must be readable"),
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
        selected_scenarios += 1;

        let prefix = profile["sourceVersionPrefix"]
            .as_str()
            .filter(|prefix| !prefix.is_empty())
            .expect("selected MP profile must declare a nonempty source version prefix");
        assert_eq!(
            profile["profileId"].as_str(),
            Some(SYNTHETIC_MP_PROFILE_ID),
            "{}: selected fixture must retain the synthetic MP profile",
            scenario_directory.display()
        );
        assert_eq!(
            prefix,
            SYNTHETIC_MP_SOURCE_VERSION,
            "{}: selected synthetic profile must retain its exact source version prefix",
            scenario_directory.display()
        );

        let expected_artifacts = expected["artifactProvenance"]
            .as_array()
            .expect("MP expected artifact provenance must be an array");
        assert!(
            !expected_artifacts.is_empty(),
            "{}: selected MP fixture must retain artifact provenance",
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
        for expected_artifact in expected_artifacts {
            let artifact_id = expected_artifact["artifactId"]
                .as_str()
                .expect("MP expected artifact ID must be a string");
            let source_version = expected_artifact["sourceVersion"]
                .as_str()
                .expect("selected MP artifact provenance must declare a source version");
            assert!(
                source_version.starts_with(prefix),
                "{}: {artifact_id} source version {source_version:?} must match profile prefix {prefix:?}",
                scenario_directory.display()
            );
            assert_eq!(
                source_version,
                SYNTHETIC_MP_SOURCE_VERSION,
                "{}: {artifact_id} must retain the exact admitted synthetic ConfigMgr version",
                scenario_directory.display()
            );
            let manifest_artifact = manifest_artifacts
                .iter()
                .find(|artifact| artifact["artifactId"] == artifact_id)
                .expect("MP expected artifact must exist in its manifest");
            assert_eq!(
                manifest_artifact["sourceVersion"].as_str(),
                Some(source_version),
                "{}: {artifact_id} manifest provenance must exactly match expected source version",
                scenario_directory.display()
            );
            selected_artifacts += 1;
        }
    }

    assert_eq!(
        expected_scenarios, EXPECTED_MP_FIXTURE_SCENARIOS,
        "MP fixture scenario cardinality drifted"
    );
    assert_eq!(
        selected_scenarios, SELECTED_MP_FIXTURE_SCENARIOS,
        "selected MP fixture scenario cardinality drifted"
    );
    assert_eq!(
        selected_artifacts, SELECTED_MP_FIXTURE_ARTIFACTS,
        "selected MP fixture artifact cardinality drifted"
    );
}

#[test]
#[deny(unreachable_patterns)]
fn public_management_point_intake_errors_allow_future_variants() {
    let category = match SccmManagementPointIntakeError::TopologyMismatch {
        SccmManagementPointIntakeError::TopologyMismatch => "topology",
        SccmManagementPointIntakeError::RoleMismatch { .. } => "role",
        SccmManagementPointIntakeError::ProfileMismatch { .. } => "profile",
        SccmManagementPointIntakeError::SourceMismatch { .. } => "source",
        SccmManagementPointIntakeError::IncompleteSource { .. } => "incomplete",
        _ => "future",
    };

    assert_eq!(category, "topology");
}
