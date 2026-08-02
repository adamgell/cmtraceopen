use std::fs;
use std::path::{Path, PathBuf};

use cmtraceopen_parser::sccm::server::windows::{
    analyze_management_point_from_server_intake, assess_server_intake,
    SccmManagementPointIntakeError, SccmServerArtifactPayload,
};
use cmtraceopen_parser::sccm::SccmCoverageState;
use serde_json::Value;

const FIXTURE_ROOT: &str = "tests/fixtures/sccm/server/management-point";

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
        Err(SccmManagementPointIntakeError::IncompleteSource { .. })
    ));
}
