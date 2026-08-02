use std::path::{Path, PathBuf};

use cmtraceopen_parser::sccm::server::windows::{
    analyze_distribution_point, assess_server_intake, SccmServerArtifactPayload,
};
use cmtraceopen_parser::sccm::{SccmCoverageState, SccmRole, SccmTimeOrderingState};
use serde_json::Value;

fn intake_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sccm/server/intake")
}

fn load_assessment(scenario: &str) -> cmtraceopen_parser::sccm::server::windows::SccmServerIntakeAssessment {
    let scenario_root = intake_root().join(scenario);
    let manifest_json =
        std::fs::read_to_string(scenario_root.join("manifest.json")).expect("manifest is readable");
    let manifest: Value = serde_json::from_str(&manifest_json).expect("manifest is valid JSON");
    let payloads = manifest["artifacts"]
        .as_array()
        .expect("artifacts are an array")
        .iter()
        .filter_map(|artifact| {
            let relative_path = artifact["relativePath"].as_str()?;
            Some(SccmServerArtifactPayload {
                manifest_artifact_id: artifact["artifactId"]
                    .as_str()
                    .expect("artifact id is a string")
                    .to_owned(),
                bytes: std::fs::read(scenario_root.join(relative_path))
                    .expect("captured evidence is readable"),
            })
        })
        .collect::<Vec<_>>();

    assess_server_intake(&manifest_json, &payloads).expect("fixture intake is accepted")
}

#[test]
fn distribution_point_adapter_projects_only_canonical_intake_observations_deterministically() {
    let assessment = load_assessment("complete-multi-role");

    let analysis = analyze_distribution_point(&assessment);

    assert!(!analysis.cross_side_correlation_performed);
    assert!(analysis.coverage_gaps.is_empty());
    assert!(analysis.artifact_requests.is_empty());
    assert_eq!(analysis.source_observations.len(), 1);

    let observation = &analysis.source_observations[0];
    assert_eq!(observation.artifact_id, "dp-dist-current");
    assert_eq!(observation.producer_role, SccmRole::SiteServer);
    assert_eq!(observation.workflow_subject_role, Some(SccmRole::DistributionPoint));
    assert_eq!(observation.source_id, "server-dp-distribution");
    assert_eq!(
        observation.timestamp.ordering_state,
        SccmTimeOrderingState::NormalizedUtc
    );

    let mut reordered = assessment.clone();
    reordered.artifacts.reverse();
    reordered.coverage.reverse();
    reordered.evidence.reverse();
    assert_eq!(
        serde_json::to_value(&analysis).expect("analysis serializes"),
        serde_json::to_value(analyze_distribution_point(&reordered))
            .expect("reordered analysis serializes")
    );
}

#[test]
fn absent_dp_candidate_is_coverage_not_a_role_diagnosis() {
    let assessment = load_assessment("absent-dp");

    let analysis = analyze_distribution_point(&assessment);

    assert!(!analysis.cross_side_correlation_performed);
    assert!(analysis.source_observations.is_empty());
    assert_eq!(analysis.coverage_gaps.len(), 1);
    assert_eq!(analysis.coverage_gaps[0].state, SccmCoverageState::Absent);
    assert_eq!(analysis.coverage_gaps[0].source_id, "server-dp-distribution");
    assert_eq!(analysis.artifact_requests.len(), 1);
    assert_eq!(analysis.artifact_requests[0].logical_id, "server-dp-distribution");
    assert_eq!(analysis.artifact_requests[0].role, SccmRole::DistributionPoint);
}
