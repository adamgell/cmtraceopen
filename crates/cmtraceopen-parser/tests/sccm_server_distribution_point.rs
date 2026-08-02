use std::path::{Path, PathBuf};

use cmtraceopen_parser::sccm::server::windows::{
    analyze_distribution_point, assess_server_intake, SccmServerArtifactPayload,
};
use cmtraceopen_parser::sccm::{SccmCoverageState, SccmRole, SccmRotation, SccmTimeOrderingState};
use serde_json::Value;

fn intake_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sccm/server/intake")
}

fn load_assessment(
    scenario: &str,
) -> cmtraceopen_parser::sccm::server::windows::SccmServerIntakeAssessment {
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

fn dp_artifact_index(
    assessment: &cmtraceopen_parser::sccm::server::windows::SccmServerIntakeAssessment,
) -> usize {
    assessment
        .artifacts
        .iter()
        .position(|artifact| artifact.artifact_id == "dp-dist-current")
        .expect("fixture contains the DP artifact")
}

fn dp_evidence_index(
    assessment: &cmtraceopen_parser::sccm::server::windows::SccmServerIntakeAssessment,
) -> usize {
    assessment
        .evidence
        .iter()
        .position(|evidence| evidence.reference.artifact_id == "dp-dist-current")
        .expect("fixture contains the DP evidence")
}

fn add_dp_peer(
    assessment: &mut cmtraceopen_parser::sccm::server::windows::SccmServerIntakeAssessment,
) {
    let artifact_index = dp_artifact_index(assessment);
    let mut peer = assessment.artifacts[artifact_index].clone();
    peer.artifact_id = "dp-dist-peer".to_owned();
    peer.rotation_lineage_handle = "synthetic:lineage:dp-dist-peer".to_owned();
    peer.path_fingerprint = "synthetic:path:site-dp-control-peer".to_owned();
    assessment.artifacts.push(peer);

    let evidence_index = dp_evidence_index(assessment);
    let mut peer_evidence = assessment.evidence[evidence_index].clone();
    peer_evidence.evidence_id = "dp-dist-peer:1-1".to_owned();
    peer_evidence.reference.artifact_id = "dp-dist-peer".to_owned();
    peer_evidence.reference.entry_id = "dp-dist-peer:1-1".to_owned();
    peer_evidence.reference.line_start = Some(1);
    peer_evidence.reference.line_end = Some(1);
    assessment.evidence.push(peer_evidence);

    assessment
        .coverage
        .iter_mut()
        .find(|coverage| coverage.source_id == "server-dp-distribution")
        .expect("fixture contains DP coverage")
        .artifact_ids
        .push("dp-dist-peer".to_owned());
}

fn assert_dp_coverage_only(
    assessment: &cmtraceopen_parser::sccm::server::windows::SccmServerIntakeAssessment,
) -> Value {
    let analysis = analyze_distribution_point(assessment);
    assert!(
        analysis.source_observations.is_empty(),
        "invalid DP evidence must not become a source observation"
    );
    assert!(
        !analysis.coverage_gaps.is_empty(),
        "invalid DP evidence must remain an explicit coverage gap"
    );
    assert!(
        !analysis.artifact_requests.is_empty(),
        "invalid DP evidence must request a bounded declared source"
    );
    assert!(!analysis.cross_side_correlation_performed);
    serde_json::to_value(analysis).expect("coverage-only analysis serializes")
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
    assert_eq!(
        observation.workflow_subject_role,
        Some(SccmRole::DistributionPoint)
    );
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
    assert_eq!(
        analysis.coverage_gaps[0].state,
        Some(SccmCoverageState::Absent)
    );
    assert_eq!(
        analysis.coverage_gaps[0].source_id,
        "server-dp-distribution"
    );
    assert_eq!(analysis.artifact_requests.len(), 1);
    assert_eq!(analysis.artifact_requests[0].logical_id, "distmgr");
    assert_eq!(analysis.artifact_requests[0].role, SccmRole::SiteServer);
    serde_json::to_value(&analysis).expect("coverage-only analysis serializes");
}

#[test]
fn duplicate_dp_artifact_identity_fails_closed_independent_of_input_order() {
    let mut assessment = load_assessment("complete-multi-role");
    let artifact_index = dp_artifact_index(&assessment);
    let mut duplicate = assessment.artifacts[artifact_index].clone();
    duplicate.producer_host_handle = Some("synthetic:host:site-02".to_owned());
    duplicate.path_fingerprint = "synthetic:path:site-dp-control-02".to_owned();
    assessment.artifacts.push(duplicate);

    let first = assert_dp_coverage_only(&assessment);
    assessment.artifacts.reverse();
    let reversed = assert_dp_coverage_only(&assessment);

    assert_eq!(first, reversed);
}

#[test]
fn missing_duplicate_and_overlapping_evidence_ranges_are_coverage_only() {
    let assessment = load_assessment("complete-multi-role");
    let evidence_index = dp_evidence_index(&assessment);

    let mut missing_range = assessment.clone();
    missing_range.evidence[evidence_index].reference.line_start = None;
    assert_dp_coverage_only(&missing_range);

    let mut duplicate = assessment.clone();
    duplicate
        .evidence
        .push(duplicate.evidence[evidence_index].clone());
    assert_dp_coverage_only(&duplicate);

    let mut overlap = assessment.clone();
    let mut overlapping = overlap.evidence[evidence_index].clone();
    overlapping.evidence_id = "dp-dist-current:1-2".to_owned();
    overlapping.reference.entry_id = "dp-dist-current:1-2".to_owned();
    overlapping.reference.line_end = Some(2);
    overlap.evidence.push(overlapping);
    assert_dp_coverage_only(&overlap);
}

#[test]
fn evidence_ranges_with_a_physical_line_hole_are_coverage_only() {
    let mut assessment = load_assessment("complete-multi-role");
    let evidence_index = dp_evidence_index(&assessment);
    assessment.evidence[evidence_index].evidence_id = "dp-dist-current:1-1".to_owned();
    assessment.evidence[evidence_index].reference.entry_id = "dp-dist-current:1-1".to_owned();
    assessment.evidence[evidence_index].reference.line_start = Some(1);
    assessment.evidence[evidence_index].reference.line_end = Some(1);

    let mut after_hole = assessment.evidence[evidence_index].clone();
    after_hole.evidence_id = "dp-dist-current:3-3".to_owned();
    after_hole.reference.entry_id = "dp-dist-current:3-3".to_owned();
    after_hole.reference.line_start = Some(3);
    after_hole.reference.line_end = Some(3);
    assessment.evidence.push(after_hole);

    assert_dp_coverage_only(&assessment);
}

#[test]
fn coverage_gap_preserves_every_declared_member_when_a_peer_is_not_admitted() {
    for defect in [
        "profile-ineligible",
        "parser-ineligible",
        "incomplete-fragment",
        "invalid-evidence",
    ] {
        let mut assessment = load_assessment("complete-multi-role");
        add_dp_peer(&mut assessment);
        let peer_index = assessment
            .artifacts
            .iter()
            .position(|artifact| artifact.artifact_id == "dp-dist-peer")
            .expect("peer artifact exists");

        match defect {
            "profile-ineligible" => assessment.artifacts[peer_index].profile_eligible = false,
            "parser-ineligible" => assessment.artifacts[peer_index].parser_eligible = false,
            "incomplete-fragment" => {
                assessment.artifacts[peer_index].fragment_complete = Some(false)
            }
            "invalid-evidence" => {
                assessment
                    .evidence
                    .iter_mut()
                    .find(|evidence| evidence.reference.artifact_id == "dp-dist-peer")
                    .expect("peer evidence exists")
                    .reference
                    .line_start = None
            }
            _ => unreachable!("test defect is declared above"),
        }

        let analysis = analyze_distribution_point(&assessment);
        assert_eq!(
            analysis
                .source_observations
                .iter()
                .map(|observation| observation.artifact_id.as_str())
                .collect::<Vec<_>>(),
            vec!["dp-dist-current"],
            "{defect} peer must not be admitted"
        );
        assert_eq!(analysis.coverage_gaps.len(), 1, "{defect}");
        assert_eq!(
            analysis.coverage_gaps[0].artifact_ids,
            vec!["dp-dist-current", "dp-dist-peer"],
            "{defect} coverage gap must preserve every declared member"
        );
        assert_eq!(analysis.artifact_requests.len(), 1, "{defect}");

        let expected = serde_json::to_value(&analysis).expect("analysis serializes");
        assessment.artifacts.reverse();
        assessment.evidence.reverse();
        assessment.coverage.reverse();
        for coverage in &mut assessment.coverage {
            coverage.artifact_ids.reverse();
        }
        assert_eq!(
            expected,
            serde_json::to_value(analyze_distribution_point(&assessment))
                .expect("reordered analysis serializes"),
            "{defect} output must be deterministic"
        );
    }
}

#[test]
fn source_observation_requires_exact_intake_coverage_membership() {
    let mut assessment = load_assessment("complete-multi-role");
    assessment
        .coverage
        .retain(|coverage| coverage.source_id != "server-dp-distribution");

    assert_dp_coverage_only(&assessment);
}

#[test]
fn role_topology_profile_and_rotation_mutations_fail_closed() {
    let assessment = load_assessment("complete-multi-role");
    let artifact_index = dp_artifact_index(&assessment);

    let mut wrong_role = assessment.clone();
    wrong_role.artifacts[artifact_index].workflow_subject_role = Some(SccmRole::ManagementPoint);
    assert_dp_coverage_only(&wrong_role);

    let mut missing_topology = assessment.clone();
    missing_topology
        .topology
        .roles_observed
        .retain(|role| role != &SccmRole::DistributionPoint);
    assert_dp_coverage_only(&missing_topology);

    let mut ineligible_profile = assessment.clone();
    ineligible_profile.artifacts[artifact_index].profile_eligible = false;
    assert_dp_coverage_only(&ineligible_profile);

    let mut wrong_rotation = assessment.clone();
    wrong_rotation.artifacts[artifact_index].rotation = Some(SccmRotation::LoUnderscore);
    assert_dp_coverage_only(&wrong_rotation);
}
