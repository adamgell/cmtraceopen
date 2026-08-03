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

fn assert_dp_intake_authority_invalid(
    assessment: &cmtraceopen_parser::sccm::server::windows::SccmServerIntakeAssessment,
    context: &str,
) -> Value {
    let analysis = analyze_distribution_point(assessment);
    assert!(
        analysis.source_observations.is_empty(),
        "{context}: unsealed intake must not export a source observation"
    );
    assert_eq!(analysis.coverage_gaps.len(), 1, "{context}");
    let gap = &analysis.coverage_gaps[0];
    assert_eq!(gap.source_id, "server-dp-distribution", "{context}");
    assert_eq!(gap.producer_role, None, "{context}");
    assert_eq!(
        gap.workflow_subject_role,
        Some(SccmRole::DistributionPoint),
        "{context}"
    );
    assert_eq!(gap.state, Some(SccmCoverageState::ParseFailed), "{context}");
    assert!(gap.artifact_ids.is_empty(), "{context}");
    assert_eq!(
        gap.reason, "Canonical server intake authority could not be verified.",
        "{context}"
    );
    assert_eq!(analysis.artifact_requests.len(), 1, "{context}");
    assert_eq!(analysis.artifact_requests[0].logical_id, "distmgr");
    assert_eq!(analysis.artifact_requests[0].role, SccmRole::SiteServer);
    assert!(!analysis.cross_side_correlation_performed);
    serde_json::to_value(analysis).expect("authority-invalid analysis serializes")
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
        observation.producer_host_handle.as_deref(),
        Some("synthetic:host:site-01")
    );
    assert_eq!(
        observation.workflow_subject_role,
        Some(SccmRole::DistributionPoint)
    );
    assert_eq!(
        observation.workflow_subject_handle.as_deref(),
        Some("synthetic:subject:dp-01")
    );
    assert_eq!(observation.source_id, "server-dp-distribution");
    assert_eq!(observation.rotation, Some(SccmRotation::Current));
    assert_eq!(observation.rotation_lineage_handle, "dp-dist-lab");
    assert_eq!(
        observation.timestamp.ordering_state,
        SccmTimeOrderingState::NormalizedUtc
    );

    let mut reordered = assessment.clone();
    reordered.artifacts.reverse();
    reordered.coverage.reverse();
    reordered.evidence.reverse();
    reordered.topology.roles_observed.reverse();
    assert_eq!(
        serde_json::to_value(&analysis).expect("analysis serializes"),
        serde_json::to_value(analyze_distribution_point(&reordered))
            .expect("reordered analysis serializes")
    );
}

#[test]
fn post_intake_topology_and_coverage_handle_mutations_fail_sealed_authority_closed() {
    let assessment = load_assessment("complete-multi-role");
    let artifact_index = dp_artifact_index(&assessment);
    let coverage_index = assessment
        .coverage
        .iter()
        .position(|coverage| coverage.source_id == "server-dp-distribution")
        .expect("fixture contains DP coverage");

    let mut coordinated_producer = assessment.clone();
    coordinated_producer.artifacts[artifact_index].producer_host_handle =
        Some("synthetic:host:forged-dp-producer".to_owned());
    coordinated_producer.coverage[coverage_index].producer_host_handle =
        Some("synthetic:host:forged-dp-producer".to_owned());
    let producer_output = assert_dp_intake_authority_invalid(
        &coordinated_producer,
        "coordinated producer-host mutation",
    );
    assert!(!producer_output
        .to_string()
        .contains("synthetic:host:forged-dp-producer"));

    let mut coordinated_subject = assessment.clone();
    coordinated_subject.artifacts[artifact_index].workflow_subject_handle =
        Some("synthetic:subject:forged-dp".to_owned());
    coordinated_subject.coverage[coverage_index].workflow_subject_handle =
        Some("synthetic:subject:forged-dp".to_owned());
    let subject_output = assert_dp_intake_authority_invalid(
        &coordinated_subject,
        "coordinated workflow-subject mutation",
    );
    assert!(!subject_output
        .to_string()
        .contains("synthetic:subject:forged-dp"));

    let mut changed_topology = assessment;
    changed_topology.topology.capture_host_handle = "synthetic:host:forged-capture".to_owned();
    changed_topology.topology.site_handle = "synthetic:site:forged".to_owned();
    let topology_output =
        assert_dp_intake_authority_invalid(&changed_topology, "topology handle mutation");
    let topology_json = topology_output.to_string();
    assert!(!topology_json.contains("synthetic:host:forged-capture"));
    assert!(!topology_json.contains("synthetic:site:forged"));
}

#[test]
fn post_intake_coverage_and_evidence_shape_mutations_fail_sealed_authority_closed() {
    let assessment = load_assessment("complete-multi-role");
    let evidence_index = dp_evidence_index(&assessment);

    let mut missing_coverage = assessment.clone();
    missing_coverage
        .coverage
        .retain(|coverage| coverage.source_id != "server-dp-distribution");

    let mut duplicate_coverage = assessment.clone();
    let dp_coverage = duplicate_coverage
        .coverage
        .iter()
        .find(|coverage| coverage.source_id == "server-dp-distribution")
        .expect("fixture contains DP coverage")
        .clone();
    duplicate_coverage.coverage.push(dp_coverage);

    let mut holey_coverage = assessment.clone();
    holey_coverage
        .coverage
        .iter_mut()
        .find(|coverage| coverage.source_id == "server-dp-distribution")
        .expect("fixture contains DP coverage")
        .artifact_ids
        .push("dp-dist-undeclared".to_owned());

    let mut missing_evidence = assessment.clone();
    missing_evidence.evidence.remove(evidence_index);

    let mut duplicate_evidence = assessment.clone();
    duplicate_evidence
        .evidence
        .push(duplicate_evidence.evidence[evidence_index].clone());

    let mut holey_evidence = assessment.clone();
    holey_evidence.evidence[evidence_index].evidence_id = "dp-dist-current:1-1".to_owned();
    holey_evidence.evidence[evidence_index].reference.entry_id = "dp-dist-current:1-1".to_owned();
    holey_evidence.evidence[evidence_index].reference.line_start = Some(1);
    holey_evidence.evidence[evidence_index].reference.line_end = Some(1);
    let mut after_hole = holey_evidence.evidence[evidence_index].clone();
    after_hole.evidence_id = "dp-dist-current:3-3".to_owned();
    after_hole.reference.entry_id = "dp-dist-current:3-3".to_owned();
    after_hole.reference.line_start = Some(3);
    after_hole.reference.line_end = Some(3);
    holey_evidence.evidence.push(after_hole);

    let mut mismatched_evidence = assessment;
    mismatched_evidence.evidence[evidence_index].role = SccmRole::DistributionPoint;

    for (context, mutated) in [
        ("missing coverage", missing_coverage),
        ("duplicate coverage", duplicate_coverage),
        ("holey coverage", holey_coverage),
        ("missing evidence", missing_evidence),
        ("duplicate evidence", duplicate_evidence),
        ("holey evidence", holey_evidence),
        ("mismatched evidence", mismatched_evidence),
    ] {
        assert_dp_intake_authority_invalid(&mutated, context);
    }
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
fn post_intake_peer_mutations_fail_sealed_authority_closed() {
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

        let expected = assert_dp_intake_authority_invalid(&assessment, defect);
        assessment.artifacts.reverse();
        assessment.evidence.reverse();
        assessment.coverage.reverse();
        for coverage in &mut assessment.coverage {
            coverage.artifact_ids.reverse();
        }
        assert_eq!(
            expected,
            assert_dp_intake_authority_invalid(&assessment, defect),
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
