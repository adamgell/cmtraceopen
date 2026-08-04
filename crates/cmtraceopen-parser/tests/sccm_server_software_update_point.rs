use std::path::{Path, PathBuf};

use cmtraceopen_parser::sccm::server::windows::{
    analyze_software_update_point, assess_server_intake, SccmServerArtifactPayload,
    SccmServerIntakeAssessment, SccmSoftwareUpdatePointDiagnosticMeaning,
};
use cmtraceopen_parser::sccm::{SccmCoverageState, SccmRole};
use serde_json::Value;

fn intake_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sccm/server/intake")
}

fn load_manifest_and_payloads(scenario: &str) -> (Value, Vec<SccmServerArtifactPayload>) {
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
                    .expect("artifact ID is a string")
                    .to_owned(),
                bytes: std::fs::read(scenario_root.join(relative_path))
                    .expect("captured payload is readable"),
            })
        })
        .collect();

    (manifest, payloads)
}

fn load_assessment(scenario: &str) -> SccmServerIntakeAssessment {
    let (manifest, payloads) = load_manifest_and_payloads(scenario);
    assess_manifest(&manifest, &payloads)
}

fn assess_manifest(
    manifest: &Value,
    payloads: &[SccmServerArtifactPayload],
) -> SccmServerIntakeAssessment {
    assess_server_intake(
        &serde_json::to_string(&manifest).expect("manifest serializes"),
        payloads,
    )
    .expect("fixture is accepted by canonical server intake")
}

#[test]
fn capped_sup_projects_only_canonical_coverage_and_its_bounded_recapture() {
    let assessment = load_assessment("capped-sup");

    let analysis = analyze_software_update_point(&assessment);

    assert_eq!(
        analysis.diagnostic_meaning,
        SccmSoftwareUpdatePointDiagnosticMeaning::CoverageOnly
    );
    assert!(!analysis.cross_side_correlation_performed);
    assert_eq!(analysis.coverage_rows.len(), 1);
    let row = &analysis.coverage_rows[0];
    assert_eq!(row.artifact_id, "sup-sync-capped");
    assert_eq!(row.source_id, "server-sup-sync");
    assert_eq!(row.producer_role, SccmRole::SiteServer);
    assert_eq!(
        row.producer_host_handle.as_deref(),
        Some("synthetic:host:site-01")
    );
    assert_eq!(
        row.workflow_subject_role,
        Some(SccmRole::SoftwareUpdatePoint)
    );
    assert_eq!(
        row.workflow_subject_handle.as_deref(),
        Some("synthetic:subject:sup-01")
    );
    assert_eq!(row.capture_state, SccmCoverageState::Capped);
    assert_eq!(row.rotation_fragment_complete, Some(false));
    assert!(row.profile_eligible);

    assert_eq!(analysis.coverage_gaps.len(), 1);
    assert_eq!(
        analysis.coverage_gaps[0].artifact_id.as_deref(),
        Some("sup-sync-capped")
    );
    assert_eq!(
        analysis.coverage_gaps[0].capture_state,
        SccmCoverageState::Capped
    );
    assert_eq!(
        analysis.coverage_gaps[0].workflow_subject_role,
        Some(SccmRole::SoftwareUpdatePoint)
    );
    assert_eq!(
        analysis.next_artifact_requests,
        assessment.next_artifact_requests
    );
}

#[test]
fn captured_wsyncmgr_is_an_observation_without_a_health_or_outcome_interpretation() {
    let assessment = load_assessment("complete-multi-role");

    let analysis = analyze_software_update_point(&assessment);
    let serialized = serde_json::to_value(&analysis).expect("coverage analysis serializes");

    assert_eq!(analysis.coverage_rows.len(), 1);
    assert_eq!(analysis.coverage_rows[0].artifact_id, "sup-sync-current");
    assert_eq!(
        analysis.coverage_rows[0].capture_state,
        SccmCoverageState::Captured
    );
    assert!(analysis.coverage_gaps.is_empty());
    assert!(analysis.next_artifact_requests.is_empty());
    assert_eq!(
        serialized["diagnosticMeaning"],
        Value::String("coverageOnly".to_owned())
    );
    for forbidden in [
        "transaction",
        "health",
        "success",
        "failure",
        "finding",
        "evidence",
    ] {
        assert!(
            !serialized.to_string().contains(forbidden),
            "coverage-only output must not expose {forbidden} interpretation"
        );
    }
}

#[test]
fn sup_analysis_excludes_an_unrelated_management_point_recapture_request() {
    let (mut manifest, mut payloads) = load_manifest_and_payloads("complete-multi-role");
    let management_point = manifest["artifacts"]
        .as_array_mut()
        .expect("artifacts are an array")
        .iter_mut()
        .find(|artifact| artifact["artifactId"] == "mp-policy-current")
        .expect("complete multi-role fixture includes MP_GetPolicy");
    management_point["captureState"] = Value::String("accessDenied".to_owned());
    management_point["collectionDetail"] = Value::String("synthetic permission denial".to_owned());
    management_point["relativePath"] = Value::Null;
    management_point["bytesCopied"] = Value::from(0);
    let fields = management_point
        .as_object_mut()
        .expect("artifact is an object");
    fields.remove("encoding");
    fields.remove("collectionLimit");
    payloads.retain(|payload| payload.manifest_artifact_id != "mp-policy-current");

    let assessment = assess_manifest(&manifest, &payloads);
    assert_eq!(assessment.next_artifact_requests.len(), 1);
    assert_eq!(
        assessment.next_artifact_requests[0].logical_id, "mpGetPolicy",
        "canonical intake keeps the MP recapture request"
    );
    assert_eq!(
        assessment.next_artifact_requests[0].role,
        SccmRole::ManagementPoint
    );

    let analysis = analyze_software_update_point(&assessment);

    assert_eq!(analysis.coverage_rows.len(), 1);
    assert_eq!(analysis.coverage_rows[0].artifact_id, "sup-sync-current");
    assert!(analysis.next_artifact_requests.is_empty());
}

#[test]
fn non_captured_sup_gaps_report_the_canonical_state_without_claiming_no_capture() {
    let capped = analyze_software_update_point(&load_assessment("capped-sup"));
    assert_eq!(capped.coverage_gaps.len(), 1);
    assert_eq!(
        capped.coverage_gaps[0].reason,
        "Canonical intake reports Software Update Point source coverage as capped; no outcome is inferred."
    );

    let (mut manifest, mut payloads) = load_manifest_and_payloads("complete-multi-role");
    let payload = payloads
        .iter_mut()
        .find(|payload| payload.manifest_artifact_id == "sup-sync-current")
        .expect("complete multi-role fixture includes wsyncmgr bytes");
    payload.bytes = b"not a complete CCM logical record".to_vec();
    let software_update_point = manifest["artifacts"]
        .as_array_mut()
        .expect("artifacts are an array")
        .iter_mut()
        .find(|artifact| artifact["artifactId"] == "sup-sync-current")
        .expect("complete multi-role fixture includes wsyncmgr");
    software_update_point["bytesCopied"] = Value::from(payload.bytes.len() as u64);

    let parse_failed = analyze_software_update_point(&assess_manifest(&manifest, &payloads));
    assert_eq!(parse_failed.coverage_gaps.len(), 1);
    assert_eq!(
        parse_failed.coverage_gaps[0].capture_state,
        SccmCoverageState::ParseFailed
    );
    assert_eq!(
        parse_failed.coverage_gaps[0].reason,
        "Canonical intake reports Software Update Point source coverage as parseFailed; no outcome is inferred."
    );
}

#[test]
fn skipped_supplemental_wsus_is_coverage_not_wsus_health_proof() {
    let assessment = load_assessment("supplemental-wsus-skipped");

    let analysis = analyze_software_update_point(&assessment);

    assert_eq!(analysis.coverage_rows.len(), 1);
    let row = &analysis.coverage_rows[0];
    assert_eq!(row.artifact_id, "sup-wsus-health-skipped");
    assert_eq!(row.source_id, "server-sup-wsus");
    assert_eq!(row.producer_role, SccmRole::WsUs);
    assert_eq!(
        row.workflow_subject_role,
        Some(SccmRole::SoftwareUpdatePoint)
    );
    assert_eq!(row.capture_state, SccmCoverageState::Skipped);
    assert_eq!(row.rotation_fragment_complete, None);
    assert!(row.profile_eligible);
    assert_eq!(analysis.coverage_gaps.len(), 1);
    assert_eq!(
        analysis.coverage_gaps[0].producer_role,
        Some(SccmRole::WsUs)
    );
    assert_eq!(
        analysis.coverage_gaps[0].workflow_subject_role,
        Some(SccmRole::SoftwareUpdatePoint)
    );
    assert_eq!(
        analysis.coverage_gaps[0].capture_state,
        SccmCoverageState::Skipped
    );
    assert_eq!(
        analysis.next_artifact_requests,
        assessment.next_artifact_requests
    );
}

#[test]
fn tampered_intake_fails_closed_to_one_authority_coverage_gap() {
    let mut assessment = load_assessment("complete-multi-role");
    assessment.artifacts[0].artifact_id = "forged-artifact".to_owned();

    let analysis = analyze_software_update_point(&assessment);

    assert!(analysis.coverage_rows.is_empty());
    assert!(analysis.next_artifact_requests.is_empty());
    assert_eq!(analysis.coverage_gaps.len(), 1);
    assert_eq!(
        analysis.coverage_gaps[0].reason,
        "Canonical server intake authority could not be verified."
    );
    assert_eq!(
        analysis.coverage_gaps[0].capture_state,
        SccmCoverageState::ParseFailed
    );
    assert!(!analysis.cross_side_correlation_performed);
}

#[test]
fn topology_only_tampering_fails_closed_to_one_authority_coverage_gap() {
    let mut assessment = load_assessment("complete-multi-role");
    assessment.topology.roles_observed.pop();

    let analysis = analyze_software_update_point(&assessment);

    assert!(analysis.coverage_rows.is_empty());
    assert!(analysis.next_artifact_requests.is_empty());
    assert_eq!(analysis.coverage_gaps.len(), 1);
    assert_eq!(
        analysis.coverage_gaps[0].reason,
        "Canonical server intake authority could not be verified."
    );
}

#[test]
fn same_size_catalog_valid_request_tampering_fails_closed_to_one_authority_coverage_gap() {
    let mut assessment = load_assessment("capped-sup");
    assert_eq!(assessment.next_artifact_requests.len(), 1);
    assessment.next_artifact_requests[0]
        .reason
        .replace_range(0..1, "X");

    let analysis = analyze_software_update_point(&assessment);

    assert!(analysis.coverage_rows.is_empty());
    assert!(analysis.next_artifact_requests.is_empty());
    assert_eq!(analysis.coverage_gaps.len(), 1);
    assert_eq!(
        analysis.coverage_gaps[0].reason,
        "Canonical server intake authority could not be verified."
    );
}

#[test]
fn reordered_sealed_intake_serializes_to_identical_coverage_analysis() {
    let assessment = load_assessment("complete-multi-role");
    let mut reordered = assessment.clone();
    reordered.artifacts.reverse();
    reordered.coverage.reverse();
    reordered.evidence.reverse();
    reordered.next_artifact_requests.reverse();
    reordered.topology.roles_observed.reverse();

    assert_eq!(
        serde_json::to_vec(&analyze_software_update_point(&assessment))
            .expect("original coverage analysis serializes"),
        serde_json::to_vec(&analyze_software_update_point(&reordered))
            .expect("reordered coverage analysis serializes")
    );
}
