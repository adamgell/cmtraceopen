use std::path::{Path, PathBuf};

use cmtraceopen_parser::sccm::server::windows::{
    analyze_distribution_point, analyze_distribution_point_content_from_server_intake,
    assess_server_intake, SccmDistributionPointContentConfidence,
    SccmDistributionPointContentPhase, SccmDistributionPointContentState,
    SccmServerArtifactPayload, SccmServerIntakeAssessment, SccmServerIntakeError,
    SCCM_DISTRIBUTION_POINT_ANALYSIS_SCHEMA_VERSION, SCCM_DISTRIBUTION_POINT_INTAKE_PROFILE_ID,
    SCCM_DISTRIBUTION_POINT_INTAKE_PROFILE_VERSION,
};
use cmtraceopen_parser::sccm::{
    SccmArtifactRequest, SccmCoverageState, SccmRole, SccmRotation, SccmTimeOrderingState,
};
use serde_json::{json, Value};

fn artifact_request_contracts(requests: &[SccmArtifactRequest]) -> Vec<(&str, SccmRole, &str)> {
    requests
        .iter()
        .map(|request| {
            (
                request.logical_id.as_str(),
                request.role.clone(),
                request.reason.as_str(),
            )
        })
        .collect()
}

#[test]
fn production_content_lifecycle_covers_success_failure_and_bounded_progress_states() {
    let cases = [
        (
            "healthy-package",
            SccmDistributionPointContentState::Succeeded,
            Some(SccmDistributionPointContentPhase::MakeAvailable),
            None,
            0,
        ),
        (
            "distribution-failure",
            SccmDistributionPointContentState::Failed,
            Some(SccmDistributionPointContentPhase::ReceiveContent),
            Some(SccmDistributionPointContentPhase::Distribute),
            1,
        ),
        (
            "transfer-failure",
            SccmDistributionPointContentState::Failed,
            Some(SccmDistributionPointContentPhase::Distribute),
            Some(SccmDistributionPointContentPhase::Transfer),
            1,
        ),
        (
            "validation-failure",
            SccmDistributionPointContentState::Failed,
            Some(SccmDistributionPointContentPhase::Transfer),
            Some(SccmDistributionPointContentPhase::Validate),
            1,
        ),
        (
            "transfer-retry",
            SccmDistributionPointContentState::Retrying,
            Some(SccmDistributionPointContentPhase::Distribute),
            Some(SccmDistributionPointContentPhase::Transfer),
            0,
        ),
        (
            "backlog-blocked",
            SccmDistributionPointContentState::Blocked,
            Some(SccmDistributionPointContentPhase::Distribute),
            Some(SccmDistributionPointContentPhase::Transfer),
            0,
        ),
        (
            "transfer-deferred",
            SccmDistributionPointContentState::Deferred,
            Some(SccmDistributionPointContentPhase::Distribute),
            Some(SccmDistributionPointContentPhase::Transfer),
            0,
        ),
    ];

    for (scenario, state, last_phase, stop_phase, terminal_evidence_count) in cases {
        let assessment = load_distribution_point_assessment(scenario);
        let analysis = analyze_distribution_point_content_from_server_intake(&assessment)
            .unwrap_or_else(|error| panic!("{scenario} remains analyzable: {error}"));
        assert_eq!(analysis.transactions.len(), 1, "{scenario}");
        let transaction = &analysis.transactions[0];
        assert_eq!(transaction.state, state, "{scenario}");
        assert_eq!(transaction.last_proven_phase, last_phase, "{scenario}");
        assert_eq!(transaction.stop_phase, stop_phase, "{scenario}");
        assert_eq!(
            transaction.terminal_evidence.len(),
            terminal_evidence_count,
            "{scenario}"
        );
        if state == SccmDistributionPointContentState::Failed
            || state == SccmDistributionPointContentState::Succeeded
        {
            assert!(transaction.next_artifact.is_none(), "{scenario}");
        } else {
            assert_eq!(
                transaction
                    .next_artifact
                    .as_ref()
                    .map(|request| request.logical_id.as_str()),
                Some("pkgXferMgr"),
                "{scenario}"
            );
        }
    }
}

#[test]
fn optional_serve_recovery_and_exact_source_evidence_are_preserved() {
    let served = analyze_distribution_point_content_from_server_intake(
        &load_distribution_point_assessment("serve-observed"),
    )
    .expect("optional serving evidence is analyzable");
    assert_eq!(served.transactions.len(), 1);
    let served = &served.transactions[0];
    assert_eq!(
        served.last_proven_phase,
        Some(SccmDistributionPointContentPhase::ServeOrReport)
    );
    assert_eq!(
        served.confidence,
        SccmDistributionPointContentConfidence::High
    );
    assert_eq!(
        served
            .observations
            .last()
            .map(|item| item.source_id.as_str()),
        Some("server-dp-serve")
    );

    let recovered = analyze_distribution_point_content_from_server_intake(
        &load_distribution_point_assessment("contradiction-recovery"),
    )
    .expect("later exact success can recover an earlier terminal transfer failure");
    assert_eq!(recovered.transactions.len(), 1);
    let recovered = &recovered.transactions[0];
    assert_eq!(
        recovered.state,
        SccmDistributionPointContentState::Succeeded
    );
    assert!(recovered.recovered);
    assert_eq!(recovered.terminal_evidence.len(), 1);
    assert_eq!(
        recovered.terminal_evidence[0].artifact_id,
        "dp-recovery-02-pkgxfer"
    );
}

#[test]
fn unresolved_same_timestamp_outcomes_are_contradictory_and_request_one_source() {
    let assessment = load_distribution_point_assessment_after("transfer-retry", |_, payloads| {
        let payload = payloads
            .iter_mut()
            .find(|payload| payload.manifest_artifact_id == "dp-transfer-retry-02-pkgxfer")
            .expect("retry fixture has transfer evidence");
        let content = std::str::from_utf8(&payload.bytes).expect("fixture is UTF-8");
        let conflict = content.replace("Disposition=retrying", "Disposition=succeeded");
        payload.bytes.extend_from_slice(conflict.as_bytes());
    });
    let analysis = analyze_distribution_point_content_from_server_intake(&assessment)
        .expect("contradictory sealed evidence remains analyzable");
    assert_eq!(analysis.transactions.len(), 1);
    assert_eq!(
        analysis.transactions[0].state,
        SccmDistributionPointContentState::Contradictory
    );
    assert_eq!(
        analysis.transactions[0]
            .next_artifact
            .as_ref()
            .map(|request| request.logical_id.as_str()),
        Some("pkgXferMgr")
    );
}

#[test]
fn multiple_distribution_points_and_versions_sort_by_the_full_sealed_key() {
    let assessment = load_distribution_point_assessment("content-version-mismatch");
    let analysis = analyze_distribution_point_content_from_server_intake(&assessment)
        .expect("multi-DP version evidence is analyzable");
    assert_eq!(analysis.transactions.len(), 3);
    assert!(analysis
        .transactions
        .windows(2)
        .all(|pair| pair[0].key < pair[1].key));
    assert_eq!(
        analysis
            .transactions
            .iter()
            .map(|transaction| (
                transaction.key.distribution_point_handle.as_str(),
                transaction.key.content_version,
                transaction.content_version_mismatch,
                transaction.state,
            ))
            .collect::<Vec<_>>(),
        vec![
            (
                "synthetic:subject:dp-01",
                1,
                true,
                SccmDistributionPointContentState::Succeeded,
            ),
            (
                "synthetic:subject:dp-02",
                1,
                false,
                SccmDistributionPointContentState::Succeeded,
            ),
            (
                "synthetic:subject:dp-01",
                2,
                true,
                SccmDistributionPointContentState::Retrying,
            ),
        ]
    );

    let mut reordered = assessment.clone();
    reordered.artifacts.reverse();
    reordered.coverage.reverse();
    reordered.evidence.reverse();
    reordered.topology.roles_observed.reverse();
    assert_eq!(
        serde_json::to_value(analysis).expect("analysis serializes"),
        serde_json::to_value(
            analyze_distribution_point_content_from_server_intake(&reordered)
                .expect("reordered intake is analyzable"),
        )
        .expect("reordered analysis serializes")
    );
}

#[test]
fn production_matrix_matches_exact_full_output_oracles() {
    for scenario in [
        "healthy-package",
        "distribution-failure",
        "transfer-failure",
        "transfer-retry",
        "backlog-blocked",
        "transfer-deferred",
        "validation-failure",
        "serve-observed",
        "contradiction-recovery",
        "content-version-mismatch",
        "incomplete",
        "rotation-boundary",
        "malformed-current",
        "absent-dp",
    ] {
        let assessment = load_distribution_point_assessment(scenario);
        let analysis = analyze_distribution_point_content_from_server_intake(&assessment)
            .unwrap_or_else(|error| panic!("{scenario} remains analyzable: {error}"));
        let actual = serde_json::to_value(analysis).expect("analysis serializes");
        let expected_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/sccm/server/distribution_point")
            .join(scenario)
            .join("expected.json");
        let expected: Value = serde_json::from_str(
            &std::fs::read_to_string(&expected_path).expect("oracle is readable"),
        )
        .expect("oracle is valid JSON");
        assert_eq!(actual, expected, "{scenario}");
    }
}

#[test]
fn full_output_oracles_detect_omitted_and_mutated_lifecycle_authority() {
    let assessment = load_distribution_point_assessment("distribution-failure");
    let actual = serde_json::to_value(
        analyze_distribution_point_content_from_server_intake(&assessment)
            .expect("terminal failure remains analyzable"),
    )
    .expect("analysis serializes");

    let mut omitted = actual.clone();
    omitted["transactions"][0]
        .as_object_mut()
        .expect("transaction is an object")
        .remove("terminalEvidence");
    assert_ne!(actual, omitted, "terminal authority is oracle-visible");

    let mut mutated = actual.clone();
    mutated["transactions"][0]["terminalEvidence"][0]["lineStart"] = json!(1);
    assert_ne!(
        actual, mutated,
        "exact evidence coordinates are oracle-visible"
    );

    let mut weakened = actual.clone();
    weakened["transactions"][0]["classification"] = json!("success");
    weakened["transactions"][0]["severity"] = json!("Success");
    assert_ne!(
        actual, weakened,
        "class and severity cannot be silently weakened"
    );
}

#[test]
fn production_output_contains_no_self_attested_profile_or_raw_path_claims() {
    for scenario in [
        "healthy-package",
        "distribution-failure",
        "serve-observed",
        "content-version-mismatch",
        "incomplete",
    ] {
        let output = serde_json::to_string(
            &analyze_distribution_point_content_from_server_intake(
                &load_distribution_point_assessment(scenario),
            )
            .unwrap_or_else(|error| panic!("{scenario} remains analyzable: {error}")),
        )
        .expect("analysis serializes");
        assert!(!output.contains("ProfileId="), "{scenario}");
        assert!(!output.contains("originalPath"), "{scenario}");
        assert!(!output.contains("sanitizedSourcePath"), "{scenario}");
        assert!(!output.contains("safe:server:"), "{scenario}");
    }
}

fn expected_site_server_artifact_requests() -> Vec<(&'static str, SccmRole, &'static str)> {
    vec![
        (
            "distmgr",
            SccmRole::SiteServer,
            "Collect the complete distmgr.log file.",
        ),
        (
            "pkgXferMgr",
            SccmRole::SiteServer,
            "Collect the complete PkgXferMgr.log file.",
        ),
    ]
}

fn expected_all_dp_profile_artifact_requests() -> Vec<(&'static str, SccmRole, &'static str)> {
    let mut requests = expected_site_server_artifact_requests();
    requests.push((
        "smsDpProv",
        SccmRole::DistributionPoint,
        "Collect the complete SMSDPProv.log file.",
    ));
    requests
}

fn expected_dp_artifact_requests() -> Vec<(&'static str, SccmRole, &'static str)> {
    vec![(
        "smsDpProv",
        SccmRole::DistributionPoint,
        "Collect the complete SMSDPProv.log file.",
    )]
}

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
                    .expect("artifact id is a string")
                    .to_owned(),
                bytes: std::fs::read(scenario_root.join(relative_path))
                    .expect("captured evidence is readable"),
            })
        })
        .collect::<Vec<_>>();

    (manifest, payloads)
}

fn assess_manifest(
    manifest: &Value,
    payloads: &[SccmServerArtifactPayload],
) -> Result<SccmServerIntakeAssessment, SccmServerIntakeError> {
    let manifest_json = serde_json::to_string(manifest).expect("manifest serializes");
    assess_server_intake(&manifest_json, payloads)
}

fn assess_complete_manifest_after(
    mutate: impl FnOnce(&mut Value),
) -> Result<SccmServerIntakeAssessment, SccmServerIntakeError> {
    assess_complete_manifest_and_payloads_after(|manifest, _| mutate(manifest))
}

fn assess_complete_manifest_and_payloads_after(
    mutate: impl FnOnce(&mut Value, &mut Vec<SccmServerArtifactPayload>),
) -> Result<SccmServerIntakeAssessment, SccmServerIntakeError> {
    let (mut manifest, payloads) = load_manifest_and_payloads("complete-multi-role");
    let mut payloads = payloads;
    mutate(&mut manifest, &mut payloads);
    assess_manifest(&manifest, &payloads)
}

fn load_assessment(scenario: &str) -> SccmServerIntakeAssessment {
    let (manifest, payloads) = load_manifest_and_payloads(scenario);
    assess_manifest(&manifest, &payloads).expect("fixture intake is accepted")
}

fn load_distribution_point_assessment(scenario: &str) -> SccmServerIntakeAssessment {
    load_distribution_point_assessment_after(scenario, |_, _| {})
}

fn load_distribution_point_assessment_after(
    scenario: &str,
    mutate: impl FnOnce(&mut Value, &mut Vec<SccmServerArtifactPayload>),
) -> SccmServerIntakeAssessment {
    let scenario_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sccm/server/distribution_point")
        .join(scenario);
    let fixture_manifest_json =
        std::fs::read_to_string(scenario_root.join("manifest.json")).expect("manifest is readable");
    let mut manifest: Value =
        serde_json::from_str(&fixture_manifest_json).expect("manifest is valid JSON");
    let mut payloads = manifest["artifacts"]
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
    mutate(&mut manifest, &mut payloads);
    let canonical_manifest = json!({
        "sccmManifestVersion": 1,
        "syntheticFixture": true,
        "proposalOnly": true,
        "privacy": {"synthetic": true, "rawPaths": "redacted"},
        "bundleRole": "server",
        "topology": {
            "captureHost": "LAB-CM01",
            "siteCode": manifest["topology"]["siteCode"],
            "rolesObserved": manifest["topology"]["rolesObserved"],
        },
        "artifacts": manifest["artifacts"]
            .as_array()
            .expect("artifacts are an array")
            .iter()
            .map(|artifact| json!({
                "artifactId": artifact["artifactId"],
                "producerRole": artifact["producerRole"],
                "producerHostHandle": canonical_distribution_point_host_handle(
                    artifact["producerHostHandle"].as_str()
                ),
                "workflowSubject": if artifact["producerRole"] == "distributionPoint" {
                    Value::Null
                } else {
                    json!({
                        "role": artifact["workflowSubjectRole"],
                        "instanceHandle": canonical_distribution_point_subject_handle(
                            artifact["workflowSubjectHandle"].as_str()
                        ),
                    })
                },
                "sourceId": artifact["sourceId"],
                "sourceKind": artifact["sourceKind"],
                "sourceVersion": artifact["sourceVersion"],
                "originalPath": "REDACTED_DP_SOURCE_ROOT",
                "originalBasename": artifact["originalBasename"],
                "configuredPathProvenance": {
                    "state": "configured",
                    "pathFingerprint": artifact["pathFingerprint"],
                },
                "rotation": {
                    "kind": artifact["rotation"]["kind"],
                    "lineageId": artifact["rotation"]["lineageId"],
                },
                "captureState": artifact["captureState"],
                "truncated": if artifact["rotation"]["fragmentComplete"] == json!(false) {
                    json!(false)
                } else {
                    Value::Null
                },
                "fragmentComplete": if artifact["rotation"]["fragmentComplete"] == json!(false) {
                    json!(false)
                } else {
                    Value::Null
                },
                "encoding": artifact["encoding"],
                "collectionLimit": artifact["collectionLimit"],
                "collectedUtc": artifact["collectedUtc"],
                "relativePath": if matches!(
                    artifact["captureState"].as_str(),
                    Some("captured" | "capped" | "parseFailed")
                ) {
                    json!(canonical_distribution_point_relative_path(artifact))
                } else {
                    Value::Null
                },
                "bytesCopied": payloads
                    .iter()
                    .find(|payload| payload.manifest_artifact_id == artifact["artifactId"])
                    .map(|payload| payload.bytes.len() as u64)
                    .unwrap_or(0),
            }))
            .collect::<Vec<_>>(),
    });
    let canonical_manifest_json =
        serde_json::to_string(&canonical_manifest).expect("canonical manifest serializes");
    assess_server_intake(&canonical_manifest_json, &payloads)
        .expect("distribution point fixture is canonical server intake")
}

fn canonical_distribution_point_relative_path(artifact: &Value) -> String {
    let role_segment = match artifact["producerRole"].as_str() {
        Some("siteServer") => "site-server",
        Some("distributionPoint") => "distribution-point",
        _ => panic!("DP fixture has a supported producer role"),
    };
    let basename = artifact["originalBasename"]
        .as_str()
        .expect("DP fixture has a source basename");
    let subject_segment = match artifact["workflowSubjectHandle"].as_str() {
        _ if artifact["producerRole"] == "distributionPoint" => "",
        Some("safe:dp:lab-dp-01") => "subject-distribution-point/instance-aaaaaaaa/",
        Some("safe:dp:lab-dp-02") => "subject-distribution-point/instance-bbbbbbbb/",
        _ => "subject-distribution-point/",
    };
    let root_segment = match artifact["producerHostHandle"].as_str() {
        Some("safe:dp:lab-dp-01") => "root-aaaaaaaa/",
        Some("safe:dp:lab-dp-02") => "root-bbbbbbbb/",
        _ => "",
    };
    let source_id = artifact["sourceId"]
        .as_str()
        .expect("DP fixture has a source id");
    let rotation_segment = match artifact["rotation"]["kind"].as_str() {
        Some("current") => "current",
        Some("lo_") => "lo_",
        other => panic!("unsupported DP fixture rotation: {other:?}"),
    };
    format!(
        "evidence/sccm/server/{role_segment}/{source_id}/{subject_segment}{root_segment}{rotation_segment}/{basename}"
    )
}

fn canonical_distribution_point_host_handle(handle: Option<&str>) -> Value {
    match handle {
        Some("safe:server:lab-pri-01") => json!("synthetic:host:site-01"),
        Some("safe:dp:lab-dp-01") => json!("synthetic:host:mp-01"),
        Some("safe:dp:lab-dp-02") => json!("synthetic:host:wsus-01"),
        Some("safe:client:lab-client-01") => json!("synthetic:host:site-01"),
        None => Value::Null,
        Some(other) => panic!("unsupported DP fixture host handle: {other}"),
    }
}

fn canonical_distribution_point_subject_handle(handle: Option<&str>) -> Value {
    match handle {
        Some("safe:dp:lab-dp-01") => json!("synthetic:subject:dp-01"),
        Some("safe:dp:lab-dp-02") => json!("synthetic:subject:dp-02"),
        None => Value::Null,
        Some(other) => panic!("unsupported DP fixture subject handle: {other}"),
    }
}

fn dp_payload_mut(payloads: &mut [SccmServerArtifactPayload]) -> &mut SccmServerArtifactPayload {
    payloads
        .iter_mut()
        .find(|payload| payload.manifest_artifact_id == "dp-dist-current")
        .expect("fixture contains the DP payload")
}

fn set_dp_nonphysical_coverage(
    manifest: &mut Value,
    payloads: &mut Vec<SccmServerArtifactPayload>,
    state: &str,
) {
    let artifact = dp_manifest_artifact_mut(manifest);
    artifact["captureState"] = json!(state);
    artifact["relativePath"] = Value::Null;
    artifact["bytesCopied"] = json!(0);
    artifact["encoding"] = Value::Null;
    artifact["collectionLimit"] = Value::Null;
    artifact["collectionDetail"] = Value::Null;
    artifact["skipReason"] = Value::Null;
    artifact["unsupportedReason"] = Value::Null;
    match state {
        "accessDenied" => artifact["collectionDetail"] = json!("synthetic permission denial"),
        "skipped" => artifact["skipReason"] = json!("optional supplemental source not requested"),
        "unsupported" => {
            artifact["unsupportedReason"] = json!("no approved server source contract")
        }
        _ => {}
    }
    payloads.retain(|payload| payload.manifest_artifact_id != "dp-dist-current");
}

fn dp_coverage_assessment(case: &str) -> SccmServerIntakeAssessment {
    assess_complete_manifest_and_payloads_after(|manifest, payloads| match case {
        "absent" | "accessDenied" | "skipped" | "unsupported" => {
            set_dp_nonphysical_coverage(manifest, payloads, case);
        }
        "capped" => {
            let payload = dp_payload_mut(payloads);
            payload.bytes.truncate(64);
            let artifact = dp_manifest_artifact_mut(manifest);
            artifact["captureState"] = json!("capped");
            artifact["bytesCopied"] = json!(64);
            artifact["collectionLimit"] = json!({"byteLimit": 64, "limitApplied": true});
            artifact["truncated"] = json!(true);
            artifact["fragmentComplete"] = json!(false);
        }
        "malformed" => {
            let payload = dp_payload_mut(payloads);
            payload.bytes = b"not a complete CCM logical record".to_vec();
            let bytes_copied = payload.bytes.len() as u64;
            dp_manifest_artifact_mut(manifest)["bytesCopied"] = json!(bytes_copied);
        }
        _ => panic!("declared DP coverage case"),
    })
    .unwrap_or_else(|error| panic!("{case} DP coverage is sealed: {error}"))
}

fn dp_manifest_artifact_mut(manifest: &mut Value) -> &mut Value {
    manifest["artifacts"]
        .as_array_mut()
        .expect("artifacts are an array")
        .iter_mut()
        .find(|artifact| artifact["artifactId"] == "dp-dist-current")
        .expect("fixture contains the DP artifact")
}

fn dp_artifact_index(assessment: &SccmServerIntakeAssessment) -> usize {
    assessment
        .artifacts
        .iter()
        .position(|artifact| artifact.artifact_id == "dp-dist-current")
        .expect("fixture contains the DP artifact")
}

fn dp_evidence_index(assessment: &SccmServerIntakeAssessment) -> usize {
    assessment
        .evidence
        .iter()
        .position(|evidence| evidence.reference.artifact_id == "dp-dist-current")
        .expect("fixture contains the DP evidence")
}

fn add_dp_peer(assessment: &mut SccmServerIntakeAssessment) {
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

fn assert_dp_sealed_guard_rejection(
    assessment: &SccmServerIntakeAssessment,
    context: &str,
) -> Value {
    let analysis = analyze_distribution_point(assessment);
    assert!(
        analysis.source_observations.is_empty(),
        "{context}: rejected DP evidence must not become a source observation"
    );
    assert_eq!(analysis.coverage_gaps.len(), 1, "{context}");
    let gap = &analysis.coverage_gaps[0];
    assert_eq!(gap.source_id, "server-dp-distribution", "{context}");
    assert_eq!(gap.producer_role, Some(SccmRole::SiteServer), "{context}");
    assert_eq!(
        gap.workflow_subject_role,
        Some(SccmRole::DistributionPoint),
        "{context}"
    );
    assert_eq!(gap.state, Some(SccmCoverageState::Captured), "{context}");
    assert_eq!(gap.artifact_ids, vec!["dp-dist-current"], "{context}");
    assert_eq!(
        gap.reason,
        "Captured Distribution Point evidence is incomplete or outside the supported intake profile.",
        "{context}"
    );
    assert_eq!(
        artifact_request_contracts(&analysis.artifact_requests),
        expected_site_server_artifact_requests(),
        "{context}"
    );
    assert!(!analysis.cross_side_correlation_performed, "{context}");
    serde_json::to_value(analysis).expect("coverage-only analysis serializes")
}

fn assert_dp_intake_authority_invalid(
    assessment: &SccmServerIntakeAssessment,
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
    assert_eq!(
        artifact_request_contracts(&analysis.artifact_requests),
        expected_all_dp_profile_artifact_requests(),
        "{context}"
    );
    assert!(!analysis.cross_side_correlation_performed, "{context}");
    serde_json::to_value(analysis).expect("authority-invalid analysis serializes")
}

#[test]
fn distribution_point_adapter_projects_only_canonical_intake_observations_deterministically() {
    let assessment = load_assessment("complete-multi-role");

    let analysis = analyze_distribution_point(&assessment);

    assert!(!analysis.cross_side_correlation_performed);
    assert_eq!(
        analysis.schema_version,
        SCCM_DISTRIBUTION_POINT_ANALYSIS_SCHEMA_VERSION
    );
    assert_eq!(
        analysis.profile.id,
        SCCM_DISTRIBUTION_POINT_INTAKE_PROFILE_ID
    );
    assert_eq!(
        analysis.profile.version,
        SCCM_DISTRIBUTION_POINT_INTAKE_PROFILE_VERSION
    );
    assert_eq!(analysis.profile.stability, "experimental");
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
fn healthy_package_reduces_a_sealed_role_local_transaction() {
    let assessment = load_distribution_point_assessment("healthy-package");
    let bounded = analyze_distribution_point(&assessment);
    assert_eq!(bounded.source_observations.len(), 5);

    let analysis = analyze_distribution_point_content_from_server_intake(&assessment)
        .expect("healthy canonical intake must enter the DP semantic reducer");

    assert!(!analysis.cross_side_correlation_performed);
    assert_eq!(analysis.transactions.len(), 1);
    assert_eq!(analysis.transactions[0].key.package_id, "LAB00001");
    assert_eq!(analysis.transactions[0].key.content_id, "content-alpha");
    assert_eq!(analysis.transactions[0].key.content_version, 1);
    assert_eq!(
        analysis.transactions[0].key.topology_site_handle,
        assessment.topology.site_handle
    );
    assert_eq!(
        analysis.transactions[0]
            .key
            .distribution_point_handle
            .as_str(),
        "synthetic:subject:dp-01"
    );
    assert_eq!(analysis.transactions[0].evidence.len(), 5);
}

#[test]
fn newer_intake_valid_source_version_stays_outside_the_exact_semantic_profile() {
    let assessment = load_distribution_point_assessment_after("healthy-package", |manifest, _| {
        for artifact in manifest["artifacts"]
            .as_array_mut()
            .expect("artifacts are an array")
        {
            artifact["sourceVersion"] = json!("5.00.TEST.0002");
        }
    });
    assert!(assessment.artifacts.iter().all(|artifact| {
        artifact.profile_eligible && artifact.source_version.as_deref() == Some("5.00.TEST.0002")
    }));
    assert_eq!(
        analyze_distribution_point(&assessment)
            .source_observations
            .len(),
        5
    );

    let analysis = analyze_distribution_point_content_from_server_intake(&assessment)
        .expect("newer source version remains canonical intake");

    assert!(
        analysis.transactions.is_empty(),
        "the exact .0001 profile must not claim success for .0002 evidence"
    );
    assert_eq!(analysis.coverage_gaps.len(), 2);
    assert!(analysis
        .coverage_gaps
        .iter()
        .all(|gap| gap.state == Some(SccmCoverageState::Captured)));
    assert_eq!(
        artifact_request_contracts(&analysis.artifact_requests),
        expected_all_dp_profile_artifact_requests()
    );
}

#[test]
fn healthy_package_requires_profile_site_token_to_match_sealed_topology() {
    let mut mutated_records = 0usize;
    let assessment = load_distribution_point_assessment_after("healthy-package", |_, payloads| {
        for payload in payloads {
            let content =
                std::str::from_utf8(&payload.bytes).expect("synthetic DP evidence is UTF-8");
            assert!(
                content.contains("SiteCode=LAB"),
                "every healthy source must carry the profile site token"
            );
            mutated_records =
                mutated_records.saturating_add(content.matches("SiteCode=LAB").count());
            payload.bytes = content.replace("SiteCode=LAB", "SiteCode=ABC").into_bytes();
        }
    });
    assert_eq!(
        mutated_records, 5,
        "the required healthy phase chain is mutated"
    );
    assert_eq!(assessment.topology.site_handle, "synthetic:site:lab");

    let analysis = analyze_distribution_point_content_from_server_intake(&assessment)
        .expect("site-token mismatch remains sealed evidence, not forged authority");

    assert!(
        analysis.transactions.is_empty(),
        "valid-looking evidence for another site cannot become a healthy transaction"
    );
}

#[test]
fn semantic_analysis_preserves_conservative_source_coverage_and_bounded_requests() {
    for (case, expected_state) in [
        ("absent", SccmCoverageState::Absent),
        ("accessDenied", SccmCoverageState::AccessDenied),
        ("capped", SccmCoverageState::Capped),
        ("skipped", SccmCoverageState::Skipped),
        ("unsupported", SccmCoverageState::Unsupported),
        ("malformed", SccmCoverageState::ParseFailed),
    ] {
        let assessment = dp_coverage_assessment(case);
        let analysis = analyze_distribution_point_content_from_server_intake(&assessment)
            .unwrap_or_else(|error| panic!("{case} coverage remains analyzable: {error}"));

        assert!(analysis.transactions.is_empty(), "{case}");
        assert_eq!(analysis.coverage_gaps.len(), 1, "{case}");
        assert_eq!(
            analysis.coverage_gaps[0].state,
            Some(expected_state),
            "{case}"
        );
        assert_eq!(
            artifact_request_contracts(&analysis.artifact_requests),
            expected_site_server_artifact_requests(),
            "{case}"
        );

        let repeated =
            analyze_distribution_point_content_from_server_intake(&dp_coverage_assessment(case))
                .expect("repeated coverage remains analyzable");
        assert_eq!(
            serde_json::to_value(&analysis).expect("analysis serializes"),
            serde_json::to_value(repeated).expect("repeated analysis serializes"),
            "{case} output is deterministic"
        );
    }
}

#[test]
fn incomplete_and_unknown_evidence_remain_explicit_bounded_results() {
    let incomplete =
        load_distribution_point_assessment_after("healthy-package", |manifest, payloads| {
            let provider = payloads
                .iter_mut()
                .find(|payload| payload.manifest_artifact_id == "dp-healthy-03-provider")
                .expect("fixture contains provider payload");
            let content =
                std::str::from_utf8(&provider.bytes).expect("synthetic provider evidence is UTF-8");
            let retained = content
                .lines()
                .filter(|line| !line.contains("Phase=makeAvailable"))
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";
            provider.bytes = retained.into_bytes();
            manifest["artifacts"]
                .as_array_mut()
                .expect("artifacts are an array")
                .iter_mut()
                .find(|artifact| artifact["artifactId"] == "dp-healthy-03-provider")
                .expect("fixture contains provider artifact")["bytesCopied"] =
                json!(provider.bytes.len() as u64);
        });
    let incomplete_analysis = analyze_distribution_point_content_from_server_intake(&incomplete)
        .expect("incomplete semantic evidence remains analyzable");
    assert_eq!(incomplete_analysis.transactions.len(), 1);
    assert_eq!(
        format!("{:?}", incomplete_analysis.transactions[0].state),
        "Incomplete"
    );
    assert!(incomplete_analysis.coverage_gaps.is_empty());
    assert_eq!(
        artifact_request_contracts(&incomplete_analysis.artifact_requests),
        expected_dp_artifact_requests()
    );

    let unknown_profile =
        load_distribution_point_assessment_after("healthy-package", |_, payloads| {
            for payload in payloads {
                let content =
                    std::str::from_utf8(&payload.bytes).expect("synthetic DP evidence is UTF-8");
                payload.bytes = content
                    .replace("Disposition=succeeded", "Disposition=unknown")
                    .into_bytes();
            }
        });
    let unknown_analysis = analyze_distribution_point_content_from_server_intake(&unknown_profile)
        .expect("unknown semantic profile remains analyzable");
    assert!(unknown_analysis.transactions.is_empty());
    assert_eq!(unknown_analysis.coverage_gaps.len(), 2);
    assert!(unknown_analysis
        .coverage_gaps
        .iter()
        .all(|gap| gap.state == Some(SccmCoverageState::Captured)));
    assert_eq!(
        artifact_request_contracts(&unknown_analysis.artifact_requests),
        expected_all_dp_profile_artifact_requests()
    );
}

#[test]
fn healthy_transaction_cannot_hide_a_sealed_coverage_gap_or_keep_high_confidence() {
    let assessment = load_distribution_point_assessment_after("healthy-package", |manifest, _| {
        manifest["artifacts"]
            .as_array_mut()
            .expect("artifacts are an array")
            .push(json!({
                "artifactId": "dp-distribution-absent-candidate",
                "sourceId": "server-dp-distribution",
                "producerRole": "siteServer",
                "producerHostHandle": "safe:server:lab-pri-01",
                "workflowSubjectRole": "distributionPoint",
                "workflowSubjectHandle": "safe:dp:lab-dp-01",
                "sourceKind": "ccmLog",
                "sourceVersion": "5.00.TEST.0001",
                "originalBasename": "distmgr.log",
                "pathFingerprint": "synthetic:path:dp-default",
                "rotation": {"kind": "current", "lineageId": "dp-distribution-default"},
                "captureState": "absent",
                "encoding": null,
                "collectionLimit": null,
                "collectedUtc": "2026-07-30T12:20:00Z",
                "relativePath": null,
                "bytesCopied": 0
            }));
    });

    let analysis = analyze_distribution_point_content_from_server_intake(&assessment)
        .expect("mixed healthy and missing coverage remains analyzable");

    assert_eq!(analysis.transactions.len(), 1);
    assert_eq!(analysis.coverage_gaps.len(), 1);
    assert_eq!(
        analysis.coverage_gaps[0].state,
        Some(SccmCoverageState::Absent)
    );
    assert_eq!(
        artifact_request_contracts(&analysis.artifact_requests),
        expected_site_server_artifact_requests()
    );
    assert_eq!(
        analysis.transactions[0].confidence,
        SccmDistributionPointContentConfidence::Medium
    );
}

#[test]
fn sealed_intake_without_dp_source_version_reaches_profile_eligibility_guard() {
    let assessment = assess_complete_manifest_after(|manifest| {
        dp_manifest_artifact_mut(manifest)
            .as_object_mut()
            .expect("DP artifact is an object")
            .remove("sourceVersion");
    })
    .expect("missing source version is retained as sealed, profile-ineligible intake");
    let artifact = &assessment.artifacts[dp_artifact_index(&assessment)];

    assert_eq!(artifact.source_version, None);
    assert!(!artifact.profile_eligible);
    assert!(artifact.parser_eligible);
    assert_eq!(
        artifact.workflow_subject_handle.as_deref(),
        Some("synthetic:subject:dp-01")
    );
    assert!(assessment
        .topology
        .roles_observed
        .contains(&SccmRole::DistributionPoint));
    assert_dp_sealed_guard_rejection(&assessment, "missing DP source version");
}

#[test]
fn sealed_intake_without_dp_subject_handle_reaches_subject_congruence_guard() {
    let assessment = assess_complete_manifest_after(|manifest| {
        let subject = dp_manifest_artifact_mut(manifest)["workflowSubject"]
            .as_object_mut()
            .expect("workflow subject is an object");
        subject.remove("instanceHandle");
        subject.insert(
            "basis".to_owned(),
            Value::String("incidentScopeOnly".to_owned()),
        );
    })
    .expect("missing subject handle is retained as sealed intake");
    let artifact = &assessment.artifacts[dp_artifact_index(&assessment)];

    assert!(artifact.profile_eligible);
    assert!(artifact.parser_eligible);
    assert_eq!(
        artifact.workflow_subject_role,
        Some(SccmRole::DistributionPoint)
    );
    assert_eq!(artifact.workflow_subject_handle, None);
    assert!(assessment
        .topology
        .roles_observed
        .contains(&SccmRole::DistributionPoint));
    assert_dp_sealed_guard_rejection(&assessment, "missing DP subject handle");
}

#[test]
fn sealed_intake_without_observed_dp_role_reaches_topology_congruence_guard() {
    let assessment = assess_complete_manifest_after(|manifest| {
        manifest["topology"]["rolesObserved"]
            .as_array_mut()
            .expect("observed roles are an array")
            .retain(|role| role.as_str() != Some("distributionPoint"));
    })
    .expect("unobserved workflow-subject role is retained as sealed intake");
    let artifact = &assessment.artifacts[dp_artifact_index(&assessment)];

    assert!(artifact.profile_eligible);
    assert!(artifact.parser_eligible);
    assert_eq!(
        artifact.workflow_subject_handle.as_deref(),
        Some("synthetic:subject:dp-01")
    );
    assert!(!assessment
        .topology
        .roles_observed
        .contains(&SccmRole::DistributionPoint));
    assert_dp_sealed_guard_rejection(&assessment, "unobserved DP workflow-subject role");
}

#[test]
fn dp_subject_role_mismatch_is_rejected_before_intake_sealing() {
    let result = assess_complete_manifest_after(|manifest| {
        dp_manifest_artifact_mut(manifest)["workflowSubject"]["role"] =
            Value::String("managementPoint".to_owned());
    });

    assert!(
        matches!(result, Err(SccmServerIntakeError::InvalidArtifact)),
        "role/source mismatch must not produce a sealed assessment: {result:?}"
    );
}

#[test]
fn dp_rotation_mismatch_is_rejected_before_intake_sealing() {
    let result = assess_complete_manifest_after(|manifest| {
        dp_manifest_artifact_mut(manifest)["rotation"]["kind"] = Value::String("lo_".to_owned());
    });

    assert!(
        matches!(result, Err(SccmServerIntakeError::InvalidArtifact)),
        "basename/rotation mismatch must not produce a sealed assessment: {result:?}"
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
    assert_eq!(
        analysis.coverage_gaps[0].reason,
        "Distribution Point source coverage is absent; recollect the declared source without changing its state."
    );
    assert_eq!(
        artifact_request_contracts(&analysis.artifact_requests),
        expected_site_server_artifact_requests()
    );
    serde_json::to_value(&analysis).expect("coverage-only analysis serializes");
}

#[test]
fn no_declared_dp_source_requests_both_bounded_sides_without_correlation() {
    let assessment = load_assessment("collision-same-basename-configured-roots");

    let analysis = analyze_distribution_point(&assessment);

    assert!(analysis.source_observations.is_empty());
    assert_eq!(analysis.coverage_gaps.len(), 1);
    assert_eq!(analysis.coverage_gaps[0].producer_role, None);
    assert_eq!(
        artifact_request_contracts(&analysis.artifact_requests),
        expected_all_dp_profile_artifact_requests()
    );
    assert!(!analysis.cross_side_correlation_performed);
}

#[test]
fn post_intake_duplicate_dp_artifact_identity_is_authority_quarantined_deterministically() {
    let mut assessment = load_assessment("complete-multi-role");
    let artifact_index = dp_artifact_index(&assessment);
    let mut duplicate = assessment.artifacts[artifact_index].clone();
    duplicate.producer_host_handle = Some("synthetic:host:site-02".to_owned());
    duplicate.path_fingerprint = "synthetic:path:site-dp-control-02".to_owned();
    assessment.artifacts.push(duplicate);

    let first = assert_dp_intake_authority_invalid(&assessment, "duplicate DP artifact identity");
    assessment.artifacts.reverse();
    let reversed =
        assert_dp_intake_authority_invalid(&assessment, "reordered duplicate DP artifact identity");

    assert_eq!(first, reversed);
}

#[test]
fn post_intake_evidence_range_mutations_are_authority_quarantined() {
    let assessment = load_assessment("complete-multi-role");
    let evidence_index = dp_evidence_index(&assessment);

    let mut missing_range = assessment.clone();
    missing_range.evidence[evidence_index].reference.line_start = None;
    assert_dp_intake_authority_invalid(&missing_range, "missing evidence range start");

    let mut duplicate = assessment.clone();
    duplicate
        .evidence
        .push(duplicate.evidence[evidence_index].clone());
    assert_dp_intake_authority_invalid(&duplicate, "duplicate evidence range");

    let mut overlap = assessment.clone();
    let mut overlapping = overlap.evidence[evidence_index].clone();
    overlapping.evidence_id = "dp-dist-current:1-2".to_owned();
    overlapping.reference.entry_id = "dp-dist-current:1-2".to_owned();
    overlapping.reference.line_end = Some(2);
    overlap.evidence.push(overlapping);
    assert_dp_intake_authority_invalid(&overlap, "overlapping evidence range");
}

#[test]
fn post_intake_physical_line_hole_is_authority_quarantined() {
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

    assert_dp_intake_authority_invalid(&assessment, "physical evidence line hole");
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
fn post_intake_missing_exact_coverage_membership_is_authority_quarantined() {
    // Canonical intake derives coverage membership from normalized artifacts.
    // A missing membership is therefore a post-intake integrity mutation, not
    // a separately reachable adapter-predicate state.
    let mut assessment = load_assessment("complete-multi-role");
    assessment
        .coverage
        .retain(|coverage| coverage.source_id != "server-dp-distribution");

    assert_dp_intake_authority_invalid(&assessment, "missing exact coverage membership");
}

#[test]
fn post_intake_role_topology_profile_and_rotation_mutations_are_authority_quarantined() {
    let assessment = load_assessment("complete-multi-role");
    let artifact_index = dp_artifact_index(&assessment);

    let mut wrong_role = assessment.clone();
    wrong_role.artifacts[artifact_index].workflow_subject_role = Some(SccmRole::ManagementPoint);
    assert_dp_intake_authority_invalid(&wrong_role, "workflow-subject role mutation");

    let mut missing_topology = assessment.clone();
    missing_topology
        .topology
        .roles_observed
        .retain(|role| role != &SccmRole::DistributionPoint);
    assert_dp_intake_authority_invalid(&missing_topology, "topology role mutation");

    let mut ineligible_profile = assessment.clone();
    ineligible_profile.artifacts[artifact_index].profile_eligible = false;
    assert_dp_intake_authority_invalid(&ineligible_profile, "profile eligibility mutation");

    let mut wrong_rotation = assessment.clone();
    wrong_rotation.artifacts[artifact_index].rotation = Some(SccmRotation::LoUnderscore);
    assert_dp_intake_authority_invalid(&wrong_rotation, "rotation mutation");
}
