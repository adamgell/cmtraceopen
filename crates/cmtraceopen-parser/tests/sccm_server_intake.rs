use cmtraceopen_parser::models::log_entry::Severity;
use cmtraceopen_parser::sccm::server::windows::{
    assess_server_intake, SccmServerArtifactPayload, SccmServerIntakeError,
};
use cmtraceopen_parser::sccm::{
    SccmConfidence, SccmCoverageState, SccmFinding, SccmFindingBuilder, SccmFindingClass,
    SccmFindingCoverageGap, SccmPhase, SccmRole, SccmRotation,
};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

fn intake_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sccm/server/intake")
}

fn load_bundle(scenario: &str) -> (String, Vec<SccmServerArtifactPayload>) {
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
                    .expect("artifactId is a string")
                    .to_owned(),
                bytes: std::fs::read(scenario_root.join(relative_path))
                    .expect("captured artifact bytes are readable"),
            })
        })
        .collect();
    (manifest_json, payloads)
}

fn manifest_value(manifest_json: &str) -> Value {
    serde_json::from_str(manifest_json).expect("manifest is valid JSON")
}

fn serialize_manifest(manifest: &Value) -> String {
    serde_json::to_string(manifest).expect("manifest serializes")
}

fn assert_unsafe_mutation_is_rejected(
    scenario: &str,
    marker: &str,
    mutate: impl FnOnce(&mut Value, &mut Vec<SccmServerArtifactPayload>),
) {
    let (manifest_json, mut payloads) = load_bundle(scenario);
    let mut manifest = manifest_value(&manifest_json);
    mutate(&mut manifest, &mut payloads);

    match assess_server_intake(&serialize_manifest(&manifest), &payloads) {
        Err(_) => {}
        Ok(assessment) => {
            let serialized = serde_json::to_string(&assessment).expect("assessment serializes");
            assert!(
                !serialized
                    .to_ascii_lowercase()
                    .contains(&marker.to_ascii_lowercase()),
                "unsafe marker was projected into public JSON: {serialized}"
            );
            panic!("unsafe manifest mutation was accepted");
        }
    }
}

fn artifact_json<'a>(assessment: &'a Value, artifact_id: &str) -> &'a Value {
    assessment["artifacts"]
        .as_array()
        .expect("assessment artifacts are an array")
        .iter()
        .find(|artifact| artifact["artifactId"] == artifact_id)
        .expect("artifact is present")
}

fn assert_request_passes_finding_boundaries(
    scenario: &str,
    assessment: &cmtraceopen_parser::sccm::server::windows::SccmServerIntakeAssessment,
) {
    let request = assessment
        .next_artifact_requests
        .first()
        .unwrap_or_else(|| panic!("{scenario} emits one bounded request"));
    let artifact = assessment
        .artifacts
        .first()
        .unwrap_or_else(|| panic!("{scenario} retains its coverage artifact"));
    let finding = SccmFindingBuilder::new(format!("server-intake-{scenario}"))
        .class(SccmFindingClass::InsufficientEvidence)
        .phase(SccmPhase::Unknown("serverIntake".to_owned()))
        .role(request.role.clone())
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .coverage_gap(SccmFindingCoverageGap {
            artifact_id: artifact.artifact_id.clone(),
            role: request.role.clone(),
            coverage: artifact.state.clone(),
        })
        .next_artifact(request.clone())
        .build()
        .unwrap_or_else(|error| panic!("{scenario} request must validate: {error:?}"));

    let serialized = serde_json::to_value(&finding)
        .unwrap_or_else(|error| panic!("{scenario} finding must serialize: {error}"));
    let deserialized = serde_json::from_value::<SccmFinding>(serialized)
        .unwrap_or_else(|error| panic!("{scenario} finding must deserialize: {error}"));
    assert_eq!(
        deserialized, finding,
        "{scenario} request and coverage data must survive the JSON boundary"
    );
}

#[test]
fn server_intake_normalizes_role_coverage_and_logical_records() {
    let (complete_manifest, complete_payloads) = load_bundle("complete-multi-role");
    let complete =
        assess_server_intake(&complete_manifest, &complete_payloads).expect("bundle is assessed");

    assert_eq!(complete.schema_version, 1);
    assert_eq!(
        complete
            .coverage
            .iter()
            .map(|row| (
                row.producer_role.clone(),
                row.workflow_subject_role.clone(),
                row.source_id.as_str(),
                row.state.clone(),
            ))
            .collect::<Vec<_>>(),
        vec![
            (
                SccmRole::ManagementPoint,
                None,
                "server-mp-policy",
                SccmCoverageState::Captured,
            ),
            (
                SccmRole::SiteServer,
                Some(SccmRole::DistributionPoint),
                "server-dp-distribution",
                SccmCoverageState::Captured,
            ),
            (
                SccmRole::SiteServer,
                None,
                "server-sitecomp",
                SccmCoverageState::Captured,
            ),
            (
                SccmRole::SiteServer,
                Some(SccmRole::SoftwareUpdatePoint),
                "server-sup-sync",
                SccmCoverageState::Captured,
            ),
        ]
    );
    assert_eq!(complete.evidence.len(), 4);
    assert!(complete.findings.is_empty());

    let (multiline_manifest, multiline_payloads) = load_bundle("multiline");
    let multiline =
        assess_server_intake(&multiline_manifest, &multiline_payloads).expect("bundle is assessed");
    assert_eq!(multiline.evidence.len(), 1);
    assert_eq!(multiline.evidence[0].reference.line_start, Some(1));
    assert_eq!(multiline.evidence[0].reference.line_end, Some(2));

    let (absent_manifest, absent_payloads) = load_bundle("absent-dp");
    let absent =
        assess_server_intake(&absent_manifest, &absent_payloads).expect("bundle is assessed");
    assert_eq!(absent.coverage.len(), 1);
    assert_eq!(absent.coverage[0].state, SccmCoverageState::Absent);
    assert!(absent.evidence.is_empty());
    assert!(absent.findings.is_empty());
    assert_eq!(absent.next_artifact_requests.len(), 1);
    assert_eq!(absent.next_artifact_requests[0].logical_id, "distmgr");

    let (unsorted_manifest, unsorted_payloads) = load_bundle("unsorted-manifest");
    let unsorted =
        assess_server_intake(&unsorted_manifest, &unsorted_payloads).expect("bundle is assessed");
    let mut reordered_manifest: Value =
        serde_json::from_str(&unsorted_manifest).expect("manifest is valid JSON");
    reordered_manifest["artifacts"]
        .as_array_mut()
        .expect("artifacts are an array")
        .reverse();
    let reordered = assess_server_intake(
        &serde_json::to_string(&reordered_manifest).expect("manifest serializes"),
        &unsorted_payloads,
    )
    .expect("reordered bundle is assessed");
    assert_eq!(
        serde_json::to_vec(&unsorted).expect("assessment serializes"),
        serde_json::to_vec(&reordered).expect("assessment serializes"),
        "manifest order must not affect normalized output"
    );
}

#[test]
fn server_intake_gap_requests_use_exact_shared_catalog_artifacts() {
    let cases = [
        (
            "absent-dp",
            "distmgr",
            SccmRole::SiteServer,
            "Collect the complete distmgr.log file.",
        ),
        (
            "access-denied-mp",
            "mpGetPolicy",
            SccmRole::ManagementPoint,
            "Collect the complete MP_GetPolicy.log file.",
        ),
        (
            "capped-sup",
            "wsyncmgr",
            SccmRole::SiteServer,
            "Collect the complete wsyncmgr.log file.",
        ),
    ];

    for (scenario, logical_id, role, reason) in cases {
        let (manifest, payloads) = load_bundle(scenario);
        let assessment = assess_server_intake(&manifest, &payloads)
            .unwrap_or_else(|error| panic!("{scenario} should be assessed: {error}"));

        assert_request_passes_finding_boundaries(scenario, &assessment);
        assert_eq!(assessment.next_artifact_requests.len(), 1, "{scenario}");
        let request = &assessment.next_artifact_requests[0];
        assert_eq!(request.logical_id, logical_id, "{scenario}");
        assert_eq!(request.role, role, "{scenario}");
        assert_eq!(request.reason, reason, "{scenario}");
    }
}

#[test]
fn server_intake_does_not_request_unknown_or_non_ccm_sources() {
    let (iis_manifest, iis_payloads) = load_bundle("skipped-iis");
    let mut denied_iis = manifest_value(&iis_manifest);
    denied_iis["artifacts"][0]["captureState"] = Value::String("accessDenied".to_owned());
    let iis = assess_server_intake(&serialize_manifest(&denied_iis), &iis_payloads)
        .expect("non-CCM coverage remains assessable");
    assert!(
        iis.next_artifact_requests.is_empty(),
        "a non-CCM group has no shared catalog artifact request"
    );

    let (unknown_manifest, unknown_payloads) = load_bundle("unsupported-db-supplement");
    let unknown = assess_server_intake(&unknown_manifest, &unknown_payloads)
        .expect("unknown coverage remains assessable");
    assert!(
        unknown.next_artifact_requests.is_empty(),
        "an unknown source has no shared catalog artifact request"
    );
}

#[test]
fn server_intake_rejects_identity_bearing_public_inputs() {
    assert_unsafe_mutation_is_rejected("complete-multi-role", "realuser", |manifest, _payloads| {
        manifest["artifacts"][0]["relativePath"] = Value::String(
            "evidence/sccm/server/site-server/server-sitecomp/current/RealUsersitecomp.log"
                .to_owned(),
        );
    });
    assert_unsafe_mutation_is_rejected("complete-multi-role", "realuser", |manifest, _payloads| {
        manifest["artifacts"][0]["relativePath"] = Value::String(
            "evidence/sccm/server/site-server/realuser/current/sitecomp.log".to_owned(),
        );
    });
    assert_unsafe_mutation_is_rejected(
        "complete-multi-role",
        "realuser.example.test",
        |manifest, _payloads| {
            manifest["artifacts"][0]["sourceVersion"] =
                Value::String("realuser.example.test".to_owned());
        },
    );
    assert_unsafe_mutation_is_rejected("complete-multi-role", "realuser", |manifest, payloads| {
        manifest["artifacts"][0]["artifactId"] = Value::String("realuser".to_owned());
        payloads[0].manifest_artifact_id = "realuser".to_owned();
    });
    assert_unsafe_mutation_is_rejected("complete-multi-role", "realuser", |manifest, _payloads| {
        manifest["artifacts"][0]["producerHostHandle"] =
            Value::String("synthetic:host:realuser".to_owned());
    });
    assert_unsafe_mutation_is_rejected("complete-multi-role", "realuser", |manifest, _payloads| {
        manifest["artifacts"][2]["workflowSubject"]["instanceHandle"] =
            Value::String("synthetic:subject:realuser".to_owned());
    });
    assert_unsafe_mutation_is_rejected("complete-multi-role", "realuser", |manifest, _payloads| {
        manifest["artifacts"][0]["configuredPathProvenance"]["pathFingerprint"] =
            Value::String("synthetic:path:realuser".to_owned());
    });
    assert_unsafe_mutation_is_rejected("complete-multi-role", "realuser", |manifest, _payloads| {
        manifest["artifacts"][0]["rotation"]["lineageId"] = Value::String("realuser".to_owned());
    });
    assert_unsafe_mutation_is_rejected("complete-multi-role", "realuser", |manifest, _payloads| {
        manifest["topology"]["captureHost"] = Value::String("LAB-REALUSER".to_owned());
    });
}

#[test]
fn server_intake_reserves_windows_equivalent_paths_and_fingerprints() {
    let (manifest_json, payloads) = load_bundle("collision-same-basename-configured-roots");
    let accepted =
        assess_server_intake(&manifest_json, &payloads).expect("distinct roots are valid");
    assert_eq!(accepted.artifacts.len(), 2);

    let mut case_collision = manifest_value(&manifest_json);
    case_collision["artifacts"][1]["relativePath"] = Value::String(
        "evidence/sccm/server/management-point/server-mp-policy/root-7D4A9C2E/current/MP_GetPolicy.log"
            .to_owned(),
    );
    assert!(
        assess_server_intake(&serialize_manifest(&case_collision), &payloads).is_err(),
        "Windows-equivalent destination paths must collide"
    );

    let mut fingerprint_collision = manifest_value(&manifest_json);
    fingerprint_collision["artifacts"][1]["configuredPathProvenance"]["pathFingerprint"] =
        fingerprint_collision["artifacts"][0]["configuredPathProvenance"]["pathFingerprint"]
            .clone();
    assert!(
        assess_server_intake(&serialize_manifest(&fingerprint_collision), &payloads).is_err(),
        "two physical candidates must not share one path fingerprint"
    );

    let mut exact_collision = manifest_value(&manifest_json);
    exact_collision["artifacts"][1]["relativePath"] =
        exact_collision["artifacts"][0]["relativePath"].clone();
    assert!(
        assess_server_intake(&serialize_manifest(&exact_collision), &payloads).is_err(),
        "exact destination paths must collide"
    );
}

#[test]
fn server_intake_rejects_mp_produced_mpcontrol_without_workflow_subject() {
    let (manifest_json, payloads) = load_bundle("complete-multi-role");
    let mut manifest = manifest_value(&manifest_json);
    let artifact = manifest["artifacts"]
        .as_array_mut()
        .expect("artifacts are an array")
        .iter_mut()
        .find(|artifact| artifact["artifactId"] == "mp-policy-current")
        .expect("MP policy artifact is present");
    artifact["originalBasename"] = Value::String("mpcontrol.log".to_owned());
    artifact["relativePath"] = Value::String(
        "evidence/sccm/server/management-point/server-mp-policy/current/mpcontrol.log".to_owned(),
    );

    assert!(
        assess_server_intake(&serialize_manifest(&manifest), &payloads).is_err(),
        "mpcontrol is not physically produced by the Management Point role"
    );
}

#[test]
fn server_intake_accepts_site_server_mpcontrol_with_management_point_subject() {
    let (manifest_json, payloads) = load_bundle("complete-multi-role");
    let mut manifest = manifest_value(&manifest_json);
    let artifact = manifest["artifacts"]
        .as_array_mut()
        .expect("artifacts are an array")
        .iter_mut()
        .find(|artifact| artifact["artifactId"] == "mp-policy-current")
        .expect("MP policy artifact is present");
    artifact["producerRole"] = Value::String("siteServer".to_owned());
    artifact["producerHostHandle"] = Value::String("synthetic:host:site-01".to_owned());
    artifact["workflowSubject"] = json!({ "role": "managementPoint" });
    artifact["originalBasename"] = Value::String("mpcontrol.log".to_owned());
    artifact["relativePath"] = Value::String(
        "evidence/sccm/server/site-server/server-mp-policy/subject-management-point/current/mpcontrol.log"
            .to_owned(),
    );

    let assessment = assess_server_intake(&serialize_manifest(&manifest), &payloads)
        .expect("site-server-produced MP control evidence is assessed");
    let mpcontrol = assessment
        .artifacts
        .iter()
        .find(|artifact| artifact.artifact_id == "mp-policy-current")
        .expect("MP control artifact is retained");
    assert_eq!(mpcontrol.producer_role, SccmRole::SiteServer);
    assert_eq!(
        mpcontrol.workflow_subject_role,
        Some(SccmRole::ManagementPoint)
    );
    assert_eq!(mpcontrol.source_id, "server-mp-policy");
}

#[test]
fn server_intake_rejects_relabelled_duplicate_canonical_artifact_identity() {
    let (manifest_json, payloads) = load_bundle("collision-same-basename-configured-roots");
    let mut manifest = manifest_value(&manifest_json);
    let fingerprint =
        manifest["artifacts"][0]["configuredPathProvenance"]["pathFingerprint"].clone();
    let lineage = manifest["artifacts"][0]["rotation"]["lineageId"].clone();
    manifest["artifacts"][1]["configuredPathProvenance"]["pathFingerprint"] = fingerprint;
    manifest["artifacts"][1]["rotation"]["lineageId"] = lineage;

    assert_eq!(
        assess_server_intake(&serialize_manifest(&manifest), &payloads),
        Err(SccmServerIntakeError::DuplicateArtifact),
        "caller-chosen artifact and root labels must not duplicate one canonical identity",
    );
}

#[test]
fn server_intake_scopes_canonical_identity_to_producer_host() {
    let (manifest_json, payloads) = load_bundle("collision-same-basename-configured-roots");
    let mut manifest = manifest_value(&manifest_json);
    let fingerprint =
        manifest["artifacts"][0]["configuredPathProvenance"]["pathFingerprint"].clone();
    let lineage = manifest["artifacts"][0]["rotation"]["lineageId"].clone();
    manifest["artifacts"][0]["producerHostHandle"] =
        Value::String("synthetic:host:site-01".to_owned());
    manifest["artifacts"][1]["producerHostHandle"] =
        Value::String("synthetic:host:mp-01".to_owned());
    manifest["artifacts"][1]["configuredPathProvenance"]["pathFingerprint"] = fingerprint;
    manifest["artifacts"][1]["rotation"]["lineageId"] = lineage;

    let assessment = assess_server_intake(&serialize_manifest(&manifest), &payloads)
        .expect("the same artifact identity on a distinct producer host is independent");
    assert_eq!(assessment.artifacts.len(), 2);
    assert_eq!(
        assessment
            .artifacts
            .iter()
            .map(|artifact| artifact.producer_host_handle.as_deref())
            .collect::<Vec<_>>(),
        vec![Some("synthetic:host:mp-01"), Some("synthetic:host:site-01"),],
        "producer-host provenance orders otherwise-equal artifacts before caller ids",
    );

    let mut reordered_manifest = manifest.clone();
    reordered_manifest["artifacts"]
        .as_array_mut()
        .expect("artifacts are an array")
        .reverse();
    let reordered = assess_server_intake(&serialize_manifest(&reordered_manifest), &payloads)
        .expect("reordered distinct-host artifacts are assessed");
    assert_eq!(
        serde_json::to_vec(&assessment).expect("assessment serializes"),
        serde_json::to_vec(&reordered).expect("reordered assessment serializes"),
        "distinct-host output is independent of manifest order",
    );
}

#[test]
fn server_intake_scopes_path_fingerprint_lineage_to_producer_host() {
    let (manifest_json, payloads) = load_bundle("collision-same-basename-configured-roots");
    let mut manifest = manifest_value(&manifest_json);
    let fingerprint =
        manifest["artifacts"][0]["configuredPathProvenance"]["pathFingerprint"].clone();
    manifest["artifacts"][1]["producerHostHandle"] =
        Value::String("synthetic:host:site-01".to_owned());
    manifest["artifacts"][1]["configuredPathProvenance"]["pathFingerprint"] = fingerprint;

    let assessment = assess_server_intake(&serialize_manifest(&manifest), &payloads)
        .expect("path fingerprints are scoped to their producer host");
    assert_eq!(assessment.artifacts.len(), 2);
}

fn configure_second_artifact_as_dp_identity(
    manifest: &mut Value,
    subject_handle: &str,
    share_lineage: bool,
) {
    let fingerprint =
        manifest["artifacts"][2]["configuredPathProvenance"]["pathFingerprint"].clone();
    let lineage = manifest["artifacts"][2]["rotation"]["lineageId"].clone();
    let artifact = &mut manifest["artifacts"][3];
    artifact["workflowSubject"] = json!({
        "role": "distributionPoint",
        "instanceHandle": subject_handle,
    });
    artifact["sourceId"] = Value::String("server-dp-distribution".to_owned());
    artifact["originalPath"] = Value::String("REDACTED_SITE_DP_CONTROL_ROOT_COPY".to_owned());
    artifact["originalBasename"] = Value::String("distmgr.log".to_owned());
    artifact["configuredPathProvenance"]["pathFingerprint"] = fingerprint;
    if share_lineage {
        artifact["rotation"]["lineageId"] = lineage;
    }
    artifact["relativePath"] = Value::String(
        "evidence/sccm/server/site-server/server-dp-distribution/subject-distribution-point/instance-bbbbbbbb/current/distmgr.log"
            .to_owned(),
    );
}

#[test]
fn server_intake_scopes_canonical_identity_to_workflow_subject() {
    let (manifest_json, payloads) = load_bundle("complete-multi-role");
    let mut manifest = manifest_value(&manifest_json);
    manifest["artifacts"][2]["workflowSubject"]["instanceHandle"] =
        Value::String("synthetic:subject:dp-02".to_owned());
    configure_second_artifact_as_dp_identity(&mut manifest, "synthetic:subject:dp-01", true);

    let assessment = assess_server_intake(&serialize_manifest(&manifest), &payloads)
        .expect("the same artifact identity for a distinct workflow subject is independent");
    assert_eq!(assessment.artifacts.len(), 4);
    assert_eq!(
        assessment
            .artifacts
            .iter()
            .filter(|artifact| artifact.source_id == "server-dp-distribution")
            .map(|artifact| artifact.workflow_subject_handle.as_deref())
            .collect::<Vec<_>>(),
        vec![
            Some("synthetic:subject:dp-01"),
            Some("synthetic:subject:dp-02"),
        ],
        "workflow-subject provenance orders otherwise-equal artifacts before caller ids",
    );

    let mut reordered_manifest = manifest.clone();
    reordered_manifest["artifacts"]
        .as_array_mut()
        .expect("artifacts are an array")
        .reverse();
    let reordered = assess_server_intake(&serialize_manifest(&reordered_manifest), &payloads)
        .expect("reordered distinct-subject artifacts are assessed");
    assert_eq!(
        serde_json::to_vec(&assessment).expect("assessment serializes"),
        serde_json::to_vec(&reordered).expect("reordered assessment serializes"),
        "distinct-subject output is independent of manifest order",
    );
}

#[test]
fn server_intake_scopes_path_fingerprint_lineage_to_workflow_subject() {
    let (manifest_json, payloads) = load_bundle("complete-multi-role");
    let mut manifest = manifest_value(&manifest_json);
    configure_second_artifact_as_dp_identity(&mut manifest, "synthetic:subject:dp-02", false);

    let assessment = assess_server_intake(&serialize_manifest(&manifest), &payloads)
        .expect("path fingerprints are scoped to their workflow subject");
    assert_eq!(assessment.artifacts.len(), 4);
}

#[test]
fn server_intake_rejects_relabelled_duplicate_for_same_workflow_subject() {
    let (manifest_json, payloads) = load_bundle("complete-multi-role");
    let mut manifest = manifest_value(&manifest_json);
    configure_second_artifact_as_dp_identity(&mut manifest, "synthetic:subject:dp-01", true);

    assert_eq!(
        assess_server_intake(&serialize_manifest(&manifest), &payloads),
        Err(SccmServerIntakeError::DuplicateArtifact),
        "caller labels cannot split one host-and-subject artifact identity",
    );
}

#[test]
fn server_intake_preserves_physical_parse_failure_provenance() {
    let (manifest_json, payloads) = load_bundle("multiline");
    let mut manifest = manifest_value(&manifest_json);
    manifest["artifacts"][0]["captureState"] = Value::String("parseFailed".to_owned());

    let assessment = assess_server_intake(&serialize_manifest(&manifest), &payloads)
        .expect("physical parse failure remains assessable");
    assert_eq!(
        assessment.artifacts[0].state,
        SccmCoverageState::ParseFailed
    );
    assert!(assessment.evidence.is_empty());
    assert!(assessment.findings.is_empty());
    assert_eq!(assessment.next_artifact_requests.len(), 1);

    let serialized = serde_json::to_value(&assessment).expect("assessment serializes");
    let artifact = artifact_json(&serialized, "mp-policy-multiline");
    assert_eq!(artifact["bytesCopied"], 207);
    assert_eq!(artifact["captureProvenance"]["schemaVersion"], 1);
    assert_eq!(artifact["captureProvenance"]["encoding"], "utf-8");
    assert_eq!(artifact["captureProvenance"]["byteLimit"], 4096);
    assert_eq!(artifact["captureProvenance"]["limitApplied"], false);
    assert_eq!(
        artifact["relativePath"],
        "evidence/sccm/server/management-point/server-mp-policy/current/MP_GetPolicy.log"
    );
}

#[test]
fn server_intake_converts_malformed_captured_ccm_to_parse_failed() {
    let (manifest_json, mut payloads) = load_bundle("multiline");
    let mut manifest = manifest_value(&manifest_json);
    payloads[0].bytes = b"not a complete CCM logical record".to_vec();
    manifest["artifacts"][0]["bytesCopied"] = Value::from(payloads[0].bytes.len() as u64);

    let assessment = assess_server_intake(&serialize_manifest(&manifest), &payloads)
        .expect("malformed collected bytes retain explicit partial coverage");
    assert_eq!(
        assessment.artifacts[0].state,
        SccmCoverageState::ParseFailed
    );
    assert!(assessment.evidence.is_empty());
    assert!(assessment.findings.is_empty());
    assert_eq!(assessment.next_artifact_requests.len(), 1);

    let serialized = serde_json::to_value(&assessment).expect("assessment serializes");
    let artifact = artifact_json(&serialized, "mp-policy-multiline");
    assert_eq!(artifact["captureProvenance"]["encoding"], "utf-8");
    assert_eq!(artifact["captureProvenance"]["byteLimit"], 4096);
    assert_eq!(artifact["captureProvenance"]["limitApplied"], false);
}

#[test]
fn server_intake_projects_versioned_capture_provenance() {
    let (captured_manifest, captured_payloads) = load_bundle("configured-nondefault-path");
    let captured = assess_server_intake(&captured_manifest, &captured_payloads)
        .expect("captured bundle is assessed");
    let captured_json = serde_json::to_value(&captured).expect("assessment serializes");
    let captured_artifact = artifact_json(&captured_json, "mp-policy-configured");
    assert_eq!(captured_artifact["captureProvenance"]["schemaVersion"], 1);
    assert_eq!(captured_artifact["captureProvenance"]["encoding"], "utf-8");
    assert_eq!(captured_artifact["captureProvenance"]["byteLimit"], 4096);
    assert_eq!(
        captured_artifact["captureProvenance"]["limitApplied"],
        false
    );

    let (capped_manifest, capped_payloads) = load_bundle("capped-sup");
    let capped = assess_server_intake(&capped_manifest, &capped_payloads)
        .expect("capped bundle is assessed");
    let capped_json = serde_json::to_value(&capped).expect("assessment serializes");
    let capped_artifact = artifact_json(&capped_json, "sup-sync-capped");
    assert_eq!(capped_artifact["captureProvenance"]["schemaVersion"], 1);
    assert_eq!(capped_artifact["captureProvenance"]["encoding"], "utf-8");
    assert_eq!(capped_artifact["captureProvenance"]["byteLimit"], 64);
    assert_eq!(capped_artifact["captureProvenance"]["limitApplied"], true);
}

#[test]
fn server_intake_suppresses_absent_default_request_when_configured_source_is_usable() {
    let (configured_manifest, configured_payloads) = load_bundle("configured-nondefault-path");
    let mut combined = manifest_value(&configured_manifest);
    let (absent_manifest, _absent_payloads) = load_bundle("access-denied-mp");
    let mut absent = manifest_value(&absent_manifest)["artifacts"][0].clone();
    absent["captureState"] = Value::String("absent".to_owned());
    absent["configuredPathProvenance"]["state"] = Value::String("defaultCandidate".to_owned());
    combined["artifacts"]
        .as_array_mut()
        .expect("artifacts are an array")
        .push(absent);

    let assessment = assess_server_intake(&serialize_manifest(&combined), &configured_payloads)
        .expect("compatible configured and default candidates are assessed together");
    assert_eq!(assessment.coverage.len(), 2);
    assert!(assessment
        .coverage
        .iter()
        .any(|row| row.state == SccmCoverageState::Captured));
    assert!(assessment
        .coverage
        .iter()
        .any(|row| row.state == SccmCoverageState::Absent));
    assert!(
        assessment.next_artifact_requests.is_empty(),
        "a usable configured candidate satisfies the logical source request"
    );
}

#[test]
fn server_intake_does_not_suppress_default_request_across_producer_hosts() {
    let (configured_manifest, configured_payloads) = load_bundle("configured-nondefault-path");
    let mut combined = manifest_value(&configured_manifest);
    let (absent_manifest, _absent_payloads) = load_bundle("access-denied-mp");
    let mut absent = manifest_value(&absent_manifest)["artifacts"][0].clone();
    absent["producerHostHandle"] = Value::String("synthetic:host:site-01".to_owned());
    absent["captureState"] = Value::String("absent".to_owned());
    absent["configuredPathProvenance"]["state"] = Value::String("defaultCandidate".to_owned());
    combined["artifacts"]
        .as_array_mut()
        .expect("artifacts are an array")
        .push(absent);

    let assessment = assess_server_intake(&serialize_manifest(&combined), &configured_payloads)
        .expect("distinct-host configured and default candidates are assessed together");
    assert_eq!(assessment.next_artifact_requests.len(), 1);
    assert_eq!(
        assessment.next_artifact_requests[0].logical_id,
        "mpGetPolicy"
    );
}

#[test]
fn server_intake_does_not_suppress_default_request_across_workflow_subjects() {
    let (captured_manifest, captured_payloads) = load_bundle("complete-multi-role");
    let mut combined = manifest_value(&captured_manifest);
    let (absent_manifest, _absent_payloads) = load_bundle("absent-dp");
    let mut absent = manifest_value(&absent_manifest)["artifacts"][0].clone();
    absent["workflowSubject"] = json!({
        "role": "distributionPoint",
        "instanceHandle": "synthetic:subject:dp-02",
    });
    combined["artifacts"]
        .as_array_mut()
        .expect("artifacts are an array")
        .push(absent);

    let assessment = assess_server_intake(&serialize_manifest(&combined), &captured_payloads)
        .expect("distinct-subject configured and default candidates are assessed together");
    assert_eq!(assessment.next_artifact_requests.len(), 1);
    assert_eq!(assessment.next_artifact_requests[0].logical_id, "distmgr");
}

#[test]
fn server_intake_exercises_role_state_rotation_and_privacy_matrix() {
    let cases = [
        (
            "configured-nondefault-path",
            SccmCoverageState::Captured,
            1,
            0,
        ),
        ("absent-dp", SccmCoverageState::Absent, 0, 1),
        ("access-denied-mp", SccmCoverageState::AccessDenied, 0, 1),
        ("capped-sup", SccmCoverageState::Capped, 0, 1),
        ("skipped-iis", SccmCoverageState::Skipped, 0, 0),
        (
            "unsupported-db-supplement",
            SccmCoverageState::Unsupported,
            0,
            0,
        ),
    ];
    for (scenario, state, evidence_count, request_count) in cases {
        let (manifest, payloads) = load_bundle(scenario);
        let assessment = assess_server_intake(&manifest, &payloads)
            .unwrap_or_else(|error| panic!("{scenario} should be assessed: {error}"));
        assert_eq!(assessment.coverage[0].state, state, "{scenario}");
        assert_eq!(assessment.evidence.len(), evidence_count, "{scenario}");
        assert_eq!(
            assessment.next_artifact_requests.len(),
            request_count,
            "{scenario}"
        );
        assert!(assessment.findings.is_empty(), "{scenario}");
        let public_json = serde_json::to_string(&assessment).expect("assessment serializes");
        assert!(!public_json.contains("REDACTED_"), "{scenario}");
        assert!(!public_json.contains("LAB-"), "{scenario}");
    }

    let (rotations_manifest, rotations_payloads) = load_bundle("rotations");
    let rotations = assess_server_intake(&rotations_manifest, &rotations_payloads)
        .expect("declared rotations are assessed");
    assert_eq!(
        rotations
            .artifacts
            .iter()
            .map(|artifact| artifact.rotation.clone())
            .collect::<Vec<_>>(),
        vec![
            Some(SccmRotation::LoUnderscore),
            Some(SccmRotation::Numbered(2)),
            Some(SccmRotation::Timestamped("20260729-235700".to_owned())),
            Some(SccmRotation::Current),
        ]
    );

    let mut unknown_rotation = manifest_value(&rotations_manifest);
    unknown_rotation["artifacts"][0]["rotation"]["kind"] = Value::String("unknown".to_owned());
    unknown_rotation["artifacts"][0]["rotation"]["value"] = Value::Null;
    assert!(
        assess_server_intake(&serialize_manifest(&unknown_rotation), &rotations_payloads).is_err(),
        "unknown rotations fail closed"
    );

    let (complete_manifest, complete_payloads) = load_bundle("complete-multi-role");
    let complete = assess_server_intake(&complete_manifest, &complete_payloads)
        .expect("role-aware bundle is assessed");
    assert_eq!(
        complete.topology.capture_host_handle,
        "synthetic:host:lab-cm01"
    );
    assert_eq!(
        complete.topology.roles_observed,
        vec![
            SccmRole::DistributionPoint,
            SccmRole::ManagementPoint,
            SccmRole::SiteServer,
            SccmRole::SoftwareUpdatePoint,
        ]
    );
}
