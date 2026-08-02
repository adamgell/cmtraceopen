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

fn load_expected(scenario: &str) -> Value {
    let path = intake_root().join(scenario).join("expected.json");
    let json = std::fs::read_to_string(path).expect("expected intake output is readable");
    serde_json::from_str(&json).expect("expected intake output is valid JSON")
}

fn opaque_handle(prefix: &str, ordinal: usize) -> String {
    format!("{prefix}{ordinal:064x}")
}

fn bounded_manifest(
    artifact_count: usize,
    byte_limit: u64,
) -> (String, Vec<SccmServerArtifactPayload>) {
    let capture_host = opaque_handle("cmtraceopen.host.sha256.v1:", 1);
    let site_code = opaque_handle("cmtraceopen.site.sha256.v1:", 1);
    let producer_host = opaque_handle("cmtraceopen.host.sha256.v1:", 2);
    let mut artifacts = Vec::with_capacity(artifact_count);
    let mut payloads = Vec::with_capacity(artifact_count);

    for ordinal in 0..artifact_count {
        let artifact_id = opaque_handle("cmtraceopen.artifact.sha256.v1:", ordinal);
        artifacts.push(json!({
            "artifactId": artifact_id.clone(),
            "producerRole": "managementPoint",
            "producerHostHandle": producer_host.clone(),
            "sourceId": "server-mp-policy",
            "sourceKind": "ccmLog",
            "sourceVersion": "5.00.9999.9999",
            "originalPath": "REDACTED",
            "originalBasename": "MP_GetPolicy.log",
            "configuredPathProvenance": {
                "state": "configured",
                "pathFingerprint": opaque_handle("cmtraceopen.path.sha256.v1:", ordinal),
            },
            "rotation": {
                "kind": "current",
                "lineageId": opaque_handle("cmtraceopen.lineage.sha256.v1:", ordinal),
            },
            "captureState": "captured",
            "encoding": "utf-8",
            "collectionLimit": { "byteLimit": byte_limit, "limitApplied": false },
            "collectedUtc": "2026-07-30T00:03:00Z",
            "relativePath": format!(
                "evidence/sccm/server/management-point/server-mp-policy/root-{ordinal:08x}/current/MP_GetPolicy.log"
            ),
            "bytesCopied": 0,
        }));
        payloads.push(SccmServerArtifactPayload {
            manifest_artifact_id: artifact_id,
            bytes: Vec::new(),
        });
    }

    (
        serde_json::to_string(&json!({
            "sccmManifestVersion": 1,
            "syntheticFixture": false,
            "bundleRole": "server",
            "topology": {
                "captureHost": capture_host,
                "siteCode": site_code,
                "rolesObserved": ["managementPoint"],
            },
            "artifacts": artifacts,
        }))
        .expect("bounded manifest serializes"),
        payloads,
    )
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
            Some(SccmRotation::Timestamped("20260729-235700".to_owned())),
            Some(SccmRotation::Numbered(2)),
            Some(SccmRotation::LoUnderscore),
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

#[test]
fn server_intake_marks_an_incomplete_tail_as_a_parse_gap_even_after_valid_evidence() {
    let (manifest_json, mut payloads) = load_bundle("multiline");
    let mut manifest = manifest_value(&manifest_json);
    payloads[0]
        .bytes
        .extend_from_slice(b"\n<![LOG[SYNTHETIC FIXTURE incomplete rotation tail");
    manifest["artifacts"][0]["bytesCopied"] = Value::from(payloads[0].bytes.len() as u64);

    let assessment = assess_server_intake(&serialize_manifest(&manifest), &payloads)
        .expect("complete evidence plus a partial tail remains assessable");

    assert_eq!(
        assessment.evidence.len(),
        1,
        "the complete record is retained"
    );
    assert_eq!(
        assessment.artifacts[0].state,
        SccmCoverageState::ParseFailed,
        "the unmatched tail is an explicit parse gap"
    );
    assert_eq!(assessment.next_artifact_requests.len(), 1);
}

#[test]
fn server_intake_keeps_a_zero_byte_capture_distinct_from_parse_failure() {
    let (manifest_json, mut payloads) = load_bundle("multiline");
    let mut manifest = manifest_value(&manifest_json);
    payloads[0].bytes.clear();
    manifest["artifacts"][0]["bytesCopied"] = Value::from(0);

    let assessment = assess_server_intake(&serialize_manifest(&manifest), &payloads)
        .expect("a bounded zero-byte capture remains valid capture provenance");

    assert_eq!(assessment.artifacts[0].state, SccmCoverageState::Captured);
    assert_eq!(assessment.coverage[0].state, SccmCoverageState::Captured);
    assert!(assessment.evidence.is_empty());
    assert!(assessment.next_artifact_requests.is_empty());
}

#[test]
fn server_intake_decodes_declared_utf16le_ccm_payloads() {
    let (manifest_json, mut payloads) = load_bundle("multiline");
    let mut manifest = manifest_value(&manifest_json);
    let content = String::from_utf8(payloads[0].bytes.clone()).expect("fixture is UTF-8");
    let mut utf16le = vec![0xff, 0xfe];
    for unit in content.encode_utf16() {
        utf16le.extend_from_slice(&unit.to_le_bytes());
    }
    payloads[0].bytes = utf16le;
    manifest["artifacts"][0]["encoding"] = Value::String("utf-16le".to_owned());
    manifest["artifacts"][0]["bytesCopied"] = Value::from(payloads[0].bytes.len() as u64);

    let assessment = assess_server_intake(&serialize_manifest(&manifest), &payloads)
        .expect("the declared UTF-16LE contract is decoded");

    assert_eq!(assessment.artifacts[0].state, SccmCoverageState::Captured);
    assert_eq!(assessment.evidence.len(), 1);
    assert!(assessment.evidence[0].message.contains("SYNTHETIC FIXTURE"));
}

#[test]
fn server_intake_decodes_declared_windows_1252_ccm_payloads() {
    let (manifest_json, mut payloads) = load_bundle("multiline");
    let mut manifest = manifest_value(&manifest_json);
    let marker = b"SYNTHETIC FIXTURE";
    let marker_start = payloads[0]
        .bytes
        .windows(marker.len())
        .position(|window| window == marker)
        .expect("fixture contains its synthetic marker");
    let marker_end = marker_start + marker.len();
    let mut windows_1252 = payloads[0].bytes[..marker_end].to_vec();
    windows_1252.extend_from_slice(b" caf");
    windows_1252.push(0xe9);
    windows_1252.push(b' ');
    windows_1252.push(0x80);
    windows_1252.extend_from_slice(&payloads[0].bytes[marker_end..]);
    payloads[0].bytes = windows_1252;
    manifest["artifacts"][0]["encoding"] = Value::String("windows-1252".to_owned());
    manifest["artifacts"][0]["bytesCopied"] = Value::from(payloads[0].bytes.len() as u64);

    let assessment = assess_server_intake(&serialize_manifest(&manifest), &payloads)
        .expect("the declared Windows-1252 contract is decoded");

    assert_eq!(assessment.artifacts[0].state, SccmCoverageState::Captured);
    assert_eq!(assessment.evidence.len(), 1);
    assert!(assessment.evidence[0].message.contains("café €"));
}

#[test]
fn server_intake_keeps_unknown_encoding_as_unsupported_coverage() {
    let (manifest_json, payloads) = load_bundle("multiline");
    let mut manifest = manifest_value(&manifest_json);
    manifest["artifacts"][0]["encoding"] = Value::String("unknown".to_owned());

    let assessment = assess_server_intake(&serialize_manifest(&manifest), &payloads)
        .expect("unknown encoding is retained without guessing a decoder");

    assert_eq!(
        assessment.artifacts[0].state,
        SccmCoverageState::Unsupported
    );
    assert!(!assessment.artifacts[0].parser_eligible);
    assert!(assessment.evidence.is_empty());
    assert_eq!(assessment.next_artifact_requests.len(), 1);
    let serialized = serde_json::to_value(&assessment).expect("assessment serializes");
    assert_eq!(
        serialized["artifacts"][0]["captureProvenance"]["encoding"],
        "unknown"
    );
}

#[test]
fn server_intake_retains_unsupported_source_provenance() {
    let (manifest_json, payloads) = load_bundle("unsupported-db-supplement");
    let assessment = assess_server_intake(&manifest_json, &payloads)
        .expect("unsupported source remains assessable");
    let serialized = serde_json::to_value(&assessment).expect("assessment serializes");
    let artifact = artifact_json(&serialized, "unknown-db-export");

    assert_eq!(artifact["sourceId"], "unknown-db-supplement");
    assert_eq!(artifact["sourceKind"], "unknown");
    assert_eq!(artifact["family"], "unknown-db-supplement");
    assert_eq!(artifact["originalBasename"], "synthetic-db-export.txt");
    assert_eq!(artifact["rotationLineageHandle"], "unknown-db-export");
    assert_eq!(
        serialized["coverage"][0]["sourceId"],
        "unknown-db-supplement"
    );
}

#[test]
fn server_intake_tolerates_future_safe_unsupported_source_labels() {
    let (manifest_json, payloads) = load_bundle("unsupported-db-supplement");
    let mut manifest = manifest_value(&manifest_json);
    manifest["artifacts"][0]["sourceId"] = Value::String("future-server-supplement".to_owned());
    manifest["artifacts"][0]["sourceKind"] = Value::String("futureSupplement".to_owned());

    let assessment = assess_server_intake(&serialize_manifest(&manifest), &payloads)
        .expect("a privacy-safe future unsupported label remains forward-compatible");
    let serialized = serde_json::to_value(&assessment).expect("assessment serializes");
    let artifact = artifact_json(&serialized, "unknown-db-export");

    assert_eq!(artifact["sourceId"], "future-server-supplement");
    assert_eq!(artifact["sourceKind"], "futureSupplement");
    assert_eq!(artifact["family"], "future-server-supplement");
}

#[test]
fn server_intake_bounds_each_declared_artifact_limit() {
    let (manifest_json, payloads) = bounded_manifest(1, 268_435_457);

    assert!(
        assess_server_intake(&manifest_json, &payloads).is_err(),
        "a single artifact may not declare more than 256 MiB"
    );
}

#[test]
fn server_intake_bounds_manifest_artifact_count() {
    let (manifest_json, payloads) = bounded_manifest(513, 4_096);

    assert!(
        assess_server_intake(&manifest_json, &payloads).is_err(),
        "a manifest may not force unbounded per-artifact work"
    );
}

#[test]
fn server_intake_bounds_aggregate_declared_bytes() {
    let (manifest_json, payloads) = bounded_manifest(5, 268_435_456);

    assert!(
        assess_server_intake(&manifest_json, &payloads).is_err(),
        "aggregate declared collection work may not exceed 1 GiB"
    );
}

#[test]
fn server_intake_rejects_evidence_later_than_collection_time() {
    let (manifest_json, payloads) = load_bundle("multiline");
    let mut manifest = manifest_value(&manifest_json);
    manifest["artifacts"][0]["collectedUtc"] = Value::String("2026-07-30T00:02:58Z".to_owned());

    assert!(
        assess_server_intake(&serialize_manifest(&manifest), &payloads).is_err(),
        "a comparable record instant cannot be later than collection"
    );
}

#[test]
fn server_intake_rejects_incoherent_configured_path_class() {
    let (manifest_json, payloads) = load_bundle("absent-dp");
    let mut manifest = manifest_value(&manifest_json);
    manifest["artifacts"][0]["configuredPathProvenance"]["pathClass"] =
        Value::String("nonDefault".to_owned());

    assert!(
        assess_server_intake(&serialize_manifest(&manifest), &payloads).is_err(),
        "a default candidate cannot claim non-default configured provenance"
    );
}

#[test]
fn server_intake_requires_producer_host_for_declared_sources() {
    let (manifest_json, payloads) = load_bundle("multiline");
    let mut manifest = manifest_value(&manifest_json);
    manifest["artifacts"][0]["producerHostHandle"] = Value::Null;

    assert!(
        assess_server_intake(&serialize_manifest(&manifest), &payloads).is_err(),
        "declared server evidence must retain its producer-host provenance"
    );
}

#[test]
fn server_intake_exercises_committed_expected_contracts() {
    let mut scenarios = std::fs::read_dir(intake_root())
        .expect("intake fixture root is readable")
        .filter_map(Result::ok)
        .filter(|entry| entry.path().join("expected.json").is_file())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    scenarios.sort();

    for scenario in scenarios {
        let expected = load_expected(&scenario);
        let (manifest_json, payloads) = load_bundle(&scenario);
        let assessment = assess_server_intake(&manifest_json, &payloads)
            .unwrap_or_else(|error| panic!("{scenario} should be assessed: {error}"));
        let actual = serde_json::to_value(&assessment).expect("assessment serializes");

        assert_eq!(
            actual["schemaVersion"], expected["pre318ExpectedVersion"],
            "{scenario}: expected contract version"
        );

        for key in [
            "canonicalArtifactIds",
            "canonicalRotationArtifactIds",
            "retainedUnclassifiedArtifactIds",
        ] {
            if let Some(expected_ids) = expected.get(key) {
                let actual_ids = Value::Array(
                    actual["artifacts"]
                        .as_array()
                        .expect("assessment artifacts are an array")
                        .iter()
                        .map(|artifact| artifact["artifactId"].clone())
                        .collect(),
                );
                assert_eq!(actual_ids, *expected_ids, "{scenario}: {key}");
            }
        }

        let expected_coverage = expected["coverage"]
            .as_array()
            .expect("expected coverage is an array");
        let actual_coverage = actual["coverage"]
            .as_array()
            .expect("assessment coverage is an array");
        assert_eq!(
            actual_coverage.len(),
            expected_coverage.len(),
            "{scenario}: coverage row count"
        );
        for (actual_row, expected_row) in actual_coverage.iter().zip(expected_coverage) {
            for key in ["producerRole", "workflowSubjectRole", "sourceId", "state"] {
                if let Some(expected_value) = expected_row.get(key) {
                    assert_eq!(
                        &actual_row[key], expected_value,
                        "{scenario}: coverage {key}"
                    );
                }
            }
        }

        if let Some(expected_provenance) = expected.get("artifactProvenance") {
            for expected_artifact in expected_provenance
                .as_array()
                .expect("artifact provenance is an array")
            {
                let artifact_id = expected_artifact["artifactId"]
                    .as_str()
                    .expect("expected artifactId is a string");
                let actual_artifact = artifact_json(&actual, artifact_id);
                for (expected_key, actual_value) in [
                    (
                        "encoding",
                        &actual_artifact["captureProvenance"]["encoding"],
                    ),
                    (
                        "byteLimit",
                        &actual_artifact["captureProvenance"]["byteLimit"],
                    ),
                    (
                        "limitApplied",
                        &actual_artifact["captureProvenance"]["limitApplied"],
                    ),
                    ("bytesCopied", &actual_artifact["bytesCopied"]),
                    ("relativePath", &actual_artifact["relativePath"]),
                ] {
                    if let Some(expected_value) = expected_artifact.get(expected_key) {
                        assert_eq!(
                            actual_value, expected_value,
                            "{scenario}: {artifact_id} {expected_key}"
                        );
                    }
                }
            }
        }

        if let Some(expected_evidence) = expected.get("evidence") {
            for expected_row in expected_evidence
                .as_array()
                .expect("expected evidence is an array")
            {
                let artifact_id = expected_row["artifactId"]
                    .as_str()
                    .expect("expected evidence artifactId is a string");
                let records = actual["evidence"]
                    .as_array()
                    .expect("assessment evidence is an array")
                    .iter()
                    .filter(|row| row["reference"]["artifactId"] == artifact_id)
                    .collect::<Vec<_>>();
                assert_eq!(
                    records.len() as u64,
                    expected_row["logicalRecordCount"]
                        .as_u64()
                        .expect("logicalRecordCount is an integer"),
                    "{scenario}: logical record count"
                );
                if let Some(line_range) = expected_row.get("lineRange") {
                    assert_eq!(records[0]["reference"]["lineStart"], line_range["start"]);
                    assert_eq!(records[0]["reference"]["lineEnd"], line_range["end"]);
                }
            }
        }

        if let Some(expected_path) = expected.get("configuredPathProvenance") {
            let artifact_id = expected["artifactId"]
                .as_str()
                .expect("configured-path expected artifactId is a string");
            let actual_artifact = artifact_json(&actual, artifact_id);
            assert_eq!(
                actual_artifact["configuredPathState"],
                expected_path["state"]
            );
            assert_eq!(
                actual_artifact["configuredPathClass"],
                expected_path["pathClass"]
            );
            assert_eq!(
                actual_artifact["pathFingerprint"],
                expected_path["pathFingerprint"]
            );
        }

        if let Some(expected_roles) = expected.get("rolesObserved") {
            assert_eq!(actual["topology"]["rolesObserved"], *expected_roles);
        }
    }
}
