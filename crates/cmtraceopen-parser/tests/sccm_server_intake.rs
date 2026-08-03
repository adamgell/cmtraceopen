use cmtraceopen_parser::sccm::server::windows::{assess_server_intake, SccmServerArtifactPayload};
use cmtraceopen_parser::sccm::{SccmCoverageState, SccmRole, SccmRotation};
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

/// Identity-bearing shapes that must never reach a public synthetic surface: a
/// bare account name, a hyphenated account name, a second account name, an
/// FQDN, a down-level logon name, a UPN, a SID, a braced GUID, a UNC share, a
/// drive-letter path, an IPv4 address, and a NetBIOS-style server name.
const IDENTITY_SHAPES: &[&str] = &[
    "realuser",
    "real-user",
    "adamgell",
    "dc01.contoso.com",
    "contoso\\adminuser",
    "administrator@contoso.com",
    "s-1-5-21-1004336348-1177238915-682003330-512",
    "{3f2504e0-4f89-11d3-9a0c-0305e82c3301}",
    "\\\\fileserver\\share",
    "d:/program files/sms_ccm",
    "10.0.0.5",
    "srv-prd-01",
];

/// The same shapes cast the way a ConfigMgr capture host would be written.
const IDENTITY_HOST_SHAPES: &[&str] = &[
    "REALUSER",
    "LAB-REALUSER",
    "LAB-ADAMGELL01",
    "CONTOSO-DC01",
    "DC01.CONTOSO.COM",
    "SRV-PRD-01",
    "CM01",
    "LAB-CM01-CONTOSO",
];

/// Every public string surface that a synthetic manifest supplies verbatim.
#[derive(Clone, Copy)]
enum SyntheticSurface {
    ArtifactId,
    LineageId,
    PathFingerprint,
    ProducerHostHandle,
    WorkflowSubjectHandle,
}

impl SyntheticSurface {
    const ALL: [Self; 5] = [
        Self::ArtifactId,
        Self::LineageId,
        Self::PathFingerprint,
        Self::ProducerHostHandle,
        Self::WorkflowSubjectHandle,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::ArtifactId => "artifactId",
            Self::LineageId => "rotation.lineageId",
            Self::PathFingerprint => "configuredPathProvenance.pathFingerprint",
            Self::ProducerHostHandle => "producerHostHandle",
            Self::WorkflowSubjectHandle => "workflowSubject.instanceHandle",
        }
    }

    fn namespace(self) -> &'static str {
        match self {
            Self::ArtifactId | Self::LineageId => "",
            Self::PathFingerprint => "synthetic:path:",
            Self::ProducerHostHandle => "synthetic:host:",
            Self::WorkflowSubjectHandle => "synthetic:subject:",
        }
    }

    /// The only committed artifact carrying a workflow subject handle is the
    /// distribution-point control record; every other surface is exercised on
    /// the first artifact.
    fn artifact_index(self) -> usize {
        match self {
            Self::WorkflowSubjectHandle => 2,
            _ => 0,
        }
    }

    /// A novel value drawn from the vocabulary the committed corpus uses.
    fn conforming_label(self) -> &'static str {
        match self {
            Self::ArtifactId | Self::LineageId => "sitecomp-capped-b",
            Self::PathFingerprint => "site-capped-b",
            Self::ProducerHostHandle => "site-03",
            Self::WorkflowSubjectHandle => "dp-03",
        }
    }

    fn apply(self, manifest: &mut Value, payloads: &mut [SccmServerArtifactPayload], label: &str) {
        let written = format!("{}{label}", self.namespace());
        let artifact = &mut manifest["artifacts"][self.artifact_index()];
        match self {
            Self::ArtifactId => {
                let committed = artifact["artifactId"]
                    .as_str()
                    .expect("artifactId is a string")
                    .to_owned();
                artifact["artifactId"] = Value::String(written.clone());
                for payload in payloads {
                    if payload.manifest_artifact_id == committed {
                        payload.manifest_artifact_id = written.clone();
                    }
                }
            }
            Self::LineageId => artifact["rotation"]["lineageId"] = Value::String(written),
            Self::PathFingerprint => {
                artifact["configuredPathProvenance"]["pathFingerprint"] = Value::String(written);
            }
            Self::ProducerHostHandle => artifact["producerHostHandle"] = Value::String(written),
            Self::WorkflowSubjectHandle => {
                artifact["workflowSubject"]["instanceHandle"] = Value::String(written);
            }
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
    assert_eq!(
        absent.next_artifact_requests[0].logical_id,
        "server-dp-distribution"
    );

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

    assert!(
        assess_server_intake(&serialize_manifest(&manifest), &payloads).is_err(),
        "caller-chosen artifact and root labels must not duplicate one canonical identity"
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

/// A fixture author must be able to declare new synthetic identifiers without
/// editing production source. Every identifier written below conforms to the
/// synthetic vocabulary the committed corpus already uses, and none of them
/// appears in any committed intake fixture.
#[test]
fn server_intake_admits_conforming_new_synthetic_identifiers() {
    let (manifest_json, mut payloads) = load_bundle("complete-multi-role");
    let mut manifest = manifest_value(&manifest_json);
    manifest["topology"]["captureHost"] = Value::String("LAB-DP01".to_owned());

    let rewrites = [
        (
            "sitecomp-current",
            "sitecomp-supplied-b",
            "synthetic:host:site-02",
            "synthetic:path:site-supplied-b",
            "sitecomp-supplied-b",
            None,
        ),
        (
            "mp-policy-current",
            "mp-policy-supplied-b",
            "synthetic:host:mp-02",
            "synthetic:path:mp-supplied-b",
            "mp-policy-supplied-b",
            None,
        ),
        (
            "dp-dist-current",
            "dp-distribution-supplied-b",
            "synthetic:host:site-02",
            "synthetic:path:site-dp-supplied-b",
            "dp-distribution-supplied-b",
            Some("synthetic:subject:dp-02"),
        ),
        (
            "sup-sync-current",
            "sup-sync-supplied-b",
            "synthetic:host:site-02",
            "synthetic:path:site-sup-supplied-b",
            "sup-sync-supplied-b",
            Some("synthetic:subject:sup-02"),
        ),
    ];

    for (committed_id, artifact_id, host_handle, fingerprint, lineage_id, subject_handle) in
        rewrites
    {
        let artifact = manifest["artifacts"]
            .as_array_mut()
            .expect("artifacts are an array")
            .iter_mut()
            .find(|artifact| artifact["artifactId"] == committed_id)
            .unwrap_or_else(|| panic!("{committed_id} is present"));
        artifact["artifactId"] = Value::String(artifact_id.to_owned());
        artifact["producerHostHandle"] = Value::String(host_handle.to_owned());
        artifact["configuredPathProvenance"]["pathFingerprint"] =
            Value::String(fingerprint.to_owned());
        artifact["rotation"]["lineageId"] = Value::String(lineage_id.to_owned());
        if let Some(subject_handle) = subject_handle {
            artifact["workflowSubject"]["instanceHandle"] =
                Value::String(subject_handle.to_owned());
        }
        for payload in &mut payloads {
            if payload.manifest_artifact_id == committed_id {
                payload.manifest_artifact_id = artifact_id.to_owned();
            }
        }
    }

    let assessment = assess_server_intake(&serialize_manifest(&manifest), &payloads)
        .expect("a conforming synthetic vocabulary must not require a production-source edit");
    let serialized = serde_json::to_string(&assessment).expect("assessment serializes");
    for projected in [
        "synthetic:host:lab-dp01",
        "sitecomp-supplied-b",
        "mp-policy-supplied-b",
        "dp-distribution-supplied-b",
        "sup-sync-supplied-b",
        "synthetic:host:site-02",
        "synthetic:host:mp-02",
        "synthetic:path:site-supplied-b",
        "synthetic:path:mp-supplied-b",
        "synthetic:path:site-dp-supplied-b",
        "synthetic:path:site-sup-supplied-b",
        "synthetic:subject:dp-02",
        "synthetic:subject:sup-02",
    ] {
        assert!(
            serialized.contains(projected),
            "{projected} is not projected: {serialized}"
        );
    }
}

/// The gate on synthetic identifiers has to discriminate, not merely reject.
/// Asserting only that identity-bearing values fail can be satisfied by
/// refusing everything, and asserting only that new values pass can be
/// satisfied by accepting everything, so each surface is exercised both ways in
/// one test.
#[test]
fn server_intake_discriminates_conforming_labels_from_identity_shapes() {
    for surface in SyntheticSurface::ALL {
        let (manifest_json, mut payloads) = load_bundle("complete-multi-role");
        let mut manifest = manifest_value(&manifest_json);
        surface.apply(&mut manifest, &mut payloads, surface.conforming_label());
        assert!(
            assess_server_intake(&serialize_manifest(&manifest), &payloads).is_ok(),
            "{} must admit a conforming novel label",
            surface.label()
        );

        for shape in IDENTITY_SHAPES {
            assert_unsafe_mutation_is_rejected(
                "complete-multi-role",
                shape,
                |manifest, payloads| {
                    surface.apply(manifest, payloads.as_mut_slice(), shape);
                },
            );
        }
    }

    let (manifest_json, payloads) = load_bundle("complete-multi-role");
    let mut manifest = manifest_value(&manifest_json);
    manifest["topology"]["captureHost"] = Value::String("LAB-SUP01".to_owned());
    assert!(
        assess_server_intake(&serialize_manifest(&manifest), &payloads).is_ok(),
        "topology.captureHost must admit a conforming novel synthetic host"
    );
    for shape in IDENTITY_HOST_SHAPES {
        assert_unsafe_mutation_is_rejected("complete-multi-role", shape, |manifest, _payloads| {
            manifest["topology"]["captureHost"] = Value::String((*shape).to_owned());
        });
    }

    // The synthetic site code stays a single reserved token on purpose. Every
    // three-character code is shaped exactly like a real ConfigMgr site code,
    // so no grammar can widen this surface without admitting a real one.
    for shape in ["CTS", "PRD", "HQ1", "S01", "CONTOSO"] {
        assert_unsafe_mutation_is_rejected("complete-multi-role", shape, |manifest, _payloads| {
            manifest["topology"]["siteCode"] = Value::String(shape.to_owned());
        });
    }
}

/// An unclassified supplement declares that it satisfies no source contract, so
/// the declared catalog cannot name its `sourceId` and intake pins the value to
/// one committed fixture spelling instead. That literal is the last remaining
/// fixture string in production source, and it is not gated on the synthetic
/// flag at all.
///
/// The projected `sourceId` for this path is the constant `unsupported`, so the
/// declared value never reaches a public surface; it still has to stay a
/// bounded, non-identity-bearing label, and it still has to admit a spelling
/// the committed corpus has not already used.
#[test]
fn server_intake_admits_any_conforming_unclassified_supplement_source_id() {
    for source_id in [
        "unknown-registry-supplement",
        "unknown-status-export",
        "unknown-provider-supplement",
    ] {
        let (manifest_json, payloads) = load_bundle("unsupported-db-supplement");
        let mut manifest = manifest_value(&manifest_json);
        manifest["artifacts"][0]["sourceId"] = Value::String(source_id.to_owned());

        let assessment = assess_server_intake(&serialize_manifest(&manifest), &payloads)
            .unwrap_or_else(|error| {
                panic!("{source_id} is a conforming unclassified supplement: {error}")
            });
        let serialized = serde_json::to_string(&assessment).expect("assessment serializes");
        assert!(
            !serialized.contains(source_id),
            "an unclassified sourceId must not reach a public surface: {serialized}"
        );
        assert_eq!(
            assessment.artifacts[0].source_id, "unsupported",
            "an unclassified supplement projects the constant source id"
        );
        assert_eq!(
            assessment.coverage[0].source_id, "unsupported",
            "coverage projects the constant source id too"
        );
    }

    // The same surface must still refuse an identity-bearing value.
    for shape in IDENTITY_SHAPES {
        assert_unsafe_mutation_is_rejected(
            "unsupported-db-supplement",
            shape,
            |manifest, _payloads| {
                manifest["artifacts"][0]["sourceId"] = Value::String((*shape).to_owned());
            },
        );
    }
}

/// A classified artifact's `sourceId` names a declared source contract, so the
/// declared catalog is the only authority over it. Widening the unclassified
/// path must not widen this one: an id the catalog does not declare stays
/// rejected however well-formed it is.
#[test]
fn server_intake_binds_classified_source_ids_to_the_declared_catalog() {
    for undeclared in [
        "server-hierarchy-control",
        "server-provider",
        "server-admin-service",
        "unknown-db-supplement",
    ] {
        let (manifest_json, payloads) = load_bundle("complete-multi-role");
        let mut manifest = manifest_value(&manifest_json);
        manifest["artifacts"][0]["sourceId"] = Value::String(undeclared.to_owned());
        assert!(
            assess_server_intake(&serialize_manifest(&manifest), &payloads).is_err(),
            "{undeclared} is not a declared server source contract"
        );
    }
}
