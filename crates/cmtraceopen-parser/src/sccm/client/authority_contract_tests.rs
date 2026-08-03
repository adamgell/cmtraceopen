use sha2::{Digest, Sha256};

use super::admission::{
    admit_client_evidence, SccmClientAdmittedEvidence, SccmClientCapturedPayload,
    SccmClientEvidenceAdmissionError,
};
use super::{assess_client_intake, SccmClientIntakeArtifact, SccmClientIntakeBundle};
use crate::sccm::{
    extract_keys, SccmArtifact, SccmArtifactFamily, SccmCorrelationKeyKind, SccmCoverageState,
    SccmExtractionGapKind, SccmExtractionProfile, SccmExtractionProfileMaturity, SccmKeyConfidence,
    SccmRole, SccmRotation, SCCM_EXPERIMENTAL_KEY_PROFILE_ID,
};

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn ccm_bytes(message: &str) -> Vec<u8> {
    format!(
        concat!(
            "<![LOG[{message}]LOG]!><time=\"00:00:07.000+000\" ",
            "date=\"7-30-2026\" component=\"Synthetic\" context=\"\" ",
            "type=\"1\" thread=\"1\" file=\"synthetic.cc:1\">\n"
        ),
        message = message,
    )
    .into_bytes()
}

fn source_group(basename: &str) -> &'static str {
    match basename {
        "PolicyAgent.log" => "client-policy-agent",
        "CAS.log" => "client-content",
        "AppIntentEval.log" => "client-app-intent",
        "AppEnforce.log" => "client-app-enforce",
        "client.msi.log" => "client-ccmsetup",
        "ReportingEvents.log" => "client-windows-update-supplemental",
        "CustomVendorHook.log" => "unknown",
        _ => panic!("authority fixture basename must be declared here"),
    }
}

fn artifact(
    identity: &str,
    basename: &str,
    coverage: SccmCoverageState,
    fragment_complete: bool,
    binding: Option<&[u8]>,
) -> SccmClientIntakeArtifact {
    let physical = matches!(
        coverage,
        SccmCoverageState::Captured | SccmCoverageState::Capped | SccmCoverageState::ParseFailed
    );
    let (declared_byte_length, content_sha256) = binding
        .map(|bytes| (Some(bytes.len() as u64), Some(digest(bytes))))
        .unwrap_or((None, None));
    let group = source_group(basename);
    let relative_path = (physical && group != "unknown")
        .then(|| format!("evidence/{group}/current/{basename}"))
        .or_else(|| {
            (physical && group == "unknown").then(|| format!("evidence/{group}/{basename}"))
        });

    SccmClientIntakeArtifact {
        artifact: SccmArtifact {
            artifact_id: format!("fixture-{identity}"),
            display_name: basename.to_owned(),
            original_path: None,
            host: None,
            role: SccmRole::Client,
            configmgr_version: Some("5.00.9128.1000".to_owned()),
            collected_at_utc: Some("2026-07-30T00:00:00Z".to_owned()),
            rotation: SccmRotation::Current,
            coverage,
            encoding: Some("utf-8".to_owned()),
        },
        path_fingerprint: physical.then(|| format!("synthetic-{identity}")),
        rotation_lineage: None,
        relative_path,
        fragment_complete: Some(fragment_complete),
        declared_byte_length,
        content_sha256,
    }
}

fn bundle_with(artifacts: Vec<SccmClientIntakeArtifact>) -> SccmClientIntakeBundle {
    SccmClientIntakeBundle {
        artifacts,
        capture_gaps: Vec::new(),
    }
}

fn payload(artifact_id: &str, bytes: Vec<u8>) -> SccmClientCapturedPayload {
    match SccmClientCapturedPayload::new(artifact_id.to_owned(), bytes) {
        Ok(payload) => payload,
        Err(error) => panic!("authority fixture payload must be valid: {error}"),
    }
}

fn admission_error(
    result: Result<SccmClientAdmittedEvidence, SccmClientEvidenceAdmissionError>,
    context: &str,
) -> SccmClientEvidenceAdmissionError {
    match result {
        Ok(_) => panic!("{context}"),
        Err(error) => error,
    }
}

#[test]
fn admission_rejects_substituted_valid_ccm_bytes_against_the_intake_binding() {
    let bound = ccm_bytes("bound policy evidence");
    let substituted = ccm_bytes("different but valid policy evidence");
    let bundle = bundle_with(vec![artifact(
        "policy",
        "PolicyAgent.log",
        SccmCoverageState::Captured,
        true,
        Some(&bound),
    )]);
    let assessment = assess_client_intake(&bundle).expect("bound intake is canonical");

    let error = admission_error(
        admit_client_evidence(
            &bundle,
            &assessment,
            &[payload("fixture-policy", substituted)],
        ),
        "valid substituted bytes must not inherit the intake artifact's authority",
    );
    assert_eq!(
        error,
        SccmClientEvidenceAdmissionError::PayloadIntegrityMismatch
    );
}

#[test]
fn admission_rejects_a_mutated_assessment_content_binding() {
    let bytes = ccm_bytes("bound policy evidence");
    let bundle = bundle_with(vec![artifact(
        "policy",
        "PolicyAgent.log",
        SccmCoverageState::Captured,
        true,
        Some(&bytes),
    )]);
    let mut assessment = assess_client_intake(&bundle).expect("bound intake is canonical");
    assessment.physical_artifacts[0].content_sha256 = Some("0".repeat(64));

    let error = admission_error(
        admit_client_evidence(&bundle, &assessment, &[payload("fixture-policy", bytes)]),
        "a caller-mutated assessment binding must not become authority",
    );
    assert_eq!(error, SccmClientEvidenceAdmissionError::AssessmentMutation);
}

#[test]
fn intake_content_binding_is_paired_lowercase_and_capture_local() {
    let bytes = ccm_bytes("bound policy evidence");
    let valid = artifact(
        "policy",
        "PolicyAgent.log",
        SccmCoverageState::Captured,
        true,
        Some(&bytes),
    );
    let assessment = assess_client_intake(&bundle_with(vec![valid.clone()]))
        .expect("a recognized complete capture may carry a content binding");
    let projected = &assessment.physical_artifacts[0];
    assert_eq!(projected.declared_byte_length, Some(bytes.len() as u64));
    assert_eq!(
        projected.content_sha256.as_deref(),
        Some(digest(&bytes).as_str())
    );

    let mut missing_digest = valid.clone();
    missing_digest.content_sha256 = None;
    assert_eq!(
        assess_client_intake(&bundle_with(vec![missing_digest])),
        Err(super::SccmClientIntakeError::InvalidContentBinding)
    );

    let mut missing_length = valid.clone();
    missing_length.declared_byte_length = None;
    assert_eq!(
        assess_client_intake(&bundle_with(vec![missing_length])),
        Err(super::SccmClientIntakeError::InvalidContentBinding)
    );

    let mut uppercase_digest = valid.clone();
    uppercase_digest.content_sha256 = uppercase_digest
        .content_sha256
        .map(|value| value.to_uppercase());
    assert_eq!(
        assess_client_intake(&bundle_with(vec![uppercase_digest])),
        Err(super::SccmClientIntakeError::InvalidContentBinding)
    );

    for mut inadmissible in [
        artifact(
            "denied",
            "PolicyAgent.log",
            SccmCoverageState::AccessDenied,
            false,
            Some(&bytes),
        ),
        artifact(
            "capped",
            "CAS.log",
            SccmCoverageState::Capped,
            false,
            Some(&bytes),
        ),
        artifact(
            "incomplete",
            "AppIntentEval.log",
            SccmCoverageState::Captured,
            false,
            Some(&bytes),
        ),
        artifact(
            "custom",
            "CustomVendorHook.log",
            SccmCoverageState::Captured,
            true,
            Some(&bytes),
        ),
    ] {
        assert_eq!(
            assess_client_intake(&bundle_with(vec![inadmissible.clone()])),
            Err(super::SccmClientIntakeError::InvalidContentBinding),
            "content authority must be absent outside a recognized complete capture"
        );
        inadmissible.declared_byte_length = None;
        inadmissible.content_sha256 = None;
        assess_client_intake(&bundle_with(vec![inadmissible]))
            .expect("the same coverage remains representable without content authority");
    }
}

#[test]
fn legacy_intake_remains_assessable_but_cannot_admit_bytes() {
    let bytes = ccm_bytes("legacy policy evidence");
    let legacy = artifact(
        "policy-approved",
        "PolicyAgent.log",
        SccmCoverageState::Captured,
        true,
        None,
    );
    let bundle = bundle_with(vec![legacy]);
    let assessment = assess_client_intake(&bundle).expect("legacy intake remains assessment-only");
    let wire = serde_json::to_value(&bundle).expect("legacy intake remains serializable");
    assert!(wire["artifacts"][0].get("declaredByteLength").is_none());
    assert!(wire["artifacts"][0].get("contentSha256").is_none());

    let error = admission_error(
        admit_client_evidence(
            &bundle,
            &assessment,
            &[payload("fixture-policy-approved", bytes)],
        ),
        "legacy intake must not authorize caller-supplied bytes",
    );
    assert_eq!(
        error,
        SccmClientEvidenceAdmissionError::MissingContentBinding
    );
}

#[test]
fn admission_rejects_swapped_duplicate_extra_and_missing_payloads() {
    let policy_bytes = ccm_bytes("policy evidence");
    let content_bytes = ccm_bytes("content evidence");
    let bundle = bundle_with(vec![
        artifact(
            "policy",
            "PolicyAgent.log",
            SccmCoverageState::Captured,
            true,
            Some(&policy_bytes),
        ),
        artifact(
            "content",
            "CAS.log",
            SccmCoverageState::Captured,
            true,
            Some(&content_bytes),
        ),
    ]);
    let assessment = assess_client_intake(&bundle).expect("two bound sources are canonical");

    let swapped = admission_error(
        admit_client_evidence(
            &bundle,
            &assessment,
            &[
                payload("fixture-policy", content_bytes.clone()),
                payload("fixture-content", policy_bytes.clone()),
            ],
        ),
        "swapped valid payloads must not be admitted",
    );
    assert_eq!(
        swapped,
        SccmClientEvidenceAdmissionError::PayloadIntegrityMismatch
    );

    let duplicate = admission_error(
        admit_client_evidence(
            &bundle,
            &assessment,
            &[
                payload("fixture-policy", policy_bytes.clone()),
                payload("fixture-policy", policy_bytes.clone()),
            ],
        ),
        "duplicate payload identities must fail closed",
    );
    assert_eq!(
        duplicate,
        SccmClientEvidenceAdmissionError::DuplicatePayload
    );

    let extra = admission_error(
        admit_client_evidence(
            &bundle,
            &assessment,
            &[
                payload("fixture-policy", policy_bytes.clone()),
                payload("fixture-policy-two", ccm_bytes("extra evidence")),
            ],
        ),
        "an extra syntactically valid payload identity must fail closed",
    );
    assert_eq!(extra, SccmClientEvidenceAdmissionError::ExtraPayload);

    let missing = admission_error(
        admit_client_evidence(
            &bundle,
            &assessment,
            &[payload("fixture-policy", policy_bytes)],
        ),
        "a missing bound payload must fail closed",
    );
    assert_eq!(missing, SccmClientEvidenceAdmissionError::MissingPayload);
}

#[test]
fn incomplete_and_capped_sources_fail_locally_without_blocking_bound_policy() {
    let policy_bytes = ccm_bytes("policy evidence");
    let bundle = bundle_with(vec![
        artifact(
            "policy",
            "PolicyAgent.log",
            SccmCoverageState::Captured,
            true,
            Some(&policy_bytes),
        ),
        artifact(
            "content-capped",
            "CAS.log",
            SccmCoverageState::Capped,
            false,
            None,
        ),
        artifact(
            "intent-incomplete",
            "AppIntentEval.log",
            SccmCoverageState::Captured,
            false,
            None,
        ),
        artifact(
            "enforce-missing",
            "AppEnforce.log",
            SccmCoverageState::Captured,
            true,
            None,
        ),
    ]);
    let assessment = assess_client_intake(&bundle).expect("mixed source coverage is canonical");
    let admitted = match admit_client_evidence(
        &bundle,
        &assessment,
        &[payload("fixture-policy", policy_bytes)],
    ) {
        Ok(admitted) => admitted,
        Err(error) => panic!("unrelated source gaps must not block policy admission: {error}"),
    };

    assert!(admitted
        .require_captured_source("client-policy-agent")
        .is_ok());
    assert!(admitted.require_captured_source("client-content").is_err());
    assert!(admitted
        .require_captured_source("client-app-intent")
        .is_err());
    assert!(admitted
        .require_captured_source("client-app-enforce")
        .is_err());
    assert_eq!(admitted.evidence().expect("valid authority seal").len(), 1);
}

#[test]
fn admitted_profile_is_bound_to_the_catalogued_source_family() {
    let bytes = ccm_bytes("policy evidence");
    let bundle = bundle_with(vec![artifact(
        "policy",
        "PolicyAgent.log",
        SccmCoverageState::Captured,
        true,
        Some(&bytes),
    )]);
    let assessment = assess_client_intake(&bundle).expect("bound policy intake is canonical");
    let admitted =
        match admit_client_evidence(&bundle, &assessment, &[payload("fixture-policy", bytes)]) {
            Ok(admitted) => admitted,
            Err(error) => panic!("bound policy evidence must be admitted: {error}"),
        };

    let profile = admitted
        .profile_for_artifact("fixture-policy")
        .expect("valid authority seal")
        .expect("admitted artifact has a profile");
    assert_eq!(
        profile.validated_artifact_families,
        [SccmArtifactFamily::ClientPolicy]
    );
}

#[test]
fn recognized_non_ccm_sources_cannot_enter_raw_ccm_admission() {
    for (identity, basename) in [
        ("client-setup", "client.msi.log"),
        ("reporting-supplemental", "ReportingEvents.log"),
    ] {
        let bytes = ccm_bytes("CCM-shaped bytes from a non-CCM source");
        let bundle = bundle_with(vec![artifact(
            identity,
            basename,
            SccmCoverageState::Captured,
            true,
            Some(&bytes),
        )]);
        let assessment = assess_client_intake(&bundle).expect("bound intake is canonical");

        assert!(
            admit_client_evidence(
                &bundle,
                &assessment,
                &[payload(&format!("fixture-{identity}"), bytes)],
            )
            .is_err(),
            "{basename} must never authorize raw CCM evidence"
        );
    }
}

#[test]
fn captured_non_ccm_supplement_does_not_block_or_join_policy_admission() {
    let policy_bytes = ccm_bytes("policy evidence");
    let supplemental_bytes = ccm_bytes("CCM-shaped supplemental text");
    let bundle = bundle_with(vec![
        artifact(
            "policy",
            "PolicyAgent.log",
            SccmCoverageState::Captured,
            true,
            Some(&policy_bytes),
        ),
        artifact(
            "reporting-supplemental",
            "ReportingEvents.log",
            SccmCoverageState::Captured,
            true,
            Some(&supplemental_bytes),
        ),
    ]);
    let assessment = assess_client_intake(&bundle).expect("mixed intake is canonical");
    let admitted = admit_client_evidence(
        &bundle,
        &assessment,
        &[payload("fixture-policy", policy_bytes)],
    )
    .expect("non-CCM supplemental bytes must not be required for policy admission");

    assert!(admitted
        .require_captured_source("client-policy-agent")
        .is_ok());
    assert!(admitted
        .require_captured_source("client-windows-update-supplemental")
        .is_err());
    assert_eq!(admitted.evidence().expect("valid authority seal").len(), 1);
    assert!(admitted
        .profile_for_artifact("fixture-reporting-supplemental")
        .expect("valid authority seal")
        .is_none());
}

#[test]
fn sealed_policy_profile_extracts_a_low_confidence_assignment_key() {
    let assignment_id = "12345678-1234-1234-1234-123456789abc";
    let bytes = ccm_bytes(&format!("Assignment ID = {assignment_id}"));
    let bundle = bundle_with(vec![artifact(
        "policy",
        "PolicyAgent.log",
        SccmCoverageState::Captured,
        true,
        Some(&bytes),
    )]);
    let assessment = assess_client_intake(&bundle).expect("bound policy intake is canonical");
    let admitted = admit_client_evidence(&bundle, &assessment, &[payload("fixture-policy", bytes)])
        .expect("bound policy evidence must be admitted");
    let evidence = &admitted.evidence().expect("valid authority seal")[0];
    let profile = admitted
        .profile_for_artifact("fixture-policy")
        .expect("valid authority seal")
        .expect("policy evidence has a sealed profile");

    let result = extract_keys(evidence, profile);

    assert_eq!(result.keys.len(), 1);
    assert_eq!(result.keys[0].kind, SccmCorrelationKeyKind::AssignmentId);
    assert_eq!(result.keys[0].normalized, assignment_id);
    assert_eq!(result.keys[0].confidence, SccmKeyConfidence::Low);
    assert!(result
        .gaps
        .iter()
        .any(|gap| gap.kind == SccmExtractionGapKind::ExperimentalProfile));
    assert!(result
        .gaps
        .iter()
        .all(|gap| gap.kind != SccmExtractionGapKind::UnvalidatedProfile));
}

#[test]
fn caller_forged_family_profile_is_rejected_by_key_extraction() {
    let assignment_id = "12345678-1234-1234-1234-123456789abc";
    let bytes = ccm_bytes(&format!("Assignment ID = {assignment_id}"));
    let bundle = bundle_with(vec![artifact(
        "policy",
        "PolicyAgent.log",
        SccmCoverageState::Captured,
        true,
        Some(&bytes),
    )]);
    let assessment = assess_client_intake(&bundle).expect("bound policy intake is canonical");
    let admitted = admit_client_evidence(&bundle, &assessment, &[payload("fixture-policy", bytes)])
        .expect("bound policy evidence must be admitted");
    let evidence = &admitted.evidence().expect("valid authority seal")[0];
    let forged = SccmExtractionProfile {
        profile_id: SCCM_EXPERIMENTAL_KEY_PROFILE_ID.to_owned(),
        configmgr_version_prefixes: vec!["5.00.9128.".to_owned()],
        validated_artifact_families: vec![SccmArtifactFamily::Unknown("callerForged".to_owned())],
        selected_configmgr_version: Some("5.00.9128.1000".to_owned()),
        maturity: SccmExtractionProfileMaturity::Experimental,
    };

    let result = extract_keys(evidence, &forged);

    assert!(result.keys.is_empty());
    assert_eq!(result.gaps.len(), 1);
    assert_eq!(
        result.gaps[0].kind,
        SccmExtractionGapKind::UnvalidatedProfile
    );
    assert_eq!(
        result.gaps[0].candidate_kind,
        Some(SccmCorrelationKeyKind::AssignmentId)
    );
}

#[test]
fn unregistered_ccm_family_is_admitted_with_an_unvalidated_profile_gap() {
    let bytes = ccm_bytes("Package ID = LAB00001");
    let bundle = bundle_with(vec![artifact(
        "content",
        "CAS.log",
        SccmCoverageState::Captured,
        true,
        Some(&bytes),
    )]);
    let assessment = assess_client_intake(&bundle).expect("bound content intake is canonical");
    let admitted =
        admit_client_evidence(&bundle, &assessment, &[payload("fixture-content", bytes)])
            .expect("raw CCM evidence does not require a validated key-extraction family");
    let evidence = &admitted.evidence().expect("valid authority seal")[0];
    let profile = admitted
        .profile_for_artifact("fixture-content")
        .expect("valid authority seal")
        .expect("content evidence has a sealed family-bound profile");

    let result = extract_keys(evidence, profile);

    assert_eq!(
        profile.validated_artifact_families,
        [SccmArtifactFamily::ClientContent]
    );
    assert!(result.keys.is_empty());
    assert_eq!(result.gaps.len(), 1);
    assert_eq!(
        result.gaps[0].kind,
        SccmExtractionGapKind::UnvalidatedProfile
    );
    assert_eq!(
        result.gaps[0].candidate_kind,
        Some(SccmCorrelationKeyKind::PackageId)
    );
}

#[test]
fn captured_payload_constructor_rejects_noncanonical_identity() {
    let result = SccmClientCapturedPayload::new("C:\\Users\\raw\\PolicyAgent.log", ccm_bytes("x"));
    match result {
        Err(SccmClientEvidenceAdmissionError::InvalidPayloadArtifactId) => {}
        Err(error) => panic!("unexpected payload constructor error: {error}"),
        Ok(_) => panic!("raw path identity must not enter the payload boundary"),
    }
}
