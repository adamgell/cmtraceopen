use sha2::{Digest, Sha256};

use super::admission::{
    admit_client_evidence, SccmClientAdmittedEvidence, SccmClientAdmittedKeyExtraction,
    SccmClientCapturedPayload, SccmClientEvidenceAdmissionError,
};
use super::{
    assess_client_intake, SccmClientIntakeArtifact, SccmClientIntakeBundle,
    SccmClientIntakeCaptureGap, SccmTaskSequencePathClass, SccmTaskSequenceProvenance,
};
use crate::sccm::{
    extract_keys, normalize_key, SccmArtifact, SccmArtifactFamily, SccmCorrelationKeyKind,
    SccmCoverageState, SccmEvidence, SccmEvidenceRef, SccmExtractionGapKind, SccmExtractionProfile,
    SccmExtractionProfileMaturity, SccmKeyConfidence, SccmRole, SccmRotation,
    SccmTimeOrderingState, SccmTimestamp, SCCM_ADMIN_SERVICE_SYNTHETIC_KEY_PROFILE_ID,
    SCCM_EXPERIMENTAL_KEY_PROFILE_ID, SCCM_POLICY_KEY_PROFILE_ID,
    SCCM_PROVIDER_SYNTHETIC_KEY_PROFILE_ID,
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
        "smsts.log" => "client-task-sequence-smsts",
        "PolicyAgent.log" => "client-policy-agent",
        "CAS.log" => "client-content",
        "AppIntentEval.log" => "client-app-intent",
        "AppEnforce.log" => "client-app-enforce",
        "ccmsetup.log" | "ccmsetup.lo_" => "client-ccmsetup",
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
    let relative_path = (physical && basename == "smsts.log")
        .then(|| format!("evidence/{group}/client/current/{basename}"))
        .or_else(|| {
            (physical && group != "unknown").then(|| format!("evidence/{group}/current/{basename}"))
        })
        .or_else(|| {
            (physical && group == "unknown").then(|| format!("evidence/{group}/{basename}"))
        });
    let task_sequence_provenance =
        (physical && basename == "smsts.log").then(|| SccmTaskSequenceProvenance {
            version: 1,
            path_class: SccmTaskSequencePathClass::Client,
            smsts_log_path_evidence: None,
            relocation_lineage: "synthetic:ts-relocation:authority".to_owned(),
            relocation_ordinal: 0,
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
        task_sequence_provenance,
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
fn missing_fragment_encoding_is_a_local_admission_gap() {
    let policy_bytes = ccm_bytes("policy evidence");
    let content_bytes = ccm_bytes("content evidence without decoding provenance");
    let mut content = artifact(
        "content-missing",
        "CAS.log",
        SccmCoverageState::Captured,
        true,
        Some(&content_bytes),
    );
    content.artifact.encoding = None;
    let bundle = bundle_with(vec![
        artifact(
            "policy",
            "PolicyAgent.log",
            SccmCoverageState::Captured,
            true,
            Some(&policy_bytes),
        ),
        content,
    ]);
    let assessment = assess_client_intake(&bundle)
        .expect("missing decoding provenance remains an assessable local coverage gap");

    let admitted = admit_client_evidence(
        &bundle,
        &assessment,
        &[payload("fixture-policy", policy_bytes)],
    )
    .expect("a fragment without decoding provenance must not block unrelated bound evidence");

    assert!(admitted
        .require_captured_source("client-policy-agent")
        .is_ok());
    assert_eq!(
        admitted.require_captured_source("client-content"),
        Err(SccmClientEvidenceAdmissionError::SourceCoverageUnavailable),
        "the un-decodable source remains a local admission gap"
    );
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

    let extraction = admitted
        .extract_keys_for_artifact("fixture-policy")
        .expect("admitted artifact has sealed key-extraction authority");
    assert_eq!(
        extraction.artifact_family(),
        &SccmArtifactFamily::ClientPolicy
    );
    assert_eq!(extraction.artifact_id(), "fixture-policy");
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
        .extract_keys_for_artifact("fixture-reporting-supplemental")
        .is_err());
}

#[test]
fn non_ccm_sibling_coverage_does_not_block_bound_ccmsetup_admission() {
    for (coverage, identity) in [
        (SccmCoverageState::Capped, "client-setup-capped"),
        (SccmCoverageState::AccessDenied, "client-setup-denied"),
    ] {
        let setup_bytes = ccm_bytes("bound ccmsetup evidence");
        let bundle = bundle_with(vec![
            artifact(
                "ccmsetup",
                "ccmsetup.log",
                SccmCoverageState::Captured,
                true,
                Some(&setup_bytes),
            ),
            artifact(identity, "client.msi.log", coverage.clone(), false, None),
        ]);
        let assessment = assess_client_intake(&bundle).expect("mixed setup intake is canonical");
        let admitted = admit_client_evidence(
            &bundle,
            &assessment,
            &[payload("fixture-ccmsetup", setup_bytes)],
        )
        .expect("a non-CCM sibling must not block exact bound ccmsetup evidence");

        assert!(admitted.require_captured_source("client-ccmsetup").is_ok());
        assert_eq!(
            admitted
                .source_coverage("client-ccmsetup")
                .expect("valid authority seal"),
            Some(&coverage),
            "canonical non-CCM coverage remains visible for evidence-first reporting"
        );
        assert_eq!(admitted.evidence().expect("valid authority seal").len(), 1);
    }
}

#[test]
fn raw_ccm_sibling_gap_still_blocks_ccmsetup_group_readiness() {
    let setup_bytes = ccm_bytes("bound ccmsetup evidence");
    let mut denied_rollback = artifact(
        "ccmsetup-denied",
        "ccmsetup.lo_",
        SccmCoverageState::AccessDenied,
        false,
        None,
    );
    denied_rollback.artifact.rotation = SccmRotation::LoUnderscore;
    let bundle = bundle_with(vec![
        artifact(
            "ccmsetup",
            "ccmsetup.log",
            SccmCoverageState::Captured,
            true,
            Some(&setup_bytes),
        ),
        denied_rollback,
    ]);
    let assessment = assess_client_intake(&bundle).expect("raw CCM gap intake is canonical");
    let admitted = admit_client_evidence(
        &bundle,
        &assessment,
        &[payload("fixture-ccmsetup", setup_bytes)],
    )
    .expect("a raw CCM gap is local readiness state, not global admission failure");

    assert!(admitted.require_captured_source("client-ccmsetup").is_err());
    assert_eq!(admitted.evidence().expect("valid authority seal").len(), 1);
}

#[test]
fn admitted_task_sequence_provenance_is_integrity_sealed() {
    let bytes = ccm_bytes("Task Sequence authority");
    let bundle = bundle_with(vec![artifact(
        "valid",
        "smsts.log",
        SccmCoverageState::Captured,
        true,
        Some(&bytes),
    )]);
    let assessment = assess_client_intake(&bundle).expect("Task Sequence intake is canonical");

    for mutation in 0..4 {
        let mut admitted = admit_client_evidence(
            &bundle,
            &assessment,
            &[payload("fixture-valid", bytes.clone())],
        )
        .expect("Task Sequence evidence is admitted");
        admitted.test_only_mutate_task_sequence_provenance(mutation);
        assert!(
            admitted.verify_integrity().is_err(),
            "Task Sequence provenance mutation {mutation} must fail closed"
        );
    }
}

#[test]
fn raw_ccm_capture_gap_still_blocks_ccmsetup_group_readiness() {
    let setup_bytes = ccm_bytes("bound ccmsetup evidence");
    let bundle = SccmClientIntakeBundle {
        artifacts: vec![artifact(
            "ccmsetup",
            "ccmsetup.log",
            SccmCoverageState::Captured,
            true,
            Some(&setup_bytes),
        )],
        capture_gaps: vec![SccmClientIntakeCaptureGap {
            artifact_id: "fixture-capped-rotation".to_owned(),
            basename: "ccmsetup.log.1".to_owned(),
            rotation: SccmRotation::Numbered(1),
            coverage: SccmCoverageState::Capped,
            path_fingerprint: "synthetic-capped-rotation".to_owned(),
            rotation_lineage: "synthetic:capped-rotation".to_owned(),
        }],
    };
    let assessment = assess_client_intake(&bundle).expect("raw CCM capture gap is canonical");
    let admitted = admit_client_evidence(
        &bundle,
        &assessment,
        &[payload("fixture-ccmsetup", setup_bytes)],
    )
    .expect("a raw CCM capture gap is local readiness state, not admission failure");

    assert!(admitted.require_captured_source("client-ccmsetup").is_err());
    assert_eq!(admitted.evidence().expect("valid authority seal").len(), 1);
}

#[test]
fn admitted_policy_extraction_is_sealed_to_the_exact_artifact_and_family() {
    let assignment_id = "12345678-1234-1234-1234-123456789abc";
    let policy_bytes = ccm_bytes(&format!("Assignment ID = {assignment_id}"));
    let content_bytes = ccm_bytes("Package ID = LAB00001");
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
    let assessment = assess_client_intake(&bundle).expect("bound policy intake is canonical");
    let admitted = admit_client_evidence(
        &bundle,
        &assessment,
        &[
            payload("fixture-content", content_bytes),
            payload("fixture-policy", policy_bytes),
        ],
    )
    .expect("bound policy and content evidence must be admitted");
    let extraction: SccmClientAdmittedKeyExtraction = admitted
        .extract_keys_for_artifact("fixture-policy")
        .expect("policy evidence has sealed extraction authority");
    let result = &extraction.results()[0];

    assert_eq!(extraction.artifact_id(), "fixture-policy");
    assert_eq!(
        extraction.artifact_family(),
        &SccmArtifactFamily::ClientPolicy
    );
    assert_eq!(extraction.results().len(), 1);
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
fn caller_constructed_policy_profile_cannot_cross_the_admitted_boundary() {
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
    let caller_constructed = SccmExtractionProfile {
        profile_id: SCCM_EXPERIMENTAL_KEY_PROFILE_ID.to_owned(),
        configmgr_version_prefixes: vec!["5.00.9128.".to_owned()],
        validated_artifact_families: vec![SccmArtifactFamily::ClientPolicy],
        selected_configmgr_version: Some("5.00.9128.1000".to_owned()),
        maturity: SccmExtractionProfileMaturity::Experimental,
    };

    let generic_result = extract_keys(evidence, &caller_constructed);
    assert!(generic_result.keys.is_empty());
    assert!(generic_result
        .gaps
        .iter()
        .any(|gap| gap.kind == SccmExtractionGapKind::UnvalidatedProfile));

    let admitted_result: SccmClientAdmittedKeyExtraction = admitted
        .extract_keys_for_artifact("fixture-policy")
        .expect("only the admitted authority selects the sealed profile");
    let result = &admitted_result.results()[0];

    assert_eq!(admitted_result.artifact_id(), "fixture-policy");
    assert_eq!(
        admitted_result.artifact_family(),
        &SccmArtifactFamily::ClientPolicy
    );
    assert_eq!(admitted_result.results().len(), 1);
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
fn caller_constructed_stable_policy_profile_does_not_mint_exact_keys() {
    let bytes = ccm_bytes(concat!(
        "Request succeeded ",
        "AssignmentId={12345678-1234-1234-1234-123456789abc} ",
        "PolicyId={abcdefab-cdef-cdef-cdef-abcdefabcdef}"
    ));
    let mut policy = artifact(
        "policy",
        "PolicyAgent.log",
        SccmCoverageState::Captured,
        true,
        Some(&bytes),
    );
    policy.artifact.configmgr_version = Some("5.00.TEST.0000".to_owned());
    let bundle = bundle_with(vec![policy]);
    let assessment = assess_client_intake(&bundle).expect("stable policy intake is canonical");
    let admitted = admit_client_evidence(&bundle, &assessment, &[payload("fixture-policy", bytes)])
        .expect("stable policy bytes are sealed");
    let evidence = &admitted.evidence().expect("valid seal")[0];
    let caller_constructed = SccmExtractionProfile {
        profile_id: SCCM_POLICY_KEY_PROFILE_ID.to_owned(),
        configmgr_version_prefixes: vec!["5.00.TEST.0000".to_owned()],
        validated_artifact_families: vec![SccmArtifactFamily::ClientPolicy],
        selected_configmgr_version: Some("5.00.TEST.0000".to_owned()),
        maturity: SccmExtractionProfileMaturity::Stable,
    };

    let generic = extract_keys(evidence, &caller_constructed);
    assert!(generic.keys.is_empty());
    assert!(generic
        .gaps
        .iter()
        .all(|gap| gap.kind == SccmExtractionGapKind::UnvalidatedProfile));

    let sealed = admitted
        .extract_keys_for_artifact("fixture-policy")
        .expect("admission owns stable profile authority");
    assert_eq!(sealed.results()[0].keys.len(), 2);
    assert!(sealed.results()[0]
        .keys
        .iter()
        .all(|key| key.confidence == SccmKeyConfidence::Exact));
}

#[test]
fn synthetic_server_profiles_are_exact_registered_tuples_but_keys_remain_low() {
    let request_id = "11111111-1111-1111-1111-111111111111";
    let evidence = SccmEvidence {
        evidence_id: "synthetic-server-entry".to_owned(),
        reference: SccmEvidenceRef {
            artifact_id: "synthetic-server-artifact".to_owned(),
            entry_id: "synthetic-server-entry".to_owned(),
            line_start: Some(1),
            line_end: Some(1),
        },
        role: SccmRole::Provider,
        component: Some("Synthetic".to_owned()),
        ccm_source_file: Some("synthetic.cc".to_owned()),
        message: format!("RequestId={request_id}"),
        timestamp: SccmTimestamp {
            original_display: Some("synthetic".to_owned()),
            offset_minutes: Some(0),
            utc_millis: Some(1),
            ordering_state: SccmTimeOrderingState::NormalizedUtc,
        },
        execution_context: None,
    };

    for (family, profile_id) in [
        (
            SccmArtifactFamily::Provider,
            SCCM_PROVIDER_SYNTHETIC_KEY_PROFILE_ID,
        ),
        (
            SccmArtifactFamily::AdminService,
            SCCM_ADMIN_SERVICE_SYNTHETIC_KEY_PROFILE_ID,
        ),
    ] {
        let profile = SccmExtractionProfile::for_artifact_family(Some("5.00.TEST"), &family);
        assert_eq!(profile.profile_id, profile_id);
        assert_eq!(profile.configmgr_version_prefixes, ["5.00.TEST"]);
        assert_eq!(profile.validated_artifact_families, [family]);
        assert_eq!(
            profile.selected_configmgr_version.as_deref(),
            Some("5.00.TEST")
        );
        let extraction = extract_keys(&evidence, &profile);
        assert_eq!(extraction.keys.len(), 1);
        assert_eq!(extraction.keys[0].confidence, SccmKeyConfidence::Low);
        assert_eq!(
            extraction.keys[0].extraction_profile_id.as_deref(),
            Some(profile_id)
        );
        assert!(extraction
            .gaps
            .iter()
            .any(|gap| gap.kind == SccmExtractionGapKind::ExperimentalProfile));
    }
    assert_eq!(
        normalize_key(SccmCorrelationKeyKind::RequestId, request_id).confidence,
        SccmKeyConfidence::Exact
    );
}

#[test]
fn forged_synthetic_server_profile_cannot_activate_shared_extraction() {
    let evidence = SccmEvidence {
        evidence_id: "synthetic-forged-entry".to_owned(),
        reference: SccmEvidenceRef {
            artifact_id: "synthetic-forged-artifact".to_owned(),
            entry_id: "synthetic-forged-entry".to_owned(),
            line_start: Some(1),
            line_end: Some(1),
        },
        role: SccmRole::Provider,
        component: None,
        ccm_source_file: None,
        message: "RequestId=11111111-1111-1111-1111-111111111111".to_owned(),
        timestamp: SccmTimestamp {
            original_display: None,
            offset_minutes: Some(0),
            utc_millis: Some(1),
            ordering_state: SccmTimeOrderingState::NormalizedUtc,
        },
        execution_context: None,
    };
    let mut forged = SccmExtractionProfile::for_artifact_family(
        Some("5.00.TEST"),
        &SccmArtifactFamily::Provider,
    );
    forged.profile_id.push_str("-forged");
    let extraction = extract_keys(&evidence, &forged);
    assert!(extraction.keys.is_empty());
    assert!(extraction
        .gaps
        .iter()
        .any(|gap| gap.kind == SccmExtractionGapKind::UnvalidatedProfile));
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
    let extraction = admitted
        .extract_keys_for_artifact("fixture-content")
        .expect("content evidence has sealed family-bound extraction authority");
    let result = &extraction.results()[0];

    assert_eq!(
        extraction.artifact_family(),
        &SccmArtifactFamily::ClientContent
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
