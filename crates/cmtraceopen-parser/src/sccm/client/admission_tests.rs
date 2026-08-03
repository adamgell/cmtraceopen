use sha2::{Digest, Sha256};

use super::admission::{
    admit_client_evidence, SccmClientAdmittedEvidence, SccmClientCapturedPayload,
    SccmClientEvidenceAdmissionError,
};
use super::{assess_client_intake, SccmClientIntakeArtifact, SccmClientIntakeBundle};
use crate::sccm::{SccmArtifact, SccmCoverageState, SccmRole, SccmRotation};

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn bundle() -> SccmClientIntakeBundle {
    SccmClientIntakeBundle {
        artifacts: vec![artifact("policy-agent", "PolicyAgent.log")],
        capture_gaps: Vec::new(),
    }
}

fn bundle_with_bound_policy(bytes: &[u8]) -> SccmClientIntakeBundle {
    let mut bundle = bundle();
    bind_artifact_to_bytes(&mut bundle.artifacts[0], bytes);
    bundle
}

fn artifact(identity: &str, basename: &str) -> SccmClientIntakeArtifact {
    let artifact_id = format!("fixture-{identity}");
    let bytes = payload_bytes_for(&artifact_id, "+000");
    artifact_bound_to(identity, basename, &bytes)
}

fn artifact_bound_to(identity: &str, basename: &str, bytes: &[u8]) -> SccmClientIntakeArtifact {
    let group = match basename {
        "PolicyAgent.log" => "client-policy-agent",
        "CIAgent.log" => "client-policy-state",
        _ => panic!("test artifact must be catalogued"),
    };
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
            coverage: SccmCoverageState::Captured,
            encoding: Some("utf-8".to_owned()),
        },
        path_fingerprint: Some(format!("synthetic-{identity}")),
        rotation_lineage: None,
        relative_path: Some(format!("evidence/{group}/current/{basename}")),
        fragment_complete: Some(true),
        declared_byte_length: Some(bytes.len() as u64),
        content_sha256: Some(digest(bytes)),
    }
}

fn payload() -> SccmClientCapturedPayload {
    payload_for("fixture-policy-agent", "+000")
}

fn payload_for(artifact_id: &str, offset: &str) -> SccmClientCapturedPayload {
    payload_from_bytes(artifact_id, payload_bytes_for(artifact_id, offset))
}

fn payload_bytes_for(artifact_id: &str, offset: &str) -> Vec<u8> {
    ccm_record(&format!("SYNTHETIC FIXTURE {artifact_id}"), offset).into_bytes()
}

fn payload_from_bytes(artifact_id: &str, bytes: Vec<u8>) -> SccmClientCapturedPayload {
    match SccmClientCapturedPayload::new(artifact_id.to_owned(), bytes) {
        Ok(payload) => payload,
        Err(error) => panic!("test payload must satisfy its public boundary: {error}"),
    }
}

fn ccm_record(message: &str, offset: &str) -> String {
    format!(
        concat!(
            "<![LOG[{message}]LOG]!><time=\"00:00:07.000{offset}\" ",
            "date=\"7-30-2026\" component=\"Synthetic\" context=\"\" ",
            "type=\"1\" thread=\"1\" file=\"synthetic.cc:1\">\n"
        ),
        message = message,
        offset = offset,
    )
}

fn utf16_with_bom(value: &str, little_endian: bool) -> Vec<u8> {
    let mut bytes = if little_endian {
        vec![0xff, 0xfe]
    } else {
        vec![0xfe, 0xff]
    };
    for unit in value.encode_utf16() {
        let encoded = if little_endian {
            unit.to_le_bytes()
        } else {
            unit.to_be_bytes()
        };
        bytes.extend_from_slice(&encoded);
    }
    bytes
}

fn bind_artifact_to_bytes(artifact: &mut SccmClientIntakeArtifact, bytes: &[u8]) {
    artifact.declared_byte_length = Some(bytes.len() as u64);
    artifact.content_sha256 = Some(digest(bytes));
}

fn payload_bytes_padded_to(artifact_id: &str, total_bytes: usize) -> Vec<u8> {
    let mut bytes = payload_bytes_for(artifact_id, "+000");
    assert!(bytes.len() <= total_bytes, "test payload remains valid");
    bytes.resize(total_bytes, b' ');
    bytes
}

fn repeated_record_bytes(record_count: usize, message: &str) -> Vec<u8> {
    ccm_record(message, "+000")
        .repeat(record_count)
        .into_bytes()
}

fn numbered_artifact(number: u32) -> SccmClientIntakeArtifact {
    let artifact_id = format!("sccm-artifact:v1:sha256:{number:064x}");
    let bytes = payload_bytes_for(&artifact_id, "+000");
    numbered_artifact_bound_to(number, &bytes)
}

fn numbered_artifact_bound_to(number: u32, bytes: &[u8]) -> SccmClientIntakeArtifact {
    let artifact_id = format!("sccm-artifact:v1:sha256:{number:064x}");
    let basename = format!("PolicyAgent.log.{number}");
    SccmClientIntakeArtifact {
        artifact: SccmArtifact {
            artifact_id,
            display_name: basename.clone(),
            original_path: None,
            host: None,
            role: SccmRole::Client,
            configmgr_version: Some("5.00.9128.1000".to_owned()),
            collected_at_utc: Some("2026-07-30T00:00:00Z".to_owned()),
            rotation: SccmRotation::Numbered(number),
            coverage: SccmCoverageState::Captured,
            encoding: Some("utf-8".to_owned()),
        },
        path_fingerprint: Some(format!("sha256:{number:064x}")),
        rotation_lineage: None,
        relative_path: Some(format!(
            "evidence/client-policy-agent/numbered-{number}/{basename}"
        )),
        fragment_complete: Some(true),
        declared_byte_length: Some(bytes.len() as u64),
        content_sha256: Some(digest(bytes)),
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
fn admission_seals_canonical_records_from_complete_captured_payloads() {
    let bundle = bundle();
    let assessment = assess_client_intake(&bundle).expect("fixture assessment is canonical");

    let admitted = admit_client_evidence(&bundle, &assessment, &[payload()])
        .expect("a complete payload with the registered profile is admitted");

    assert_eq!(admitted.evidence().expect("valid seal").len(), 1);
    assert!(admitted.verify_integrity().is_ok());
    assert_eq!(
        admitted
            .source_coverage("client-policy-agent")
            .expect("valid seal"),
        Some(&SccmCoverageState::Captured)
    );
    assert!(admitted
        .profile_for_artifact("fixture-policy-agent")
        .expect("valid seal")
        .is_some());
    assert!(admitted
        .require_captured_source("client-policy-agent")
        .is_ok());
    assert!(admitted
        .require_captured_source("client-policy-state")
        .is_err());
    assert!(admitted.require_captured_source("not-a-source").is_err());
}

#[test]
fn admission_rejects_missing_extra_duplicate_and_swapped_payloads() {
    let mut bundle = bundle();
    bundle
        .artifacts
        .push(artifact("policy-state", "CIAgent.log"));
    let assessment = assess_client_intake(&bundle).expect("two payload fixture is canonical");
    assert!(admit_client_evidence(&bundle, &assessment, &[payload()]).is_err());

    assert!(admit_client_evidence(
        &bundle,
        &assessment,
        &[
            payload(),
            payload_for("fixture-policy-state", "+000"),
            payload_for("fixture-unknown", "+000"),
        ]
    )
    .is_err());

    assert!(admit_client_evidence(&bundle, &assessment, &[payload(), payload()]).is_err());

    assert!(admit_client_evidence(
        &bundle,
        &assessment,
        &[
            payload(),
            payload_from_bytes(
                "fixture-policy-state",
                payload_bytes_for("fixture-policy-agent", "+000"),
            ),
        ]
    )
    .is_err());
}

#[test]
fn admission_distinguishes_within_cap_extra_payloads_from_missing_payloads() {
    let bundle = bundle();
    let assessment = assess_client_intake(&bundle).expect("one payload fixture is canonical");

    let missing = admission_error(
        admit_client_evidence(&bundle, &assessment, &[]),
        "an omitted eligible payload must fail closed",
    );
    assert_eq!(missing, SccmClientEvidenceAdmissionError::MissingPayload);

    let extra = admission_error(
        admit_client_evidence(
            &bundle,
            &assessment,
            &[payload(), payload_for("fixture-policy-approved", "+000")],
        ),
        "an additional within-cap payload must fail closed",
    );
    assert_eq!(extra, SccmClientEvidenceAdmissionError::ExtraPayload);
}

#[test]
fn admission_rejects_payload_digest_and_length_mismatches() {
    let mut bad_digest_bundle = bundle();
    bad_digest_bundle.artifacts[0].content_sha256 = Some("0".repeat(64));
    let bad_digest_assessment =
        assess_client_intake(&bad_digest_bundle).expect("wrong digest remains canonical metadata");
    assert!(
        admit_client_evidence(&bad_digest_bundle, &bad_digest_assessment, &[payload()]).is_err()
    );

    let mut bad_length_bundle = bundle();
    bad_length_bundle.artifacts[0].declared_byte_length = bad_length_bundle.artifacts[0]
        .declared_byte_length
        .and_then(|length| length.checked_add(1));
    let bad_length_assessment =
        assess_client_intake(&bad_length_bundle).expect("wrong length remains canonical metadata");
    assert!(
        admit_client_evidence(&bad_length_bundle, &bad_length_assessment, &[payload()]).is_err()
    );
}

#[test]
fn admission_rejects_boms_that_do_not_match_the_declared_encoding() {
    let record = ccm_record("declared encoding authority", "+000");
    let mut utf8_bom = vec![0xef, 0xbb, 0xbf];
    utf8_bom.extend_from_slice(record.as_bytes());
    let cases = [
        ("utf-8", utf16_with_bom(&record, true)),
        ("utf-16le", utf16_with_bom(&record, false)),
        ("utf-16be", utf8_bom.clone()),
        ("windows-1252", utf8_bom),
    ];

    for (declared_encoding, bytes) in cases {
        let mut bundle = bundle_with_bound_policy(&bytes);
        bundle.artifacts[0].artifact.encoding = Some(declared_encoding.to_owned());
        let assessment = assess_client_intake(&bundle)
            .expect("a declared encoding and byte binding remain canonical intake metadata");
        let error = admission_error(
            admit_client_evidence(
                &bundle,
                &assessment,
                &[payload_from_bytes("fixture-policy-agent", bytes)],
            ),
            "a mismatched Unicode BOM must not override declared encoding authority",
        );
        assert_eq!(
            error,
            SccmClientEvidenceAdmissionError::InvalidEncoding,
            "declared {declared_encoding}"
        );
    }
}

#[test]
fn admission_accepts_only_matching_unicode_boms() {
    let record = ccm_record("matching declared encoding", "+000");
    let mut utf8_bom = vec![0xef, 0xbb, 0xbf];
    utf8_bom.extend_from_slice(record.as_bytes());
    let cases = [
        ("utf-8", utf8_bom),
        ("utf-16le", utf16_with_bom(&record, true)),
        ("utf-16be", utf16_with_bom(&record, false)),
    ];

    for (declared_encoding, bytes) in cases {
        let mut bundle = bundle_with_bound_policy(&bytes);
        bundle.artifacts[0].artifact.encoding = Some(declared_encoding.to_owned());
        let assessment = assess_client_intake(&bundle)
            .expect("a matching BOM remains canonical intake metadata");
        admit_client_evidence(
            &bundle,
            &assessment,
            &[payload_from_bytes("fixture-policy-agent", bytes)],
        )
        .unwrap_or_else(|error| {
            panic!("matching {declared_encoding} BOM must be admitted: {error}")
        });
    }
}

#[test]
fn admission_accepts_the_exact_cap_and_rejects_payload_overflow_before_reassessment() {
    let artifacts = (1..=super::MAX_SCCM_CLIENT_INTAKE_ARTIFACTS as u32)
        .map(numbered_artifact)
        .collect::<Vec<_>>();
    let bundle = SccmClientIntakeBundle {
        artifacts,
        capture_gaps: Vec::new(),
    };
    let assessment = assess_client_intake(&bundle).expect("exact artifact cap is canonical");
    let payloads = bundle
        .artifacts
        .iter()
        .map(|artifact| payload_for(&artifact.artifact.artifact_id, "+000"))
        .collect::<Vec<_>>();
    if let Err(error) = admit_client_evidence(&bundle, &assessment, &payloads) {
        panic!("the exact payload and record cap must remain admissible: {error}");
    }

    let mut overflow = payloads;
    overflow.push(payload_for("fixture-policy-approved", "+000"));
    let error = admission_error(
        admit_client_evidence(&bundle, &assessment, &overflow),
        "the global payload-count guard must reject 4,097 payloads",
    );
    assert_eq!(
        error,
        SccmClientEvidenceAdmissionError::PayloadLimitExceeded
    );
}

#[test]
fn admission_rejects_noncaptured_incomplete_malformed_and_invalid_offset_payloads() {
    let mut capped = bundle();
    capped.artifacts[0].artifact.coverage = SccmCoverageState::Capped;
    capped.artifacts[0].fragment_complete = Some(false);
    capped.artifacts[0].declared_byte_length = None;
    capped.artifacts[0].content_sha256 = None;
    let capped_assessment = assess_client_intake(&capped).expect("capped state is explicit");
    assert!(admit_client_evidence(&capped, &capped_assessment, &[payload()]).is_err());

    let mut incomplete = bundle();
    incomplete.artifacts[0].fragment_complete = Some(false);
    incomplete.artifacts[0].declared_byte_length = None;
    incomplete.artifacts[0].content_sha256 = None;
    let incomplete_assessment =
        assess_client_intake(&incomplete).expect("incomplete boundary is explicit");
    assert!(admit_client_evidence(&incomplete, &incomplete_assessment, &[payload()]).is_err());

    let mut unknown_profile = bundle();
    unknown_profile.artifacts[0].artifact.configmgr_version = Some("5.00.9999.1000".to_owned());
    let unknown_profile_assessment =
        assess_client_intake(&unknown_profile).expect("unknown version remains canonical coverage");
    assert!(
        admit_client_evidence(&unknown_profile, &unknown_profile_assessment, &[payload()],)
            .is_err()
    );

    let malformed_bytes = b"not a CCM logical record".to_vec();
    let malformed_bundle = bundle_with_bound_policy(&malformed_bytes);
    let malformed_assessment =
        assess_client_intake(&malformed_bundle).expect("malformed bytes remain bound intake");
    assert!(admit_client_evidence(
        &malformed_bundle,
        &malformed_assessment,
        &[payload_from_bytes("fixture-policy-agent", malformed_bytes)]
    )
    .is_err());

    let invalid_offset_bytes = payload_bytes_for("fixture-policy-agent", "+9999");
    let invalid_offset_bundle = bundle_with_bound_policy(&invalid_offset_bytes);
    let invalid_offset_assessment = assess_client_intake(&invalid_offset_bundle)
        .expect("invalid record time remains bound intake metadata");
    assert!(admit_client_evidence(
        &invalid_offset_bundle,
        &invalid_offset_assessment,
        &[payload_from_bytes(
            "fixture-policy-agent",
            invalid_offset_bytes,
        )]
    )
    .is_err());
}

#[test]
fn admission_rejects_unclosed_ccm_suffix_even_when_manifest_claims_complete() {
    let mut truncated_bytes = payload_bytes_for("fixture-policy-agent", "+000");
    truncated_bytes.extend_from_slice(b"<![LOG[unclosed synthetic CCM suffix");
    let bundle = bundle_with_bound_policy(&truncated_bytes);
    let assessment = assess_client_intake(&bundle).expect("fixture assessment is canonical");
    let error = admission_error(
        admit_client_evidence(
            &bundle,
            &assessment,
            &[payload_from_bytes("fixture-policy-agent", truncated_bytes)],
        ),
        "manifest completeness must not promote an unclosed CCM suffix",
    );
    assert_eq!(
        error.to_string(),
        "client evidence admission CCM framing is incomplete or ambiguous"
    );
}

#[test]
fn admission_rejects_oversized_payload_work_records_and_retained_evidence() {
    let oversized_bytes = payload_bytes_padded_to("fixture-policy-agent", 4 * 1024 * 1024 + 1);
    let error = match SccmClientCapturedPayload::new("fixture-policy-agent", oversized_bytes) {
        Err(error) => error,
        Ok(_) => panic!("the bytes-only constructor must cap per-payload parser work"),
    };
    assert_eq!(
        error.to_string(),
        "client evidence admission payload exceeds the v1 per-payload byte cap"
    );

    let mut aggregate_artifacts = Vec::new();
    let mut aggregate_payloads = Vec::new();
    for number in 1..=5 {
        let artifact_id = format!("sccm-artifact:v1:sha256:{number:064x}");
        let bytes = payload_bytes_padded_to(&artifact_id, 4 * 1024 * 1024);
        aggregate_artifacts.push(numbered_artifact_bound_to(number, &bytes));
        aggregate_payloads.push(payload_from_bytes(&artifact_id, bytes));
    }
    let aggregate_bundle = SccmClientIntakeBundle {
        artifacts: aggregate_artifacts,
        capture_gaps: Vec::new(),
    };
    let aggregate_assessment =
        assess_client_intake(&aggregate_bundle).expect("aggregate fixture assessment is canonical");
    let error = admission_error(
        admit_client_evidence(
            &aggregate_bundle,
            &aggregate_assessment,
            &aggregate_payloads,
        ),
        "aggregate parser work must be capped before hashing every payload",
    );
    assert_eq!(
        error.to_string(),
        "client evidence admission aggregate payload bytes exceed the v1 cap"
    );

    let too_many_record_bytes = repeated_record_bytes(4_097, "synthetic record");
    let too_many_record_bundle = bundle_with_bound_policy(&too_many_record_bytes);
    let too_many_record_assessment = assess_client_intake(&too_many_record_bundle)
        .expect("record-limit fixture intake is canonical");
    let error = admission_error(
        admit_client_evidence(
            &too_many_record_bundle,
            &too_many_record_assessment,
            &[payload_from_bytes(
                "fixture-policy-agent",
                too_many_record_bytes,
            )],
        ),
        "logical-record expansion must be capped before evidence retention",
    );
    assert_eq!(
        error.to_string(),
        "client evidence admission logical record count exceeds the v1 cap"
    );

    let retained_message = "x".repeat(3_000);
    let oversized_retained_bytes = repeated_record_bytes(1_024, &retained_message);
    let oversized_retained_bundle = bundle_with_bound_policy(&oversized_retained_bytes);
    let oversized_retained_assessment = assess_client_intake(&oversized_retained_bundle)
        .expect("retained-limit fixture intake is canonical");
    let error = admission_error(
        admit_client_evidence(
            &oversized_retained_bundle,
            &oversized_retained_assessment,
            &[payload_from_bytes(
                "fixture-policy-agent",
                oversized_retained_bytes,
            )],
        ),
        "retained evidence and seal input must remain bounded",
    );
    assert_eq!(
        error.to_string(),
        "client evidence admission retained evidence exceeds the v1 byte cap"
    );
}

#[test]
fn admission_enforces_logical_record_cap_across_all_payloads() {
    let mut artifacts = Vec::new();
    let mut payloads = Vec::new();
    for number in 1..=2 {
        let artifact_id = format!("sccm-artifact:v1:sha256:{number:064x}");
        let bytes = repeated_record_bytes(2_049, "x");
        artifacts.push(numbered_artifact_bound_to(number, &bytes));
        payloads.push(payload_from_bytes(&artifact_id, bytes));
    }
    let bundle = SccmClientIntakeBundle {
        artifacts,
        capture_gaps: Vec::new(),
    };
    let assessment =
        assess_client_intake(&bundle).expect("two captured rotations are canonical intake");

    let result = admit_client_evidence(&bundle, &assessment, &payloads);
    assert!(
        result.is_err(),
        "two individually bounded rotations totaling 4,098 records were admitted"
    );
    let error = admission_error(
        result,
        "the logical-record cap must apply across the complete bundle",
    );
    assert_eq!(
        error.to_string(),
        "client evidence admission logical record count exceeds the v1 cap"
    );
}

#[test]
fn admission_reassesses_bundle_and_is_deterministic_across_payload_order() {
    let mut bundle = bundle();
    bundle
        .artifacts
        .push(artifact("policy-state", "CIAgent.log"));
    let canonical = assess_client_intake(&bundle).expect("canonical assessment");
    let mut forged = canonical.clone();
    forged
        .groups
        .iter_mut()
        .find(|group| group.logical_artifact_id == "client-policy-agent")
        .expect("fixture contains policy-agent group")
        .fragments
        .clear();
    assert!(admit_client_evidence(
        &bundle,
        &forged,
        &[payload(), payload_for("fixture-policy-state", "+000",)]
    )
    .is_err());

    let forward = admit_client_evidence(
        &bundle,
        &canonical,
        &[payload(), payload_for("fixture-policy-state", "+000")],
    )
    .expect("forward payload ordering is admitted");
    let reverse = admit_client_evidence(
        &bundle,
        &canonical,
        &[payload_for("fixture-policy-state", "+000"), payload()],
    )
    .expect("reverse payload ordering is admitted");
    assert_eq!(
        forward.evidence().expect("forward seal"),
        reverse.evidence().expect("reverse seal")
    );
    assert_eq!(forward.integrity_seal(), reverse.integrity_seal());
}

#[test]
fn admission_integrity_rejects_test_only_record_profile_and_identity_collisions() {
    let bundle = bundle();
    let assessment = assess_client_intake(&bundle).expect("fixture assessment is canonical");

    let mut record_mutation =
        admit_client_evidence(&bundle, &assessment, &[payload()]).expect("admitted evidence");
    record_mutation.test_only_mutate_first_message();
    assert!(record_mutation.verify_integrity().is_err());
    assert!(record_mutation.evidence().is_err());

    let mut profile_mutation =
        admit_client_evidence(&bundle, &assessment, &[payload()]).expect("admitted evidence");
    profile_mutation.test_only_mutate_first_profile();
    assert!(profile_mutation.verify_integrity().is_err());
    assert!(profile_mutation
        .profile_for_artifact("fixture-policy-agent")
        .is_err());

    let mut collision =
        admit_client_evidence(&bundle, &assessment, &[payload()]).expect("admitted evidence");
    collision.test_only_duplicate_first_evidence();
    assert!(collision.verify_integrity().is_err());
}
