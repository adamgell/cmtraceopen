use sha2::{Digest, Sha256};

use super::admission::{admit_client_evidence, SccmClientCapturedPayload};
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

fn artifact(identity: &str, basename: &str) -> SccmClientIntakeArtifact {
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
    }
}

fn payload() -> SccmClientCapturedPayload {
    payload_for("fixture-policy-agent", "+000")
}

fn payload_for(artifact_id: &str, offset: &str) -> SccmClientCapturedPayload {
    let bytes = concat!(
        "<![LOG[SYNTHETIC FIXTURE admitted policy]LOG]!>",
        "<time=\"00:00:07.000"
    )
    .to_owned()
        + offset
        + concat!(
            "\" date=\"7-30-2026\" ",
            "component=\"Synthetic\" context=\"\" type=\"1\" ",
            "thread=\"1\" file=\"synthetic.cc:1\">\n"
        );
    let bytes = bytes.into_bytes();
    SccmClientCapturedPayload {
        artifact_id: artifact_id.to_owned(),
        byte_length: bytes.len() as u64,
        expected_sha256: digest(&bytes),
        bytes,
    }
}

fn numbered_artifact(number: u32) -> SccmClientIntakeArtifact {
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
    let agent = payload();
    let state = payload_for("fixture-policy-state", "+000");

    assert!(admit_client_evidence(&bundle, &assessment, std::slice::from_ref(&agent)).is_err());

    let mut extra = vec![agent.clone(), state.clone()];
    extra.push(payload_for("fixture-unknown", "+000"));
    assert!(admit_client_evidence(&bundle, &assessment, &extra).is_err());

    assert!(admit_client_evidence(&bundle, &assessment, &[agent.clone(), agent]).is_err());

    let mut swapped = state;
    swapped.artifact_id = "fixture-policy-agent".to_owned();
    assert!(admit_client_evidence(&bundle, &assessment, &[payload(), swapped]).is_err());
}

#[test]
fn admission_rejects_payload_digest_and_length_mismatches() {
    let bundle = bundle();
    let assessment = assess_client_intake(&bundle).expect("fixture assessment is canonical");

    let mut bad_digest = payload();
    bad_digest.expected_sha256 = "0".repeat(64);
    assert!(admit_client_evidence(&bundle, &assessment, &[bad_digest]).is_err());

    let mut bad_length = payload();
    bad_length.byte_length += 1;
    assert!(admit_client_evidence(&bundle, &assessment, &[bad_length]).is_err());
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
    assert!(admit_client_evidence(&bundle, &assessment, &payloads).is_ok());

    let mut overflow = payloads;
    overflow.push(payload_for("fixture-overflow", "+000"));
    assert!(admit_client_evidence(&bundle, &assessment, &overflow).is_err());
}

#[test]
fn admission_rejects_noncaptured_incomplete_malformed_and_invalid_offset_payloads() {
    let mut capped = bundle();
    capped.artifacts[0].artifact.coverage = SccmCoverageState::Capped;
    capped.artifacts[0].fragment_complete = Some(false);
    let capped_assessment = assess_client_intake(&capped).expect("capped state is explicit");
    assert!(admit_client_evidence(&capped, &capped_assessment, &[payload()]).is_err());

    let mut incomplete = bundle();
    incomplete.artifacts[0].fragment_complete = Some(false);
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

    let malformed = SccmClientCapturedPayload {
        artifact_id: "fixture-policy-agent".to_owned(),
        bytes: b"not a CCM logical record".to_vec(),
        byte_length: 24,
        expected_sha256: digest(b"not a CCM logical record"),
    };
    let assessment = assess_client_intake(&bundle()).expect("fixture assessment is canonical");
    assert!(admit_client_evidence(&bundle(), &assessment, &[malformed]).is_err());

    assert!(admit_client_evidence(
        &bundle(),
        &assessment,
        &[payload_for("fixture-policy-agent", "+9999",)]
    )
    .is_err());
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
