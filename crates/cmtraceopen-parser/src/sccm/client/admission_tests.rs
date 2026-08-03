use sha2::{Digest, Sha256};

use super::{
    admit_client_evidence, assess_client_intake, SccmClientCapturedPayload,
    SccmClientIntakeArtifact, SccmClientIntakeBundle,
};
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
            artifact_id: format!("fixture-admitted-{identity}"),
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
        path_fingerprint: Some(format!("synthetic-admitted-{identity}")),
        rotation_lineage: None,
        relative_path: Some(format!("evidence/{group}/current/{basename}")),
        fragment_complete: Some(true),
    }
}

fn payload() -> SccmClientCapturedPayload {
    payload_for("fixture-admitted-policy-agent", "+000")
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

#[test]
fn admission_seals_canonical_records_from_complete_captured_payloads() {
    let bundle = bundle();
    let assessment = assess_client_intake(&bundle).expect("fixture assessment is canonical");

    let admitted = admit_client_evidence(&bundle, &assessment, &[payload()])
        .expect("a complete payload with the registered profile is admitted");

    assert_eq!(admitted.evidence().len(), 1);
    assert!(admitted.verify_integrity().is_ok());
    assert_eq!(
        admitted.source_coverage("client-policy-agent"),
        Some(&SccmCoverageState::Captured)
    );
}

#[test]
fn admission_rejects_missing_extra_duplicate_and_swapped_payloads() {
    let mut bundle = bundle();
    bundle.artifacts.push(artifact("policy-state", "CIAgent.log"));
    let assessment = assess_client_intake(&bundle).expect("two payload fixture is canonical");
    let agent = payload();
    let state = payload_for("fixture-admitted-policy-state", "+000");

    assert!(admit_client_evidence(&bundle, &assessment, &[agent.clone()]).is_err());

    let mut extra = vec![agent.clone(), state.clone()];
    extra.push(payload_for("fixture-not-in-bundle", "+000"));
    assert!(admit_client_evidence(&bundle, &assessment, &extra).is_err());

    assert!(admit_client_evidence(&bundle, &assessment, &[agent.clone(), agent]).is_err());

    let mut swapped = state;
    swapped.artifact_id = "fixture-admitted-policy-agent".to_owned();
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

    let malformed = SccmClientCapturedPayload {
        artifact_id: "fixture-admitted-policy-agent".to_owned(),
        bytes: b"not a CCM logical record".to_vec(),
        byte_length: 24,
        expected_sha256: digest(b"not a CCM logical record"),
    };
    let assessment = assess_client_intake(&bundle()).expect("fixture assessment is canonical");
    assert!(admit_client_evidence(&bundle(), &assessment, &[malformed]).is_err());

    assert!(admit_client_evidence(&bundle(), &assessment, &[payload_for(
        "fixture-admitted-policy-agent",
        "+9999",
    )])
    .is_err());
}

#[test]
fn admission_reassesses_bundle_and_is_deterministic_across_payload_order() {
    let mut bundle = bundle();
    bundle.artifacts.push(artifact("policy-state", "CIAgent.log"));
    let canonical = assess_client_intake(&bundle).expect("canonical assessment");
    let mut forged = canonical.clone();
    forged.groups[0].fragments.clear();
    assert!(admit_client_evidence(&bundle, &forged, &[payload(), payload_for(
        "fixture-admitted-policy-state",
        "+000",
    )])
    .is_err());

    let forward = admit_client_evidence(
        &bundle,
        &canonical,
        &[payload(), payload_for("fixture-admitted-policy-state", "+000")],
    )
    .expect("forward payload ordering is admitted");
    let reverse = admit_client_evidence(
        &bundle,
        &canonical,
        &[payload_for("fixture-admitted-policy-state", "+000"), payload()],
    )
    .expect("reverse payload ordering is admitted");
    assert_eq!(forward.evidence(), reverse.evidence());
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

    let mut profile_mutation =
        admit_client_evidence(&bundle, &assessment, &[payload()]).expect("admitted evidence");
    profile_mutation.test_only_mutate_first_profile();
    assert!(profile_mutation.verify_integrity().is_err());

    let mut collision =
        admit_client_evidence(&bundle, &assessment, &[payload()]).expect("admitted evidence");
    collision.test_only_duplicate_first_evidence();
    assert!(collision.verify_integrity().is_err());
}
