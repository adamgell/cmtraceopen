use cmtraceopen_parser::sccm::client::{
    admit_client_evidence, assess_client_intake, SccmClientCapturedPayload,
    SccmClientIntakeArtifact, SccmClientIntakeBundle,
};
use cmtraceopen_parser::sccm::{SccmArtifact, SccmCoverageState, SccmRole, SccmRotation};
use sha2::{Digest, Sha256};

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn bytes() -> Vec<u8> {
    concat!(
        "<![LOG[public authority contract]LOG]!><time=\"00:00:07.000+000\" ",
        "date=\"7-30-2026\" component=\"Synthetic\" context=\"\" ",
        "type=\"1\" thread=\"1\" file=\"synthetic.cc:1\">\n"
    )
    .as_bytes()
    .to_vec()
}

#[test]
fn public_bytes_only_facade_uses_intake_bound_content_authority() {
    let bytes = bytes();
    let bundle = SccmClientIntakeBundle {
        artifacts: vec![SccmClientIntakeArtifact {
            artifact: SccmArtifact {
                artifact_id: "fixture-public-authority".to_owned(),
                display_name: "PolicyAgent.log".to_owned(),
                original_path: None,
                host: None,
                role: SccmRole::Client,
                configmgr_version: Some("5.00.9128.1000".to_owned()),
                collected_at_utc: Some("2026-07-30T00:00:00Z".to_owned()),
                rotation: SccmRotation::Current,
                coverage: SccmCoverageState::Captured,
                encoding: Some("utf-8".to_owned()),
            },
            path_fingerprint: Some("synthetic-public-authority".to_owned()),
            rotation_lineage: None,
            relative_path: Some("evidence/client-policy-agent/current/PolicyAgent.log".to_owned()),
            fragment_complete: Some(true),
            declared_byte_length: Some(bytes.len() as u64),
            content_sha256: Some(digest(&bytes)),
        }],
        capture_gaps: Vec::new(),
    };
    let assessment = assess_client_intake(&bundle).expect("public intake is canonical");
    let payload = match SccmClientCapturedPayload::new("fixture-public-authority", bytes) {
        Ok(payload) => payload,
        Err(error) => panic!("public payload constructor rejected canonical bytes: {error}"),
    };

    assert!(
        admit_client_evidence(&bundle, &assessment, &[payload]).is_ok(),
        "public callers can obtain opaque authority only for intake-bound bytes"
    );

    let wire = serde_json::to_value(&bundle).expect("bound intake serializes");
    assert!(wire["artifacts"][0]["declaredByteLength"].is_u64());
    assert_eq!(
        wire["artifacts"][0]["contentSha256"].as_str().map(str::len),
        Some(64)
    );
    let round_trip: SccmClientIntakeBundle =
        serde_json::from_value(wire).expect("bound intake round trips");
    let projected = assess_client_intake(&round_trip).expect("round trip remains canonical");
    assert_eq!(
        projected.physical_artifacts[0].declared_byte_length,
        Some(round_trip.artifacts[0].declared_byte_length.unwrap())
    );
}
