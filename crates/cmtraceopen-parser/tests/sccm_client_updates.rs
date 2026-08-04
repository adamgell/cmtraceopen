use cmtraceopen_parser::sccm::client::{
    admit_client_evidence, analyze_client_updates, assess_client_intake, SccmClientCapturedPayload,
    SccmClientIntakeArtifact, SccmClientIntakeBundle, SccmClientUpdatePhase, SccmClientUpdateState,
};
use cmtraceopen_parser::sccm::{SccmArtifact, SccmCoverageState, SccmRole, SccmRotation};
use sha2::{Digest, Sha256};

const UPDATE_ID: &str = "32300000-0000-0000-0000-000000000003";
const CI_ID: &str = "323003";

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn admitted_scan(message: &str) -> cmtraceopen_parser::sccm::client::SccmClientAdmittedEvidence {
    let bytes = format!(
        "<![LOG[{message}]LOG]!><time=\"04:00:01.000+000\" date=\"7-30-2026\" \
         component=\"ScanAgent\" context=\"\" type=\"3\" thread=\"1\" \
         file=\"scanagent.cpp:323\">\n"
    )
    .into_bytes();
    let bundle = SccmClientIntakeBundle {
        artifacts: vec![SccmClientIntakeArtifact {
            artifact: SccmArtifact {
                artifact_id: "fixture-update-failure".to_owned(),
                display_name: "ScanAgent.log".to_owned(),
                original_path: None,
                host: None,
                role: SccmRole::Client,
                configmgr_version: Some("5.00.9128.1000".to_owned()),
                collected_at_utc: Some("2026-07-30T04:00:02Z".to_owned()),
                rotation: SccmRotation::Current,
                coverage: SccmCoverageState::Captured,
                encoding: Some("utf-8".to_owned()),
            },
            path_fingerprint: Some("synthetic-update-failure".to_owned()),
            rotation_lineage: None,
            relative_path: Some("evidence/client-updates/current/ScanAgent.log".to_owned()),
            fragment_complete: Some(true),
            declared_byte_length: Some(bytes.len() as u64),
            content_sha256: Some(sha256(&bytes)),
        }],
        capture_gaps: Vec::new(),
    };
    let assessment = assess_client_intake(&bundle).expect("canonical update intake");
    let payload =
        SccmClientCapturedPayload::new("fixture-update-failure", bytes).expect("bounded payload");
    admit_client_evidence(&bundle, &assessment, &[payload]).expect("sealed update evidence")
}

#[test]
fn scan_failure_uses_sealed_exact_key_evidence_without_server_cause() {
    let admitted = admitted_scan(&format!(
        "UpdateId={UPDATE_ID} CIId={CI_ID} ScanResult=failed ErrorCode=0x8024401c"
    ));

    let analysis = analyze_client_updates(&admitted).expect("update analysis");

    assert_eq!(analysis.transactions.len(), 1);
    let transaction = &analysis.transactions[0];
    assert_eq!(transaction.key.update_id, UPDATE_ID);
    assert_eq!(transaction.key.ci_id, CI_ID);
    assert_eq!(transaction.phase, SccmClientUpdatePhase::Scan);
    assert_eq!(transaction.state, SccmClientUpdateState::Failed);
    assert_eq!(transaction.last_successful_phase, None);
    assert_eq!(transaction.evidence.len(), 1);
    assert_eq!(
        transaction.evidence[0].artifact_id,
        "fixture-update-failure"
    );
    assert!(!analysis.correlation_handoff.performed);
    assert!(!analysis.correlation_handoff.server_cause_claimed);
    assert!(!analysis.correlation_handoff.time_only_eligible);
}
