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

#[derive(Clone)]
struct Record<'a> {
    id: &'a str,
    basename: &'a str,
    group: &'a str,
    component: &'a str,
    time: &'a str,
    message: String,
}

fn admitted(
    records: &[Record<'_>],
) -> cmtraceopen_parser::sccm::client::SccmClientAdmittedEvidence {
    let mut artifacts = Vec::new();
    let mut payloads = Vec::new();
    for record in records {
        let artifact_id = format!("fixture-{}", record.id);
        let path_fingerprint = format!("synthetic-{}", record.id);
        let bytes = format!(
            "<![LOG[{}]LOG]!><time=\"{}+000\" date=\"7-30-2026\" \
             component=\"{}\" context=\"\" type=\"1\" thread=\"1\" \
             file=\"synthetic.cc:323\">\n",
            record.message, record.time, record.component
        )
        .into_bytes();
        artifacts.push(SccmClientIntakeArtifact {
            artifact: SccmArtifact {
                artifact_id: artifact_id.clone(),
                display_name: record.basename.to_owned(),
                original_path: None,
                host: None,
                role: SccmRole::Client,
                configmgr_version: Some("5.00.9128.1000".to_owned()),
                collected_at_utc: Some("2026-07-30T23:59:59Z".to_owned()),
                rotation: SccmRotation::Current,
                coverage: SccmCoverageState::Captured,
                encoding: Some("utf-8".to_owned()),
            },
            path_fingerprint: Some(path_fingerprint),
            rotation_lineage: None,
            relative_path: Some(format!(
                "evidence/{}/current/{}",
                record.group, record.basename
            )),
            fragment_complete: Some(true),
            declared_byte_length: Some(bytes.len() as u64),
            content_sha256: Some(sha256(&bytes)),
        });
        payloads.push(
            SccmClientCapturedPayload::new(artifact_id.clone(), bytes)
                .unwrap_or_else(|error| panic!("{artifact_id}: bounded update payload: {error}")),
        );
    }
    let bundle = SccmClientIntakeBundle {
        artifacts,
        capture_gaps: Vec::new(),
    };
    let assessment = assess_client_intake(&bundle).expect("canonical update intake");
    admit_client_evidence(&bundle, &assessment, &payloads).expect("sealed update evidence")
}

fn admitted_scan(message: &str) -> cmtraceopen_parser::sccm::client::SccmClientAdmittedEvidence {
    admitted(&[Record {
        id: "update-failure",
        basename: "ScanAgent.log",
        group: "client-updates",
        component: "ScanAgent",
        time: "04:00:01.000",
        message: message.to_owned(),
    }])
}

fn keyed(update_id: &str, ci_id: &str, disposition: &str) -> String {
    format!(
        "{disposition} UpdateId={{{update_id}}} CIId={ci_id} \
         ContentId=CONTENT-{ci_id} UpdateJobId=JOB-{ci_id} \
         ClientHandle=safe:client:{ci_id} SiteCode=LAB SupHostHandle=safe:sup:lab"
    )
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

#[test]
fn full_success_proves_all_eight_phases_without_cross_side_correlation() {
    let records = vec![
        Record {
            id: "update-a",
            basename: "ScanAgent.log",
            group: "client-updates",
            component: "ScanAgent",
            time: "02:00:00.000",
            message: keyed(UPDATE_ID, CI_ID, "Scan succeeded"),
        },
        Record {
            id: "update-b",
            basename: "WUAHandler.log",
            group: "client-updates",
            component: "WUAHandler",
            time: "02:00:01.000",
            message: keyed(UPDATE_ID, CI_ID, "Evaluate applicable"),
        },
        Record {
            id: "update-location",
            basename: "LocationServices.log",
            group: "client-location-services-shared",
            component: "LocationServices",
            time: "02:00:02.000",
            message: keyed(UPDATE_ID, CI_ID, "LocateSup selected"),
        },
        Record {
            id: "update-download",
            basename: "DataTransferService.log",
            group: "client-content",
            component: "DataTransferService",
            time: "02:00:03.000",
            message: keyed(UPDATE_ID, CI_ID, "Download succeeded"),
        },
        Record {
            id: "update-c",
            basename: "UpdatesStore.log",
            group: "client-updates",
            component: "UpdatesStore",
            time: "02:00:04.000",
            message: keyed(UPDATE_ID, CI_ID, "MaintenanceWindow open"),
        },
        Record {
            id: "update-success",
            basename: "UpdatesHandler.log",
            group: "client-updates",
            component: "UpdatesHandler",
            time: "02:00:05.000",
            message: keyed(UPDATE_ID, CI_ID, "Install succeeded"),
        },
        Record {
            id: "update-recovery",
            basename: "UpdatesDeployment.log",
            group: "client-updates",
            component: "UpdatesDeployment",
            time: "02:00:06.000",
            message: keyed(UPDATE_ID, CI_ID, "Reboot complete"),
        },
        Record {
            id: "update-report",
            basename: "StateMessage.log",
            group: "client-policy-state",
            component: "StateMessage",
            time: "02:00:07.000",
            message: keyed(UPDATE_ID, CI_ID, "Report succeeded"),
        },
    ];

    let analysis = analyze_client_updates(&admitted(&records)).expect("update analysis");
    assert_eq!(analysis.transactions.len(), 1);
    let transaction = &analysis.transactions[0];
    assert_eq!(transaction.phase, SccmClientUpdatePhase::Report);
    assert_eq!(transaction.state, SccmClientUpdateState::Succeeded);
    assert_eq!(
        transaction.last_successful_phase,
        Some(SccmClientUpdatePhase::Report)
    );
    assert_eq!(transaction.evidence.len(), 8);
    assert!(analysis.findings.is_empty());
    assert!(!analysis.correlation_handoff.performed);
    assert!(!analysis.correlation_handoff.server_cause_claimed);
}

#[test]
fn maintenance_window_defer_is_not_a_failure() {
    let records = vec![
        Record {
            id: "update-a",
            basename: "ScanAgent.log",
            group: "client-updates",
            component: "ScanAgent",
            time: "07:00:00.000",
            message: keyed(UPDATE_ID, CI_ID, "Scan succeeded"),
        },
        Record {
            id: "update-b",
            basename: "WUAHandler.log",
            group: "client-updates",
            component: "WUAHandler",
            time: "07:00:01.000",
            message: keyed(UPDATE_ID, CI_ID, "Evaluate applicable"),
        },
        Record {
            id: "update-location",
            basename: "LocationServices.log",
            group: "client-location-services-shared",
            component: "LocationServices",
            time: "07:00:02.000",
            message: keyed(UPDATE_ID, CI_ID, "LocateSup selected"),
        },
        Record {
            id: "update-download",
            basename: "DataTransferService.log",
            group: "client-content",
            component: "DataTransferService",
            time: "07:00:03.000",
            message: keyed(UPDATE_ID, CI_ID, "Download succeeded"),
        },
        Record {
            id: "update-c",
            basename: "UpdatesDeployment.log",
            group: "client-updates",
            component: "UpdatesDeployment",
            time: "07:00:04.000",
            message: keyed(
                UPDATE_ID,
                CI_ID,
                "MaintenanceWindow deferred next-context unavailable",
            ),
        },
    ];

    let analysis = analyze_client_updates(&admitted(&records)).expect("update analysis");
    let transaction = &analysis.transactions[0];
    assert_eq!(transaction.phase, SccmClientUpdatePhase::MaintenanceWindow);
    assert_eq!(transaction.state, SccmClientUpdateState::BlockedOrDeferred);
    assert_eq!(
        transaction.last_successful_phase,
        Some(SccmClientUpdatePhase::Download)
    );
    assert_eq!(
        analysis.findings[0].class,
        cmtraceopen_parser::sccm::SccmFindingClass::BlockedOrDeferred
    );
}

#[test]
fn same_minute_updates_remain_separate_and_input_order_is_deterministic() {
    let other_update = "32300000-0000-0000-0000-000000000099";
    let records = vec![
        Record {
            id: "update-a",
            basename: "ScanAgent.log",
            group: "client-updates",
            component: "ScanAgent",
            time: "12:00:00.000",
            message: keyed(UPDATE_ID, CI_ID, "Scan succeeded"),
        },
        Record {
            id: "update-b",
            basename: "WUAHandler.log",
            group: "client-updates",
            component: "WUAHandler",
            time: "12:00:00.000",
            message: keyed(other_update, "323099", "Evaluate terminal failure"),
        },
    ];
    let original = analyze_client_updates(&admitted(&records)).expect("ordered analysis");
    let mut reversed_records = records.clone();
    reversed_records.reverse();
    let reversed = analyze_client_updates(&admitted(&reversed_records)).expect("reversed analysis");

    assert_eq!(original.transactions.len(), 2);
    assert_eq!(
        serde_json::to_value(original).expect("serialize"),
        serde_json::to_value(reversed).expect("serialize")
    );
}
