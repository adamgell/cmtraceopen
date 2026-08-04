use cmtraceopen_parser::sccm::client::{
    admit_client_evidence, analyze_client_updates, assess_client_intake, SccmClientCapturedPayload,
    SccmClientIntakeArtifact, SccmClientIntakeBundle, SccmClientIntakeCaptureGap,
    SccmClientUpdatePhase, SccmClientUpdateState,
};
use cmtraceopen_parser::sccm::{
    classify_artifact_name, SccmArtifact, SccmCoverageState, SccmRole, SccmRotation,
};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};

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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CorpusManifest {
    artifacts: Vec<CorpusArtifact>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CorpusArtifact {
    design_only_catalog: CorpusCatalog,
    capture_state: String,
    encoding: Option<String>,
    original_basename: String,
    rotation: CorpusRotation,
    source_version: Option<String>,
    captured_utc: Option<String>,
    relative_path: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CorpusCatalog {
    entry_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CorpusRotation {
    kind: String,
    fragment_complete: Option<bool>,
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

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sccm/client/updates")
}

fn corpus_admitted(
    scenario: &str,
) -> Result<cmtraceopen_parser::sccm::client::SccmClientAdmittedEvidence, String> {
    let scenario_dir = corpus_root().join(scenario);
    let manifest: CorpusManifest = serde_json::from_slice(
        &fs::read(scenario_dir.join("manifest.json")).expect("corpus manifest"),
    )
    .expect("valid corpus manifest");
    let mut artifacts = Vec::new();
    let mut payloads = Vec::new();
    for (index, source) in manifest.artifacts.into_iter().enumerate() {
        let coverage = match source.capture_state.as_str() {
            "captured" => SccmCoverageState::Captured,
            "absent" => SccmCoverageState::Absent,
            "accessDenied" => SccmCoverageState::AccessDenied,
            "capped" => SccmCoverageState::Capped,
            "skipped" => SccmCoverageState::Skipped,
            "unsupported" => SccmCoverageState::Unsupported,
            "parseFailed" => SccmCoverageState::ParseFailed,
            other => panic!("unsupported corpus coverage {other}"),
        };
        let rotation = match source.rotation.kind.as_str() {
            "current" => SccmRotation::Current,
            "lo" | "loUnderscore" => SccmRotation::LoUnderscore,
            other => panic!("unsupported corpus rotation {other}"),
        };
        let artifact_id = format!("fixture-update-numbered-{:02}", index + 1);
        let classified = classify_artifact_name(&source.original_basename, SccmRole::Client);
        let eligible_payload = coverage == SccmCoverageState::Captured
            && source.rotation.fragment_complete == Some(true)
            && classified.supported_for_diagnosis
            && classified.uses_ccm_records;
        let bytes = eligible_payload.then(|| {
            fs::read(
                scenario_dir.join(
                    source
                        .relative_path
                        .as_deref()
                        .expect("captured corpus relative path"),
                ),
            )
            .expect("captured corpus bytes")
        });
        let relative_path = source.relative_path.or_else(|| {
            matches!(
                coverage,
                SccmCoverageState::Captured
                    | SccmCoverageState::Capped
                    | SccmCoverageState::ParseFailed
            )
            .then(|| {
                let rotation_segment = match &rotation {
                    SccmRotation::LoUnderscore => "lo",
                    _ => "current",
                };
                format!(
                    "evidence/{}/{rotation_segment}/{}",
                    source.design_only_catalog.entry_id, source.original_basename
                )
            })
        });
        artifacts.push(SccmClientIntakeArtifact {
            artifact: SccmArtifact {
                artifact_id: artifact_id.clone(),
                display_name: source.original_basename,
                original_path: None,
                host: None,
                role: SccmRole::Client,
                configmgr_version: if classified.uses_ccm_records {
                    Some("5.00.9128.1000".to_owned())
                } else {
                    source.source_version
                },
                collected_at_utc: source.captured_utc,
                rotation,
                coverage,
                encoding: source.encoding,
            },
            path_fingerprint: Some(format!("synthetic:numbered-{:02}", index + 1)),
            rotation_lineage: None,
            relative_path,
            fragment_complete: Some(source.rotation.fragment_complete.unwrap_or(false)),
            declared_byte_length: bytes.as_ref().map(|bytes| bytes.len() as u64),
            content_sha256: bytes.as_ref().map(|bytes| sha256(bytes)),
        });
        if let Some(bytes) = bytes {
            payloads.push(
                SccmClientCapturedPayload::new(artifact_id, bytes)
                    .map_err(|error| error.to_string())?,
            );
        }
    }
    let bundle = SccmClientIntakeBundle {
        artifacts,
        capture_gaps: Vec::new(),
    };
    let assessment = assess_client_intake(&bundle).map_err(|error| error.to_string())?;
    admit_client_evidence(&bundle, &assessment, &payloads).map_err(|error| error.to_string())
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
    assert_eq!(
        serde_json::to_value(transaction.classification).expect("classification"),
        "symptom"
    );
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
    assert!(analysis.correlation_handoff.emitted_counterpart_ready_fact);
    assert_eq!(
        analysis.correlation_handoff.counterpart_ready_facts.len(),
        1
    );
    let counterpart = &analysis.correlation_handoff.counterpart_ready_facts[0];
    assert_eq!(counterpart.update_id, UPDATE_ID);
    assert_eq!(counterpart.ci_id, CI_ID);
    assert_eq!(counterpart.phase, SccmClientUpdatePhase::LocateSup);
    assert_eq!(
        counterpart.key_confidence,
        cmtraceopen_parser::sccm::SccmKeyConfidence::Low
    );
    assert_eq!(
        counterpart.timestamp_provenance.normalized_utc,
        "2026-07-30T02:00:02.000Z"
    );
    assert_eq!(counterpart.evidence.artifact_id, "fixture-update-location");
    assert!(!counterpart.correlation_eligible);
    assert!(!counterpart.time_only_eligible);
    assert!(
        !analysis
            .correlation_handoff
            .topology_compatibility_evaluated
    );
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
        transaction.coverage_gap_artifact_ids,
        ["client-maintenance-window"]
    );
    assert_eq!(
        transaction
            .next_artifact
            .as_ref()
            .map(|request| request.logical_artifact_id.as_str()),
        Some("client-maintenance-window")
    );
    assert_eq!(
        analysis.findings[0].class,
        cmtraceopen_parser::sccm::SccmFindingClass::BlockedOrDeferred
    );
}

#[test]
fn evaluate_only_does_not_infer_a_missing_sup_without_a_declared_gap() {
    let records = vec![
        Record {
            id: "update-a",
            basename: "ScanAgent.log",
            group: "client-updates",
            component: "ScanAgent",
            time: "03:00:00.000",
            message: keyed(UPDATE_ID, CI_ID, "Scan succeeded"),
        },
        Record {
            id: "update-b",
            basename: "WUAHandler.log",
            group: "client-updates",
            component: "WUAHandler",
            time: "03:00:01.000",
            message: keyed(UPDATE_ID, CI_ID, "Evaluate applicable"),
        },
    ];

    let analysis = analyze_client_updates(&admitted(&records)).expect("update analysis");
    let transaction = &analysis.transactions[0];
    assert_eq!(transaction.phase, SccmClientUpdatePhase::Evaluate);
    assert_eq!(transaction.state, SccmClientUpdateState::Succeeded);
    assert_eq!(
        transaction.last_successful_phase,
        Some(SccmClientUpdatePhase::Evaluate)
    );
    assert!(transaction.coverage_gap_artifact_ids.is_empty());
    assert!(transaction.next_artifact.is_none());
    assert!(!analysis.correlation_handoff.server_cause_claimed);
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

#[test]
fn counterpart_fact_requires_location_services_and_every_exact_field() {
    let missing_sup = Record {
        id: "update-a",
        basename: "LocationServices.log",
        group: "client-location-services-shared",
        component: "LocationServices",
        time: "05:00:00.000",
        message: format!(
            "LocateSup selected UpdateId={{{UPDATE_ID}}} CIId={CI_ID} \
             ContentId=CONTENT-{CI_ID} UpdateJobId=JOB-{CI_ID} \
             ClientHandle=safe:client:{CI_ID} SiteCode=LAB"
        ),
    };
    let wrong_source = Record {
        id: "update-b",
        basename: "UpdatesDeployment.log",
        group: "client-updates",
        component: "UpdatesDeployment",
        time: "05:00:01.000",
        message: keyed(UPDATE_ID, CI_ID, "LocateSup selected"),
    };
    let raw_host = Record {
        id: "update-c",
        basename: "LocationServices.log",
        group: "client-location-services-shared",
        component: "LocationServices",
        time: "05:00:02.000",
        message: keyed(UPDATE_ID, CI_ID, "LocateSup selected")
            .replace("safe:sup:lab", "LAB-SUP-01"),
    };

    for record in [missing_sup, wrong_source, raw_host] {
        let analysis = analyze_client_updates(&admitted(&[record])).expect("update analysis");
        assert!(!analysis.correlation_handoff.emitted_counterpart_ready_fact);
        assert!(analysis
            .correlation_handoff
            .counterpart_ready_facts
            .is_empty());
    }
}

#[test]
fn later_same_phase_success_recovers_an_earlier_terminal_marker() {
    let records = vec![
        Record {
            id: "update-a",
            basename: "UpdatesHandler.log",
            group: "client-updates",
            component: "UpdatesHandler",
            time: "06:00:00.000",
            message: keyed(UPDATE_ID, CI_ID, "Install terminal failure"),
        },
        Record {
            id: "update-b",
            basename: "UpdatesDeployment.log",
            group: "client-updates",
            component: "UpdatesDeployment",
            time: "06:00:01.000",
            message: keyed(UPDATE_ID, CI_ID, "Install succeeded"),
        },
    ];

    let analysis = analyze_client_updates(&admitted(&records)).expect("update analysis");
    let transaction = &analysis.transactions[0];
    assert_eq!(transaction.phase, SccmClientUpdatePhase::Install);
    assert_eq!(transaction.state, SccmClientUpdateState::Succeeded);
    assert_eq!(
        transaction.last_successful_phase,
        Some(SccmClientUpdatePhase::Install)
    );
    assert!(analysis.findings.is_empty());
}

#[test]
fn canonical_capture_gap_keeps_the_transaction_incomplete() {
    let record = Record {
        id: "update-a",
        basename: "ScanAgent.log",
        group: "client-updates",
        component: "ScanAgent",
        time: "09:00:00.000",
        message: keyed(UPDATE_ID, CI_ID, "Scan succeeded"),
    };
    let artifact_id = format!("fixture-{}", record.id);
    let bytes = format!(
        "<![LOG[{}]LOG]!><time=\"{}+000\" date=\"7-30-2026\" component=\"{}\" context=\"\" type=\"1\" thread=\"1\" file=\"synthetic.cc:323\">\n",
        record.message, record.time, record.component
    )
    .into_bytes();
    let bundle = SccmClientIntakeBundle {
        artifacts: vec![SccmClientIntakeArtifact {
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
            path_fingerprint: Some("synthetic-update-a".to_owned()),
            rotation_lineage: None,
            relative_path: Some("evidence/client-updates/current/ScanAgent.log".to_owned()),
            fragment_complete: Some(true),
            declared_byte_length: Some(bytes.len() as u64),
            content_sha256: Some(sha256(&bytes)),
        }],
        capture_gaps: vec![SccmClientIntakeCaptureGap {
            artifact_id: "fixture-capped-rotation".to_owned(),
            basename: "UpdatesHandler.log".to_owned(),
            rotation: SccmRotation::Current,
            coverage: SccmCoverageState::Capped,
            path_fingerprint: "synthetic:capped-rotation".to_owned(),
            rotation_lineage: "synthetic:capped-rotation".to_owned(),
        }],
    };
    let assessment = assess_client_intake(&bundle).expect("canonical gap intake");
    let admitted = admit_client_evidence(
        &bundle,
        &assessment,
        &[SccmClientCapturedPayload::new(artifact_id, bytes).expect("bounded payload")],
    )
    .expect("sealed evidence with canonical gap");

    let analysis = analyze_client_updates(&admitted).expect("update analysis");
    assert_eq!(
        analysis.transactions[0].state,
        SccmClientUpdateState::Incomplete
    );
    assert_eq!(
        analysis.transactions[0].phase,
        SccmClientUpdatePhase::Install
    );
    assert_eq!(analysis.findings.len(), 1);
}

#[test]
fn partial_rotation_is_reported_as_partial_coverage() {
    let admitted = corpus_admitted("rotation-boundary").expect("rotation corpus admission");
    let analysis = analyze_client_updates(&admitted).expect("rotation analysis");
    let updates = analysis
        .coverage
        .iter()
        .find(|coverage| coverage.logical_artifact_id == "client-updates")
        .expect("updates coverage");
    assert_eq!(
        serde_json::to_value(updates).expect("coverage")["state"],
        "partial"
    );
}

#[test]
fn counterpart_rejects_component_spoofing_and_privacy_bearing_handles() {
    let spoofed_source = Record {
        id: "update-a",
        basename: "UpdatesDeployment.log",
        group: "client-updates",
        component: "LocationServices",
        time: "10:00:00.000",
        message: keyed(UPDATE_ID, CI_ID, "LocateSup selected"),
    };
    let privacy_client = Record {
        id: "update-b",
        basename: "LocationServices.log",
        group: "client-location-services-shared",
        component: "LocationServices",
        time: "10:00:01.000",
        message: keyed(UPDATE_ID, CI_ID, "LocateSup selected")
            .replace(&format!("safe:client:{CI_ID}"), "safe:Adam.Gell"),
    };
    let privacy_sup = Record {
        id: "update-c",
        basename: "LocationServices.log",
        group: "client-location-services-shared",
        component: "LocationServices",
        time: "10:00:02.000",
        message: keyed(UPDATE_ID, CI_ID, "LocateSup selected")
            .replace("safe:sup:lab", "safe:sup:prod.contoso.com"),
    };

    for record in [spoofed_source, privacy_client, privacy_sup] {
        let analysis = analyze_client_updates(&admitted(&[record])).expect("update analysis");
        assert!(analysis
            .correlation_handoff
            .counterpart_ready_facts
            .is_empty());
    }
}

#[test]
fn full_subject_tuple_prevents_false_phase_merges() {
    let mut scan = keyed(UPDATE_ID, CI_ID, "Scan succeeded");
    scan = scan.replace(&format!("JOB-{CI_ID}"), "JOB-A");
    let mut evaluate = keyed(UPDATE_ID, CI_ID, "Evaluate applicable");
    evaluate = evaluate.replace(&format!("JOB-{CI_ID}"), "JOB-B");
    let records = [
        Record {
            id: "update-a",
            basename: "ScanAgent.log",
            group: "client-updates",
            component: "ScanAgent",
            time: "11:00:00.000",
            message: scan,
        },
        Record {
            id: "update-b",
            basename: "WUAHandler.log",
            group: "client-updates",
            component: "WUAHandler",
            time: "11:00:01.000",
            message: evaluate,
        },
    ];

    let analysis = analyze_client_updates(&admitted(&records)).expect("update analysis");
    assert_eq!(analysis.transactions.len(), 2);
    assert!(analysis.transactions.iter().all(|transaction| {
        transaction.phase == SccmClientUpdatePhase::Scan
            || transaction.phase == SccmClientUpdatePhase::Evaluate
    }));
}

#[test]
fn equal_time_opposing_outcomes_are_contradictory() {
    let records = [
        Record {
            id: "update-a",
            basename: "UpdatesHandler.log",
            group: "client-updates",
            component: "UpdatesHandler",
            time: "12:30:00.000",
            message: keyed(UPDATE_ID, CI_ID, "Install terminal failure"),
        },
        Record {
            id: "update-b",
            basename: "UpdatesDeployment.log",
            group: "client-updates",
            component: "UpdatesDeployment",
            time: "12:30:00.000",
            message: keyed(UPDATE_ID, CI_ID, "Install succeeded"),
        },
    ];

    let analysis = analyze_client_updates(&admitted(&records)).expect("update analysis");
    assert_eq!(
        analysis.transactions[0].state,
        SccmClientUpdateState::Contradictory
    );
}

#[test]
fn public_ids_include_the_full_stable_subject_discriminator() {
    let records = [
        Record {
            id: "update-a",
            basename: "ScanAgent.log",
            group: "client-updates",
            component: "ScanAgent",
            time: "13:00:00.000",
            message: keyed(UPDATE_ID, "323010", "Scan terminal failure"),
        },
        Record {
            id: "update-b",
            basename: "WUAHandler.log",
            group: "client-updates",
            component: "ScanAgent",
            time: "13:00:01.000",
            message: keyed(UPDATE_ID, "323011", "Scan terminal failure"),
        },
    ];

    let analysis = analyze_client_updates(&admitted(&records)).expect("update analysis");
    assert_eq!(analysis.transactions.len(), 2);
    assert_ne!(
        analysis.transactions[0].transaction_id,
        analysis.transactions[1].transaction_id
    );
    assert_eq!(analysis.findings.len(), 2);
    assert_ne!(
        analysis.findings[0].finding_id,
        analysis.findings[1].finding_id
    );
}

#[test]
fn all_committed_update_scenarios_execute_through_the_exported_analyzer() {
    let mut scenarios = fs::read_dir(corpus_root())
        .expect("updates corpus directory")
        .map(|entry| entry.expect("scenario entry"))
        .filter(|entry| entry.file_type().expect("scenario type").is_dir())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    scenarios.sort();
    assert_eq!(
        scenarios.len(),
        17,
        "the complete committed corpus is executable"
    );

    for scenario in scenarios {
        let expected: Value = serde_json::from_slice(
            &fs::read(corpus_root().join(&scenario).join("expected.json"))
                .expect("scenario expected contract"),
        )
        .expect("valid scenario expected contract");
        let admitted = corpus_admitted(&scenario)
            .unwrap_or_else(|error| panic!("{scenario}: sealed corpus admission: {error}"));
        let analysis = analyze_client_updates(&admitted)
            .unwrap_or_else(|error| panic!("{scenario}: exported analyzer: {error}"));
        let actual = serde_json::to_value(&analysis).expect("serializable analysis");

        assert_eq!(
            actual["transactions"].as_array().map(Vec::len),
            expected["transactions"].as_array().map(Vec::len),
            "{scenario}: transaction count"
        );
        assert_eq!(
            actual["findings"].as_array().map(Vec::len),
            expected["findings"].as_array().map(Vec::len),
            "{scenario}: finding count"
        );
        for expected_transaction in expected["transactions"]
            .as_array()
            .expect("expected transactions")
        {
            let update_id = &expected_transaction["key"]["updateId"];
            let actual_transaction = actual["transactions"]
                .as_array()
                .expect("actual transactions")
                .iter()
                .find(|transaction| transaction["key"]["updateId"] == *update_id)
                .unwrap_or_else(|| panic!("{scenario}: missing transaction {update_id}"));
            for field in ["phase", "state", "lastSuccessfulPhase"] {
                assert_eq!(
                    actual_transaction[field], expected_transaction[field],
                    "{scenario}: {field}"
                );
            }
            if actual_transaction["state"] == "failed" {
                assert_eq!(
                    actual_transaction["classification"], "symptom",
                    "{scenario}: experimental keys cannot establish causal failure"
                );
            }
            assert_eq!(
                actual_transaction["nextArtifact"]["logicalArtifactId"],
                expected_transaction["nextArtifact"]["logicalArtifactId"],
                "{scenario}: bounded next artifact"
            );
        }
        assert_eq!(
            actual["correlationHandoff"]["counterpartReadyFacts"]
                .as_array()
                .map(Vec::len),
            expected["correlationHandoff"]["counterpartReadyFacts"]
                .as_array()
                .map(Vec::len),
            "{scenario}: counterpart-ready fact count"
        );
    }
}
