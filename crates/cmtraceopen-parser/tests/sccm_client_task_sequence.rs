use std::path::{Path, PathBuf};

use cmtraceopen_parser::sccm::client::{
    admit_client_evidence, analyze_client_task_sequence, assess_client_intake,
    SccmClientCapturedPayload, SccmClientIntakeArtifact, SccmClientIntakeBundle,
    SccmClientIntakeCaptureGap, SccmTaskSequenceClassification, SccmTaskSequenceCoverageState,
    SccmTaskSequenceOrderingState,
};
use cmtraceopen_parser::sccm::{SccmArtifact, SccmCoverageState, SccmRole, SccmRotation};
use serde_json::Value;
use sha2::{Digest, Sha256};

const SCENARIOS: [&str; 17] = [
    "client-install-failure",
    "client-installed",
    "complete-looking-unkeyed",
    "completed",
    "disk-image-failure",
    "incomplete",
    "invalid-offset",
    "post-format",
    "pre-client",
    "reboot-continuation",
    "relocated-fragments",
    "rotation-boundary",
    "software-install-failure",
    "terminal-preflight",
    "unknown-profile",
    "unrelated-runs",
    "winpe",
];

fn fixture_root(scenario: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sccm/client/task_sequence")
        .join(scenario)
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).expect("fixture JSON is readable"))
        .expect("fixture JSON is valid")
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn opaque_artifact_id(value: &str) -> String {
    format!("sccm-artifact:v1:sha256:{}", digest(value.as_bytes()))
}

fn coverage(value: &str) -> SccmCoverageState {
    match value {
        "captured" => SccmCoverageState::Captured,
        "absent" => SccmCoverageState::Absent,
        other => panic!("unsupported Task Sequence fixture capture state: {other}"),
    }
}

fn rotation(value: &Value) -> SccmRotation {
    match value["kind"].as_str().expect("rotation kind is a string") {
        "current" => SccmRotation::Current,
        "lo" => SccmRotation::LoUnderscore,
        other => panic!("unsupported Task Sequence fixture rotation: {other}"),
    }
}

fn safe_path_class(value: &str) -> &str {
    match value {
        "winpe" => "winpe",
        "setup" => "setup",
        "fullOs" => "full-os",
        "client" => "client",
        "unknown" => "unknown",
        other => panic!("unsupported Task Sequence fixture path class: {other}"),
    }
}

fn intake_relative_path(artifact: &Value, display_name: &str, rotation: &SccmRotation) -> String {
    let path_class = safe_path_class(
        artifact["pathClass"]
            .as_str()
            .expect("pathClass is a string"),
    );
    let storage_path = artifact["relativePath"].as_str().unwrap_or_default();
    let root = if storage_path.contains("/root-a/") {
        Some("root-a")
    } else if storage_path.contains("/root-b/") {
        Some("root-b")
    } else {
        None
    };
    let rotation_segment = match rotation {
        SccmRotation::Current => "current",
        SccmRotation::LoUnderscore => "lo",
        _ => unreachable!("fixture rotation is bounded above"),
    };

    match root {
        Some(root) => format!(
            "evidence/client-task-sequence-smsts/{path_class}/{root}/{rotation_segment}/{display_name}"
        ),
        None => format!(
            "evidence/client-task-sequence-smsts/{path_class}/{rotation_segment}/{display_name}"
        ),
    }
}

fn admitted_scenario(
    scenario: &str,
) -> cmtraceopen_parser::sccm::client::SccmClientAdmittedEvidence {
    admitted_scenario_with_order(scenario, false)
}

fn admitted_scenario_with_order(
    scenario: &str,
    reverse: bool,
) -> cmtraceopen_parser::sccm::client::SccmClientAdmittedEvidence {
    let root = fixture_root(scenario);
    let manifest = read_json(&root.join("manifest.json"));
    let mut artifacts = Vec::new();
    let mut payloads = Vec::new();

    for fixture in manifest["artifacts"]
        .as_array()
        .expect("manifest artifacts are an array")
    {
        let fixture_artifact_id = fixture["artifactId"]
            .as_str()
            .expect("artifactId is a string");
        let artifact_id = opaque_artifact_id(fixture_artifact_id);
        let display_name = fixture["originalBasename"]
            .as_str()
            .expect("originalBasename is a string");
        let capture_state = fixture["captureState"]
            .as_str()
            .expect("captureState is a string");
        let rotation = rotation(&fixture["rotation"]);
        let fragment_complete = Some(
            fixture["rotation"]["fragmentComplete"]
                .as_bool()
                .unwrap_or(false),
        );
        let relative_path = fixture["relativePath"]
            .as_str()
            .filter(|path| !path.is_empty());
        let bytes = relative_path.map(|path| {
            std::fs::read(root.join(path)).expect("declared Task Sequence evidence is readable")
        });
        let content_binding = bytes
            .as_ref()
            .filter(|_| capture_state == "captured" && fragment_complete == Some(true));
        let path_fingerprint = fixture["pathFingerprint"]
            .as_str()
            .map(|value| format!("sha256:{}", digest(value.as_bytes())));
        let rotation_lineage = fixture["sanitizedSourcePath"]
            .as_str()
            .and_then(|value| value.rsplit_once('/').map(|(parent, _)| parent))
            .map(|parent| {
                format!(
                    "cmtraceopen.lineage.sha256.v1:{}",
                    digest(parent.as_bytes())
                )
            });

        artifacts.push(SccmClientIntakeArtifact {
            artifact: SccmArtifact {
                artifact_id: artifact_id.clone(),
                display_name: display_name.to_owned(),
                original_path: None,
                host: None,
                role: SccmRole::Client,
                configmgr_version: fixture["sourceVersion"].as_str().map(str::to_owned),
                collected_at_utc: fixture["capturedUtc"].as_str().map(str::to_owned),
                rotation: rotation.clone(),
                coverage: coverage(capture_state),
                encoding: fixture["encoding"].as_str().map(str::to_owned),
            },
            path_fingerprint,
            rotation_lineage,
            relative_path: relative_path
                .map(|_| intake_relative_path(fixture, display_name, &rotation)),
            fragment_complete,
            declared_byte_length: content_binding.map(|bytes| bytes.len() as u64),
            content_sha256: content_binding.map(|bytes| digest(bytes)),
        });

        if let Some(bytes) = content_binding {
            payloads.push(
                SccmClientCapturedPayload::new(&artifact_id, bytes.clone())
                    .expect("fixture payload identity is canonical"),
            );
        }
    }

    if reverse {
        artifacts.reverse();
        payloads.reverse();
    }

    let bundle = SccmClientIntakeBundle {
        artifacts,
        capture_gaps: Vec::new(),
    };
    let assessment = assess_client_intake(&bundle)
        .unwrap_or_else(|error| panic!("{scenario}: Task Sequence intake is canonical: {error}"));
    admit_client_evidence(&bundle, &assessment, &payloads)
        .expect("Task Sequence evidence reaches the sealed admission boundary")
}

fn admitted_custom_records(
    label: &str,
    content: &str,
) -> cmtraceopen_parser::sccm::client::SccmClientAdmittedEvidence {
    let bytes = content.as_bytes().to_vec();
    let artifact_id = opaque_artifact_id(label);
    let bundle = SccmClientIntakeBundle {
        artifacts: vec![SccmClientIntakeArtifact {
            artifact: SccmArtifact {
                artifact_id: artifact_id.clone(),
                display_name: "smsts.log".to_owned(),
                original_path: None,
                host: None,
                role: SccmRole::Client,
                configmgr_version: Some("5.00.TEST.0000".to_owned()),
                collected_at_utc: Some("2026-07-30T02:00:00Z".to_owned()),
                rotation: SccmRotation::Current,
                coverage: SccmCoverageState::Captured,
                encoding: Some("utf-8".to_owned()),
            },
            path_fingerprint: Some(format!("sha256:{}", digest(label.as_bytes()))),
            rotation_lineage: Some(format!(
                "cmtraceopen.lineage.sha256.v1:{}",
                digest(format!("{label}-lineage").as_bytes())
            )),
            relative_path: Some(
                "evidence/client-task-sequence-smsts/client/current/smsts.log".to_owned(),
            ),
            fragment_complete: Some(true),
            declared_byte_length: Some(bytes.len() as u64),
            content_sha256: Some(digest(&bytes)),
        }],
        capture_gaps: Vec::new(),
    };
    let assessment =
        assess_client_intake(&bundle).expect("custom Task Sequence intake is canonical");
    let payload = SccmClientCapturedPayload::new(&artifact_id, bytes)
        .expect("custom payload identity is canonical");
    admit_client_evidence(&bundle, &assessment, &[payload])
        .expect("custom Task Sequence records are admitted")
}

fn evidence_projection(value: &Value, make_opaque: bool) -> Vec<(String, u64, u64)> {
    value
        .as_array()
        .expect("evidence is an array")
        .iter()
        .map(|reference| {
            let artifact_id = reference["artifactId"]
                .as_str()
                .expect("artifactId is a string");
            (
                if make_opaque {
                    opaque_artifact_id(artifact_id)
                } else {
                    artifact_id.to_owned()
                },
                reference
                    .get("lineStart")
                    .or_else(|| reference.get("startLine"))
                    .expect("line start is present")
                    .as_u64()
                    .expect("lineStart is a number"),
                reference
                    .get("lineEnd")
                    .or_else(|| reference.get("endLine"))
                    .expect("line end is present")
                    .as_u64()
                    .expect("lineEnd is a number"),
            )
        })
        .collect()
}

#[test]
fn every_committed_scenario_runs_through_the_exported_production_reducer() {
    for scenario in SCENARIOS {
        let expected = read_json(&fixture_root(scenario).join("expected.json"));
        let admitted = admitted_scenario(scenario);
        let actual = serde_json::to_value(
            analyze_client_task_sequence(&admitted)
                .expect("sealed Task Sequence analysis succeeds"),
        )
        .expect("Task Sequence analysis serializes");
        let actual_transactions = actual["transactions"]
            .as_array()
            .expect("production transactions are an array");
        let expected_transactions = expected["transactions"]
            .as_array()
            .expect("expected transactions are an array");

        assert_eq!(
            actual_transactions.len(),
            expected_transactions.len(),
            "{scenario}: transaction count"
        );
        for (actual_transaction, expected_transaction) in
            actual_transactions.iter().zip(expected_transactions)
        {
            for field in ["phase", "state", "classification"] {
                assert_eq!(
                    actual_transaction[field], expected_transaction[field],
                    "{scenario}: transaction {field}"
                );
            }
            assert_eq!(
                actual_transaction["orderingState"],
                expected_transaction["timestampProvenance"]["orderingState"],
                "{scenario}: ordering state"
            );
            assert_eq!(
                evidence_projection(&actual_transaction["evidence"], false),
                evidence_projection(&expected_transaction["evidence"], true),
                "{scenario}: exact transaction evidence"
            );
            assert_eq!(
                actual_transaction["identityProof"]["evidence"], actual_transaction["evidence"],
                "{scenario}: every joined record independently proves the exact identity"
            );
            assert_eq!(
                actual_transaction["pathSequence"]
                    .as_array()
                    .expect("pathSequence is an array")
                    .iter()
                    .map(|path| path["pathClass"].clone())
                    .collect::<Vec<_>>(),
                expected_transaction["pathSequence"]
                    .as_array()
                    .expect("expected pathSequence is an array")
                    .iter()
                    .map(|path| path["pathClass"].clone())
                    .collect::<Vec<_>>(),
                "{scenario}: admitted path progression"
            );
        }

        assert_eq!(
            actual["findings"].as_array().map(Vec::len),
            expected["findings"].as_array().map(Vec::len),
            "{scenario}: finding count"
        );
    }
}

#[test]
fn exported_analysis_redacts_join_identity_paths_and_native_acceptance() {
    let admitted = admitted_scenario("relocated-fragments");
    let wire = serde_json::to_string(
        &analyze_client_task_sequence(&admitted).expect("sealed Task Sequence analysis succeeds"),
    )
    .expect("Task Sequence analysis serializes");

    assert!(!wire.contains("72400000-0000-0000-0000-000000000006"));
    assert!(!wire.contains("LAB00324"));
    assert!(!wire.contains("LAB20306"));
    assert!(!wire.contains("SYNTHETIC://"));
    assert!(!wire.contains("_SMSTSLogPath"));
    assert!(!wire.contains("nativeAcceptance"));
}

#[test]
fn production_result_is_input_order_invariant() {
    let admitted = admitted_scenario_with_order("relocated-fragments", false);
    let first = serde_json::to_value(
        analyze_client_task_sequence(&admitted).expect("first analysis succeeds"),
    )
    .expect("first analysis serializes");
    let reversed = admitted_scenario_with_order("relocated-fragments", true);
    let second = serde_json::to_value(
        analyze_client_task_sequence(&reversed).expect("reversed analysis succeeds"),
    )
    .expect("second analysis serializes");

    assert_eq!(first, second);
}

#[test]
fn same_execution_with_equal_timestamps_is_ambiguous_not_ordered() {
    let admitted = admitted_custom_records(
        "same-time-task-sequence",
        concat!(
            "<![LOG[phase=installClient state=succeeded terminal=false executionId=72400000-0000-0000-0000-000000000099 taskSequencePackageId=LAB00324 advertisementId=LAB20399 runContext=osd _SMSTSLogPath=SYNTHETIC://client/CCM/Logs/smsts.log]LOG]!><time=\"02:00:00.000+000\" date=\"07-30-2026\" component=\"TSManager\" context=\"\" type=\"0\" thread=\"1\" file=\"synthetic.ts:1\">\n",
            "<![LOG[phase=installSoftware state=inProgress terminal=false executionId=72400000-0000-0000-0000-000000000099 taskSequencePackageId=LAB00324 advertisementId=LAB20399 runContext=osd _SMSTSLogPath=SYNTHETIC://client/CCM/Logs/smsts.log]LOG]!><time=\"02:00:00.000+000\" date=\"07-30-2026\" component=\"TSManager\" context=\"\" type=\"1\" thread=\"1\" file=\"synthetic.ts:2\">\n"
        ),
    );

    let analysis = analyze_client_task_sequence(&admitted).expect("analysis succeeds");

    assert_eq!(analysis.transactions.len(), 1);
    assert_eq!(
        analysis.transactions[0].ordering_state,
        SccmTaskSequenceOrderingState::Ambiguous
    );
    assert_eq!(
        analysis.transactions[0].classification,
        SccmTaskSequenceClassification::InsufficientEvidence
    );
}

#[test]
fn identity_fields_split_across_records_never_form_a_transaction() {
    let admitted = admitted_custom_records(
        "split-task-sequence-identity",
        concat!(
            "<![LOG[phase=preflight state=inProgress terminal=false executionId=72400000-0000-0000-0000-000000000098 taskSequencePackageId=LAB00324 _SMSTSLogPath=SYNTHETIC://client/CCM/Logs/smsts.log]LOG]!><time=\"02:00:01.000+000\" date=\"07-30-2026\" component=\"TSManager\" context=\"\" type=\"1\" thread=\"1\" file=\"synthetic.ts:1\">\n",
            "<![LOG[phase=preflight state=inProgress terminal=false advertisementId=LAB20398 runContext=osd _SMSTSLogPath=SYNTHETIC://client/CCM/Logs/smsts.log]LOG]!><time=\"02:00:02.000+000\" date=\"07-30-2026\" component=\"TSManager\" context=\"\" type=\"1\" thread=\"1\" file=\"synthetic.ts:2\">\n"
        ),
    );

    let analysis = analyze_client_task_sequence(&admitted).expect("analysis succeeds");

    assert!(analysis.transactions.is_empty());
    assert_eq!(analysis.findings.len(), 2);
}

#[test]
fn coverage_only_task_sequence_capture_gap_survives_sealed_analysis() {
    let lineage_digest = digest(b"coverage-only-task-sequence-lineage");
    let bundle = SccmClientIntakeBundle {
        artifacts: Vec::new(),
        capture_gaps: vec![SccmClientIntakeCaptureGap {
            artifact_id: opaque_artifact_id("coverage-only-task-sequence"),
            basename: "smsts.log".to_owned(),
            rotation: SccmRotation::Current,
            coverage: SccmCoverageState::Capped,
            path_fingerprint: format!("sha256:{}", digest(b"coverage-only-task-sequence-path")),
            rotation_lineage: format!("cmtraceopen.lineage.sha256.v1:{lineage_digest}"),
        }],
    };
    let assessment = assess_client_intake(&bundle).expect("coverage-only intake is canonical");
    let admitted = admit_client_evidence(&bundle, &assessment, &[])
        .expect("coverage-only intake yields sealed authority");

    let analysis = analyze_client_task_sequence(&admitted).expect("analysis succeeds");

    assert!(analysis.transactions.is_empty());
    assert_eq!(analysis.coverage_gaps.len(), 1);
    assert_eq!(
        analysis.coverage_gaps[0].coverage,
        SccmTaskSequenceCoverageState::Capped
    );
}
