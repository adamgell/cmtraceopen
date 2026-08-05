use std::path::{Path, PathBuf};

use cmtraceopen_parser::sccm::client::{
    admit_client_evidence, analyze_client_task_sequence, assess_client_intake,
    SccmClientCapturedPayload, SccmClientIntakeArtifact, SccmClientIntakeBundle,
    SccmClientIntakeCaptureGap, SccmTaskSequenceClassification, SccmTaskSequenceConfidence,
    SccmTaskSequenceCoverageState, SccmTaskSequenceOrderingState, SccmTaskSequencePathClass,
    SccmTaskSequenceProvenance,
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

fn stable_opaque_id(prefix: &str, parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    format!(
        "{prefix}{}",
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

fn expected_transaction_id(transaction: &Value) -> String {
    let key = &transaction["key"];
    stable_opaque_id(
        "cmtraceopen.task-sequence.transaction.sha256.v1:",
        &[
            key["executionId"].as_str().expect("executionId is present"),
            key["taskSequencePackageId"]
                .as_str()
                .expect("package ID is present"),
            key["advertisementId"]
                .as_str()
                .expect("advertisement ID is present"),
            key["runContext"].as_str().expect("run context is present"),
        ],
    )
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

fn wire_rotation_kind(value: &Value) -> &str {
    match value["kind"].as_str().expect("rotation kind is a string") {
        "lo" => "loUnderscore",
        "current" => "current",
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

fn path_class(value: &str) -> SccmTaskSequencePathClass {
    match value {
        "winpe" => SccmTaskSequencePathClass::WinPe,
        "setup" => SccmTaskSequencePathClass::Setup,
        "fullOs" => SccmTaskSequencePathClass::FullOs,
        "client" => SccmTaskSequencePathClass::Client,
        "unknown" => SccmTaskSequencePathClass::Unknown,
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
        let content_binding = bytes.as_ref().filter(|_| capture_state == "captured");
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
        let task_sequence_provenance =
            matches!(capture_state, "captured" | "capped" | "parseFailed").then(|| {
                SccmTaskSequenceProvenance {
                    version: 1,
                    path_class: path_class(
                        fixture["pathClass"]
                            .as_str()
                            .expect("pathClass is a string"),
                    ),
                    smsts_log_path_evidence: fixture["smstsLogPathEvidence"]
                        .as_str()
                        .map(str::to_owned),
                    relocation_lineage: stable_opaque_id(
                        "cmtraceopen.task-sequence.relocation.sha256.v1:",
                        &[
                            scenario,
                            if fixture["relativePath"]
                                .as_str()
                                .is_some_and(|path| path.contains("/root-a/"))
                            {
                                "root-a"
                            } else if fixture["relativePath"]
                                .as_str()
                                .is_some_and(|path| path.contains("/root-b/"))
                            {
                                "root-b"
                            } else {
                                "single-root"
                            },
                        ],
                    ),
                    relocation_ordinal: fixture["relocationOrdinal"]
                        .as_u64()
                        .expect("relocationOrdinal is a number")
                        as u32,
                }
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
            task_sequence_provenance,
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

struct CustomTaskSequenceSource<'a> {
    artifact_label: &'a str,
    source_label: &'a str,
    content: &'a str,
    rotation: SccmRotation,
    root: Option<&'a str>,
    relocation_lineage: &'a str,
    relocation_ordinal: u32,
}

fn admitted_custom_sources(
    sources: Vec<CustomTaskSequenceSource<'_>>,
) -> cmtraceopen_parser::sccm::client::SccmClientAdmittedEvidence {
    let mut artifacts = Vec::new();
    let mut payloads = Vec::new();
    for source in sources {
        let bytes = source.content.as_bytes().to_vec();
        let artifact_id = opaque_artifact_id(source.artifact_label);
        let basename = match source.rotation {
            SccmRotation::Current => "smsts.log",
            SccmRotation::LoUnderscore => "smsts.lo_",
            _ => panic!("custom Task Sequence source uses an unsupported rotation"),
        };
        let rotation_segment = match source.rotation {
            SccmRotation::Current => "current",
            SccmRotation::LoUnderscore => "lo",
            _ => unreachable!("custom Task Sequence rotation is bounded above"),
        };
        let relative_path = source.root.map_or_else(
            || format!("evidence/client-task-sequence-smsts/client/{rotation_segment}/{basename}"),
            |root| {
                format!(
                    "evidence/client-task-sequence-smsts/client/{root}/{rotation_segment}/{basename}"
                )
            },
        );
        artifacts.push(SccmClientIntakeArtifact {
            artifact: SccmArtifact {
                artifact_id: artifact_id.clone(),
                display_name: basename.to_owned(),
                original_path: None,
                host: None,
                role: SccmRole::Client,
                configmgr_version: Some("5.00.TEST.0000".to_owned()),
                collected_at_utc: Some("2026-07-30T02:00:00Z".to_owned()),
                rotation: source.rotation,
                coverage: SccmCoverageState::Captured,
                encoding: Some("utf-8".to_owned()),
            },
            path_fingerprint: Some(format!("sha256:{}", digest(source.source_label.as_bytes()))),
            rotation_lineage: Some(format!(
                "cmtraceopen.lineage.sha256.v1:{}",
                digest(format!("{}-lineage", source.source_label).as_bytes())
            )),
            relative_path: Some(relative_path),
            task_sequence_provenance: Some(SccmTaskSequenceProvenance {
                version: 1,
                path_class: SccmTaskSequencePathClass::Client,
                smsts_log_path_evidence: None,
                relocation_lineage: source.relocation_lineage.to_owned(),
                relocation_ordinal: source.relocation_ordinal,
            }),
            fragment_complete: Some(true),
            declared_byte_length: Some(bytes.len() as u64),
            content_sha256: Some(digest(&bytes)),
        });
        payloads.push(
            SccmClientCapturedPayload::new(&artifact_id, bytes)
                .expect("custom payload identity is canonical"),
        );
    }
    let bundle = SccmClientIntakeBundle {
        artifacts,
        capture_gaps: Vec::new(),
    };
    let assessment =
        assess_client_intake(&bundle).expect("custom Task Sequence intake is canonical");
    admit_client_evidence(&bundle, &assessment, &payloads)
        .expect("custom Task Sequence records are admitted")
}

fn admitted_custom_records(
    label: &str,
    content: &str,
) -> cmtraceopen_parser::sccm::client::SccmClientAdmittedEvidence {
    admitted_custom_sources(vec![CustomTaskSequenceSource {
        artifact_label: label,
        source_label: label,
        content,
        rotation: SccmRotation::Current,
        root: None,
        relocation_lineage: "synthetic:ts-relocation:custom",
        relocation_ordinal: 0,
    }])
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

fn evidence_item_projection(value: &Value, make_opaque: bool) -> Option<(String, u64, u64)> {
    (!value.is_null()).then(|| {
        let artifact_id = value["artifactId"]
            .as_str()
            .expect("artifactId is a string");
        (
            if make_opaque {
                opaque_artifact_id(artifact_id)
            } else {
                artifact_id.to_owned()
            },
            value
                .get("lineStart")
                .or_else(|| value.get("startLine"))
                .expect("line start is present")
                .as_u64()
                .expect("line start is numeric"),
            value
                .get("lineEnd")
                .or_else(|| value.get("endLine"))
                .expect("line end is present")
                .as_u64()
                .expect("line end is numeric"),
        )
    })
}

#[test]
fn every_committed_scenario_runs_through_the_exported_production_reducer() {
    for scenario in SCENARIOS {
        let root = fixture_root(scenario);
        let expected = read_json(&root.join("expected.json"));
        let manifest = read_json(&root.join("manifest.json"));
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
        for expected_transaction in expected_transactions {
            let transaction_id = expected_transaction_id(expected_transaction);
            let actual_transaction = actual_transactions
                .iter()
                .find(|transaction| transaction["transactionId"] == transaction_id)
                .unwrap_or_else(|| {
                    panic!("{scenario}: missing stable transaction {transaction_id}")
                });
            for field in ["phase", "state", "classification"] {
                assert_eq!(
                    actual_transaction[field], expected_transaction[field],
                    "{scenario}: transaction {field}"
                );
            }
            for field in ["lastSuccessfulPhase", "confidence"] {
                assert_eq!(
                    actual_transaction[field], expected_transaction[field],
                    "{scenario}: transaction {field}"
                );
            }
            assert_eq!(
                actual_transaction["transactionId"], transaction_id,
                "{scenario}: subject-derived transaction ID"
            );
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
                actual_transaction["identityProof"]["extractionProfileId"],
                expected["extractionProfile"]["id"],
                "{scenario}: reviewed extraction profile"
            );
            assert_eq!(
                evidence_item_projection(&actual_transaction["terminalEvidence"], false),
                evidence_item_projection(&expected_transaction["terminalEvidence"], true),
                "{scenario}: terminal evidence"
            );
            let actual_next = &actual_transaction["nextEvidence"];
            let expected_next = &expected_transaction["nextArtifact"];
            assert_eq!(
                actual_next.is_null(),
                expected_next.is_null(),
                "{scenario}: bounded next-evidence presence"
            );
            if !expected_next.is_null() {
                for field in ["logicalArtifactId", "pathClass"] {
                    assert_eq!(
                        actual_next[field], expected_next[field],
                        "{scenario}: next-evidence {field}"
                    );
                }
                assert!(
                    actual_next["reason"]
                        .as_str()
                        .is_some_and(|reason| !reason.is_empty()),
                    "{scenario}: next-evidence reason is bounded and nonempty"
                );
            }
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
            assert_eq!(
                actual_transaction["pathSequence"]
                    .as_array()
                    .expect("pathSequence is an array")
                    .iter()
                    .map(|path| path["relocationOrdinal"].clone())
                    .collect::<Vec<_>>(),
                expected_transaction["pathSequence"]
                    .as_array()
                    .expect("expected pathSequence is an array")
                    .iter()
                    .map(|path| path["relocationOrdinal"].clone())
                    .collect::<Vec<_>>(),
                "{scenario}: explicit relocation ordering"
            );
            for path in actual_transaction["pathSequence"]
                .as_array()
                .expect("pathSequence is an array")
            {
                let fixture_id = manifest["artifacts"]
                    .as_array()
                    .expect("manifest artifacts are an array")
                    .iter()
                    .find(|artifact| {
                        opaque_artifact_id(
                            artifact["artifactId"]
                                .as_str()
                                .expect("fixture artifact ID is a string"),
                        ) == path["artifactId"]
                    })
                    .expect("path observation is owned by one physical artifact");
                assert_eq!(
                    path["rotation"]["kind"],
                    wire_rotation_kind(&fixture_id["rotation"]),
                    "{scenario}: physical rotation ownership"
                );
            }
        }

        let mut expected_coverage_gaps = manifest["artifacts"]
            .as_array()
            .expect("manifest artifacts are an array")
            .iter()
            .filter(|artifact| {
                artifact["captureState"] != "captured"
                    || artifact["rotation"]["fragmentComplete"] != true
            })
            .map(|artifact| {
                (
                    opaque_artifact_id(
                        artifact["artifactId"]
                            .as_str()
                            .expect("artifact ID is a string"),
                    ),
                    if artifact["captureState"] == "captured" {
                        "partial".to_owned()
                    } else {
                        artifact["captureState"]
                            .as_str()
                            .expect("capture state is a string")
                            .to_owned()
                    },
                    artifact["pathClass"]
                        .as_str()
                        .expect("path class is a string")
                        .to_owned(),
                )
            })
            .collect::<Vec<_>>();
        expected_coverage_gaps.sort();
        let mut actual_coverage_gaps = actual["coverageGaps"]
            .as_array()
            .expect("coverage gaps are an array")
            .iter()
            .map(|gap| {
                (
                    gap["artifactId"]
                        .as_str()
                        .expect("gap artifact ID is a string")
                        .to_owned(),
                    gap["coverage"]
                        .as_str()
                        .expect("gap coverage is a string")
                        .to_owned(),
                    gap["pathClass"]
                        .as_str()
                        .expect("gap path class is a string")
                        .to_owned(),
                )
            })
            .collect::<Vec<_>>();
        actual_coverage_gaps.sort();
        assert_eq!(
            actual_coverage_gaps, expected_coverage_gaps,
            "{scenario}: physical coverage gaps"
        );

        let actual_observations = actual["sourceLocalObservations"]
            .as_array()
            .expect("source-local observations are an array");
        let expected_observations = expected["sourceLocalObservations"]
            .as_array()
            .expect("expected source-local observations are an array");
        assert_eq!(
            actual_observations.len(),
            expected_observations.len(),
            "{scenario}: source-local observation count"
        );
        for expected_observation in expected_observations {
            let expected_artifact_id = opaque_artifact_id(
                expected_observation["artifactId"]
                    .as_str()
                    .expect("observation artifact ID is a string"),
            );
            let actual_observation = actual_observations
                .iter()
                .find(|observation| observation["artifactId"] == expected_artifact_id)
                .expect("source-local observation retains physical ownership");
            for field in [
                "keyConfidence",
                "confidence",
                "correlationEligible",
                "phaseHint",
                "stateHint",
            ] {
                assert_eq!(
                    actual_observation[field], expected_observation[field],
                    "{scenario}: source-local {field}"
                );
            }
            assert_eq!(
                evidence_item_projection(&actual_observation["evidence"], false),
                evidence_item_projection(&expected_observation["evidence"], true),
                "{scenario}: source-local physical citation"
            );
            let fixture_artifact = manifest["artifacts"]
                .as_array()
                .expect("manifest artifacts are an array")
                .iter()
                .find(|artifact| artifact["artifactId"] == expected_observation["artifactId"])
                .expect("source-local observation has manifest provenance");
            assert_eq!(
                actual_observation["rotation"]["kind"],
                wire_rotation_kind(&fixture_artifact["rotation"])
            );
            assert_eq!(
                actual_observation["coverage"],
                fixture_artifact["captureState"]
            );
            let evidence = expected_observation["evidence"]
                .as_object()
                .expect("source-local evidence is present");
            let line_start = evidence["startLine"]
                .as_u64()
                .expect("source-local start line is present")
                .to_string();
            let line_end = evidence["endLine"]
                .as_u64()
                .expect("source-local end line is present")
                .to_string();
            let mut observation_parts = vec![
                expected_artifact_id.as_str(),
                line_start.as_str(),
                line_end.as_str(),
            ];
            if fixture_artifact["rotation"]["fragmentComplete"] == false {
                observation_parts.push("physical-fragment");
            }
            assert_eq!(
                actual_observation["observationId"],
                stable_opaque_id(
                    "cmtraceopen.task-sequence.observation.sha256.v1:",
                    &observation_parts,
                ),
                "{scenario}: stable source-local observation ID"
            );
        }

        assert_eq!(
            actual["findings"].as_array().map(Vec::len),
            expected["findings"].as_array().map(Vec::len),
            "{scenario}: finding count"
        );
        let actual_findings = actual["findings"]
            .as_array()
            .expect("findings are an array");
        let expected_findings = expected["findings"]
            .as_array()
            .expect("expected findings are an array");
        for expected_finding in expected_findings {
            let expected_evidence = evidence_projection(&expected_finding["evidence"], true);
            let actual_finding = actual_findings
                .iter()
                .find(|finding| {
                    finding["classification"] == expected_finding["classification"]
                        && evidence_projection(&finding["evidence"], false) == expected_evidence
                })
                .expect("expected finding is emitted with exact evidence");
            let expected_finding_id =
                if let Some(transaction_id) = actual_finding["transactionId"].as_str() {
                    stable_opaque_id(
                        "cmtraceopen.task-sequence.finding.sha256.v1:",
                        &[transaction_id, "transaction"],
                    )
                } else if !actual_finding["coverageGaps"]
                    .as_array()
                    .expect("finding coverage gaps are an array")
                    .is_empty()
                    || expected_evidence.len() > 1
                {
                    let mut parts = vec!["coverage"];
                    parts.extend(
                        actual["coverageGaps"]
                            .as_array()
                            .expect("analysis coverage gaps are an array")
                            .iter()
                            .map(|gap| {
                                gap["artifactId"]
                                    .as_str()
                                    .expect("gap artifact ID is present")
                            }),
                    );
                    stable_opaque_id("cmtraceopen.task-sequence.finding.sha256.v1:", &parts)
                } else {
                    let observation_id = actual_observations
                        .iter()
                        .find(|observation| {
                            evidence_item_projection(&observation["evidence"], false)
                                == expected_evidence.first().cloned()
                        })
                        .and_then(|observation| observation["observationId"].as_str())
                        .expect("source-local finding has its observation");
                    stable_opaque_id(
                        "cmtraceopen.task-sequence.finding.sha256.v1:",
                        &["source-local", observation_id],
                    )
                };
            assert_eq!(
                actual_finding["findingId"], expected_finding_id,
                "{scenario}: stable finding ID"
            );
            let mut actual_finding_gaps = actual_finding["coverageGaps"]
                .as_array()
                .expect("finding coverage gaps are an array")
                .iter()
                .map(|gap| {
                    gap["artifactId"]
                        .as_str()
                        .expect("finding gap artifact ID is present")
                        .to_owned()
                })
                .collect::<Vec<_>>();
            actual_finding_gaps.sort();
            let mut expected_finding_gaps = expected_finding["coverageGapArtifactIds"]
                .as_array()
                .expect("expected finding gap IDs are an array")
                .iter()
                .map(|artifact_id| {
                    opaque_artifact_id(
                        artifact_id
                            .as_str()
                            .expect("expected finding gap ID is a string"),
                    )
                })
                .collect::<Vec<_>>();
            expected_finding_gaps.sort();
            assert_eq!(
                actual_finding_gaps, expected_finding_gaps,
                "{scenario}: finding coverage evidence"
            );
            if let Some(transaction_id) = actual_finding["transactionId"].as_str() {
                let transaction = actual_transactions
                    .iter()
                    .find(|transaction| transaction["transactionId"] == transaction_id)
                    .expect("transaction finding references its transaction");
                assert_eq!(actual_finding["confidence"], transaction["confidence"]);
                assert_eq!(actual_finding["phase"], transaction["phase"]);
            } else {
                assert_eq!(actual_finding["confidence"], "low");
                assert!(actual_finding["phase"].is_null());
            }
            assert_eq!(
                actual_finding["nextEvidence"].is_null(),
                expected_finding["boundedNextArtifact"].is_null(),
                "{scenario}: finding next-evidence presence"
            );
            if !expected_finding["boundedNextArtifact"].is_null() {
                for field in ["logicalArtifactId", "pathClass"] {
                    assert_eq!(
                        actual_finding["nextEvidence"][field],
                        expected_finding["boundedNextArtifact"][field],
                        "{scenario}: finding next-evidence {field}"
                    );
                }
            }
        }
        assert_eq!(
            actual_findings
                .iter()
                .filter_map(|finding| finding["findingId"].as_str())
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            actual_findings.len(),
            "{scenario}: finding IDs are unique"
        );
    }
}

#[test]
fn exported_analysis_redacts_join_identity_paths_and_native_acceptance() {
    let wire = SCENARIOS
        .iter()
        .map(|scenario| {
            serde_json::to_string(
                &analyze_client_task_sequence(&admitted_scenario(scenario))
                    .expect("sealed Task Sequence analysis succeeds"),
            )
            .expect("Task Sequence analysis serializes")
        })
        .collect::<String>();

    assert!(!wire.contains("72400000"));
    assert!(!wire.contains("LAB00324"));
    assert!(!wire.contains("LAB203"));
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
    assert_eq!(
        analysis.transactions[0].confidence,
        SccmTaskSequenceConfidence::Low
    );
    assert!(analysis.transactions[0].terminal_evidence.is_none());
}

#[test]
fn transaction_ids_are_subject_derived_and_stable_across_result_sets() {
    let run_a = "<![LOG[phase=preflight state=inProgress terminal=false executionId=72400000-0000-0000-0000-000000000091 taskSequencePackageId=LAB00324 advertisementId=LAB20391 runContext=osd _SMSTSLogPath=SYNTHETIC://client/CCM/Logs/smsts.log]LOG]!><time=\"02:00:01.000+000\" date=\"07-30-2026\" component=\"TSManager\" context=\"\" type=\"1\" thread=\"1\" file=\"synthetic.ts:1\">\n";
    let run_b = "<![LOG[phase=installSoftware state=inProgress terminal=false executionId=72400000-0000-0000-0000-000000000092 taskSequencePackageId=LAB00324 advertisementId=LAB20392 runContext=osd _SMSTSLogPath=SYNTHETIC://client/CCM/Logs/smsts.log]LOG]!><time=\"02:00:02.000+000\" date=\"07-30-2026\" component=\"TSManager\" context=\"\" type=\"1\" thread=\"1\" file=\"synthetic.ts:2\">\n";
    let analysis_a = analyze_client_task_sequence(&admitted_custom_records("stable-a", run_a))
        .expect("run A analysis succeeds");
    let analysis_b = analyze_client_task_sequence(&admitted_custom_records("stable-b", run_b))
        .expect("run B analysis succeeds");
    let combined = analyze_client_task_sequence(&admitted_custom_records(
        "stable-combined",
        &format!("{run_b}{run_a}"),
    ))
    .expect("combined analysis succeeds");

    let id_a = &analysis_a.transactions[0].transaction_id;
    let id_b = &analysis_b.transactions[0].transaction_id;
    assert_ne!(id_a, id_b);
    assert!(id_a.starts_with("cmtraceopen.task-sequence.transaction.sha256.v1:"));
    assert_eq!(
        combined
            .transactions
            .iter()
            .map(|transaction| transaction.transaction_id.as_str())
            .collect::<std::collections::BTreeSet<_>>(),
        [id_a.as_str(), id_b.as_str()].into_iter().collect()
    );
}

#[test]
fn identical_execution_identity_across_distinct_relocation_lineages_stays_source_local() {
    let execution_id = "72400000-0000-0000-0000-000000000095";
    let package_id = "LAB00324";
    let advertisement_id = "LAB20395";
    let run_context = "osd";
    let first = format!(
        "<![LOG[phase=preflight state=inProgress terminal=false executionId={execution_id} taskSequencePackageId={package_id} advertisementId={advertisement_id} runContext={run_context} _SMSTSLogPath=SYNTHETIC://client/root-a/CCM/Logs/smstslog/smsts.log]LOG]!><time=\"02:00:01.000+000\" date=\"07-30-2026\" component=\"TSManager\" context=\"\" type=\"1\" thread=\"1\" file=\"synthetic.ts:1\">\n"
    );
    let terminal = format!(
        "<![LOG[phase=complete state=succeeded terminal=true executionId={execution_id} taskSequencePackageId={package_id} advertisementId={advertisement_id} runContext={run_context} _SMSTSLogPath=SYNTHETIC://client/root-b/CCM/Logs/smstslog/smsts.log]LOG]!><time=\"02:00:02.000+000\" date=\"07-30-2026\" component=\"TSManager\" context=\"\" type=\"0\" thread=\"1\" file=\"synthetic.ts:2\">\n"
    );
    let admitted = admitted_custom_sources(vec![
        CustomTaskSequenceSource {
            artifact_label: "cross-lineage-a",
            source_label: "cross-lineage-source-a",
            content: &first,
            rotation: SccmRotation::Current,
            root: Some("root-a"),
            relocation_lineage: "synthetic:ts-relocation:root-a",
            relocation_ordinal: 0,
        },
        CustomTaskSequenceSource {
            artifact_label: "cross-lineage-b",
            source_label: "cross-lineage-source-b",
            content: &terminal,
            rotation: SccmRotation::Current,
            root: Some("root-b"),
            relocation_lineage: "synthetic:ts-relocation:root-b",
            relocation_ordinal: 0,
        },
    ]);

    let analysis = analyze_client_task_sequence(&admitted).expect("analysis succeeds");

    assert!(analysis.transactions.is_empty());
    assert_eq!(analysis.source_local_observations.len(), 2);
    assert!(analysis
        .source_local_observations
        .iter()
        .all(|observation| !observation.correlation_eligible));
    assert_eq!(analysis.findings.len(), 2);
    assert!(analysis.findings.iter().all(|finding| {
        finding.transaction_id.is_none()
            && finding.classification == SccmTaskSequenceClassification::InsufficientEvidence
            && finding.confidence == SccmTaskSequenceConfidence::Low
    }));
}

#[test]
fn same_lineage_current_and_lo_rotation_still_form_one_transaction() {
    let execution_id = "72400000-0000-0000-0000-000000000096";
    let package_id = "LAB00324";
    let advertisement_id = "LAB20396";
    let run_context = "osd";
    let archived = format!(
        "<![LOG[phase=preflight state=inProgress terminal=false executionId={execution_id} taskSequencePackageId={package_id} advertisementId={advertisement_id} runContext={run_context} _SMSTSLogPath=SYNTHETIC://client/CCM/Logs/smsts.log]LOG]!><time=\"02:00:01.000+000\" date=\"07-30-2026\" component=\"TSManager\" context=\"\" type=\"1\" thread=\"1\" file=\"synthetic.ts:1\">\n"
    );
    let current = format!(
        "<![LOG[phase=complete state=succeeded terminal=true executionId={execution_id} taskSequencePackageId={package_id} advertisementId={advertisement_id} runContext={run_context} _SMSTSLogPath=SYNTHETIC://client/CCM/Logs/smsts.log]LOG]!><time=\"02:00:02.000+000\" date=\"07-30-2026\" component=\"TSManager\" context=\"\" type=\"0\" thread=\"1\" file=\"synthetic.ts:2\">\n"
    );
    let admitted = admitted_custom_sources(vec![
        CustomTaskSequenceSource {
            artifact_label: "same-lineage-lo",
            source_label: "same-lineage-source",
            content: &archived,
            rotation: SccmRotation::LoUnderscore,
            root: None,
            relocation_lineage: "synthetic:ts-relocation:same-source",
            relocation_ordinal: 0,
        },
        CustomTaskSequenceSource {
            artifact_label: "same-lineage-current",
            source_label: "same-lineage-source",
            content: &current,
            rotation: SccmRotation::Current,
            root: None,
            relocation_lineage: "synthetic:ts-relocation:same-source",
            relocation_ordinal: 0,
        },
    ]);

    let analysis = analyze_client_task_sequence(&admitted).expect("analysis succeeds");

    assert_eq!(analysis.transactions.len(), 1);
    assert_eq!(
        analysis.transactions[0].classification,
        SccmTaskSequenceClassification::Success
    );
    assert!(analysis.transactions[0].terminal_evidence.is_some());
}

#[test]
fn terminal_failure_followed_by_success_requires_explicit_recovery_authority() {
    let admitted = admitted_custom_records(
        "ambiguous-recovery",
        concat!(
            "<![LOG[phase=installClient state=failed terminal=true executionId=72400000-0000-0000-0000-000000000093 taskSequencePackageId=LAB00324 advertisementId=LAB20393 runContext=osd _SMSTSLogPath=SYNTHETIC://client/CCM/Logs/smsts.log]LOG]!><time=\"02:00:01.000+000\" date=\"07-30-2026\" component=\"TSManager\" context=\"\" type=\"3\" thread=\"1\" file=\"synthetic.ts:1\">\n",
            "<![LOG[phase=complete state=succeeded terminal=true executionId=72400000-0000-0000-0000-000000000093 taskSequencePackageId=LAB00324 advertisementId=LAB20393 runContext=osd _SMSTSLogPath=SYNTHETIC://client/CCM/Logs/smsts.log]LOG]!><time=\"02:00:02.000+000\" date=\"07-30-2026\" component=\"TSManager\" context=\"\" type=\"0\" thread=\"1\" file=\"synthetic.ts:2\">\n"
        ),
    );

    let analysis = analyze_client_task_sequence(&admitted).expect("analysis succeeds");
    let transaction = &analysis.transactions[0];
    assert_eq!(
        transaction.classification,
        SccmTaskSequenceClassification::InsufficientEvidence
    );
    assert_eq!(transaction.confidence, SccmTaskSequenceConfidence::Low);
    assert_eq!(
        transaction.ordering_state,
        SccmTaskSequenceOrderingState::Ambiguous
    );
    assert!(transaction.terminal_evidence.is_none());
}

#[test]
fn mixed_invalid_chronology_is_ambiguous_without_a_terminal_citation() {
    let admitted = admitted_custom_records(
        "mixed-invalid-chronology",
        concat!(
            "<![LOG[phase=installClient state=inProgress terminal=false executionId=72400000-0000-0000-0000-000000000094 taskSequencePackageId=LAB00324 advertisementId=LAB20394 runContext=osd _SMSTSLogPath=SYNTHETIC://client/CCM/Logs/smsts.log]LOG]!><time=\"02:00:01.000+9999\" date=\"07-30-2026\" component=\"TSManager\" context=\"\" type=\"1\" thread=\"1\" file=\"synthetic.ts:1\">\n",
            "<![LOG[phase=complete state=succeeded terminal=true executionId=72400000-0000-0000-0000-000000000094 taskSequencePackageId=LAB00324 advertisementId=LAB20394 runContext=osd _SMSTSLogPath=SYNTHETIC://client/CCM/Logs/smsts.log]LOG]!><time=\"02:00:02.000+000\" date=\"07-30-2026\" component=\"TSManager\" context=\"\" type=\"0\" thread=\"1\" file=\"synthetic.ts:2\">\n"
        ),
    );

    let analysis = analyze_client_task_sequence(&admitted).expect("analysis succeeds");
    let transaction = &analysis.transactions[0];
    assert_eq!(
        transaction.ordering_state,
        SccmTaskSequenceOrderingState::Ambiguous
    );
    assert_eq!(
        transaction.classification,
        SccmTaskSequenceClassification::InsufficientEvidence
    );
    assert!(transaction.terminal_evidence.is_none());
}

#[test]
fn source_local_profile_and_rotation_gaps_remain_cited_and_noncorrelatable() {
    let unknown = analyze_client_task_sequence(&admitted_scenario("unknown-profile"))
        .expect("unknown profile analysis succeeds");
    assert_eq!(unknown.source_local_observations.len(), 1);
    assert!(!unknown.source_local_observations[0].correlation_eligible);
    assert!(unknown.source_local_observations[0].evidence.is_some());

    let unkeyed = analyze_client_task_sequence(&admitted_scenario("complete-looking-unkeyed"))
        .expect("unkeyed analysis succeeds");
    assert_eq!(unkeyed.source_local_observations.len(), 1);
    assert!(!unkeyed.source_local_observations[0].correlation_eligible);

    let rotation = analyze_client_task_sequence(&admitted_scenario("rotation-boundary"))
        .expect("rotation analysis succeeds");
    assert_eq!(rotation.source_local_observations.len(), 2);
    assert!(rotation
        .source_local_observations
        .iter()
        .all(|observation| !observation.correlation_eligible));
    assert!(rotation
        .source_local_observations
        .iter()
        .all(|observation| observation.evidence.is_some()));
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
fn duplicate_record_local_identity_labels_are_not_exact_keys() {
    let admitted = admitted_custom_records(
        "duplicate-task-sequence-identity",
        "<![LOG[phase=preflight state=inProgress terminal=false executionId=72400000-0000-0000-0000-000000000097 executionId=72400000-0000-0000-0000-000000000096 taskSequencePackageId=LAB00324 advertisementId=LAB20397 runContext=osd _SMSTSLogPath=SYNTHETIC://client/CCM/Logs/smsts.log]LOG]!><time=\"02:00:01.000+000\" date=\"07-30-2026\" component=\"TSManager\" context=\"\" type=\"1\" thread=\"1\" file=\"synthetic.ts:1\">\n",
    );

    let analysis = analyze_client_task_sequence(&admitted).expect("analysis succeeds");

    assert!(analysis.transactions.is_empty());
    assert_eq!(analysis.source_local_observations.len(), 1);
    assert!(!analysis.source_local_observations[0].correlation_eligible);
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
