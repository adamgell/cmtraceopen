use cmtraceopen_parser::sccm::client::{
    admit_client_evidence, analyze_client_extended, assess_client_intake,
    SccmClientCapturedPayload, SccmClientExtendedState, SccmClientExtendedWorkflow,
    SccmClientIntakeArtifact, SccmClientIntakeBundle,
};
use cmtraceopen_parser::sccm::{SccmArtifact, SccmCoverageState, SccmRole, SccmRotation};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

struct Source<'a> {
    id: &'a str,
    basename: &'a str,
    component: &'a str,
    coverage: SccmCoverageState,
    records: Vec<(&'a str, &'a str)>,
}

fn source_group(basename: &str) -> &'static str {
    match basename {
        "InventoryAgent.log" | "InventoryProvider.log" | "InventoryAgentProvider.log" => {
            "client-inventory"
        }
        "CIAgent.log" | "StateMessage.log" => "client-policy-state",
        "CITaskMgr.log" | "DCMAgent.log" | "DCMReporting.log" => "client-compliance",
        "SWMTRReportGen.log" => "client-metering",
        _ => panic!("unexpected extended source {basename}"),
    }
}

fn admitted(
    sources: Vec<Source<'_>>,
) -> cmtraceopen_parser::sccm::client::SccmClientAdmittedEvidence {
    let mut artifacts = Vec::new();
    let mut payloads = Vec::new();
    for source in sources {
        let artifact_id = format!("fixture-{}", source.id);
        let bytes = source
            .records
            .iter()
            .map(|(time, message)| {
                format!(
                    "<![LOG[{message}]LOG]!><time=\"{time}+000\" date=\"7-30-2026\" component=\"{}\" context=\"\" type=\"1\" thread=\"1\" file=\"synthetic.cc:325\">\n",
                    source.component
                )
            })
            .collect::<String>()
            .into_bytes();
        let captured = source.coverage == SccmCoverageState::Captured;
        artifacts.push(SccmClientIntakeArtifact {
            artifact: SccmArtifact {
                artifact_id: artifact_id.clone(),
                display_name: source.basename.to_owned(),
                original_path: None,
                host: None,
                role: SccmRole::Client,
                configmgr_version: Some("5.00.9128.1000".to_owned()),
                collected_at_utc: Some("2026-07-30T23:59:59Z".to_owned()),
                rotation: SccmRotation::Current,
                coverage: source.coverage,
                encoding: captured.then(|| "utf-8".to_owned()),
            },
            path_fingerprint: Some(format!("synthetic-{}", source.id)),
            rotation_lineage: None,
            relative_path: captured.then(|| {
                format!(
                    "evidence/{}/current/{}",
                    source_group(source.basename),
                    source.basename
                )
            }),
            fragment_complete: Some(captured),
            declared_byte_length: captured.then_some(bytes.len() as u64),
            content_sha256: captured.then(|| {
                Sha256::digest(&bytes)
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect()
            }),
        });
        if captured {
            payloads
                .push(SccmClientCapturedPayload::new(artifact_id, bytes).expect("bounded payload"));
        }
    }
    let bundle = SccmClientIntakeBundle {
        artifacts,
        capture_gaps: Vec::new(),
    };
    let assessment = assess_client_intake(&bundle).expect("canonical intake");
    admit_client_evidence(&bundle, &assessment, &payloads).expect("sealed evidence")
}

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sccm/client/inventory-compliance-metering")
}

fn corpus_scenarios() -> Vec<(String, PathBuf)> {
    let mut scenarios = Vec::new();
    for workflow in ["inventory", "compliance", "metering"] {
        let workflow_root = corpus_root().join(workflow);
        for entry in fs::read_dir(&workflow_root).expect("workflow corpus directory") {
            let entry = entry.expect("scenario entry");
            if entry.file_type().expect("scenario type").is_dir() {
                scenarios.push((
                    format!("{workflow}/{}", entry.file_name().to_string_lossy()),
                    entry.path(),
                ));
            }
        }
    }
    scenarios.sort_by(|left, right| left.0.cmp(&right.0));
    scenarios
}

struct CorpusAdmission {
    admitted: cmtraceopen_parser::sccm::client::SccmClientAdmittedEvidence,
    artifact_ids: BTreeMap<String, String>,
}

fn corpus_admitted(scenario_dir: &Path) -> Result<CorpusAdmission, String> {
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(scenario_dir.join("manifest.json")).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let mut artifacts = Vec::new();
    let mut payloads = Vec::new();
    let mut artifact_ids = BTreeMap::new();
    for (index, source) in manifest["artifacts"]
        .as_array()
        .ok_or("manifest artifacts missing")?
        .iter()
        .enumerate()
    {
        let coverage = match source["captureState"].as_str().ok_or("capture state")? {
            "captured" => SccmCoverageState::Captured,
            "absent" => SccmCoverageState::Absent,
            "accessDenied" => SccmCoverageState::AccessDenied,
            "capped" => SccmCoverageState::Capped,
            "skipped" => SccmCoverageState::Skipped,
            "unsupported" => SccmCoverageState::Unsupported,
            "parseFailed" => SccmCoverageState::ParseFailed,
            other => return Err(format!("unsupported coverage {other}")),
        };
        let rotation = match source["rotation"]["kind"].as_str().ok_or("rotation kind")? {
            "current" => SccmRotation::Current,
            "lo" => SccmRotation::LoUnderscore,
            other => return Err(format!("unsupported rotation {other}")),
        };
        let manifest_basename = source["originalBasename"]
            .as_str()
            .ok_or("original basename")?;
        let normalized_rotation_basename = manifest_basename
            .strip_suffix(".log.lo")
            .map(|stem| format!("{stem}.lo_"));
        let basename = normalized_rotation_basename
            .as_deref()
            .unwrap_or(manifest_basename);
        let preparation_group = source["designOnlyCatalog"]["entryId"]
            .as_str()
            .ok_or("source group")?;
        let group = if matches!(basename, "CIAgent.log" | "StateMessage.log") {
            "client-policy-state"
        } else {
            preparation_group
        };
        let fragment_complete = source["rotation"]["fragmentComplete"]
            .as_bool()
            .unwrap_or(false);
        let source_version = source["sourceVersion"].as_str();
        let preparation_artifact_id = source["artifactId"].as_str().unwrap_or_default();
        let artifact_id = format!("fixture-update-numbered-{:02}", index + 1);
        artifact_ids.insert(preparation_artifact_id.to_owned(), artifact_id.clone());
        let payload_bytes = (coverage == SccmCoverageState::Captured && fragment_complete)
            .then(|| {
                let relative_path = source["relativePath"]
                    .as_str()
                    .ok_or("captured relative path")?;
                fs::read(scenario_dir.join(relative_path)).map_err(|error| error.to_string())
            })
            .transpose()?;
        let physical = matches!(
            coverage,
            SccmCoverageState::Captured
                | SccmCoverageState::Capped
                | SccmCoverageState::ParseFailed
        );
        let rotation_segment = if matches!(rotation, SccmRotation::LoUnderscore) {
            "lo"
        } else {
            "current"
        };
        let root_identity = source["sanitizedSourcePath"]
            .as_str()
            .and_then(|path| path.strip_prefix("SYNTHETIC://"))
            .and_then(|path| path.split('/').next())
            .unwrap_or(preparation_artifact_id);
        let root_digest: String = Sha256::digest(root_identity.as_bytes())
            .iter()
            .take(8)
            .map(|byte| format!("{byte:02x}"))
            .collect();
        artifacts.push(SccmClientIntakeArtifact {
            artifact: SccmArtifact {
                artifact_id: artifact_id.clone(),
                display_name: basename.to_owned(),
                original_path: None,
                host: None,
                role: SccmRole::Client,
                configmgr_version: source_version.map(|version| {
                    if version == "5.00.TEST.325" {
                        "5.00.9128.1000".to_owned()
                    } else {
                        version.to_owned()
                    }
                }),
                collected_at_utc: source["capturedUtc"].as_str().map(str::to_owned),
                rotation,
                coverage,
                encoding: source["encoding"].as_str().map(str::to_owned),
            },
            path_fingerprint: Some(format!("synthetic-update-numbered-{:02}", index + 1)),
            rotation_lineage: None,
            relative_path: physical.then(|| {
                format!("evidence/{group}/root-{root_digest}/{rotation_segment}/{basename}")
            }),
            fragment_complete: Some(fragment_complete),
            declared_byte_length: payload_bytes.as_ref().map(|bytes| bytes.len() as u64),
            content_sha256: payload_bytes.as_ref().map(|bytes| {
                Sha256::digest(bytes)
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect()
            }),
        });
        if let Some(bytes) = payload_bytes {
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
    for artifact in &bundle.artifacts {
        assess_client_intake(&SccmClientIntakeBundle {
            artifacts: vec![artifact.clone()],
            capture_gaps: Vec::new(),
        })
        .map_err(|error| format!("{}: {error}", artifact.artifact.artifact_id))?;
    }
    let assessment = assess_client_intake(&bundle).map_err(|error| error.to_string())?;
    let admitted = admit_client_evidence(&bundle, &assessment, &payloads)
        .map_err(|error| error.to_string())?;
    Ok(CorpusAdmission {
        admitted,
        artifact_ids,
    })
}

fn translate_admitted_artifact_ids(
    value: &mut serde_json::Value,
    artifact_ids: &BTreeMap<String, String>,
) {
    match value {
        serde_json::Value::String(text) => {
            let mut translations = artifact_ids.iter().collect::<Vec<_>>();
            translations.sort_by_key(|(_, admitted)| std::cmp::Reverse(admitted.len()));
            for (fixture, admitted) in translations {
                *text = text.replace(admitted, fixture);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                translate_admitted_artifact_ids(value, artifact_ids);
            }
        }
        serde_json::Value::Object(fields) => {
            for value in fields.values_mut() {
                translate_admitted_artifact_ids(value, artifact_ids);
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

fn canonicalize_json(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.into_iter().map(canonicalize_json).collect())
        }
        serde_json::Value::Object(fields) => {
            let mut entries = fields.into_iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            serde_json::Value::Object(
                entries
                    .into_iter()
                    .map(|(key, value)| (key, canonicalize_json(value)))
                    .collect(),
            )
        }
        scalar => scalar,
    }
}

fn production_output_digest(
    analysis: &cmtraceopen_parser::sccm::client::SccmClientExtendedAnalysis,
    artifact_ids: &BTreeMap<String, String>,
) -> String {
    let mut normalized = serde_json::to_value(analysis).expect("serializable production analysis");
    translate_admitted_artifact_ids(&mut normalized, artifact_ids);
    let normalized = canonicalize_json(normalized);
    Sha256::digest(serde_json::to_vec(&normalized).expect("canonical production JSON"))
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn separates_inventory_compliance_and_metering_transactions() {
    let evidence = admitted(vec![
        Source {
            id: "update-a",
            basename: "InventoryAgentProvider.log",
            component: "InventoryAgentProvider",
            coverage: SccmCoverageState::Captured,
            records: vec![("01:00:00.000", "Family=inventory InventoryCycleId=INV-CYCLE-001 ResourceHandle=safe:resource:inventory-001 ReportId=INV-REPORT-001 Phase=Report Disposition=Succeeded Terminal=true")],
        },
        Source {
            id: "update-b",
            basename: "DCMReporting.log",
            component: "DCMReporting",
            coverage: SccmCoverageState::Captured,
            records: vec![("01:00:01.000", "Family=compliance CiId=CI-001 BaselineId=BASELINE-001 StateId=STATE-001 ResourceHandle=safe:resource:compliance-001 Phase=Report Disposition=Succeeded ResultType=Evaluation Terminal=true")],
        },
        Source {
            id: "update-state",
            basename: "StateMessage.log",
            component: "StateMessage",
            coverage: SccmCoverageState::Captured,
            records: vec![("01:00:01.500", "Family=compliance CiId=CI-001 BaselineId=BASELINE-001 StateId=STATE-001 ResourceHandle=safe:resource:compliance-001 Phase=Report Disposition=Succeeded ResultType=Evaluation Terminal=true")],
        },
        Source {
            id: "update-c",
            basename: "SWMTRReportGen.log",
            component: "SWMTRReportGen",
            coverage: SccmCoverageState::Captured,
            records: vec![("01:00:02.000", "Family=metering MeteringCycleId=METER-CYCLE-001 RuleId=RULE-001 ReportId=METER-REPORT-001 ResourceHandle=safe:resource:metering-001 Phase=Report Disposition=Succeeded Terminal=true")],
        },
    ]);

    let result = analyze_client_extended(&evidence).expect("extended analysis");
    assert_eq!(result.transactions.len(), 3);
    assert_eq!(
        result
            .transactions
            .iter()
            .map(|transaction| transaction.workflow)
            .collect::<Vec<_>>(),
        vec![
            SccmClientExtendedWorkflow::Inventory,
            SccmClientExtendedWorkflow::Compliance,
            SccmClientExtendedWorkflow::Metering,
        ]
    );
    assert!(result
        .transactions
        .iter()
        .all(|transaction| transaction.state == SccmClientExtendedState::Succeeded));
    assert!(result
        .transactions
        .iter()
        .all(|transaction| transaction.keys.len() >= 3));
}

#[test]
fn joins_recovery_only_with_the_same_complete_key_tuple_and_ordering() {
    let evidence = admitted(vec![Source {
        id: "update-a",
        basename: "InventoryAgentProvider.log",
        component: "InventoryAgentProvider",
        coverage: SccmCoverageState::Captured,
        records: vec![
            ("02:00:00.000", "InventoryCycleId=INV-CYCLE-002 ResourceHandle=safe:resource:inventory-002 ReportId=INV-REPORT-002 Phase=Report Disposition=Failed Terminal=true"),
            ("02:00:01.000", "InventoryCycleId=INV-CYCLE-002 ResourceHandle=safe:resource:inventory-002 ReportId=INV-REPORT-002 Phase=Report Disposition=Succeeded Terminal=true"),
            ("02:00:02.000", "InventoryCycleId=INV-CYCLE-003 ResourceHandle=safe:resource:inventory-003 ReportId=INV-REPORT-003 Phase=Report Disposition=Failed Terminal=true"),
            ("02:00:02.000", "InventoryCycleId=INV-CYCLE-003 ResourceHandle=safe:resource:inventory-003 ReportId=INV-REPORT-003 Phase=Report Disposition=Succeeded Terminal=true"),
        ],
    }]);

    let result = analyze_client_extended(&evidence).expect("extended analysis");
    assert_eq!(result.transactions.len(), 2);
    assert_eq!(
        result.transactions[0].state,
        SccmClientExtendedState::Recovered
    );
    assert_eq!(
        result.transactions[1].state,
        SccmClientExtendedState::Contradictory
    );
}

#[test]
fn keeps_missing_sources_and_keys_as_explicit_gaps() {
    let evidence = admitted(vec![
        Source {
            id: "absent",
            basename: "CIAgent.log",
            component: "CIAgent",
            coverage: SccmCoverageState::Absent,
            records: Vec::new(),
        },
        Source {
            id: "agent-a",
            basename: "InventoryAgent.log",
            component: "InventoryAgent",
            coverage: SccmCoverageState::Captured,
            records: vec![(
                "03:00:00.000",
                "InventoryCycleId=INV-CYCLE-004 Phase=Collect Disposition=Succeeded Terminal=false",
            )],
        },
    ]);

    let result = analyze_client_extended(&evidence).expect("extended analysis");
    assert!(result.transactions.is_empty());
    assert_eq!(result.coverage.len(), 2);
    assert_eq!(
        result
            .coverage
            .iter()
            .find(|coverage| coverage.source.artifact_id == "fixture-absent")
            .expect("compliance coverage")
            .source
            .coverage,
        SccmCoverageState::Absent
    );
    assert_eq!(result.source_local_observations.len(), 2);
    assert!(result.source_local_observations.iter().any(|observation| {
        observation
            .sources
            .iter()
            .map(|source| source.artifact_id.as_str())
            .collect::<Vec<_>>()
            == ["fixture-absent"]
            && observation.evidence.is_empty()
    }));
    assert!(result.source_local_observations.iter().any(|observation| {
        observation
            .sources
            .iter()
            .map(|source| source.artifact_id.as_str())
            .collect::<Vec<_>>()
            == ["fixture-agent-a"]
            && observation.evidence.len() == 1
    }));
}

#[test]
fn component_spoofing_cannot_cross_the_sealed_physical_source_boundary() {
    let evidence = admitted(vec![Source {
        id: "agent-a",
        basename: "InventoryAgent.log",
        component: "DCMReporting",
        coverage: SccmCoverageState::Captured,
        records: vec![("04:00:00.000", "CiId=CI-001 BaselineId=BASELINE-001 StateId=STATE-001 ResourceHandle=safe:resource:compliance-001 Phase=Report Disposition=Failed Terminal=true")],
    }]);

    let result = analyze_client_extended(&evidence).expect("extended analysis");
    assert!(result.transactions.is_empty());
    assert!(result.findings.is_empty());
}

#[test]
fn all_committed_extended_scenarios_execute_the_exported_analyzer() {
    let scenarios = corpus_scenarios();
    assert_eq!(
        scenarios.len(),
        21,
        "the complete committed corpus executes"
    );

    for (scenario, scenario_dir) in scenarios {
        let expected: serde_json::Value = serde_json::from_slice(
            &fs::read(scenario_dir.join("expected.json")).expect("scenario expected contract"),
        )
        .expect("valid expected contract");
        if scenario == "compliance/malformed-unknown-profile-invalid-offset" {
            match corpus_admitted(&scenario_dir) {
                Ok(_) => panic!("{scenario}: invalid time and unknown profile were admitted"),
                Err(error) => {
                    assert!(
                        expected["productionOutputSha256"].is_null(),
                        "{scenario}: rejected input has no production output"
                    );
                    assert_eq!(
                        expected["productionAdmissionError"].as_str(),
                        Some(error.as_str()),
                        "{scenario}: exact committed admission rejection"
                    );
                }
            }
            continue;
        }
        let corpus = corpus_admitted(&scenario_dir)
            .unwrap_or_else(|error| panic!("{scenario}: sealed corpus admission: {error}"));
        let analysis = analyze_client_extended(&corpus.admitted)
            .unwrap_or_else(|error| panic!("{scenario}: exported analyzer: {error}"));
        let actual = serde_json::to_value(&analysis).expect("serializable production analysis");
        let repeated = serde_json::to_value(
            analyze_client_extended(&corpus.admitted).expect("repeat production analysis"),
        )
        .expect("serializable repeated analysis");
        assert_eq!(actual, repeated, "{scenario}: full output is deterministic");
        assert!(
            expected["productionAdmissionError"].is_null(),
            "{scenario}: admitted input has no admission rejection"
        );
        let actual_digest = production_output_digest(&analysis, &corpus.artifact_ids);
        assert_eq!(
            expected["productionOutputSha256"].as_str(),
            Some(actual_digest.as_str()),
            "{scenario}: complete normalized production output"
        );
        assert_eq!(actual["schemaVersion"], 1, "{scenario}: schema");
        let expected_transactions = expected["transactions"]
            .as_array()
            .expect("expected transactions");
        assert_eq!(
            analysis.transactions.len(),
            expected_transactions.len(),
            "{scenario}: transaction count"
        );

        let mut transaction_ids = std::collections::BTreeSet::new();
        for expected_transaction in expected_transactions {
            let workflow = expected_transaction["workflow"].as_str().expect("workflow");
            let key_labels: &[&str] = match workflow {
                "inventory" => &["InventoryCycleId", "ResourceHandle", "ReportId"],
                "compliance" => &["CiId", "BaselineId", "StateId", "ResourceHandle"],
                "metering" => &["MeteringCycleId", "RuleId", "ReportId", "ResourceHandle"],
                other => panic!("{scenario}: unknown workflow {other}"),
            };
            let expected_values = key_labels
                .iter()
                .map(|label| {
                    expected_transaction["key"][label]
                        .as_str()
                        .expect("key value")
                })
                .collect::<Vec<_>>();
            let transaction = analysis
                .transactions
                .iter()
                .find(|transaction| {
                    transaction
                        .keys
                        .iter()
                        .map(|key| key.normalized.as_str())
                        .collect::<Vec<_>>()
                        == expected_values
                })
                .unwrap_or_else(|| panic!("{scenario}: exact expected key tuple missing"));
            let serialized = serde_json::to_value(transaction).expect("serialized transaction");
            assert_eq!(
                serialized["workflow"].as_str(),
                Some(workflow),
                "{scenario}: workflow"
            );
            assert_eq!(
                serialized["phase"].as_str().map(str::to_ascii_lowercase),
                expected_transaction["phase"]
                    .as_str()
                    .map(str::to_ascii_lowercase),
                "{scenario}: phase"
            );
            assert_eq!(
                serialized["state"].as_str().map(str::to_ascii_lowercase),
                expected_transaction["state"]
                    .as_str()
                    .map(str::to_ascii_lowercase),
                "{scenario}: state"
            );
            assert_eq!(
                transaction.profile_id,
                "sccm-keys-5.00.9128-experimental-v1"
            );
            let discriminator = transaction
                .transaction_id
                .rsplit(':')
                .next()
                .expect("digest");
            assert_eq!(
                discriminator.len(),
                64,
                "{scenario}: full SHA-256 discriminator"
            );
            assert!(discriminator.bytes().all(|byte| byte.is_ascii_hexdigit()));
            assert!(
                transaction_ids.insert(transaction.transaction_id.clone()),
                "{scenario}: unique transaction id"
            );

            let expected_evidence = expected_transaction["evidence"]
                .as_array()
                .expect("expected evidence")
                .iter()
                .map(|reference| {
                    (
                        corpus.artifact_ids[reference["artifactId"].as_str().expect("artifact id")]
                            .as_str(),
                        Some(reference["startLine"].as_u64().expect("start line")),
                        Some(reference["endLine"].as_u64().expect("end line")),
                    )
                })
                .collect::<Vec<_>>();
            let actual_evidence = transaction
                .evidence
                .iter()
                .map(|reference| {
                    (
                        reference.artifact_id.as_str(),
                        reference.line_start.map(u64::from),
                        reference.line_end.map(u64::from),
                    )
                })
                .collect::<Vec<_>>();
            assert_eq!(
                actual_evidence, expected_evidence,
                "{scenario}: exact evidence citations"
            );

            let expected_gap_ids = expected_transaction["coverageGapArtifactIds"]
                .as_array()
                .expect("expected gaps")
                .iter()
                .map(|id| corpus.artifact_ids[id.as_str().expect("gap id")].clone())
                .collect::<Vec<_>>();
            assert_eq!(
                transaction.coverage_gap_artifact_ids, expected_gap_ids,
                "{scenario}: exact phase-source coverage gaps"
            );

            let abnormal = matches!(
                expected_transaction["state"].as_str(),
                Some(
                    "failed"
                        | "evaluatedNonCompliant"
                        | "blockedOrDeferred"
                        | "contradictory"
                        | "insufficientEvidence"
                )
            );
            let finding = analysis
                .findings
                .iter()
                .find(|finding| finding.subject_id == transaction.transaction_id);
            assert_eq!(
                finding.is_some(),
                abnormal,
                "{scenario}: finding presence follows committed expected state"
            );
            if let Some(finding) = finding {
                let request = finding
                    .next_artifact
                    .as_ref()
                    .expect("abnormal outcome has exact next artifact");
                assert_eq!(request.source_basename, transaction.source_basename);
                assert!(!request.logical_artifact_id.is_empty());
                assert!(!request.reason.is_empty());
                if expected_transaction["nextArtifact"].is_object() {
                    assert_eq!(
                        request.logical_artifact_id,
                        expected_transaction["nextArtifact"]["logicalArtifactId"]
                            .as_str()
                            .unwrap()
                    );
                    assert_eq!(
                        request.source_basename,
                        expected_transaction["nextArtifact"]["sourceBasename"]
                            .as_str()
                            .unwrap()
                    );
                    assert_eq!(
                        request.reason,
                        expected_transaction["nextArtifact"]["reason"]
                            .as_str()
                            .unwrap()
                    );
                }
            }
        }

        let mut expected_coverage = expected["coverage"]
            .as_array()
            .expect("expected coverage")
            .iter()
            .map(|item| {
                (
                    corpus.artifact_ids[item["artifactId"].as_str().unwrap()].clone(),
                    item["state"].as_str().unwrap().to_ascii_lowercase(),
                )
            })
            .collect::<Vec<_>>();
        let mut actual_coverage = analysis
            .coverage
            .iter()
            .map(|item| {
                (
                    item.source.artifact_id.clone(),
                    if item.source.coverage == SccmCoverageState::Captured
                        && !item.source.fragment_complete
                    {
                        "partial".to_owned()
                    } else {
                        serde_json::to_value(item.source.coverage.clone())
                            .unwrap()
                            .as_str()
                            .unwrap()
                            .to_ascii_lowercase()
                    },
                )
            })
            .collect::<Vec<_>>();
        expected_coverage.sort();
        actual_coverage.sort();
        assert_eq!(
            actual_coverage, expected_coverage,
            "{scenario}: exact artifact-level coverage"
        );

        let mut expected_observation_ids = expected["sourceLocalObservations"]
            .as_array()
            .expect("expected observations")
            .iter()
            .flat_map(|observation| {
                observation["artifactIds"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|id| corpus.artifact_ids[id.as_str().unwrap()].clone())
            })
            .collect::<Vec<_>>();
        let mut actual_observation_ids = analysis
            .source_local_observations
            .iter()
            .flat_map(|observation| {
                observation
                    .sources
                    .iter()
                    .map(|source| source.artifact_id.clone())
            })
            .collect::<Vec<_>>();
        expected_observation_ids.sort();
        expected_observation_ids.dedup();
        actual_observation_ids.sort();
        actual_observation_ids.dedup();
        assert_eq!(
            actual_observation_ids, expected_observation_ids,
            "{scenario}: source-local observations cite exact sources"
        );
        for observation in &analysis.source_local_observations {
            assert!(
                !observation.sources.is_empty(),
                "{scenario}: source citation"
            );
            assert!(observation.evidence.iter().all(|reference| observation
                .sources
                .iter()
                .any(|source| source.artifact_id == reference.artifact_id)));
        }
        assert_eq!(
            analysis.prohibited_claims,
            [
                "server root cause",
                "time-only cross-artifact causality",
                "native Windows acceptance",
            ]
        );
    }
}

#[test]
fn duplicate_and_case_variant_semantic_labels_are_rejected_as_ambiguous() {
    let evidence = admitted(vec![Source {
        id: "update-a",
        basename: "InventoryAgent.log",
        component: "InventoryAgent",
        coverage: SccmCoverageState::Captured,
        records: vec![(
            "05:00:00.000",
            "InventoryCycleId=INV-DUP-001 inventorycycleid=INV-DUP-002 ResourceHandle=safe:resource:dup ReportId=REPORT-DUP Phase=Collect phase=Report Disposition=Succeeded Terminal=true",
        )],
    }]);

    let analysis = analyze_client_extended(&evidence).expect("extended analysis");
    assert!(analysis.transactions.is_empty());
    assert!(analysis.findings.is_empty());
    assert_eq!(analysis.source_local_observations.len(), 1);
    assert!(analysis.source_local_observations[0]
        .reason
        .contains("repeats a field label"));
    assert_eq!(
        analysis.source_local_observations[0].sources[0].artifact_id,
        "fixture-update-a"
    );
}
