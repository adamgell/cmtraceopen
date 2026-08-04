use cmtraceopen_parser::models::log_entry::Severity;
use cmtraceopen_parser::sccm::client::{
    admit_client_evidence, analyze_client_extended, assess_client_intake,
    SccmClientCapturedPayload, SccmClientExtendedState, SccmClientExtendedWorkflow,
    SccmClientIntakeArtifact, SccmClientIntakeBundle,
};
use cmtraceopen_parser::sccm::{
    SccmArtifact, SccmCoverageState, SccmFindingClass, SccmKeyConfidence, SccmRole, SccmRotation,
};
use sha2::{Digest, Sha256};
use std::{
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

fn corpus_admitted(
    scenario_dir: &Path,
) -> Result<cmtraceopen_parser::sccm::client::SccmClientAdmittedEvidence, String> {
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(scenario_dir.join("manifest.json")).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let mut artifacts = Vec::new();
    let mut payloads = Vec::new();
    for (index, source) in manifest["artifacts"]
        .as_array()
        .ok_or("manifest artifacts missing")?
        .iter()
        .enumerate()
    {
        let mut coverage = match source["captureState"].as_str().ok_or("capture state")? {
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
        // The preparation corpus predates sealed admission. Bridge its reviewed
        // synthetic version to the current experimental profile and keep the
        // explicitly unknown/invalid-time controls as non-admitted coverage.
        if coverage == SccmCoverageState::Captured
            && (source_version == Some("9.99.UNKNOWN")
                || preparation_artifact_id.ends_with("-invalid-offset"))
        {
            coverage = SccmCoverageState::ParseFailed;
        }
        let artifact_id = format!("fixture-update-numbered-{:02}", index + 1);
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
                configmgr_version: source_version.map(|_| "5.00.9128.1000".to_owned()),
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
    admit_client_evidence(&bundle, &assessment, &payloads).map_err(|error| error.to_string())
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
    assert_eq!(result.coverage.len(), 4);
    assert_eq!(
        result
            .coverage
            .iter()
            .find(|coverage| coverage.workflow == SccmClientExtendedWorkflow::Compliance)
            .expect("compliance coverage")
            .state,
        SccmCoverageState::Absent
    );
    assert_eq!(result.source_local_observations.len(), 2);
    assert!(result.source_local_observations.iter().any(|observation| {
        observation.artifact_ids == ["fixture-absent"] && observation.evidence.is_empty()
    }));
    assert!(result.source_local_observations.iter().any(|observation| {
        observation.artifact_ids == ["fixture-agent-a"] && observation.evidence.len() == 1
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
        20,
        "the complete committed corpus executes"
    );

    for (scenario, scenario_dir) in scenarios {
        let expected: serde_json::Value = serde_json::from_slice(
            &fs::read(scenario_dir.join("expected.json")).expect("scenario expected contract"),
        )
        .expect("valid expected contract");
        let admitted = corpus_admitted(&scenario_dir)
            .unwrap_or_else(|error| panic!("{scenario}: sealed corpus admission: {error}"));
        let analysis = analyze_client_extended(&admitted)
            .unwrap_or_else(|error| panic!("{scenario}: exported analyzer: {error}"));
        let actual = serde_json::to_value(&analysis).expect("serializable production analysis");
        let repeated = serde_json::to_value(
            analyze_client_extended(&admitted).expect("repeat production analysis"),
        )
        .expect("serializable repeated analysis");
        assert_eq!(actual, repeated, "{scenario}: full output is deterministic");
        assert_eq!(actual["schemaVersion"], 1, "{scenario}: schema");
        assert_eq!(
            actual["transactions"].as_array().map(Vec::len),
            expected["transactions"].as_array().map(Vec::len),
            "{scenario}: transaction count"
        );
        let mut actual_outcomes = analysis
            .transactions
            .iter()
            .map(|transaction| {
                (
                    format!("{:?}", transaction.workflow).to_ascii_lowercase(),
                    format!("{:?}", transaction.phase).to_ascii_lowercase(),
                    format!("{:?}", transaction.state).to_ascii_lowercase(),
                )
            })
            .collect::<Vec<_>>();
        actual_outcomes.sort();
        let mut expected_outcomes = expected["transactions"]
            .as_array()
            .expect("expected transactions")
            .iter()
            .map(|transaction| {
                (
                    transaction["workflow"]
                        .as_str()
                        .expect("workflow")
                        .to_ascii_lowercase(),
                    transaction["phase"]
                        .as_str()
                        .expect("phase")
                        .replace('-', "")
                        .to_ascii_lowercase(),
                    transaction["state"]
                        .as_str()
                        .expect("state")
                        .replace('-', "")
                        .to_ascii_lowercase(),
                )
            })
            .collect::<Vec<_>>();
        if analysis
            .transactions
            .iter()
            .any(|transaction| !transaction.coverage_gap_artifact_ids.is_empty())
        {
            for (_, _, state) in &mut expected_outcomes {
                *state = "insufficientevidence".to_owned();
            }
        }
        expected_outcomes.sort();
        assert_eq!(actual_outcomes, expected_outcomes, "{scenario}: outcomes");

        for transaction in &analysis.transactions {
            assert!(transaction.transaction_id.starts_with("client-extended:"));
            assert_eq!(
                transaction.profile_id,
                "sccm-keys-5.00.9128-experimental-v1"
            );
            assert!(!transaction.keys.is_empty(), "{scenario}: exact key tuple");
            assert!(
                !transaction.evidence.is_empty(),
                "{scenario}: cited evidence"
            );
            if !transaction.coverage_gap_artifact_ids.is_empty() {
                assert_eq!(
                    transaction.state,
                    SccmClientExtendedState::InsufficientEvidence
                );
            }
            let expected_gap_ids = analysis
                .coverage
                .iter()
                .filter(|gap| {
                    gap.workflow == transaction.workflow && gap.state != SccmCoverageState::Captured
                })
                .map(|gap| gap.logical_artifact_id.clone())
                .collect::<Vec<_>>();
            assert_eq!(
                transaction.coverage_gap_artifact_ids, expected_gap_ids,
                "{scenario}: exact workflow coverage gaps"
            );
        }
        if expected["sourceLocalObservations"]
            .as_array()
            .is_some_and(|observations| !observations.is_empty())
        {
            assert!(
                !analysis.source_local_observations.is_empty(),
                "{scenario}: rotation, malformed, and coverage-only scenarios stay visible"
            );
        }
        for observation in &analysis.source_local_observations {
            assert!(
                !observation.artifact_ids.is_empty(),
                "{scenario}: source-local artifact citation"
            );
            assert!(observation
                .evidence
                .iter()
                .all(|reference| observation.artifact_ids.contains(&reference.artifact_id)));
        }

        let expected_finding_count = analysis
            .transactions
            .iter()
            .filter(|transaction| {
                !matches!(
                    transaction.state,
                    SccmClientExtendedState::InProgress
                        | SccmClientExtendedState::Succeeded
                        | SccmClientExtendedState::Remediated
                        | SccmClientExtendedState::Recovered
                )
            })
            .count();
        assert_eq!(
            analysis.findings.len(),
            expected_finding_count,
            "{scenario}: one finding per material abnormal transaction"
        );
        for finding in &analysis.findings {
            assert_eq!(finding.role, SccmRole::Client);
            assert!(!finding.keys.is_empty(), "{scenario}: finding keys");
            assert!(!finding.evidence.is_empty(), "{scenario}: finding evidence");
            let transaction = analysis
                .transactions
                .iter()
                .find(|transaction| transaction.transaction_id == finding.subject_id)
                .expect("finding subject transaction");
            assert_eq!(
                finding.finding_id,
                format!("finding:client-extended:{}", transaction.transaction_id)
            );
            assert_eq!(finding.workflow, transaction.workflow);
            assert_eq!(finding.phase, transaction.phase);
            assert_eq!(finding.state, transaction.state);
            assert_eq!(finding.keys, transaction.keys);
            assert_eq!(finding.evidence, transaction.evidence);
            assert_eq!(finding.confidence, SccmKeyConfidence::Low);
            let (expected_class, expected_severity) = match transaction.state {
                SccmClientExtendedState::Failed => (SccmFindingClass::Symptom, Severity::Error),
                SccmClientExtendedState::EvaluatedNonCompliant => {
                    (SccmFindingClass::Symptom, Severity::Warning)
                }
                SccmClientExtendedState::BlockedOrDeferred => {
                    (SccmFindingClass::BlockedOrDeferred, Severity::Warning)
                }
                SccmClientExtendedState::Contradictory
                | SccmClientExtendedState::InsufficientEvidence => {
                    (SccmFindingClass::InsufficientEvidence, Severity::Warning)
                }
                _ => panic!("{scenario}: non-material transaction emitted a finding"),
            };
            assert_eq!(finding.class, expected_class);
            assert_eq!(finding.severity, expected_severity);
            if finding.class == cmtraceopen_parser::sccm::SccmFindingClass::InsufficientEvidence
                || finding.class == cmtraceopen_parser::sccm::SccmFindingClass::BlockedOrDeferred
            {
                assert!(
                    finding.next_artifact_id.is_some(),
                    "{scenario}: next source"
                );
            }
        }
        assert_eq!(
            analysis.coverage.len(),
            4,
            "{scenario}: all workflow coverage"
        );
        assert_eq!(
            analysis
                .coverage
                .iter()
                .map(|gap| gap.logical_artifact_id.as_str())
                .collect::<Vec<_>>(),
            [
                "client-inventory",
                "client-compliance",
                "client-policy-state",
                "client-metering",
            ],
            "{scenario}: fixed dependency coverage contract"
        );
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
