use std::path::{Path, PathBuf};

use cmtraceopen_parser::sccm::server::windows::{
    analyze_hierarchy_replication, declared_server_source_catalog, SccmHierarchyArtifact,
    SccmHierarchyBundle, SccmHierarchyDirection, SccmHierarchyProfileSelectionState,
    SccmHierarchyState, SccmHierarchyTarget, SccmHierarchyTopology, SCCM_HIERARCHY_PROFILE_ID,
    SCCM_HIERARCHY_SOURCE_VERSION,
};
use cmtraceopen_parser::sccm::{
    SccmArtifact, SccmConfidence, SccmCoverageState, SccmFindingClass, SccmRole, SccmRotation,
};
use serde_json::{json, Value};

const SCENARIOS: &[&str] = &[
    "absent-remote-source",
    "backlog-retry",
    "clock-offset-unknown",
    "generic-site-token",
    "healthy-link",
    "incomplete",
    "receiver-processing-failure",
    "recovery",
    "rotation-boundary",
    "sender-failure",
    "topology-mismatch",
];

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sccm/server/hierarchy_and_replication")
}

fn load_bundle(scenario: &str) -> (SccmHierarchyBundle, Value) {
    let root = corpus_root().join(scenario);
    let manifest: Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("manifest.json")).expect("manifest is readable"),
    )
    .expect("manifest is valid JSON");
    let expected: Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("expected.json")).expect("expected output is readable"),
    )
    .expect("expected output is valid JSON");
    let topology = &manifest["topology"];
    let additional_targets = topology["additionalTargets"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|target| SccmHierarchyTarget {
            site_code: required_str(target, "siteCode").to_owned(),
            host_handle: required_str(target, "hostHandle").to_owned(),
        })
        .collect();
    let artifacts = manifest["artifacts"]
        .as_array()
        .expect("artifacts are an array")
        .iter()
        .map(|artifact| {
            let relative_path = artifact["relativePath"].as_str();
            let content = relative_path
                .map(|relative_path| {
                    std::fs::read_to_string(root.join(relative_path))
                        .expect("declared hierarchy payload is readable")
                })
                .unwrap_or_default();
            let rotation = match required_str(&artifact["rotation"], "kind") {
                "current" => SccmRotation::Current,
                "loUnderscore" => SccmRotation::LoUnderscore,
                value => panic!("unexpected hierarchy rotation {value}"),
            };
            let coverage = match required_str(artifact, "captureState") {
                "captured" => SccmCoverageState::Captured,
                "absent" => SccmCoverageState::Absent,
                "accessDenied" => SccmCoverageState::AccessDenied,
                "capped" => SccmCoverageState::Capped,
                "skipped" => SccmCoverageState::Skipped,
                "unsupported" => SccmCoverageState::Unsupported,
                "parseFailed" => SccmCoverageState::ParseFailed,
                value => panic!("unexpected hierarchy coverage {value}"),
            };
            let direction = match required_str(artifact, "direction") {
                "origin" => SccmHierarchyDirection::Origin,
                "target" => SccmHierarchyDirection::Target,
                value => panic!("unexpected hierarchy direction {value}"),
            };
            let producer_host_handle = required_str(artifact, "producerHostHandle").to_owned();
            SccmHierarchyArtifact {
                artifact: SccmArtifact {
                    artifact_id: required_str(artifact, "artifactId").to_owned(),
                    display_name: required_str(artifact, "originalBasename").to_owned(),
                    original_path: None,
                    host: Some(producer_host_handle.clone()),
                    role: SccmRole::SiteServer,
                    configmgr_version: artifact["sourceVersion"].as_str().map(str::to_owned),
                    collected_at_utc: artifact["collectedUtc"].as_str().map(str::to_owned),
                    rotation,
                    coverage,
                    encoding: artifact["encoding"].as_str().map(str::to_owned),
                },
                source_id: required_str(artifact, "sourceId").to_owned(),
                direction,
                producer_host_handle,
                rotation_lineage_id: required_str(&artifact["rotation"], "lineageId").to_owned(),
                fragment_complete: artifact["rotation"]["fragmentComplete"]
                    .as_bool()
                    .unwrap_or(true),
                content,
            }
        })
        .collect();

    (
        SccmHierarchyBundle {
            profile_id: SCCM_HIERARCHY_PROFILE_ID.to_owned(),
            source_version: SCCM_HIERARCHY_SOURCE_VERSION.to_owned(),
            topology: SccmHierarchyTopology {
                origin_site_code: required_str(topology, "originSiteCode").to_owned(),
                target_site_code: required_str(topology, "targetSiteCode").to_owned(),
                origin_host_handle: required_str(topology, "originHostHandle").to_owned(),
                target_host_handle: required_str(topology, "targetHostHandle").to_owned(),
                additional_targets,
            },
            artifacts,
        },
        expected,
    )
}

fn required_str<'a>(value: &'a Value, field: &str) -> &'a str {
    value[field]
        .as_str()
        .unwrap_or_else(|| panic!("{field} is a string"))
}

#[test]
fn every_corpus_scenario_runs_through_the_exported_production_analyzer() {
    for scenario in SCENARIOS {
        let (bundle, expected) = load_bundle(scenario);
        let analysis = analyze_hierarchy_replication(&bundle).expect("topology is accepted");
        assert_eq!(analysis.workflow, "hierarchyAndReplication", "{scenario}");
        assert_eq!(analysis.state_chain.len(), 7, "{scenario}");
        assert_eq!(
            analysis.extraction_profile.selection_state,
            SccmHierarchyProfileSelectionState::SelectedSynthetic,
            "{scenario}"
        );
        assert!(
            analysis.extraction_profile.synthetic_fixture_only,
            "{scenario}"
        );
        assert!(!analysis.native_validation_performed, "{scenario}");
        assert!(analysis.cross_side_causal_claims.is_empty(), "{scenario}");

        assert_eq!(
            coverage_projection(&analysis),
            expected["coverage"],
            "coverage mismatch for {scenario}"
        );
        assert_eq!(
            transaction_projection(&analysis),
            transaction_expectation(&expected),
            "transaction mismatch for {scenario}"
        );
        assert_eq!(
            source_local_projection(&analysis),
            source_local_expectation(&expected),
            "source-local mismatch for {scenario}"
        );
        assert_eq!(
            request_projection(&analysis),
            expected["artifactRequests"],
            "request mismatch for {scenario}"
        );

        for transaction in &analysis.transactions {
            assert_eq!(transaction.producer_role, SccmRole::SiteServer);
            assert_eq!(transaction.source_version, SCCM_HIERARCHY_SOURCE_VERSION);
            assert!(
                transaction.last_successful_phase.is_some()
                    || transaction.state == SccmHierarchyState::Deferred
                    || transaction.state == SccmHierarchyState::Failed
            );
            assert_eq!(
                transaction.next_artifacts,
                analysis
                    .artifact_requests
                    .iter()
                    .filter(|request| request.target_site_code == transaction.key.target_site_code)
                    .cloned()
                    .collect::<Vec<_>>()
            );
            assert!(transaction.observations.iter().all(|observation| {
                !observation.evidence.is_empty()
                    && observation.evidence.iter().all(|reference| {
                        reference.line_start.is_some() && reference.line_end.is_some()
                    })
            }));
        }

        let mut reversed = bundle.clone();
        reversed.artifacts.reverse();
        assert_eq!(
            serde_json::to_value(&analysis).expect("analysis serializes"),
            serde_json::to_value(
                analyze_hierarchy_replication(&reversed).expect("reversed topology is accepted")
            )
            .expect("reversed analysis serializes"),
            "input order changed full output for {scenario}"
        );
    }
}

#[test]
fn framed_hierarchy_grammar_does_not_depend_on_the_synthetic_marker_or_profile_claim() {
    let (mut bundle, _) = load_bundle("healthy-link");
    for artifact in &mut bundle.artifacts {
        artifact.content = artifact
            .content
            .replace("SYNTHETIC FIXTURE; ", "")
            .replace("; ProfileId=hierarchy-server-5.00.test-v1", "");
    }

    let analysis = analyze_hierarchy_replication(&bundle).expect("topology is accepted");
    assert_eq!(analysis.transactions.len(), 1);
    assert_eq!(
        analysis.transactions[0].state,
        SccmHierarchyState::Succeeded
    );
    assert_eq!(analysis.transactions[0].confidence, SccmConfidence::High);
}

#[test]
fn arbitrary_profiles_and_source_versions_fail_closed() {
    let (mut arbitrary_profile, _) = load_bundle("healthy-link");
    arbitrary_profile.profile_id = "caller-attested-profile".to_owned();
    let analysis =
        analyze_hierarchy_replication(&arbitrary_profile).expect("topology remains valid");
    assert!(analysis.transactions.is_empty());
    assert_eq!(
        analysis.extraction_profile.selection_state,
        SccmHierarchyProfileSelectionState::Unavailable
    );
    assert!(analysis
        .source_local_observations
        .iter()
        .all(|observation| observation.reason_code == "unvalidatedProfile"));

    let (mut unknown_version, _) = load_bundle("healthy-link");
    unknown_version.source_version = "5.00.UNKNOWN.0001".to_owned();
    let analysis = analyze_hierarchy_replication(&unknown_version).expect("topology remains valid");
    assert!(analysis.transactions.is_empty());
    assert_eq!(
        analysis.extraction_profile.selection_state,
        SccmHierarchyProfileSelectionState::Unavailable
    );
}

#[test]
fn exact_message_and_link_kinds_reject_content_like_or_partial_values() {
    let (mut bundle, _) = load_bundle("sender-failure");
    bundle.artifacts[0].content = bundle.artifacts[0]
        .content
        .replace("MessageId=msg-send-chd", "MessageId=content-chd")
        .replace("LinkId=link-lab-sec", "LinkId=content-lab-sec");
    let analysis = analyze_hierarchy_replication(&bundle).expect("topology is accepted");
    assert!(analysis.transactions.is_empty());
    assert!(analysis
        .source_local_observations
        .iter()
        .all(|observation| !observation.correlation_eligible));
}

#[test]
fn terminal_and_remote_causality_are_conservative() {
    let (sender, _) = load_bundle("sender-failure");
    let sender = analyze_hierarchy_replication(&sender).expect("topology is accepted");
    assert!(sender.transactions.iter().all(|transaction| {
        transaction.state == SccmHierarchyState::Failed
            && transaction.finding_class == Some(SccmFindingClass::ConfirmedFailure)
            && !transaction.correlation_eligible
    }));

    let (mut receiver, _) = load_bundle("receiver-processing-failure");
    let despool = receiver
        .artifacts
        .iter_mut()
        .find(|artifact| artifact.artifact.display_name == "despool.log")
        .expect("despool artifact exists");
    despool.content = despool
        .content
        .lines()
        .next()
        .expect("receiver fact exists")
        .replace(
            "Disposition=succeeded; Terminal=false",
            "Disposition=failed; Terminal=true",
        );
    let receiver = analyze_hierarchy_replication(&receiver).expect("topology is accepted");
    assert_eq!(receiver.transactions[0].state, SccmHierarchyState::Failed);
    assert_eq!(receiver.transactions[0].confidence, SccmConfidence::High);
    assert_eq!(
        receiver.transactions[0].finding_class,
        Some(SccmFindingClass::ConfirmedFailure)
    );

    for scenario in ["healthy-link", "receiver-processing-failure", "recovery"] {
        let (bundle, _) = load_bundle(scenario);
        let analysis = analyze_hierarchy_replication(&bundle).expect("topology is accepted");
        assert!(analysis
            .transactions
            .iter()
            .all(|transaction| transaction.correlation_eligible));
    }
}

#[test]
fn contradiction_malformed_grammar_and_topology_mutations_fail_closed() {
    let (mut contradictory, _) = load_bundle("healthy-link");
    let sender = contradictory
        .artifacts
        .iter_mut()
        .find(|artifact| artifact.artifact.display_name == "sender.log")
        .expect("sender artifact exists");
    let failed = sender
        .content
        .replace(
            "Disposition=succeeded; Terminal=false",
            "Disposition=failed; Terminal=true",
        )
        .replace("15:03:02.000+000", "15:03:02.500+000");
    sender.content = format!("{}\n{failed}", sender.content);
    let analysis = analyze_hierarchy_replication(&contradictory).expect("topology is accepted");
    assert_eq!(
        analysis.transactions[0].state,
        SccmHierarchyState::Contradictory
    );
    assert_eq!(analysis.transactions[0].confidence, SccmConfidence::Low);
    assert!(!analysis.transactions[0].correlation_eligible);

    let (mut malformed, _) = load_bundle("sender-failure");
    malformed.artifacts[0].content = malformed.artifacts[0]
        .content
        .replace("MessageId=msg-", "MessageId=msg/");
    let analysis = analyze_hierarchy_replication(&malformed).expect("topology is accepted");
    assert!(analysis.transactions.is_empty());
    assert!(analysis
        .source_local_observations
        .iter()
        .all(|observation| !observation.correlation_eligible));

    let (mut wrong_role, _) = load_bundle("healthy-link");
    for artifact in &mut wrong_role.artifacts {
        artifact.artifact.role = SccmRole::ManagementPoint;
    }
    assert!(analyze_hierarchy_replication(&wrong_role)
        .expect("topology is accepted")
        .transactions
        .is_empty());

    let (mut wrong_host, _) = load_bundle("receiver-processing-failure");
    wrong_host.artifacts[1].producer_host_handle = wrong_host.topology.origin_host_handle.clone();
    let analysis = analyze_hierarchy_replication(&wrong_host).expect("topology is accepted");
    assert!(analysis.transactions.iter().all(|transaction| {
        transaction.state == SccmHierarchyState::Incomplete && !transaction.correlation_eligible
    }));

    let (mut artifact_versions, _) = load_bundle("healthy-link");
    for artifact in &mut artifact_versions.artifacts {
        artifact.artifact.configmgr_version = Some("5.00.UNKNOWN.0001".to_owned());
    }
    let analysis = analyze_hierarchy_replication(&artifact_versions).expect("topology is accepted");
    assert!(analysis.transactions.is_empty());
    assert!(analysis
        .source_local_observations
        .iter()
        .all(|observation| observation.reason_code == "unvalidatedProfile"));
}

#[test]
fn hierarchy_sources_live_in_the_canonical_server_windows_catalog() {
    let hierarchy = declared_server_source_catalog()
        .iter()
        .filter(|spec| spec.source_id.starts_with("server-hierarchy-"))
        .collect::<Vec<_>>();
    assert_eq!(hierarchy.len(), 2);
    assert!(hierarchy.iter().all(|spec| {
        spec.producer_role == SccmRole::SiteServer
            && spec.workflow_subject_role.is_none()
            && !spec.supplemental
    }));
    assert_eq!(hierarchy[0].logical_names, ["replmgr", "rcmctrl"]);
    assert_eq!(hierarchy[1].logical_names, ["sender", "despool"]);
}

fn coverage_projection(
    analysis: &cmtraceopen_parser::sccm::server::windows::SccmHierarchyAnalysis,
) -> Value {
    Value::Array(
        analysis
            .coverage
            .iter()
            .map(|coverage| {
                json!({
                    "artifactId": coverage.artifact_id,
                    "state": serde_json::to_value(coverage.state.clone()).expect("state serializes"),
                })
            })
            .collect(),
    )
}

fn transaction_projection(
    analysis: &cmtraceopen_parser::sccm::server::windows::SccmHierarchyAnalysis,
) -> Value {
    Value::Array(
        analysis
            .transactions
            .iter()
            .map(|transaction| {
                json!({
                    "transactionId": transaction.transaction_id,
                    "key": transaction.key,
                    "topologyCompatibility": transaction.topology_compatibility,
                    "timestampOrdering": transaction.timestamp_ordering,
                    "terminalEvidence": transaction.terminal_evidence,
                    "state": transaction.state,
                    "classification": classification(transaction),
                    "confidence": confidence_name(transaction.confidence),
                    "confidenceCeiling": confidence_name(transaction.confidence_ceiling),
                    "coverageGapArtifactIds": transaction.coverage_gap_artifact_ids,
                    "observations": transaction.observations.iter().map(|observation| json!({
                        "phase": observation.phase,
                        "disposition": observation.disposition,
                        "terminal": observation.terminal,
                        "evidence": observation.evidence.iter().map(|reference| json!({
                            "artifactId": reference.artifact_id,
                            "startLine": reference.line_start,
                            "endLine": reference.line_end,
                        })).collect::<Vec<_>>(),
                    })).collect::<Vec<_>>(),
                })
            })
            .collect(),
    )
}

fn transaction_expectation(expected: &Value) -> Value {
    Value::Array(
        expected["transactions"]
            .as_array()
            .expect("transactions are an array")
            .iter()
            .map(|transaction| {
                json!({
                    "transactionId": transaction["transactionId"],
                    "key": transaction["key"],
                    "topologyCompatibility": transaction["topologyCompatibility"],
                    "timestampOrdering": transaction["timestampOrdering"],
                    "terminalEvidence": transaction["terminalEvidence"],
                    "state": transaction["state"],
                    "classification": transaction["classification"],
                    "confidence": transaction["confidence"],
                    "confidenceCeiling": transaction["confidenceCeiling"],
                    "coverageGapArtifactIds": transaction["coverageGapArtifactIds"],
                    "observations": transaction["observations"].as_array().expect("observations are an array").iter().map(|observation| json!({
                        "phase": observation["phase"],
                        "disposition": observation["disposition"],
                        "terminal": observation["terminal"],
                        "evidence": observation["evidence"],
                    })).collect::<Vec<_>>(),
                })
            })
            .collect(),
    )
}

fn classification(
    transaction: &cmtraceopen_parser::sccm::server::windows::SccmHierarchyTransaction,
) -> &'static str {
    match transaction.state {
        SccmHierarchyState::Succeeded | SccmHierarchyState::Recovered => "success",
        SccmHierarchyState::Failed => "confirmedFailure",
        SccmHierarchyState::Deferred => "blockedOrDeferred",
        SccmHierarchyState::Incomplete => "insufficientEvidence",
        SccmHierarchyState::Contradictory => "contradictoryEvidence",
    }
}

fn confidence_name(confidence: SccmConfidence) -> &'static str {
    match confidence {
        SccmConfidence::None => "none",
        SccmConfidence::Low => "low",
        SccmConfidence::Moderate => "medium",
        SccmConfidence::High => "high",
    }
}

fn source_local_projection(
    analysis: &cmtraceopen_parser::sccm::server::windows::SccmHierarchyAnalysis,
) -> Value {
    Value::Array(
        analysis
            .source_local_observations
            .iter()
            .map(|observation| {
                json!({
                    "classification": match observation.reason_code.as_str() {
                        "rotationSplit" => "rotationSplit",
                        "topologyOrGrammarMismatch" | "unlinkedTopologyCandidate" | "topologyMismatch" => "topologyMismatch",
                        _ => "coverageOnly",
                    },
                    "confidence": confidence_name(observation.confidence),
                    "correlationEligible": observation.correlation_eligible,
                    "artifactIds": observation.artifact_ids,
                    "evidence": observation.evidence.iter().map(|reference| json!({
                        "artifactId": reference.artifact_id,
                        "startLine": reference.line_start,
                        "endLine": reference.line_end,
                    })).collect::<Vec<_>>(),
                })
            })
            .collect(),
    )
}

fn source_local_expectation(expected: &Value) -> Value {
    Value::Array(
        expected["sourceLocalObservations"]
            .as_array()
            .expect("source-local observations are an array")
            .iter()
            .map(|observation| {
                json!({
                    "classification": observation["classification"],
                    "confidence": observation["confidence"],
                    "correlationEligible": observation["correlationEligible"],
                    "artifactIds": observation["artifactIds"],
                    "evidence": observation["evidence"],
                })
            })
            .collect(),
    )
}

fn request_projection(
    analysis: &cmtraceopen_parser::sccm::server::windows::SccmHierarchyAnalysis,
) -> Value {
    serde_json::to_value(&analysis.artifact_requests).expect("requests serialize")
}
