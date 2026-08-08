use super::*;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OracleMatrix {
    schema_version: String,
    pair: String,
    scenarios: Vec<OracleScenario>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OracleScenario {
    scenario_id: String,
    mutation: OracleMutation,
    expected_outcome: String,
    expected_link_strength: String,
    expected_confidence: String,
    expected_reason_codes: Vec<String>,
    expected_triggered_guards: Vec<String>,
    expected_output_sha256: String,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase")]
enum OracleMutation {
    ConflictingExactKey,
    Healthy,
    IncompatibleTopology,
    InvalidTimestampOffset,
    MissingClientCounterpart,
    MissingServerCounterpart,
    PartialCapture,
    RedactionBoundary,
    ReorderedInputA,
    ReorderedInputB,
    RotationSplit,
    SameTimeNoKey,
    UnknownExtractionProfile,
    UnrelatedTerminalError,
    VersionMismatch,
}

fn fact(key: &str, topology: &str, time: Option<i64>, terminal: bool) -> CanonicalFact {
    CanonicalFact {
        exact_key: key.to_owned(),
        topology: topology.to_owned(),
        utc_millis: time,
        ordering_usable: time.is_some(),
        terminal_failure: terminal,
        stable_source: format!("source-{key}-{topology}-{time:?}-{terminal}"),
    }
}

fn evidence_ref(id: &str) -> crate::sccm::SccmEvidenceRef {
    crate::sccm::SccmEvidenceRef {
        artifact_id: format!("artifact-{id}"),
        entry_id: format!("entry-{id}"),
        line_start: Some(1),
        line_end: Some(1),
    }
}

fn timestamp(utc_millis: i64) -> crate::sccm::SccmTimestamp {
    crate::sccm::SccmTimestamp {
        original_display: Some("01-01-1970 00:00:00.100+000".to_owned()),
        offset_minutes: Some(0),
        utc_millis: Some(utc_millis),
        ordering_state: SccmTimeOrderingState::NormalizedUtc,
    }
}

fn healthy(pair: SccmCorrelationPair) -> CanonicalInput {
    CanonicalInput {
        pair,
        client_facts: vec![fact("key=one", "topology=one", Some(100), false)],
        server_facts: vec![fact("key=one", "topology=one", Some(200), true)],
        client_profile: ProfileAuthority::Validated,
        server_profile: ProfileAuthority::Validated,
        client_coverage_complete: true,
        server_coverage_complete: true,
        client_rotation_complete: true,
        server_rotation_complete: true,
        input_capped: false,
    }
    .normalize()
}

fn apply_mutation(mut input: CanonicalInput, mutation: OracleMutation) -> CanonicalInput {
    match mutation {
        OracleMutation::Healthy => {}
        OracleMutation::ConflictingExactKey => {
            input.server_facts[0].exact_key = "key=other".to_owned();
            input.server_facts[0].utc_millis = Some(300);
            input.server_facts[0].terminal_failure = false;
        }
        OracleMutation::IncompatibleTopology => {
            input.server_facts[0].topology = "topology=other".to_owned();
        }
        OracleMutation::InvalidTimestampOffset => {
            input.server_facts[0].ordering_usable = false;
            input.server_facts[0].utc_millis = None;
        }
        OracleMutation::MissingClientCounterpart => input.client_facts.clear(),
        OracleMutation::MissingServerCounterpart => input.server_facts.clear(),
        OracleMutation::PartialCapture => input.server_coverage_complete = false,
        OracleMutation::RedactionBoundary => {
            input.client_facts[0].stable_source =
                r"C:\Windows\CCM\Logs\PolicyAgent.log|LAB\SyntheticUser|Bearer secret-token"
                    .to_owned();
            input.server_facts[0].stable_source = "mp01.contoso.example".to_owned();
        }
        OracleMutation::ReorderedInputA | OracleMutation::ReorderedInputB => {
            input
                .client_facts
                .push(fact("key=two", "topology=two", Some(300), false));
            input
                .server_facts
                .push(fact("key=two", "topology=two", Some(400), true));
            if matches!(mutation, OracleMutation::ReorderedInputB) {
                input.client_facts.reverse();
                input.server_facts.reverse();
            }
        }
        OracleMutation::RotationSplit => input.client_rotation_complete = false,
        OracleMutation::SameTimeNoKey => {
            input.server_facts[0].exact_key = "key=other".to_owned();
            input.server_facts[0].utc_millis = Some(100);
            input.server_facts[0].terminal_failure = false;
        }
        OracleMutation::UnknownExtractionProfile => {
            input.client_profile = ProfileAuthority::Unknown;
        }
        OracleMutation::UnrelatedTerminalError => {
            input.server_facts[0].exact_key = "key=other".to_owned();
            input.server_facts[0].utc_millis = Some(300);
        }
        OracleMutation::VersionMismatch => {
            input.server_profile = ProfileAuthority::VersionMismatch;
        }
    }
    input.normalize()
}

fn pair_from_fixture(value: &str) -> SccmCorrelationPair {
    match value {
        "contentDistributionPoint" => SccmCorrelationPair::ContentDistributionPoint,
        "policyManagementPoint" => SccmCorrelationPair::PolicyManagementPoint,
        "updatesSoftwareUpdatePoint" => SccmCorrelationPair::UpdatesSoftwareUpdatePoint,
        other => panic!("unknown oracle pair {other}"),
    }
}

fn run_oracle_matrix(path: &str) {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sccm/correlation");
    let bytes = std::fs::read(root.join(path)).expect("correlation oracle is readable");
    let matrix: OracleMatrix = serde_json::from_slice(&bytes).expect("typed oracle JSON");
    assert_eq!(matrix.schema_version, "1.0.0");
    let pair = pair_from_fixture(&matrix.pair);
    assert_eq!(matrix.scenarios.len(), 15, "{path}");
    let mut scenario_ids = BTreeSet::new();
    for scenario in matrix.scenarios {
        assert!(
            scenario_ids.insert(scenario.scenario_id.clone()),
            "{}: duplicate scenario {}",
            path,
            scenario.scenario_id
        );
        let input = apply_mutation(healthy(pair), scenario.mutation);
        let analysis = correlate(&input);
        let output = serde_json::to_vec(&analysis).expect("analysis serializes");
        let output_hash = sha256_hex(&output);
        assert_eq!(
            output_hash,
            scenario.expected_output_sha256,
            "{}:{} exact output hash; actual JSON: {}",
            path,
            scenario.scenario_id,
            String::from_utf8_lossy(&output)
        );
        let value = serde_json::to_value(&analysis).expect("analysis is JSON");
        let first = &value["results"][0];
        assert_eq!(
            first["outcome"], scenario.expected_outcome,
            "{}",
            scenario.scenario_id
        );
        assert_eq!(
            first["linkStrength"], scenario.expected_link_strength,
            "{}",
            scenario.scenario_id
        );
        assert_eq!(
            first["confidence"], scenario.expected_confidence,
            "{}",
            scenario.scenario_id
        );
        let reasons = first["reasonCodes"]
            .as_array()
            .expect("reason codes")
            .iter()
            .map(|reason| reason.as_str().expect("reason string").to_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            reasons, scenario.expected_reason_codes,
            "{}",
            scenario.scenario_id
        );
        let triggered = first["guardChecks"]
            .as_array()
            .expect("guard checks")
            .iter()
            .filter(|check| check["state"] == "triggered")
            .map(|check| check["guardId"].as_str().expect("guard ID").to_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            triggered, scenario.expected_triggered_guards,
            "{}",
            scenario.scenario_id
        );
        let serialized = String::from_utf8(output).expect("JSON is UTF-8");
        for marker in [
            r"C:\Windows\CCM\Logs",
            "mp01.contoso.example",
            r"LAB\SyntheticUser",
            "secret-token",
        ] {
            assert!(
                !serialized.contains(marker),
                "{} leaked {marker}",
                scenario.scenario_id
            );
        }
    }
}

#[test]
fn healthy_exact_link_requires_every_gate() {
    for pair in [
        SccmCorrelationPair::ContentDistributionPoint,
        SccmCorrelationPair::PolicyManagementPoint,
        SccmCorrelationPair::UpdatesSoftwareUpdatePoint,
    ] {
        let analysis = correlate(&healthy(pair));
        assert_eq!(analysis.results.len(), 1);
        let result = &analysis.results[0];
        assert_eq!(result.outcome, SccmCorrelationOutcome::CausalFinding);
        assert_eq!(
            result.link_strength,
            SccmCorrelationLinkStrength::ExactCorroborated
        );
        assert_eq!(result.confidence, SccmCorrelationConfidence::High);
        assert!(result.reason_codes.is_empty());
        assert!(result
            .guard_checks
            .iter()
            .all(|check| check.state == SccmCorrelationGuardState::Passed));
    }
}

#[test]
fn all_three_public_adapters_can_emit_an_exact_corroborated_link() {
    let policy_ref = evidence_ref("policy");
    let policy = crate::sccm::SccmPolicyAnalysis {
        workflow: "policy".to_owned(),
        state_chain: Vec::new(),
        extraction_profile: crate::sccm::SccmPolicyExtractionProfile {
            selection_state: SccmPolicyProfileSelectionState::Selected,
            profile_id: Some(SCCM_POLICY_KEY_PROFILE_ID.to_owned()),
            synthetic_fixture_only: true,
        },
        coverage: vec![crate::sccm::SccmPolicyCoverage {
            logical_artifact_id: "client-policy-agent".to_owned(),
            state: SccmCoverageState::Captured,
            artifact_ids: vec!["artifact-policy".to_owned()],
        }],
        profile_gaps: Vec::new(),
        transactions: vec![crate::sccm::SccmPolicyTransaction {
            transaction_id: "policy-transaction".to_owned(),
            key: crate::sccm::SccmPolicyTransactionKey {
                assignment_id: "assignment-safe".to_owned(),
                policy_id: "policy-safe".to_owned(),
                request_id: Some("request-safe".to_owned()),
                extraction_profile_id: SCCM_POLICY_KEY_PROFILE_ID.to_owned(),
            },
            phase: crate::sccm::SccmPolicyPhase::Request,
            state: SccmPolicyState::Failed,
            classification: crate::sccm::SccmPolicyClassification::ConfirmedFailure,
            condition: Some(crate::sccm::SccmPolicyCondition::ProcessingFailure),
            last_confirmed_phase: None,
            confidence: crate::sccm::SccmConfidence::High,
            correlation_keys: vec![crate::sccm::SccmCorrelationKey {
                kind: SccmCorrelationKeyKind::SiteCode,
                raw: "LAB".to_owned(),
                normalized: "LAB".to_owned(),
                confidence: SccmKeyConfidence::Exact,
                extraction_profile_id: Some(SCCM_POLICY_KEY_PROFILE_ID.to_owned()),
                evidence: Some(policy_ref.clone()),
                start: Some(0),
                end: Some(3),
            }],
            observations: vec![crate::sccm::SccmPolicyObservation {
                observation_id: "policy-observation".to_owned(),
                phase: crate::sccm::SccmPolicyPhase::Request,
                outcome: crate::sccm::SccmPolicyObservationOutcome::Failed,
                terminal: true,
                timestamp: timestamp(100),
                evidence: policy_ref.clone(),
            }],
            evidence: vec![policy_ref.clone()],
            coverage_gaps: Vec::new(),
            next_artifacts: Vec::new(),
        }],
        source_local_observations: Vec::new(),
        findings: Vec::new(),
        artifact_requests: Vec::new(),
        cross_source_correlation_performed: false,
        time_only_causality_allowed: false,
    };
    let management_point = crate::sccm::server::windows::SccmManagementPointAnalysis {
        schema_version: 1,
        workflow: crate::sccm::server::windows::SccmServerWorkflow::ManagementPoint,
        state_chain: Vec::new(),
        transactions: Vec::new(),
        source_local_observations: Vec::new(),
        findings: Vec::new(),
        coverage_gaps: Vec::new(),
        artifact_requests: Vec::new(),
        counterpart_ready_facts: vec![
            crate::sccm::server::windows::SccmManagementPointCounterpartReadyFact {
                transaction_id: "mp-transaction".to_owned(),
                key: crate::sccm::server::windows::SccmManagementPointKey {
                    request_id: "request-safe".to_owned(),
                    policy_id: Some("policy-safe".to_owned()),
                    client_handle: "client-safe".to_owned(),
                    site_code: "LAB".to_owned(),
                    management_point_host_handle: "mp-safe".to_owned(),
                    confidence: SccmKeyConfidence::Exact,
                    extraction_profile_id: SCCM_MANAGEMENT_POINT_TEST_PROFILE_ID.to_owned(),
                },
                phase: crate::sccm::server::windows::SccmManagementPointPhase::Respond,
                state: SccmManagementPointState::Failed,
                classification:
                    crate::sccm::server::windows::SccmManagementPointClassification::ConfirmedFailure,
                confidence:
                    crate::sccm::server::windows::SccmManagementPointConfidence::High,
                timestamp: timestamp(200),
                evidence: evidence_ref("mp"),
                terminal_evidence: Some(evidence_ref("mp-terminal")),
            },
        ],
        cross_side_correlation_performed: false,
    };

    let content_ref = evidence_ref("content");
    let deployment = crate::sccm::SccmDeploymentAnalysis {
        schema_version: 1,
        workflow: crate::sccm::SccmDeploymentWorkflow::Deployment,
        extraction_profile: crate::sccm::SccmDeploymentExtractionProfile {
            selection_state: SccmDeploymentProfileSelectionState::Selected,
            profile_id: SCCM_DEPLOYMENT_PROFILE_ID.to_owned(),
            source_version_prefix: "5.00".to_owned(),
            content_version_required: true,
            key_kinds: Vec::new(),
            validated_artifact_families: Vec::new(),
        },
        coverage: vec![crate::sccm::SccmDeploymentCoverage {
            logical_artifact_id: "client-content".to_owned(),
            state: SccmCoverageState::Captured,
            capture_complete: true,
            artifact_ids: vec!["artifact-content".to_owned()],
        }],
        transactions: vec![crate::sccm::SccmDeploymentTransaction {
            transaction_id: "deployment-transaction".to_owned(),
            key: crate::sccm::SccmDeploymentKey {
                key_profile_kind:
                    crate::sccm::SccmDeploymentKeyProfileKind::AssignmentCiContentTopology,
                assignment_id: "assignment-safe".to_owned(),
                ci_id: "1001".to_owned(),
                package_id: Some("LAB00001".to_owned()),
                content_id: Some("content-safe".to_owned()),
                content_version: Some(1),
                distribution_point_host_handle: Some("dp-safe".to_owned()),
                request_id: Some("content-request".to_owned()),
                bits_job_id: None,
                product_code: None,
                exit_code: None,
                confidence: crate::sccm::SccmDeploymentKeyConfidence::Exact,
                extraction_profile_id: SCCM_DEPLOYMENT_PROFILE_ID.to_owned(),
            },
            counterpart_ready_fact: Some(crate::sccm::SccmDeploymentCounterpartFact {
                fact_kind: crate::sccm::SccmDeploymentCounterpartFactKind::ClientContentRequest,
                phase: crate::sccm::SccmDeploymentPhase::LocateContent,
                extraction_profile_id: SCCM_DEPLOYMENT_PROFILE_ID.to_owned(),
                package_id: "LAB00001".to_owned(),
                content_id: "content-safe".to_owned(),
                content_version: 1,
                distribution_point_host_handle: "dp-safe".to_owned(),
                request_id: "content-request".to_owned(),
                timestamp_provenance: crate::sccm::SccmDeploymentTimestampProvenance {
                    kind: crate::sccm::SccmDeploymentTimestampProvenanceKind::ExplicitOffset,
                    offset_minutes: 0,
                    normalized_utc: "1970-01-01T00:00:00.100Z".to_owned(),
                },
                evidence: content_ref.clone(),
            }),
            phase: crate::sccm::SccmDeploymentPhase::LocateContent,
            state: crate::sccm::SccmDeploymentState::Failed,
            last_successful_phase: None,
            classification: crate::sccm::SccmDeploymentClassification::ConfirmedFailure,
            confidence: crate::sccm::SccmDeploymentConfidence::High,
            confidence_ceiling: crate::sccm::SccmDeploymentConfidence::High,
            coverage_gap_artifact_ids: Vec::new(),
            next_artifact: None,
            evidence: vec![content_ref.clone()],
        }],
        source_local_observations: Vec::new(),
        findings: Vec::new(),
        coverage_gaps: Vec::new(),
        artifact_requests: Vec::new(),
        correlation_handoff: crate::sccm::SccmDeploymentCorrelationHandoff {
            issue: "#333".to_owned(),
            performed: false,
            time_only_eligible: false,
            topology_compatibility_evaluated: false,
            server_cause_claimed: false,
            counterpart_ready_key_kinds: Vec::new(),
            emitted_counterpart_ready_fact: true,
        },
    };
    let dp_observation = crate::sccm::server::windows::SccmDistributionPointContentObservation {
        phase: crate::sccm::server::windows::SccmDistributionPointContentPhase::Transfer,
        disposition: crate::sccm::server::windows::SccmDistributionPointContentDisposition::Failed,
        terminal: true,
        source_id: "server-dp-distribution".to_owned(),
        timestamp: timestamp(200),
        evidence: evidence_ref("dp"),
    };
    let distribution_point =
        crate::sccm::server::windows::SccmDistributionPointContentAnalysis {
            schema_version: 1,
            workflow:
                crate::sccm::server::windows::SccmDistributionPointWorkflow::DistributionPointContent,
            profile: crate::sccm::server::windows::SccmDistributionPointProfile {
                id: SCCM_DISTRIBUTION_POINT_CONTENT_PROFILE_ID.to_owned(),
                version: SCCM_DISTRIBUTION_POINT_CONTENT_PROFILE_VERSION,
                stability: "synthetic".to_owned(),
            },
            transactions: vec![
                crate::sccm::server::windows::SccmDistributionPointContentTransaction {
                    transaction_id: "dp-transaction".to_owned(),
                    key: crate::sccm::server::windows::SccmDistributionPointContentKey {
                        package_id: "LAB00001".to_owned(),
                        content_id: "content-safe".to_owned(),
                        content_version: 1,
                        topology_site_handle: "site-safe".to_owned(),
                        site_code: "LAB".to_owned(),
                        distribution_point_handle: "dp-safe".to_owned(),
                        extraction_profile_id:
                            SCCM_DISTRIBUTION_POINT_CONTENT_PROFILE_ID.to_owned(),
                        extraction_profile_version:
                            SCCM_DISTRIBUTION_POINT_CONTENT_PROFILE_VERSION,
                    },
                    state: SccmDistributionPointContentState::Failed,
                    classification: crate::sccm::server::windows::SccmDistributionPointContentClassification::ConfirmedFailure,
                    confidence: crate::sccm::server::windows::SccmDistributionPointContentConfidence::High,
                    severity: crate::models::log_entry::Severity::Error,
                    scope: crate::sccm::server::windows::SccmDistributionPointContentScope::DistributionPointContent,
                    last_proven_phase: None,
                    stop_phase: Some(crate::sccm::server::windows::SccmDistributionPointContentPhase::Transfer),
                    recovered: false,
                    content_version_mismatch: false,
                    evidence: vec![dp_observation.evidence.clone()],
                    terminal_evidence: vec![dp_observation.evidence.clone()],
                    next_artifact: None,
                    observations: vec![dp_observation],
                },
            ],
            coverage_gaps: Vec::new(),
            artifact_requests: Vec::new(),
            cross_side_correlation_performed: false,
        };

    let updates = crate::sccm::SccmClientUpdatesAnalysis {
        schema_version: 1,
        transactions: Vec::new(),
        observations: Vec::new(),
        findings: Vec::new(),
        coverage: vec![crate::sccm::SccmClientUpdateCoverage {
            logical_artifact_id: "client-updates".to_owned(),
            state: crate::sccm::SccmClientUpdateCoverageState::Captured,
        }],
        extraction_profile: crate::sccm::SccmClientUpdateExtractionProfile {
            selection_state: "selected".to_owned(),
            profile_id: SCCM_EXPERIMENTAL_KEY_PROFILE_ID.to_owned(),
            key_confidence_ceiling: SccmKeyConfidence::Exact,
            validated_artifact_families: Vec::new(),
        },
        correlation_handoff: crate::sccm::SccmClientUpdateCorrelationHandoff {
            issue: "#333".to_owned(),
            server_prerequisite_issue: "#330".to_owned(),
            performed: false,
            time_only_eligible: false,
            topology_compatibility_evaluated: false,
            server_cause_claimed: false,
            native_acceptance_claimed: false,
            bundle_capture_host_used_as_sup_evidence: false,
            counterpart_ready_key_kinds: Vec::new(),
            emitted_counterpart_ready_fact: true,
            counterpart_ready_facts: vec![crate::sccm::SccmClientUpdateCounterpartReadyFact {
                update_id: "update-safe".to_owned(),
                ci_id: "1001".to_owned(),
                content_id: "content-safe".to_owned(),
                update_job_id: "job-safe".to_owned(),
                client_handle: "client-safe".to_owned(),
                site_code: "LAB".to_owned(),
                sup_host_handle: "sup-safe".to_owned(),
                key_confidence: SccmKeyConfidence::Exact,
                correlation_eligible: false,
                time_only_eligible: false,
                phase: crate::sccm::SccmClientUpdatePhase::LocateSup,
                extraction_profile_id: SCCM_EXPERIMENTAL_KEY_PROFILE_ID.to_owned(),
                timestamp_provenance: crate::sccm::SccmClientUpdateTimestampProvenance {
                    normalized_utc: "1970-01-01T00:00:00.100Z".to_owned(),
                    utc_millis: 100,
                    offset_minutes: 0,
                    ordering_state: SccmTimeOrderingState::NormalizedUtc,
                },
                evidence: crate::sccm::SccmClientUpdateCounterpartEvidence {
                    artifact_id: "artifact-update".to_owned(),
                    start_line: 1,
                    end_line: 1,
                },
            }],
        },
        prohibited_claims: Vec::new(),
    };
    let software_update_point = crate::sccm::server::windows::SccmSoftwareUpdatePointAnalysis {
        workflow: crate::sccm::server::windows::SccmSoftwareUpdatePointWorkflow::SoftwareUpdatePoint,
        state_chain: Vec::new(),
        analysis_contract: crate::sccm::server::windows::SccmSoftwareUpdatePointAnalysisContract {
            independent_reducer: true,
            consumes_client_output: false,
            cross_side_correlation_performed: false,
        },
        extraction_profile: crate::sccm::server::windows::SccmSoftwareUpdatePointExtractionProfile {
            selection_state: SccmSoftwareUpdatePointProfileSelection::SelectedSynthetic,
            profile_id: Some(SCCM_SOFTWARE_UPDATE_POINT_PROFILE_ID.to_owned()),
            validated_role: Some(crate::sccm::SccmRole::SoftwareUpdatePoint),
        },
        role_assessment: crate::sccm::server::windows::SccmSoftwareUpdatePointRoleAssessment {
            software_update_point_observed: true,
            role_absent_inferred: false,
            missing_default_path_interpretation: crate::sccm::server::windows::SccmSoftwareUpdatePointMissingPathInterpretation::SourceCoverageOnly,
        },
        coverage: vec![crate::sccm::server::windows::SccmSoftwareUpdatePointCoverage {
            artifact_id: "artifact-sup".to_owned(),
            state: SccmCoverageState::Captured,
        }],
        transactions: vec![crate::sccm::server::windows::SccmSoftwareUpdatePointTransaction {
            transaction_id: "sup-transaction".to_owned(),
            key: crate::sccm::server::windows::SccmSoftwareUpdatePointKey {
                sync_run_id: "sync-safe".to_owned(),
                site_code: "LAB".to_owned(),
                sup_handle: "sup-safe".to_owned(),
                update_id: Some("update-safe".to_owned()),
                kb_id: None,
                confidence: crate::sccm::server::windows::SccmSoftwareUpdatePointKeyConfidence::Exact,
                extraction_profile_id: SCCM_SOFTWARE_UPDATE_POINT_PROFILE_ID.to_owned(),
            },
            topology_compatibility: crate::sccm::server::windows::SccmSoftwareUpdatePointTopologyCompatibility::Exact,
            correlation_eligible: true,
            state: SccmSoftwareUpdatePointState::Failed,
            classification: crate::sccm::server::windows::SccmSoftwareUpdatePointClassification::ConfirmedFailure,
            confidence: crate::sccm::server::windows::SccmSoftwareUpdatePointConfidence::High,
            confidence_ceiling: crate::sccm::server::windows::SccmSoftwareUpdatePointConfidence::High,
            last_successful_phase: None,
            next_source_id: None,
            coverage_gap_artifact_ids: Vec::new(),
            observations: vec![crate::sccm::server::windows::SccmSoftwareUpdatePointObservation {
                observation_id: "sup-terminal".to_owned(),
                phase: crate::sccm::server::windows::SccmSoftwareUpdatePointPhase::HealthyOrTerminal,
                disposition: SccmSoftwareUpdatePointDisposition::Failed,
                terminal: true,
                timestamp: timestamp(200),
                evidence: vec![crate::sccm::server::windows::SccmSoftwareUpdatePointEvidence {
                    artifact_id: "artifact-sup".to_owned(),
                    start_line: 1,
                    end_line: 1,
                }],
            }],
        }],
        source_local_observations: Vec::new(),
        artifact_requests: Vec::new(),
        client_causal_claims: Vec::new(),
        correlation_handoff: crate::sccm::server::windows::SccmSoftwareUpdatePointCorrelationHandoff {
            issue: "#333".to_owned(),
            performed: false,
            time_only_eligible: false,
        },
    };

    let outputs = [
        correlate_policy_management_point(&SccmPolicyManagementPointInput::from_analyses(
            &policy,
            &management_point,
        )),
        correlate_content_distribution_point(&SccmContentDistributionPointInput::from_analyses(
            &deployment,
            &distribution_point,
        )),
        correlate_updates_software_update_point(
            &SccmUpdatesSoftwareUpdatePointInput::from_analyses(&updates, &software_update_point),
        ),
    ];
    for output in outputs {
        assert_eq!(output.results.len(), 1, "{:?}", output.pair);
        assert_eq!(
            output.results[0].link_strength,
            SccmCorrelationLinkStrength::ExactCorroborated,
            "{:?}",
            output.pair
        );
        assert_eq!(
            output.results[0].confidence,
            SccmCorrelationConfidence::High,
            "{:?}",
            output.pair
        );
    }

    let assert_guard = |output: SccmCorrelationAnalysis,
                        guard: SccmCorrelationGuard,
                        reason: SccmCorrelationReason| {
        let result = &output.results[0];
        assert!(result.guard_checks.iter().any(|check| {
            check.guard_id == guard && check.state == SccmCorrelationGuardState::Triggered
        }));
        assert!(result.reason_codes.contains(&reason));
        assert_ne!(
            result.link_strength,
            SccmCorrelationLinkStrength::ExactCorroborated
        );
    };

    let mut policy_bad_time = policy.clone();
    policy_bad_time.transactions[0].observations[0]
        .timestamp
        .ordering_state = SccmTimeOrderingState::OffsetInvalid;
    policy_bad_time.transactions[0].observations[0]
        .timestamp
        .utc_millis = None;
    assert_guard(
        correlate_policy_management_point(&SccmPolicyManagementPointInput::from_analyses(
            &policy_bad_time,
            &management_point,
        )),
        SccmCorrelationGuard::InvalidTimestampOffset,
        SccmCorrelationReason::OrderingUnavailable,
    );

    let mut deployment_bad_time = deployment.clone();
    deployment_bad_time.transactions[0]
        .counterpart_ready_fact
        .as_mut()
        .unwrap()
        .timestamp_provenance
        .normalized_utc = "not-rfc3339".to_owned();
    assert_guard(
        correlate_content_distribution_point(&SccmContentDistributionPointInput::from_analyses(
            &deployment_bad_time,
            &distribution_point,
        )),
        SccmCorrelationGuard::InvalidTimestampOffset,
        SccmCorrelationReason::OrderingUnavailable,
    );

    let mut policy_bad_profile = policy.clone();
    policy_bad_profile.transactions[0].key.extraction_profile_id = "wrong-profile".to_owned();
    let mut deployment_bad_profile = deployment.clone();
    deployment_bad_profile.transactions[0]
        .counterpart_ready_fact
        .as_mut()
        .unwrap()
        .extraction_profile_id = "wrong-profile".to_owned();
    let mut dp_bad_profile = distribution_point.clone();
    dp_bad_profile.transactions[0]
        .key
        .extraction_profile_version += 1;
    let mut updates_bad_profile = updates.clone();
    updates_bad_profile
        .correlation_handoff
        .counterpart_ready_facts[0]
        .extraction_profile_id = "wrong-profile".to_owned();
    let mut sup_bad_profile = software_update_point.clone();
    sup_bad_profile.transactions[0].key.extraction_profile_id = "wrong-profile".to_owned();
    for output in [
        correlate_policy_management_point(&SccmPolicyManagementPointInput::from_analyses(
            &policy_bad_profile,
            &management_point,
        )),
        correlate_content_distribution_point(&SccmContentDistributionPointInput::from_analyses(
            &deployment_bad_profile,
            &distribution_point,
        )),
        correlate_content_distribution_point(&SccmContentDistributionPointInput::from_analyses(
            &deployment,
            &dp_bad_profile,
        )),
        correlate_updates_software_update_point(
            &SccmUpdatesSoftwareUpdatePointInput::from_analyses(
                &updates_bad_profile,
                &software_update_point,
            ),
        ),
        correlate_updates_software_update_point(
            &SccmUpdatesSoftwareUpdatePointInput::from_analyses(&updates, &sup_bad_profile),
        ),
    ] {
        assert_guard(
            output,
            SccmCorrelationGuard::VersionMismatch,
            SccmCorrelationReason::ProfileVersionMismatch,
        );
    }
}

#[test]
fn input_order_does_not_change_bytes() {
    let mut first = healthy(SccmCorrelationPair::PolicyManagementPoint);
    first
        .client_facts
        .push(fact("key=two", "topology=two", Some(300), false));
    first
        .server_facts
        .push(fact("key=two", "topology=two", Some(400), true));
    let first = first.normalize();
    let mut second = first.clone();
    second.client_facts.reverse();
    second.server_facts.reverse();
    let second = second.normalize();
    assert_eq!(
        serde_json::to_vec(&correlate(&first)).unwrap(),
        serde_json::to_vec(&correlate(&second)).unwrap()
    );
}

#[test]
fn duplicate_exact_identity_and_recovered_terminal_fail_closed() {
    let mut collision = healthy(SccmCorrelationPair::ContentDistributionPoint);
    collision
        .server_facts
        .push(fact("key=one", "topology=one", Some(300), true));
    let collision = correlate(&collision.normalize());
    assert_eq!(
        collision.results[0].link_strength,
        SccmCorrelationLinkStrength::Incompatible
    );
    assert_eq!(
        collision.results[0].confidence,
        SccmCorrelationConfidence::Low
    );
    assert!(collision.results[0]
        .reason_codes
        .contains(&SccmCorrelationReason::ExactKeyConflict));

    let mut recovered = healthy(SccmCorrelationPair::ContentDistributionPoint);
    recovered.server_facts[0].terminal_failure = false;
    let recovered = correlate(&recovered.normalize());
    assert_eq!(
        recovered.results[0].outcome,
        SccmCorrelationOutcome::NotCausal
    );
    assert_eq!(
        recovered.results[0].link_strength,
        SccmCorrelationLinkStrength::ExactPartial
    );
    assert_eq!(
        recovered.results[0].confidence,
        SccmCorrelationConfidence::Medium
    );
    assert!(recovered.results[0]
        .reason_codes
        .contains(&SccmCorrelationReason::TerminalRelationMissing));
}

#[test]
fn every_guard_is_checked_for_every_pair() {
    for pair in [
        SccmCorrelationPair::ContentDistributionPoint,
        SccmCorrelationPair::PolicyManagementPoint,
        SccmCorrelationPair::UpdatesSoftwareUpdatePoint,
    ] {
        let result = &correlate(&healthy(pair)).results[0];
        assert_eq!(
            result
                .guard_checks
                .iter()
                .map(|check| check.guard_id)
                .collect::<Vec<_>>(),
            ALL_GUARDS
        );
    }
}

#[test]
fn raw_source_markers_never_enter_public_output() {
    let markers = [
        r"C:\Windows\CCM\Logs\PolicyAgent.log",
        "mp01.contoso.example",
        r"LAB\SyntheticUser",
        "Bearer secret-token",
    ];
    for marker in markers {
        let mut input = healthy(SccmCorrelationPair::PolicyManagementPoint);
        input.client_facts[0].stable_source = marker.to_owned();
        let json = serde_json::to_string(&correlate(&input)).unwrap();
        assert!(!json.contains(marker), "leaked {marker}");
    }
}

#[test]
fn typed_adapters_leave_all_source_analyses_byte_identical() {
    let policy = crate::sccm::SccmPolicyAnalysis {
        workflow: "policy".to_owned(),
        state_chain: Vec::new(),
        extraction_profile: crate::sccm::SccmPolicyExtractionProfile {
            selection_state: crate::sccm::SccmPolicyProfileSelectionState::Unavailable,
            profile_id: None,
            synthetic_fixture_only: false,
        },
        coverage: Vec::new(),
        profile_gaps: Vec::new(),
        transactions: Vec::new(),
        source_local_observations: Vec::new(),
        findings: Vec::new(),
        artifact_requests: Vec::new(),
        cross_source_correlation_performed: false,
        time_only_causality_allowed: false,
    };
    let management_point = crate::sccm::server::windows::SccmManagementPointAnalysis {
        schema_version: 1,
        workflow: crate::sccm::server::windows::SccmServerWorkflow::ManagementPoint,
        state_chain: Vec::new(),
        transactions: Vec::new(),
        source_local_observations: Vec::new(),
        findings: Vec::new(),
        coverage_gaps: Vec::new(),
        artifact_requests: Vec::new(),
        counterpart_ready_facts: Vec::new(),
        cross_side_correlation_performed: false,
    };
    let deployment = crate::sccm::SccmDeploymentAnalysis {
        schema_version: 1,
        workflow: crate::sccm::SccmDeploymentWorkflow::Deployment,
        extraction_profile: crate::sccm::SccmDeploymentExtractionProfile {
            selection_state: crate::sccm::SccmDeploymentProfileSelectionState::Unselected,
            profile_id: SCCM_DEPLOYMENT_PROFILE_ID.to_owned(),
            source_version_prefix: String::new(),
            content_version_required: true,
            key_kinds: Vec::new(),
            validated_artifact_families: Vec::new(),
        },
        coverage: Vec::new(),
        transactions: Vec::new(),
        source_local_observations: Vec::new(),
        findings: Vec::new(),
        coverage_gaps: Vec::new(),
        artifact_requests: Vec::new(),
        correlation_handoff: crate::sccm::SccmDeploymentCorrelationHandoff {
            issue: "#333".to_owned(),
            performed: false,
            time_only_eligible: false,
            topology_compatibility_evaluated: false,
            server_cause_claimed: false,
            counterpart_ready_key_kinds: Vec::new(),
            emitted_counterpart_ready_fact: false,
        },
    };
    let distribution_point = crate::sccm::server::windows::SccmDistributionPointContentAnalysis {
        schema_version: 1,
        workflow:
            crate::sccm::server::windows::SccmDistributionPointWorkflow::DistributionPointContent,
        profile: crate::sccm::server::windows::SccmDistributionPointProfile {
            id: SCCM_DISTRIBUTION_POINT_CONTENT_PROFILE_ID.to_owned(),
            version: SCCM_DISTRIBUTION_POINT_CONTENT_PROFILE_VERSION,
            stability: "synthetic".to_owned(),
        },
        transactions: Vec::new(),
        coverage_gaps: Vec::new(),
        artifact_requests: Vec::new(),
        cross_side_correlation_performed: false,
    };
    let updates = crate::sccm::SccmClientUpdatesAnalysis {
        schema_version: 1,
        transactions: Vec::new(),
        observations: Vec::new(),
        findings: Vec::new(),
        coverage: Vec::new(),
        extraction_profile: crate::sccm::SccmClientUpdateExtractionProfile {
            selection_state: "unavailable".to_owned(),
            profile_id: String::new(),
            key_confidence_ceiling: SccmKeyConfidence::Low,
            validated_artifact_families: Vec::new(),
        },
        correlation_handoff: crate::sccm::SccmClientUpdateCorrelationHandoff {
            issue: "#333".to_owned(),
            server_prerequisite_issue: "#330".to_owned(),
            performed: false,
            time_only_eligible: false,
            topology_compatibility_evaluated: false,
            server_cause_claimed: false,
            native_acceptance_claimed: false,
            bundle_capture_host_used_as_sup_evidence: false,
            counterpart_ready_key_kinds: Vec::new(),
            emitted_counterpart_ready_fact: false,
            counterpart_ready_facts: Vec::new(),
        },
        prohibited_claims: Vec::new(),
    };
    let software_update_point =
        crate::sccm::server::windows::SccmSoftwareUpdatePointAnalysis {
        workflow: crate::sccm::server::windows::SccmSoftwareUpdatePointWorkflow::SoftwareUpdatePoint,
        state_chain: Vec::new(),
        analysis_contract: crate::sccm::server::windows::SccmSoftwareUpdatePointAnalysisContract {
            independent_reducer: true,
            consumes_client_output: false,
            cross_side_correlation_performed: false,
        },
        extraction_profile: crate::sccm::server::windows::SccmSoftwareUpdatePointExtractionProfile {
            selection_state:
                crate::sccm::server::windows::SccmSoftwareUpdatePointProfileSelection::Unavailable,
            profile_id: None,
            validated_role: None,
        },
        role_assessment: crate::sccm::server::windows::SccmSoftwareUpdatePointRoleAssessment {
            software_update_point_observed: false,
            role_absent_inferred: false,
            missing_default_path_interpretation:
                crate::sccm::server::windows::SccmSoftwareUpdatePointMissingPathInterpretation::SourceCoverageOnly,
        },
        coverage: Vec::new(),
        transactions: Vec::new(),
        source_local_observations: Vec::new(),
        artifact_requests: Vec::new(),
        client_causal_claims: Vec::new(),
        correlation_handoff: crate::sccm::server::windows::SccmSoftwareUpdatePointCorrelationHandoff {
            issue: "#333".to_owned(),
            performed: false,
            time_only_eligible: false,
        },
    };

    let before = [
        serde_json::to_vec(&policy).unwrap(),
        serde_json::to_vec(&management_point).unwrap(),
        serde_json::to_vec(&deployment).unwrap(),
        serde_json::to_vec(&distribution_point).unwrap(),
        serde_json::to_vec(&updates).unwrap(),
        serde_json::to_vec(&software_update_point).unwrap(),
    ];
    correlate_policy_management_point(&SccmPolicyManagementPointInput::from_analyses(
        &policy,
        &management_point,
    ));
    correlate_content_distribution_point(&SccmContentDistributionPointInput::from_analyses(
        &deployment,
        &distribution_point,
    ));
    correlate_updates_software_update_point(&SccmUpdatesSoftwareUpdatePointInput::from_analyses(
        &updates,
        &software_update_point,
    ));
    let after = [
        serde_json::to_vec(&policy).unwrap(),
        serde_json::to_vec(&management_point).unwrap(),
        serde_json::to_vec(&deployment).unwrap(),
        serde_json::to_vec(&distribution_point).unwrap(),
        serde_json::to_vec(&updates).unwrap(),
        serde_json::to_vec(&software_update_point).unwrap(),
    ];
    assert_eq!(before, after);
}

#[test]
fn policy_management_point_matrix_is_an_exact_production_oracle() {
    run_oracle_matrix("policy_management_point/adversarial-matrix.json");
}

#[test]
fn content_distribution_point_matrix_is_an_exact_production_oracle() {
    run_oracle_matrix("content_distribution_point/adversarial-matrix.json");
}

#[test]
fn updates_software_update_point_matrix_is_an_exact_production_oracle() {
    run_oracle_matrix("updates_software_update_point/adversarial-matrix.json");
}
