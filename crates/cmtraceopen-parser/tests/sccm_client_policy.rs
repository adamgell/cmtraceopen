use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use cmtraceopen_parser::sccm::{
    analyze_client_policy, assess_client_intake, SccmArtifact, SccmClientCapturedPayload,
    SccmClientIntakeArtifact, SccmClientIntakeBundle, SccmClientIntakeCaptureGap, SccmConfidence,
    SccmCoverageState, SccmFindingClass, SccmKeyConfidence, SccmPolicyClassification,
    SccmPolicyCondition, SccmPolicyPhase, SccmPolicyProfileSelectionState, SccmPolicyState,
    SccmRole, SccmRotation, SCCM_POLICY_KEY_PROFILE_ID,
};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

const FIXTURE_ROOT: &str = "tests/fixtures/sccm/client/policy";
const SCENARIOS: &[&str] = &[
    "complete",
    "contradictory-offset",
    "download-failure",
    "evaluation-failure",
    "gate-c-contradictory",
    "incomplete",
    "malformed",
    "multiline",
    "persist-failure",
    "recovery",
    "reporting-failure",
    "request-auth-failure",
    "rotation-split",
    "scheduler-deferred",
];

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureManifest {
    artifacts: Vec<FixtureArtifact>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureArtifact {
    artifact_id: String,
    role: String,
    capture_state: String,
    encoding: Option<String>,
    original_basename: String,
    path_fingerprint: Option<String>,
    rotation: FixtureRotation,
    source_version: Option<String>,
    captured_utc: Option<String>,
    relative_path: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureRotation {
    kind: String,
    value: Option<u32>,
    lineage_id: Option<String>,
    fragment_complete: Option<bool>,
}

fn fixture_directory(scenario: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(FIXTURE_ROOT)
        .join(scenario)
}

fn fixture_input(scenario: &str) -> (SccmClientIntakeBundle, Vec<SccmClientCapturedPayload>) {
    let root = fixture_directory(scenario);
    let manifest: FixtureManifest = serde_json::from_str(
        &fs::read_to_string(root.join("manifest.json")).expect("manifest is readable"),
    )
    .expect("manifest is valid");
    let mut payloads = Vec::new();
    let artifacts = manifest
        .artifacts
        .into_iter()
        .map(|fixture| {
            assert_eq!(fixture.role, "client");
            let artifact_id = format!("fixture-{}", fixture.artifact_id);
            let coverage = fixture_coverage(&fixture.capture_state);
            let rotation_lineage = fixture
                .rotation
                .lineage_id
                .as_ref()
                .map(|_| "synthetic:policy-rotation-boundary".to_owned());
            let complete_capture = coverage == SccmCoverageState::Captured
                && fixture.rotation.fragment_complete == Some(true);
            let bytes = complete_capture.then(|| {
                fs::read(
                    root.join(
                        fixture
                            .relative_path
                            .as_deref()
                            .expect("complete capture has a relative path"),
                    ),
                )
                .expect("payload is readable")
            });
            let declared_byte_length = bytes
                .as_ref()
                .map(|bytes| u64::try_from(bytes.len()).expect("fixture length fits u64"));
            let content_sha256 = bytes.as_ref().map(|bytes| hex_sha256(bytes));
            if let Some(bytes) = bytes {
                payloads.push(
                    SccmClientCapturedPayload::new(artifact_id.clone(), bytes)
                        .expect("fixture payload is bounded"),
                );
            }
            SccmClientIntakeArtifact {
                artifact: SccmArtifact {
                    artifact_id,
                    display_name: fixture.original_basename,
                    original_path: None,
                    host: None,
                    role: SccmRole::Client,
                    configmgr_version: fixture.source_version,
                    collected_at_utc: fixture.captured_utc,
                    rotation: fixture_rotation(&fixture.rotation),
                    coverage,
                    encoding: fixture.encoding,
                },
                path_fingerprint: rotation_lineage
                    .as_ref()
                    .map(|_| "synthetic:policy-rotation-boundary".to_owned())
                    .or(fixture.path_fingerprint),
                rotation_lineage,
                relative_path: fixture.relative_path,
                task_sequence_provenance: None,
                fragment_complete: fixture.rotation.fragment_complete,
                declared_byte_length,
                content_sha256,
            }
        })
        .collect();
    (
        SccmClientIntakeBundle {
            artifacts,
            capture_gaps: Vec::new(),
        },
        payloads,
    )
}

fn analyze_fixture(scenario: &str) -> cmtraceopen_parser::sccm::SccmPolicyAnalysis {
    let (bundle, payloads) = fixture_input(scenario);
    let assessment = assess_client_intake(&bundle).expect("fixture intake is canonical");
    analyze_client_policy(&bundle, &assessment, &payloads)
        .unwrap_or_else(|error| panic!("{scenario} policy analysis succeeds: {error:?}"))
}

fn fixture_rotation(rotation: &FixtureRotation) -> SccmRotation {
    match rotation.kind.as_str() {
        "current" => SccmRotation::Current,
        "lo" => SccmRotation::LoUnderscore,
        "numbered" => SccmRotation::Numbered(rotation.value.expect("numbered value")),
        other => panic!("unsupported rotation {other}"),
    }
}

fn fixture_coverage(value: &str) -> SccmCoverageState {
    match value {
        "captured" => SccmCoverageState::Captured,
        "absent" => SccmCoverageState::Absent,
        "accessDenied" => SccmCoverageState::AccessDenied,
        "capped" => SccmCoverageState::Capped,
        "parseFailed" => SccmCoverageState::ParseFailed,
        other => panic!("unsupported fixture coverage {other}"),
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn single_policy_input(
    artifact_id: &str,
    basename: &str,
    records: &[&str],
) -> (SccmClientIntakeBundle, Vec<SccmClientCapturedPayload>) {
    let bytes = records.join("\n").into_bytes();
    let canonical_id = format!("fixture-{artifact_id}");
    let bundle = SccmClientIntakeBundle {
        artifacts: vec![SccmClientIntakeArtifact {
            artifact: SccmArtifact {
                artifact_id: canonical_id.clone(),
                display_name: basename.to_owned(),
                original_path: None,
                host: None,
                role: SccmRole::Client,
                configmgr_version: Some("5.00.TEST.0000".to_owned()),
                collected_at_utc: Some("2026-08-04T12:00:00Z".to_owned()),
                rotation: SccmRotation::Current,
                coverage: SccmCoverageState::Captured,
                encoding: Some("utf-8".to_owned()),
            },
            path_fingerprint: Some(format!("synthetic:{artifact_id}")),
            rotation_lineage: None,
            relative_path: Some(format!("evidence/client-policy-agent/current/{basename}")),
            task_sequence_provenance: None,
            fragment_complete: Some(true),
            declared_byte_length: Some(u64::try_from(bytes.len()).expect("length")),
            content_sha256: Some(hex_sha256(&bytes)),
        }],
        capture_gaps: Vec::new(),
    };
    let payloads =
        vec![SccmClientCapturedPayload::new(canonical_id, bytes).expect("bounded payload")];
    (bundle, payloads)
}

#[test]
fn every_policy_fixture_runs_through_production_with_exact_oracles() {
    let oracle_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(FIXTURE_ROOT)
        .join("production-oracles.json");
    let oracles: Value = serde_json::from_str(
        &fs::read_to_string(&oracle_path).expect("production oracle is committed"),
    )
    .expect("production oracle is valid JSON");

    for scenario in SCENARIOS {
        let analysis = analyze_fixture(scenario);
        assert_eq!(
            serde_json::to_value(&analysis).expect("analysis serializes"),
            oracles[*scenario],
            "{scenario}"
        );
        assert!(analysis.findings.iter().all(|finding| {
            finding.validate().is_ok()
                && !finding.evidence.is_empty()
                && finding
                    .evidence
                    .iter()
                    .all(|reference| reference.line_start.is_some() && reference.line_end.is_some())
        }));
        assert!(!analysis.time_only_causality_allowed);

        let (mut reversed_bundle, mut reversed_payloads) = fixture_input(scenario);
        reversed_bundle.artifacts.reverse();
        reversed_payloads.reverse();
        let reversed_assessment =
            assess_client_intake(&reversed_bundle).expect("reordered intake is canonical");
        let reversed =
            analyze_client_policy(&reversed_bundle, &reversed_assessment, &reversed_payloads)
                .expect("reordered analysis succeeds");
        assert_eq!(
            serde_json::to_value(&analysis).expect("analysis serializes"),
            serde_json::to_value(reversed).expect("reordered analysis serializes"),
            "input order changed output for {scenario}"
        );
    }
    assert_eq!(
        oracles.as_object().expect("oracle object").len(),
        SCENARIOS.len()
    );
    assert!(analyze_fixture("complete").cross_source_correlation_performed);
    assert!(!analyze_fixture("download-failure").cross_source_correlation_performed);
}

#[test]
fn policy_acceptance_states_are_distinct_and_conservative() {
    assert!(
        analyze_fixture("complete")
            .extraction_profile
            .synthetic_fixture_only
    );
    assert_eq!(
        analyze_fixture("complete").transactions[0].state,
        SccmPolicyState::Succeeded
    );
    assert_eq!(
        analyze_fixture("request-auth-failure").transactions[0].condition,
        Some(SccmPolicyCondition::TransferAuthenticationFailure)
    );
    assert_eq!(
        analyze_fixture("scheduler-deferred").transactions[0].state,
        SccmPolicyState::Deferred
    );
    assert_eq!(
        analyze_fixture("gate-c-contradictory").transactions[0].state,
        SccmPolicyState::Contradictory
    );
    assert_eq!(
        analyze_fixture("incomplete").transactions[0].state,
        SccmPolicyState::Incomplete
    );
    assert_eq!(
        analyze_fixture("malformed")
            .extraction_profile
            .selection_state,
        SccmPolicyProfileSelectionState::UnvalidatedVersion
    );
    assert!(analyze_fixture("rotation-split").transactions.is_empty());
}

#[test]
fn authority_mutations_fail_closed_without_caller_profiles_or_evidence() {
    let (bundle, payloads) = fixture_input("complete");
    let mut assessment = assess_client_intake(&bundle).expect("canonical");
    assessment.groups[0].logical_artifact_id = "forged-policy-group".to_owned();
    assert!(analyze_client_policy(&bundle, &assessment, &payloads).is_err());

    let (bundle, mut payloads) = fixture_input("complete");
    payloads[0] = SccmClientCapturedPayload::new(
        bundle.artifacts[0].artifact.artifact_id.clone(),
        b"forged payload".to_vec(),
    )
    .expect("bounded forged payload");
    let assessment = assess_client_intake(&bundle).expect("canonical");
    assert!(analyze_client_policy(&bundle, &assessment, &payloads).is_err());
}

#[test]
fn observation_identity_and_public_privacy_are_collision_safe() {
    for scenario in SCENARIOS {
        let analysis = analyze_fixture(scenario);
        let mut ids = BTreeSet::new();
        for observation in analysis
            .transactions
            .iter()
            .flat_map(|transaction| transaction.observations.iter())
        {
            assert!(ids.insert(observation.observation_id.clone()), "{scenario}");
            assert!(observation
                .observation_id
                .contains(&observation.evidence.artifact_id));
            assert!(observation.observation_id.contains(
                &observation
                    .evidence
                    .line_start
                    .expect("admitted line")
                    .to_string()
            ));
        }
        let public = serde_json::to_string(&analysis).expect("analysis serializes");
        assert!(!public.contains("SYNTHETIC://"), "{scenario}");
        assert!(!public.contains("safe:client:"), "{scenario}");
        assert!(!public.contains("safe:mp:"), "{scenario}");
        assert!(!public.contains("LAB-CLIENT"), "{scenario}");
    }
}

#[test]
fn exact_keys_not_time_join_policy_transactions() {
    let analysis = analyze_fixture("gate-c-contradictory");
    assert_eq!(analysis.transactions.len(), 2);
    assert_ne!(
        analysis.transactions[0].key.assignment_id,
        analysis.transactions[1].key.assignment_id
    );
    assert!(analysis.transactions.iter().all(|transaction| {
        transaction.confidence == SccmConfidence::High
            || transaction.state == SccmPolicyState::Contradictory
    }));
    assert!(analysis
        .transactions
        .iter()
        .flat_map(|transaction| &transaction.correlation_keys)
        .all(|key| {
            key.confidence == SccmKeyConfidence::Exact
                && key.extraction_profile_id.as_deref() == Some(SCCM_POLICY_KEY_PROFILE_ID)
        }));
}

#[test]
fn conflicting_and_unkeyed_same_time_records_never_merge() {
    let first = "<![LOG[Request succeeded AssignmentId={41414141-4141-4141-4141-414141414141} PolicyId={d1d1d1d1-d1d1-d1d1-d1d1-d1d1d1d1d1d1} RequestId={51414141-4141-4141-4141-414141414141}]LOG]!><time=\"13:00:00.000+000\" date=\"8-4-2026\" component=\"PolicyAgent\" context=\"\" type=\"1\" thread=\"1\" file=\"synthetic.cc:1\">";
    let conflicting = "<![LOG[Download succeeded AssignmentId={41414141-4141-4141-4141-414141414141} PolicyId={d2d2d2d2-d2d2-d2d2-d2d2-d2d2d2d2d2d2}]LOG]!><time=\"13:00:00.000+000\" date=\"8-4-2026\" component=\"PolicyAgent\" context=\"\" type=\"1\" thread=\"1\" file=\"synthetic.cc:2\">";
    let (bundle, payloads) = single_policy_input(
        "policy-contradictory",
        "PolicyAgent.log",
        &[first, conflicting],
    );
    let assessment = assess_client_intake(&bundle).expect("canonical");
    let analysis = analyze_client_policy(&bundle, &assessment, &payloads).expect("analyzed");
    assert!(analysis.transactions.is_empty());
    assert_eq!(analysis.source_local_observations.len(), 2);
    assert!(analysis
        .source_local_observations
        .iter()
        .all(|observation| {
            observation.condition == SccmPolicyCondition::ConflictingEvidence
                && !observation.correlation_eligible
        }));

    let unkeyed = "<![LOG[Schedule succeeded with unresolved policy identity]LOG]!><time=\"13:00:00.000+000\" date=\"8-4-2026\" component=\"Scheduler\" context=\"\" type=\"1\" thread=\"1\" file=\"synthetic.cc:2\">";
    let (bundle, payloads) =
        single_policy_input("policy-gate", "PolicyAgent.log", &[first, unkeyed]);
    let assessment = assess_client_intake(&bundle).expect("canonical");
    let analysis = analyze_client_policy(&bundle, &assessment, &payloads).expect("analyzed");
    assert_eq!(analysis.transactions.len(), 1);
    assert_eq!(analysis.transactions[0].observations.len(), 1);
    assert_eq!(analysis.source_local_observations.len(), 1);
    assert!(!analysis.source_local_observations[0].correlation_eligible);
}

#[test]
fn no_assignment_stale_assignment_and_corrupt_processing_remain_distinct() {
    let no_assignment = "<![LOG[No assignment available for this policy cycle]LOG]!><time=\"12:00:00.000+000\" date=\"8-4-2026\" component=\"PolicyAgent\" context=\"\" type=\"1\" thread=\"1\" file=\"synthetic.cc:1\">";
    let (bundle, payloads) = single_policy_input("policy-no", "PolicyAgent.log", &[no_assignment]);
    let assessment = assess_client_intake(&bundle).expect("canonical");
    let analysis = analyze_client_policy(&bundle, &assessment, &payloads).expect("analyzed");
    assert!(analysis.transactions.is_empty());
    assert_eq!(
        analysis.source_local_observations[0].condition,
        SccmPolicyCondition::NoAssignment
    );

    let stale = "<![LOG[Stale assignment deferred AssignmentId={31313131-3131-3131-3131-313131313131} PolicyId={c1c1c1c1-c1c1-c1c1-c1c1-c1c1c1c1c1c1}]LOG]!><time=\"12:01:00.000+000\" date=\"8-4-2026\" component=\"Scheduler\" context=\"\" type=\"2\" thread=\"1\" file=\"synthetic.cc:1\">";
    let (bundle, payloads) = single_policy_input("policy-deferred", "Scheduler.log", &[stale]);
    let assessment = assess_client_intake(&bundle).expect("canonical");
    let analysis = analyze_client_policy(&bundle, &assessment, &payloads).expect("analyzed");
    assert_eq!(analysis.transactions[0].state, SccmPolicyState::Deferred);
    assert_eq!(
        analysis.transactions[0].condition,
        Some(SccmPolicyCondition::StaleAssignment)
    );

    let corrupt = "<![LOG[Processing corrupt failed terminal AssignmentId={32323232-3232-3232-3232-323232323232} PolicyId={c2c2c2c2-c2c2-c2c2-c2c2-c2c2c2c2c2c2}]LOG]!><time=\"12:02:00.000+000\" date=\"8-4-2026\" component=\"PolicyAgent\" context=\"\" type=\"3\" thread=\"1\" file=\"synthetic.cc:1\">";
    let (bundle, payloads) =
        single_policy_input("policy-persist-failure", "PolicyAgent.log", &[corrupt]);
    let assessment = assess_client_intake(&bundle).expect("canonical");
    let analysis = analyze_client_policy(&bundle, &assessment, &payloads).expect("analyzed");
    assert_eq!(analysis.transactions[0].state, SccmPolicyState::Failed);
    assert_eq!(
        analysis.transactions[0].condition,
        Some(SccmPolicyCondition::ProcessingFailure)
    );
    assert_eq!(analysis.findings[0].terminal_evidence.len(), 1);
}

#[test]
fn nonterminal_failure_is_only_a_low_confidence_symptom() {
    let record = "<![LOG[Download failed AssignmentId={33333333-3333-3333-3333-333333333333} PolicyId={c3c3c3c3-c3c3-c3c3-c3c3-c3c3c3c3c3c3}]LOG]!><time=\"12:03:00.000+000\" date=\"8-4-2026\" component=\"PolicyAgent\" context=\"\" type=\"3\" thread=\"1\" file=\"synthetic.cc:1\">";
    let (bundle, payloads) = single_policy_input("policy-failure", "PolicyAgent.log", &[record]);
    let assessment = assess_client_intake(&bundle).expect("canonical");
    let analysis = analyze_client_policy(&bundle, &assessment, &payloads).expect("analyzed");

    assert_eq!(analysis.transactions[0].state, SccmPolicyState::Observed);
    assert_eq!(
        analysis.transactions[0].classification,
        SccmPolicyClassification::LowConfidenceSymptom
    );
    assert_eq!(analysis.transactions[0].confidence, SccmConfidence::Low);
    assert!(analysis.findings[0].terminal_evidence.is_empty());
}

#[test]
fn capped_policy_source_is_an_explicit_transaction_gap() {
    let record = "<![LOG[Request succeeded AssignmentId={34343434-3434-3434-3434-343434343434} PolicyId={c4c4c4c4-c4c4-c4c4-c4c4-c4c4c4c4c4c4}]LOG]!><time=\"12:04:00.000+000\" date=\"8-4-2026\" component=\"PolicyAgent\" context=\"\" type=\"1\" thread=\"1\" file=\"synthetic.cc:1\">";
    let (mut bundle, payloads) = single_policy_input("policy-capped", "PolicyAgent.log", &[record]);
    bundle.capture_gaps.push(SccmClientIntakeCaptureGap {
        artifact_id: "fixture-policy-capped-rotation".to_owned(),
        basename: "PolicyAgent.log.1".to_owned(),
        rotation: SccmRotation::Numbered(1),
        coverage: SccmCoverageState::Capped,
        path_fingerprint: "synthetic-policy-capped-rotation".to_owned(),
        rotation_lineage: "synthetic:policy-capped-rotation".to_owned(),
    });
    let assessment = assess_client_intake(&bundle).expect("canonical capped declaration");
    let analysis = analyze_client_policy(&bundle, &assessment, &payloads).expect("analyzed");

    assert_eq!(analysis.transactions[0].state, SccmPolicyState::Incomplete);
    assert!(analysis.transactions[0].coverage_gaps.iter().any(|gap| {
        gap.artifact_id == "client-policy-agent" && gap.coverage == SccmCoverageState::Capped
    }));
    assert!(analysis.transactions[0]
        .next_artifacts
        .iter()
        .any(|request| request.logical_id == "policyAgent"));
}

fn policy_record(message: &str, time: &str, offset: &str, component: &str) -> String {
    format!(
        "<![LOG[{message} AssignmentId={{35353535-3535-3535-3535-353535353535}} PolicyId={{c5c5c5c5-c5c5-c5c5-c5c5-c5c5c5c5c5c5}}]LOG]!><time=\"{time}{offset}\" date=\"8-4-2026\" component=\"{component}\" context=\"\" type=\"1\" thread=\"1\" file=\"synthetic.cc:1\">"
    )
}

fn analyze_policy_records(
    artifact_id: &str,
    records: &[String],
) -> cmtraceopen_parser::sccm::SccmPolicyAnalysis {
    let borrowed = records.iter().map(String::as_str).collect::<Vec<_>>();
    let (bundle, payloads) = single_policy_input(artifact_id, "PolicyAgent.log", &borrowed);
    let assessment = assess_client_intake(&bundle).expect("canonical chronology input");
    analyze_client_policy(&bundle, &assessment, &payloads).expect("chronology analysis")
}

#[test]
fn cross_phase_chronology_precedes_failure_deferred_and_success_decisions() {
    let cases = [
        (
            "policy-failure",
            vec![
                policy_record("Request succeeded", "12:10:00.000", "+000", "PolicyAgent"),
                policy_record(
                    "Download failed terminal",
                    "12:05:00.000",
                    "+000",
                    "PolicyAgent",
                ),
            ],
        ),
        (
            "policy-deferred",
            vec![
                policy_record("Request succeeded", "12:10:00.000", "+000", "PolicyAgent"),
                policy_record("Schedule deferred", "12:05:00.000", "+000", "Scheduler"),
            ],
        ),
        (
            "policy-success",
            vec![
                policy_record("Request succeeded", "12:10:00.000", "+000", "PolicyAgent"),
                policy_record("Download succeeded", "12:05:00.000", "+000", "PolicyAgent"),
            ],
        ),
    ];

    for (artifact_id, records) in cases {
        let analysis = analyze_policy_records(artifact_id, &records);
        let transaction = &analysis.transactions[0];
        assert_eq!(
            transaction.state,
            SccmPolicyState::Contradictory,
            "{artifact_id}"
        );
        assert_eq!(transaction.confidence, SccmConfidence::Low, "{artifact_id}");
        assert_eq!(
            transaction.classification,
            SccmPolicyClassification::ContradictoryEvidence,
            "{artifact_id}"
        );
        assert_eq!(analysis.findings[0].class, SccmFindingClass::Symptom);
        assert!(analysis.findings[0].terminal_evidence.is_empty());
    }
}

#[test]
fn chronology_conflict_confirms_only_a_successful_ordered_prefix() {
    let cases = [
        ("policy-failure", "Request failed terminal", None),
        ("policy-deferred", "Request deferred", None),
        (
            "policy-success",
            "Request succeeded",
            Some(SccmPolicyPhase::Request),
        ),
    ];

    for (artifact_id, earlier, expected_last_confirmed) in cases {
        let records = vec![
            policy_record(earlier, "12:10:00.000", "+000", "PolicyAgent"),
            policy_record("Download succeeded", "12:05:00.000", "+000", "PolicyAgent"),
        ];
        let analysis = analyze_policy_records(artifact_id, &records);
        let transaction = &analysis.transactions[0];
        assert_eq!(
            transaction.phase,
            SccmPolicyPhase::Download,
            "{artifact_id}"
        );
        assert_eq!(
            transaction.state,
            SccmPolicyState::Contradictory,
            "{artifact_id}"
        );
        assert_eq!(
            transaction.condition,
            Some(SccmPolicyCondition::OrderingUnavailable),
            "{artifact_id}"
        );
        assert_eq!(
            transaction.last_confirmed_phase, expected_last_confirmed,
            "{artifact_id}"
        );
        assert_eq!(analysis.findings[0].class, SccmFindingClass::Symptom);
        assert!(analysis.findings[0].terminal_evidence.is_empty());
    }
}

#[test]
fn equal_and_noncomparable_cross_phase_times_are_ambiguous() {
    let cases = [
        (
            "policy-time",
            vec![
                policy_record("Request succeeded", "12:10:00.000", "+000", "PolicyAgent"),
                policy_record(
                    "Download failed terminal",
                    "12:10:00.000",
                    "+000",
                    "PolicyAgent",
                ),
            ],
        ),
        (
            "policy-offset",
            vec![
                policy_record("Request succeeded", "12:10:00.000", "+000", "PolicyAgent"),
                policy_record(
                    "Download failed terminal",
                    "12:11:00.000",
                    "+9999",
                    "PolicyAgent",
                ),
            ],
        ),
    ];

    for (artifact_id, records) in cases {
        let analysis = analyze_policy_records(artifact_id, &records);
        assert_eq!(
            analysis.transactions[0].state,
            SccmPolicyState::Contradictory
        );
        assert_eq!(analysis.transactions[0].confidence, SccmConfidence::Low);
        assert_eq!(analysis.findings[0].class, SccmFindingClass::Symptom);
        assert!(analysis.findings[0].terminal_evidence.is_empty());
    }
}
