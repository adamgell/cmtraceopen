use std::fs;
use std::path::{Path, PathBuf};

use cmtraceopen_parser::sccm::server::windows::{
    analyze_provider_admin_service, assess_server_intake, ProviderAdminServiceAnalysis,
    ProviderAdminServiceClassification, ProviderAdminServiceDisposition, ProviderAdminServiceLayer,
    ProviderAdminServicePhase, ProviderAdminServiceSourceLocalKind, ProviderAdminServiceState,
    ProviderAdminServiceSupportState, ProviderAdminServiceTimestampOrdering,
    SccmServerArtifactPayload, SccmServerIntakeAssessment, SccmServerIntakeError,
};
use cmtraceopen_parser::sccm::{SccmConfidence, SccmCoverageState, SccmRole};
use serde_json::{json, Value};

const SCENARIOS: [&str; 20] = [
    "admin-service-access-denied",
    "admin-service-auth-failure",
    "admin-service-backend-failure",
    "admin-service-parse-failed",
    "admin-service-skipped",
    "admin-service-success",
    "blocked-deferred",
    "contradictory-evidence",
    "iis-supplemental",
    "incomplete",
    "privacy-redaction",
    "provider-authz-denied",
    "provider-query-failure",
    "provider-retry",
    "provider-source-absent",
    "provider-source-capped",
    "provider-source-unsupported",
    "provider-success",
    "provider-timeout",
    "rotation-boundary",
];

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sccm/server/provider_and_admin_service")
}

fn load_manifest_and_payloads(scenario: &str) -> (Value, Vec<SccmServerArtifactPayload>) {
    let scenario_root = corpus_root().join(scenario);
    let manifest_json =
        fs::read_to_string(scenario_root.join("manifest.json")).expect("fixture manifest");
    let manifest: Value = serde_json::from_str(&manifest_json).expect("valid fixture manifest");
    let payloads = manifest["artifacts"]
        .as_array()
        .expect("artifact array")
        .iter()
        .filter_map(|artifact| {
            let relative_path = artifact["relativePath"].as_str()?;
            Some(SccmServerArtifactPayload {
                manifest_artifact_id: artifact["artifactId"]
                    .as_str()
                    .expect("artifact id")
                    .to_owned(),
                bytes: fs::read(scenario_root.join(Path::new(relative_path)))
                    .expect("fixture payload"),
            })
        })
        .collect();
    (manifest, payloads)
}

fn assess(scenario: &str) -> SccmServerIntakeAssessment {
    let (manifest, payloads) = load_manifest_and_payloads(scenario);
    assess_server_intake(&manifest.to_string(), &payloads)
        .unwrap_or_else(|error| panic!("{scenario}: canonical fixture intake: {error:?}"))
}

fn assess_parts(
    manifest: &Value,
    payloads: &[SccmServerArtifactPayload],
) -> Result<SccmServerIntakeAssessment, SccmServerIntakeError> {
    assess_server_intake(&manifest.to_string(), payloads)
}

fn analyze(scenario: &str) -> ProviderAdminServiceAnalysis {
    analyze_provider_admin_service(&assess(scenario))
}

fn expected(scenario: &str) -> Value {
    serde_json::from_str(
        &fs::read_to_string(corpus_root().join(scenario).join("expected.json"))
            .expect("expected fixture contract"),
    )
    .expect("valid expected fixture contract")
}

#[test]
fn all_provider_and_admin_service_fixtures_enter_through_canonical_intake() {
    for scenario in SCENARIOS {
        let analysis = analyze(scenario);
        assert_eq!(analysis.workflow, "providerAndAdminService", "{scenario}");
        assert_eq!(
            analysis.support_state,
            ProviderAdminServiceSupportState::SyntheticProfileOnly,
            "{scenario}"
        );
        assert!(!analysis.coverage.is_empty(), "{scenario}");
        assert!(analysis
            .profiles
            .iter()
            .all(|profile| profile.limitation.contains("Synthetic fixtures only")));
        assert!(analysis.cross_side_causal_claims.is_empty(), "{scenario}");
    }
}

#[derive(Clone, Copy)]
struct ExpectedTransaction {
    state: ProviderAdminServiceState,
    classification: ProviderAdminServiceClassification,
    confidence: SccmConfidence,
    ordering: ProviderAdminServiceTimestampOrdering,
}

fn expected_transactions(scenario: &str) -> &'static [ExpectedTransaction] {
    use ProviderAdminServiceClassification as Class;
    use ProviderAdminServiceState as State;
    use ProviderAdminServiceTimestampOrdering as Ordering;
    const SUCCESS: ExpectedTransaction = ExpectedTransaction {
        state: State::Succeeded,
        classification: Class::Success,
        confidence: SccmConfidence::High,
        ordering: Ordering::Usable,
    };
    const FAILURE: ExpectedTransaction = ExpectedTransaction {
        state: State::Failed,
        classification: Class::ConfirmedFailure,
        confidence: SccmConfidence::High,
        ordering: Ordering::Usable,
    };
    const BLOCKED: ExpectedTransaction = ExpectedTransaction {
        state: State::BlockedOrDeferred,
        classification: Class::BlockedOrDeferred,
        confidence: SccmConfidence::Moderate,
        ordering: Ordering::Usable,
    };
    const INCOMPLETE: ExpectedTransaction = ExpectedTransaction {
        state: State::Incomplete,
        classification: Class::InsufficientEvidence,
        confidence: SccmConfidence::Low,
        ordering: Ordering::Usable,
    };
    const UNORDERED: ExpectedTransaction = ExpectedTransaction {
        state: State::Incomplete,
        classification: Class::InsufficientEvidence,
        confidence: SccmConfidence::Low,
        ordering: Ordering::Unusable,
    };
    match scenario {
        "admin-service-auth-failure"
        | "admin-service-backend-failure"
        | "provider-authz-denied"
        | "provider-query-failure" => &[FAILURE],
        "admin-service-success" | "iis-supplemental" | "provider-retry" | "provider-success" => {
            &[SUCCESS]
        }
        "blocked-deferred" => &[BLOCKED],
        "contradictory-evidence" | "incomplete" => &[INCOMPLETE],
        "privacy-redaction" => &[SUCCESS, SUCCESS],
        "provider-timeout" => &[UNORDERED],
        _ => &[],
    }
}

#[test]
fn complete_fixture_matrix_runs_through_the_production_analyzer() {
    for scenario in SCENARIOS {
        let analysis = analyze(scenario);
        let expected_contract = expected(scenario);
        let public = serde_json::to_value(&analysis).unwrap_or_else(|error| {
            panic!("{scenario}: shared review contract must serialize: {error}")
        });
        let expected = expected_transactions(scenario);
        assert_eq!(analysis.transactions.len(), expected.len(), "{scenario}");
        for (transaction, expected) in analysis.transactions.iter().zip(expected) {
            assert_eq!(transaction.state, expected.state, "{scenario}");
            assert_eq!(
                transaction.classification, expected.classification,
                "{scenario}"
            );
            assert_eq!(transaction.confidence, expected.confidence, "{scenario}");
            assert_eq!(
                transaction.confidence_ceiling, expected.confidence,
                "{scenario}"
            );
            assert_eq!(
                transaction.timestamp_ordering, expected.ordering,
                "{scenario}"
            );
            assert_eq!(transaction.source_version, "5.00.TEST", "{scenario}");
            assert_eq!(
                transaction.producer_role,
                match transaction.layer {
                    ProviderAdminServiceLayer::Provider => SccmRole::Provider,
                    ProviderAdminServiceLayer::AdminService => SccmRole::AdminService,
                },
                "{scenario}"
            );
            assert_eq!(
                transaction.correlation_eligible,
                matches!(
                    transaction.state,
                    ProviderAdminServiceState::Succeeded | ProviderAdminServiceState::Failed
                ),
                "{scenario}"
            );
            assert_eq!(
                transaction.next_artifact_request.is_some(),
                matches!(
                    transaction.state,
                    ProviderAdminServiceState::Incomplete
                        | ProviderAdminServiceState::BlockedOrDeferred
                ),
                "{scenario}"
            );
        }

        let expected_request = matches!(
            scenario,
            "admin-service-access-denied"
                | "admin-service-parse-failed"
                | "admin-service-skipped"
                | "blocked-deferred"
                | "contradictory-evidence"
                | "incomplete"
                | "provider-source-absent"
                | "provider-source-capped"
                | "provider-source-unsupported"
                | "provider-timeout"
                | "rotation-boundary"
        );
        assert_eq!(
            analysis.artifact_requests.len(),
            usize::from(expected_request),
            "{scenario}"
        );

        let actual_coverage = public["coverage"]
            .as_array()
            .expect("public coverage")
            .iter()
            .map(|coverage| {
                json!({
                    "artifactId": coverage["artifactId"],
                    "sourceId": coverage["sourceId"],
                    "producerRole": coverage["producerRole"],
                    "state": coverage["state"],
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(
            Value::Array(actual_coverage),
            expected_contract["expectedCoverage"],
            "{scenario}"
        );

        let actual_transactions = public["transactions"]
            .as_array()
            .expect("public transactions")
            .iter()
            .map(|transaction| {
                json!({
                    "layer": transaction["layer"],
                    "state": transaction["state"],
                    "classification": transaction["classification"],
                    "confidence": transaction["confidence"],
                    "timestampOrdering": transaction["timestampOrdering"],
                    "terminalEvidence": transaction["terminalEvidence"],
                    "lastSuccessfulPhase": transaction["lastSuccessfulPhase"],
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(
            Value::Array(actual_transactions),
            expected_contract["expectedTransactions"],
            "{scenario}"
        );

        let actual_local_kinds = public["sourceLocalObservations"]
            .as_array()
            .expect("source-local observations")
            .iter()
            .map(|observation| observation["kind"].clone())
            .collect::<Vec<_>>();
        assert_eq!(
            Value::Array(actual_local_kinds),
            expected_contract["expectedSourceLocalKinds"],
            "{scenario}"
        );

        let actual_request = public["artifactRequests"]
            .as_array()
            .expect("artifact requests")
            .first()
            .map(|request| {
                json!({
                    "logicalId": request["logicalId"],
                    "role": request["role"],
                })
            })
            .unwrap_or(Value::Null);
        assert_eq!(
            actual_request, expected_contract["expectedArtifactRequest"],
            "{scenario}"
        );
    }
}

#[test]
fn phase_reduction_covers_success_failure_deferred_recovery_and_contradiction() {
    let provider_success = analyze("provider-success");
    assert_eq!(
        provider_success.transactions[0]
            .observations
            .iter()
            .map(|observation| observation.phase)
            .collect::<Vec<_>>(),
        vec![
            ProviderAdminServicePhase::Receive,
            ProviderAdminServicePhase::AuthenticateOrAuthorize,
            ProviderAdminServicePhase::ExecuteProviderOperation,
            ProviderAdminServicePhase::Respond,
            ProviderAdminServicePhase::RecordOutcome,
        ]
    );

    let retry = analyze("provider-retry");
    assert_eq!(
        retry.transactions[0]
            .observations
            .iter()
            .filter(|observation| {
                observation.phase == ProviderAdminServicePhase::ExecuteProviderOperation
            })
            .map(|observation| observation.disposition)
            .collect::<Vec<_>>(),
        vec![
            ProviderAdminServiceDisposition::RetryableFailure,
            ProviderAdminServiceDisposition::Succeeded,
        ]
    );
    assert_eq!(
        retry.transactions[0].last_successful_phase,
        Some(ProviderAdminServicePhase::RecordOutcome)
    );

    let contradiction = analyze("contradictory-evidence");
    assert!(contradiction.transactions[0].terminal_evidence);
    assert_eq!(
        contradiction.transactions[0].state,
        ProviderAdminServiceState::Incomplete
    );
    assert!(!contradiction.transactions[0].correlation_eligible);

    let blocked = analyze("blocked-deferred");
    assert_eq!(
        blocked.transactions[0].state,
        ProviderAdminServiceState::BlockedOrDeferred
    );
    assert_eq!(
        blocked.transactions[0].last_successful_phase,
        Some(ProviderAdminServicePhase::AuthenticateOrAuthorize)
    );
}

#[test]
fn one_artifact_with_two_exact_keys_produces_two_transactions() {
    let (mut manifest, mut payloads) = load_manifest_and_payloads("provider-success");
    let original = String::from_utf8(payloads[0].bytes.clone()).expect("UTF-8 fixture");
    let peer = original
        .replace(
            "11111111-1111-1111-1111-111111111111",
            "99999999-9999-9999-9999-999999999999",
        )
        .replace(
            "safe-operation-read-device",
            "safe-operation-read-device-peer",
        );
    payloads[0].bytes.extend_from_slice(peer.as_bytes());
    manifest["artifacts"][0]["bytesCopied"] = json!(payloads[0].bytes.len());

    let analysis = analyze_provider_admin_service(
        &assess_parts(&manifest, &payloads).expect("multi-request canonical intake"),
    );
    assert_eq!(analysis.transactions.len(), 2);
    assert_ne!(
        analysis.transactions[0].key.request_handle,
        analysis.transactions[1].key.request_handle
    );
    assert!(analysis
        .transactions
        .iter()
        .all(|transaction| transaction.state == ProviderAdminServiceState::Succeeded));
}

#[test]
fn timestamp_ordering_is_provenance_driven_and_valid_input_order_is_irrelevant() {
    let invalid = analyze("provider-timeout");
    assert_eq!(invalid.transactions.len(), 1);
    assert_eq!(
        invalid.transactions[0].timestamp_ordering,
        ProviderAdminServiceTimestampOrdering::Unusable
    );
    assert_eq!(
        invalid.transactions[0].state,
        ProviderAdminServiceState::Incomplete
    );
    assert!(!invalid.transactions[0].correlation_eligible);

    let baseline = analyze("provider-success");
    let (mut manifest, mut payloads) = load_manifest_and_payloads("provider-success");
    let content = String::from_utf8(payloads[0].bytes.clone()).expect("UTF-8 fixture");
    let reversed = content.lines().rev().collect::<Vec<_>>().join("\n") + "\n";
    payloads[0].bytes = reversed.into_bytes();
    manifest["artifacts"][0]["bytesCopied"] = json!(payloads[0].bytes.len());
    let reordered = analyze_provider_admin_service(
        &assess_parts(&manifest, &payloads).expect("reordered canonical intake"),
    );
    assert_eq!(
        reordered.transactions[0].state,
        baseline.transactions[0].state
    );
    assert_eq!(
        reordered.transactions[0]
            .observations
            .iter()
            .map(|observation| observation.phase)
            .collect::<Vec<_>>(),
        baseline.transactions[0]
            .observations
            .iter()
            .map(|observation| observation.phase)
            .collect::<Vec<_>>()
    );
}

#[test]
fn coverage_gaps_are_scoped_to_the_exact_topology_subject() {
    let (mut manifest, mut payloads) = load_manifest_and_payloads("provider-success");
    let (gap_manifest, gap_payloads) = load_manifest_and_payloads("provider-source-capped");
    let mut gap = gap_manifest["artifacts"][0].clone();
    gap["originalBasename"] = json!("Smsprov.lo_");
    gap["rotation"]["kind"] = json!("lo_");
    gap["relativePath"] =
        json!("evidence/sccm/server/provider/server-provider/subject-provider/lo_/Smsprov.lo_");
    manifest["artifacts"]
        .as_array_mut()
        .expect("artifact array")
        .push(gap);
    payloads.extend(gap_payloads);

    let analysis = analyze_provider_admin_service(
        &assess_parts(&manifest, &payloads).expect("mixed-coverage canonical intake"),
    );
    let transaction = &analysis.transactions[0];
    assert_eq!(transaction.state, ProviderAdminServiceState::Incomplete);
    assert_eq!(
        transaction.coverage_gap_artifact_ids,
        vec!["coverage-provider-capped"]
    );
    assert!(transaction.next_artifact_request.is_some());
    assert!(!transaction.correlation_eligible);
}

#[test]
fn public_projection_is_privacy_safe_and_admin_service_has_its_own_role() {
    let assessment = assess("privacy-redaction");
    let analysis = analyze_provider_admin_service(&assessment);
    assert!(analysis
        .transactions
        .iter()
        .any(|transaction| transaction.producer_role == SccmRole::AdminService));
    assert!(analysis
        .source_local_observations
        .iter()
        .all(|observation| {
            observation.kind == ProviderAdminServiceSourceLocalKind::PrivacyRedacted
                && !observation.correlation_eligible
        }));
    let public = serde_json::to_string(&analysis).expect("privacy-safe report serializes");
    for private in [
        "99999999-9999-9999-9999-999999999999",
        "safe-operation-provider-privacy",
        "safe-operation-admin-privacy",
        "synthetic.user@example.invalid",
        "Bearer",
        "SELECT",
        "provider-local",
        "admin-service-lab",
    ] {
        assert!(!public.contains(private), "private shape leaked: {private}");
    }
    assert!(public.contains("cmtraceopen.request.sha256.v1:"));
    assert!(public.contains("cmtraceopen.operation.sha256.v1:"));
}

#[test]
fn canonical_intake_seals_role_and_authority_before_analysis() {
    let (mut manifest, payloads) = load_manifest_and_payloads("admin-service-success");
    manifest["topology"]["rolesObserved"] = json!(["adminService", "provider"]);
    manifest["artifacts"][0]["producerRole"] = json!("provider");
    assert_eq!(
        assess_parts(&manifest, &payloads),
        Err(SccmServerIntakeError::InvalidArtifact)
    );

    let mut assessment = assess("provider-success");
    assessment.coverage[0].state = SccmCoverageState::Capped;
    let analysis = analyze_provider_admin_service(&assessment);
    assert_eq!(
        analysis.support_state,
        ProviderAdminServiceSupportState::IntakeAuthorityInvalid
    );
    assert!(analysis.transactions.is_empty());
    assert!(analysis.coverage.is_empty());
}
