use std::fs;
use std::path::{Path, PathBuf};

use cmtraceopen_parser::sccm::server::windows::{
    analyze_provider_admin_service, assess_server_intake, ProviderAdminServiceAnalysis,
    ProviderAdminServiceClassification, ProviderAdminServiceDisposition, ProviderAdminServiceLayer,
    ProviderAdminServicePhase, ProviderAdminServiceSourceLocalKind, ProviderAdminServiceState,
    ProviderAdminServiceSupportState, ProviderAdminServiceTimestampOrdering,
    SccmServerArtifactPayload, SccmServerIntakeAssessment, SccmServerIntakeError,
};
use cmtraceopen_parser::sccm::{SccmCoverageState, SccmKeyConfidence, SccmRole};
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

fn make_provider_host_two(artifact: &mut Value, artifact_id: &str) {
    artifact["artifactId"] = json!(artifact_id);
    artifact["producerHostHandle"] = json!("synthetic:host:provider-02");
    let basename = artifact["originalBasename"]
        .as_str()
        .expect("provider basename");
    artifact["relativePath"] = json!(format!(
        "evidence/sccm/server/provider/server-provider/subject-provider/root-aaaaaaaa/current/{basename}"
    ));
}

fn expected(scenario: &str) -> Value {
    serde_json::from_str(
        &fs::read_to_string(corpus_root().join(scenario).join("expected.json"))
            .expect("expected fixture contract"),
    )
    .expect("valid expected fixture contract")
}

fn assert_exact_oracle(scenario: &str, actual: &Value, oracle: &Value) {
    assert_eq!(
        actual, oracle,
        "{scenario}: complete public contract drifted"
    );
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

#[test]
fn complete_fixture_matrix_runs_through_the_production_analyzer() {
    for scenario in SCENARIOS {
        let analysis = analyze(scenario);
        let expected_contract = expected(scenario);
        let public = serde_json::to_value(&analysis).unwrap_or_else(|error| {
            panic!("{scenario}: shared review contract must serialize: {error}")
        });
        assert_exact_oracle(scenario, &public, &expected_contract);
    }
}

#[test]
fn exact_oracle_gate_detects_mutation_of_every_material_public_surface() {
    let mutations = [
        ("provider-success", "/coverage/0/producerRole"),
        ("provider-success", "/coverage/0/producerHostHandle"),
        ("provider-success", "/coverage/0/workflowSubjectHandle"),
        ("provider-success", "/coverage/0/sourceVersion"),
        (
            "provider-success",
            "/profiles/0/extractionProfile/profileId",
        ),
        ("provider-success", "/transactions/0/transactionId"),
        ("provider-success", "/transactions/0/key/requestHandle"),
        ("provider-success", "/transactions/0/key/operationHandle"),
        ("provider-success", "/transactions/0/key/confidence"),
        (
            "provider-success",
            "/transactions/0/key/extractionProfile/profileId",
        ),
        (
            "provider-success",
            "/transactions/0/observations/0/observationId",
        ),
        (
            "provider-success",
            "/transactions/0/observations/0/evidence/0/entryId",
        ),
        ("blocked-deferred", "/transactions/0/coverageGapArtifactIds"),
        (
            "blocked-deferred",
            "/transactions/0/nextArtifactRequests/0/request/reason",
        ),
        (
            "blocked-deferred",
            "/transactions/0/nextArtifactRequests/0/producerHostHandle",
        ),
        ("blocked-deferred", "/findings/0/finding/class"),
        ("blocked-deferred", "/findings/0/finding/severity"),
        ("blocked-deferred", "/findings/0/finding/evidence/0/entryId"),
        (
            "provider-source-capped",
            "/findings/0/finding/coverageGaps/0/artifactId",
        ),
        (
            "provider-source-capped",
            "/artifactRequests/0/workflowSubjectHandle",
        ),
        (
            "rotation-boundary",
            "/sourceLocalObservations/0/artifactIds",
        ),
    ];
    for (scenario, pointer) in mutations {
        let oracle = expected(scenario);
        let actual = serde_json::to_value(analyze(scenario)).expect("analysis serializes");
        assert_exact_oracle(scenario, &actual, &oracle);
        let mut mutated = actual;
        *mutated
            .pointer_mut(pointer)
            .unwrap_or_else(|| panic!("{scenario}: mutation pointer must exist: {pointer}")) =
            json!("oracle-mutation");
        assert_ne!(mutated, oracle, "{scenario}: oracle missed {pointer}");
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
    assert_eq!(
        retry.transactions[0].state,
        ProviderAdminServiceState::Recovered
    );
    assert_eq!(
        retry.transactions[0].classification,
        ProviderAdminServiceClassification::Recovered
    );

    let contradiction = analyze("contradictory-evidence");
    assert!(contradiction.transactions[0].terminal_evidence);
    assert_eq!(
        contradiction.transactions[0].state,
        ProviderAdminServiceState::Contradictory
    );
    assert_eq!(
        contradiction.transactions[0].classification,
        ProviderAdminServiceClassification::ContradictoryEvidence
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
fn one_artifact_with_two_registered_low_confidence_keys_produces_two_transactions() {
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
    assert!(analysis.transactions.iter().all(|transaction| {
        transaction.key.confidence == SccmKeyConfidence::Low && !transaction.correlation_eligible
    }));
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
    assert!(!transaction.next_artifact_requests.is_empty());
    assert!(!transaction.correlation_eligible);
}

#[test]
fn coverage_gaps_are_scoped_to_the_producer_host_as_well_as_the_subject() {
    let (mut manifest, mut payloads) = load_manifest_and_payloads("provider-success");
    let (gap_manifest, gap_payloads) = load_manifest_and_payloads("provider-source-capped");
    let mut gap = gap_manifest["artifacts"][0].clone();
    make_provider_host_two(&mut gap, "coverage-provider-capped");
    gap["originalBasename"] = json!("Smsprov.lo_");
    gap["rotation"]["kind"] = json!("lo_");
    gap["relativePath"] = json!(
        "evidence/sccm/server/provider/server-provider/subject-provider/root-aaaaaaaa/lo_/Smsprov.lo_"
    );
    let gap_id = gap["artifactId"].as_str().expect("gap id").to_owned();
    manifest["artifacts"]
        .as_array_mut()
        .expect("artifact array")
        .push(gap);
    payloads.extend(gap_payloads.into_iter().map(|mut payload| {
        payload.manifest_artifact_id = gap_id.clone();
        payload
    }));

    let analysis = analyze_provider_admin_service(
        &assess_parts(&manifest, &payloads).expect("cross-host coverage intake"),
    );
    assert_eq!(analysis.transactions.len(), 1);
    assert_eq!(
        analysis.transactions[0].state,
        ProviderAdminServiceState::Succeeded
    );
    assert!(analysis.transactions[0]
        .coverage_gap_artifact_ids
        .is_empty());
    assert!(analysis.transactions[0].next_artifact_requests.is_empty());
    assert_eq!(analysis.artifact_requests.len(), 1);
    assert_eq!(
        analysis.artifact_requests[0].producer_host_handle,
        "synthetic:host:provider-02"
    );
}

#[test]
fn transaction_identity_includes_producer_host() {
    let (mut manifest, mut payloads) = load_manifest_and_payloads("provider-success");
    let mut second = manifest["artifacts"][0].clone();
    make_provider_host_two(&mut second, "provider-retry-current");
    let second_id = second["artifactId"].as_str().expect("second id").to_owned();
    manifest["artifacts"]
        .as_array_mut()
        .expect("artifact array")
        .push(second);
    let mut second_payload = payloads[0].clone();
    second_payload.manifest_artifact_id = second_id;
    payloads.push(second_payload);

    let analysis = analyze_provider_admin_service(
        &assess_parts(&manifest, &payloads).expect("two-host canonical intake"),
    );
    assert_eq!(analysis.transactions.len(), 2);
    assert_ne!(
        analysis.transactions[0].transaction_id,
        analysis.transactions[1].transaction_id
    );
    assert_ne!(
        analysis.transactions[0].key.producer_host_handle,
        analysis.transactions[1].key.producer_host_handle
    );
}

#[test]
fn independent_provider_and_admin_service_gaps_keep_two_scoped_requests() {
    let (mut provider, _) = load_manifest_and_payloads("provider-source-absent");
    let (admin, _) = load_manifest_and_payloads("admin-service-access-denied");
    provider["topology"]["rolesObserved"] = json!(["provider", "adminService"]);
    provider["artifacts"]
        .as_array_mut()
        .expect("provider artifacts")
        .push(admin["artifacts"][0].clone());

    let analysis = analyze_provider_admin_service(
        &assess_parts(&provider, &[]).expect("two-layer coverage intake"),
    );
    assert_eq!(analysis.artifact_requests.len(), 2);
    assert!(analysis.artifact_requests.iter().any(|request| {
        request.layer == ProviderAdminServiceLayer::Provider
            && request.producer_role == SccmRole::Provider
            && request.request.logical_id == "smsprov"
    }));
    assert!(analysis.artifact_requests.iter().any(|request| {
        request.layer == ProviderAdminServiceLayer::AdminService
            && request.producer_role == SccmRole::AdminService
            && request.request.logical_id == "adminService"
    }));
}

#[test]
fn forged_or_unregistered_profile_never_creates_a_transaction() {
    let (mut manifest, mut payloads) = load_manifest_and_payloads("provider-success");
    let forged = String::from_utf8(payloads[0].bytes.clone())
        .expect("UTF-8 fixture")
        .replace(
            "ProfileId=provider-server-5.00.test-v1",
            "ProfileId=provider-server-5.00.test-v1-forged",
        );
    payloads[0].bytes = forged.into_bytes();
    manifest["artifacts"][0]["bytesCopied"] = json!(payloads[0].bytes.len());
    let analysis = analyze_provider_admin_service(
        &assess_parts(&manifest, &payloads).expect("forged profile remains valid raw intake"),
    );
    assert!(analysis.transactions.is_empty());
    assert!(analysis.findings.is_empty());
    assert!(!serde_json::to_string(&analysis)
        .expect("analysis serializes")
        .contains("\"confidence\":\"exact\""));
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
