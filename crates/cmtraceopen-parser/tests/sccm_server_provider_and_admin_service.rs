use std::fs;
use std::path::PathBuf;

use cmtraceopen_parser::sccm::server::windows::provider_and_admin_service::{
    analyze_provider_admin_service, ProviderAdminServiceArtifact, ProviderAdminServiceLayer,
};
use cmtraceopen_parser::sccm::{
    normalize_ccm_artifact, SccmArtifact, SccmCoverageState, SccmRole, SccmRotation,
};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sccm/server/provider_and_admin_service")
}

fn captured_fixture(
    scenario: &str,
    artifact_id: &str,
    source_id: &str,
    endpoint_id: &str,
    role: SccmRole,
    source_version: Option<&str>,
    basename: &str,
) -> ProviderAdminServiceArtifact {
    let content = fs::read_to_string(fixture_root().join(scenario).join("evidence").join(
        if source_id == "server-provider" {
            "server-provider/provider-local/current/Smsprov.log"
        } else {
            "server-admin-service/admin-service-lab/current/AdminService.log"
        },
    ))
    .expect("fixture log is readable");
    let evidence = normalize_ccm_artifact(
        SccmArtifact {
            artifact_id: artifact_id.to_owned(),
            display_name: basename.to_owned(),
            original_path: None,
            host: Some("safe:server:lab-provider-01".to_owned()),
            role: role.clone(),
            configmgr_version: source_version.map(str::to_owned),
            collected_at_utc: Some("2026-07-30T21:00:00Z".to_owned()),
            rotation: SccmRotation::Current,
            coverage: SccmCoverageState::Captured,
            encoding: Some("utf-8".to_owned()),
        },
        &content,
    );
    ProviderAdminServiceArtifact {
        artifact_id: artifact_id.to_owned(),
        source_id: source_id.to_owned(),
        endpoint_id: endpoint_id.to_owned(),
        producer_host_handle: Some("safe:server:lab-provider-01".to_owned()),
        producer_role: role,
        source_version: source_version.map(str::to_owned),
        coverage: SccmCoverageState::Captured,
        evidence,
    }
}

#[test]
fn provider_and_admin_service_requests_with_same_id_do_not_join() {
    let provider = captured_fixture(
        "privacy-redaction",
        "privacy-provider-current",
        "server-provider",
        "provider-local",
        SccmRole::Provider,
        Some("5.00.TEST.0001"),
        "Smsprov.log",
    );
    let admin = captured_fixture(
        "privacy-redaction",
        "privacy-admin-current",
        "server-admin-service",
        "admin-service-lab",
        SccmRole::Provider,
        Some("5.00.TEST.0001"),
        "AdminService.log",
    );

    let report = analyze_provider_admin_service(&[provider, admin]);

    assert_eq!(report.transactions.len(), 2);
    assert!(report
        .transactions
        .iter()
        .any(|transaction| transaction.layer == ProviderAdminServiceLayer::Provider));
    assert!(report
        .transactions
        .iter()
        .any(|transaction| transaction.layer == ProviderAdminServiceLayer::AdminService));
    assert_ne!(
        report.transactions[0].transaction_id,
        report.transactions[1].transaction_id
    );
    let public = serde_json::to_string(&report).expect("public report serializes");
    assert!(!public.contains("synthetic.user@example.invalid"));
    assert!(!public.contains("Bearer"));
    assert!(!public.contains("SELECT"));
}

#[test]
fn provider_success_has_monotonic_layer_specific_phases() {
    let provider = captured_fixture(
        "provider-success",
        "provider-success-current",
        "server-provider",
        "provider-local",
        SccmRole::Provider,
        Some("5.00.TEST.0001"),
        "Smsprov.log",
    );

    let report = analyze_provider_admin_service(&[provider]);
    let transaction = &report.transactions[0];

    assert_eq!(transaction.layer, ProviderAdminServiceLayer::Provider);
    assert_eq!(transaction.state, "succeeded");
    assert_eq!(transaction.classification, "success");
    assert_eq!(transaction.confidence, "high");
    assert!(transaction.terminal_evidence);
    assert_eq!(
        transaction
            .observations
            .iter()
            .map(|observation| observation.phase.as_str())
            .collect::<Vec<_>>(),
        vec![
            "receive",
            "authenticateOrAuthorize",
            "executeProviderOperation",
            "respond",
            "recordOutcome"
        ]
    );
}

#[test]
fn unsupported_version_is_explicitly_incomplete_and_not_exactly_keyed() {
    let provider = captured_fixture(
        "provider-success",
        "provider-success-current",
        "server-provider",
        "provider-local",
        SccmRole::Provider,
        Some("5.00.9999.0001"),
        "Smsprov.log",
    );

    let report = analyze_provider_admin_service(&[provider]);

    assert!(report.transactions.is_empty());
    assert_eq!(report.gaps.len(), 1);
    assert_eq!(report.gaps[0].reason, "unvalidated source version");
}

#[test]
fn explicit_provider_authorization_failure_is_terminal_without_imagined_phases() {
    let provider = captured_fixture(
        "provider-authz-denied",
        "provider-authz-current",
        "server-provider",
        "provider-local",
        SccmRole::Provider,
        Some("5.00.TEST.0001"),
        "Smsprov.log",
    );

    let report = analyze_provider_admin_service(&[provider]);
    let transaction = &report.transactions[0];

    assert_eq!(transaction.state, "failed");
    assert_eq!(transaction.classification, "confirmedFailure");
    assert_eq!(transaction.confidence, "high");
    assert!(transaction.terminal_evidence);
    assert_eq!(transaction.observations.len(), 3);
}

#[test]
fn admin_service_backend_failure_uses_admin_service_phases() {
    let admin = captured_fixture(
        "admin-service-backend-failure",
        "admin-backend-current",
        "server-admin-service",
        "admin-service-lab",
        SccmRole::Provider,
        Some("5.00.TEST.0001"),
        "AdminService.log",
    );

    let report = analyze_provider_admin_service(&[admin]);
    let transaction = &report.transactions[0];

    assert_eq!(transaction.layer, ProviderAdminServiceLayer::AdminService);
    assert_eq!(transaction.state, "failed");
    assert_eq!(transaction.classification, "confirmedFailure");
    assert_eq!(
        transaction
            .observations
            .iter()
            .map(|observation| observation.phase.as_str())
            .collect::<Vec<_>>(),
        vec![
            "receive",
            "authenticateOrAuthorize",
            "route",
            "executeBackendOperation",
            "recordOutcome"
        ]
    );
}
