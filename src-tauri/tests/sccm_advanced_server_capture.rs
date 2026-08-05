use std::fs;
use std::time::Instant;

use app_lib::sccm::collector::{
    advanced_source_contracts, capture_advanced_authorized, PrivateAdvancedSourceFact,
    PrivateSccmEnvironment, SccmAdvancedCapabilityStore, SccmAdvancedCaptureAuthorizationRequest,
    SccmCaptureRoot, SccmCollectorError, SccmDetectedRole, SccmDiscoveryBasis,
    ADVANCED_CAPTURE_BYTE_LIMIT,
};
use app_lib::sccm::{SccmCoverageState, SccmRole};

fn operator_environment() -> PrivateSccmEnvironment {
    PrivateSccmEnvironment {
        supported: true,
        configmgr_version: Some("5.00.9141.1000".to_owned()),
        roles: vec![SccmDetectedRole {
            role: SccmRole::SiteServer,
            basis: SccmDiscoveryBasis::Registry,
        }],
        private_host: Some("PRIVATE-HOST".to_owned()),
        private_site_code: Some("ABC".to_owned()),
        ..PrivateSccmEnvironment::default()
    }
}

fn request(root: &str, source_id: &str) -> SccmAdvancedCaptureAuthorizationRequest {
    let contract = advanced_source_contracts()
        .iter()
        .find(|contract| contract.source_id == source_id)
        .unwrap();
    SccmAdvancedCaptureAuthorizationRequest {
        card_id: contract.card_id.to_owned(),
        card_version: contract.card_version.to_owned(),
        source_id: contract.source_id.to_owned(),
        role_scope: contract.role_scopes[0].to_owned(),
        path_class: contract.path_classes[0].to_owned(),
        expected_source_version: Some("5.00.9141.1000".to_owned()),
        selected_root: root.to_owned(),
    }
}

#[test]
fn advanced_contract_is_exactly_the_six_capture_only_sources() {
    let contracts = advanced_source_contracts();
    assert_eq!(contracts.len(), 6);
    assert_eq!(
        contracts
            .iter()
            .map(|contract| contract.basename)
            .collect::<Vec<_>>(),
        [
            "smspxe.log",
            "crp.log",
            "srsrp.log",
            "CloudMgr.log",
            "SMS_Cloud_ProxyConnector.log",
            "BgbServer.log",
        ]
    );
    assert!(contracts
        .iter()
        .all(|contract| contract.card_version == "1.0.0"));
    assert!(contracts.iter().all(|contract| {
        !contract.source_id.to_ascii_lowercase().contains("sql")
            && contract
                .path_classes
                .iter()
                .all(|path| !path.contains("Database"))
    }));
}

#[test]
fn operator_declared_capture_retains_only_current_and_lo_with_source_local_caps() {
    let source = tempfile::tempdir().unwrap();
    fs::write(source.path().join("CloudMgr.log"), b"current").unwrap();
    fs::write(source.path().join("CloudMgr.lo_"), b"previous").unwrap();
    fs::write(
        source.path().join("CloudMgr.log.1"),
        b"numbered-must-not-ship",
    )
    .unwrap();
    fs::write(
        source.path().join("CloudMgr-copy.log"),
        b"similar-must-not-ship",
    )
    .unwrap();
    let output = tempfile::tempdir().unwrap();
    let mut store = SccmAdvancedCapabilityStore::default();
    let capability = store
        .authorize(
            &operator_environment(),
            request(source.path().to_str().unwrap(), "advanced-cloud-manager"),
            Instant::now(),
        )
        .unwrap();
    let authorization = store
        .consume(&capability.capability_handle, Instant::now())
        .unwrap();
    let bundle = output.path().join("bundle");
    let result = capture_advanced_authorized(authorization, &bundle).unwrap();

    assert_eq!(result.artifact_count, 2);
    assert_eq!(result.retained_bytes, 15);
    assert_eq!(result.sources.len(), 2);
    assert!(result
        .sources
        .iter()
        .all(|source| source.role == SccmRole::Unknown("unclassified".to_owned())));
    let manifest = fs::read_to_string(bundle.join("sccm-server-manifest.json")).unwrap();
    assert!(manifest.contains("\"sourceKind\": \"advancedCapture\""));
    assert!(manifest.contains("\"roleProvenance\": \"operatorDeclared\""));
    assert!(manifest.contains("\"state\": \"operatorDeclared\""));
    assert!(!manifest.contains(source.path().to_string_lossy().as_ref()));
    assert!(!manifest.contains("PRIVATE-HOST"));
    assert!(!manifest.contains("numbered-must-not-ship"));
    assert!(!manifest.contains("similar-must-not-ship"));
    assert!(!bundle
        .join("evidence")
        .to_string_lossy()
        .contains(source.path().to_string_lossy().as_ref()));
}

#[test]
fn operator_declared_missing_candidate_is_unsupported_not_absent() {
    let source = tempfile::tempdir().unwrap();
    let output = tempfile::tempdir().unwrap();
    let mut store = SccmAdvancedCapabilityStore::default();
    let capability = store
        .authorize(
            &operator_environment(),
            request(source.path().to_str().unwrap(), "advanced-reporting"),
            Instant::now(),
        )
        .unwrap();
    let authorization = store
        .consume(&capability.capability_handle, Instant::now())
        .unwrap();
    let bundle = output.path().join("bundle");
    let result = capture_advanced_authorized(authorization, &bundle).unwrap();

    assert_eq!(result.artifact_count, 0);
    assert_eq!(result.sources[0].state, SccmCoverageState::Unsupported);
    let manifest = fs::read_to_string(bundle.join("sccm-server-manifest.json")).unwrap();
    assert!(manifest.contains("\"captureState\": \"unsupported\""));
    assert!(!manifest.contains("\"captureState\": \"absent\""));
}

#[test]
fn hard_link_to_an_external_source_is_rejected_without_copying_bytes() {
    let external = tempfile::tempdir().unwrap();
    let source = tempfile::tempdir().unwrap();
    let external_file = external.path().join("CloudMgr.log");
    fs::write(&external_file, b"external-must-not-ship").unwrap();
    fs::hard_link(&external_file, source.path().join("CloudMgr.log")).unwrap();

    let mut store = SccmAdvancedCapabilityStore::default();
    let now = Instant::now();
    let capability = store
        .authorize(
            &operator_environment(),
            request(source.path().to_str().unwrap(), "advanced-cloud-manager"),
            now,
        )
        .unwrap();
    let authorization = store.consume(&capability.capability_handle, now).unwrap();
    let output = tempfile::tempdir().unwrap();
    let bundle = output.path().join("bundle");

    assert_eq!(
        capture_advanced_authorized(authorization, &bundle),
        Err(SccmCollectorError::AdvancedAuthorizationRejected)
    );
    assert!(!bundle.join("evidence").exists());
}

#[test]
fn bgb_matching_management_point_fact_is_observed() {
    let source = tempfile::tempdir().unwrap();
    fs::write(source.path().join("BgbServer.log"), b"bgb").unwrap();
    let mut environment = operator_environment();
    environment.roles.push(SccmDetectedRole {
        role: SccmRole::ManagementPoint,
        basis: SccmDiscoveryBasis::Registry,
    });
    environment.roots.push(SccmCaptureRoot {
        role: SccmRole::ManagementPoint,
        path: source.path().to_owned(),
    });
    environment
        .advanced_source_facts
        .push(PrivateAdvancedSourceFact {
            source_id: "advanced-client-notification-bgb".to_owned(),
            role_scope: "managementPoint".to_owned(),
            path_class: "configuredRoleLogRoot".to_owned(),
            root: source.path().to_owned(),
            source_version: Some("5.00.9141.1000".to_owned()),
            pxe_enabled: false,
        });
    let mut request = request(
        source.path().to_str().unwrap(),
        "advanced-client-notification-bgb",
    );
    request.role_scope = "managementPoint".to_owned();
    let mut store = SccmAdvancedCapabilityStore::default();
    let capability = store
        .authorize(&environment, request, Instant::now())
        .unwrap();
    let authorization = store
        .consume(&capability.capability_handle, Instant::now())
        .unwrap();
    let output = tempfile::tempdir().unwrap();
    let bundle = output.path().join("bundle");
    capture_advanced_authorized(authorization, &bundle).unwrap();
    let manifest = fs::read_to_string(bundle.join("sccm-server-manifest.json")).unwrap();

    assert!(manifest.contains("\"producerRole\": \"managementPoint\""));
    assert!(manifest.contains("\"roleProvenance\": \"observed\""));
    assert!(manifest.contains("\"pathClass\": \"configuredRoleLogRoot\""));
}

#[test]
fn bgb_missing_management_point_role_falls_back_to_operator_declared() {
    let source = tempfile::tempdir().unwrap();
    fs::write(source.path().join("BgbServer.log"), b"bgb").unwrap();
    let mut environment = operator_environment();
    environment
        .advanced_source_facts
        .push(PrivateAdvancedSourceFact {
            source_id: "advanced-client-notification-bgb".to_owned(),
            role_scope: "managementPoint".to_owned(),
            path_class: "configuredRoleLogRoot".to_owned(),
            root: source.path().to_owned(),
            source_version: Some("5.00.9141.1000".to_owned()),
            pxe_enabled: false,
        });
    let mut bgb_request = request(
        source.path().to_str().unwrap(),
        "advanced-client-notification-bgb",
    );
    bgb_request.role_scope = "managementPoint".to_owned();

    let mut store = SccmAdvancedCapabilityStore::default();
    let capability = store
        .authorize(&environment, bgb_request, Instant::now())
        .unwrap();
    let authorization = store
        .consume(&capability.capability_handle, Instant::now())
        .unwrap();
    let output = tempfile::tempdir().unwrap();
    capture_advanced_authorized(authorization, &output.path().join("bundle")).unwrap();
    let manifest =
        fs::read_to_string(output.path().join("bundle/sccm-server-manifest.json")).unwrap();

    assert!(manifest.contains("\"roleProvenance\": \"operatorDeclared\""));
}

#[test]
fn bgb_mismatched_path_class_falls_back_to_operator_declared() {
    let source = tempfile::tempdir().unwrap();
    fs::write(source.path().join("BgbServer.log"), b"bgb").unwrap();
    let mut environment = operator_environment();
    environment.roles.push(SccmDetectedRole {
        role: SccmRole::ManagementPoint,
        basis: SccmDiscoveryBasis::Registry,
    });
    environment.roots.push(SccmCaptureRoot {
        role: SccmRole::ManagementPoint,
        path: source.path().to_owned(),
    });
    environment
        .advanced_source_facts
        .push(PrivateAdvancedSourceFact {
            source_id: "advanced-client-notification-bgb".to_owned(),
            role_scope: "managementPoint".to_owned(),
            path_class: "configuredRoleLogRoot".to_owned(),
            root: source.path().to_owned(),
            source_version: Some("5.00.9141.1000".to_owned()),
            pxe_enabled: false,
        });
    let mut bgb_request = request(
        source.path().to_str().unwrap(),
        "advanced-client-notification-bgb",
    );
    bgb_request.role_scope = "managementPoint".to_owned();
    bgb_request.path_class = "siteServerLogs".to_owned();

    let mut store = SccmAdvancedCapabilityStore::default();
    let capability = store
        .authorize(&environment, bgb_request, Instant::now())
        .unwrap();
    let authorization = store
        .consume(&capability.capability_handle, Instant::now())
        .unwrap();
    let output = tempfile::tempdir().unwrap();
    capture_advanced_authorized(authorization, &output.path().join("bundle")).unwrap();
    let manifest =
        fs::read_to_string(output.path().join("bundle/sccm-server-manifest.json")).unwrap();

    assert!(manifest.contains("\"roleProvenance\": \"operatorDeclared\""));
    assert!(!manifest.contains("\"producerRole\": \"managementPoint\""));
}

#[cfg(unix)]
#[test]
fn bgb_hostile_symlink_fact_falls_back_to_operator_declared() {
    use std::os::unix::fs::symlink;

    let source = tempfile::tempdir().unwrap();
    let hostile_fact_root = tempfile::tempdir().unwrap();
    fs::write(source.path().join("BgbServer.log"), b"bgb").unwrap();
    let fact_link = hostile_fact_root.path().join("observed-root");
    symlink(source.path(), &fact_link).unwrap();

    let mut environment = operator_environment();
    environment.roles.push(SccmDetectedRole {
        role: SccmRole::ManagementPoint,
        basis: SccmDiscoveryBasis::Registry,
    });
    environment
        .advanced_source_facts
        .push(PrivateAdvancedSourceFact {
            source_id: "advanced-client-notification-bgb".to_owned(),
            role_scope: "managementPoint".to_owned(),
            path_class: "configuredRoleLogRoot".to_owned(),
            root: fact_link,
            source_version: Some("5.00.9141.1000".to_owned()),
            pxe_enabled: false,
        });
    let mut bgb_request = request(
        source.path().to_str().unwrap(),
        "advanced-client-notification-bgb",
    );
    bgb_request.role_scope = "managementPoint".to_owned();

    let mut store = SccmAdvancedCapabilityStore::default();
    let capability = store
        .authorize(&environment, bgb_request, Instant::now())
        .unwrap();
    let authorization = store
        .consume(&capability.capability_handle, Instant::now())
        .unwrap();
    let output = tempfile::tempdir().unwrap();
    capture_advanced_authorized(authorization, &output.path().join("bundle")).unwrap();
    let manifest =
        fs::read_to_string(output.path().join("bundle/sccm-server-manifest.json")).unwrap();

    assert!(manifest.contains("\"roleProvenance\": \"operatorDeclared\""));
}

#[test]
fn pxe_observed_mode_requires_an_explicit_enabled_fact() {
    let source = tempfile::tempdir().unwrap();
    let mut environment = operator_environment();
    environment
        .advanced_source_facts
        .push(PrivateAdvancedSourceFact {
            source_id: "advanced-osd-pxe".to_owned(),
            role_scope: "siteServer".to_owned(),
            path_class: "siteServerLogs".to_owned(),
            root: source.path().to_owned(),
            source_version: Some("5.00.9141.1000".to_owned()),
            pxe_enabled: false,
        });
    let mut pxe_request = request(source.path().to_str().unwrap(), "advanced-osd-pxe");
    pxe_request.role_scope = "siteServer".to_owned();
    pxe_request.path_class = "siteServerLogs".to_owned();
    let mut store = SccmAdvancedCapabilityStore::default();
    let capability = store
        .authorize(&environment, pxe_request.clone(), Instant::now())
        .unwrap();
    let output = tempfile::tempdir().unwrap();
    let authorization = store
        .consume(&capability.capability_handle, Instant::now())
        .unwrap();
    capture_advanced_authorized(authorization, &output.path().join("operator")).unwrap();
    let manifest =
        fs::read_to_string(output.path().join("operator/sccm-server-manifest.json")).unwrap();
    assert!(manifest.contains("\"roleProvenance\": \"operatorDeclared\""));

    environment.advanced_source_facts[0].pxe_enabled = true;
    let capability = store
        .authorize(&environment, pxe_request, Instant::now())
        .unwrap();
    let authorization = store
        .consume(&capability.capability_handle, Instant::now())
        .unwrap();
    capture_advanced_authorized(authorization, &output.path().join("observed")).unwrap();
    let manifest =
        fs::read_to_string(output.path().join("observed/sccm-server-manifest.json")).unwrap();
    assert!(manifest.contains("\"roleProvenance\": \"observed\""));
}

#[test]
fn oversized_source_is_capped_at_four_mib() {
    let source = tempfile::tempdir().unwrap();
    fs::write(
        source.path().join("crp.log"),
        vec![b'x'; ADVANCED_CAPTURE_BYTE_LIMIT as usize + 17],
    )
    .unwrap();
    let mut store = SccmAdvancedCapabilityStore::default();
    let capability = store
        .authorize(
            &operator_environment(),
            request(
                source.path().to_str().unwrap(),
                "advanced-certificate-enrollment-pki",
            ),
            Instant::now(),
        )
        .unwrap();
    let authorization = store
        .consume(&capability.capability_handle, Instant::now())
        .unwrap();
    let output = tempfile::tempdir().unwrap();
    let result = capture_advanced_authorized(authorization, &output.path().join("bundle")).unwrap();
    assert_eq!(result.retained_bytes, ADVANCED_CAPTURE_BYTE_LIMIT);
    assert_eq!(result.sources[0].state, SccmCoverageState::Capped);
}

#[test]
fn advanced_capture_byte_limit_is_shared_exactly_across_current_and_lo() {
    let source = tempfile::tempdir().unwrap();
    let current_bytes = ADVANCED_CAPTURE_BYTE_LIMIT as usize - 11;
    fs::write(
        source.path().join("CloudMgr.log"),
        vec![b'c'; current_bytes],
    )
    .unwrap();
    fs::write(source.path().join("CloudMgr.lo_"), vec![b'l'; 11]).unwrap();
    let mut store = SccmAdvancedCapabilityStore::default();
    let capability = store
        .authorize(
            &operator_environment(),
            request(source.path().to_str().unwrap(), "advanced-cloud-manager"),
            Instant::now(),
        )
        .unwrap();
    let authorization = store
        .consume(&capability.capability_handle, Instant::now())
        .unwrap();
    let output = tempfile::tempdir().unwrap();
    let bundle = output.path().join("bundle");
    let result = capture_advanced_authorized(authorization, &bundle).unwrap();

    assert_eq!(result.retained_bytes, ADVANCED_CAPTURE_BYTE_LIMIT);
    assert_eq!(
        result
            .sources
            .iter()
            .map(|source| source.state.clone())
            .collect::<Vec<_>>(),
        vec![SccmCoverageState::Captured, SccmCoverageState::Captured]
    );
    let manifest: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(bundle.join("sccm-server-manifest.json")).unwrap(),
    )
    .unwrap();
    assert!(manifest["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .all(|artifact| {
            artifact["collectionLimit"]["byteLimit"] == ADVANCED_CAPTURE_BYTE_LIMIT
                && artifact["collectionLimit"]["limitApplied"] == false
                && artifact["captureState"] == "captured"
        }));
}

#[test]
fn advanced_capture_byte_limit_is_current_first_and_caps_overflow_rotation() {
    let source = tempfile::tempdir().unwrap();
    fs::write(
        source.path().join("CloudMgr.log"),
        vec![b'c'; ADVANCED_CAPTURE_BYTE_LIMIT as usize - 1],
    )
    .unwrap();
    fs::write(source.path().join("CloudMgr.lo_"), b"overflow").unwrap();
    let mut store = SccmAdvancedCapabilityStore::default();
    let capability = store
        .authorize(
            &operator_environment(),
            request(source.path().to_str().unwrap(), "advanced-cloud-manager"),
            Instant::now(),
        )
        .unwrap();
    let authorization = store
        .consume(&capability.capability_handle, Instant::now())
        .unwrap();
    let output = tempfile::tempdir().unwrap();
    let bundle = output.path().join("bundle");
    let result = capture_advanced_authorized(authorization, &bundle).unwrap();

    assert_eq!(result.retained_bytes, ADVANCED_CAPTURE_BYTE_LIMIT);
    assert_eq!(result.sources.len(), 2);
    assert_eq!(result.sources[0].state, SccmCoverageState::Captured);
    assert_eq!(
        result.sources[0].retained_bytes,
        ADVANCED_CAPTURE_BYTE_LIMIT - 1
    );
    assert_eq!(result.sources[1].state, SccmCoverageState::Capped);
    assert_eq!(result.sources[1].retained_bytes, 1);
    let manifest: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(bundle.join("sccm-server-manifest.json")).unwrap(),
    )
    .unwrap();
    let overflow = manifest["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|artifact| artifact["originalBasename"] == "CloudMgr.lo_")
        .unwrap();
    assert_eq!(overflow["captureState"], "capped");
    assert_eq!(overflow["bytesCopied"], 1);
    assert_eq!(overflow["collectionLimit"]["byteLimit"], 1);
    assert_eq!(overflow["collectionLimit"]["fileLimit"], 2);
    assert_eq!(overflow["collectionLimit"]["limitApplied"], true);
    assert_eq!(overflow["truncated"], true);
    assert_eq!(overflow["fragmentComplete"], false);
}
