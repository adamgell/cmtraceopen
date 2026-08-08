use std::time::{Duration, Instant};

use app_lib::sccm::collector::{
    advanced_source_contracts, PrivateSccmEnvironment, SccmAdvancedCapabilityStore,
    SccmAdvancedCaptureAuthorizationRequest, SccmDetectedRole, SccmDiscoveryBasis,
    ADVANCED_CAPABILITY_LIMIT, ADVANCED_CAPABILITY_TTL,
};
use app_lib::sccm::SccmRole;

fn environment() -> PrivateSccmEnvironment {
    PrivateSccmEnvironment {
        supported: true,
        configmgr_version: Some("5.00.9141.1000".to_owned()),
        roles: vec![SccmDetectedRole {
            role: SccmRole::SiteServer,
            basis: SccmDiscoveryBasis::Registry,
        }],
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
fn authorization_dto_rejects_unknown_or_free_form_fields() {
    let valid = serde_json::json!({
        "cardId": "osd-pxe",
        "cardVersion": "1.0.0",
        "sourceId": "advanced-osd-pxe",
        "roleScope": "distributionPointPxe",
        "pathClass": "configuredRoleLogRoot",
        "expectedSourceVersion": "5.00.9141.1000",
        "selectedRoot": "C:\\private"
    });
    assert!(
        serde_json::from_value::<SccmAdvancedCaptureAuthorizationRequest>(valid.clone()).is_ok()
    );
    for field in ["basename", "glob", "path", "rawEvidence"] {
        let mut hostile = valid.clone();
        hostile[field] = serde_json::json!("*");
        assert!(
            serde_json::from_value::<SccmAdvancedCaptureAuthorizationRequest>(hostile).is_err()
        );
    }
}

#[test]
fn rejection_is_fail_closed_and_leaves_no_capability() {
    let root = tempfile::tempdir().unwrap();
    let mut store = SccmAdvancedCapabilityStore::default();
    let mut hostile = request(root.path().to_str().unwrap(), "advanced-osd-pxe");
    hostile.card_id = "reporting".to_owned();
    assert!(store
        .authorize(&environment(), hostile, Instant::now())
        .is_err());
    assert_eq!(store.pending_count(), 0);

    let glob = request("/tmp/*", "advanced-osd-pxe");
    assert!(store
        .authorize(&environment(), glob, Instant::now())
        .is_err());
    assert_eq!(store.pending_count(), 0);
}

#[test]
fn capability_is_single_use_cancelable_expiring_and_nonpersistent() {
    let root = tempfile::tempdir().unwrap();
    let now = Instant::now();
    let mut store = SccmAdvancedCapabilityStore::default();
    let capability = store
        .authorize(
            &environment(),
            request(root.path().to_str().unwrap(), "advanced-reporting"),
            now,
        )
        .unwrap();
    assert!(capability
        .capability_handle
        .starts_with("cmtraceopen.capture-capability.sha256.v1:"));
    assert_eq!(
        capability.capability_handle.len(),
        "cmtraceopen.capture-capability.sha256.v1:".len() + 64
    );
    assert_eq!(store.pending_count(), 1);
    assert!(store.consume(&capability.capability_handle, now).is_ok());
    assert!(store.consume(&capability.capability_handle, now).is_err());

    let capability = store
        .authorize(
            &environment(),
            request(root.path().to_str().unwrap(), "advanced-reporting"),
            now,
        )
        .unwrap();
    store.cancel(&capability.capability_handle, now);
    assert!(store.consume(&capability.capability_handle, now).is_err());

    let capability = store
        .authorize(
            &environment(),
            request(root.path().to_str().unwrap(), "advanced-reporting"),
            now,
        )
        .unwrap();
    assert!(store
        .consume(
            &capability.capability_handle,
            now + ADVANCED_CAPABILITY_TTL + Duration::from_millis(1),
        )
        .is_err());
    assert_eq!(store.pending_count(), 0);

    let restarted = SccmAdvancedCapabilityStore::default();
    assert_eq!(restarted.pending_count(), 0);
}

#[test]
fn capability_store_is_bounded_and_purges_before_authorize() {
    let parent = tempfile::tempdir().unwrap();
    let now = Instant::now();
    let mut store = SccmAdvancedCapabilityStore::default();
    for index in 0..ADVANCED_CAPABILITY_LIMIT {
        let root = parent.path().join(index.to_string());
        std::fs::create_dir(&root).unwrap();
        store
            .authorize(
                &environment(),
                request(root.to_str().unwrap(), "advanced-reporting"),
                now,
            )
            .unwrap();
    }
    let ninth = parent.path().join("ninth");
    std::fs::create_dir(&ninth).unwrap();
    assert!(store
        .authorize(
            &environment(),
            request(ninth.to_str().unwrap(), "advanced-reporting"),
            now,
        )
        .is_err());

    let replacement = parent.path().join("replacement");
    std::fs::create_dir(&replacement).unwrap();
    assert!(store
        .authorize(
            &environment(),
            request(replacement.to_str().unwrap(), "advanced-reporting"),
            now + ADVANCED_CAPABILITY_TTL + Duration::from_millis(1),
        )
        .is_ok());
    assert_eq!(store.pending_count(), 1);
}

#[cfg(unix)]
#[test]
fn symlink_roots_are_rejected_before_storage() {
    use std::os::unix::fs::symlink;

    let real = tempfile::tempdir().unwrap();
    let parent = tempfile::tempdir().unwrap();
    let link = parent.path().join("linked-root");
    symlink(real.path(), &link).unwrap();
    let mut store = SccmAdvancedCapabilityStore::default();
    assert!(store
        .authorize(
            &environment(),
            request(link.to_str().unwrap(), "advanced-reporting"),
            Instant::now(),
        )
        .is_err());
    assert_eq!(store.pending_count(), 0);
}
