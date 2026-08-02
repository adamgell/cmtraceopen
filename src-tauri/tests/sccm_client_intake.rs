use std::collections::BTreeMap;
use std::fs;

use app_lib::sccm::{
    capture_client_bundle, discover_client_sources, read_sccm_manifest_or_legacy,
    SccmClientCaptureRequest, SccmClientDiscoveryInput, SccmClientSourceSpec, SccmCoverageState,
    SccmManifestSourceState, SccmRole, SccmRotation,
};
use tempfile::tempdir;

fn source(
    catalog_entry_id: &str,
    logical_artifact_id: &str,
    basenames: &[&str],
) -> SccmClientSourceSpec {
    SccmClientSourceSpec {
        catalog_entry_id: catalog_entry_id.to_string(),
        logical_artifact_id: logical_artifact_id.to_string(),
        basenames: basenames.iter().map(|value| (*value).to_string()).collect(),
        enabled: true,
    }
}

fn input(
    roots: Vec<std::path::PathBuf>,
    sources: Vec<SccmClientSourceSpec>,
) -> SccmClientDiscoveryInput {
    SccmClientDiscoveryInput {
        candidate_roots: roots,
        source_catalog: sources,
        max_files_per_source: 8,
        max_bytes_per_source: 1024,
        access_status_overrides: BTreeMap::new(),
    }
}

#[test]
fn capture_preserves_rotations_and_cross_root_collisions_in_a_versioned_manifest() {
    let temp = tempdir().expect("temporary test root");
    let root_a = temp.path().join("logs-a");
    let root_b = temp.path().join("logs-b");
    fs::create_dir_all(&root_a).expect("root a");
    fs::create_dir_all(&root_b).expect("root b");
    fs::write(root_a.join("AppEnforce.log"), "current-a").expect("current log");
    fs::write(root_a.join("AppEnforce.lo_"), "lo-a").expect("lo log");
    fs::write(root_a.join("AppEnforce.log.2"), "numbered-a").expect("numbered log");
    fs::write(root_b.join("AppEnforce.log"), "current-b").expect("colliding current log");

    let request = SccmClientCaptureRequest {
        bundle_root: temp.path().join("bundle"),
        host: "LAB-CLIENT-01".to_string(),
        discovery: input(
            vec![root_b, root_a],
            vec![source(
                "catalog.client.app-enforce",
                "client-app-enforce",
                &["AppEnforce.log"],
            )],
        ),
    };

    let captured = capture_client_bundle(&request).expect("capture succeeds");
    assert_eq!(captured.manifest.sccm_manifest_version, 1);
    assert_eq!(captured.manifest.artifacts.len(), 4);

    let artifacts = &captured.manifest.artifacts;
    assert!(artifacts
        .iter()
        .all(|artifact| artifact.host == "LAB-CLIENT-01"));
    assert!(artifacts
        .iter()
        .all(|artifact| artifact.role == SccmRole::Client));
    assert_eq!(
        artifacts
            .iter()
            .filter(|artifact| artifact.rotation == SccmRotation::Current)
            .count(),
        2
    );
    assert!(artifacts
        .iter()
        .any(|artifact| artifact.rotation == SccmRotation::LoUnderscore));
    assert!(artifacts
        .iter()
        .any(|artifact| artifact.rotation == SccmRotation::Numbered(2)));
    assert_ne!(artifacts[0].relative_path, artifacts[1].relative_path);
    assert!(artifacts.iter().all(|artifact| {
        artifact
            .relative_path
            .as_ref()
            .is_some_and(|path| request.bundle_root.join(path).is_file())
    }));

    let manifest_json = fs::read_to_string(request.bundle_root.join("sccm-manifest.json"))
        .expect("manifest written");
    assert!(manifest_json.contains("\"sccmManifestVersion\": 1"));
}

#[test]
fn discovery_emits_explicit_absent_access_denied_capped_and_skipped_states() {
    let temp = tempdir().expect("temporary test root");
    let root = temp.path().join("logs");
    fs::create_dir_all(&root).expect("log root");
    fs::write(root.join("AppEnforce.log"), "first").expect("first log");
    fs::write(root.join("AppEnforce.log.1"), "second").expect("second log");

    let denied = source(
        "catalog.policy",
        "client-policy-agent",
        &["PolicyAgent.log"],
    );
    let absent = source("catalog.updates", "client-updates", &["ScanAgent.log"]);
    let capped = source(
        "catalog.app-enforce",
        "client-app-enforce",
        &["AppEnforce.log"],
    );
    let mut skipped = source("catalog.content", "client-content", &["CAS.log"]);
    skipped.enabled = false;

    let mut discovery = input(vec![root.clone()], vec![denied, absent, capped, skipped]);
    discovery.max_files_per_source = 1;
    discovery.access_status_overrides.insert(
        root.join("PolicyAgent.log"),
        SccmCoverageState::AccessDenied,
    );

    let result = discover_client_sources(&discovery);
    let state_for = |logical_artifact_id: &str| {
        result
            .source_states
            .iter()
            .find(|state| state.logical_artifact_id == logical_artifact_id)
            .expect("source state")
            .coverage
            .clone()
    };
    assert_eq!(
        state_for("client-policy-agent"),
        SccmCoverageState::AccessDenied
    );
    assert_eq!(state_for("client-updates"), SccmCoverageState::Absent);
    assert_eq!(state_for("client-app-enforce"), SccmCoverageState::Capped);
    assert_eq!(state_for("client-content"), SccmCoverageState::Skipped);

    let captured = capture_client_bundle(&SccmClientCaptureRequest {
        bundle_root: temp.path().join("bundle"),
        host: "LAB-CLIENT-01".to_string(),
        discovery,
    })
    .expect("capture manifest");
    let manifest_state_for = |logical_artifact_id: &str| {
        captured
            .manifest
            .artifacts
            .iter()
            .find(|artifact| {
                artifact.logical_artifact_id == logical_artifact_id
                    && artifact.state != SccmManifestSourceState::Captured
            })
            .expect("manifest state")
            .state
    };
    assert_eq!(
        manifest_state_for("client-policy-agent"),
        SccmManifestSourceState::AccessDenied
    );
    assert_eq!(
        manifest_state_for("client-updates"),
        SccmManifestSourceState::Absent
    );
    assert_eq!(
        manifest_state_for("client-app-enforce"),
        SccmManifestSourceState::Capped
    );
    assert_eq!(
        manifest_state_for("client-content"),
        SccmManifestSourceState::Skipped
    );
}

#[cfg(unix)]
#[test]
fn discovery_rejects_a_symlink_that_escapes_the_configured_root() {
    use std::os::unix::fs::symlink;

    let temp = tempdir().expect("temporary test root");
    let root = temp.path().join("logs");
    let outside = temp.path().join("outside");
    fs::create_dir_all(&root).expect("log root");
    fs::create_dir_all(&outside).expect("outside root");
    fs::write(outside.join("AppEnforce.log"), "must not capture").expect("outside log");
    symlink(outside.join("AppEnforce.log"), root.join("AppEnforce.log")).expect("link");

    let result = discover_client_sources(&input(
        vec![root],
        vec![source(
            "catalog.client.app-enforce",
            "client-app-enforce",
            &["AppEnforce.log"],
        )],
    ));

    assert!(result.artifacts.is_empty());
    assert_eq!(
        result.source_states[0].coverage,
        SccmCoverageState::Unsupported,
        "an escaping symlink must never be recast as absent"
    );
}

#[test]
fn legacy_generic_manifest_maps_only_unambiguous_statuses() {
    let temp = tempdir().expect("temporary test root");
    fs::write(
        temp.path().join("manifest.json"),
        r#"{"artifacts":[
          {"artifactId":"captured","status":"collected","relativePath":"evidence/a.log"},
          {"artifactId":"missing","status":"missing"},
          {"artifactId":"failed","status":"failed"}
        ]}"#,
    )
    .expect("legacy manifest");

    let manifest = read_sccm_manifest_or_legacy(temp.path()).expect("legacy mapping");
    assert_eq!(manifest.sccm_manifest_version, 1);
    assert_eq!(
        manifest.artifacts[0].state,
        SccmManifestSourceState::Captured
    );
    assert_eq!(manifest.artifacts[1].state, SccmManifestSourceState::Absent);
    assert_eq!(
        manifest.artifacts[2].state,
        SccmManifestSourceState::FailedUnknownDetail
    );
}

#[test]
fn manifest_artifacts_are_sorted_by_catalog_path_rotation_basename_and_id() {
    let temp = tempdir().expect("temporary test root");
    let root = temp.path().join("logs");
    fs::create_dir_all(&root).expect("log root");
    for basename in ["PolicyAgent.log.2", "PolicyAgent.log", "AppEnforce.log"] {
        fs::write(root.join(basename), basename).expect("log");
    }

    let captured = capture_client_bundle(&SccmClientCaptureRequest {
        bundle_root: temp.path().join("bundle"),
        host: "LAB-CLIENT-01".to_string(),
        discovery: input(
            vec![root],
            vec![
                source(
                    "catalog.policy",
                    "client-policy-agent",
                    &["PolicyAgent.log"],
                ),
                source("catalog.apps", "client-app-enforce", &["AppEnforce.log"]),
            ],
        ),
    })
    .expect("capture");

    let keys = captured
        .manifest
        .artifacts
        .iter()
        .map(|artifact| {
            (
                artifact.catalog_entry_id.as_str(),
                artifact.path_fingerprint.as_str(),
                artifact.rotation_rank,
                artifact.basename.as_str(),
                artifact.artifact_id.as_str(),
            )
        })
        .collect::<Vec<_>>();
    assert!(keys.windows(2).all(|pair| pair[0] <= pair[1]));
}
