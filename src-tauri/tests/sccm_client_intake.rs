use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use app_lib::sccm::{
    authoritative_client_source_catalog, capture_client_bundle, discover_client_sources,
    manifest_to_client_intake_bundle, read_sccm_manifest_or_legacy, SccmClientCaptureRequest,
    SccmClientDiscoveryInput, SccmClientSourceSpec, SccmCoverageState, SccmManifestSourceState,
    SccmRole, SccmRotation,
};
use cmtraceopen_parser::sccm::{assess_client_intake, declared_client_source_groups};
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

fn request(
    bundle_root: std::path::PathBuf,
    host: &str,
    discovery: SccmClientDiscoveryInput,
) -> SccmClientCaptureRequest {
    SccmClientCaptureRequest {
        bundle_root,
        host: host.to_owned(),
        collected_at_utc: "2026-07-30T15:00:00Z".to_owned(),
        configmgr_version: Some("5.00.TEST.0000".to_owned()),
        encoding: Some("utf-8".to_owned()),
        discovery,
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

    let request = request(
        temp.path().join("bundle"),
        "LAB-CLIENT-01",
        input(
            vec![root_b, root_a],
            vec![source(
                "sccm-client-group:v1:client-app-enforce",
                "client-app-enforce",
                &["AppEnforce.log"],
            )],
        ),
    );

    let captured = capture_client_bundle(&request).expect("capture succeeds");
    assert_eq!(captured.manifest.sccm_manifest_version, 1);
    assert_eq!(captured.manifest.artifacts.len(), 4);

    let artifacts = &captured.manifest.artifacts;
    assert!(captured
        .manifest
        .host_handle
        .as_deref()
        .is_some_and(|value| value.starts_with("cmtraceopen.host.sha256.v1:")));
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
    let current_paths = artifacts
        .iter()
        .filter(|artifact| artifact.rotation == SccmRotation::Current)
        .map(|artifact| artifact.relative_path.as_deref().expect("current path"))
        .collect::<Vec<_>>();
    assert_eq!(current_paths.len(), 2);
    assert_ne!(current_paths[0], current_paths[1]);
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
        "sccm-client-group:v1:client-policy-agent",
        "client-policy-agent",
        &["PolicyAgent.log"],
    );
    let absent = source(
        "sccm-client-group:v1:client-updates",
        "client-updates",
        &["ScanAgent.log"],
    );
    let capped = source(
        "sccm-client-group:v1:client-app-enforce",
        "client-app-enforce",
        &["AppEnforce.log"],
    );
    let mut skipped = source(
        "sccm-client-group:v1:client-content",
        "client-content",
        &["CAS.log"],
    );
    skipped.enabled = false;

    let mut discovery = input(vec![root.clone()], vec![denied, absent, capped, skipped]);
    discovery.max_files_per_source = 1;
    discovery.access_status_overrides.insert(
        root.join("PolicyAgent.log"),
        SccmCoverageState::AccessDenied,
    );

    let result = discover_client_sources(&discovery).expect("discovery");
    let has_state = |logical_artifact_id: &str, expected_state: SccmManifestSourceState| {
        result.source_states.iter().any(|state| {
            state
                .logical_artifact_ids
                .iter()
                .any(|value| value == logical_artifact_id)
                && state.state == expected_state
        })
    };
    assert!(has_state(
        "client-policy-agent",
        SccmManifestSourceState::AccessDenied
    ));
    assert!(has_state("client-updates", SccmManifestSourceState::Absent));
    assert!(has_state(
        "client-app-enforce",
        SccmManifestSourceState::Capped
    ));
    assert!(has_state(
        "client-content",
        SccmManifestSourceState::Skipped
    ));

    let captured = capture_client_bundle(&request(
        temp.path().join("bundle"),
        "LAB-CLIENT-01",
        discovery,
    ))
    .expect("capture manifest");
    let manifest_state_for = |logical_artifact_id: &str| {
        captured
            .manifest
            .artifacts
            .iter()
            .find(|artifact| {
                artifact
                    .logical_artifact_ids
                    .iter()
                    .any(|value| value == logical_artifact_id)
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
            "sccm-client-group:v1:client-app-enforce",
            "client-app-enforce",
            &["AppEnforce.log"],
        )],
    ))
    .expect("discovery");

    assert!(result.artifacts.is_empty());
    assert_eq!(
        result.source_states[0].state,
        SccmManifestSourceState::UnsafePath,
        "an escaping symlink must never be recast as absent"
    );
}

#[test]
fn legacy_generic_manifest_preserves_unknown_detail_without_inventing_sccm_capture() {
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
        SccmManifestSourceState::FailedUnknownDetail
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

    let captured = capture_client_bundle(&request(
        temp.path().join("bundle"),
        "LAB-CLIENT-01",
        input(
            vec![root],
            vec![
                source(
                    "sccm-client-group:v1:client-policy-agent",
                    "client-policy-agent",
                    &["PolicyAgent.log"],
                ),
                source(
                    "sccm-client-group:v1:client-app-enforce",
                    "client-app-enforce",
                    &["AppEnforce.log"],
                ),
            ],
        ),
    ))
    .expect("capture");

    let rotations = captured
        .manifest
        .artifacts
        .iter()
        .map(|artifact| artifact.rotation.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        rotations,
        vec![
            SccmRotation::Current,
            SccmRotation::Current,
            SccmRotation::Numbered(2),
        ]
    );
}

#[test]
fn capture_rejects_unapproved_catalog_identity_before_constructing_a_path() {
    let temp = tempdir().expect("temporary test root");
    let root = temp.path().join("logs");
    let bundle_root = temp.path().join("bundle");
    fs::create_dir_all(&root).expect("log root");
    fs::write(root.join("PolicyAgent.log"), "policy").expect("policy log");

    let request = request(
        bundle_root.clone(),
        "LAB-CLIENT-01",
        input(
            vec![root],
            vec![source(
                "sccm-client-group:v1:client-policy-agent",
                "../../../../escaped",
                &["PolicyAgent.log"],
            )],
        ),
    );

    assert!(capture_client_bundle(&request).is_err());
    assert!(
        !temp.path().join("escaped").exists(),
        "validation must happen before any destination outside bundle_root can be created"
    );
}

#[test]
fn public_manifest_never_contains_raw_host_or_native_source_paths() {
    let temp = tempdir().expect("temporary test root");
    let root = temp.path().join("RealUser@example.test-private-logs");
    let bundle_root = temp.path().join("bundle");
    fs::create_dir_all(&root).expect("log root");
    fs::write(root.join("PolicyAgent.log"), "policy").expect("policy log");
    let raw_host = "REALUSER-LAPTOP-SECRET";
    let raw_path = root.to_string_lossy().into_owned();

    capture_client_bundle(&request(
        bundle_root.clone(),
        raw_host,
        input(
            vec![root],
            vec![source(
                "sccm-client-group:v1:client-policy-agent",
                "client-policy-agent",
                &["PolicyAgent.log"],
            )],
        ),
    ))
    .expect("capture");

    let serialized = fs::read_to_string(bundle_root.join("sccm-manifest.json")).expect("manifest");
    assert!(!serialized.contains(raw_host));
    assert!(!serialized.contains(&raw_path));
    assert!(!serialized.contains("RealUser@example.test"));
}

#[test]
fn timestamp_and_numbered_rotations_retain_values_order_and_shared_lineage() {
    let temp = tempdir().expect("temporary test root");
    let root = temp.path().join("logs");
    let bundle_root = temp.path().join("bundle");
    fs::create_dir_all(&root).expect("log root");
    for basename in [
        "PolicyAgent.log",
        "PolicyAgent.lo_",
        "PolicyAgent.log.7",
        "PolicyAgent.log.20260730-150000",
    ] {
        fs::write(root.join(basename), basename).expect("rotation");
    }

    let captured = capture_client_bundle(&request(
        bundle_root,
        "LAB-CLIENT-01",
        input(
            vec![root],
            vec![source(
                "sccm-client-group:v1:client-policy-agent",
                "client-policy-agent",
                &["PolicyAgent.log"],
            )],
        ),
    ))
    .expect("capture");

    let rotations = captured
        .manifest
        .artifacts
        .iter()
        .map(|artifact| artifact.rotation.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        rotations,
        vec![
            SccmRotation::Current,
            SccmRotation::LoUnderscore,
            SccmRotation::Numbered(7),
            SccmRotation::Timestamped("20260730-150000".to_string()),
        ]
    );
    assert!(captured.manifest.artifacts[2]
        .relative_path
        .as_deref()
        .is_some_and(|path| path.contains("/numbered-7/")));

    let json = serde_json::to_value(&captured.manifest).expect("manifest JSON");
    let lineages = json["artifacts"]
        .as_array()
        .expect("artifact array")
        .iter()
        .map(|artifact| artifact["rotationLineage"].as_str())
        .collect::<Vec<_>>();
    assert!(lineages.iter().all(Option::is_some));
    assert!(lineages.windows(2).all(|pair| pair[0] == pair[1]));
}

#[test]
fn capped_capture_retains_exact_bounded_prefix_as_incomplete_evidence() {
    let temp = tempdir().expect("temporary test root");
    let root = temp.path().join("logs");
    let bundle_root = temp.path().join("bundle");
    fs::create_dir_all(&root).expect("log root");
    fs::write(root.join("PolicyAgent.log"), b"0123456789").expect("policy log");
    let mut discovery = input(
        vec![root],
        vec![source(
            "sccm-client-group:v1:client-policy-agent",
            "client-policy-agent",
            &["PolicyAgent.log"],
        )],
    );
    discovery.max_bytes_per_source = 4;

    let captured = capture_client_bundle(&request(bundle_root.clone(), "LAB-CLIENT-01", discovery))
        .expect("bounded capture");
    let capped = captured
        .manifest
        .artifacts
        .iter()
        .find(|artifact| artifact.state == SccmManifestSourceState::Capped)
        .expect("capped physical artifact");
    assert_eq!(capped.bytes_copied, 4);
    let relative_path = capped
        .relative_path
        .as_deref()
        .expect("retained prefix path");
    assert_eq!(
        fs::read(bundle_root.join(relative_path)).expect("retained prefix"),
        b"0123"
    );
    let json = serde_json::to_value(capped).expect("capped JSON");
    assert_eq!(json["fragmentComplete"], false);
}

#[test]
fn manifest_reader_rejects_parent_paths_and_duplicate_artifact_ids() {
    let temp = tempdir().expect("temporary test root");
    let root = temp.path().join("logs");
    let bundle_root = temp.path().join("bundle");
    fs::create_dir_all(&root).expect("log root");
    fs::write(root.join("PolicyAgent.log"), "policy").expect("policy log");
    capture_client_bundle(&request(
        bundle_root.clone(),
        "LAB-CLIENT-01",
        input(
            vec![root],
            vec![source(
                "sccm-client-group:v1:client-policy-agent",
                "client-policy-agent",
                &["PolicyAgent.log"],
            )],
        ),
    ))
    .expect("capture");

    let path = bundle_root.join("sccm-manifest.json");
    let original = fs::read_to_string(&path).expect("manifest");
    let mut manifest: serde_json::Value = serde_json::from_str(&original).expect("manifest JSON");
    manifest["artifacts"][0]["relativePath"] = serde_json::json!("../../outside.log");
    fs::write(&path, serde_json::to_vec(&manifest).expect("serialize")).expect("unsafe manifest");
    assert!(read_sccm_manifest_or_legacy(&bundle_root).is_err());

    let mut manifest: serde_json::Value = serde_json::from_str(&original).expect("manifest JSON");
    let duplicate = manifest["artifacts"][0].clone();
    manifest["artifacts"]
        .as_array_mut()
        .expect("artifact array")
        .push(duplicate);
    fs::write(&path, serde_json::to_vec(&manifest).expect("serialize"))
        .expect("duplicate manifest");
    assert!(read_sccm_manifest_or_legacy(&bundle_root).is_err());
}

#[test]
fn generic_legacy_collected_state_is_not_promoted_to_sccm_captured_evidence() {
    let temp = tempdir().expect("temporary test root");
    fs::write(
        temp.path().join("manifest.json"),
        r#"{"artifacts":[{"artifactId":"arbitrary","status":"collected","relativePath":"../../private.log"}]}"#,
    )
    .expect("legacy manifest");

    assert!(read_sccm_manifest_or_legacy(temp.path()).is_err());
}

#[test]
fn shared_location_services_source_is_captured_once_with_both_memberships() {
    let temp = tempdir().expect("temporary test root");
    let root = temp.path().join("logs");
    let bundle_root = temp.path().join("bundle");
    fs::create_dir_all(&root).expect("log root");
    fs::write(root.join("LocationServices.log"), "location").expect("location log");

    let captured = capture_client_bundle(&request(
        bundle_root,
        "LAB-CLIENT-01",
        input(
            vec![root],
            vec![
                source(
                    "sccm-client-group:v1:client-location",
                    "client-location",
                    &["LocationServices.log"],
                ),
                source(
                    "sccm-client-group:v1:client-content",
                    "client-content",
                    &["LocationServices.log"],
                ),
            ],
        ),
    ))
    .expect("capture");

    assert_eq!(captured.manifest.artifacts.len(), 1);
    let json = serde_json::to_value(&captured.manifest.artifacts[0]).expect("artifact JSON");
    assert_eq!(
        json["logicalArtifactIds"],
        serde_json::json!(["client-content", "client-location"])
    );
}

#[test]
fn manifest_reader_rejects_unknown_fields_oversize_input_and_state_path_mismatch() {
    let temp = tempdir().expect("temporary test root");
    let manifest_path = temp.path().join("sccm-manifest.json");
    let valid_empty = serde_json::json!({
        "sccmManifestVersion": 1,
        "artifacts": []
    });

    let mut unknown = valid_empty.clone();
    unknown["unexpected"] = serde_json::json!(true);
    fs::write(
        &manifest_path,
        serde_json::to_vec(&unknown).expect("unknown manifest"),
    )
    .expect("write unknown manifest");
    assert!(read_sccm_manifest_or_legacy(temp.path()).is_err());

    let mut oversized = valid_empty;
    oversized["padding"] = serde_json::json!("x".repeat(5 * 1024 * 1024));
    fs::write(
        &manifest_path,
        serde_json::to_vec(&oversized).expect("oversized manifest"),
    )
    .expect("write oversized manifest");
    let error = read_sccm_manifest_or_legacy(temp.path()).expect_err("oversize rejected");
    assert!(error.to_string().contains("size limit"));

    let root = temp.path().join("logs");
    let bundle_root = temp.path().join("coherence-bundle");
    fs::create_dir_all(&root).expect("log root");
    fs::write(root.join("PolicyAgent.log"), "policy").expect("policy log");
    capture_client_bundle(&request(
        bundle_root.clone(),
        "LAB-CLIENT-01",
        input(
            vec![root],
            vec![source(
                "sccm-client-group:v1:client-policy-agent",
                "client-policy-agent",
                &["PolicyAgent.log"],
            )],
        ),
    ))
    .expect("capture");
    let path = bundle_root.join("sccm-manifest.json");
    let mut incoherent: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("manifest")).expect("manifest JSON");
    incoherent["artifacts"][0]["relativePath"] = serde_json::Value::Null;
    incoherent["artifacts"][0]["bytesCopied"] = serde_json::json!(99);
    fs::write(
        path,
        serde_json::to_vec(&incoherent).expect("incoherent manifest"),
    )
    .expect("write incoherent manifest");
    assert!(read_sccm_manifest_or_legacy(&bundle_root).is_err());
}

#[test]
fn manifest_reader_rejects_duplicate_relative_paths_even_with_distinct_ids() {
    let temp = tempdir().expect("temporary test root");
    let root_a = temp.path().join("logs-a");
    let root_b = temp.path().join("logs-b");
    let bundle_root = temp.path().join("bundle");
    fs::create_dir_all(&root_a).expect("root a");
    fs::create_dir_all(&root_b).expect("root b");
    fs::write(root_a.join("PolicyAgent.log"), "a").expect("source a");
    fs::write(root_b.join("PolicyAgent.log"), "b").expect("source b");
    capture_client_bundle(&request(
        bundle_root.clone(),
        "LAB-CLIENT-01",
        input(
            vec![root_a, root_b],
            vec![source(
                "sccm-client-group:v1:client-policy-agent",
                "client-policy-agent",
                &["PolicyAgent.log"],
            )],
        ),
    ))
    .expect("capture");

    let path = bundle_root.join("sccm-manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("manifest")).expect("manifest JSON");
    manifest["artifacts"][1]["relativePath"] = manifest["artifacts"][0]["relativePath"].clone();
    fs::write(
        path,
        serde_json::to_vec(&manifest).expect("duplicate path manifest"),
    )
    .expect("write duplicate path manifest");
    assert!(read_sccm_manifest_or_legacy(&bundle_root).is_err());
}

#[test]
fn parse_failed_override_remains_distinct_from_unsupported() {
    let temp = tempdir().expect("temporary test root");
    let root = temp.path().join("logs");
    let bundle_root = temp.path().join("bundle");
    fs::create_dir_all(&root).expect("log root");
    let source_path = root.join("PolicyAgent.log");
    fs::write(&source_path, "malformed logical record").expect("policy log");
    let mut discovery = input(
        vec![root],
        vec![source(
            "sccm-client-group:v1:client-policy-agent",
            "client-policy-agent",
            &["PolicyAgent.log"],
        )],
    );
    discovery
        .access_status_overrides
        .insert(source_path, SccmCoverageState::ParseFailed);

    capture_client_bundle(&request(bundle_root.clone(), "LAB-CLIENT-01", discovery))
        .expect("capture");
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(bundle_root.join("sccm-manifest.json")).expect("manifest"),
    )
    .expect("manifest JSON");
    assert_eq!(manifest["artifacts"][0]["state"], "parseFailed");
}

#[cfg(unix)]
#[test]
fn filesystem_permission_denial_maps_to_access_denied() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempdir().expect("temporary test root");
    let root = temp.path().join("denied-logs");
    fs::create_dir_all(&root).expect("log root");
    fs::write(root.join("PolicyAgent.log"), "policy").expect("policy log");
    let original_permissions = fs::metadata(&root).expect("root metadata").permissions();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o000)).expect("deny root");

    struct RestorePermissions {
        path: std::path::PathBuf,
        permissions: Option<fs::Permissions>,
    }

    impl Drop for RestorePermissions {
        fn drop(&mut self) {
            if let Some(permissions) = self.permissions.take() {
                let _ = fs::set_permissions(&self.path, permissions);
            }
        }
    }

    let _restore = RestorePermissions {
        path: root.clone(),
        permissions: Some(original_permissions),
    };
    if fs::read_dir(&root).is_ok() {
        return;
    }

    let result = discover_client_sources(&input(
        vec![root.clone()],
        vec![source(
            "sccm-client-group:v1:client-policy-agent",
            "client-policy-agent",
            &["PolicyAgent.log"],
        )],
    ))
    .expect("discovery");

    assert_eq!(
        result.source_states[0].state,
        SccmManifestSourceState::AccessDenied
    );
}

#[cfg(unix)]
#[test]
fn destination_symlink_is_not_followed_and_only_that_source_fails() {
    use std::os::unix::fs::symlink;

    let temp = tempdir().expect("temporary test root");
    let root = temp.path().join("logs");
    let bundle_root = temp.path().join("bundle");
    let outside = temp.path().join("outside.log");
    fs::create_dir_all(&root).expect("log root");
    fs::write(root.join("PolicyAgent.log"), "policy").expect("policy log");
    fs::write(root.join("AppEnforce.log"), "application").expect("application log");
    fs::write(&outside, "sentinel").expect("outside sentinel");
    let discovery = input(
        vec![root],
        vec![
            source(
                "sccm-client-group:v1:client-policy-agent",
                "client-policy-agent",
                &["PolicyAgent.log"],
            ),
            source(
                "sccm-client-group:v1:client-app-enforce",
                "client-app-enforce",
                &["AppEnforce.log"],
            ),
        ],
    );
    let discovered = discover_client_sources(&discovery).expect("discovery");
    let policy = discovered
        .artifacts
        .iter()
        .find(|artifact| artifact.basename == "PolicyAgent.log")
        .expect("policy discovery");
    let relative = format!(
        "evidence/sccm/client/client-policy-agent/{}/current/PolicyAgent.log",
        policy.root_handle
    );
    let destination = bundle_root.join(relative);
    fs::create_dir_all(destination.parent().expect("destination parent"))
        .expect("destination tree");
    symlink(&outside, &destination).expect("destination symlink");

    let captured = capture_client_bundle(&request(bundle_root, "LAB-CLIENT-01", discovery))
        .expect("per-source failure does not abort bundle");
    assert_eq!(
        fs::read_to_string(&outside).expect("outside sentinel"),
        "sentinel"
    );
    assert!(captured
        .manifest
        .artifacts
        .iter()
        .any(|artifact| artifact.state == SccmManifestSourceState::FailedUnknownDetail));
    assert!(captured
        .manifest
        .artifacts
        .iter()
        .any(|artifact| artifact.state == SccmManifestSourceState::Captured));
}

#[test]
fn manifest_reader_binds_artifact_and_root_handles_to_the_captured_source() {
    let temp = tempdir().expect("temporary test root");
    let root = temp.path().join("logs");
    let bundle_root = temp.path().join("bundle");
    fs::create_dir_all(&root).expect("log root");
    fs::write(root.join("PolicyAgent.log"), "policy").expect("policy log");
    capture_client_bundle(&request(
        bundle_root.clone(),
        "LAB-CLIENT-01",
        input(
            vec![root],
            vec![source(
                "sccm-client-group:v1:client-policy-agent",
                "client-policy-agent",
                &["PolicyAgent.log"],
            )],
        ),
    ))
    .expect("capture");

    let manifest_path = bundle_root.join("sccm-manifest.json");
    let original = fs::read_to_string(&manifest_path).expect("manifest");
    let mut mutated: serde_json::Value = serde_json::from_str(&original).expect("manifest JSON");
    mutated["artifacts"][0]["artifactId"] =
        serde_json::json!(format!("sccm-artifact:v1:sha256:{}", "a".repeat(64)));
    fs::write(
        &manifest_path,
        serde_json::to_vec(&mutated).expect("mutated manifest"),
    )
    .expect("write mutated manifest");
    assert!(read_sccm_manifest_or_legacy(&bundle_root).is_err());

    let mut mutated: serde_json::Value = serde_json::from_str(&original).expect("manifest JSON");
    let original_relative = mutated["artifacts"][0]["relativePath"]
        .as_str()
        .expect("relative path")
        .to_owned();
    let mut segments = original_relative
        .split('/')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    assert_eq!(segments.len(), 7, "unexpected evidence layout");
    assert!(
        segments[4].starts_with("root-"),
        "unexpected root-handle segment"
    );
    segments[4] = format!("root-{}", "b".repeat(64));
    let forged_relative = segments.join("/");
    let forged_path = bundle_root.join(&forged_relative);
    fs::create_dir_all(forged_path.parent().expect("forged parent")).expect("forged tree");
    fs::rename(bundle_root.join(&original_relative), &forged_path).expect("move evidence");
    mutated["artifacts"][0]["relativePath"] = serde_json::json!(forged_relative);
    fs::write(
        &manifest_path,
        serde_json::to_vec(&mutated).expect("forged root manifest"),
    )
    .expect("write forged root manifest");
    assert!(read_sccm_manifest_or_legacy(&bundle_root).is_err());
}

#[test]
fn authoritative_catalog_manifest_converts_to_the_pure_intake_without_raw_context() {
    let temp = tempdir().expect("temporary test root");
    let raw_host = "REAL-CLIENT-IDENTITY.example.test";
    let catalog = authoritative_client_source_catalog();
    let expected_basenames = catalog
        .iter()
        .flat_map(|source| source.basenames.iter().cloned())
        .collect::<BTreeSet<_>>();
    let captured = capture_client_bundle(&request(
        temp.path().join("bundle"),
        raw_host,
        input(Vec::new(), catalog),
    ))
    .expect("all-catalog absent capture");

    assert_eq!(captured.manifest.artifacts.len(), expected_basenames.len());
    let bundle = manifest_to_client_intake_bundle(&captured.manifest).expect("pure bundle");
    let assessment = assess_client_intake(&bundle).expect("pure intake assessment");
    let expected_groups = declared_client_source_groups()
        .into_iter()
        .map(|group| group.logical_artifact_id)
        .collect::<Vec<_>>();
    assert_eq!(
        assessment
            .groups
            .iter()
            .map(|group| group.logical_artifact_id.clone())
            .collect::<Vec<_>>(),
        expected_groups
    );
    let serialized = serde_json::to_string(&captured.manifest).expect("manifest JSON");
    assert!(!serialized.contains(raw_host));
}

#[test]
fn discovery_rejects_a_catalog_entry_id_that_is_not_bound_to_its_declared_group() {
    let temp = tempdir().expect("temporary test root");
    let root = temp.path().join("logs");
    fs::create_dir_all(&root).expect("log root");
    fs::write(root.join("PolicyAgent.log"), "policy").expect("policy log");
    let mut forged = source(
        "sccm-client-group:v1:client-policy-agent",
        "client-policy-agent",
        &["PolicyAgent.log"],
    );
    forged.catalog_entry_id = "sccm-client-group:v1:client-content".to_owned();

    assert!(discover_client_sources(&input(vec![root], vec![forged])).is_err());
}

#[test]
fn duplicate_configured_roots_do_not_duplicate_one_physical_source() {
    let temp = tempdir().expect("temporary test root");
    let root = temp.path().join("logs");
    fs::create_dir_all(&root).expect("log root");
    fs::write(root.join("PolicyAgent.log"), "policy").expect("policy log");

    let discovered = discover_client_sources(&input(
        vec![root.clone(), root],
        vec![source(
            "sccm-client-group:v1:client-policy-agent",
            "client-policy-agent",
            &["PolicyAgent.log"],
        )],
    ))
    .expect("discovery");

    assert_eq!(discovered.artifacts.len(), 1);
}

#[test]
fn capture_preserves_per_root_access_gap_alongside_a_distinct_captured_root() {
    let temp = tempdir().expect("temporary test root");
    let root_a = temp.path().join("logs-a");
    let root_b = temp.path().join("logs-b");
    fs::create_dir_all(&root_a).expect("root a");
    fs::create_dir_all(&root_b).expect("root b");
    fs::write(root_a.join("PolicyAgent.log"), "captured").expect("policy log");
    let mut discovery = input(
        vec![root_a, root_b.clone()],
        vec![source(
            "sccm-client-group:v1:client-policy-agent",
            "client-policy-agent",
            &["PolicyAgent.log"],
        )],
    );
    discovery.access_status_overrides.insert(
        root_b.join("PolicyAgent.log"),
        SccmCoverageState::AccessDenied,
    );

    let captured = capture_client_bundle(&request(
        temp.path().join("bundle"),
        "LAB-CLIENT-01",
        discovery,
    ))
    .expect("mixed-root capture");
    assert_eq!(captured.manifest.artifacts.len(), 2);
    let denied = captured
        .manifest
        .artifacts
        .iter()
        .find(|artifact| artifact.state == SccmManifestSourceState::AccessDenied)
        .expect("root-specific access gap");
    assert!(denied.root_handle.is_some());
    assert!(denied.path_fingerprint.is_some());
    assert!(denied.rotation_lineage.is_some());
    manifest_to_client_intake_bundle(&captured.manifest).expect("pure mixed-root intake");
}

#[cfg(unix)]
#[test]
fn one_cross_root_copy_failure_remains_pinned_and_does_not_abort_its_sibling() {
    use std::os::unix::fs::symlink;

    let temp = tempdir().expect("temporary test root");
    let root_a = temp.path().join("logs-a");
    let root_b = temp.path().join("logs-b");
    let bundle_root = temp.path().join("bundle");
    let outside = temp.path().join("outside.log");
    fs::create_dir_all(&root_a).expect("root a");
    fs::create_dir_all(&root_b).expect("root b");
    fs::write(root_a.join("PolicyAgent.log"), "root-a").expect("source a");
    fs::write(root_b.join("PolicyAgent.log"), "root-b").expect("source b");
    fs::write(&outside, "sentinel").expect("outside sentinel");
    let discovery = input(
        vec![root_a, root_b],
        vec![source(
            "sccm-client-group:v1:client-policy-agent",
            "client-policy-agent",
            &["PolicyAgent.log"],
        )],
    );
    let discovered = discover_client_sources(&discovery).expect("discovery");
    let blocked = &discovered.artifacts[0];
    let blocked_destination = bundle_root.join(format!(
        "evidence/sccm/client/client-policy-agent/{}/current/PolicyAgent.log",
        blocked.root_handle
    ));
    fs::create_dir_all(blocked_destination.parent().expect("blocked parent"))
        .expect("blocked tree");
    symlink(&outside, &blocked_destination).expect("blocked destination");

    let captured = capture_client_bundle(&request(bundle_root, "LAB-CLIENT-01", discovery))
        .expect("one root failure remains representable");
    assert_eq!(
        fs::read_to_string(outside).expect("outside sentinel"),
        "sentinel"
    );
    assert_eq!(
        captured
            .manifest
            .artifacts
            .iter()
            .filter(|artifact| artifact.state == SccmManifestSourceState::Captured)
            .count(),
        1
    );
    let failed = captured
        .manifest
        .artifacts
        .iter()
        .find(|artifact| artifact.state == SccmManifestSourceState::FailedUnknownDetail)
        .expect("pinned per-root failure");
    assert!(failed.path_fingerprint.is_some());
    assert!(failed.rotation_lineage.is_some());
    manifest_to_client_intake_bundle(&captured.manifest).expect("pure collision-safe intake");
}

#[test]
fn manifest_reader_rejects_nested_unknown_fields_unsafe_versions_and_cardinality_overflow() {
    let temp = tempdir().expect("temporary test root");
    let root = temp.path().join("logs");
    let bundle_root = temp.path().join("bundle");
    fs::create_dir_all(&root).expect("log root");
    fs::write(root.join("PolicyAgent.log"), "policy").expect("policy log");
    let captured = capture_client_bundle(&request(
        bundle_root.clone(),
        "LAB-CLIENT-01",
        input(
            vec![root],
            vec![source(
                "sccm-client-group:v1:client-policy-agent",
                "client-policy-agent",
                &["PolicyAgent.log"],
            )],
        ),
    ))
    .expect("capture");

    let path = bundle_root.join("sccm-manifest.json");
    let original = fs::read_to_string(&path).expect("manifest");
    let mut nested_unknown: serde_json::Value =
        serde_json::from_str(&original).expect("manifest JSON");
    nested_unknown["artifacts"][0]["unexpected"] = serde_json::json!(true);
    fs::write(
        &path,
        serde_json::to_vec(&nested_unknown).expect("unknown artifact field"),
    )
    .expect("write unknown artifact field");
    assert!(read_sccm_manifest_or_legacy(&bundle_root).is_err());

    let mut unsafe_version: serde_json::Value =
        serde_json::from_str(&original).expect("manifest JSON");
    unsafe_version["artifacts"][0]["configmgrVersion"] = serde_json::json!("RealUser@example.test");
    fs::write(
        &path,
        serde_json::to_vec(&unsafe_version).expect("unsafe version"),
    )
    .expect("write unsafe version");
    assert!(read_sccm_manifest_or_legacy(&bundle_root).is_err());

    let mut oversized = captured.manifest;
    oversized.artifacts =
        vec![oversized.artifacts[0].clone(); app_lib::sccm::MAX_SCCM_MANIFEST_ARTIFACTS + 1];
    let error = manifest_to_client_intake_bundle(&oversized)
        .expect_err("artifact cardinality must fail closed");
    assert!(error.to_string().contains("too many artifacts"));
}

#[test]
fn reading_a_missing_bundle_has_no_filesystem_side_effect() {
    let temp = tempdir().expect("temporary test root");
    let missing = temp.path().join("missing-bundle");

    assert!(read_sccm_manifest_or_legacy(&missing).is_err());
    assert!(!missing.exists());
}

#[test]
fn invalid_capture_context_is_rejected_before_any_bundle_bytes_are_written() {
    let temp = tempdir().expect("temporary test root");
    let root = temp.path().join("logs");
    let bundle_root = temp.path().join("bundle");
    fs::create_dir_all(&root).expect("log root");
    fs::write(root.join("PolicyAgent.log"), "policy").expect("policy log");
    let mut invalid = request(
        bundle_root.clone(),
        "LAB-CLIENT-01",
        input(
            vec![root],
            vec![source(
                "sccm-client-group:v1:client-policy-agent",
                "client-policy-agent",
                &["PolicyAgent.log"],
            )],
        ),
    );
    invalid.configmgr_version = Some("RealUser@example.test".to_owned());

    assert!(capture_client_bundle(&invalid).is_err());
    assert!(
        !bundle_root.exists(),
        "invalid capture metadata must fail before destination creation"
    );
}

#[test]
fn identical_inputs_serialize_an_identical_manifest_independent_of_input_order() {
    let temp = tempdir().expect("temporary test root");
    let root_a = temp.path().join("logs-a");
    let root_b = temp.path().join("logs-b");
    fs::create_dir_all(&root_a).expect("root a");
    fs::create_dir_all(&root_b).expect("root b");
    fs::write(root_a.join("PolicyAgent.log.2"), "archive").expect("archive");
    fs::write(root_b.join("AppEnforce.log"), "application").expect("application");
    let policy = source(
        "sccm-client-group:v1:client-policy-agent",
        "client-policy-agent",
        &["PolicyAgent.log"],
    );
    let application = source(
        "sccm-client-group:v1:client-app-enforce",
        "client-app-enforce",
        &["AppEnforce.log"],
    );

    let first = capture_client_bundle(&request(
        temp.path().join("bundle-a"),
        "LAB-CLIENT-01",
        input(
            vec![root_a.clone(), root_b.clone()],
            vec![policy.clone(), application.clone()],
        ),
    ))
    .expect("first capture");
    let second = capture_client_bundle(&request(
        temp.path().join("bundle-b"),
        "LAB-CLIENT-01",
        input(vec![root_b, root_a], vec![application, policy]),
    ))
    .expect("second capture");

    assert_eq!(
        serde_json::to_vec_pretty(&first.manifest).expect("first JSON"),
        serde_json::to_vec_pretty(&second.manifest).expect("second JSON")
    );
}

#[test]
fn a_repeat_capture_never_overwrites_the_existing_manifest_or_evidence() {
    let temp = tempdir().expect("temporary test root");
    let root = temp.path().join("logs");
    let bundle_root = temp.path().join("bundle");
    fs::create_dir_all(&root).expect("log root");
    let source_path = root.join("PolicyAgent.log");
    fs::write(&source_path, "first").expect("first source");
    let capture_request = request(
        bundle_root.clone(),
        "LAB-CLIENT-01",
        input(
            vec![root],
            vec![source(
                "sccm-client-group:v1:client-policy-agent",
                "client-policy-agent",
                &["PolicyAgent.log"],
            )],
        ),
    );
    let first = capture_client_bundle(&capture_request).expect("first capture");
    let relative_path = first.manifest.artifacts[0]
        .relative_path
        .as_deref()
        .expect("evidence path");
    let manifest_before = fs::read(bundle_root.join("sccm-manifest.json")).expect("manifest");
    let evidence_before = fs::read(bundle_root.join(relative_path)).expect("evidence");

    fs::write(source_path, "second-longer").expect("changed source");
    assert!(capture_client_bundle(&capture_request).is_err());
    assert_eq!(
        fs::read(bundle_root.join("sccm-manifest.json")).expect("preserved manifest"),
        manifest_before
    );
    assert_eq!(
        fs::read(bundle_root.join(relative_path)).expect("preserved evidence"),
        evidence_before
    );
}
