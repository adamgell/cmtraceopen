use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use app_lib::collector::{
    manifest::write_manifest as write_generic_manifest,
    types::{
        ArtifactCounts, ArtifactResult, ArtifactStatus, CollectedArtifactFile, CollectionProfile,
    },
};
use app_lib::sccm::{
    authoritative_client_source_catalog, capture_client_bundle, discover_client_sources,
    manifest_to_client_intake_bundle, read_sccm_client_intake_bundle, read_sccm_manifest_or_legacy,
    SccmClientCaptureRequest, SccmClientDiscoveryInput, SccmClientSourceSpec, SccmCoverageState,
    SccmHostPseudonymKey, SccmManifestCoverageScope, SccmManifestSourceState, SccmRole,
    SccmRotation,
};
use cmtraceopen_parser::sccm::{assess_client_intake, declared_client_source_groups};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

const TEST_HOST_PSEUDONYM_KEY: [u8; 32] = [0xa5; 32];

fn make_private_directory(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .expect("private test directory");
    }
    #[cfg(not(unix))]
    let _ = path;
}

fn make_private_tree_to_root(root: &std::path::Path, deepest: &std::path::Path) {
    let mut current = deepest;
    loop {
        assert!(
            current.starts_with(root),
            "test path escaped its bundle root"
        );
        make_private_directory(current);
        if current == root {
            break;
        }
        current = current.parent().expect("bundle parent");
    }
}

fn write_configmgr_generic_manifest(
    bundle_root: &std::path::Path,
    result: ArtifactResult,
    counts: ArtifactCounts,
) {
    write_generic_manifest(
        bundle_root,
        "CMTRACE-SYNTHETIC",
        &CollectionProfile::embedded(),
        &[result],
        &counts,
        5,
    )
    .expect("generic writer manifest");
    make_private_directory(bundle_root);
}

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
        enumeration_status_overrides: BTreeMap::new(),
        provenance_pseudonym_key: SccmHostPseudonymKey::from_secret_bytes(TEST_HOST_PSEUDONYM_KEY)
            .expect("synthetic provenance key"),
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
        host_pseudonym_key: SccmHostPseudonymKey::from_secret_bytes(TEST_HOST_PSEUDONYM_KEY)
            .expect("synthetic host key"),
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
        .is_some_and(|value| value.starts_with("cmtraceopen.host.hmac-sha256.v1:")));
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
fn legacy_generic_writer_maps_an_exact_known_missing_source_to_absent_attempt_coverage() {
    let temp = tempdir().expect("temporary test root");
    write_configmgr_generic_manifest(
        temp.path(),
        ArtifactResult {
            id: "configmgr-ccm-logs".to_owned(),
            category: "logs".to_owned(),
            family: "configmgr".to_owned(),
            parse_hints: vec!["cmtrace".to_owned()],
            notes: Some("ConfigMgr CCMSetup logs.".to_owned()),
            status: ArtifactStatus::Missing,
            files: Vec::new(),
            error: Some("synthetic source did not match".to_owned()),
        },
        ArtifactCounts {
            collected: 0,
            missing: 1,
            failed: 0,
            total: 1,
        },
    );

    let manifest = read_sccm_manifest_or_legacy(temp.path()).expect("legacy mapping");
    assert_eq!(manifest.sccm_manifest_version, 1);
    assert_eq!(manifest.artifacts.len(), 1);
    assert_eq!(manifest.artifacts[0].state, SccmManifestSourceState::Absent);

    let bundle = read_sccm_client_intake_bundle(temp.path())
        .expect("known generic source projects attempt coverage");
    assert_eq!(bundle.artifacts.len(), 1);
    assert_eq!(bundle.artifacts[0].artifact.display_name, "ccmsetup.log");
    assert_eq!(
        bundle.artifacts[0].artifact.coverage,
        SccmCoverageState::Absent
    );
    assert!(bundle.artifacts[0].artifact.original_path.is_none());
    assert!(bundle.artifacts[0].artifact.host.is_none());
    let assessment = assess_client_intake(&bundle).expect("known legacy projection");
    assert_eq!(
        assessment
            .groups
            .iter()
            .find(|group| group.logical_artifact_id == "client-ccmsetup")
            .expect("ccmsetup group")
            .coverage,
        SccmCoverageState::Absent
    );
    assert!(assessment.physical_artifacts.is_empty());
    assert!(assessment.unsupported_artifacts.is_empty());
}

#[test]
fn legacy_generic_writer_keeps_known_failed_source_detail_unknown() {
    let temp = tempdir().expect("temporary test root");
    write_configmgr_generic_manifest(
        temp.path(),
        ArtifactResult {
            id: "configmgr-ccm-logs".to_owned(),
            category: "logs".to_owned(),
            family: "configmgr".to_owned(),
            parse_hints: vec!["cmtrace".to_owned()],
            notes: Some("ConfigMgr CCMSetup logs.".to_owned()),
            status: ArtifactStatus::Failed,
            files: Vec::new(),
            error: Some("access denied and malformed are untrusted reason text".to_owned()),
        },
        ArtifactCounts {
            collected: 0,
            missing: 0,
            failed: 1,
            total: 1,
        },
    );

    let bundle = read_sccm_client_intake_bundle(temp.path()).expect("failed source projection");
    assert_eq!(bundle.artifacts.len(), 1);
    assert_eq!(
        bundle.artifacts[0].artifact.coverage,
        SccmCoverageState::Unsupported,
        "generic reason text must not invent access-denied or parse-failed detail"
    );
    assert!(bundle.artifacts[0].relative_path.is_none());
    assert_eq!(bundle.artifacts[0].fragment_complete, Some(false));
}

#[test]
fn legacy_generic_writer_does_not_invent_physical_provenance_for_a_collected_file() {
    let temp = tempdir().expect("temporary test root");
    let relative_path = "evidence/logs/configmgr/ccmsetup/ccmsetup.log";
    let evidence_path = temp.path().join(relative_path);
    fs::create_dir_all(evidence_path.parent().expect("evidence parent")).expect("evidence tree");
    fs::write(&evidence_path, "synthetic ccmsetup evidence").expect("evidence");
    write_configmgr_generic_manifest(
        temp.path(),
        ArtifactResult {
            id: "configmgr-ccm-logs".to_owned(),
            category: "logs".to_owned(),
            family: "configmgr".to_owned(),
            parse_hints: vec!["cmtrace".to_owned()],
            notes: Some("ConfigMgr CCMSetup logs.".to_owned()),
            status: ArtifactStatus::Collected,
            files: vec![CollectedArtifactFile {
                relative_path: relative_path.to_owned(),
                origin_path: Some("C:\\Windows\\ccmsetup\\Logs\\ccmsetup.log".to_owned()),
                bytes_copied: fs::metadata(&evidence_path)
                    .expect("evidence metadata")
                    .len(),
            }],
            error: None,
        },
        ArtifactCounts {
            collected: 1,
            missing: 0,
            failed: 0,
            total: 1,
        },
    );

    let bundle = read_sccm_client_intake_bundle(temp.path())
        .expect("generic collected evidence remains conservative");
    assert!(
        bundle.artifacts.is_empty(),
        "the generic writer has no keyed path fingerprint and uses a non-SCCM intake layout"
    );
}

#[test]
fn legacy_supported_profile_without_a_gaps_field_is_an_empty_attempt_view() {
    let temp = tempdir().expect("temporary test root");
    write_configmgr_generic_manifest(
        temp.path(),
        ArtifactResult {
            id: "configmgr-ccm-logs".to_owned(),
            category: "logs".to_owned(),
            family: "configmgr".to_owned(),
            parse_hints: vec!["cmtrace".to_owned()],
            notes: Some("ConfigMgr CCMSetup logs.".to_owned()),
            status: ArtifactStatus::Missing,
            files: Vec::new(),
            error: Some("synthetic source did not match".to_owned()),
        },
        ArtifactCounts {
            collected: 0,
            missing: 1,
            failed: 0,
            total: 1,
        },
    );
    let manifest_path = temp.path().join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("generic manifest"))
            .expect("generic manifest JSON");
    assert!(
        manifest["collection"]["results"]
            .as_object_mut()
            .expect("generic results")
            .remove("gaps")
            .is_some(),
        "generic writer fixture must contain gaps before removal"
    );
    fs::write(
        &manifest_path,
        serde_json::to_vec(&manifest).expect("generic manifest JSON"),
    )
    .expect("manifest without gaps");

    let bundle = read_sccm_client_intake_bundle(temp.path()).expect("missing gaps is tolerated");
    assert!(bundle.artifacts.is_empty());
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
fn native_source_provenance_is_keyed_versioned_and_debug_redacted() {
    let temp = tempdir().expect("temporary test root");
    let root = temp.path().join("private-user-path");
    fs::create_dir_all(&root).expect("log root");
    fs::write(root.join("PolicyAgent.log"), "policy").expect("policy log");
    let policy = source(
        "sccm-client-group:v1:client-policy-agent",
        "client-policy-agent",
        &["PolicyAgent.log"],
    );
    let first_input = input(vec![root.clone()], vec![policy.clone()]);
    let mut second_input = input(vec![root.clone()], vec![policy]);
    second_input.provenance_pseudonym_key =
        SccmHostPseudonymKey::from_secret_bytes([0x5a; 32]).expect("second provenance key");

    let first = discover_client_sources(&first_input).expect("first discovery");
    let second = discover_client_sources(&second_input).expect("second discovery");
    let first_artifact = &first.artifacts[0];
    let second_artifact = &second.artifacts[0];
    assert_ne!(first_artifact.root_handle, second_artifact.root_handle);
    assert_ne!(first_artifact.source_handle, second_artifact.source_handle);
    assert_ne!(
        first_artifact.path_fingerprint,
        second_artifact.path_fingerprint
    );
    let raw_path = root
        .canonicalize()
        .expect("canonical root")
        .to_string_lossy()
        .into_owned();
    assert!(!format!("{first_artifact:?}").contains(&raw_path));

    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;

        let unsalted = Sha256::digest(
            root.canonicalize()
                .expect("canonical root")
                .as_os_str()
                .as_bytes(),
        )
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
        assert_ne!(first_artifact.root_handle, format!("root-{unsalted}"));
    }

    let bundle_root = temp.path().join("bundle");
    let captured =
        capture_client_bundle(&request(bundle_root.clone(), "LAB-CLIENT-01", first_input))
            .expect("capture");
    let serialized =
        fs::read_to_string(bundle_root.join("sccm-manifest.json")).expect("public manifest");
    assert_eq!(
        serde_json::to_value(captured.manifest).expect("manifest JSON")["provenanceProfile"],
        "hmacSha256V1"
    );
    assert!(!serialized.contains(&raw_path));
    let json_escaped_raw_path = serde_json::to_string(&raw_path).expect("JSON-escaped raw path");
    let json_escaped_raw_path = json_escaped_raw_path
        .strip_prefix('"')
        .and_then(|path| path.strip_suffix('"'))
        .expect("JSON string delimiters");
    assert!(!serialized.contains(json_escaped_raw_path));
    assert!(!serialized.contains("provenancePseudonymKey"));
    assert!(!serialized.contains(&"a5".repeat(32)));
}

#[test]
fn host_handle_is_keyed_per_retention_scope_and_not_an_unsalted_digest() {
    let temp = tempdir().expect("temporary test root");
    let root = temp.path().join("logs");
    fs::create_dir_all(&root).expect("log root");
    fs::write(root.join("PolicyAgent.log"), "policy").expect("policy log");
    let policy = source(
        "sccm-client-group:v1:client-policy-agent",
        "client-policy-agent",
        &["PolicyAgent.log"],
    );
    let raw_host = "LAB-CLIENT-01";
    let first_request = request(
        temp.path().join("bundle-a"),
        raw_host,
        input(vec![root.clone()], vec![policy.clone()]),
    );
    let mut second_request = request(
        temp.path().join("bundle-b"),
        raw_host,
        input(vec![root.clone()], vec![policy.clone()]),
    );
    second_request.host_pseudonym_key =
        SccmHostPseudonymKey::from_secret_bytes([0x5a; 32]).expect("second synthetic host key");
    let same_key_request = request(
        temp.path().join("bundle-c"),
        raw_host,
        input(vec![root.clone()], vec![policy.clone()]),
    );
    let different_host_request = request(
        temp.path().join("bundle-d"),
        "LAB-CLIENT-02",
        input(vec![root], vec![policy]),
    );

    let first = capture_client_bundle(&first_request).expect("first capture");
    let second = capture_client_bundle(&second_request).expect("second capture");
    let same_key = capture_client_bundle(&same_key_request).expect("same-key capture");
    let different_host =
        capture_client_bundle(&different_host_request).expect("different-host capture");
    let first_handle = first
        .manifest
        .host_handle
        .as_deref()
        .expect("first host handle");
    let second_handle = second
        .manifest
        .host_handle
        .as_deref()
        .expect("second host handle");
    let same_key_handle = same_key
        .manifest
        .host_handle
        .as_deref()
        .expect("same-key host handle");
    let different_host_handle = different_host
        .manifest
        .host_handle
        .as_deref()
        .expect("different-host handle");
    let unsalted = Sha256::digest(raw_host.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let serialized = serde_json::to_string(&first.manifest).expect("manifest JSON");

    assert_ne!(first_handle, second_handle);
    assert_eq!(first_handle, same_key_handle);
    assert_ne!(first_handle, different_host_handle);
    assert_ne!(
        first_handle,
        format!("cmtraceopen.host.sha256.v1:{unsalted}")
    );
    assert!(!serialized.contains("hostPseudonymKey"));
    assert!(!serialized.contains(&"a5".repeat(32)));
    assert!(!serialized.contains("[165,165"));
}

#[test]
fn host_pseudonym_key_is_required_redacted_and_absent_from_capture_errors() {
    let temp = tempdir().expect("temporary test root");
    let bundle_root = temp.path().join("bundle");
    let missing_error =
        SccmHostPseudonymKey::from_secret_bytes([0; 32]).expect_err("zero key fails closed");
    assert!(!bundle_root.exists());
    assert!(!missing_error.to_string().contains(&"00".repeat(32)));

    let secret_key = [0x7b; 32];
    let protected_key =
        SccmHostPseudonymKey::from_secret_bytes(secret_key).expect("protected host key");
    assert_eq!(
        format!("{protected_key:?}"),
        "SccmHostPseudonymKey([REDACTED])"
    );
    let mut malformed_host = request(
        temp.path().join("malformed-bundle"),
        "SECRET-HOST\n",
        input(Vec::new(), Vec::new()),
    );
    malformed_host.host_pseudonym_key = protected_key;
    let malformed_error = capture_client_bundle(&malformed_host).expect_err("host fails closed");
    let error_text = malformed_error.to_string();
    assert!(!error_text.contains("SECRET-HOST"));
    assert!(!error_text.contains(&"7b".repeat(32)));
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
fn busy_directory_filters_before_rotation_ordering_and_budgeting() {
    let temp = tempdir().expect("temporary test root");
    let root = temp.path().join("busy-logs");
    fs::create_dir_all(&root).expect("log root");

    for index in (0..64).rev() {
        fs::write(root.join(format!("unrelated-{index:03}.log")), "noise")
            .expect("unrelated entry");
    }
    for basename in [
        "PolicyAgent.log.2",
        "PolicyAgent.log.0",
        "PolicyAgent.log.20260730-150000",
        "PolicyAgent.log.01",
        "PolicyAgent.lo_",
        "PolicyAgent.log.invalid",
        "PolicyAgent.log.1",
        "PolicyAgent.log.extra.2",
        "PolicyAgent.log",
    ] {
        fs::write(root.join(basename), basename).expect("shuffled entry");
    }

    let mut discovery = input(
        vec![root],
        vec![source(
            "sccm-client-group:v1:client-policy-agent",
            "client-policy-agent",
            &["PolicyAgent.log"],
        )],
    );
    discovery.max_files_per_source = 2;
    discovery.max_bytes_per_source = 1024;

    let result = discover_client_sources(&discovery).expect("busy discovery");
    assert_eq!(
        result
            .artifacts
            .iter()
            .map(|artifact| artifact.basename.as_str())
            .collect::<Vec<_>>(),
        vec![
            "PolicyAgent.log",
            "PolicyAgent.lo_",
            "PolicyAgent.log.1",
            "PolicyAgent.log.2",
            "PolicyAgent.log.20260730-150000",
        ]
    );
    assert_eq!(
        result
            .artifacts
            .iter()
            .map(|artifact| (artifact.state, artifact.copy_bytes))
            .collect::<Vec<_>>(),
        vec![
            (SccmManifestSourceState::Captured, 15),
            (SccmManifestSourceState::Capped, 15),
            (SccmManifestSourceState::Capped, 0),
            (SccmManifestSourceState::Capped, 0),
            (SccmManifestSourceState::Capped, 0),
        ]
    );
    assert!(result.artifacts.iter().all(|artifact| {
        !artifact.basename.contains("invalid")
            && !artifact.basename.contains("extra")
            && artifact.basename != "PolicyAgent.log.0"
            && artifact.basename != "PolicyAgent.log.01"
    }));
}

#[test]
fn partial_directory_enumeration_retains_current_and_a_distinct_root_gap() {
    let temp = tempdir().expect("temporary test root");
    let root = temp.path().join("partially-readable-logs");
    let bundle_root = temp.path().join("bundle");
    fs::create_dir_all(&root).expect("log root");
    fs::write(root.join("PolicyAgent.log"), "current-policy").expect("current log");
    let mut discovery = input(
        vec![root.clone()],
        vec![source(
            "sccm-client-group:v1:client-policy-agent",
            "client-policy-agent",
            &["PolicyAgent.log"],
        )],
    );
    discovery
        .enumeration_status_overrides
        .insert(root, SccmCoverageState::AccessDenied);

    let discovered = discover_client_sources(&discovery).expect("partial discovery");
    assert_eq!(discovered.artifacts.len(), 1);
    let current = &discovered.artifacts[0];
    assert_eq!(current.rotation, SccmRotation::Current);
    assert_eq!(current.state, SccmManifestSourceState::Captured);
    let gap = discovered
        .source_states
        .iter()
        .find(|state| state.coverage_scope == SccmManifestCoverageScope::RootEnumeration)
        .expect("root enumeration gap");
    assert_eq!(gap.state, SccmManifestSourceState::AccessDenied);
    assert_eq!(
        gap.root_handle.as_deref(),
        Some(current.root_handle.as_str())
    );
    assert_ne!(
        gap.path_fingerprint.as_deref(),
        Some(current.path_fingerprint.as_str())
    );

    let captured = capture_client_bundle(&request(bundle_root, "LAB-CLIENT-01", discovery))
        .expect("partial capture remains valid");
    assert_eq!(captured.manifest.artifacts.len(), 2);
    assert!(captured.manifest.artifacts.iter().any(|artifact| {
        artifact.coverage_scope == SccmManifestCoverageScope::RootEnumeration
            && artifact.state == SccmManifestSourceState::AccessDenied
            && artifact.relative_path.is_none()
    }));
    let assessment = assess_client_intake(
        &manifest_to_client_intake_bundle(&captured.manifest).expect("pure partial bundle"),
    )
    .expect("partial assessment");
    let policy = assessment
        .groups
        .iter()
        .find(|group| group.logical_artifact_id == "client-policy-agent")
        .expect("policy group");
    assert_eq!(policy.coverage, SccmCoverageState::AccessDenied);
    assert_eq!(assessment.physical_artifacts.len(), 1);
}

#[test]
fn capped_capture_retains_exact_bounded_prefix_and_digest_as_incomplete_evidence() {
    let temp = tempdir().expect("temporary test root");
    let root = temp.path().join("logs");
    let bundle_root = temp.path().join("bundle");
    fs::create_dir_all(&root).expect("log root");
    fs::write(root.join("PolicyAgent.log"), b"abc\xc3\xa9-rest").expect("policy log");
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
        b"abc\xc3"
    );
    let json = serde_json::to_value(capped).expect("capped JSON");
    assert_eq!(json["fragmentComplete"], false);
    assert_eq!(json["captureLimitKind"], "bytes");
    assert_eq!(json["limitApplied"], 4);
    let expected_sha256 = Sha256::digest(b"abc\xc3")
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(json["contentSha256"], expected_sha256);
}

#[test]
fn file_count_cap_keeps_rotation_gap_without_a_zero_byte_evidence_file() {
    let temp = tempdir().expect("temporary test root");
    let root = temp.path().join("logs");
    let bundle_root = temp.path().join("bundle");
    fs::create_dir_all(&root).expect("log root");
    fs::write(root.join("PolicyAgent.log"), b"current").expect("current log");
    fs::write(root.join("PolicyAgent.lo_"), b"rotation").expect("rotation log");
    let mut discovery = input(
        vec![root],
        vec![source(
            "sccm-client-group:v1:client-policy-agent",
            "client-policy-agent",
            &["PolicyAgent.log"],
        )],
    );
    discovery.max_files_per_source = 1;

    let captured = capture_client_bundle(&request(bundle_root.clone(), "LAB-CLIENT-01", discovery))
        .expect("file-capped capture");
    assert_eq!(captured.manifest.artifacts.len(), 1);
    let json = serde_json::to_value(&captured.manifest).expect("manifest JSON");
    let artifacts = json["artifacts"].as_array().expect("artifacts");
    let retained = &artifacts[0];
    let gaps = json["captureGaps"].as_array().expect("capture gaps");
    assert_eq!(gaps.len(), 1);
    let gap = &gaps[0];
    assert_eq!(retained["state"], "capped");
    assert_eq!(retained["captureLimitKind"], "fileCount");
    assert_eq!(gap["state"], "capped");
    assert_eq!(gap["captureLimitKind"], "fileCount");
    assert_eq!(gap["bytesRetained"], 0);
    assert!(gap.get("relativePath").is_none());
    assert_eq!(
        fs::read(
            bundle_root.join(
                retained["relativePath"]
                    .as_str()
                    .expect("retained evidence path")
            )
        )
        .expect("retained evidence"),
        b"current"
    );
    let assessment = assess_client_intake(
        &manifest_to_client_intake_bundle(&captured.manifest).expect("pure capped bundle"),
    )
    .expect("capped assessment");
    assert_eq!(assessment.physical_artifacts.len(), 1);
    assert_eq!(
        assessment
            .groups
            .iter()
            .find(|group| group.logical_artifact_id == "client-policy-agent")
            .expect("policy group")
            .coverage,
        SccmCoverageState::Capped
    );
}

#[test]
fn file_count_cap_keeps_a_fully_captured_empty_current_file_distinct_from_rotation_gap() {
    let temp = tempdir().expect("temporary test root");
    let root = temp.path().join("logs");
    let bundle_root = temp.path().join("bundle");
    fs::create_dir_all(&root).expect("log root");
    fs::write(root.join("PolicyAgent.log"), b"").expect("empty current log");
    fs::write(root.join("PolicyAgent.lo_"), b"rotation").expect("rotation log");
    let mut discovery = input(
        vec![root],
        vec![source(
            "sccm-client-group:v1:client-policy-agent",
            "client-policy-agent",
            &["PolicyAgent.log"],
        )],
    );
    discovery.max_files_per_source = 1;

    let captured = capture_client_bundle(&request(bundle_root.clone(), "LAB-CLIENT-01", discovery))
        .expect("file-capped capture");
    assert_eq!(captured.manifest.artifacts.len(), 1);
    assert_eq!(captured.manifest.capture_gaps.len(), 1);
    let retained = &captured.manifest.artifacts[0];
    assert_eq!(retained.basename, "PolicyAgent.log");
    assert_eq!(retained.state, SccmManifestSourceState::Capped);
    assert_eq!(retained.bytes_copied, 0);
    let relative_path = retained
        .relative_path
        .as_deref()
        .expect("fully captured empty evidence path");
    assert_eq!(
        fs::metadata(bundle_root.join(relative_path))
            .expect("fully captured empty evidence")
            .len(),
        0
    );
    assert_eq!(
        captured.manifest.capture_gaps[0].basename,
        "PolicyAgent.lo_"
    );
    assert_eq!(captured.manifest.capture_gaps[0].bytes_retained, 0);
}

#[test]
fn exhausted_byte_budget_keeps_gap_without_a_zero_byte_evidence_file() {
    let temp = tempdir().expect("temporary test root");
    let root = temp.path().join("logs");
    let bundle_root = temp.path().join("bundle");
    fs::create_dir_all(&root).expect("log root");
    fs::write(root.join("PolicyAgent.log"), b"1234").expect("current log");
    fs::write(root.join("PolicyAgent.lo_"), b"5678").expect("rotation log");
    let mut discovery = input(
        vec![root],
        vec![source(
            "sccm-client-group:v1:client-policy-agent",
            "client-policy-agent",
            &["PolicyAgent.log"],
        )],
    );
    discovery.max_bytes_per_source = 4;

    let captured = capture_client_bundle(&request(bundle_root, "LAB-CLIENT-01", discovery))
        .expect("byte-capped capture");
    let json = serde_json::to_value(&captured.manifest).expect("manifest JSON");
    let artifacts = json["artifacts"].as_array().expect("artifacts");
    assert_eq!(artifacts.len(), 1);
    assert!(artifacts.iter().any(|artifact| {
        artifact["state"] == "capped" && artifact["captureLimitKind"] == "bytes"
    }));
    let gaps = json["captureGaps"].as_array().expect("capture gaps");
    assert_eq!(gaps.len(), 1);
    assert!(gaps.iter().any(|gap| {
        gap["state"] == "capped"
            && gap["captureLimitKind"] == "bytes"
            && gap["bytesRetained"] == 0
            && gap.get("relativePath").is_none()
    }));
}

#[test]
fn exhausted_byte_budget_does_not_turn_later_rotations_into_file_count_gaps() {
    let temp = tempdir().expect("temporary test root");
    let root = temp.path().join("logs");
    let bundle_root = temp.path().join("bundle");
    fs::create_dir_all(&root).expect("log root");
    fs::write(root.join("PolicyAgent.log"), b"curr").expect("current log");
    fs::write(root.join("PolicyAgent.lo_"), b"lo").expect("lo rotation");
    fs::write(root.join("PolicyAgent.log.1"), b"one").expect("numbered rotation");
    let mut discovery = input(
        vec![root],
        vec![source(
            "sccm-client-group:v1:client-policy-agent",
            "client-policy-agent",
            &["PolicyAgent.log"],
        )],
    );
    discovery.max_files_per_source = 2;
    discovery.max_bytes_per_source = 4;

    let captured = capture_client_bundle(&request(bundle_root, "LAB-CLIENT-01", discovery))
        .expect("byte-capped capture");
    assert_eq!(captured.manifest.artifacts.len(), 1);
    assert_eq!(captured.manifest.capture_gaps.len(), 2);
    assert!(captured.manifest.capture_gaps.iter().all(|gap| {
        gap.capture_limit_kind == app_lib::sccm::SccmCaptureLimitKind::Bytes
            && gap.bytes_retained == 0
    }));
}

#[test]
fn zero_capture_limits_fail_before_creating_a_bundle() {
    let temp = tempdir().expect("temporary test root");
    let bundle_root = temp.path().join("bundle");
    let mut discovery = input(Vec::new(), Vec::new());
    discovery.max_files_per_source = 0;
    discovery.max_bytes_per_source = 0;

    let error = capture_client_bundle(&request(bundle_root.clone(), "LAB-CLIENT-01", discovery))
        .expect_err("zero limits fail closed");
    assert!(error.to_string().contains("positive capture limits"));
    assert!(!bundle_root.exists());
}

#[cfg(unix)]
#[test]
fn capture_creates_private_bundle_directories_and_files() {
    use std::os::unix::fs::PermissionsExt;

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
    .expect("private capture");
    let relative_path = captured.manifest.artifacts[0]
        .relative_path
        .as_deref()
        .expect("evidence path");
    let evidence_path = bundle_root.join(relative_path);

    let mut current = Some(evidence_path.parent().expect("evidence parent"));
    while let Some(directory) = current {
        if !directory.starts_with(&bundle_root) {
            break;
        }
        assert_eq!(
            fs::metadata(directory)
                .expect("directory metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700,
            "directory {} must be private",
            directory.display()
        );
        if directory == bundle_root {
            break;
        }
        current = directory.parent();
    }
    for file in [evidence_path, bundle_root.join("sccm-manifest.json")] {
        assert_eq!(
            fs::metadata(&file)
                .expect("file metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600,
            "file {} must be private",
            file.display()
        );
    }
}

#[cfg(windows)]
#[test]
fn windows_capture_requires_a_precreated_acl_protected_bundle_root() {
    let temp = tempdir().expect("temporary test root");
    let bundle_root = temp.path().join("not-precreated");
    let request = request(
        bundle_root.clone(),
        "LAB-CLIENT-01",
        input(Vec::new(), Vec::new()),
    );

    let error = capture_client_bundle(&request).expect_err("missing ACL root fails closed");
    assert!(error.to_string().contains("pre-created"));
    assert!(!bundle_root.exists());
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
    make_private_directory(temp.path());
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
    make_private_directory(temp.path());
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
fn manifest_reader_rejects_same_length_evidence_digest_mismatch() {
    let temp = tempdir().expect("temporary test root");
    let root = temp.path().join("logs");
    let bundle_root = temp.path().join("bundle");
    fs::create_dir_all(&root).expect("log root");
    fs::write(root.join("PolicyAgent.log"), b"policy").expect("source");
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
    let relative_path = captured.manifest.artifacts[0]
        .relative_path
        .as_deref()
        .expect("evidence path");
    fs::write(bundle_root.join(relative_path), b"tamper").expect("same-length tamper");

    assert!(read_sccm_manifest_or_legacy(&bundle_root).is_err());
}

#[test]
fn parse_failed_override_remains_distinct_from_unsupported() {
    let temp = tempdir().expect("temporary test root");
    let root = temp.path().join("logs");
    let bundle_root = temp.path().join("bundle");
    fs::create_dir_all(&root).expect("log root");
    let source_path = root.join("PolicyAgent.log");
    fs::write(&source_path, b"0123456789").expect("policy log");
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
    discovery.max_bytes_per_source = 4;

    capture_client_bundle(&request(bundle_root.clone(), "LAB-CLIENT-01", discovery))
        .expect("capture");
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(bundle_root.join("sccm-manifest.json")).expect("manifest"),
    )
    .expect("manifest JSON");
    assert_eq!(manifest["artifacts"][0]["state"], "parseFailed");
    assert_eq!(manifest["artifacts"][0]["limitApplied"], 4);
    assert_eq!(manifest["artifacts"][0]["fragmentComplete"], false);
    let relative_path = manifest["artifacts"][0]["relativePath"]
        .as_str()
        .expect("bounded malformed evidence path");
    assert_eq!(
        fs::read(bundle_root.join(relative_path)).expect("bounded malformed evidence"),
        b"0123"
    );
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
    make_private_tree_to_root(
        &bundle_root,
        destination.parent().expect("destination parent"),
    );
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
    make_private_tree_to_root(
        &bundle_root,
        blocked_destination.parent().expect("blocked parent"),
    );
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
