use std::fs;
use std::path::Path;

use app_lib::sccm::{
    read_sccm_client_intake_bundle, read_sccm_manifest_or_legacy, SccmBundleManifestV1,
    SccmManifestProvenance, SccmManifestSourceState, MAX_SCCM_MANIFEST_ARTIFACTS,
    SCCM_MANIFEST_FILE_NAME,
};
use cmtraceopen_parser::sccm::{assess_client_intake, SccmCoverageState, SccmRotation};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

const COLLECTED_AT_UTC: &str = "2026-07-30T15:00:00Z";
const CONFIGMGR_VERSION: &str = "5.00.TEST.0000";
const POLICY_BASENAME: &str = "PolicyAgent.log";
const POLICY_GROUP: &str = "client-policy-agent";
const ROOT_HANDLE: &str = "root-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HOST_HANDLE: &str = concat!(
    "cmtraceopen.host.hmac-sha256.v1:",
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
);

fn sha256(value: &[u8]) -> String {
    Sha256::digest(value)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn catalog_entry_id() -> String {
    catalog_entry_id_for(POLICY_BASENAME)
}

fn catalog_entry_id_for(basename: &str) -> String {
    format!(
        "sccm-client-source:v1:sha256:{}",
        sha256(basename.as_bytes())
    )
}

fn source_digest() -> String {
    let root_digest = ROOT_HANDLE
        .strip_prefix("root-")
        .expect("fixture root handle is versioned");
    sha256(format!("cmtraceopen.sccm.source.v1\0{root_digest}\0{POLICY_BASENAME}").as_bytes())
}

fn source_handle() -> String {
    format!("cmtraceopen.source.sha256.v1:{}", source_digest())
}

fn path_fingerprint() -> String {
    format!("sha256:{}", source_digest())
}

fn rotation_lineage() -> String {
    format!(
        "cmtraceopen.lineage.sha256.v1:{}",
        sha256(format!("lineage:v1:{}", source_digest()).as_bytes())
    )
}

fn rotation_basename(rotation: &SccmRotation) -> String {
    match rotation {
        SccmRotation::Current => POLICY_BASENAME.to_owned(),
        SccmRotation::LoUnderscore => "PolicyAgent.lo_".to_owned(),
        SccmRotation::Numbered(number) => format!("{POLICY_BASENAME}.{number}"),
        SccmRotation::Timestamped(timestamp) => format!("{POLICY_BASENAME}.{timestamp}"),
        SccmRotation::Unknown(_) => panic!("fixture never uses unknown rotations"),
    }
}

fn rotation_segment(rotation: &SccmRotation) -> String {
    match rotation {
        SccmRotation::Current => "current".to_owned(),
        SccmRotation::LoUnderscore => "lo".to_owned(),
        SccmRotation::Numbered(number) => format!("numbered-{number}"),
        SccmRotation::Timestamped(timestamp) => format!("timestamped-{timestamp}"),
        SccmRotation::Unknown(_) => panic!("fixture never uses unknown rotations"),
    }
}

fn relative_path(rotation: &SccmRotation) -> String {
    format!(
        "evidence/sccm/client/{POLICY_GROUP}/{ROOT_HANDLE}/{}/{}",
        rotation_segment(rotation),
        rotation_basename(rotation)
    )
}

#[derive(Clone)]
struct PhysicalArtifactFixture {
    value: Value,
    content: Vec<u8>,
}

fn physical_artifact(rotation: SccmRotation, content: &[u8]) -> PhysicalArtifactFixture {
    let basename = rotation_basename(&rotation);
    let fingerprint = path_fingerprint();
    let artifact_id = format!(
        "sccm-artifact:v1:sha256:{}",
        sha256(
            format!(
                "artifact:v1:{fingerprint}:{}:{basename}",
                rotation_segment(&rotation)
            )
            .as_bytes()
        )
    );
    PhysicalArtifactFixture {
        value: json!({
        "catalogEntryId": catalog_entry_id(),
        "logicalArtifactIds": [POLICY_GROUP],
        "artifactId": artifact_id,
        "role": "client",
        "sourceHandle": source_handle(),
        "rootHandle": ROOT_HANDLE,
        "pathFingerprint": fingerprint,
        "rotationLineage": rotation_lineage(),
        "relativePath": relative_path(&rotation),
        "basename": basename,
        "rotation": rotation,
        "state": "captured",
        "coverageScope": "source",
        "bytesCopied": content.len(),
        "contentSha256": sha256(content),
        "fragmentComplete": false,
        "configmgrVersion": CONFIGMGR_VERSION,
        "collectedAtUtc": COLLECTED_AT_UTC,
        "encoding": "utf-8"
        }),
        content: content.to_vec(),
    }
}

fn capture_gap(rotation: SccmRotation, state: &str) -> Value {
    let basename = rotation_basename(&rotation);
    let fingerprint = path_fingerprint();
    let artifact_id = format!(
        "sccm-artifact:v1:sha256:{}",
        sha256(
            format!(
                "marker:v1:{}:{state}:{}:{basename}:{fingerprint}",
                catalog_entry_id(),
                rotation_segment(&rotation)
            )
            .as_bytes()
        )
    );
    json!({
        "artifactId": artifact_id,
        "catalogEntryId": catalog_entry_id(),
        "logicalArtifactIds": [POLICY_GROUP],
        "sourceHandle": source_handle(),
        "rootHandle": ROOT_HANDLE,
        "pathFingerprint": fingerprint,
        "rotationLineage": rotation_lineage(),
        "basename": basename,
        "rotation": rotation,
        "state": state,
        "captureLimitKind": "fileCount",
        "sourceBytes": 2048,
        "bytesRetained": 0
    })
}

fn native_manifest(artifacts: Vec<Value>, capture_gaps: Vec<Value>) -> Value {
    json!({
        "sccmManifestVersion": 1,
        "diagnosticsSchemaVersion": 1,
        "sourceCatalogVersion": 1,
        "provenance": "nativeClientCapture",
        "provenanceProfile": "hmacSha256V1",
        "hostHandle": HOST_HANDLE,
        "collectedAtUtc": COLLECTED_AT_UTC,
        "maxFilesPerSource": 8,
        "maxBytesPerSource": 4096,
        "artifacts": artifacts,
        "captureGaps": capture_gaps
    })
}

fn make_private_directory(path: &Path) {
    fs::create_dir_all(path).expect("create fixture directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .expect("make fixture directory private");
    }
}

fn write_native_bundle(
    root: &Path,
    artifacts: &[&PhysicalArtifactFixture],
    capture_gaps: &[Value],
) {
    make_private_directory(root);
    for artifact in artifacts {
        let relative_path = artifact.value["relativePath"]
            .as_str()
            .expect("physical fixture path");
        let destination = root.join(relative_path);
        fs::create_dir_all(destination.parent().expect("evidence parent"))
            .expect("create evidence tree");
        fs::write(destination, &artifact.content).expect("write synthetic evidence");
    }
    let manifest = native_manifest(
        artifacts
            .iter()
            .map(|artifact| artifact.value.clone())
            .collect(),
        capture_gaps.to_vec(),
    );
    fs::write(
        root.join(SCCM_MANIFEST_FILE_NAME),
        serde_json::to_vec_pretty(&manifest).expect("serialize fixture manifest"),
    )
    .expect("write fixture manifest");
}

fn remove_written_evidence(root: &Path, artifact: &PhysicalArtifactFixture) {
    let relative_path = artifact.value["relativePath"]
        .as_str()
        .expect("physical fixture path");
    fs::remove_file(root.join(relative_path)).expect("remove evidence after writing manifest");
}

fn set_native_limits(root: &Path, max_files: u64, max_bytes: u64) {
    let manifest_path = root.join(SCCM_MANIFEST_FILE_NAME);
    let mut manifest: Value = serde_json::from_slice(
        &fs::read(&manifest_path).expect("read synthetic manifest for limit mutation"),
    )
    .expect("synthetic manifest is JSON");
    manifest["maxFilesPerSource"] = json!(max_files);
    manifest["maxBytesPerSource"] = json!(max_bytes);
    fs::write(
        manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("serialize limit-mutated manifest"),
    )
    .expect("write limit-mutated manifest");
}

#[test]
fn validated_v1_reader_projects_one_physical_client_artifact() {
    let temp = tempdir().expect("temporary root");
    let bundle_root = temp.path().join("bundle");
    let current = physical_artifact(SccmRotation::Current, b"policy-current");
    write_native_bundle(&bundle_root, &[&current], &[]);

    let manifest = read_sccm_manifest_or_legacy(&bundle_root).expect("validated manifest");
    let bundle = read_sccm_client_intake_bundle(&bundle_root).expect("verified pure projection");

    assert_eq!(manifest.sccm_manifest_version, 1);
    assert_eq!(
        manifest.provenance,
        SccmManifestProvenance::NativeClientCapture
    );
    assert_eq!(bundle.artifacts.len(), 1);
    assert!(bundle.capture_gaps.is_empty());
    let physical = &bundle.artifacts[0];
    assert_eq!(physical.artifact.display_name, POLICY_BASENAME);
    assert_eq!(physical.artifact.coverage, SccmCoverageState::Captured);
    assert_eq!(physical.artifact.original_path, None);
    assert_eq!(physical.artifact.host, None);
    assert_eq!(
        physical.relative_path.as_deref(),
        Some(relative_path(&SccmRotation::Current).as_str())
    );
    assert_eq!(physical.fragment_complete, Some(false));
}

#[test]
fn validated_v1_reader_preserves_a_complete_fragment() {
    let temp = tempdir().expect("temporary root");
    let bundle_root = temp.path().join("bundle");
    let mut current = physical_artifact(SccmRotation::Current, b"complete-policy-current");
    current.value["fragmentComplete"] = json!(true);
    write_native_bundle(&bundle_root, &[&current], &[]);

    let bundle = read_sccm_client_intake_bundle(&bundle_root).expect("verified pure projection");
    assert_eq!(bundle.artifacts[0].fragment_complete, Some(true));
}

#[test]
fn omitted_capped_rotation_projects_as_a_gap_without_a_fake_fragment() {
    let temp = tempdir().expect("temporary root");
    let bundle_root = temp.path().join("bundle");
    let current = physical_artifact(SccmRotation::Current, b"policy-current");
    let omitted = capture_gap(SccmRotation::Numbered(1), "capped");
    write_native_bundle(&bundle_root, &[&current], std::slice::from_ref(&omitted));

    let bundle = read_sccm_client_intake_bundle(&bundle_root).expect("projected bundle");
    assert_eq!(
        bundle.artifacts.len(),
        1,
        "a gap is not a zero-byte artifact"
    );
    assert_eq!(bundle.capture_gaps.len(), 1);
    assert_eq!(bundle.capture_gaps[0].basename, "PolicyAgent.log.1");
    assert_eq!(bundle.capture_gaps[0].rotation, SccmRotation::Numbered(1));
    assert_eq!(bundle.capture_gaps[0].coverage, SccmCoverageState::Capped);

    let assessment = assess_client_intake(&bundle).expect("assessment accepts native gap");
    let group = assessment
        .groups
        .iter()
        .find(|group| group.logical_artifact_id == POLICY_GROUP)
        .expect("policy group");
    assert_eq!(group.fragments.len(), 1);
    assert_eq!(group.coverage, SccmCoverageState::Capped);
    assert_eq!(assessment.capture_gaps, bundle.capture_gaps);
}

#[test]
fn parse_failed_omitted_rotation_remains_coverage_only() {
    let temp = tempdir().expect("temporary root");
    let bundle_root = temp.path().join("bundle");
    let current = physical_artifact(SccmRotation::Current, b"policy-current");
    let failed = capture_gap(SccmRotation::Numbered(2), "parseFailed");
    write_native_bundle(&bundle_root, &[&current], std::slice::from_ref(&failed));
    let bundle = read_sccm_client_intake_bundle(&bundle_root).expect("verified pure projection");

    assert_eq!(bundle.artifacts.len(), 1);
    assert_eq!(bundle.capture_gaps.len(), 1);
    assert_eq!(
        bundle.capture_gaps[0].coverage,
        SccmCoverageState::ParseFailed
    );
    assert_eq!(bundle.capture_gaps[0].rotation, SccmRotation::Numbered(2));
}

#[test]
fn native_manifest_uses_one_shared_4096_entry_decode_ceiling() {
    let gap = capture_gap(SccmRotation::Numbered(1), "capped");
    let boundary = native_manifest(
        vec![physical_artifact(SccmRotation::Current, b"policy-current").value],
        vec![gap.clone(); MAX_SCCM_MANIFEST_ARTIFACTS - 1],
    );
    serde_json::from_value::<SccmBundleManifestV1>(boundary)
        .expect("combined 4096-entry boundary decodes");

    let overflow = native_manifest(
        vec![physical_artifact(SccmRotation::Current, b"policy-current").value],
        vec![gap; MAX_SCCM_MANIFEST_ARTIFACTS],
    );
    let error = serde_json::from_value::<SccmBundleManifestV1>(overflow)
        .expect_err("combined 4097-entry manifest is rejected during decoding");
    assert!(error
        .to_string()
        .contains("too many artifacts or capture gaps"));
}

#[test]
fn reader_rejects_artifacts_outside_canonical_rotation_order() {
    let temp = tempdir().expect("temporary root");
    let bundle_root = temp.path().join("bundle");
    let current = physical_artifact(SccmRotation::Current, b"policy-current");
    let numbered = physical_artifact(SccmRotation::Numbered(1), b"policy-rotation-one");
    write_native_bundle(&bundle_root, &[&numbered, &current], &[]);

    let error = read_sccm_manifest_or_legacy(&bundle_root)
        .expect_err("manifest order is part of deterministic intake");
    assert!(error.to_string().contains("deterministic order"));
}

#[test]
fn reader_rejects_duplicate_artifact_ids() {
    let temp = tempdir().expect("temporary root");
    let bundle_root = temp.path().join("bundle");
    let current = physical_artifact(SccmRotation::Current, b"policy-current");
    write_native_bundle(&bundle_root, &[&current, &current], &[]);

    let error =
        read_sccm_manifest_or_legacy(&bundle_root).expect_err("colliding artifacts fail closed");
    assert!(error.to_string().contains("duplicate artifact IDs"));
}

#[test]
fn legacy_projection_never_invents_native_capture_gaps() {
    let temp = tempdir().expect("temporary root");
    let bundle_root = temp.path().join("legacy-bundle");
    make_private_directory(&bundle_root);
    fs::write(
        bundle_root.join("manifest.json"),
        serde_json::to_vec_pretty(&json!({
            "collection": {
                "collectorProfile": "cmtrace-full-diagnostics-v1",
                "collectorVersion": "1.1.0",
                "results": {
                    "gaps": [{
                        "artifactId": "configmgr-ccm-logs",
                        "category": "logs",
                        "status": "Missing"
                    }]
                }
            },
            "artifacts": []
        }))
        .expect("legacy JSON"),
    )
    .expect("legacy manifest");

    let manifest = read_sccm_manifest_or_legacy(&bundle_root).expect("legacy manifest view");
    let bundle = read_sccm_client_intake_bundle(&bundle_root).expect("legacy pure view");
    assert_eq!(
        manifest.provenance,
        SccmManifestProvenance::LegacyGenericUnscoped
    );
    assert!(manifest.capture_gaps.is_empty());
    assert!(bundle.capture_gaps.is_empty());
    assert_eq!(bundle.artifacts.len(), 1);
    let expected_catalog_id = catalog_entry_id_for("ccmsetup.log");
    let expected_artifact_id = format!(
        "sccm-artifact:v1:sha256:{}",
        sha256(
            format!("marker:v1:{expected_catalog_id}:absent:current:ccmsetup.log:unscoped")
                .as_bytes()
        )
    );
    assert_eq!(
        bundle.artifacts[0].artifact.artifact_id,
        expected_artifact_id
    );
}

#[test]
fn missing_and_malformed_legacy_errors_do_not_disclose_the_bundle_path() {
    let temp = tempdir().expect("temporary root");
    let bundle_root = temp.path().join("secret-bundle-root");
    make_private_directory(&bundle_root);
    let sensitive_root = bundle_root.display().to_string();

    let missing = read_sccm_manifest_or_legacy(&bundle_root)
        .expect_err("an existing empty bundle has no supported manifest");
    assert!(!missing.to_string().contains(&sensitive_root));

    fs::write(bundle_root.join("manifest.json"), b"{malformed").expect("malformed legacy manifest");
    let malformed =
        read_sccm_manifest_or_legacy(&bundle_root).expect_err("malformed legacy JSON fails closed");
    assert!(!malformed.to_string().contains(&sensitive_root));
    assert!(malformed.to_string().contains("manifest.json"));
}

#[cfg(unix)]
#[test]
fn reader_rejects_a_symlinked_bundle_root_without_following_it() {
    use std::os::unix::fs::symlink;

    let temp = tempdir().expect("temporary root");
    let real_root = temp.path().join("real-private-root");
    let alias = temp.path().join("secret-root-alias");
    make_private_directory(&real_root);
    symlink(&real_root, &alias).expect("bundle root symlink");

    let error = read_sccm_manifest_or_legacy(&alias).expect_err("root symlink is rejected");
    assert!(!error.to_string().contains(&alias.display().to_string()));
}

#[cfg(unix)]
#[test]
fn reader_opens_manifest_without_following_a_symlink() {
    use std::os::unix::fs::symlink;

    let temp = tempdir().expect("temporary root");
    let bundle_root = temp.path().join("private-bundle");
    let outside = temp.path().join("outside-manifest.json");
    make_private_directory(&bundle_root);
    fs::write(&outside, b"{}").expect("outside file");
    symlink(&outside, bundle_root.join(SCCM_MANIFEST_FILE_NAME)).expect("manifest symlink");

    let error = read_sccm_manifest_or_legacy(&bundle_root)
        .expect_err("reader must not follow the manifest symlink");
    assert!(!error
        .to_string()
        .contains(&bundle_root.display().to_string()));
    assert!(!error.to_string().contains(&outside.display().to_string()));
    assert!(error
        .to_string()
        .contains("manifest cannot be opened safely"));
}

#[cfg(unix)]
#[test]
fn reader_rejects_a_nonprivate_bundle_directory() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempdir().expect("temporary root");
    let bundle_root = temp.path().join("public-bundle");
    make_private_directory(&bundle_root);
    fs::set_permissions(&bundle_root, fs::Permissions::from_mode(0o755))
        .expect("make bundle public");

    let error = read_sccm_manifest_or_legacy(&bundle_root)
        .expect_err("public bundle directory fails closed");
    assert!(error.to_string().contains("not private"));
    assert!(!error
        .to_string()
        .contains(&bundle_root.display().to_string()));
}

#[test]
fn manifest_wire_and_debug_never_gain_raw_host_or_native_path_fields() {
    let temp = tempdir().expect("temporary root");
    let bundle_root = temp.path().join("RealUser-secret-bundle");
    let current = physical_artifact(SccmRotation::Current, b"policy-current");
    write_native_bundle(&bundle_root, &[&current], &[]);

    let manifest = read_sccm_manifest_or_legacy(&bundle_root).expect("validated manifest");
    let serialized = serde_json::to_string(&manifest).expect("manifest JSON");
    let debug = format!("{manifest:?}");
    let native_path = bundle_root.display().to_string();
    for public in [&serialized, &debug] {
        assert!(!public.contains("LAB-CLIENT-SECRET"));
        assert!(!public.contains(&native_path));
        assert!(!public.contains("RealUser"));
    }

    let mut raw_host = native_manifest(vec![current.value], vec![]);
    raw_host["host"] = json!("LAB-CLIENT-SECRET");
    assert!(serde_json::from_value::<SccmBundleManifestV1>(raw_host).is_err());
}

#[test]
fn malformed_native_state_is_rejected_before_pure_projection() {
    let temp = tempdir().expect("temporary root");
    let bundle_root = temp.path().join("bundle");
    let mut value = native_manifest(
        vec![physical_artifact(SccmRotation::Current, b"policy-current").value],
        vec![],
    );
    value["artifacts"][0]["state"] = json!("absent");
    make_private_directory(&bundle_root);
    fs::write(
        bundle_root.join(SCCM_MANIFEST_FILE_NAME),
        serde_json::to_vec(&value).expect("serialize malformed native manifest"),
    )
    .expect("write malformed native manifest");

    let error = read_sccm_client_intake_bundle(&bundle_root)
        .expect_err("nonphysical state cannot claim a file");
    assert!(error.to_string().contains("nonphysical"));
    let manifest: SccmBundleManifestV1 = serde_json::from_value(value).expect("wire shape");
    assert_ne!(
        manifest.artifacts[0].state,
        SccmManifestSourceState::Captured
    );
}

#[test]
fn reader_enforces_the_physical_file_cap_per_canonical_source_before_evidence_reads() {
    let temp = tempdir().expect("temporary root");
    let bundle_root = temp.path().join("bundle");
    let current = physical_artifact(SccmRotation::Current, b"policy-current");
    let rotated = physical_artifact(SccmRotation::Numbered(1), b"policy-rotation-one");
    write_native_bundle(&bundle_root, &[&current, &rotated], &[]);
    set_native_limits(&bundle_root, 1, 4096);
    remove_written_evidence(&bundle_root, &rotated);

    let error = read_sccm_manifest_or_legacy(&bundle_root)
        .expect_err("two rotations cannot bypass one-file source cap");
    assert!(error.to_string().contains("source file cap"));
}

#[test]
fn reader_accepts_the_exact_physical_byte_cap_boundary() {
    let temp = tempdir().expect("temporary root");
    let bundle_root = temp.path().join("bundle");
    let content = b"policy-current";
    let current = physical_artifact(SccmRotation::Current, content);
    write_native_bundle(&bundle_root, &[&current], &[]);
    set_native_limits(&bundle_root, 1, content.len() as u64);

    read_sccm_manifest_or_legacy(&bundle_root)
        .expect("an artifact exactly at the source byte cap remains valid");
}

#[test]
fn reader_rejects_multi_rotation_physical_bytes_over_the_source_cap() {
    let temp = tempdir().expect("temporary root");
    let bundle_root = temp.path().join("bundle");
    let current = physical_artifact(SccmRotation::Current, b"policy-current");
    let rotated = physical_artifact(SccmRotation::Numbered(1), b"policy-rotation-one");
    write_native_bundle(&bundle_root, &[&current, &rotated], &[]);
    set_native_limits(&bundle_root, 2, b"policy-current".len() as u64);

    let error = read_sccm_manifest_or_legacy(&bundle_root)
        .expect_err("rotations cannot collectively exceed their source byte cap");
    assert!(error.to_string().contains("source byte cap"));
}

#[test]
fn reader_rejects_u64_max_physical_byte_metadata_before_evidence_reads() {
    let temp = tempdir().expect("temporary root");
    let bundle_root = temp.path().join("bundle");
    let mut current = physical_artifact(SccmRotation::Current, b"policy-current");
    current.value["bytesCopied"] = json!(u64::MAX);
    write_native_bundle(&bundle_root, &[&current], &[]);
    set_native_limits(&bundle_root, 1, u64::MAX);
    remove_written_evidence(&bundle_root, &current);

    let error = read_sccm_manifest_or_legacy(&bundle_root)
        .expect_err("extreme metadata fails before unbounded evidence verification");
    assert!(error.to_string().contains("physical artifact byte cap"));
}

#[test]
fn reader_rejects_a_client_owned_per_artifact_ceiling_before_evidence_reads() {
    let temp = tempdir().expect("temporary root");
    let bundle_root = temp.path().join("bundle");
    let mut current = physical_artifact(SccmRotation::Current, b"policy-current");
    current.value["bytesCopied"] = json!(256_u64 * 1024 * 1024 + 1);
    write_native_bundle(&bundle_root, &[&current], &[]);
    set_native_limits(&bundle_root, 8, u64::MAX);
    remove_written_evidence(&bundle_root, &current);

    let error = read_sccm_manifest_or_legacy(&bundle_root)
        .expect_err("a manifest cannot raise the reader-owned artifact ceiling");
    assert!(error.to_string().contains("physical artifact byte cap"));
}

#[test]
fn reader_rejects_a_client_owned_aggregate_ceiling_before_evidence_reads() {
    let temp = tempdir().expect("temporary root");
    let bundle_root = temp.path().join("bundle");
    let mut artifacts = vec![
        physical_artifact(SccmRotation::Current, b"policy-current"),
        physical_artifact(SccmRotation::LoUnderscore, b"policy-lo"),
        physical_artifact(SccmRotation::Numbered(1), b"policy-one"),
        physical_artifact(SccmRotation::Numbered(2), b"policy-two"),
        physical_artifact(SccmRotation::Numbered(3), b"policy-three"),
    ];
    for artifact in &mut artifacts {
        artifact.value["bytesCopied"] = json!(205_u64 * 1024 * 1024);
    }
    let references = artifacts.iter().collect::<Vec<_>>();
    write_native_bundle(&bundle_root, &references, &[]);
    set_native_limits(&bundle_root, 8, u64::MAX);
    for artifact in &artifacts {
        remove_written_evidence(&bundle_root, artifact);
    }

    let error = read_sccm_manifest_or_legacy(&bundle_root)
        .expect_err("a manifest cannot raise the reader-owned aggregate ceiling");
    assert!(error.to_string().contains("aggregate physical byte cap"));
}

#[cfg(unix)]
#[test]
fn reader_rejects_hard_linked_physical_evidence() {
    let temp = tempdir().expect("temporary root");
    let bundle_root = temp.path().join("bundle");
    let current = physical_artifact(SccmRotation::Current, b"policy-current");
    write_native_bundle(&bundle_root, &[&current], &[]);
    let evidence = bundle_root.join(relative_path(&SccmRotation::Current));
    fs::hard_link(&evidence, bundle_root.join("duplicate-evidence-link"))
        .expect("create a second name for the evidence inode");

    let error = read_sccm_manifest_or_legacy(&bundle_root)
        .expect_err("hard-linked physical evidence is not a private capture artifact");
    assert!(error.to_string().contains("cannot be opened safely"));
}
