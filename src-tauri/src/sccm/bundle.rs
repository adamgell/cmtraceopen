use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use cmtraceopen_parser::sccm::SccmRole;

use crate::error::AppError;

use super::intake::{
    discover_client_sources, is_reparse_point, sha256_bytes, SccmClientDiscoveredArtifact,
    SccmClientDiscoveryInput,
};
use super::manifest::{
    compare_manifest_artifacts, expected_bundle_group, expected_marker_artifact_id,
    expected_physical_artifact_id, manifest_to_client_intake_bundle, rotation_segment,
    validate_client_capture_context, write_sccm_manifest_v1, SccmBundleManifestV1,
    SccmManifestArtifact, SccmManifestSourceState,
};

#[derive(Debug, Clone)]
pub struct SccmClientCaptureRequest {
    pub bundle_root: PathBuf,
    /// Raw host context is accepted only to derive a versioned opaque handle.
    /// It is never written to the public manifest.
    pub host: String,
    pub collected_at_utc: String,
    pub configmgr_version: Option<String>,
    pub encoding: Option<String>,
    pub discovery: SccmClientDiscoveryInput,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SccmClientCaptureResult {
    pub manifest: SccmBundleManifestV1,
}

pub fn capture_client_bundle(
    request: &SccmClientCaptureRequest,
) -> Result<SccmClientCaptureResult, AppError> {
    validate_client_capture_context(
        &request.collected_at_utc,
        request.configmgr_version.as_deref(),
        request.encoding.as_deref(),
    )?;
    let host_handle = host_handle(&request.host)?;
    let discovery = discover_client_sources(&request.discovery)?;
    let mut manifest = SccmBundleManifestV1::native_client(
        host_handle,
        request.collected_at_utc.clone(),
        request.discovery.max_files_per_source,
        request.discovery.max_bytes_per_source,
    );
    let bundle_root = prepare_bundle_root(&request.bundle_root)?;

    for artifact in discovery.artifacts {
        manifest
            .artifacts
            .push(capture_artifact(&bundle_root, &artifact, request));
    }

    for state in discovery.source_states {
        if state.state.is_physical() {
            continue;
        }
        manifest.artifacts.push(SccmManifestArtifact {
            artifact_id: expected_marker_artifact_id(
                &state.catalog_entry_id,
                state.state,
                &state.rotation,
                &state.basename,
                state.path_fingerprint.as_deref(),
            ),
            catalog_entry_id: state.catalog_entry_id,
            logical_artifact_ids: state.logical_artifact_ids,
            role: SccmRole::Client,
            source_handle: state.source_handle,
            root_handle: state.root_handle,
            path_fingerprint: state.path_fingerprint,
            rotation_lineage: state.rotation_lineage,
            relative_path: None,
            basename: state.basename,
            rotation: state.rotation,
            state: state.state,
            bytes_copied: 0,
            limit_applied: None,
            fragment_complete: false,
            configmgr_version: request.configmgr_version.clone(),
            collected_at_utc: Some(request.collected_at_utc.clone()),
            encoding: request.encoding.clone(),
        });
    }
    manifest.artifacts.sort_by(compare_manifest_artifacts);

    // The pure contract is the final semantic validation boundary. This call
    // rejects catalog, role, path, lineage, state, timestamp, encoding, and
    // physical-identity inconsistencies before the manifest is published.
    manifest_to_client_intake_bundle(&manifest)?;
    write_sccm_manifest_v1(&bundle_root, &manifest)?;
    Ok(SccmClientCaptureResult { manifest })
}

fn capture_artifact(
    bundle_root: &Path,
    artifact: &SccmClientDiscoveredArtifact,
    request: &SccmClientCaptureRequest,
) -> SccmManifestArtifact {
    let relative_path = bundle_relative_path(artifact);
    let destination = bundle_root.join(&relative_path);
    let capture = secure_destination_parent(bundle_root, &relative_path).and_then(|()| {
        copy_bounded_source(
            artifact,
            &destination,
            artifact.state == SccmManifestSourceState::Capped,
        )
    });

    match capture {
        Ok(bytes_copied) => SccmManifestArtifact {
            catalog_entry_id: artifact.catalog_entry_id.clone(),
            logical_artifact_ids: artifact.logical_artifact_ids.clone(),
            artifact_id: expected_physical_artifact_id(
                &artifact.path_fingerprint,
                &artifact.rotation,
                &artifact.basename,
            ),
            role: SccmRole::Client,
            source_handle: Some(artifact.source_handle.clone()),
            root_handle: Some(artifact.root_handle.clone()),
            path_fingerprint: Some(artifact.path_fingerprint.clone()),
            rotation_lineage: Some(artifact.rotation_lineage.clone()),
            relative_path: Some(relative_path),
            basename: artifact.basename.clone(),
            rotation: artifact.rotation.clone(),
            state: artifact.state,
            bytes_copied,
            limit_applied: (artifact.state == SccmManifestSourceState::Capped)
                .then_some(artifact.copy_bytes),
            // The native copier proves byte completeness, not CCM
            // logical-record boundary completeness. Remain conservative.
            fragment_complete: false,
            configmgr_version: request.configmgr_version.clone(),
            collected_at_utc: Some(request.collected_at_utc.clone()),
            encoding: request.encoding.clone(),
        },
        Err(_) => SccmManifestArtifact {
            catalog_entry_id: artifact.catalog_entry_id.clone(),
            logical_artifact_ids: artifact.logical_artifact_ids.clone(),
            artifact_id: expected_marker_artifact_id(
                &artifact.catalog_entry_id,
                SccmManifestSourceState::FailedUnknownDetail,
                &artifact.rotation,
                &artifact.basename,
                Some(&artifact.path_fingerprint),
            ),
            role: SccmRole::Client,
            source_handle: Some(artifact.source_handle.clone()),
            root_handle: Some(artifact.root_handle.clone()),
            path_fingerprint: Some(artifact.path_fingerprint.clone()),
            rotation_lineage: Some(artifact.rotation_lineage.clone()),
            relative_path: None,
            basename: artifact.basename.clone(),
            rotation: artifact.rotation.clone(),
            state: SccmManifestSourceState::FailedUnknownDetail,
            bytes_copied: 0,
            limit_applied: None,
            fragment_complete: false,
            configmgr_version: request.configmgr_version.clone(),
            collected_at_utc: Some(request.collected_at_utc.clone()),
            encoding: request.encoding.clone(),
        },
    }
}

fn bundle_relative_path(artifact: &SccmClientDiscoveredArtifact) -> String {
    format!(
        "evidence/sccm/client/{}/{}/{}/{}",
        expected_bundle_group(&artifact.logical_artifact_ids),
        artifact.root_handle,
        rotation_segment(&artifact.rotation),
        artifact.basename
    )
}

fn copy_bounded_source(
    artifact: &SccmClientDiscoveredArtifact,
    destination: &Path,
    intentionally_capped: bool,
) -> Result<u64, AppError> {
    let source_metadata = fs::symlink_metadata(&artifact.canonical_path)?;
    if is_reparse_point(&source_metadata) || !source_metadata.is_file() {
        return Err(AppError::InvalidInput(
            "SCCM source became an unsafe path before capture".to_owned(),
        ));
    }
    let recanonicalized = artifact.canonical_path.canonicalize()?;
    if recanonicalized != artifact.canonical_path
        || !recanonicalized.starts_with(&artifact.canonical_root)
    {
        return Err(AppError::InvalidInput(
            "SCCM source escaped its approved root before capture".to_owned(),
        ));
    }

    let mut input = open_source_without_following_links(&artifact.canonical_path)?;
    let opened_metadata = input.metadata()?;
    if is_reparse_point(&opened_metadata) || !opened_metadata.is_file() {
        return Err(AppError::InvalidInput(
            "SCCM source is not a regular file at capture time".to_owned(),
        ));
    }
    if (!intentionally_capped && opened_metadata.len() != artifact.source_bytes)
        || opened_metadata.len() < artifact.copy_bytes
    {
        return Err(AppError::State(
            "SCCM source size changed before bounded capture".to_owned(),
        ));
    }

    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    let result = copy_exact_prefix(
        &mut input,
        &mut output,
        artifact.copy_bytes,
        intentionally_capped,
    )
    .and_then(|written| {
        output.sync_all()?;
        Ok(written)
    });
    if result.is_err() {
        drop(output);
        let _ = fs::remove_file(destination);
    }
    result
}

fn copy_exact_prefix(
    input: &mut File,
    output: &mut File,
    expected_bytes: u64,
    intentionally_capped: bool,
) -> Result<u64, AppError> {
    let mut limited = input.take(expected_bytes);
    let written = std::io::copy(&mut limited, output)?;
    if written != expected_bytes {
        return Err(AppError::State(format!(
            "SCCM source shrank during capture: expected {expected_bytes} bytes, copied {written}"
        )));
    }
    if !intentionally_capped {
        let input = limited.into_inner();
        let mut probe = [0_u8; 1];
        if input.read(&mut probe)? != 0 {
            return Err(AppError::State(
                "SCCM source grew during capture".to_owned(),
            ));
        }
    }
    Ok(written)
}

fn prepare_bundle_root(bundle_root: &Path) -> Result<PathBuf, AppError> {
    if !bundle_root.exists() {
        fs::create_dir_all(bundle_root)?;
    }
    let metadata = fs::symlink_metadata(bundle_root)?;
    if is_reparse_point(&metadata) || !metadata.is_dir() {
        return Err(AppError::InvalidInput(
            "SCCM bundle root must be a real directory".to_owned(),
        ));
    }
    Ok(bundle_root.canonicalize()?)
}

fn secure_destination_parent(bundle_root: &Path, relative_path: &str) -> Result<(), AppError> {
    let relative = Path::new(relative_path);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(AppError::InvalidInput(
            "SCCM destination path is not bundle-relative".to_owned(),
        ));
    }
    let parent = relative.parent().ok_or_else(|| {
        AppError::InvalidInput("SCCM destination has no relative parent".to_owned())
    })?;
    let mut current = bundle_root.to_path_buf();
    for component in parent.components() {
        let Component::Normal(segment) = component else {
            return Err(AppError::InvalidInput(
                "SCCM destination contains an unsafe component".to_owned(),
            ));
        };
        current.push(segment);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if is_reparse_point(&metadata) || !metadata.is_dir() {
                    return Err(AppError::InvalidInput(
                        "SCCM destination parent contains a symlink or reparse point".to_owned(),
                    ));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current)?;
            }
            Err(error) => return Err(AppError::Io(error)),
        }
        if !current.canonicalize()?.starts_with(bundle_root) {
            return Err(AppError::InvalidInput(
                "SCCM destination parent escaped the bundle root".to_owned(),
            ));
        }
    }
    Ok(())
}

fn host_handle(host: &str) -> Result<Option<String>, AppError> {
    if host.is_empty() {
        return Ok(None);
    }
    if host != host.trim() || host.len() > 255 || host.chars().any(char::is_control) {
        return Err(AppError::InvalidInput(
            "SCCM capture host context is malformed".to_owned(),
        ));
    }
    Ok(Some(format!(
        "cmtraceopen.host.sha256.v1:{}",
        sha256_bytes(host.as_bytes())
    )))
}

#[cfg(unix)]
fn open_source_without_following_links(path: &Path) -> Result<File, AppError> {
    use std::os::unix::fs::OpenOptionsExt;

    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?)
}

#[cfg(windows)]
fn open_source_without_following_links(path: &Path) -> Result<File, AppError> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?)
}

#[cfg(not(any(unix, windows)))]
fn open_source_without_following_links(path: &Path) -> Result<File, AppError> {
    Ok(OpenOptions::new().read(true).open(path)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_copy_detects_growth_but_allows_an_explicit_cap() {
        let temp = tempfile::tempdir().expect("temporary copy root");
        let source = temp.path().join("source.log");
        let grown_destination = temp.path().join("grown.log");
        let capped_destination = temp.path().join("capped.log");
        fs::write(&source, b"0123456789").expect("source");

        let mut input = File::open(&source).expect("source input");
        let mut output = File::create(&grown_destination).expect("grown output");
        assert!(copy_exact_prefix(&mut input, &mut output, 4, false).is_err());

        let mut input = File::open(&source).expect("source input");
        let mut output = File::create(&capped_destination).expect("capped output");
        assert_eq!(
            copy_exact_prefix(&mut input, &mut output, 4, true).expect("bounded prefix"),
            4
        );
        drop(output);
        assert_eq!(fs::read(capped_destination).expect("prefix"), b"0123");
    }

    #[test]
    fn stale_discovery_size_fails_before_creating_a_partial_destination() {
        let temp = tempfile::tempdir().expect("temporary copy root");
        let root = temp.path().join("source-root");
        fs::create_dir_all(&root).expect("source root");
        let source = root.join("PolicyAgent.log");
        let destination = temp.path().join("destination.log");
        fs::write(&source, b"0123456789").expect("source");
        let canonical_root = root.canonicalize().expect("canonical root");
        let canonical_path = source.canonicalize().expect("canonical source");
        let artifact = SccmClientDiscoveredArtifact {
            catalog_entry_id: "test-catalog".to_owned(),
            logical_artifact_ids: vec!["client-policy-agent".to_owned()],
            source_handle: "test-source".to_owned(),
            root_handle: "test-root".to_owned(),
            path_fingerprint: "test-path".to_owned(),
            rotation_lineage: "test-lineage".to_owned(),
            basename: "PolicyAgent.log".to_owned(),
            canonical_basename: "PolicyAgent.log".to_owned(),
            rotation: cmtraceopen_parser::sccm::SccmRotation::Current,
            state: SccmManifestSourceState::Captured,
            source_bytes: 4,
            copy_bytes: 4,
            canonical_root,
            canonical_path,
        };

        assert!(copy_bounded_source(&artifact, &destination, false).is_err());
        assert!(!destination.exists());
    }
}
