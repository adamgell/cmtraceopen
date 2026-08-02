use std::fs;
use std::path::Path;

use cmtraceopen_parser::sccm::SccmRole;
use sha2::{Digest, Sha256};

use crate::error::AppError;

use super::intake::{discover_client_sources, SccmClientDiscoveryInput};
use super::manifest::{
    write_sccm_manifest_v1, SccmBundleManifestV1, SccmManifestArtifact, SccmManifestSourceState,
};

#[derive(Debug, Clone)]
pub struct SccmClientCaptureRequest {
    pub bundle_root: std::path::PathBuf,
    pub host: String,
    pub discovery: SccmClientDiscoveryInput,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SccmClientCaptureResult {
    pub manifest: SccmBundleManifestV1,
}

pub fn capture_client_bundle(
    request: &SccmClientCaptureRequest,
) -> Result<SccmClientCaptureResult, AppError> {
    let discovery = discover_client_sources(&request.discovery);
    fs::create_dir_all(&request.bundle_root)?;
    let mut manifest = SccmBundleManifestV1::empty();

    for artifact in discovery.artifacts {
        let relative_path = bundle_relative_path(
            &artifact.logical_artifact_id,
            artifact.rotation_rank,
            &artifact.path_fingerprint,
            &artifact.basename,
        );
        let destination = request.bundle_root.join(&relative_path);
        let parent = destination.parent().ok_or_else(|| {
            AppError::Internal("SCCM bundle destination has no parent".to_string())
        })?;
        fs::create_dir_all(parent)?;
        copy_bounded(&artifact.canonical_path, &destination, artifact.bytes)?;
        manifest.artifacts.push(SccmManifestArtifact {
            catalog_entry_id: artifact.catalog_entry_id,
            logical_artifact_id: artifact.logical_artifact_id,
            artifact_id: artifact_id(&artifact.path_fingerprint),
            host: request.host.clone(),
            role: SccmRole::Client,
            source_path: Some(artifact.source_path.to_string_lossy().into_owned()),
            path_fingerprint: artifact.path_fingerprint,
            relative_path: Some(relative_path),
            basename: artifact.basename,
            rotation: artifact.rotation,
            rotation_rank: artifact.rotation_rank,
            state: SccmManifestSourceState::Captured,
            bytes_copied: artifact.bytes,
        });
    }
    for state in discovery.source_states {
        if state.coverage == cmtraceopen_parser::sccm::SccmCoverageState::Captured {
            continue;
        }
        manifest.artifacts.push(SccmManifestArtifact {
            catalog_entry_id: state.catalog_entry_id,
            logical_artifact_id: state.logical_artifact_id.clone(),
            artifact_id: format!("sccm-source-state:v1:{}", state.logical_artifact_id),
            host: request.host.clone(),
            role: SccmRole::Client,
            source_path: None,
            path_fingerprint: format!("source-state:{}", state.logical_artifact_id),
            relative_path: None,
            basename: state.logical_artifact_id,
            rotation: cmtraceopen_parser::sccm::SccmRotation::Current,
            rotation_rank: 0,
            state: manifest_state(state.coverage),
            bytes_copied: 0,
        });
    }
    manifest.artifacts.sort_by(|left, right| {
        left.catalog_entry_id
            .cmp(&right.catalog_entry_id)
            .then_with(|| left.path_fingerprint.cmp(&right.path_fingerprint))
            .then_with(|| left.rotation_rank.cmp(&right.rotation_rank))
            .then_with(|| left.basename.cmp(&right.basename))
            .then_with(|| left.artifact_id.cmp(&right.artifact_id))
    });
    write_sccm_manifest_v1(&request.bundle_root, &manifest)?;
    Ok(SccmClientCaptureResult { manifest })
}

fn bundle_relative_path(
    logical_artifact_id: &str,
    rotation_rank: u8,
    fingerprint: &str,
    basename: &str,
) -> String {
    let rotation = match rotation_rank {
        0 => "current".to_string(),
        1 => "lo".to_string(),
        _ => format!("numbered-{rotation_rank}"),
    };
    let fingerprint = fingerprint.trim_start_matches("sha256:");
    format!("evidence/sccm/client/{logical_artifact_id}/{rotation}/{fingerprint}/{basename}")
}

fn artifact_id(fingerprint: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(fingerprint.as_bytes());
    let digest = digest.finalize();
    let hex = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("sccm-artifact:v1:sha256:{hex}")
}

fn copy_bounded(source: &Path, destination: &Path, expected_bytes: u64) -> Result<(), AppError> {
    let written = fs::copy(source, destination)?;
    if written != expected_bytes {
        return Err(AppError::State(format!(
            "SCCM source changed during capture: expected {expected_bytes} bytes, copied {written}"
        )));
    }
    Ok(())
}

fn manifest_state(
    coverage: cmtraceopen_parser::sccm::SccmCoverageState,
) -> SccmManifestSourceState {
    match coverage {
        cmtraceopen_parser::sccm::SccmCoverageState::Captured => SccmManifestSourceState::Captured,
        cmtraceopen_parser::sccm::SccmCoverageState::Absent => SccmManifestSourceState::Absent,
        cmtraceopen_parser::sccm::SccmCoverageState::AccessDenied => {
            SccmManifestSourceState::AccessDenied
        }
        cmtraceopen_parser::sccm::SccmCoverageState::Capped => SccmManifestSourceState::Capped,
        cmtraceopen_parser::sccm::SccmCoverageState::Skipped => SccmManifestSourceState::Skipped,
        cmtraceopen_parser::sccm::SccmCoverageState::Unsupported
        | cmtraceopen_parser::sccm::SccmCoverageState::ParseFailed => {
            SccmManifestSourceState::Unsupported
        }
    }
}
