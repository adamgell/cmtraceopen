use std::fs;
use std::path::Path;

use cmtraceopen_parser::sccm::{SccmRole, SccmRotation};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::AppError;

pub const SCCM_MANIFEST_FILE_NAME: &str = "sccm-manifest.json";
pub const SCCM_MANIFEST_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmManifestSourceState {
    Captured,
    Absent,
    AccessDenied,
    Capped,
    Skipped,
    Unsupported,
    FailedUnknownDetail,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmManifestArtifact {
    pub catalog_entry_id: String,
    pub logical_artifact_id: String,
    pub artifact_id: String,
    pub host: String,
    pub role: SccmRole,
    pub source_path: Option<String>,
    pub path_fingerprint: String,
    pub relative_path: Option<String>,
    pub basename: String,
    pub rotation: SccmRotation,
    pub rotation_rank: u8,
    pub state: SccmManifestSourceState,
    pub bytes_copied: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmBundleManifestV1 {
    pub sccm_manifest_version: u32,
    pub artifacts: Vec<SccmManifestArtifact>,
}

impl SccmBundleManifestV1 {
    pub fn empty() -> Self {
        Self {
            sccm_manifest_version: SCCM_MANIFEST_VERSION,
            artifacts: Vec::new(),
        }
    }
}

pub fn write_sccm_manifest_v1(
    bundle_root: &Path,
    manifest: &SccmBundleManifestV1,
) -> Result<(), AppError> {
    if manifest.sccm_manifest_version != SCCM_MANIFEST_VERSION {
        return Err(AppError::InvalidInput(format!(
            "unsupported SCCM manifest version {}",
            manifest.sccm_manifest_version
        )));
    }
    fs::create_dir_all(bundle_root)?;
    let serialized = serde_json::to_string_pretty(manifest)
        .map_err(|error| AppError::Internal(format!("serialize SCCM manifest: {error}")))?;
    fs::write(bundle_root.join(SCCM_MANIFEST_FILE_NAME), serialized)?;
    Ok(())
}

pub fn read_sccm_manifest_or_legacy(bundle_root: &Path) -> Result<SccmBundleManifestV1, AppError> {
    let sccm_manifest = bundle_root.join(SCCM_MANIFEST_FILE_NAME);
    if sccm_manifest.is_file() {
        let manifest = serde_json::from_slice::<SccmBundleManifestV1>(&fs::read(sccm_manifest)?)
            .map_err(|error| AppError::Parse {
                file: SCCM_MANIFEST_FILE_NAME.to_string(),
                reason: error.to_string(),
            })?;
        if manifest.sccm_manifest_version != SCCM_MANIFEST_VERSION {
            return Err(AppError::InvalidInput(format!(
                "unsupported SCCM manifest version {}",
                manifest.sccm_manifest_version
            )));
        }
        return Ok(manifest);
    }

    let legacy_path = bundle_root.join("manifest.json");
    let legacy: Value =
        serde_json::from_slice(&fs::read(&legacy_path)?).map_err(|error| AppError::Parse {
            file: legacy_path.display().to_string(),
            reason: error.to_string(),
        })?;
    let artifacts = legacy
        .get("artifacts")
        .and_then(Value::as_array)
        .ok_or_else(|| AppError::InvalidInput("legacy manifest does not contain artifacts".into()))?
        .iter()
        .enumerate()
        .map(|(index, artifact)| legacy_artifact(index, artifact))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(SccmBundleManifestV1 {
        sccm_manifest_version: SCCM_MANIFEST_VERSION,
        artifacts,
    })
}

fn legacy_artifact(index: usize, artifact: &Value) -> Result<SccmManifestArtifact, AppError> {
    let artifact_id = artifact
        .get("artifactId")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::InvalidInput("legacy artifact is missing artifactId".into()))?;
    let state = match artifact.get("status").and_then(Value::as_str) {
        Some("collected") => SccmManifestSourceState::Captured,
        Some("missing") => SccmManifestSourceState::Absent,
        Some("failed") | Some(_) | None => SccmManifestSourceState::FailedUnknownDetail,
    };
    Ok(SccmManifestArtifact {
        catalog_entry_id: format!("legacy.{index:04}"),
        logical_artifact_id: artifact_id.to_string(),
        artifact_id: artifact_id.to_string(),
        host: "unknown".to_string(),
        role: SccmRole::Client,
        source_path: None,
        path_fingerprint: format!("legacy:{index:04}"),
        relative_path: artifact
            .get("relativePath")
            .and_then(Value::as_str)
            .map(str::to_string),
        basename: artifact_id.to_string(),
        rotation: SccmRotation::Current,
        rotation_rank: 0,
        state,
        bytes_copied: 0,
    })
}
