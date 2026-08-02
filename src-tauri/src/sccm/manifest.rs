use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path};

use chrono::DateTime;
use cmtraceopen_parser::sccm::{
    assess_client_intake, classify_artifact_name, SccmArtifact, SccmClientIntakeArtifact,
    SccmClientIntakeBundle, SccmCoverageState, SccmRole, SccmRotation,
    SCCM_DIAGNOSTICS_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::AppError;

use super::intake::{
    catalog_entry_id, is_reparse_point, logical_artifact_ids_for_basename, rotation_order,
    sha256_bytes,
};

pub const SCCM_MANIFEST_FILE_NAME: &str = "sccm-manifest.json";
pub const SCCM_MANIFEST_VERSION: u32 = 1;
pub const SCCM_CLIENT_SOURCE_CATALOG_VERSION: u32 = 1;
pub const MAX_SCCM_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_SCCM_MANIFEST_ARTIFACTS: usize = 4096;

const LEGACY_MANIFEST_FILE_NAME: &str = "manifest.json";
const SHA256_HEX_CHARS: usize = 64;
const MAX_SAFE_TEXT_CHARS: usize = 160;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmManifestProvenance {
    NativeClientCapture,
    LegacyGenericUnscoped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmManifestSourceState {
    Captured,
    Absent,
    AccessDenied,
    Capped,
    Skipped,
    Unsupported,
    UnsafePath,
    ParseFailed,
    FailedUnknownDetail,
}

impl SccmManifestSourceState {
    fn pure_coverage(self) -> SccmCoverageState {
        match self {
            Self::Captured => SccmCoverageState::Captured,
            Self::Absent => SccmCoverageState::Absent,
            Self::AccessDenied => SccmCoverageState::AccessDenied,
            Self::Capped => SccmCoverageState::Capped,
            Self::Skipped => SccmCoverageState::Skipped,
            Self::Unsupported | Self::UnsafePath | Self::FailedUnknownDetail => {
                SccmCoverageState::Unsupported
            }
            Self::ParseFailed => SccmCoverageState::ParseFailed,
        }
    }

    pub(super) fn is_physical(self) -> bool {
        matches!(self, Self::Captured | Self::Capped | Self::ParseFailed)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SccmManifestArtifact {
    pub catalog_entry_id: String,
    pub logical_artifact_ids: Vec<String>,
    pub artifact_id: String,
    pub role: SccmRole,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation_lineage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relative_path: Option<String>,
    pub basename: String,
    pub rotation: SccmRotation,
    pub state: SccmManifestSourceState,
    pub bytes_copied: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit_applied: Option<u64>,
    pub fragment_complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configmgr_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collected_at_utc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SccmBundleManifestV1 {
    pub sccm_manifest_version: u32,
    pub diagnostics_schema_version: u32,
    pub source_catalog_version: u32,
    pub provenance: SccmManifestProvenance,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collected_at_utc: Option<String>,
    pub max_files_per_source: usize,
    pub max_bytes_per_source: u64,
    pub artifacts: Vec<SccmManifestArtifact>,
}

impl SccmBundleManifestV1 {
    pub fn native_client(
        host_handle: Option<String>,
        collected_at_utc: String,
        max_files_per_source: usize,
        max_bytes_per_source: u64,
    ) -> Self {
        Self {
            sccm_manifest_version: SCCM_MANIFEST_VERSION,
            diagnostics_schema_version: SCCM_DIAGNOSTICS_SCHEMA_VERSION,
            source_catalog_version: SCCM_CLIENT_SOURCE_CATALOG_VERSION,
            provenance: SccmManifestProvenance::NativeClientCapture,
            host_handle,
            collected_at_utc: Some(collected_at_utc),
            max_files_per_source,
            max_bytes_per_source,
            artifacts: Vec::new(),
        }
    }
}

pub fn write_sccm_manifest_v1(
    bundle_root: &Path,
    manifest: &SccmBundleManifestV1,
) -> Result<(), AppError> {
    let canonical_root = create_real_bundle_root(bundle_root)?;
    validate_native_manifest(&canonical_root, manifest, true)?;
    let serialized = serde_json::to_vec_pretty(manifest)
        .map_err(|error| AppError::Internal(format!("serialize SCCM manifest: {error}")))?;
    if serialized.len() as u64 > MAX_SCCM_MANIFEST_BYTES {
        return Err(AppError::InvalidInput(
            "SCCM manifest exceeds its size limit".to_owned(),
        ));
    }

    let manifest_path = canonical_root.join(SCCM_MANIFEST_FILE_NAME);
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&manifest_path)?;
    if let Err(error) = output
        .write_all(&serialized)
        .and_then(|()| output.sync_all())
    {
        drop(output);
        let _ = fs::remove_file(&manifest_path);
        return Err(AppError::Io(error));
    }
    Ok(())
}

pub fn read_sccm_manifest_or_legacy(bundle_root: &Path) -> Result<SccmBundleManifestV1, AppError> {
    let canonical_root = verify_real_bundle_root(bundle_root)?;
    let sccm_manifest = canonical_root.join(SCCM_MANIFEST_FILE_NAME);
    match open_manifest_for_read(&sccm_manifest) {
        Ok(input) => {
            let bytes = read_bounded_file(input, MAX_SCCM_MANIFEST_BYTES, "SCCM manifest")?;
            let manifest =
                serde_json::from_slice::<SccmBundleManifestV1>(&bytes).map_err(|error| {
                    AppError::Parse {
                        file: SCCM_MANIFEST_FILE_NAME.to_owned(),
                        reason: error.to_string(),
                    }
                })?;
            validate_native_manifest(&canonical_root, &manifest, true)?;
            Ok(manifest)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            read_legacy_manifest(&canonical_root)
        }
        Err(error) => Err(AppError::Io(error)),
    }
}

pub fn manifest_to_client_intake_bundle(
    manifest: &SccmBundleManifestV1,
) -> Result<SccmClientIntakeBundle, AppError> {
    validate_native_manifest_structure(manifest)?;
    let artifacts = manifest
        .artifacts
        .iter()
        .map(|source| SccmClientIntakeArtifact {
            artifact: SccmArtifact {
                artifact_id: source.artifact_id.clone(),
                display_name: source.basename.clone(),
                original_path: None,
                host: None,
                role: SccmRole::Client,
                configmgr_version: source.configmgr_version.clone(),
                collected_at_utc: source.collected_at_utc.clone(),
                rotation: source.rotation.clone(),
                coverage: source.state.pure_coverage(),
                encoding: source.encoding.clone(),
            },
            path_fingerprint: source.path_fingerprint.clone(),
            rotation_lineage: source.rotation_lineage.clone(),
            relative_path: source.relative_path.clone(),
            fragment_complete: Some(source.fragment_complete),
        })
        .collect::<Vec<_>>();
    let bundle = SccmClientIntakeBundle { artifacts };
    assess_client_intake(&bundle).map_err(|error| {
        AppError::InvalidInput(format!(
            "SCCM manifest cannot be converted to the pure client intake contract: {error}"
        ))
    })?;
    Ok(bundle)
}

pub fn read_sccm_client_intake_bundle(
    bundle_root: &Path,
) -> Result<SccmClientIntakeBundle, AppError> {
    let manifest = read_sccm_manifest_or_legacy(bundle_root)?;
    manifest_to_client_intake_bundle(&manifest)
}

fn read_legacy_manifest(bundle_root: &Path) -> Result<SccmBundleManifestV1, AppError> {
    let legacy_path = bundle_root.join(LEGACY_MANIFEST_FILE_NAME);
    let input = open_manifest_for_read(&legacy_path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            AppError::InvalidInput(format!(
                "bundle {} contains neither {SCCM_MANIFEST_FILE_NAME} nor {LEGACY_MANIFEST_FILE_NAME}",
                bundle_root.display()
            ))
        } else {
            AppError::Io(error)
        }
    })?;
    let bytes = read_bounded_file(input, MAX_SCCM_MANIFEST_BYTES, "legacy manifest")?;
    let legacy: Value = serde_json::from_slice(&bytes).map_err(|error| AppError::Parse {
        file: legacy_path.display().to_string(),
        reason: error.to_string(),
    })?;
    let values = legacy
        .get("artifacts")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            AppError::InvalidInput("legacy manifest does not contain artifacts".into())
        })?;
    if values.len() > MAX_SCCM_MANIFEST_ARTIFACTS {
        return Err(AppError::InvalidInput(
            "legacy manifest has too many artifacts".to_owned(),
        ));
    }
    let artifacts = values
        .iter()
        .enumerate()
        .map(|(index, artifact)| legacy_artifact(index, artifact))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(SccmBundleManifestV1 {
        sccm_manifest_version: SCCM_MANIFEST_VERSION,
        diagnostics_schema_version: SCCM_DIAGNOSTICS_SCHEMA_VERSION,
        source_catalog_version: 0,
        provenance: SccmManifestProvenance::LegacyGenericUnscoped,
        host_handle: None,
        collected_at_utc: None,
        max_files_per_source: 0,
        max_bytes_per_source: 0,
        artifacts,
    })
}

fn legacy_artifact(index: usize, artifact: &Value) -> Result<SccmManifestArtifact, AppError> {
    let legacy_id = artifact
        .get("artifactId")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::InvalidInput("legacy artifact is missing artifactId".into()))?;
    if legacy_id.is_empty() || legacy_id.chars().count() > MAX_SAFE_TEXT_CHARS {
        return Err(AppError::InvalidInput(
            "legacy artifact identity is empty or too long".to_owned(),
        ));
    }
    if let Some(path) = artifact.get("relativePath").and_then(Value::as_str) {
        validate_legacy_relative_path(path)?;
    }
    let digest = sha256_bytes(format!("legacy:v1:{index}:{legacy_id}").as_bytes());
    let state = match artifact.get("status").and_then(Value::as_str) {
        Some("missing") => SccmManifestSourceState::Absent,
        Some("collected") | Some("failed") | Some(_) | None => {
            SccmManifestSourceState::FailedUnknownDetail
        }
    };
    Ok(SccmManifestArtifact {
        catalog_entry_id: "legacy-generic-unscoped:v1".to_owned(),
        logical_artifact_ids: Vec::new(),
        artifact_id: format!("sccm-artifact:v1:sha256:{digest}"),
        role: SccmRole::Unknown("legacyGenericUnscoped".to_owned()),
        source_handle: None,
        root_handle: None,
        path_fingerprint: None,
        rotation_lineage: None,
        relative_path: None,
        basename: format!("sccm-unknown-v1-sha256-{digest}.log"),
        rotation: SccmRotation::Current,
        state,
        bytes_copied: 0,
        limit_applied: None,
        fragment_complete: false,
        configmgr_version: None,
        collected_at_utc: None,
        encoding: None,
    })
}

fn validate_native_manifest(
    bundle_root: &Path,
    manifest: &SccmBundleManifestV1,
    validate_files: bool,
) -> Result<(), AppError> {
    validate_native_manifest_structure(manifest)?;
    manifest_to_client_intake_bundle(manifest)?;
    if validate_files {
        for artifact in &manifest.artifacts {
            if !artifact.state.is_physical() {
                continue;
            }
            let relative_path = artifact.relative_path.as_deref().ok_or_else(|| {
                AppError::InvalidInput("physical SCCM artifact has no path".into())
            })?;
            let candidate = bundle_root.join(relative_path);
            let metadata = fs::symlink_metadata(&candidate).map_err(|error| {
                AppError::InvalidInput(format!(
                    "SCCM evidence {} is unavailable: {error}",
                    relative_path
                ))
            })?;
            if is_reparse_point(&metadata) || !metadata.is_file() {
                return Err(AppError::InvalidInput(format!(
                    "SCCM evidence {relative_path} is not a real file"
                )));
            }
            let canonical = candidate.canonicalize()?;
            if !canonical.starts_with(bundle_root) || metadata.len() != artifact.bytes_copied {
                return Err(AppError::InvalidInput(format!(
                    "SCCM evidence {relative_path} violates path or size coherence"
                )));
            }
        }
    }
    Ok(())
}

fn validate_native_manifest_structure(manifest: &SccmBundleManifestV1) -> Result<(), AppError> {
    if manifest.sccm_manifest_version != SCCM_MANIFEST_VERSION
        || manifest.diagnostics_schema_version != SCCM_DIAGNOSTICS_SCHEMA_VERSION
        || manifest.source_catalog_version != SCCM_CLIENT_SOURCE_CATALOG_VERSION
        || manifest.provenance != SccmManifestProvenance::NativeClientCapture
    {
        return Err(AppError::InvalidInput(
            "unsupported or non-native SCCM client manifest contract".to_owned(),
        ));
    }
    if manifest.artifacts.len() > MAX_SCCM_MANIFEST_ARTIFACTS {
        return Err(AppError::InvalidInput(
            "SCCM manifest has too many artifacts".to_owned(),
        ));
    }
    if manifest
        .collected_at_utc
        .as_deref()
        .is_none_or(|value| !is_rfc3339(value))
        || manifest
            .host_handle
            .as_deref()
            .is_some_and(|value| !is_versioned_handle(value, "cmtraceopen.host.sha256.v1:"))
    {
        return Err(AppError::InvalidInput(
            "SCCM manifest context is malformed or privacy-unsafe".to_owned(),
        ));
    }

    let mut artifact_ids = BTreeSet::new();
    let mut relative_paths = BTreeSet::new();
    let mut lineage_bindings = BTreeMap::<String, (String, String)>::new();
    for artifact in &manifest.artifacts {
        validate_native_artifact(manifest, artifact)?;
        if !artifact_ids.insert(artifact.artifact_id.clone()) {
            return Err(AppError::InvalidInput(
                "SCCM manifest contains duplicate artifact IDs".to_owned(),
            ));
        }
        if let Some(path) = &artifact.relative_path {
            if !relative_paths.insert(path.to_ascii_lowercase()) {
                return Err(AppError::InvalidInput(
                    "SCCM manifest contains duplicate relative paths".to_owned(),
                ));
            }
        }
        if let (Some(lineage), Some(fingerprint)) =
            (&artifact.rotation_lineage, &artifact.path_fingerprint)
        {
            let binding = (artifact.basename_identity(), fingerprint.clone());
            if lineage_bindings
                .insert(lineage.clone(), binding.clone())
                .is_some_and(|existing| existing != binding)
            {
                return Err(AppError::InvalidInput(
                    "SCCM rotation lineage crosses physical sources".to_owned(),
                ));
            }
        }
    }
    if !manifest
        .artifacts
        .windows(2)
        .all(|pair| compare_manifest_artifacts(&pair[0], &pair[1]).is_le())
    {
        return Err(AppError::InvalidInput(
            "SCCM manifest artifacts are not in deterministic order".to_owned(),
        ));
    }
    Ok(())
}

fn validate_native_artifact(
    manifest: &SccmBundleManifestV1,
    artifact: &SccmManifestArtifact,
) -> Result<(), AppError> {
    if artifact.role != SccmRole::Client
        || !is_versioned_handle(&artifact.artifact_id, "sccm-artifact:v1:sha256:")
        || artifact.collected_at_utc != manifest.collected_at_utc
        || artifact
            .configmgr_version
            .as_deref()
            .is_some_and(|version| !is_safe_configmgr_version(version))
        || artifact
            .encoding
            .as_deref()
            .is_some_and(|encoding| !is_supported_encoding(encoding))
    {
        return Err(AppError::InvalidInput(
            "SCCM manifest artifact identity, role, time, or encoding is invalid".to_owned(),
        ));
    }
    let classified = classify_artifact_name(&artifact.basename, SccmRole::Client);
    if !classified.supported_for_diagnosis
        || classified.rotation != artifact.rotation
        || artifact.catalog_entry_id != catalog_entry_id(&classified.basename)
    {
        return Err(AppError::InvalidInput(
            "SCCM manifest artifact is not bound to the authoritative catalog".to_owned(),
        ));
    }
    let expected_memberships = logical_artifact_ids_for_basename(&classified.basename);
    if expected_memberships.is_empty() || artifact.logical_artifact_ids != expected_memberships {
        return Err(AppError::InvalidInput(
            "SCCM manifest artifact memberships are incomplete or unordered".to_owned(),
        ));
    }

    let physical = artifact.state.is_physical();
    if physical {
        validate_bound_provenance(artifact, &classified.basename)?;
        let fingerprint = artifact
            .path_fingerprint
            .as_deref()
            .expect("validated physical provenance has a fingerprint");
        if artifact.artifact_id
            != expected_physical_artifact_id(fingerprint, &artifact.rotation, &artifact.basename)
        {
            return Err(AppError::InvalidInput(
                "physical SCCM artifact provenance is malformed".to_owned(),
            ));
        }
        validate_relative_path(artifact, &classified.basename)?;
        if artifact.state == SccmManifestSourceState::Capped {
            if artifact.fragment_complete || artifact.limit_applied != Some(artifact.bytes_copied) {
                return Err(AppError::InvalidInput(
                    "capped SCCM artifact has incoherent limit or completeness".to_owned(),
                ));
            }
        } else if artifact.limit_applied.is_some() {
            return Err(AppError::InvalidInput(
                "uncapped SCCM artifact declares a capture limit".to_owned(),
            ));
        }
    } else {
        if artifact.relative_path.is_some()
            || artifact.bytes_copied != 0
            || artifact.limit_applied.is_some()
            || artifact.fragment_complete
        {
            return Err(AppError::InvalidInput(
                "nonphysical SCCM coverage marker claims physical evidence".to_owned(),
            ));
        }
        let has_any_provenance = artifact.source_handle.is_some()
            || artifact.root_handle.is_some()
            || artifact.path_fingerprint.is_some()
            || artifact.rotation_lineage.is_some();
        if has_any_provenance {
            validate_bound_provenance(artifact, &classified.basename)?;
        }
        if artifact.artifact_id
            != expected_marker_artifact_id(
                &artifact.catalog_entry_id,
                artifact.state,
                &artifact.rotation,
                &artifact.basename,
                artifact.path_fingerprint.as_deref(),
            )
        {
            return Err(AppError::InvalidInput(
                "SCCM coverage marker identity is not canonical".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_bound_provenance(
    artifact: &SccmManifestArtifact,
    canonical_basename: &str,
) -> Result<(), AppError> {
    let source_handle = artifact
        .source_handle
        .as_deref()
        .ok_or_else(|| AppError::InvalidInput("SCCM source provenance is incomplete".to_owned()))?;
    let root_handle = artifact
        .root_handle
        .as_deref()
        .ok_or_else(|| AppError::InvalidInput("SCCM source provenance is incomplete".to_owned()))?;
    let fingerprint = artifact
        .path_fingerprint
        .as_deref()
        .ok_or_else(|| AppError::InvalidInput("SCCM source provenance is incomplete".to_owned()))?;
    let lineage = artifact
        .rotation_lineage
        .as_deref()
        .ok_or_else(|| AppError::InvalidInput("SCCM source provenance is incomplete".to_owned()))?;
    let expected_source_digest = source_identity_digest(root_handle, canonical_basename)
        .ok_or_else(|| AppError::InvalidInput("SCCM root handle is malformed".to_owned()))?;
    let expected_lineage = sha256_bytes(format!("lineage:v1:{expected_source_digest}").as_bytes());
    if !is_versioned_handle(source_handle, "cmtraceopen.source.sha256.v1:")
        || !is_versioned_handle(fingerprint, "sha256:")
        || !is_versioned_handle(lineage, "cmtraceopen.lineage.sha256.v1:")
        || source_handle.strip_prefix("cmtraceopen.source.sha256.v1:")
            != Some(expected_source_digest.as_str())
        || fingerprint.strip_prefix("sha256:") != Some(expected_source_digest.as_str())
        || lineage.strip_prefix("cmtraceopen.lineage.sha256.v1:") != Some(expected_lineage.as_str())
    {
        return Err(AppError::InvalidInput(
            "SCCM source provenance is malformed".to_owned(),
        ));
    }
    Ok(())
}

fn validate_relative_path(
    artifact: &SccmManifestArtifact,
    canonical_basename: &str,
) -> Result<(), AppError> {
    let relative = artifact.relative_path.as_deref().ok_or_else(|| {
        AppError::InvalidInput("physical SCCM artifact has no relative path".to_owned())
    })?;
    if relative.contains('\\')
        || Path::new(relative).is_absolute()
        || Path::new(relative)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(AppError::InvalidInput(
            "SCCM artifact relative path is unsafe".to_owned(),
        ));
    }
    let segments = relative.split('/').collect::<Vec<_>>();
    if segments.len() != 7
        || segments[0..3] != ["evidence", "sccm", "client"]
        || segments[3] != expected_bundle_group(&artifact.logical_artifact_ids)
        || artifact.root_handle.as_deref() != Some(segments[4])
        || segments[5] != rotation_segment(&artifact.rotation)
        || segments[6] != artifact.basename
        || classify_artifact_name(segments[6], SccmRole::Client).basename != canonical_basename
    {
        return Err(AppError::InvalidInput(
            "SCCM artifact relative path does not match catalog provenance".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn expected_bundle_group(logical_artifact_ids: &[String]) -> &str {
    if logical_artifact_ids == ["client-content".to_owned(), "client-location".to_owned()] {
        "client-location-services-shared"
    } else {
        logical_artifact_ids
            .first()
            .map(String::as_str)
            .unwrap_or("unknown")
    }
}

pub(super) fn rotation_segment(rotation: &SccmRotation) -> String {
    match rotation {
        SccmRotation::Current => "current".to_owned(),
        SccmRotation::LoUnderscore => "lo".to_owned(),
        SccmRotation::Numbered(number) => format!("numbered-{number}"),
        SccmRotation::Timestamped(timestamp) => format!("timestamped-{timestamp}"),
        SccmRotation::Unknown(_) => "unknown".to_owned(),
    }
}

pub(super) fn expected_physical_artifact_id(
    fingerprint: &str,
    rotation: &SccmRotation,
    basename: &str,
) -> String {
    format!(
        "sccm-artifact:v1:sha256:{}",
        sha256_bytes(
            format!(
                "artifact:v1:{fingerprint}:{}:{basename}",
                rotation_segment(rotation)
            )
            .as_bytes()
        )
    )
}

pub(super) fn expected_marker_artifact_id(
    catalog_entry_id: &str,
    state: SccmManifestSourceState,
    rotation: &SccmRotation,
    basename: &str,
    path_fingerprint: Option<&str>,
) -> String {
    format!(
        "sccm-artifact:v1:sha256:{}",
        sha256_bytes(
            format!(
                "marker:v1:{catalog_entry_id}:{}:{}:{basename}:{}",
                manifest_state_segment(state),
                rotation_segment(rotation),
                path_fingerprint.unwrap_or("unscoped")
            )
            .as_bytes()
        )
    )
}

pub(super) fn compare_manifest_artifacts(
    left: &SccmManifestArtifact,
    right: &SccmManifestArtifact,
) -> std::cmp::Ordering {
    left.logical_artifact_ids
        .cmp(&right.logical_artifact_ids)
        .then_with(|| {
            left.path_fingerprint
                .as_deref()
                .unwrap_or_default()
                .cmp(right.path_fingerprint.as_deref().unwrap_or_default())
        })
        .then_with(|| rotation_order(&left.rotation, &right.rotation))
        .then_with(|| left.basename.cmp(&right.basename))
        .then_with(|| left.artifact_id.cmp(&right.artifact_id))
}

impl SccmManifestArtifact {
    fn basename_identity(&self) -> String {
        classify_artifact_name(&self.basename, SccmRole::Client)
            .basename
            .to_ascii_lowercase()
    }
}

fn create_real_bundle_root(bundle_root: &Path) -> Result<std::path::PathBuf, AppError> {
    if !bundle_root.exists() {
        fs::create_dir_all(bundle_root)?;
    }
    verify_real_bundle_root(bundle_root)
}

fn verify_real_bundle_root(bundle_root: &Path) -> Result<std::path::PathBuf, AppError> {
    let metadata = fs::symlink_metadata(bundle_root)?;
    if is_reparse_point(&metadata) || !metadata.is_dir() {
        return Err(AppError::InvalidInput(
            "SCCM bundle root must be a real directory".to_owned(),
        ));
    }
    Ok(bundle_root.canonicalize()?)
}

fn read_bounded_file(mut input: File, maximum: u64, label: &str) -> Result<Vec<u8>, AppError> {
    let metadata = input.metadata()?;
    if is_reparse_point(&metadata) || !metadata.is_file() {
        return Err(AppError::InvalidInput(format!(
            "{label} must be a real file inside the bundle"
        )));
    }
    if metadata.len() > maximum {
        return Err(AppError::InvalidInput(format!(
            "{label} exceeds its size limit"
        )));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut input)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(AppError::InvalidInput(format!(
            "{label} exceeds its size limit"
        )));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_manifest_for_read(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

#[cfg(windows)]
fn open_manifest_for_read(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(not(any(unix, windows)))]
fn open_manifest_for_read(path: &Path) -> io::Result<File> {
    OpenOptions::new().read(true).open(path)
}

fn validate_legacy_relative_path(value: &str) -> Result<(), AppError> {
    if value.is_empty()
        || value.len() > 512
        || value.contains('\\')
        || Path::new(value).is_absolute()
        || !value.starts_with("evidence/")
        || Path::new(value)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(AppError::InvalidInput(
            "legacy artifact relative path is unsafe".to_owned(),
        ));
    }
    Ok(())
}

fn is_rfc3339(value: &str) -> bool {
    value.len() <= 64 && value.is_ascii() && DateTime::parse_from_rfc3339(value).is_ok()
}

fn is_supported_encoding(value: &str) -> bool {
    matches!(value, "utf-8" | "utf-16le" | "utf-16be" | "windows-1252")
}

fn is_safe_configmgr_version(value: &str) -> bool {
    if matches!(value, "5.00.TEST.0000" | "5.00.UNKNOWN.0000") {
        return true;
    }

    let mut components = value.split('.');
    matches!(components.next(), Some("5"))
        && matches!(components.next(), Some("00"))
        && components.next().is_some_and(is_four_ascii_digits)
        && components.next().is_some_and(is_four_ascii_digits)
        && components.next().is_none()
}

fn is_four_ascii_digits(value: &str) -> bool {
    value.len() == 4 && value.bytes().all(|byte| byte.is_ascii_digit())
}

pub(super) fn validate_client_capture_context(
    collected_at_utc: &str,
    configmgr_version: Option<&str>,
    encoding: Option<&str>,
) -> Result<(), AppError> {
    if !is_rfc3339(collected_at_utc)
        || configmgr_version.is_some_and(|version| !is_safe_configmgr_version(version))
        || encoding.is_some_and(|value| !is_supported_encoding(value))
    {
        return Err(AppError::InvalidInput(
            "SCCM capture time, ConfigMgr version, or encoding is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn is_versioned_handle(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(is_sha256_digest)
}

fn source_identity_digest(root_handle: &str, basename: &str) -> Option<String> {
    let root_digest = root_handle.strip_prefix("root-")?;
    if !is_sha256_digest(root_digest) {
        return None;
    }
    Some(sha256_bytes(
        format!("cmtraceopen.sccm.source.v1\0{root_digest}\0{basename}").as_bytes(),
    ))
}

fn manifest_state_segment(state: SccmManifestSourceState) -> &'static str {
    match state {
        SccmManifestSourceState::Captured => "captured",
        SccmManifestSourceState::Absent => "absent",
        SccmManifestSourceState::AccessDenied => "accessDenied",
        SccmManifestSourceState::Capped => "capped",
        SccmManifestSourceState::Skipped => "skipped",
        SccmManifestSourceState::Unsupported => "unsupported",
        SccmManifestSourceState::UnsafePath => "unsafePath",
        SccmManifestSourceState::ParseFailed => "parseFailed",
        SccmManifestSourceState::FailedUnknownDetail => "failedUnknownDetail",
    }
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == SHA256_HEX_CHARS
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
