use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path};

use chrono::DateTime;
use cmtraceopen_parser::sccm::{
    assess_client_intake, SccmArtifact, SccmClientIntakeArtifact, SccmClientIntakeBundle,
    SccmClientIntakeCaptureGap, SccmRole, SccmRotation, SCCM_DIAGNOSTICS_SCHEMA_VERSION,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::AppError;

use super::contract::{
    canonical_client_source, catalog_entry_id, compare_manifest_artifacts,
    compare_manifest_capture_gaps, expected_bundle_group, expected_marker_artifact_id,
    expected_physical_artifact_id, is_sha256_digest, is_versioned_handle,
    logical_artifact_ids_for_basename, root_handle_digest, rotation_segment, sha256_bytes,
    source_identity_digest, SccmBundleManifestV1, SccmManifestArtifact, SccmManifestCaptureGap,
    SccmManifestCoverageScope, SccmManifestProvenance, SccmManifestProvenanceProfile,
    SccmManifestSourceState, MAX_SCCM_MANIFEST_ARTIFACTS, MAX_SCCM_MANIFEST_BYTES,
    SCCM_CLIENT_SOURCE_CATALOG_VERSION, SCCM_MANIFEST_FILE_NAME, SCCM_MANIFEST_VERSION,
};
use super::private_fs::{is_reparse_point, verify_bundle_root, VerifiedBundleRoot};

const LEGACY_MANIFEST_FILE_NAME: &str = "manifest.json";
const LEGACY_GENERIC_PROFILE_NAME: &str = "cmtrace-full-diagnostics-v1";
const LEGACY_GENERIC_PROFILE_VERSION: &str = "1.1.0";
const LEGACY_CONFIGMGR_CCM_LOGS_ID: &str = "configmgr-ccm-logs";
const LEGACY_CONFIGMGR_LOG_CATEGORY: &str = "logs";
const LEGACY_CCMSETUP_BASENAME: &str = "ccmsetup.log";
const MAX_SAFE_TEXT_CHARS: usize = 160;
const MAX_SCCM_CLIENT_PHYSICAL_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_SCCM_CLIENT_TOTAL_PHYSICAL_BYTES: u64 = 1024 * 1024 * 1024;

#[cfg(test)]
thread_local! {
    static INTAKE_PROJECTION_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn reset_intake_projection_count() {
    INTAKE_PROJECTION_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
fn intake_projection_count() -> usize {
    INTAKE_PROJECTION_COUNT.with(std::cell::Cell::get)
}

enum ValidatedManifestRead {
    Native {
        manifest: SccmBundleManifestV1,
        intake_bundle: SccmClientIntakeBundle,
    },
    Legacy(SccmBundleManifestV1),
}

fn read_validated_manifest_or_legacy(
    bundle_root: &Path,
) -> Result<ValidatedManifestRead, AppError> {
    let verified_root = verify_bundle_root(bundle_root)?;
    match verified_root.open_relative_file(Path::new(SCCM_MANIFEST_FILE_NAME)) {
        Ok(input) => {
            let bytes = read_bounded_file(input, MAX_SCCM_MANIFEST_BYTES, "SCCM manifest")?;
            let manifest =
                serde_json::from_slice::<SccmBundleManifestV1>(&bytes).map_err(|error| {
                    AppError::Parse {
                        file: SCCM_MANIFEST_FILE_NAME.to_owned(),
                        reason: error.to_string(),
                    }
                })?;
            let intake_bundle = validate_native_manifest(&verified_root, &manifest)?;
            Ok(ValidatedManifestRead::Native {
                manifest,
                intake_bundle,
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            read_legacy_manifest(&verified_root).map(ValidatedManifestRead::Legacy)
        }
        Err(_) => Err(AppError::InvalidInput(
            "SCCM manifest cannot be opened safely".to_owned(),
        )),
    }
}

pub fn read_sccm_manifest_or_legacy(bundle_root: &Path) -> Result<SccmBundleManifestV1, AppError> {
    match read_validated_manifest_or_legacy(bundle_root)? {
        ValidatedManifestRead::Native { manifest, .. }
        | ValidatedManifestRead::Legacy(manifest) => Ok(manifest),
    }
}

fn manifest_to_client_intake_bundle(
    manifest: &SccmBundleManifestV1,
) -> Result<SccmClientIntakeBundle, AppError> {
    #[cfg(test)]
    INTAKE_PROJECTION_COUNT.with(|count| count.set(count.get().saturating_add(1)));

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
        .collect();
    let capture_gaps = manifest
        .capture_gaps
        .iter()
        .map(|gap| SccmClientIntakeCaptureGap {
            artifact_id: gap.artifact_id.clone(),
            basename: gap.basename.clone(),
            rotation: gap.rotation.clone(),
            coverage: gap.state.pure_coverage(),
            path_fingerprint: gap.path_fingerprint.clone(),
            rotation_lineage: gap.rotation_lineage.clone(),
        })
        .collect();
    let bundle = SccmClientIntakeBundle {
        artifacts,
        capture_gaps,
    };
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
    match read_validated_manifest_or_legacy(bundle_root)? {
        ValidatedManifestRead::Native { intake_bundle, .. } => Ok(intake_bundle),
        ValidatedManifestRead::Legacy(_) => {
            let verified_root = verify_bundle_root(bundle_root)?;
            read_legacy_client_intake_bundle(&verified_root)
        }
    }
}

fn validate_native_manifest(
    bundle_root: &VerifiedBundleRoot,
    manifest: &SccmBundleManifestV1,
) -> Result<SccmClientIntakeBundle, AppError> {
    let intake_bundle = manifest_to_client_intake_bundle(manifest)?;
    validate_physical_source_limits(manifest)?;
    for artifact in &manifest.artifacts {
        if artifact.state.is_physical() {
            validate_evidence_file(bundle_root, artifact)?;
        }
    }
    Ok(intake_bundle)
}

fn validate_physical_source_limits(manifest: &SccmBundleManifestV1) -> Result<(), AppError> {
    let mut totals = BTreeMap::<String, (u64, u64)>::new();
    let mut total_physical_bytes = 0_u64;
    for artifact in manifest
        .artifacts
        .iter()
        .filter(|artifact| artifact.state.is_physical())
    {
        add_to_client_physical_byte_budget(artifact.bytes_copied, &mut total_physical_bytes)?;
        let canonical_basename = canonical_client_source(&artifact.basename, &artifact.rotation)
            .expect("physical artifacts were catalog-validated before source limits");
        let source = source_identity_digest(
            artifact
                .root_handle
                .as_deref()
                .expect("physical artifacts have validated root provenance"),
            &canonical_basename,
        )
        .expect("physical artifacts have a validated root handle");
        let entry = totals.entry(source).or_insert((0, 0));
        entry.0 = entry
            .0
            .checked_add(1)
            .ok_or_else(|| AppError::InvalidInput("SCCM source file cap is exceeded".to_owned()))?;
        entry.1 = entry
            .1
            .checked_add(artifact.bytes_copied)
            .ok_or_else(|| AppError::InvalidInput("SCCM source byte cap is exceeded".to_owned()))?;
        if entry.0 > manifest.max_files_per_source as u64 {
            return Err(AppError::InvalidInput(
                "SCCM source file cap is exceeded".to_owned(),
            ));
        }
        if entry.1 > manifest.max_bytes_per_source {
            return Err(AppError::InvalidInput(
                "SCCM source byte cap is exceeded".to_owned(),
            ));
        }
    }
    Ok(())
}

fn add_to_client_physical_byte_budget(
    artifact_bytes: u64,
    total_physical_bytes: &mut u64,
) -> Result<(), AppError> {
    if artifact_bytes > MAX_SCCM_CLIENT_PHYSICAL_ARTIFACT_BYTES {
        return Err(AppError::InvalidInput(
            "SCCM physical artifact byte cap is exceeded".to_owned(),
        ));
    }
    *total_physical_bytes = total_physical_bytes
        .checked_add(artifact_bytes)
        .ok_or_else(|| {
            AppError::InvalidInput("SCCM aggregate physical byte cap is exceeded".to_owned())
        })?;
    if *total_physical_bytes > MAX_SCCM_CLIENT_TOTAL_PHYSICAL_BYTES {
        return Err(AppError::InvalidInput(
            "SCCM aggregate physical byte cap is exceeded".to_owned(),
        ));
    }
    Ok(())
}

fn validate_native_manifest_structure(manifest: &SccmBundleManifestV1) -> Result<(), AppError> {
    if manifest.sccm_manifest_version != SCCM_MANIFEST_VERSION
        || manifest.diagnostics_schema_version != SCCM_DIAGNOSTICS_SCHEMA_VERSION
        || manifest.source_catalog_version != SCCM_CLIENT_SOURCE_CATALOG_VERSION
        || manifest.provenance != SccmManifestProvenance::NativeClientCapture
        || manifest.provenance_profile != SccmManifestProvenanceProfile::HmacSha256V1
    {
        return Err(AppError::InvalidInput(
            "unsupported or non-native SCCM client manifest contract".to_owned(),
        ));
    }
    if manifest
        .artifacts
        .len()
        .saturating_add(manifest.capture_gaps.len())
        > MAX_SCCM_MANIFEST_ARTIFACTS
    {
        return Err(AppError::InvalidInput(
            "SCCM manifest has too many artifacts or capture gaps".to_owned(),
        ));
    }
    if manifest.max_files_per_source == 0
        || manifest.max_bytes_per_source == 0
        || manifest
            .collected_at_utc
            .as_deref()
            .is_none_or(|value| !is_utc_rfc3339(value))
        || manifest
            .host_handle
            .as_deref()
            .is_some_and(|value| !is_versioned_handle(value, "cmtraceopen.host.hmac-sha256.v1:"))
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
        if !artifact_ids.insert(artifact.artifact_id.to_ascii_lowercase()) {
            return Err(AppError::InvalidInput(
                "SCCM manifest contains duplicate artifact IDs".to_owned(),
            ));
        }
        if let Some(relative_path) = &artifact.relative_path {
            if !relative_paths.insert(relative_path.to_ascii_lowercase()) {
                return Err(AppError::InvalidInput(
                    "SCCM manifest contains duplicate relative paths".to_owned(),
                ));
            }
        }
        if let (Some(lineage), Some(fingerprint)) =
            (&artifact.rotation_lineage, &artifact.path_fingerprint)
        {
            bind_lineage(
                &mut lineage_bindings,
                lineage,
                &canonical_basename(&artifact.basename),
                fingerprint,
                "SCCM rotation lineage crosses physical sources",
            )?;
        }
    }
    for gap in &manifest.capture_gaps {
        validate_capture_gap(gap)?;
        if !artifact_ids.insert(gap.artifact_id.to_ascii_lowercase()) {
            return Err(AppError::InvalidInput(
                "SCCM manifest contains duplicate artifact IDs".to_owned(),
            ));
        }
        bind_lineage(
            &mut lineage_bindings,
            &gap.rotation_lineage,
            &canonical_basename(&gap.basename),
            &gap.path_fingerprint,
            "SCCM capture gap lineage crosses physical sources",
        )?;
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
    if !manifest
        .capture_gaps
        .windows(2)
        .all(|pair| compare_manifest_capture_gaps(&pair[0], &pair[1]).is_le())
    {
        return Err(AppError::InvalidInput(
            "SCCM manifest capture gaps are not in deterministic order".to_owned(),
        ));
    }
    Ok(())
}

fn bind_lineage(
    bindings: &mut BTreeMap<String, (String, String)>,
    lineage: &str,
    basename: &str,
    fingerprint: &str,
    error_message: &str,
) -> Result<(), AppError> {
    let binding = (basename.to_owned(), fingerprint.to_owned());
    if bindings
        .insert(lineage.to_owned(), binding.clone())
        .is_some_and(|existing| existing != binding)
    {
        return Err(AppError::InvalidInput(error_message.to_owned()));
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
            .is_some_and(|value| !is_safe_configmgr_version(value))
        || artifact
            .encoding
            .as_deref()
            .is_some_and(|value| !is_supported_encoding(value))
    {
        return Err(AppError::InvalidInput(
            "SCCM manifest artifact identity, role, time, or encoding is invalid".to_owned(),
        ));
    }
    let canonical_basename = canonical_client_source(&artifact.basename, &artifact.rotation)
        .ok_or_else(|| {
            AppError::InvalidInput(
                "SCCM manifest artifact is not bound to the authoritative catalog".to_owned(),
            )
        })?;
    if artifact.catalog_entry_id != catalog_entry_id(&canonical_basename)
        || artifact.logical_artifact_ids != logical_artifact_ids_for_basename(&canonical_basename)
        || artifact.logical_artifact_ids.is_empty()
    {
        return Err(AppError::InvalidInput(
            "SCCM manifest artifact memberships are incomplete or unordered".to_owned(),
        ));
    }

    if artifact.state.is_physical() {
        if artifact.coverage_scope != SccmManifestCoverageScope::Source {
            return Err(AppError::InvalidInput(
                "physical SCCM evidence cannot claim a root-enumeration scope".to_owned(),
            ));
        }
        validate_bound_provenance(artifact, &canonical_basename)?;
        let fingerprint = artifact
            .path_fingerprint
            .as_deref()
            .expect("validated physical provenance includes a fingerprint");
        if artifact.artifact_id
            != expected_physical_artifact_id(fingerprint, &artifact.rotation, &artifact.basename)
        {
            return Err(AppError::InvalidInput(
                "physical SCCM artifact provenance is malformed".to_owned(),
            ));
        }
        validate_relative_path(artifact, &canonical_basename)?;
        if artifact
            .content_sha256
            .as_deref()
            .is_none_or(|digest| !is_sha256_digest(digest))
        {
            return Err(AppError::InvalidInput(
                "physical SCCM artifact has no valid content digest".to_owned(),
            ));
        }
        if artifact.state == SccmManifestSourceState::Capped
            || (artifact.state == SccmManifestSourceState::ParseFailed
                && artifact.limit_applied.is_some())
        {
            if artifact.fragment_complete
                || artifact.capture_limit_kind.is_none()
                || artifact.limit_applied != Some(artifact.bytes_copied)
            {
                return Err(AppError::InvalidInput(
                    "bounded SCCM artifact has incoherent limit or completeness".to_owned(),
                ));
            }
        } else if artifact.limit_applied.is_some() || artifact.capture_limit_kind.is_some() {
            return Err(AppError::InvalidInput(
                "uncapped SCCM artifact declares a capture limit".to_owned(),
            ));
        }
    } else {
        if artifact.relative_path.is_some()
            || artifact.bytes_copied != 0
            || artifact.limit_applied.is_some()
            || artifact.capture_limit_kind.is_some()
            || artifact.content_sha256.is_some()
            || artifact.fragment_complete
        {
            return Err(AppError::InvalidInput(
                "nonphysical SCCM coverage marker claims physical evidence".to_owned(),
            ));
        }
        validate_nonphysical_provenance(artifact, &canonical_basename)?;
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

fn validate_nonphysical_provenance(
    artifact: &SccmManifestArtifact,
    canonical_basename: &str,
) -> Result<(), AppError> {
    if artifact.coverage_scope == SccmManifestCoverageScope::RootEnumeration {
        if !matches!(
            artifact.state,
            SccmManifestSourceState::AccessDenied | SccmManifestSourceState::FailedUnknownDetail
        ) || artifact.rotation != SccmRotation::Current
        {
            return Err(AppError::InvalidInput(
                "SCCM root-enumeration coverage scope is incoherent".to_owned(),
            ));
        }
        return validate_enumeration_provenance(artifact, canonical_basename);
    }
    let has_any_provenance = artifact.source_handle.is_some()
        || artifact.root_handle.is_some()
        || artifact.path_fingerprint.is_some()
        || artifact.rotation_lineage.is_some();
    if has_any_provenance {
        validate_bound_provenance(artifact, canonical_basename)?;
    }
    Ok(())
}

fn validate_capture_gap(gap: &SccmManifestCaptureGap) -> Result<(), AppError> {
    if !matches!(
        gap.state,
        SccmManifestSourceState::Capped | SccmManifestSourceState::ParseFailed
    ) || gap.bytes_retained != 0
        || !is_versioned_handle(&gap.artifact_id, "sccm-artifact:v1:sha256:")
    {
        return Err(AppError::InvalidInput(
            "SCCM capture gap state or payload claim is incoherent".to_owned(),
        ));
    }
    let canonical_basename =
        canonical_client_source(&gap.basename, &gap.rotation).ok_or_else(|| {
            AppError::InvalidInput(
                "SCCM capture gap is not bound to the authoritative catalog".to_owned(),
            )
        })?;
    if gap.catalog_entry_id != catalog_entry_id(&canonical_basename)
        || gap.logical_artifact_ids != logical_artifact_ids_for_basename(&canonical_basename)
        || gap.logical_artifact_ids.is_empty()
    {
        return Err(AppError::InvalidInput(
            "SCCM capture gap is not bound to the authoritative catalog".to_owned(),
        ));
    }
    let expected_source_digest = source_identity_digest(&gap.root_handle, &canonical_basename)
        .ok_or_else(|| AppError::InvalidInput("SCCM root handle is malformed".to_owned()))?;
    let expected_lineage = sha256_bytes(format!("lineage:v1:{expected_source_digest}").as_bytes());
    if gap
        .source_handle
        .strip_prefix("cmtraceopen.source.sha256.v1:")
        != Some(expected_source_digest.as_str())
        || gap.path_fingerprint.strip_prefix("sha256:") != Some(expected_source_digest.as_str())
        || gap
            .rotation_lineage
            .strip_prefix("cmtraceopen.lineage.sha256.v1:")
            != Some(expected_lineage.as_str())
        || gap.artifact_id
            != expected_marker_artifact_id(
                &gap.catalog_entry_id,
                gap.state,
                &gap.rotation,
                &gap.basename,
                Some(&gap.path_fingerprint),
            )
    {
        return Err(AppError::InvalidInput(
            "SCCM capture gap provenance is malformed".to_owned(),
        ));
    }
    Ok(())
}

fn validate_bound_provenance(
    artifact: &SccmManifestArtifact,
    canonical_basename: &str,
) -> Result<(), AppError> {
    let source_handle = required_provenance(&artifact.source_handle)?;
    let root_handle = required_provenance(&artifact.root_handle)?;
    let fingerprint = required_provenance(&artifact.path_fingerprint)?;
    let lineage = required_provenance(&artifact.rotation_lineage)?;
    let expected_source_digest = source_identity_digest(root_handle, canonical_basename)
        .ok_or_else(|| AppError::InvalidInput("SCCM root handle is malformed".to_owned()))?;
    let expected_lineage = sha256_bytes(format!("lineage:v1:{expected_source_digest}").as_bytes());
    if source_handle.strip_prefix("cmtraceopen.source.sha256.v1:")
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

fn required_provenance(value: &Option<String>) -> Result<&str, AppError> {
    value
        .as_deref()
        .ok_or_else(|| AppError::InvalidInput("SCCM source provenance is incomplete".to_owned()))
}

fn validate_enumeration_provenance(
    artifact: &SccmManifestArtifact,
    canonical_basename: &str,
) -> Result<(), AppError> {
    let source_handle = required_provenance(&artifact.source_handle)?;
    let root_handle = required_provenance(&artifact.root_handle)?;
    let fingerprint = required_provenance(&artifact.path_fingerprint)?;
    let lineage = required_provenance(&artifact.rotation_lineage)?;
    let root_digest = root_handle_digest(root_handle)
        .ok_or_else(|| AppError::InvalidInput("SCCM root handle is malformed".to_owned()))?;
    let expected_source_digest = sha256_bytes(
        format!("cmtraceopen.sccm.root-enumeration.v1\0{root_digest}\0{canonical_basename}")
            .as_bytes(),
    );
    let expected_lineage = sha256_bytes(format!("lineage:v1:{expected_source_digest}").as_bytes());
    if source_handle.strip_prefix("cmtraceopen.source.sha256.v1:")
        != Some(expected_source_digest.as_str())
        || fingerprint.strip_prefix("sha256:") != Some(expected_source_digest.as_str())
        || lineage.strip_prefix("cmtraceopen.lineage.sha256.v1:") != Some(expected_lineage.as_str())
    {
        return Err(AppError::InvalidInput(
            "SCCM enumeration provenance is malformed".to_owned(),
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
    if relative.len() > 1024
        || relative.contains('\\')
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
        || canonical_client_source(segments[6], &artifact.rotation).as_deref()
            != Some(canonical_basename)
    {
        return Err(AppError::InvalidInput(
            "SCCM artifact relative path does not match catalog provenance".to_owned(),
        ));
    }
    Ok(())
}

fn validate_evidence_file(
    bundle_root: &VerifiedBundleRoot,
    artifact: &SccmManifestArtifact,
) -> Result<(), AppError> {
    let relative_path = artifact
        .relative_path
        .as_deref()
        .ok_or_else(|| AppError::InvalidInput("physical SCCM artifact has no path".to_owned()))?;
    let mut input = bundle_root
        .open_relative_file(Path::new(relative_path))
        .map_err(|_| AppError::InvalidInput("SCCM evidence cannot be opened safely".to_owned()))?;
    let opened_metadata = input.metadata().map_err(|_| {
        AppError::InvalidInput("SCCM evidence metadata cannot be verified".to_owned())
    })?;
    if is_reparse_point(&opened_metadata)
        || !opened_metadata.is_file()
        || opened_metadata.len() != artifact.bytes_copied
    {
        return Err(AppError::InvalidInput(
            "SCCM evidence violates opened-file coherence".to_owned(),
        ));
    }
    let digest = sha256_exact_file(&mut input, artifact.bytes_copied)?;
    if artifact.content_sha256.as_deref() != Some(digest.as_str()) {
        return Err(AppError::InvalidInput(
            "SCCM evidence violates content digest coherence".to_owned(),
        ));
    }
    Ok(())
}

fn read_bounded_file(mut input: File, maximum: u64, label: &str) -> Result<Vec<u8>, AppError> {
    let metadata = input
        .metadata()
        .map_err(|_| AppError::InvalidInput(format!("{label} metadata cannot be verified")))?;
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
        .read_to_end(&mut bytes)
        .map_err(|_| AppError::InvalidInput(format!("{label} cannot be read safely")))?;
    if bytes.len() as u64 > maximum {
        return Err(AppError::InvalidInput(format!(
            "{label} exceeds its size limit"
        )));
    }
    Ok(bytes)
}

fn sha256_exact_file(input: &mut File, expected_bytes: u64) -> Result<String, AppError> {
    let mut digest = Sha256::new();
    let mut remaining = expected_bytes;
    let mut buffer = [0_u8; 64 * 1024];
    while remaining > 0 {
        let requested = usize::try_from(remaining.min(buffer.len() as u64))
            .expect("bounded digest buffer length fits usize");
        let read = input.read(&mut buffer[..requested]).map_err(|_| {
            AppError::InvalidInput("SCCM evidence content cannot be verified".to_owned())
        })?;
        if read == 0 {
            return Err(AppError::InvalidInput(
                "SCCM evidence shrank during content verification".to_owned(),
            ));
        }
        digest.update(&buffer[..read]);
        remaining -= read as u64;
    }
    let mut probe = [0_u8; 1];
    if input.read(&mut probe).map_err(|_| {
        AppError::InvalidInput("SCCM evidence content cannot be verified".to_owned())
    })? != 0
    {
        return Err(AppError::InvalidInput(
            "SCCM evidence grew during content verification".to_owned(),
        ));
    }
    Ok(digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn read_legacy_manifest(
    bundle_root: &VerifiedBundleRoot,
) -> Result<SccmBundleManifestV1, AppError> {
    let legacy = read_legacy_value(bundle_root)?;
    let values = legacy
        .get("artifacts")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            AppError::InvalidInput("legacy manifest does not contain artifacts".to_owned())
        })?;
    let gaps = legacy_gaps(&legacy)?;
    if values.len().saturating_add(gaps.len()) > MAX_SCCM_MANIFEST_ARTIFACTS {
        return Err(AppError::InvalidInput(
            "legacy manifest has too many artifacts or gaps".to_owned(),
        ));
    }
    let mut artifacts = values
        .iter()
        .enumerate()
        .map(|(index, artifact)| legacy_artifact(index, artifact))
        .collect::<Result<Vec<_>, _>>()?;
    artifacts.extend(
        gaps.iter()
            .enumerate()
            .map(|(index, gap)| legacy_gap(index, gap))
            .collect::<Result<Vec<_>, _>>()?,
    );
    Ok(SccmBundleManifestV1 {
        sccm_manifest_version: SCCM_MANIFEST_VERSION,
        diagnostics_schema_version: SCCM_DIAGNOSTICS_SCHEMA_VERSION,
        source_catalog_version: 0,
        provenance: SccmManifestProvenance::LegacyGenericUnscoped,
        provenance_profile: SccmManifestProvenanceProfile::LegacyGenericUnscoped,
        host_handle: None,
        collected_at_utc: None,
        max_files_per_source: 0,
        max_bytes_per_source: 0,
        artifacts,
        capture_gaps: Vec::new(),
    })
}

fn read_legacy_value(bundle_root: &VerifiedBundleRoot) -> Result<Value, AppError> {
    let input = bundle_root
        .open_relative_file(Path::new(LEGACY_MANIFEST_FILE_NAME))
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                AppError::InvalidInput(format!(
                "bundle contains neither {SCCM_MANIFEST_FILE_NAME} nor {LEGACY_MANIFEST_FILE_NAME}"
            ))
            } else {
                AppError::InvalidInput("legacy manifest cannot be opened safely".to_owned())
            }
        })?;
    let bytes = read_bounded_file(input, MAX_SCCM_MANIFEST_BYTES, "legacy manifest")?;
    serde_json::from_slice(&bytes).map_err(|error| AppError::Parse {
        file: LEGACY_MANIFEST_FILE_NAME.to_owned(),
        reason: error.to_string(),
    })
}

fn legacy_gaps(legacy: &Value) -> Result<&[Value], AppError> {
    match legacy.pointer("/collection/results/gaps") {
        Some(Value::Array(gaps)) => Ok(gaps),
        Some(_) => Err(AppError::InvalidInput(
            "legacy manifest collection gaps are malformed".to_owned(),
        )),
        None => Ok(&[]),
    }
}

fn read_legacy_client_intake_bundle(
    bundle_root: &VerifiedBundleRoot,
) -> Result<SccmClientIntakeBundle, AppError> {
    let legacy = read_legacy_value(bundle_root)?;
    let supported_profile = legacy
        .pointer("/collection/collectorProfile")
        .and_then(Value::as_str)
        == Some(LEGACY_GENERIC_PROFILE_NAME)
        && legacy
            .pointer("/collection/collectorVersion")
            .and_then(Value::as_str)
            == Some(LEGACY_GENERIC_PROFILE_VERSION);
    if !supported_profile {
        return Ok(SccmClientIntakeBundle {
            artifacts: Vec::new(),
            capture_gaps: Vec::new(),
        });
    }
    let gaps = legacy_gaps(&legacy)?;
    if gaps.len() > MAX_SCCM_MANIFEST_ARTIFACTS {
        return Err(AppError::InvalidInput(
            "legacy manifest has too many collection gaps".to_owned(),
        ));
    }

    let mut artifacts = Vec::new();
    let mut known_gap_seen = false;
    for gap in gaps {
        if gap.get("artifactId").and_then(Value::as_str) != Some(LEGACY_CONFIGMGR_CCM_LOGS_ID)
            || gap.get("category").and_then(Value::as_str) != Some(LEGACY_CONFIGMGR_LOG_CATEGORY)
        {
            continue;
        }
        let state = match gap.get("status").and_then(Value::as_str) {
            Some("Missing") => SccmManifestSourceState::Absent,
            Some("Failed") => SccmManifestSourceState::FailedUnknownDetail,
            _ => continue,
        };
        if known_gap_seen {
            return Err(AppError::InvalidInput(
                "legacy manifest duplicates a known SCCM collection gap".to_owned(),
            ));
        }
        known_gap_seen = true;
        let catalog_id = catalog_entry_id(LEGACY_CCMSETUP_BASENAME);
        artifacts.push(SccmClientIntakeArtifact {
            artifact: SccmArtifact {
                artifact_id: expected_marker_artifact_id(
                    &catalog_id,
                    state,
                    &SccmRotation::Current,
                    LEGACY_CCMSETUP_BASENAME,
                    None,
                ),
                display_name: LEGACY_CCMSETUP_BASENAME.to_owned(),
                original_path: None,
                host: None,
                role: SccmRole::Client,
                configmgr_version: None,
                collected_at_utc: None,
                rotation: SccmRotation::Current,
                coverage: state.pure_coverage(),
                encoding: None,
            },
            path_fingerprint: None,
            rotation_lineage: None,
            relative_path: None,
            fragment_complete: Some(false),
        });
    }
    let bundle = SccmClientIntakeBundle {
        artifacts,
        capture_gaps: Vec::new(),
    };
    assess_client_intake(&bundle).map_err(|error| {
        AppError::InvalidInput(format!(
            "legacy manifest cannot be converted to the pure client intake contract: {error}"
        ))
    })?;
    Ok(bundle)
}

fn legacy_gap(index: usize, gap: &Value) -> Result<SccmManifestArtifact, AppError> {
    let legacy_id = legacy_identity(gap, "gap")?;
    let state = match gap.get("status").and_then(Value::as_str) {
        Some("Missing") => SccmManifestSourceState::Absent,
        _ => SccmManifestSourceState::FailedUnknownDetail,
    };
    Ok(legacy_unscoped_artifact("gap", index, legacy_id, state))
}

fn legacy_artifact(index: usize, artifact: &Value) -> Result<SccmManifestArtifact, AppError> {
    let legacy_id = legacy_identity(artifact, "artifact")?;
    if let Some(path) = artifact.get("relativePath").and_then(Value::as_str) {
        validate_legacy_relative_path(path)?;
    }
    let state = match artifact.get("status").and_then(Value::as_str) {
        Some("missing") => SccmManifestSourceState::Absent,
        // Legacy manifests provide no verifiable evidence binding, so even a
        // collected status remains a conservative unknown-detail failure.
        _ => SccmManifestSourceState::FailedUnknownDetail,
    };
    Ok(legacy_unscoped_artifact(
        "artifact", index, legacy_id, state,
    ))
}

fn legacy_identity<'a>(value: &'a Value, kind: &str) -> Result<&'a str, AppError> {
    let identity = value
        .get("artifactId")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::InvalidInput(format!("legacy {kind} is missing artifactId")))?;
    if identity.is_empty() || identity.chars().count() > MAX_SAFE_TEXT_CHARS {
        return Err(AppError::InvalidInput(format!(
            "legacy {kind} identity is empty or too long"
        )));
    }
    Ok(identity)
}

fn legacy_unscoped_artifact(
    domain: &str,
    index: usize,
    legacy_id: &str,
    state: SccmManifestSourceState,
) -> SccmManifestArtifact {
    let digest = sha256_bytes(format!("legacy:v1:{domain}:{index}:{legacy_id}").as_bytes());
    SccmManifestArtifact {
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
        coverage_scope: SccmManifestCoverageScope::Source,
        capture_limit_kind: None,
        bytes_copied: 0,
        limit_applied: None,
        content_sha256: None,
        fragment_complete: false,
        configmgr_version: None,
        collected_at_utc: None,
        encoding: None,
    }
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

fn canonical_basename(value: &str) -> String {
    cmtraceopen_parser::sccm::classify_artifact_name(value, SccmRole::Client)
        .basename
        .to_ascii_lowercase()
}

fn is_utc_rfc3339(value: &str) -> bool {
    value.len() <= 64
        && value.is_ascii()
        && DateTime::parse_from_rfc3339(value)
            .is_ok_and(|timestamp| timestamp.offset().local_minus_utc() == 0)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn native_intake_reader_assesses_the_projection_once() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().expect("temporary root");
        let bundle_root = temp.path().join("bundle");
        fs::create_dir(&bundle_root).expect("create bundle root");
        fs::set_permissions(&bundle_root, fs::Permissions::from_mode(0o700))
            .expect("make bundle root private");
        let manifest = serde_json::json!({
            "sccmManifestVersion": 1,
            "diagnosticsSchemaVersion": 1,
            "sourceCatalogVersion": 1,
            "provenance": "nativeClientCapture",
            "provenanceProfile": "hmacSha256V1",
            "collectedAtUtc": "2026-07-30T15:00:00Z",
            "maxFilesPerSource": 8,
            "maxBytesPerSource": 4096,
            "artifacts": [],
            "captureGaps": []
        });
        fs::write(
            bundle_root.join(SCCM_MANIFEST_FILE_NAME),
            serde_json::to_vec(&manifest).expect("serialize native manifest"),
        )
        .expect("write native manifest");

        reset_intake_projection_count();
        let bundle = read_sccm_client_intake_bundle(&bundle_root).expect("read native intake");

        assert!(bundle.artifacts.is_empty());
        assert!(bundle.capture_gaps.is_empty());
        assert_eq!(intake_projection_count(), 1);
    }

    #[test]
    fn client_owned_physical_byte_budget_accepts_exact_ceilings_without_opening_evidence() {
        let mut total = 0;
        for _ in 0..4 {
            add_to_client_physical_byte_budget(MAX_SCCM_CLIENT_PHYSICAL_ARTIFACT_BYTES, &mut total)
                .expect("the exact reader-owned ceilings are admitted before any file is opened");
        }
        assert_eq!(total, MAX_SCCM_CLIENT_TOTAL_PHYSICAL_BYTES);

        let error = add_to_client_physical_byte_budget(1, &mut total)
            .expect_err("one byte beyond the aggregate ceiling is rejected before a file open");
        assert!(error.to_string().contains("aggregate physical byte cap"));
    }
}
