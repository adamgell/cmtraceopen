use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use cmtraceopen_parser::sccm::SCCM_DIAGNOSTICS_SCHEMA_VERSION;

use crate::sccm::contract::{
    catalog_entry_id, compare_manifest_artifacts, compare_manifest_capture_gaps,
    expected_bundle_group, expected_marker_artifact_id, expected_physical_artifact_id,
    logical_artifact_ids_for_basename, root_handle_digest, rotation_segment, sha256_bytes,
    source_identity_digest, SccmBundleManifestV1, SccmCaptureLimitKind, SccmManifestArtifact,
    SccmManifestCaptureGap, SccmManifestCoverageScope, SccmManifestProvenance,
    SccmManifestProvenanceProfile, SccmManifestSourceState, SCCM_CLIENT_SOURCE_CATALOG_VERSION,
    SCCM_MANIFEST_FILE_NAME, SCCM_MANIFEST_VERSION,
};
use crate::sccm::{read_sccm_client_intake_bundle, SccmRole, SccmRotation};

use super::{SccmCollectorError, MAX_BYTES_PER_SOURCE, MAX_FRAGMENTS_PER_SOURCE};

#[derive(Debug, Clone)]
pub(super) struct CapturedClientArtifact {
    pub root_handle: String,
    pub basename: String,
    pub rotation: SccmRotation,
    pub state: SccmManifestSourceState,
    pub relative_path: String,
    pub retained_bytes: u64,
    pub content_sha256: String,
    pub capped: bool,
}

#[derive(Debug, Clone)]
pub(super) struct ClientCoverageRecord {
    pub root_handle: String,
    pub basename: String,
    pub rotation: SccmRotation,
    pub state: SccmManifestSourceState,
    pub coverage_scope: SccmManifestCoverageScope,
    pub gap_limit: Option<SccmCaptureLimitKind>,
    pub source_bytes: u64,
}

pub(super) fn client_relative_path(
    root_handle: &str,
    basename: &str,
    rotation: &SccmRotation,
) -> String {
    let memberships = logical_artifact_ids_for_basename(basename);
    format!(
        "evidence/sccm/client/{}/{}/{}/{}",
        expected_bundle_group(&memberships),
        root_handle,
        rotation_segment(rotation),
        physical_basename(basename, rotation)
    )
}

fn physical_basename(basename: &str, rotation: &SccmRotation) -> String {
    match rotation {
        SccmRotation::Current => basename.to_owned(),
        SccmRotation::LoUnderscore => {
            format!("{}.lo_", basename.strip_suffix(".log").unwrap_or(basename))
        }
        SccmRotation::Numbered(number) => format!("{basename}.{number}"),
        SccmRotation::Timestamped(timestamp) => format!("{basename}.{timestamp}"),
        SccmRotation::Unknown(_) => basename.to_owned(),
    }
}

pub(super) fn write_and_validate_client_manifest(
    bundle_root: &Path,
    collected_at_utc: &str,
    configmgr_version: Option<&str>,
    mut captured: Vec<CapturedClientArtifact>,
    coverage: Vec<ClientCoverageRecord>,
) -> Result<(), SccmCollectorError> {
    let mut artifacts = captured
        .drain(..)
        .map(|captured| {
            let canonical_basename = captured.basename.clone();
            let source_digest = source_identity_digest(&captured.root_handle, &canonical_basename)
                .ok_or(SccmCollectorError::ManifestValidationFailed)?;
            let path_fingerprint = format!("sha256:{source_digest}");
            let lineage_digest = sha256_bytes(format!("lineage:v1:{source_digest}").as_bytes());
            let physical_name = physical_basename(&canonical_basename, &captured.rotation);
            Ok(SccmManifestArtifact {
                catalog_entry_id: catalog_entry_id(&canonical_basename),
                logical_artifact_ids: logical_artifact_ids_for_basename(&canonical_basename),
                artifact_id: expected_physical_artifact_id(
                    &path_fingerprint,
                    &captured.rotation,
                    &physical_name,
                ),
                role: SccmRole::Client,
                source_handle: Some(format!("cmtraceopen.source.sha256.v1:{source_digest}")),
                root_handle: Some(captured.root_handle),
                path_fingerprint: Some(path_fingerprint),
                rotation_lineage: Some(format!("cmtraceopen.lineage.sha256.v1:{lineage_digest}")),
                relative_path: Some(captured.relative_path),
                basename: physical_name,
                rotation: captured.rotation,
                state: captured.state,
                coverage_scope: SccmManifestCoverageScope::Source,
                capture_limit_kind: captured.capped.then_some(SccmCaptureLimitKind::Bytes),
                bytes_copied: captured.retained_bytes,
                limit_applied: captured.capped.then_some(captured.retained_bytes),
                content_sha256: Some(captured.content_sha256),
                fragment_complete: !captured.capped,
                configmgr_version: configmgr_version.map(str::to_owned),
                collected_at_utc: Some(collected_at_utc.to_owned()),
                encoding: Some("utf-8".to_owned()),
            })
        })
        .collect::<Result<Vec<_>, SccmCollectorError>>()?;
    let mut capture_gaps = Vec::new();
    for record in coverage {
        let canonical_basename = record.basename.clone();
        let physical_name = physical_basename(&canonical_basename, &record.rotation);
        let source_digest = if record.coverage_scope == SccmManifestCoverageScope::RootEnumeration {
            let root_digest = root_handle_digest(&record.root_handle)
                .ok_or(SccmCollectorError::ManifestValidationFailed)?;
            sha256_bytes(
                format!(
                    "cmtraceopen.sccm.root-enumeration.v1\0{root_digest}\0{canonical_basename}"
                )
                .as_bytes(),
            )
        } else {
            source_identity_digest(&record.root_handle, &canonical_basename)
                .ok_or(SccmCollectorError::ManifestValidationFailed)?
        };
        let source_handle = format!("cmtraceopen.source.sha256.v1:{source_digest}");
        let path_fingerprint = format!("sha256:{source_digest}");
        let lineage = format!(
            "cmtraceopen.lineage.sha256.v1:{}",
            sha256_bytes(format!("lineage:v1:{source_digest}").as_bytes())
        );
        let entry_id = catalog_entry_id(&canonical_basename);
        let logical_ids = logical_artifact_ids_for_basename(&canonical_basename);
        let artifact_id = expected_marker_artifact_id(
            &entry_id,
            record.state,
            &record.rotation,
            &physical_name,
            Some(&path_fingerprint),
        );
        if let Some(capture_limit_kind) = record.gap_limit {
            capture_gaps.push(SccmManifestCaptureGap {
                artifact_id,
                catalog_entry_id: entry_id,
                logical_artifact_ids: logical_ids,
                source_handle,
                root_handle: record.root_handle,
                path_fingerprint,
                rotation_lineage: lineage,
                basename: physical_name,
                rotation: record.rotation,
                state: record.state,
                capture_limit_kind,
                source_bytes: record.source_bytes,
                bytes_retained: 0,
            });
        } else {
            artifacts.push(SccmManifestArtifact {
                catalog_entry_id: entry_id,
                logical_artifact_ids: logical_ids,
                artifact_id,
                role: SccmRole::Client,
                source_handle: Some(source_handle),
                root_handle: Some(record.root_handle),
                path_fingerprint: Some(path_fingerprint),
                rotation_lineage: Some(lineage),
                relative_path: None,
                basename: physical_name,
                rotation: record.rotation,
                state: record.state,
                coverage_scope: record.coverage_scope,
                capture_limit_kind: None,
                bytes_copied: 0,
                limit_applied: None,
                content_sha256: None,
                fragment_complete: false,
                configmgr_version: configmgr_version.map(str::to_owned),
                collected_at_utc: Some(collected_at_utc.to_owned()),
                encoding: None,
            });
        }
    }
    artifacts.sort_by(compare_manifest_artifacts);
    capture_gaps.sort_by(compare_manifest_capture_gaps);

    let manifest = SccmBundleManifestV1 {
        sccm_manifest_version: SCCM_MANIFEST_VERSION,
        diagnostics_schema_version: SCCM_DIAGNOSTICS_SCHEMA_VERSION,
        source_catalog_version: SCCM_CLIENT_SOURCE_CATALOG_VERSION,
        provenance: SccmManifestProvenance::NativeClientCapture,
        provenance_profile: SccmManifestProvenanceProfile::HmacSha256V1,
        host_handle: None,
        collected_at_utc: Some(collected_at_utc.to_owned()),
        max_files_per_source: MAX_FRAGMENTS_PER_SOURCE,
        max_bytes_per_source: MAX_BYTES_PER_SOURCE,
        artifacts,
        capture_gaps,
    };
    let bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|_| SccmCollectorError::ManifestValidationFailed)?;
    let path = bundle_root.join(SCCM_MANIFEST_FILE_NAME);
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| SccmCollectorError::DestinationUnavailable)?;
    output
        .write_all(&bytes)
        .map_err(|_| SccmCollectorError::CaptureFailed)?;
    output
        .sync_all()
        .map_err(|_| SccmCollectorError::CaptureFailed)?;
    read_sccm_client_intake_bundle(bundle_root)
        .map_err(|_| SccmCollectorError::ManifestValidationFailed)?;
    Ok(())
}
