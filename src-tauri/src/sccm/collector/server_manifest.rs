use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use cmtraceopen_parser::sccm::server::windows::{
    normalize_server_bundle, SccmServerArtifactPayload,
};
use cmtraceopen_parser::sccm::{SccmRole, SccmRotation};
use serde_json::{json, Value};

use crate::sccm::contract::sha256_bytes;

use super::{role_key, SccmCollectorError, MAX_BYTES_PER_SOURCE};

pub const SCCM_SERVER_MANIFEST_FILE_NAME: &str = "sccm-server-manifest.json";

#[derive(Debug, Clone)]
pub(super) struct CapturedServerArtifact {
    pub role: SccmRole,
    pub workflow_subject_role: Option<SccmRole>,
    pub source_id: String,
    pub source_kind: &'static str,
    pub root_handle: String,
    pub basename: String,
    pub rotation: SccmRotation,
    pub relative_path: String,
    pub retained_bytes: u64,
    pub bytes: Vec<u8>,
    pub capped: bool,
}

#[derive(Debug, Clone)]
pub(super) struct ServerCoverageRecord {
    pub role: SccmRole,
    pub workflow_subject_role: Option<SccmRole>,
    pub source_id: String,
    pub source_kind: &'static str,
    pub root_handle: String,
    pub basename: String,
    pub rotation: SccmRotation,
    pub state: cmtraceopen_parser::sccm::SccmCoverageState,
}

pub(super) fn server_relative_path(
    role: &SccmRole,
    workflow_subject_role: Option<&SccmRole>,
    source_id: &str,
    root_handle: &str,
    basename: &str,
    rotation: &SccmRotation,
) -> Result<String, SccmCollectorError> {
    let producer_segment = role_segment(role).ok_or(SccmCollectorError::CaptureFailed)?;
    let subject = workflow_subject_role
        .and_then(role_segment)
        .map(|role| format!("/subject-{role}"))
        .unwrap_or_default();
    Ok(format!(
        "evidence/sccm/server/{producer_segment}/{source_id}{subject}/{root_handle}/{}/{}",
        rotation_segment(rotation),
        basename
    ))
}

pub(super) fn write_and_validate_server_manifest(
    bundle_root: &Path,
    collected_at_utc: &str,
    roles: &[SccmRole],
    private_host: Option<&str>,
    private_site_code: Option<&str>,
    captured: Vec<CapturedServerArtifact>,
    coverage: Vec<ServerCoverageRecord>,
) -> Result<(), SccmCollectorError> {
    if roles.is_empty() {
        return Ok(());
    }
    let host_digest = sha256_bytes(private_host.unwrap_or("unavailable").as_bytes());
    let site_digest = sha256_bytes(private_site_code.unwrap_or("unavailable").as_bytes());
    let host_handle = format!("cmtraceopen.host.sha256.v1:{host_digest}");

    let mut artifacts = Vec::with_capacity(captured.len());
    let mut payloads = Vec::with_capacity(captured.len());
    for artifact in captured {
        let identity = format!(
            "{}\0{}\0{}\0{}\0{}",
            role_key(&artifact.role),
            artifact.source_id,
            artifact.root_handle,
            artifact.basename,
            rotation_segment(&artifact.rotation)
        );
        let identity_digest = sha256_bytes(identity.as_bytes());
        let artifact_id = format!("cmtraceopen.artifact.sha256.v1:{identity_digest}");
        let source_identity = format!(
            "{}\0{}\0{}",
            role_key(&artifact.role),
            artifact.source_id,
            artifact.root_handle
        );
        let lineage = format!(
            "cmtraceopen.lineage.sha256.v1:{}",
            sha256_bytes(format!("lineage\0{source_identity}").as_bytes())
        );
        let path_fingerprint = format!(
            "cmtraceopen.path.sha256.v1:{}",
            sha256_bytes(format!("path\0{source_identity}").as_bytes())
        );
        let rotation = rotation_json(&artifact.rotation);
        let requires_instance = artifact.role == SccmRole::WsUs;
        let workflow_subject = artifact.workflow_subject_role.as_ref().map(|role| {
            json!({
                "role": role,
                "instanceHandle": requires_instance.then(|| format!(
                    "cmtraceopen.subject.sha256.v1:{}",
                    sha256_bytes(identity.as_bytes())
                )),
                "basis": Value::Null
            })
        });
        let row = json!({
            "artifactId": artifact_id,
            "producerRole": artifact.role,
            "producerHostHandle": host_handle,
            "workflowSubject": workflow_subject,
            "sourceId": artifact.source_id,
            "sourceKind": artifact.source_kind,
            "sourceVersion": if requires_instance { json!("5.00.0001.0001") } else { Value::Null },
            "originalPath": "REDACTED",
            "originalBasename": artifact.basename,
            "configuredPathProvenance": {
                "state": "configured",
                "pathClass": Value::Null,
                "pathFingerprint": path_fingerprint
            },
            "defaultCandidateState": Value::Null,
            "rotation": {
                "kind": rotation.0,
                "value": rotation.1,
                "lineageId": lineage
            },
            "captureState": if artifact.capped { "capped" } else { "captured" },
            "collectionDetail": Value::Null,
            "skipReason": Value::Null,
            "unsupportedReason": Value::Null,
            "encoding": "unknown",
            "collectionLimit": {
                "byteLimit": if artifact.capped { artifact.retained_bytes } else { MAX_BYTES_PER_SOURCE },
                "limitApplied": artifact.capped
            },
            "truncated": if artifact.capped { Some(true) } else { None },
            "fragmentComplete": if artifact.capped { Some(false) } else { None },
            "collectedUtc": collected_at_utc,
            "relativePath": artifact.relative_path,
            "bytesCopied": artifact.retained_bytes
        });
        payloads.push(SccmServerArtifactPayload {
            manifest_artifact_id: artifact_id,
            bytes: artifact.bytes,
        });
        artifacts.push(row);
    }
    for record in coverage {
        let identity = format!(
            "coverage\0{}\0{}\0{}\0{}\0{}\0{:?}",
            role_key(&record.role),
            record.source_id,
            record.root_handle,
            record.basename,
            rotation_segment(&record.rotation),
            record.state
        );
        let artifact_id = format!(
            "cmtraceopen.artifact.sha256.v1:{}",
            sha256_bytes(identity.as_bytes())
        );
        let source_identity = format!(
            "{}\0{}\0{}",
            role_key(&record.role),
            record.source_id,
            record.root_handle
        );
        let lineage = format!(
            "cmtraceopen.lineage.sha256.v1:{}",
            sha256_bytes(format!("lineage\0{source_identity}").as_bytes())
        );
        let path_fingerprint = format!(
            "cmtraceopen.path.sha256.v1:{}",
            sha256_bytes(format!("path\0{source_identity}").as_bytes())
        );
        let rotation = rotation_json(&record.rotation);
        let requires_instance = record.role == SccmRole::WsUs;
        let workflow_subject = record.workflow_subject_role.as_ref().map(|role| {
            json!({
                "role": role,
                "instanceHandle": requires_instance.then(|| format!(
                    "cmtraceopen.subject.sha256.v1:{}",
                    sha256_bytes(identity.as_bytes())
                )),
                "basis": Value::Null
            })
        });
        let detail = format!(
            "cmtraceopen.collection-detail.sha256.v1:{}",
            sha256_bytes(format!("detail\0{identity}").as_bytes())
        );
        let skip = format!(
            "cmtraceopen.skip-reason.sha256.v1:{}",
            sha256_bytes(format!("skip\0{identity}").as_bytes())
        );
        let unsupported = format!(
            "cmtraceopen.unsupported-reason.sha256.v1:{}",
            sha256_bytes(format!("unsupported\0{identity}").as_bytes())
        );
        artifacts.push(json!({
            "artifactId": artifact_id,
            "producerRole": record.role,
            "producerHostHandle": host_handle,
            "workflowSubject": workflow_subject,
            "sourceId": record.source_id,
            "sourceKind": record.source_kind,
            "sourceVersion": if requires_instance { json!("5.00.0001.0001") } else { Value::Null },
            "originalPath": "REDACTED",
            "originalBasename": record.basename,
            "configuredPathProvenance": {
                "state": "configured",
                "pathClass": Value::Null,
                "pathFingerprint": path_fingerprint
            },
            "defaultCandidateState": Value::Null,
            "rotation": {
                "kind": rotation.0,
                "value": rotation.1,
                "lineageId": lineage
            },
            "captureState": record.state,
            "collectionDetail": (record.state == cmtraceopen_parser::sccm::SccmCoverageState::AccessDenied).then_some(detail),
            "skipReason": (record.state == cmtraceopen_parser::sccm::SccmCoverageState::Skipped).then_some(skip),
            "unsupportedReason": (record.state == cmtraceopen_parser::sccm::SccmCoverageState::Unsupported).then_some(unsupported),
            "encoding": Value::Null,
            "collectionLimit": Value::Null,
            "truncated": Value::Null,
            "fragmentComplete": Value::Null,
            "collectedUtc": collected_at_utc,
            "relativePath": Value::Null,
            "bytesCopied": 0
        }));
    }
    artifacts.sort_by(|left, right| {
        left["artifactId"]
            .as_str()
            .cmp(&right["artifactId"].as_str())
    });
    let manifest = json!({
        "sccmManifestVersion": 1,
        "syntheticFixture": false,
        "proposalOnly": Value::Null,
        "privacy": { "synthetic": false, "rawPaths": "redacted" },
        "bundleRole": "server",
        "topology": {
            "captureHost": host_handle,
            "siteCode": format!("cmtraceopen.site.sha256.v1:{site_digest}"),
            "rolesObserved": roles,
            "hierarchyLinks": []
        },
        "inputOrderIsDeliberatelyUnsorted": Value::Null,
        "artifacts": artifacts
    });
    let json = serde_json::to_string_pretty(&manifest)
        .map_err(|_| SccmCollectorError::ManifestValidationFailed)?;
    let path = bundle_root.join(SCCM_SERVER_MANIFEST_FILE_NAME);
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| SccmCollectorError::DestinationUnavailable)?;
    output
        .write_all(json.as_bytes())
        .map_err(|_| SccmCollectorError::CaptureFailed)?;
    output
        .sync_all()
        .map_err(|_| SccmCollectorError::CaptureFailed)?;
    normalize_server_bundle(&json, &payloads)
        .map_err(|_| SccmCollectorError::ManifestValidationFailed)?;
    Ok(())
}

fn role_segment(role: &SccmRole) -> Option<&'static str> {
    match role {
        SccmRole::SiteServer => Some("site-server"),
        SccmRole::ManagementPoint => Some("management-point"),
        SccmRole::DistributionPoint => Some("distribution-point"),
        SccmRole::SoftwareUpdatePoint => Some("software-update-point"),
        SccmRole::WsUs => Some("wsus"),
        SccmRole::Provider => Some("provider"),
        SccmRole::AdminService => Some("admin-service"),
        SccmRole::Client | SccmRole::Unknown(_) => None,
    }
}

fn rotation_segment(rotation: &SccmRotation) -> String {
    match rotation {
        SccmRotation::Current => "current".to_owned(),
        SccmRotation::LoUnderscore => "lo_".to_owned(),
        SccmRotation::Numbered(value) => format!("numbered-{value}"),
        SccmRotation::Timestamped(value) => format!("timestamped-{value}"),
        SccmRotation::Unknown(_) => "unknown".to_owned(),
    }
}

fn rotation_json(rotation: &SccmRotation) -> (&'static str, Value) {
    match rotation {
        SccmRotation::Current => ("current", Value::Null),
        SccmRotation::LoUnderscore => ("lo_", Value::Null),
        SccmRotation::Numbered(value) => ("numbered", json!(value)),
        SccmRotation::Timestamped(value) => ("timestamped", json!(value)),
        SccmRotation::Unknown(_) => ("none", Value::Null),
    }
}
