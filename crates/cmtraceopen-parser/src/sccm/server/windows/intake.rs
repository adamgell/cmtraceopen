use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::sccm::{
    normalize_ccm_artifact, SccmArtifact, SccmArtifactFamily, SccmArtifactRequest,
    SccmCoverageState, SccmEvidence, SccmFinding, SccmRole, SccmRotation,
};

use super::catalog::{classify_declared_server_source, expected_family, SccmServerSourceKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SccmServerArtifactPayload {
    pub manifest_artifact_id: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmServerIntakeAssessment {
    pub schema_version: u32,
    pub topology: SccmServerTopologyAssessment,
    pub artifacts: Vec<SccmServerArtifactAssessment>,
    pub coverage: Vec<SccmServerCoverage>,
    pub evidence: Vec<SccmEvidence>,
    pub findings: Vec<SccmFinding>,
    pub next_artifact_requests: Vec<SccmArtifactRequest>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmServerTopologyAssessment {
    pub capture_host_handle: String,
    pub site_handle: String,
    pub roles_observed: Vec<SccmRole>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmServerArtifactAssessment {
    pub artifact_id: String,
    pub producer_role: SccmRole,
    pub producer_host_handle: Option<String>,
    pub workflow_subject_role: Option<SccmRole>,
    pub workflow_subject_handle: Option<String>,
    pub source_id: String,
    pub family: SccmArtifactFamily,
    pub original_basename: Option<String>,
    pub rotation: Option<SccmRotation>,
    pub rotation_lineage_handle: String,
    pub state: SccmCoverageState,
    pub configured_path_state: SccmServerConfiguredPathState,
    pub configured_path_class: Option<SccmServerConfiguredPathClass>,
    pub path_fingerprint: String,
    pub source_version: Option<String>,
    pub profile_eligible: bool,
    pub collected_at_utc: String,
    pub relative_path: Option<String>,
    pub bytes_copied: u64,
    pub capture_provenance: Option<SccmServerCaptureProvenance>,
    pub parser_eligible: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmServerCaptureProvenance {
    pub schema_version: u32,
    pub encoding: String,
    pub byte_limit: u64,
    pub limit_applied: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmServerConfiguredPathState {
    Configured,
    DefaultCandidate,
    NotRequested,
    Supplied,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmServerConfiguredPathClass {
    NonDefault,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmServerCoverage {
    pub producer_role: SccmRole,
    pub workflow_subject_role: Option<SccmRole>,
    pub source_id: String,
    pub state: SccmCoverageState,
    pub artifact_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SccmServerIntakeError {
    #[error("server manifest is malformed")]
    MalformedManifest,
    #[error("server manifest version is unsupported")]
    UnsupportedManifestVersion,
    #[error("server manifest bundle role is invalid")]
    InvalidBundleRole,
    #[error("server manifest topology is invalid or unsafe")]
    InvalidTopology,
    #[error("server manifest artifact contract is invalid or unsafe")]
    InvalidArtifact,
    #[error("server manifest contains a duplicate artifact identity")]
    DuplicateArtifact,
    #[error("server artifact payload is missing")]
    MissingPayload,
    #[error("server artifact payload is unexpected")]
    UnexpectedPayload,
    #[error("server artifact payload length does not match manifest provenance")]
    PayloadLengthMismatch,
    #[error("server artifact payload encoding is unsupported or malformed")]
    InvalidPayloadEncoding,
}

pub fn normalize_server_bundle(
    manifest_json: &str,
    payloads: &[SccmServerArtifactPayload],
) -> Result<SccmServerIntakeAssessment, SccmServerIntakeError> {
    assess_server_intake(manifest_json, payloads)
}

pub fn assess_server_intake(
    manifest_json: &str,
    payloads: &[SccmServerArtifactPayload],
) -> Result<SccmServerIntakeAssessment, SccmServerIntakeError> {
    let manifest: RawServerManifest = serde_json::from_str(manifest_json)
        .map_err(|_| SccmServerIntakeError::MalformedManifest)?;
    if manifest.sccm_manifest_version != 1 {
        return Err(SccmServerIntakeError::UnsupportedManifestVersion);
    }
    if manifest.bundle_role != "server" {
        return Err(SccmServerIntakeError::InvalidBundleRole);
    }

    let topology = normalize_topology(&manifest)?;
    let mut payload_by_id = BTreeMap::new();
    for payload in payloads {
        if !safe_manifest_artifact_id(&payload.manifest_artifact_id, manifest.synthetic_fixture)
            || payload_by_id
                .insert(
                    payload.manifest_artifact_id.as_str(),
                    payload.bytes.as_slice(),
                )
                .is_some()
        {
            return Err(SccmServerIntakeError::UnexpectedPayload);
        }
    }

    let mut manifest_artifact_ids = BTreeSet::new();
    let mut relative_paths = BTreeSet::new();
    let mut path_fingerprint_lineages = BTreeMap::new();
    let mut prepared = Vec::with_capacity(manifest.artifacts.len());
    for artifact in manifest.artifacts {
        if !manifest_artifact_ids.insert(artifact.artifact_id.clone()) {
            return Err(SccmServerIntakeError::DuplicateArtifact);
        }
        let normalized = normalize_artifact(
            artifact,
            manifest.synthetic_fixture,
            &topology.roles_observed,
            &mut relative_paths,
            &mut path_fingerprint_lineages,
            &payload_by_id,
        )?;
        prepared.push(normalized);
    }

    if payload_by_id
        .keys()
        .any(|artifact_id| !manifest_artifact_ids.contains(*artifact_id))
    {
        return Err(SccmServerIntakeError::UnexpectedPayload);
    }

    prepared.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));

    let mut artifacts = Vec::with_capacity(prepared.len());
    let mut evidence = Vec::new();
    let mut coverage_by_key: BTreeMap<(String, String, String, String), SccmServerCoverage> =
        BTreeMap::new();
    let mut request_keys = BTreeSet::new();
    let mut next_artifact_requests = Vec::new();
    let usable_source_keys = prepared
        .iter()
        .filter(|prepared_artifact| {
            prepared_artifact.assessment.state == SccmCoverageState::Captured
        })
        .map(|prepared_artifact| logical_source_key(&prepared_artifact.assessment))
        .collect::<BTreeSet<_>>();

    for prepared_artifact in prepared {
        let artifact = prepared_artifact.assessment;
        let coverage_key = (
            role_sort_key(&artifact.producer_role).to_owned(),
            artifact.source_id.clone(),
            artifact
                .workflow_subject_role
                .as_ref()
                .map(role_sort_key)
                .unwrap_or_default()
                .to_owned(),
            coverage_sort_key(&artifact.state).to_owned(),
        );
        coverage_by_key
            .entry(coverage_key)
            .and_modify(|row| row.artifact_ids.push(artifact.artifact_id.clone()))
            .or_insert_with(|| SccmServerCoverage {
                producer_role: artifact.producer_role.clone(),
                workflow_subject_role: artifact.workflow_subject_role.clone(),
                source_id: artifact.source_id.clone(),
                state: artifact.state.clone(),
                artifact_ids: vec![artifact.artifact_id.clone()],
            });

        let usable_compatible_candidate =
            usable_source_keys.contains(&logical_source_key(&artifact));
        if let Some(request) = request_for_gap(&artifact, usable_compatible_candidate) {
            let request_key = (
                request.logical_id.clone(),
                role_sort_key(&request.role).to_owned(),
                request.reason.clone(),
            );
            if request_keys.insert(request_key) {
                next_artifact_requests.push(request);
            }
        }

        evidence.extend(prepared_artifact.evidence);
        artifacts.push(artifact);
    }

    let mut coverage = coverage_by_key.into_values().collect::<Vec<_>>();
    for row in &mut coverage {
        row.artifact_ids.sort();
    }
    evidence.sort_by(|left, right| {
        (
            left.reference.artifact_id.as_str(),
            left.reference.line_start,
            left.reference.line_end,
            left.reference.entry_id.as_str(),
        )
            .cmp(&(
                right.reference.artifact_id.as_str(),
                right.reference.line_start,
                right.reference.line_end,
                right.reference.entry_id.as_str(),
            ))
    });
    next_artifact_requests.sort_by(|left, right| {
        (
            left.logical_id.as_str(),
            role_sort_key(&left.role),
            left.reason.as_str(),
        )
            .cmp(&(
                right.logical_id.as_str(),
                role_sort_key(&right.role),
                right.reason.as_str(),
            ))
    });

    Ok(SccmServerIntakeAssessment {
        schema_version: 1,
        topology,
        artifacts,
        coverage,
        evidence,
        findings: Vec::new(),
        next_artifact_requests,
    })
}

struct PreparedArtifact {
    assessment: SccmServerArtifactAssessment,
    evidence: Vec<SccmEvidence>,
}

impl PreparedArtifact {
    fn sort_key(&self) -> (&str, &str, &str, String, &str, &str) {
        (
            role_sort_key(&self.assessment.producer_role),
            self.assessment.source_id.as_str(),
            self.assessment.path_fingerprint.as_str(),
            rotation_sort_key(self.assessment.rotation.as_ref()),
            self.assessment
                .original_basename
                .as_deref()
                .unwrap_or_default(),
            self.assessment.artifact_id.as_str(),
        )
    }
}

fn normalize_topology(
    manifest: &RawServerManifest,
) -> Result<SccmServerTopologyAssessment, SccmServerIntakeError> {
    let site_handle = if manifest.synthetic_fixture {
        // Manifest v1 synthetic fixtures use a closed, committed topology vocabulary.
        // Expanding it requires an explicit fixture/profile review, not a caller-chosen label.
        if manifest.topology.site_code != "LAB"
            || !matches!(
                manifest.topology.capture_host.as_str(),
                "LAB-CM01" | "LAB-MP01"
            )
        {
            return Err(SccmServerIntakeError::InvalidTopology);
        }
        "synthetic:site:lab".to_owned()
    } else if opaque_sha256_handle(&manifest.topology.site_code, "cmtraceopen.site.sha256.v1:") {
        manifest.topology.site_code.clone()
    } else {
        return Err(SccmServerIntakeError::InvalidTopology);
    };

    let capture_host_handle = if manifest.synthetic_fixture {
        format!(
            "synthetic:host:{}",
            manifest.topology.capture_host.to_ascii_lowercase()
        )
    } else if opaque_sha256_handle(
        &manifest.topology.capture_host,
        "cmtraceopen.host.sha256.v1:",
    ) {
        manifest.topology.capture_host.clone()
    } else {
        return Err(SccmServerIntakeError::InvalidTopology);
    };

    if manifest.topology.roles_observed.is_empty()
        || manifest
            .topology
            .roles_observed
            .iter()
            .any(|role| !is_declared_server_role(role))
    {
        return Err(SccmServerIntakeError::InvalidTopology);
    }
    let mut roles_observed = manifest.topology.roles_observed.clone();
    roles_observed.sort_by_key(|role| role_sort_key(role).to_owned());
    if roles_observed.windows(2).any(|roles| roles[0] == roles[1]) {
        return Err(SccmServerIntakeError::InvalidTopology);
    }

    Ok(SccmServerTopologyAssessment {
        capture_host_handle,
        site_handle,
        roles_observed,
    })
}

fn normalize_artifact(
    artifact: RawServerArtifact,
    synthetic_fixture: bool,
    roles_observed: &[SccmRole],
    relative_paths: &mut BTreeSet<String>,
    path_fingerprint_lineages: &mut BTreeMap<(String, String, String, String), String>,
    payload_by_id: &BTreeMap<&str, &[u8]>,
) -> Result<PreparedArtifact, SccmServerIntakeError> {
    let source_version =
        normalize_source_version(artifact.source_version.as_deref(), synthetic_fixture)?;
    if !safe_manifest_artifact_id(&artifact.artifact_id, synthetic_fixture)
        || !safe_source_id(&artifact.source_id)
        || !safe_lineage_id(&artifact.rotation.lineage_id, synthetic_fixture)
        || !safe_path_fingerprint(
            &artifact.configured_path_provenance.path_fingerprint,
            synthetic_fixture,
        )
        || !safe_original_path_marker(&artifact.original_path, synthetic_fixture)
        || !safe_optional_handle(
            artifact.producer_host_handle.as_deref(),
            synthetic_fixture,
            "host",
        )
        || !safe_optional_handle(
            artifact
                .workflow_subject
                .as_ref()
                .and_then(|subject| subject.instance_handle.as_deref()),
            synthetic_fixture,
            "subject",
        )
    {
        return Err(SccmServerIntakeError::InvalidArtifact);
    }

    let producer_is_observed = roles_observed.contains(&artifact.producer_role);
    let unsupported_unknown = artifact.capture_state == SccmCoverageState::Unsupported
        && artifact.producer_role == SccmRole::Unknown("unclassified".to_owned());
    if (!producer_is_observed && !unsupported_unknown)
        || (producer_is_observed && !is_declared_server_role(&artifact.producer_role))
    {
        return Err(SccmServerIntakeError::InvalidArtifact);
    }
    if artifact
        .workflow_subject
        .as_ref()
        .is_some_and(|subject| !is_declared_server_role(&subject.role))
    {
        return Err(SccmServerIntakeError::InvalidArtifact);
    }

    let workflow_subject_role = artifact
        .workflow_subject
        .as_ref()
        .map(|subject| subject.role.clone());
    let classification = classify_declared_server_source(
        &artifact.source_id,
        &artifact.producer_role,
        workflow_subject_role.as_ref(),
        &artifact.source_kind,
        &artifact.original_basename,
    );

    let (family, original_basename, rotation, parser_eligible) =
        if let Some((spec, classified)) = classification {
            let family =
                expected_family(spec.source_id).ok_or(SccmServerIntakeError::InvalidArtifact)?;
            if let Some(classified) = classified {
                let declared_rotation = parse_declared_rotation(&artifact.rotation)?;
                if declared_rotation.as_ref() != Some(&classified.rotation)
                    || classified.family != family
                    || spec.source_kind != SccmServerSourceKind::CcmLog
                {
                    return Err(SccmServerIntakeError::InvalidArtifact);
                }
                (
                    family,
                    Some(artifact.original_basename.clone()),
                    declared_rotation,
                    true,
                )
            } else {
                (family, None, None, false)
            }
        } else if unsupported_unknown {
            (
                SccmArtifactFamily::Unknown("unsupported".to_owned()),
                None,
                None,
                false,
            )
        } else {
            return Err(SccmServerIntakeError::InvalidArtifact);
        };

    let path_fingerprint_key = (
        role_sort_key(&artifact.producer_role).to_owned(),
        artifact.source_id.clone(),
        workflow_subject_role
            .as_ref()
            .map(role_sort_key)
            .unwrap_or_default()
            .to_owned(),
        artifact
            .configured_path_provenance
            .path_fingerprint
            .to_ascii_lowercase(),
    );
    match path_fingerprint_lineages.get(&path_fingerprint_key) {
        Some(lineage) if lineage != &artifact.rotation.lineage_id => {
            return Err(SccmServerIntakeError::DuplicateArtifact);
        }
        Some(_) => {}
        None => {
            path_fingerprint_lineages
                .insert(path_fingerprint_key, artifact.rotation.lineage_id.clone());
        }
    }

    let configured_path_state =
        parse_configured_path_state(&artifact.configured_path_provenance.state)?;
    let configured_path_class = match artifact.configured_path_provenance.path_class.as_deref() {
        None => None,
        Some("nonDefault") => Some(SccmServerConfiguredPathClass::NonDefault),
        Some(_) => return Err(SccmServerIntakeError::InvalidArtifact),
    };
    let collected_at_utc = normalize_collected_utc(&artifact.collected_utc)?;
    let relative_path = validate_relative_path(
        artifact.relative_path.clone(),
        original_basename.as_deref(),
        &artifact,
        rotation.as_ref(),
        relative_paths,
    )?;
    let (bytes, capture_provenance) =
        validate_payload_contract(&artifact, relative_path.as_deref(), payload_by_id)?;
    let profile_eligible = source_version
        .as_deref()
        .is_some_and(|version| source_version_is_profile_eligible(version, synthetic_fixture));

    let mut evidence = Vec::new();
    let mut state = artifact.capture_state.clone();
    if artifact.capture_state == SccmCoverageState::Captured && parser_eligible {
        let bytes = bytes.ok_or(SccmServerIntakeError::MissingPayload)?;
        if artifact.encoding.as_deref() != Some("utf-8") {
            return Err(SccmServerIntakeError::InvalidPayloadEncoding);
        }
        let content = std::str::from_utf8(bytes)
            .map_err(|_| SccmServerIntakeError::InvalidPayloadEncoding)?;
        evidence = normalize_ccm_artifact(
            SccmArtifact {
                artifact_id: artifact.artifact_id.clone(),
                display_name: original_basename
                    .clone()
                    .ok_or(SccmServerIntakeError::InvalidArtifact)?,
                original_path: None,
                host: artifact.producer_host_handle.clone(),
                role: artifact.producer_role.clone(),
                configmgr_version: source_version.clone(),
                collected_at_utc: Some(collected_at_utc.clone()),
                rotation: rotation
                    .clone()
                    .ok_or(SccmServerIntakeError::InvalidArtifact)?,
                coverage: artifact.capture_state.clone(),
                encoding: artifact.encoding.clone(),
            },
            content,
        );
        if evidence.is_empty() {
            state = SccmCoverageState::ParseFailed;
        }
    }

    Ok(PreparedArtifact {
        assessment: SccmServerArtifactAssessment {
            artifact_id: artifact.artifact_id,
            producer_role: artifact.producer_role,
            producer_host_handle: artifact.producer_host_handle,
            workflow_subject_role,
            workflow_subject_handle: artifact
                .workflow_subject
                .and_then(|subject| subject.instance_handle),
            source_id: if unsupported_unknown {
                "unsupported".to_owned()
            } else {
                artifact.source_id
            },
            family,
            original_basename,
            rotation,
            rotation_lineage_handle: artifact.rotation.lineage_id,
            state,
            configured_path_state,
            configured_path_class,
            path_fingerprint: artifact.configured_path_provenance.path_fingerprint,
            source_version,
            profile_eligible,
            collected_at_utc,
            relative_path,
            bytes_copied: artifact.bytes_copied,
            capture_provenance,
            parser_eligible,
        },
        evidence,
    })
}

fn validate_payload_contract<'a>(
    artifact: &RawServerArtifact,
    relative_path: Option<&str>,
    payload_by_id: &'a BTreeMap<&str, &'a [u8]>,
) -> Result<(Option<&'a [u8]>, Option<SccmServerCaptureProvenance>), SccmServerIntakeError> {
    let payload = payload_by_id.get(artifact.artifact_id.as_str()).copied();
    if is_physical_state(&artifact.capture_state) {
        let payload = payload.ok_or(SccmServerIntakeError::MissingPayload)?;
        if relative_path.is_none() {
            return Err(SccmServerIntakeError::InvalidArtifact);
        }
        if payload.len() as u64 != artifact.bytes_copied {
            return Err(SccmServerIntakeError::PayloadLengthMismatch);
        }
        let limit = artifact
            .collection_limit
            .as_ref()
            .ok_or(SccmServerIntakeError::InvalidArtifact)?;
        let valid_limit = match artifact.capture_state {
            SccmCoverageState::Captured => {
                !limit.limit_applied && artifact.bytes_copied <= limit.byte_limit
            }
            SccmCoverageState::Capped => {
                limit.limit_applied
                    && artifact.bytes_copied == limit.byte_limit
                    && artifact.bytes_copied > 0
            }
            SccmCoverageState::ParseFailed => {
                if limit.limit_applied {
                    artifact.bytes_copied == limit.byte_limit && artifact.bytes_copied > 0
                } else {
                    artifact.bytes_copied <= limit.byte_limit
                }
            }
            _ => false,
        };
        let encoding = artifact
            .encoding
            .as_deref()
            .filter(|encoding| safe_encoding(encoding))
            .ok_or(SccmServerIntakeError::InvalidArtifact)?;
        if !valid_limit || limit.byte_limit == 0 {
            return Err(SccmServerIntakeError::InvalidArtifact);
        }
        return Ok((
            Some(payload),
            Some(SccmServerCaptureProvenance {
                schema_version: 1,
                encoding: encoding.to_owned(),
                byte_limit: limit.byte_limit,
                limit_applied: limit.limit_applied,
            }),
        ));
    }

    if payload.is_some()
        || relative_path.is_some()
        || artifact.bytes_copied != 0
        || artifact.encoding.is_some()
        || artifact.collection_limit.is_some()
    {
        return Err(SccmServerIntakeError::UnexpectedPayload);
    }
    Ok((None, None))
}

fn validate_relative_path(
    relative_path: Option<String>,
    original_basename: Option<&str>,
    artifact: &RawServerArtifact,
    rotation: Option<&SccmRotation>,
    relative_paths: &mut BTreeSet<String>,
) -> Result<Option<String>, SccmServerIntakeError> {
    if !is_physical_state(&artifact.capture_state) {
        if relative_path.is_some() {
            return Err(SccmServerIntakeError::InvalidArtifact);
        }
        return Ok(None);
    }
    let relative_path = relative_path.ok_or(SccmServerIntakeError::InvalidArtifact)?;
    let components = relative_path.split('/').collect::<Vec<_>>();
    let expected_role =
        role_path_segment(&artifact.producer_role).ok_or(SccmServerIntakeError::InvalidArtifact)?;
    let expected_rotation =
        rotation_path_segment(rotation).ok_or(SccmServerIntakeError::InvalidArtifact)?;
    let basename = original_basename.ok_or(SccmServerIntakeError::InvalidArtifact)?;
    let mut cursor = 0;
    let fixed_prefix = [
        "evidence",
        "sccm",
        "server",
        expected_role,
        artifact.source_id.as_str(),
    ];
    if components.get(..fixed_prefix.len()) != Some(fixed_prefix.as_slice()) {
        return Err(SccmServerIntakeError::InvalidArtifact);
    }
    cursor += fixed_prefix.len();

    if let Some(subject_role) = artifact
        .workflow_subject
        .as_ref()
        .map(|subject| &subject.role)
    {
        let subject_segment = role_path_segment(subject_role)
            .map(|role| format!("subject-{role}"))
            .ok_or(SccmServerIntakeError::InvalidArtifact)?;
        if components.get(cursor).copied() != Some(subject_segment.as_str()) {
            return Err(SccmServerIntakeError::InvalidArtifact);
        }
        cursor += 1;
    }
    if artifact.workflow_subject.is_some()
        && components
            .get(cursor)
            .is_some_and(|component| opaque_path_component(component, "instance-"))
    {
        cursor += 1;
    }
    if components
        .get(cursor)
        .is_some_and(|component| opaque_path_component(component, "root-"))
    {
        cursor += 1;
    }

    if components.get(cursor).copied() != Some(expected_rotation.as_str())
        || components.get(cursor + 1).copied() != Some(basename)
        || components.len() != cursor + 2
        || relative_path.contains('\\')
        || relative_path.split('/').any(|segment| {
            segment.is_empty()
                || segment == "."
                || segment == ".."
                || !segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
        || !relative_paths.insert(relative_path.to_ascii_lowercase())
    {
        return Err(SccmServerIntakeError::InvalidArtifact);
    }
    Ok(Some(relative_path))
}

fn is_physical_state(state: &SccmCoverageState) -> bool {
    matches!(
        state,
        SccmCoverageState::Captured | SccmCoverageState::Capped | SccmCoverageState::ParseFailed
    )
}

fn safe_encoding(encoding: &str) -> bool {
    matches!(encoding, "utf-8" | "utf-16le" | "windows-1252" | "unknown")
}

fn role_path_segment(role: &SccmRole) -> Option<&'static str> {
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

fn rotation_path_segment(rotation: Option<&SccmRotation>) -> Option<String> {
    Some(match rotation? {
        SccmRotation::Current => "current".to_owned(),
        SccmRotation::LoUnderscore => "lo_".to_owned(),
        SccmRotation::Numbered(value) => format!("numbered-{value}"),
        SccmRotation::Timestamped(value) => format!("timestamped-{value}"),
        SccmRotation::Unknown(_) => return None,
    })
}

fn opaque_path_component(component: &str, prefix: &str) -> bool {
    component.strip_prefix(prefix).is_some_and(|value| {
        (8..=64).contains(&value.len())
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn parse_declared_rotation(
    rotation: &RawServerRotation,
) -> Result<Option<SccmRotation>, SccmServerIntakeError> {
    let parsed = match rotation.kind.as_str() {
        "current" if rotation.value.is_none() => SccmRotation::Current,
        "lo_" if rotation.value.is_none() => SccmRotation::LoUnderscore,
        "numbered" => {
            let number = rotation
                .value
                .as_ref()
                .and_then(Value::as_u64)
                .and_then(|value| u32::try_from(value).ok())
                .filter(|value| *value > 0)
                .ok_or(SccmServerIntakeError::InvalidArtifact)?;
            SccmRotation::Numbered(number)
        }
        "timestamped" => {
            let timestamp = rotation
                .value
                .as_ref()
                .and_then(Value::as_str)
                .ok_or(SccmServerIntakeError::InvalidArtifact)?;
            SccmRotation::Timestamped(timestamp.to_owned())
        }
        _ => return Ok(None),
    };
    Ok(Some(parsed))
}

fn parse_configured_path_state(
    value: &str,
) -> Result<SccmServerConfiguredPathState, SccmServerIntakeError> {
    match value {
        "configured" => Ok(SccmServerConfiguredPathState::Configured),
        "defaultCandidate" => Ok(SccmServerConfiguredPathState::DefaultCandidate),
        "notRequested" => Ok(SccmServerConfiguredPathState::NotRequested),
        "supplied" => Ok(SccmServerConfiguredPathState::Supplied),
        _ => Err(SccmServerIntakeError::InvalidArtifact),
    }
}

fn normalize_collected_utc(value: &str) -> Result<String, SccmServerIntakeError> {
    let parsed =
        DateTime::parse_from_rfc3339(value).map_err(|_| SccmServerIntakeError::InvalidArtifact)?;
    Ok(parsed
        .with_timezone(&Utc)
        .to_rfc3339_opts(SecondsFormat::Secs, true))
}

fn logical_source_key(artifact: &SccmServerArtifactAssessment) -> (String, String, String) {
    (
        role_sort_key(&artifact.producer_role).to_owned(),
        artifact.source_id.clone(),
        artifact
            .workflow_subject_role
            .as_ref()
            .map(role_sort_key)
            .unwrap_or_default()
            .to_owned(),
    )
}

fn request_for_gap(
    artifact: &SccmServerArtifactAssessment,
    usable_compatible_candidate: bool,
) -> Option<SccmArtifactRequest> {
    if artifact.state == SccmCoverageState::Absent
        && artifact.configured_path_state == SccmServerConfiguredPathState::DefaultCandidate
        && usable_compatible_candidate
    {
        return None;
    }
    let reason = match artifact.state {
        SccmCoverageState::Absent => "source was absent; role outcome remains unknown",
        SccmCoverageState::AccessDenied => "source access was denied; role outcome remains unknown",
        SccmCoverageState::Capped => "source was capped; terminal role evidence is incomplete",
        SccmCoverageState::ParseFailed => {
            "source parsing failed; terminal role evidence is unavailable"
        }
        _ => return None,
    };
    Some(SccmArtifactRequest {
        logical_id: artifact.source_id.clone(),
        role: artifact
            .workflow_subject_role
            .clone()
            .unwrap_or_else(|| artifact.producer_role.clone()),
        reason: reason.to_owned(),
    })
}

fn normalize_source_version(
    value: Option<&str>,
    synthetic_fixture: bool,
) -> Result<Option<String>, SccmServerIntakeError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let safe = if synthetic_fixture {
        value == "5.00.TEST"
    } else {
        source_version_is_profile_eligible(value, false)
            || opaque_sha256_handle(value, "cmtraceopen.version.sha256.v1:")
    };
    if !safe {
        return Err(SccmServerIntakeError::InvalidArtifact);
    }
    Ok(Some(value.to_owned()))
}

fn source_version_is_profile_eligible(value: &str, synthetic_fixture: bool) -> bool {
    if synthetic_fixture && value == "5.00.TEST" {
        return true;
    }
    let mut parts = value.split('.');
    matches!(
        (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ),
        (Some("5"), Some("00"), Some(build), Some(revision), None)
            if build.len() == 4
                && revision.len() == 4
                && build.bytes().all(|byte| byte.is_ascii_digit())
                && revision.bytes().all(|byte| byte.is_ascii_digit())
    )
}

fn safe_manifest_artifact_id(value: &str, synthetic_fixture: bool) -> bool {
    if synthetic_fixture {
        // The top-level manifest version gate makes this the v1 synthetic-fixture vocabulary.
        // These public identities must never become free-form based on the manifest flag alone.
        return matches!(
            value,
            "a-mp-policy"
                | "b-sitecomp"
                | "dp-dist-current"
                | "dp-distribution-absent-candidate"
                | "mp-iis-skipped"
                | "mp-policy-access-denied"
                | "mp-policy-configured"
                | "mp-policy-current"
                | "mp-policy-lo"
                | "mp-policy-multiline"
                | "mp-policy-numbered-2"
                | "mp-policy-root-a-current"
                | "mp-policy-root-b-current"
                | "mp-policy-ts-20260729-235700"
                | "sitecomp-current"
                | "sup-sync-capped"
                | "sup-sync-current"
                | "unknown-db-export"
                | "z-site-status"
        );
    }
    opaque_sha256_handle(value, "cmtraceopen.artifact.sha256.v1:")
}

fn safe_source_id(value: &str) -> bool {
    matches!(
        value,
        "server-sitecomp"
            | "server-status"
            | "server-mp-auth"
            | "server-mp-policy"
            | "server-mp-iis"
            | "server-dp-distribution"
            | "server-sup-sync"
            | "unknown-db-supplement"
    )
}

fn safe_lineage_id(value: &str, synthetic_fixture: bool) -> bool {
    if synthetic_fixture {
        return matches!(
            value,
            "dp-dist-lab"
                | "dp-distribution-default"
                | "mp-iis-supplement"
                | "mp-policy-a"
                | "mp-policy-access"
                | "mp-policy-configured"
                | "mp-policy-lab"
                | "mp-policy-multiline"
                | "mp-policy-root-a"
                | "mp-policy-root-b"
                | "mp-policy-rotation"
                | "site-status-z"
                | "sitecomp-a"
                | "sitecomp-lab"
                | "sup-sync-cap"
                | "sup-sync-lab"
                | "unknown-db-export"
        );
    }
    opaque_sha256_handle(value, "cmtraceopen.lineage.sha256.v1:")
}

fn safe_path_fingerprint(value: &str, synthetic_fixture: bool) -> bool {
    if synthetic_fixture {
        return matches!(
            value,
            "synthetic:path:a-mp"
                | "synthetic:path:a-site"
                | "synthetic:path:dp-default"
                | "synthetic:path:iis-not-requested"
                | "synthetic:path:mp-configured-a"
                | "synthetic:path:mp-default"
                | "synthetic:path:mp-root-a"
                | "synthetic:path:mp-root-b"
                | "synthetic:path:site-default"
                | "synthetic:path:site-dp-control"
                | "synthetic:path:site-sup-control"
                | "synthetic:path:unsupported-db"
                | "synthetic:path:z-site"
        );
    }
    opaque_sha256_handle(value, "cmtraceopen.path.sha256.v1:")
}

fn safe_original_path_marker(value: &str, synthetic_fixture: bool) -> bool {
    if synthetic_fixture {
        return value.starts_with("REDACTED_")
            && value.len() <= 96
            && value
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_');
    }
    !value.is_empty() && value.len() <= 1024 && !value.chars().any(char::is_control)
}

fn safe_optional_handle(value: Option<&str>, synthetic_fixture: bool, domain: &str) -> bool {
    let Some(value) = value else {
        return true;
    };
    if synthetic_fixture {
        return match domain {
            "host" => matches!(value, "synthetic:host:mp-01" | "synthetic:host:site-01"),
            "subject" => {
                matches!(
                    value,
                    "synthetic:subject:dp-01" | "synthetic:subject:sup-01"
                )
            }
            _ => false,
        };
    }
    opaque_sha256_handle(value, &format!("cmtraceopen.{domain}.sha256.v1:"))
}

fn opaque_sha256_handle(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn is_declared_server_role(role: &SccmRole) -> bool {
    matches!(
        role,
        SccmRole::SiteServer
            | SccmRole::ManagementPoint
            | SccmRole::DistributionPoint
            | SccmRole::SoftwareUpdatePoint
            | SccmRole::WsUs
            | SccmRole::Provider
            | SccmRole::AdminService
    )
}

fn role_sort_key(role: &SccmRole) -> &str {
    match role {
        SccmRole::Client => "client",
        SccmRole::SiteServer => "siteServer",
        SccmRole::ManagementPoint => "managementPoint",
        SccmRole::DistributionPoint => "distributionPoint",
        SccmRole::SoftwareUpdatePoint => "softwareUpdatePoint",
        SccmRole::WsUs => "wsUs",
        SccmRole::Provider => "provider",
        SccmRole::AdminService => "adminService",
        SccmRole::Unknown(value) => value,
    }
}

fn coverage_sort_key(state: &SccmCoverageState) -> &'static str {
    match state {
        SccmCoverageState::Captured => "captured",
        SccmCoverageState::Absent => "absent",
        SccmCoverageState::AccessDenied => "accessDenied",
        SccmCoverageState::Capped => "capped",
        SccmCoverageState::Skipped => "skipped",
        SccmCoverageState::Unsupported => "unsupported",
        SccmCoverageState::ParseFailed => "parseFailed",
    }
}

fn rotation_sort_key(rotation: Option<&SccmRotation>) -> String {
    match rotation {
        Some(SccmRotation::LoUnderscore) => "0-lo-underscore".to_owned(),
        Some(SccmRotation::Numbered(value)) => format!("1-numbered-{value:010}"),
        Some(SccmRotation::Timestamped(value)) => format!("2-timestamped-{value}"),
        Some(SccmRotation::Current) => "3-current".to_owned(),
        Some(SccmRotation::Unknown(_)) => "4-unknown".to_owned(),
        None => "5-not-applicable".to_owned(),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawServerManifest {
    sccm_manifest_version: u32,
    #[serde(default)]
    synthetic_fixture: bool,
    bundle_role: String,
    topology: RawServerTopology,
    artifacts: Vec<RawServerArtifact>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawServerTopology {
    capture_host: String,
    site_code: String,
    roles_observed: Vec<SccmRole>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawServerArtifact {
    artifact_id: String,
    producer_role: SccmRole,
    producer_host_handle: Option<String>,
    workflow_subject: Option<RawWorkflowSubject>,
    source_id: String,
    source_kind: String,
    source_version: Option<String>,
    original_path: String,
    original_basename: String,
    configured_path_provenance: RawConfiguredPathProvenance,
    rotation: RawServerRotation,
    capture_state: SccmCoverageState,
    encoding: Option<String>,
    collection_limit: Option<RawCollectionLimit>,
    collected_utc: String,
    relative_path: Option<String>,
    bytes_copied: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawWorkflowSubject {
    role: SccmRole,
    instance_handle: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawConfiguredPathProvenance {
    state: String,
    path_class: Option<String>,
    path_fingerprint: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawServerRotation {
    kind: String,
    value: Option<Value>,
    lineage_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawCollectionLimit {
    byte_limit: u64,
    limit_applied: bool,
}
