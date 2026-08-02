use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, Write};

use chrono::{DateTime, SecondsFormat, Utc};
use serde::de::{Error as _, MapAccess, SeqAccess, Visitor};
use serde::ser::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::sccm::rotation::is_canonical_rotation_timestamp;
use crate::sccm::{
    classify_artifact_name, normalize_ccm_artifact, SccmArtifact, SccmArtifactFamily,
    SccmArtifactRequest, SccmCoverageState, SccmEvidence, SccmFinding, SccmRole, SccmRotation,
};

use super::catalog::{classify_declared_server_source, expected_family, SccmServerSourceKind};

/// Keep parser-side work bounded even when the manifest did not come from the
/// native collector. These match the existing bounded bundle intake envelope.
pub const MAX_SCCM_SERVER_MANIFEST_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_SCCM_SERVER_MANIFEST_ARTIFACTS: usize = 512;
pub const MAX_SCCM_SERVER_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_SCCM_SERVER_TOTAL_DECLARED_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_SCCM_SERVER_OPAQUE_EXTENSIONS: usize = 32;
const MAX_SCCM_SERVER_OPAQUE_EXTENSION_BYTES_PER_SCOPE: usize = 8 * 1024;
const MAX_SCCM_SERVER_TOTAL_OPAQUE_EXTENSIONS: usize = 1_024;
const MAX_SCCM_SERVER_TOTAL_OPAQUE_EXTENSION_BYTES: usize = 256 * 1024;

type PathFingerprintKey = (
    String,
    Option<String>,
    String,
    String,
    Option<String>,
    String,
);
type CanonicalArtifactIdentity = (
    String,
    Option<String>,
    String,
    String,
    Option<String>,
    String,
    String,
    String,
    String,
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SccmServerArtifactPayload {
    pub manifest_artifact_id: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SccmServerIntakeAssessment {
    pub schema_version: u32,
    pub topology: SccmServerTopologyAssessment,
    pub artifacts: Vec<SccmServerArtifactAssessment>,
    pub coverage: Vec<SccmServerCoverage>,
    pub evidence: Vec<SccmEvidence>,
    pub findings: Vec<SccmFinding>,
    pub next_artifact_requests: Vec<SccmArtifactRequest>,
    /// Private integrity binding for the canonical projection that server-role
    /// reducers consume. It is sequence-independent, but every authoritative
    /// schema, topology, artifact, coverage, and evidence field remains bound
    /// to the assessment produced by intake.
    intake_integrity: SccmServerIntakeIntegrity,
    /// Versioned opaque manifest extensions retained without interpreting them.
    extensions: Vec<SccmServerOpaqueExtension>,
    privacy_extensions: Vec<SccmServerOpaqueExtension>,
}

/// A public, deterministic representation of a recognized opaque manifest extension.
///
/// Extension names use `x-cmtraceopen-opaque-v1-<token>` and values use
/// `cmtraceopen.extension.sha256.v1:<64 lowercase hexadecimal characters>`.
/// The parser retains this provenance but never interprets it as diagnostic input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SccmServerOpaqueExtension {
    schema_version: u32,
    name: String,
    value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SccmServerOpaqueExtensionError {
    #[error("unsupported opaque extension schema version {schema_version}")]
    UnsupportedSchemaVersion { schema_version: u32 },
    #[error("opaque extension name is invalid or unsafe")]
    InvalidName,
    #[error("opaque extension value is invalid or unsafe")]
    InvalidValue,
}

impl SccmServerOpaqueExtension {
    pub fn try_new(
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, SccmServerOpaqueExtensionError> {
        let extension = Self {
            schema_version: 1,
            name: name.into(),
            value: value.into(),
        };
        extension.validate()?;
        Ok(extension)
    }

    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    fn validate(&self) -> Result<(), SccmServerOpaqueExtensionError> {
        if self.schema_version != 1 {
            return Err(SccmServerOpaqueExtensionError::UnsupportedSchemaVersion {
                schema_version: self.schema_version,
            });
        }
        if !safe_opaque_extension_name(&self.name) {
            return Err(SccmServerOpaqueExtensionError::InvalidName);
        }
        if !opaque_sha256_handle(&self.value, "cmtraceopen.extension.sha256.v1:") {
            return Err(SccmServerOpaqueExtensionError::InvalidValue);
        }
        Ok(())
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SccmServerOpaqueExtensionSerializeWire<'a> {
    schema_version: u32,
    name: &'a str,
    value: &'a str,
}

impl Serialize for SccmServerOpaqueExtension {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.validate().map_err(S::Error::custom)?;
        SccmServerOpaqueExtensionSerializeWire {
            schema_version: self.schema_version,
            name: &self.name,
            value: &self.value,
        }
        .serialize(serializer)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SccmServerOpaqueExtensionDeserializeWire {
    schema_version: u32,
    name: String,
    value: String,
}

impl<'de> Deserialize<'de> for SccmServerOpaqueExtension {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SccmServerOpaqueExtensionDeserializeWire::deserialize(deserializer)?;
        let extension = Self {
            schema_version: wire.schema_version,
            name: wire.name,
            value: wire.value,
        };
        extension.validate().map_err(D::Error::custom)?;
        Ok(extension)
    }
}

impl SccmServerIntakeAssessment {
    pub fn extensions(&self) -> &[SccmServerOpaqueExtension] {
        &self.extensions
    }

    pub fn privacy_extensions(&self) -> &[SccmServerOpaqueExtension] {
        &self.privacy_extensions
    }

    pub(crate) fn adapter_authority_is_intake_bound(&self) -> bool {
        if self.schema_version != self.intake_integrity.schema_version
            || self.topology.roles_observed.len() != self.intake_integrity.topology_role_count
            || self.artifacts.len() != self.intake_integrity.artifacts.len()
            || self.coverage.len() != self.intake_integrity.coverage.len()
            || self.evidence.len() != self.intake_integrity.evidence.len()
        {
            return false;
        }
        canonical_intake_integrity_for_adapter(
            self.schema_version,
            &self.topology,
            &self.artifacts,
            &self.coverage,
            &self.evidence,
            &self.intake_integrity,
        )
        .as_ref()
        .is_some_and(|integrity| integrity == &self.intake_integrity)
    }
}

/// Nonserialized canonical-input binding for downstream server-role adapters.
/// Collection order is not authority: the normalized records are serialized
/// independently and compared as duplicate-free sets.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SccmServerIntakeIntegrity {
    schema_version: u32,
    topology_role_count: usize,
    structure: IntakeIntegrityStructure,
    topology: IntakeIntegrityRecord,
    artifacts: BTreeMap<ArtifactIntegrityIdentity, IntakeIntegrityRecord>,
    coverage: BTreeMap<CoverageIntegrityIdentity, IntakeIntegrityRecord>,
    evidence: BTreeMap<EvidenceIntegrityIdentity, IntakeIntegrityRecord>,
}

type IntakeIntegrityDigest = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
struct IntakeIntegrityRecord {
    payload_len: u64,
    digest: IntakeIntegrityDigest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IntakeIntegrityStructure {
    // Exact aggregate lengths keep the adapter preflight allocation-free and
    // order-independent. Any one caller-mutated string is therefore bounded
    // by the canonical aggregate before canonical JSON is visited.
    topology_string_bytes: usize,
    artifact_string_bytes: usize,
    coverage_string_bytes: usize,
    evidence_string_bytes: usize,
    coverage_artifact_memberships: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ArtifactIntegrityIdentity(String);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CoverageIntegrityIdentity {
    producer_role: String,
    workflow_subject_role: String,
    source_id: String,
    state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct EvidenceIntegrityIdentity(String);

impl std::borrow::Borrow<str> for ArtifactIntegrityIdentity {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl std::borrow::Borrow<str> for EvidenceIntegrityIdentity {
    fn borrow(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
impl SccmServerIntakeIntegrity {
    fn retained_material_bytes(&self) -> usize {
        std::mem::size_of_val(&self.schema_version)
            + std::mem::size_of_val(&self.topology_role_count)
            + std::mem::size_of_val(&self.structure)
            + std::mem::size_of_val(&self.topology.payload_len)
            + self.topology.digest.len()
            + self
                .artifacts
                .iter()
                .map(|(identity, record)| {
                    identity.0.len()
                        + std::mem::size_of_val(&record.payload_len)
                        + record.digest.len()
                })
                .sum::<usize>()
            + self
                .coverage
                .iter()
                .map(|(identity, record)| {
                    identity.producer_role.len()
                        + identity.workflow_subject_role.len()
                        + identity.source_id.len()
                        + identity.state.len()
                        + std::mem::size_of_val(&record.payload_len)
                        + record.digest.len()
                })
                .sum::<usize>()
            + self
                .evidence
                .iter()
                .map(|(identity, record)| {
                    identity.0.len()
                        + std::mem::size_of_val(&record.payload_len)
                        + record.digest.len()
                })
                .sum::<usize>()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SccmServerIntakeAssessmentSerializeWire<'a> {
    schema_version: u32,
    topology: &'a SccmServerTopologyAssessment,
    artifacts: &'a [SccmServerArtifactAssessment],
    coverage: &'a [SccmServerCoverage],
    evidence: &'a [SccmEvidence],
    findings: &'a [SccmFinding],
    next_artifact_requests: &'a [SccmArtifactRequest],
    #[serde(skip_serializing_if = "<[SccmServerOpaqueExtension]>::is_empty")]
    extensions: &'a [SccmServerOpaqueExtension],
    #[serde(skip_serializing_if = "<[SccmServerOpaqueExtension]>::is_empty")]
    privacy_extensions: &'a [SccmServerOpaqueExtension],
}

impl Serialize for SccmServerIntakeAssessment {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        validate_assessment_extensions(self).map_err(S::Error::custom)?;
        SccmServerIntakeAssessmentSerializeWire {
            schema_version: self.schema_version,
            topology: &self.topology,
            artifacts: &self.artifacts,
            coverage: &self.coverage,
            evidence: &self.evidence,
            findings: &self.findings,
            next_artifact_requests: &self.next_artifact_requests,
            extensions: &self.extensions,
            privacy_extensions: &self.privacy_extensions,
        }
        .serialize(serializer)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmServerTopologyAssessment {
    pub capture_host_handle: String,
    pub site_handle: String,
    pub roles_observed: Vec<SccmRole>,
    #[serde(
        skip_serializing_if = "Vec::is_empty",
        serialize_with = "serialize_opaque_extensions"
    )]
    extensions: Vec<SccmServerOpaqueExtension>,
}

impl SccmServerTopologyAssessment {
    pub fn extensions(&self) -> &[SccmServerOpaqueExtension] {
        &self.extensions
    }
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
    pub source_kind: String,
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
    pub content_sha256: Option<String>,
    pub truncated: Option<bool>,
    pub fragment_complete: Option<bool>,
    pub capture_provenance: Option<SccmServerCaptureProvenance>,
    pub parser_eligible: bool,
    #[serde(
        skip_serializing_if = "Vec::is_empty",
        serialize_with = "serialize_opaque_extensions"
    )]
    extensions: Vec<SccmServerOpaqueExtension>,
    #[serde(
        skip_serializing_if = "Vec::is_empty",
        serialize_with = "serialize_opaque_extensions"
    )]
    workflow_subject_extensions: Vec<SccmServerOpaqueExtension>,
    #[serde(
        skip_serializing_if = "Vec::is_empty",
        serialize_with = "serialize_opaque_extensions"
    )]
    configured_path_provenance_extensions: Vec<SccmServerOpaqueExtension>,
    #[serde(
        skip_serializing_if = "Vec::is_empty",
        serialize_with = "serialize_opaque_extensions"
    )]
    rotation_extensions: Vec<SccmServerOpaqueExtension>,
    #[serde(
        skip_serializing_if = "Vec::is_empty",
        serialize_with = "serialize_opaque_extensions"
    )]
    collection_limit_extensions: Vec<SccmServerOpaqueExtension>,
}

impl SccmServerArtifactAssessment {
    pub fn extensions(&self) -> &[SccmServerOpaqueExtension] {
        &self.extensions
    }

    pub fn workflow_subject_extensions(&self) -> &[SccmServerOpaqueExtension] {
        &self.workflow_subject_extensions
    }

    pub fn configured_path_provenance_extensions(&self) -> &[SccmServerOpaqueExtension] {
        &self.configured_path_provenance_extensions
    }

    pub fn rotation_extensions(&self) -> &[SccmServerOpaqueExtension] {
        &self.rotation_extensions
    }

    pub fn collection_limit_extensions(&self) -> &[SccmServerOpaqueExtension] {
        &self.collection_limit_extensions
    }
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub producer_host_handle: Option<String>,
    pub workflow_subject_role: Option<SccmRole>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow_subject_handle: Option<String>,
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
    #[error("server manifest exceeds a bounded intake limit")]
    ManifestLimitExceeded,
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
    if manifest_json.len() > MAX_SCCM_SERVER_MANIFEST_BYTES {
        return Err(SccmServerIntakeError::ManifestLimitExceeded);
    }
    preflight_server_manifest_extensions(manifest_json)?;
    let manifest: RawServerManifest = serde_json::from_str(manifest_json)
        .map_err(|_| SccmServerIntakeError::MalformedManifest)?;
    if manifest.sccm_manifest_version != 1 {
        return Err(SccmServerIntakeError::UnsupportedManifestVersion);
    }
    if manifest.bundle_role != "server" {
        return Err(SccmServerIntakeError::InvalidBundleRole);
    }
    validate_manifest_metadata(&manifest)?;
    validate_manifest_bounds(&manifest, payloads)?;

    let topology = normalize_topology(&manifest)?;
    if topology.roles_observed.iter().any(|role| {
        is_opaque_future_role(role)
            && !manifest
                .artifacts
                .iter()
                .any(|artifact| artifact.producer_role == *role)
    }) {
        return Err(SccmServerIntakeError::InvalidTopology);
    }
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
    let mut canonical_artifact_identities = BTreeSet::new();
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
            &mut canonical_artifact_identities,
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
    let mut coverage_by_key: BTreeMap<
        (String, String, String, String, String, String),
        SccmServerCoverage,
    > = BTreeMap::new();
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
            artifact.producer_host_handle.clone().unwrap_or_default(),
            artifact.source_id.clone(),
            artifact
                .workflow_subject_role
                .as_ref()
                .map(role_sort_key)
                .unwrap_or_default()
                .to_owned(),
            artifact.workflow_subject_handle.clone().unwrap_or_default(),
            coverage_sort_key(&artifact.state).to_owned(),
        );
        coverage_by_key
            .entry(coverage_key)
            .and_modify(|row| row.artifact_ids.push(artifact.artifact_id.clone()))
            .or_insert_with(|| SccmServerCoverage {
                producer_role: artifact.producer_role.clone(),
                producer_host_handle: artifact.producer_host_handle.clone(),
                workflow_subject_role: artifact.workflow_subject_role.clone(),
                workflow_subject_handle: artifact.workflow_subject_handle.clone(),
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
    let schema_version = 1;
    let intake_integrity =
        canonical_intake_integrity(schema_version, &topology, &artifacts, &coverage, &evidence)
            .ok_or(SccmServerIntakeError::InvalidArtifact)?;

    Ok(SccmServerIntakeAssessment {
        schema_version,
        topology,
        artifacts,
        coverage,
        evidence,
        findings: Vec::new(),
        next_artifact_requests,
        intake_integrity,
        extensions: normalize_opaque_extensions(
            &manifest.extensions,
            SccmServerIntakeError::MalformedManifest,
        )?,
        privacy_extensions: manifest
            .privacy
            .as_ref()
            .map(|privacy| {
                normalize_opaque_extensions(
                    &privacy.extensions,
                    SccmServerIntakeError::MalformedManifest,
                )
            })
            .transpose()?
            .unwrap_or_default(),
    })
}

struct PreparedArtifact {
    assessment: SccmServerArtifactAssessment,
    evidence: Vec<SccmEvidence>,
}

impl PreparedArtifact {
    fn sort_key(&self) -> (&str, &str, &str, &str, &str, &str, String, &str, &str) {
        (
            role_sort_key(&self.assessment.producer_role),
            self.assessment
                .producer_host_handle
                .as_deref()
                .unwrap_or_default(),
            self.assessment.source_id.as_str(),
            self.assessment
                .workflow_subject_role
                .as_ref()
                .map(role_sort_key)
                .unwrap_or_default(),
            self.assessment
                .workflow_subject_handle
                .as_deref()
                .unwrap_or_default(),
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

fn validate_manifest_bounds(
    manifest: &RawServerManifest,
    payloads: &[SccmServerArtifactPayload],
) -> Result<(), SccmServerIntakeError> {
    if manifest.artifacts.len() > MAX_SCCM_SERVER_MANIFEST_ARTIFACTS
        || payloads.len() > MAX_SCCM_SERVER_MANIFEST_ARTIFACTS
    {
        return Err(SccmServerIntakeError::ManifestLimitExceeded);
    }

    let mut declared_bytes = 0u64;
    let mut copied_bytes = 0u64;
    for artifact in &manifest.artifacts {
        if artifact.bytes_copied > MAX_SCCM_SERVER_ARTIFACT_BYTES {
            return Err(SccmServerIntakeError::ManifestLimitExceeded);
        }
        copied_bytes = copied_bytes
            .checked_add(artifact.bytes_copied)
            .ok_or(SccmServerIntakeError::ManifestLimitExceeded)?;
        if copied_bytes > MAX_SCCM_SERVER_TOTAL_DECLARED_BYTES {
            return Err(SccmServerIntakeError::ManifestLimitExceeded);
        }
        if let Some(limit) = &artifact.collection_limit {
            if limit.byte_limit > MAX_SCCM_SERVER_ARTIFACT_BYTES {
                return Err(SccmServerIntakeError::ManifestLimitExceeded);
            }
            declared_bytes = declared_bytes
                .checked_add(limit.byte_limit)
                .ok_or(SccmServerIntakeError::ManifestLimitExceeded)?;
            if declared_bytes > MAX_SCCM_SERVER_TOTAL_DECLARED_BYTES {
                return Err(SccmServerIntakeError::ManifestLimitExceeded);
            }
        }
    }

    let mut payload_bytes = 0u64;
    for payload in payloads {
        payload_bytes = payload_bytes
            .checked_add(
                u64::try_from(payload.bytes.len())
                    .map_err(|_| SccmServerIntakeError::ManifestLimitExceeded)?,
            )
            .ok_or(SccmServerIntakeError::ManifestLimitExceeded)?;
        if payload_bytes > MAX_SCCM_SERVER_TOTAL_DECLARED_BYTES {
            return Err(SccmServerIntakeError::ManifestLimitExceeded);
        }
    }

    Ok(())
}

fn validate_manifest_metadata(manifest: &RawServerManifest) -> Result<(), SccmServerIntakeError> {
    if manifest.synthetic_fixture {
        let privacy = manifest
            .privacy
            .as_ref()
            .ok_or(SccmServerIntakeError::MalformedManifest)?;
        if manifest.proposal_only != Some(true)
            || !privacy.synthetic
            || privacy.raw_paths != "redacted"
        {
            return Err(SccmServerIntakeError::MalformedManifest);
        }
    } else if manifest.proposal_only == Some(true)
        || manifest
            .privacy
            .as_ref()
            .is_some_and(|privacy| privacy.synthetic || privacy.raw_paths != "redacted")
    {
        return Err(SccmServerIntakeError::MalformedManifest);
    }

    if manifest.input_order_is_deliberately_unsorted == Some(false) {
        return Err(SccmServerIntakeError::MalformedManifest);
    }
    Ok(())
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
        || manifest.topology.roles_observed.iter().any(|role| {
            !is_declared_server_role(role)
                && (manifest.synthetic_fixture || !is_opaque_future_role(role))
        })
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
        extensions: normalize_opaque_extensions(
            &manifest.topology.extensions,
            SccmServerIntakeError::InvalidTopology,
        )?,
    })
}

fn normalize_artifact(
    artifact: RawServerArtifact,
    synthetic_fixture: bool,
    roles_observed: &[SccmRole],
    relative_paths: &mut BTreeSet<String>,
    path_fingerprint_lineages: &mut BTreeMap<PathFingerprintKey, String>,
    canonical_artifact_identities: &mut BTreeSet<CanonicalArtifactIdentity>,
    payload_by_id: &BTreeMap<&str, &[u8]>,
) -> Result<PreparedArtifact, SccmServerIntakeError> {
    let extensions =
        normalize_opaque_extensions(&artifact.extensions, SccmServerIntakeError::InvalidArtifact)?;
    let workflow_subject_extensions = artifact
        .workflow_subject
        .as_ref()
        .map(|subject| {
            normalize_opaque_extensions(&subject.extensions, SccmServerIntakeError::InvalidArtifact)
        })
        .transpose()?
        .unwrap_or_default();
    let configured_path_provenance_extensions = normalize_opaque_extensions(
        &artifact.configured_path_provenance.extensions,
        SccmServerIntakeError::InvalidArtifact,
    )?;
    let rotation_extensions = normalize_opaque_extensions(
        &artifact.rotation.extensions,
        SccmServerIntakeError::InvalidArtifact,
    )?;
    let collection_limit_extensions = artifact
        .collection_limit
        .as_ref()
        .map(|limit| {
            normalize_opaque_extensions(&limit.extensions, SccmServerIntakeError::InvalidArtifact)
        })
        .transpose()?
        .unwrap_or_default();
    let unclassified_producer =
        artifact.producer_role == SccmRole::Unknown("unclassified".to_owned());
    let opaque_future_role = !synthetic_fixture && is_opaque_future_role(&artifact.producer_role);
    let retained_unknown = opaque_future_role
        || (unclassified_producer && artifact.capture_state == SccmCoverageState::Unsupported);
    validate_artifact_annotations(&artifact, synthetic_fixture)?;
    let source_version =
        normalize_source_version(artifact.source_version.as_deref(), synthetic_fixture)?;
    if !safe_manifest_artifact_id(&artifact.artifact_id, synthetic_fixture)
        || !safe_source_id(&artifact.source_id, retained_unknown, synthetic_fixture)
        || !safe_source_kind(&artifact.source_kind, retained_unknown, synthetic_fixture)
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
        || ((!retained_unknown || is_physical_state(&artifact.capture_state))
            && artifact.producer_host_handle.is_none())
        || (retained_unknown
            && !safe_public_basename(&artifact.original_basename, synthetic_fixture))
    {
        return Err(SccmServerIntakeError::InvalidArtifact);
    }

    let producer_is_observed = roles_observed.contains(&artifact.producer_role);
    if (!producer_is_observed && !unclassified_producer)
        || (!is_declared_server_role(&artifact.producer_role) && !retained_unknown)
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

    let (family, original_basename, rotation, mut parser_eligible) =
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
        } else if retained_unknown {
            (
                SccmArtifactFamily::Unknown(artifact.source_id.clone()),
                Some(artifact.original_basename.clone()),
                parse_retained_rotation(&artifact.rotation)?,
                false,
            )
        } else {
            return Err(SccmServerIntakeError::InvalidArtifact);
        };

    let path_fingerprint_key = (
        role_sort_key(&artifact.producer_role).to_owned(),
        artifact.producer_host_handle.clone(),
        artifact.source_id.clone(),
        workflow_subject_role
            .as_ref()
            .map(role_sort_key)
            .unwrap_or_default()
            .to_owned(),
        artifact
            .workflow_subject
            .as_ref()
            .and_then(|subject| subject.instance_handle.clone()),
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

    let canonical_identity = (
        role_sort_key(&artifact.producer_role).to_owned(),
        artifact.producer_host_handle.clone(),
        artifact.source_id.clone(),
        workflow_subject_role
            .as_ref()
            .map(role_sort_key)
            .unwrap_or_default()
            .to_owned(),
        artifact
            .workflow_subject
            .as_ref()
            .and_then(|subject| subject.instance_handle.clone()),
        artifact
            .configured_path_provenance
            .path_fingerprint
            .to_ascii_lowercase(),
        artifact.rotation.lineage_id.clone(),
        original_basename
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase(),
        rotation_sort_key(rotation.as_ref()),
    );
    if !canonical_artifact_identities.insert(canonical_identity) {
        return Err(SccmServerIntakeError::DuplicateArtifact);
    }

    let configured_path_state =
        parse_configured_path_state(&artifact.configured_path_provenance.state)?;
    let configured_path_class = match artifact.configured_path_provenance.path_class.as_deref() {
        None => None,
        Some("nonDefault") => Some(SccmServerConfiguredPathClass::NonDefault),
        Some(_) => return Err(SccmServerIntakeError::InvalidArtifact),
    };
    if configured_path_class.is_some()
        && configured_path_state != SccmServerConfiguredPathState::Configured
    {
        return Err(SccmServerIntakeError::InvalidArtifact);
    }
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
    let content_sha256 = bytes.map(payload_sha256);
    let profile_eligible = source_version
        .as_deref()
        .is_some_and(|version| source_version_is_profile_eligible(version, synthetic_fixture));

    let mut evidence = Vec::new();
    let mut state = artifact.capture_state.clone();
    if artifact.capture_state == SccmCoverageState::Captured && parser_eligible {
        let bytes = bytes.ok_or(SccmServerIntakeError::MissingPayload)?;
        let encoding = artifact
            .encoding
            .as_deref()
            .ok_or(SccmServerIntakeError::InvalidArtifact)?;
        if let Some(content) = decode_server_payload(bytes, encoding)? {
            let display_name = original_basename
                .clone()
                .ok_or(SccmServerIntakeError::InvalidArtifact)?;
            let (_, parse_errors) =
                crate::parser::ccm::parse_content(&content, &display_name, None);
            evidence = normalize_ccm_artifact(
                SccmArtifact {
                    artifact_id: artifact.artifact_id.clone(),
                    display_name,
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
                &content,
            );
            let collected_utc_millis = DateTime::parse_from_rfc3339(&collected_at_utc)
                .map_err(|_| SccmServerIntakeError::InvalidArtifact)?
                .timestamp_millis();
            if evidence.iter().any(|record| {
                record
                    .timestamp
                    .utc_millis
                    .is_some_and(|instant| instant > collected_utc_millis)
            }) {
                return Err(SccmServerIntakeError::InvalidArtifact);
            }
            if parse_errors > 0 {
                state = SccmCoverageState::ParseFailed;
            }
        } else {
            state = SccmCoverageState::Unsupported;
            parser_eligible = false;
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
            source_id: artifact.source_id,
            source_kind: artifact.source_kind,
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
            content_sha256,
            truncated: artifact.truncated,
            fragment_complete: artifact.fragment_complete,
            capture_provenance,
            parser_eligible,
            extensions,
            workflow_subject_extensions,
            configured_path_provenance_extensions,
            rotation_extensions,
            collection_limit_extensions,
        },
        evidence,
    })
}

fn payload_sha256(bytes: &[u8]) -> String {
    const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";

    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(char::from(LOWER_HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(LOWER_HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn checked_add_string_bytes(total: &mut usize, value: &str) -> Option<()> {
    *total = total.checked_add(value.len())?;
    Some(())
}

fn checked_add_optional_string_bytes(total: &mut usize, value: Option<&str>) -> Option<()> {
    if let Some(value) = value {
        checked_add_string_bytes(total, value)?;
    }
    Some(())
}

fn checked_add_opaque_extension_bytes(
    total: &mut usize,
    extensions: &[SccmServerOpaqueExtension],
) -> Option<()> {
    for extension in extensions {
        checked_add_string_bytes(total, &extension.name)?;
        checked_add_string_bytes(total, &extension.value)?;
    }
    Some(())
}

fn artifact_family_integrity_key(family: &SccmArtifactFamily) -> &str {
    family.serialized_name()
}

fn topology_string_bytes(topology: &SccmServerTopologyAssessment) -> Option<usize> {
    let mut total = 0usize;
    checked_add_string_bytes(&mut total, &topology.capture_host_handle)?;
    checked_add_string_bytes(&mut total, &topology.site_handle)?;
    for role in &topology.roles_observed {
        checked_add_string_bytes(&mut total, role_sort_key(role))?;
    }
    checked_add_opaque_extension_bytes(&mut total, &topology.extensions)?;
    Some(total)
}

fn artifact_string_bytes(artifacts: &[SccmServerArtifactAssessment]) -> Option<usize> {
    let mut total = 0usize;
    for artifact in artifacts {
        checked_add_string_bytes(&mut total, &artifact.artifact_id)?;
        checked_add_string_bytes(&mut total, role_sort_key(&artifact.producer_role))?;
        checked_add_optional_string_bytes(&mut total, artifact.producer_host_handle.as_deref())?;
        checked_add_optional_string_bytes(
            &mut total,
            artifact.workflow_subject_role.as_ref().map(role_sort_key),
        )?;
        checked_add_optional_string_bytes(&mut total, artifact.workflow_subject_handle.as_deref())?;
        checked_add_string_bytes(&mut total, &artifact.source_id)?;
        checked_add_string_bytes(&mut total, &artifact.source_kind)?;
        checked_add_string_bytes(&mut total, artifact_family_integrity_key(&artifact.family))?;
        checked_add_optional_string_bytes(&mut total, artifact.original_basename.as_deref())?;
        match artifact.rotation.as_ref() {
            None => {}
            Some(SccmRotation::Current) => checked_add_string_bytes(&mut total, "current")?,
            Some(SccmRotation::LoUnderscore) => {
                checked_add_string_bytes(&mut total, "loUnderscore")?;
            }
            Some(SccmRotation::Numbered(_)) => {
                checked_add_string_bytes(&mut total, "numbered")?;
            }
            Some(SccmRotation::Timestamped(value)) => {
                checked_add_string_bytes(&mut total, "timestamped")?;
                checked_add_string_bytes(&mut total, value)?;
            }
            // Canonical server intake admits only its closed rotation grammar.
            // Reject a caller-injected open JSON value before traversing it.
            Some(SccmRotation::Unknown(_)) => return None,
        }
        checked_add_string_bytes(&mut total, &artifact.rotation_lineage_handle)?;
        checked_add_string_bytes(&mut total, coverage_sort_key(&artifact.state))?;
        checked_add_string_bytes(
            &mut total,
            match artifact.configured_path_state {
                SccmServerConfiguredPathState::Configured => "configured",
                SccmServerConfiguredPathState::DefaultCandidate => "defaultCandidate",
                SccmServerConfiguredPathState::NotRequested => "notRequested",
                SccmServerConfiguredPathState::Supplied => "supplied",
            },
        )?;
        if artifact.configured_path_class.is_some() {
            checked_add_string_bytes(&mut total, "nonDefault")?;
        }
        checked_add_string_bytes(&mut total, &artifact.path_fingerprint)?;
        checked_add_optional_string_bytes(&mut total, artifact.source_version.as_deref())?;
        checked_add_string_bytes(&mut total, &artifact.collected_at_utc)?;
        checked_add_optional_string_bytes(&mut total, artifact.relative_path.as_deref())?;
        checked_add_optional_string_bytes(&mut total, artifact.content_sha256.as_deref())?;
        if let Some(provenance) = &artifact.capture_provenance {
            checked_add_string_bytes(&mut total, &provenance.encoding)?;
        }
        checked_add_opaque_extension_bytes(&mut total, &artifact.extensions)?;
        checked_add_opaque_extension_bytes(&mut total, &artifact.workflow_subject_extensions)?;
        checked_add_opaque_extension_bytes(
            &mut total,
            &artifact.configured_path_provenance_extensions,
        )?;
        checked_add_opaque_extension_bytes(&mut total, &artifact.rotation_extensions)?;
        checked_add_opaque_extension_bytes(&mut total, &artifact.collection_limit_extensions)?;
    }
    Some(total)
}

fn coverage_artifact_memberships(coverage: &[SccmServerCoverage]) -> Option<usize> {
    coverage.iter().try_fold(0usize, |total, record| {
        total.checked_add(record.artifact_ids.len())
    })
}

fn coverage_string_bytes(coverage: &[SccmServerCoverage]) -> Option<usize> {
    let mut total = 0usize;
    for record in coverage {
        checked_add_string_bytes(&mut total, role_sort_key(&record.producer_role))?;
        checked_add_optional_string_bytes(
            &mut total,
            record.workflow_subject_role.as_ref().map(role_sort_key),
        )?;
        checked_add_string_bytes(&mut total, &record.source_id)?;
        checked_add_string_bytes(&mut total, coverage_sort_key(&record.state))?;
        for artifact_id in &record.artifact_ids {
            checked_add_string_bytes(&mut total, artifact_id)?;
        }
    }
    Some(total)
}

fn evidence_string_bytes(evidence: &[SccmEvidence]) -> Option<usize> {
    let mut total = 0usize;
    for record in evidence {
        checked_add_string_bytes(&mut total, &record.evidence_id)?;
        checked_add_string_bytes(&mut total, &record.reference.artifact_id)?;
        checked_add_string_bytes(&mut total, &record.reference.entry_id)?;
        checked_add_string_bytes(&mut total, role_sort_key(&record.role))?;
        checked_add_optional_string_bytes(&mut total, record.component.as_deref())?;
        checked_add_optional_string_bytes(&mut total, record.ccm_source_file.as_deref())?;
        checked_add_string_bytes(&mut total, &record.message)?;
        checked_add_optional_string_bytes(
            &mut total,
            record.timestamp.original_display.as_deref(),
        )?;
        if let Some(context) = &record.execution_context {
            checked_add_string_bytes(&mut total, &context.scheme)?;
            checked_add_string_bytes(&mut total, &context.value)?;
        }
    }
    Some(total)
}

fn intake_integrity_structure(
    topology: &SccmServerTopologyAssessment,
    artifacts: &[SccmServerArtifactAssessment],
    coverage: &[SccmServerCoverage],
    evidence: &[SccmEvidence],
    coverage_artifact_memberships: usize,
) -> Option<IntakeIntegrityStructure> {
    Some(IntakeIntegrityStructure {
        topology_string_bytes: topology_string_bytes(topology)?,
        artifact_string_bytes: artifact_string_bytes(artifacts)?,
        coverage_string_bytes: coverage_string_bytes(coverage)?,
        evidence_string_bytes: evidence_string_bytes(evidence)?,
        coverage_artifact_memberships,
    })
}

fn canonical_intake_integrity(
    schema_version: u32,
    topology: &SccmServerTopologyAssessment,
    artifacts: &[SccmServerArtifactAssessment],
    coverage: &[SccmServerCoverage],
    evidence: &[SccmEvidence],
) -> Option<SccmServerIntakeIntegrity> {
    let coverage_artifact_memberships = coverage_artifact_memberships(coverage)?;
    let structure = intake_integrity_structure(
        topology,
        artifacts,
        coverage,
        evidence,
        coverage_artifact_memberships,
    )?;
    canonical_intake_integrity_with_structure(
        schema_version,
        topology,
        artifacts,
        coverage,
        evidence,
        structure,
        None,
    )
}

fn canonical_intake_integrity_for_adapter(
    schema_version: u32,
    topology: &SccmServerTopologyAssessment,
    artifacts: &[SccmServerArtifactAssessment],
    coverage: &[SccmServerCoverage],
    evidence: &[SccmEvidence],
    expected: &SccmServerIntakeIntegrity,
) -> Option<SccmServerIntakeIntegrity> {
    let coverage_artifact_memberships = coverage_artifact_memberships(coverage)?;
    if coverage_artifact_memberships != expected.structure.coverage_artifact_memberships {
        return None;
    }
    let structure = intake_integrity_structure(
        topology,
        artifacts,
        coverage,
        evidence,
        coverage_artifact_memberships,
    )?;
    if structure != expected.structure {
        return None;
    }
    canonical_intake_integrity_with_structure(
        schema_version,
        topology,
        artifacts,
        coverage,
        evidence,
        structure,
        Some(expected),
    )
}

#[allow(clippy::too_many_arguments)]
fn canonical_intake_integrity_with_structure(
    schema_version: u32,
    topology: &SccmServerTopologyAssessment,
    artifacts: &[SccmServerArtifactAssessment],
    coverage: &[SccmServerCoverage],
    evidence: &[SccmEvidence],
    structure: IntakeIntegrityStructure,
    expected: Option<&SccmServerIntakeIntegrity>,
) -> Option<SccmServerIntakeIntegrity> {
    #[cfg(test)]
    INTAKE_CANONICALIZATION_CALLS.with(|calls| calls.set(calls.get().saturating_add(1)));

    let mut normalized_topology = topology.clone();
    normalized_topology
        .roles_observed
        .sort_by(|left, right| role_sort_key(left).cmp(role_sort_key(right)));
    if normalized_topology
        .roles_observed
        .windows(2)
        .any(|roles| roles[0] == roles[1])
    {
        return None;
    }

    let mut normalized_coverage = coverage.to_vec();
    for record in &mut normalized_coverage {
        record.artifact_ids.sort();
        if record.artifact_ids.windows(2).any(|ids| ids[0] == ids[1]) {
            return None;
        }
    }

    if evidence
        .iter()
        .any(|record| record.evidence_id != record.reference.entry_id)
    {
        return None;
    }

    let mut artifact_integrity = BTreeMap::new();
    for artifact in artifacts {
        let max_payload_len = match expected {
            Some(expected) => Some(
                expected
                    .artifacts
                    .get(artifact.artifact_id.as_str())?
                    .payload_len,
            ),
            None => None,
        };
        if artifact_integrity
            .insert(
                ArtifactIntegrityIdentity(artifact.artifact_id.clone()),
                canonical_record_digest_bounded(b"artifact", artifact, max_payload_len)?,
            )
            .is_some()
        {
            return None;
        }
    }

    let mut coverage_integrity = BTreeMap::new();
    for record in &normalized_coverage {
        let identity = CoverageIntegrityIdentity {
            producer_role: role_sort_key(&record.producer_role).to_owned(),
            workflow_subject_role: record
                .workflow_subject_role
                .as_ref()
                .map(role_sort_key)
                .unwrap_or_default()
                .to_owned(),
            source_id: record.source_id.clone(),
            state: coverage_sort_key(&record.state).to_owned(),
        };
        let max_payload_len = match expected {
            Some(expected) => Some(expected.coverage.get(&identity)?.payload_len),
            None => None,
        };
        if coverage_integrity
            .insert(
                identity,
                canonical_record_digest_bounded(b"coverage", record, max_payload_len)?,
            )
            .is_some()
        {
            return None;
        }
    }

    let mut evidence_integrity = BTreeMap::new();
    for record in evidence {
        let max_payload_len = match expected {
            Some(expected) => Some(
                expected
                    .evidence
                    .get(record.evidence_id.as_str())?
                    .payload_len,
            ),
            None => None,
        };
        if evidence_integrity
            .insert(
                EvidenceIntegrityIdentity(record.evidence_id.clone()),
                canonical_record_digest_bounded(b"evidence", record, max_payload_len)?,
            )
            .is_some()
        {
            return None;
        }
    }

    Some(SccmServerIntakeIntegrity {
        schema_version,
        topology_role_count: normalized_topology.roles_observed.len(),
        structure,
        topology: canonical_record_digest_bounded(
            b"topology",
            &normalized_topology,
            expected.map(|expected| expected.topology.payload_len),
        )?,
        artifacts: artifact_integrity,
        coverage: coverage_integrity,
        evidence: evidence_integrity,
    })
}

const INTAKE_INTEGRITY_DOMAIN: &[u8] = b"cmtraceopen.sccm.server-intake.integrity.v1";

#[cfg(test)]
std::thread_local! {
    static INTAKE_CANONICALIZATION_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static INTAKE_CANONICAL_JSON_BYTES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_intake_integrity_work_probe() {
    INTAKE_CANONICALIZATION_CALLS.with(|calls| calls.set(0));
    INTAKE_CANONICAL_JSON_BYTES.with(|bytes| bytes.set(0));
}

#[cfg(test)]
pub(crate) fn intake_integrity_work_probe() -> (usize, usize) {
    let calls = INTAKE_CANONICALIZATION_CALLS.with(std::cell::Cell::get);
    let bytes = INTAKE_CANONICAL_JSON_BYTES.with(std::cell::Cell::get);
    (calls, bytes)
}

struct IntakeIntegrityWriter {
    hasher: Sha256,
    payload_len: u64,
    max_payload_len: Option<u64>,
}

impl Write for IntakeIntegrityWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        #[cfg(test)]
        INTAKE_CANONICAL_JSON_BYTES.with(|total| {
            total.set(total.get().saturating_add(bytes.len()));
        });
        let bytes_len = u64::try_from(bytes.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "integrity input length overflow",
            )
        })?;
        let payload_len = self.payload_len.checked_add(bytes_len).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "integrity input length overflow",
            )
        })?;
        if self
            .max_payload_len
            .is_some_and(|max_payload_len| payload_len > max_payload_len)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "integrity input exceeds sealed payload length",
            ));
        }
        self.hasher.update(bytes);
        self.payload_len = payload_len;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn framed_integrity_hasher(domain: &[u8]) -> Option<Sha256> {
    // The master namespace is fixed, the variable domain is length-framed,
    // and the one canonical JSON value is terminal. That encoding has only
    // one boundary interpretation, so hashing does not need a length pass.
    let domain_len = u64::try_from(domain.len()).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(INTAKE_INTEGRITY_DOMAIN);
    hasher.update(domain_len.to_be_bytes());
    hasher.update(domain);
    Some(hasher)
}

#[cfg(test)]
fn canonical_record_digest<T: Serialize>(
    domain: &[u8],
    record: &T,
) -> Option<IntakeIntegrityRecord> {
    canonical_record_digest_bounded(domain, record, None)
}

fn canonical_record_digest_bounded<T: Serialize>(
    domain: &[u8],
    record: &T,
    max_payload_len: Option<u64>,
) -> Option<IntakeIntegrityRecord> {
    let mut writer = IntakeIntegrityWriter {
        hasher: framed_integrity_hasher(domain)?,
        payload_len: 0,
        max_payload_len,
    };
    serde_json::to_writer(&mut writer, record).ok()?;
    if max_payload_len.is_some_and(|max_payload_len| writer.payload_len != max_payload_len) {
        return None;
    }
    let digest = writer.hasher.finalize();
    let mut encoded = [0; 32];
    encoded.copy_from_slice(&digest);
    Some(IntakeIntegrityRecord {
        payload_len: writer.payload_len,
        digest: encoded,
    })
}

#[cfg(test)]
mod intake_integrity_tests {
    use std::fs;
    use std::path::Path;

    use super::*;

    fn canonical_assessment() -> SccmServerIntakeAssessment {
        let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/sccm/server/management-point/canonical-intake-policy-scope");
        let manifest_json =
            fs::read_to_string(directory.join("manifest.json")).expect("fixture manifest");
        let manifest: Value = serde_json::from_str(&manifest_json).expect("fixture JSON");
        let payloads = manifest["artifacts"]
            .as_array()
            .expect("fixture artifacts")
            .iter()
            .filter_map(|artifact| {
                let relative_path = artifact["relativePath"].as_str()?;
                Some(SccmServerArtifactPayload {
                    manifest_artifact_id: artifact["artifactId"]
                        .as_str()
                        .expect("fixture artifact ID")
                        .to_owned(),
                    bytes: fs::read(directory.join(relative_path)).expect("fixture payload"),
                })
            })
            .collect::<Vec<_>>();
        assess_server_intake(&manifest_json, &payloads).expect("canonical fixture")
    }

    fn integrity(assessment: &SccmServerIntakeAssessment) -> Option<SccmServerIntakeIntegrity> {
        canonical_intake_integrity(
            assessment.schema_version,
            &assessment.topology,
            &assessment.artifacts,
            &assessment.coverage,
            &assessment.evidence,
        )
    }

    #[test]
    fn intake_integrity_is_compact_and_collision_safe() {
        let assessment = canonical_assessment();
        let baseline = integrity(&assessment).expect("baseline integrity");

        let mut large_message = assessment.clone();
        large_message.evidence[0].message = "x".repeat(1024 * 1024);
        let large_integrity = integrity(&large_message).expect("large-message integrity");
        assert!(
            large_integrity.retained_material_bytes() <= 1_024,
            "integrity retained {} bytes for one 1 MiB message",
            large_integrity.retained_material_bytes()
        );

        let mut schema_mutation = assessment.clone();
        schema_mutation.schema_version += 1;
        assert_ne!(integrity(&schema_mutation), Some(baseline.clone()));

        let mut topology_mutation = assessment.clone();
        topology_mutation
            .topology
            .capture_host_handle
            .push_str("-changed");
        assert_ne!(integrity(&topology_mutation), Some(baseline.clone()));

        let mut artifact_mutation = assessment.clone();
        artifact_mutation.artifacts[0]
            .path_fingerprint
            .push_str("-changed");
        assert_ne!(integrity(&artifact_mutation), Some(baseline.clone()));

        let mut coverage_mutation = assessment.clone();
        coverage_mutation.coverage[0].state = SccmCoverageState::Capped;
        assert_ne!(integrity(&coverage_mutation), Some(baseline.clone()));

        let mut evidence_mutation = assessment.clone();
        evidence_mutation.evidence[0].message.push_str(" changed");
        assert_ne!(integrity(&evidence_mutation), Some(baseline.clone()));

        let mut duplicate = assessment.clone();
        duplicate.evidence.push(duplicate.evidence[0].clone());
        assert_eq!(integrity(&duplicate), None);

        let mut removed = assessment.clone();
        removed.evidence.clear();
        assert_ne!(integrity(&removed), Some(baseline.clone()));

        let mut appended = assessment.clone();
        let mut appended_record = appended.evidence[0].clone();
        appended_record.evidence_id = "mp-policy-current:replayed".to_owned();
        appended_record.reference.entry_id = "mp-policy-current:replayed".to_owned();
        appended.evidence.push(appended_record);
        assert_ne!(integrity(&appended), Some(baseline.clone()));

        let mut collision = assessment.clone();
        let mut colliding_record = collision.evidence[0].clone();
        colliding_record.message.push_str(" different content");
        collision.evidence.push(colliding_record);
        assert_eq!(
            integrity(&collision),
            None,
            "one semantic evidence identity cannot retain two bodies"
        );

        let mut artifact_collision = assessment.clone();
        let mut colliding_artifact = artifact_collision.artifacts[0].clone();
        colliding_artifact.path_fingerprint.push_str("-different");
        artifact_collision.artifacts.push(colliding_artifact);
        assert_eq!(integrity(&artifact_collision), None);

        let mut coverage_collision = assessment.clone();
        let mut colliding_coverage = coverage_collision.coverage[0].clone();
        colliding_coverage.artifact_ids = vec!["different-artifact".to_owned()];
        coverage_collision.coverage.push(colliding_coverage);
        assert_eq!(integrity(&coverage_collision), None);

        let mut duplicate_membership = assessment.clone();
        let artifact_id = duplicate_membership.coverage[0].artifact_ids[0].clone();
        duplicate_membership.coverage[0]
            .artifact_ids
            .push(artifact_id);
        assert_eq!(integrity(&duplicate_membership), None);

        let mut duplicate_topology_role = assessment;
        duplicate_topology_role
            .topology
            .roles_observed
            .push(SccmRole::ManagementPoint);
        assert_eq!(integrity(&duplicate_topology_role), None);
    }

    #[test]
    fn intake_integrity_hash_framing_separates_domains_and_boundaries() {
        fn framed_digest(domain: &[u8], payload: &[u8]) -> IntakeIntegrityDigest {
            let mut hasher = framed_integrity_hasher(domain).expect("test hash framing");
            hasher.update(payload);
            let digest = hasher.finalize();
            let mut encoded = [0; 32];
            encoded.copy_from_slice(&digest);
            encoded
        }

        assert_ne!(
            framed_digest(b"artifact", b"same-body"),
            framed_digest(b"evidence", b"same-body"),
            "record domains must not share a digest namespace"
        );
        assert_ne!(
            framed_digest(b"a", b"bc"),
            framed_digest(b"ab", b"c"),
            "a length-framed domain and terminal payload must not concatenate ambiguously"
        );
    }

    #[test]
    fn intake_integrity_serializes_each_record_once() {
        struct CountedRecord<'a>(&'a std::cell::Cell<usize>);

        impl Serialize for CountedRecord<'_> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                self.0.set(self.0.get().saturating_add(1));
                serializer.serialize_str("canonical-payload")
            }
        }

        let serializations = std::cell::Cell::new(0);
        canonical_record_digest(b"evidence", &CountedRecord(&serializations))
            .expect("integrity digest");
        assert_eq!(
            serializations.get(),
            1,
            "integrity hashing must stream one terminal canonical JSON payload"
        );
    }
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

fn decode_server_payload(
    bytes: &[u8],
    encoding: &str,
) -> Result<Option<String>, SccmServerIntakeError> {
    match encoding {
        "utf-8" => {
            let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
            std::str::from_utf8(bytes)
                .map(|content| Some(content.to_owned()))
                .map_err(|_| SccmServerIntakeError::InvalidPayloadEncoding)
        }
        "utf-16le" => {
            let bytes = bytes.strip_prefix(&[0xff, 0xfe]).unwrap_or(bytes);
            if !bytes.len().is_multiple_of(2) {
                return Err(SccmServerIntakeError::InvalidPayloadEncoding);
            }
            let units = bytes
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect::<Vec<_>>();
            String::from_utf16(&units)
                .map(Some)
                .map_err(|_| SccmServerIntakeError::InvalidPayloadEncoding)
        }
        "windows-1252" => Ok(Some(
            encoding_rs::WINDOWS_1252
                .decode_without_bom_handling(bytes)
                .0
                .into_owned(),
        )),
        "unknown" => Ok(None),
        _ => Err(SccmServerIntakeError::InvalidPayloadEncoding),
    }
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
    let expected_source = source_path_segment(&artifact.source_id);
    let expected_rotation =
        rotation_path_segment(rotation).ok_or(SccmServerIntakeError::InvalidArtifact)?;
    let basename = original_basename.ok_or(SccmServerIntakeError::InvalidArtifact)?;
    let expected_basename = basename_path_segment(basename);
    let mut cursor = 0;
    let fixed_prefix = [
        "evidence",
        "sccm",
        "server",
        expected_role.as_str(),
        expected_source.as_str(),
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
        || components.get(cursor + 1).copied() != Some(expected_basename.as_str())
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

fn role_path_segment(role: &SccmRole) -> Option<String> {
    Some(match role {
        SccmRole::SiteServer => "site-server".to_owned(),
        SccmRole::ManagementPoint => "management-point".to_owned(),
        SccmRole::DistributionPoint => "distribution-point".to_owned(),
        SccmRole::SoftwareUpdatePoint => "software-update-point".to_owned(),
        SccmRole::WsUs => "wsus".to_owned(),
        SccmRole::Provider => "provider".to_owned(),
        SccmRole::AdminService => "admin-service".to_owned(),
        SccmRole::Unknown(value) => format!(
            "role-{}",
            opaque_sha256_digest(value, "cmtraceopen.role.sha256.v1:")?
        ),
        SccmRole::Client => return None,
    })
}

fn source_path_segment(source_id: &str) -> String {
    opaque_sha256_digest(source_id, "cmtraceopen.source.sha256.v1:")
        .map(|digest| format!("source-{digest}"))
        .unwrap_or_else(|| source_id.to_owned())
}

fn basename_path_segment(basename: &str) -> String {
    opaque_sha256_digest(basename, "cmtraceopen.basename.sha256.v1:")
        .map(|digest| format!("basename-{digest}"))
        .unwrap_or_else(|| basename.to_owned())
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
                .filter(|value| is_canonical_rotation_timestamp(value))
                .ok_or(SccmServerIntakeError::InvalidArtifact)?;
            SccmRotation::Timestamped(timestamp.to_owned())
        }
        _ => return Ok(None),
    };
    Ok(Some(parsed))
}

fn parse_retained_rotation(
    rotation: &RawServerRotation,
) -> Result<Option<SccmRotation>, SccmServerIntakeError> {
    if rotation.kind == "none" && rotation.value.is_none() {
        return Ok(None);
    }
    parse_declared_rotation(rotation)?
        .ok_or(SccmServerIntakeError::InvalidArtifact)
        .map(Some)
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

fn logical_source_key(
    artifact: &SccmServerArtifactAssessment,
) -> (String, String, String, String, String) {
    (
        role_sort_key(&artifact.producer_role).to_owned(),
        artifact
            .producer_host_handle
            .as_deref()
            .unwrap_or_default()
            .to_owned(),
        artifact.source_id.clone(),
        artifact
            .workflow_subject_role
            .as_ref()
            .map(role_sort_key)
            .unwrap_or_default()
            .to_owned(),
        artifact
            .workflow_subject_handle
            .as_deref()
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
    if !matches!(
        artifact.state,
        SccmCoverageState::Absent
            | SccmCoverageState::AccessDenied
            | SccmCoverageState::Capped
            | SccmCoverageState::Unsupported
            | SccmCoverageState::ParseFailed
    ) {
        return None;
    }

    let classified = classify_artifact_name(
        artifact.original_basename.as_deref()?,
        artifact.producer_role.clone(),
    );
    if !classified.uses_ccm_records
        || !classified.supported_for_diagnosis
        || classified.family != artifact.family
    {
        return None;
    }

    Some(SccmArtifactRequest {
        logical_id: classified.logical_name,
        role: classified.role,
        reason: format!("Collect the complete {} file.", classified.basename),
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

fn validate_artifact_annotations(
    artifact: &RawServerArtifact,
    synthetic_fixture: bool,
) -> Result<(), SccmServerIntakeError> {
    if artifact
        .workflow_subject
        .as_ref()
        .and_then(|subject| subject.basis.as_deref())
        .is_some_and(|basis| {
            if synthetic_fixture {
                basis != "incidentScopeOnly"
            } else {
                !opaque_sha256_handle(basis, "cmtraceopen.subject-basis.sha256.v1:")
            }
        })
    {
        return Err(SccmServerIntakeError::InvalidArtifact);
    }
    if artifact
        .default_candidate_state
        .as_deref()
        .is_some_and(|value| value != "absentCandidateOnly")
    {
        return Err(SccmServerIntakeError::InvalidArtifact);
    }

    for (detail, expected_state, synthetic_value, domain) in [
        (
            artifact.collection_detail.as_deref(),
            SccmCoverageState::AccessDenied,
            "synthetic permission denial",
            "collection-detail",
        ),
        (
            artifact.skip_reason.as_deref(),
            SccmCoverageState::Skipped,
            "optional supplemental source not requested",
            "skip-reason",
        ),
        (
            artifact.unsupported_reason.as_deref(),
            SccmCoverageState::Unsupported,
            "no approved server source contract",
            "unsupported-reason",
        ),
    ] {
        if let Some(detail) = detail {
            if artifact.capture_state != expected_state
                || if synthetic_fixture {
                    detail != synthetic_value
                } else {
                    !opaque_sha256_handle(detail, &format!("cmtraceopen.{domain}.sha256.v1:"))
                }
            {
                return Err(SccmServerIntakeError::InvalidArtifact);
            }
        }
    }

    match (artifact.truncated, artifact.fragment_complete) {
        (None, None) => {}
        (Some(true), Some(false)) if artifact.capture_state == SccmCoverageState::Capped => {}
        _ => return Err(SccmServerIntakeError::InvalidArtifact),
    }
    Ok(())
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

fn safe_source_id(value: &str, allow_unknown: bool, synthetic_fixture: bool) -> bool {
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
    ) || (allow_unknown
        && !synthetic_fixture
        && opaque_sha256_handle(value, "cmtraceopen.source.sha256.v1:"))
}

fn safe_source_kind(value: &str, allow_unknown: bool, synthetic_fixture: bool) -> bool {
    matches!(
        value,
        "ccmLog" | "iisW3c" | "structuredSupplement" | "unknown"
    ) || (allow_unknown
        && !synthetic_fixture
        && opaque_sha256_handle(value, "cmtraceopen.source-kind.sha256.v1:"))
}

fn safe_public_basename(value: &str, synthetic_fixture: bool) -> bool {
    if synthetic_fixture {
        value == "synthetic-db-export.txt"
    } else {
        opaque_sha256_handle(value, "cmtraceopen.basename.sha256.v1:")
    }
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
    value == "REDACTED" || opaque_sha256_handle(value, "cmtraceopen.original-path.sha256.v1:")
}

fn normalize_opaque_extensions(
    extensions: &BTreeMap<String, Value>,
    scope_error: SccmServerIntakeError,
) -> Result<Vec<SccmServerOpaqueExtension>, SccmServerIntakeError> {
    let normalized = extensions
        .iter()
        .map(|(name, value)| {
            let value = value.as_str().ok_or_else(|| scope_error.clone())?;
            SccmServerOpaqueExtension::try_new(name.clone(), value.to_owned())
                .map_err(|_| scope_error.clone())
        })
        .collect::<Result<Vec<_>, _>>()?;
    validate_opaque_extension_collection(&normalized).map_err(|_| scope_error)?;
    Ok(normalized)
}

fn validate_opaque_extension_collection(
    extensions: &[SccmServerOpaqueExtension],
) -> Result<(usize, usize), &'static str> {
    if extensions.len() > MAX_SCCM_SERVER_OPAQUE_EXTENSIONS {
        return Err("opaque extension scope exceeds its count bound");
    }
    let mut bytes = 0usize;
    let mut previous_name: Option<&str> = None;
    for extension in extensions {
        extension
            .validate()
            .map_err(|_| "opaque extension record is invalid")?;
        if previous_name.is_some_and(|previous| previous >= extension.name()) {
            return Err("opaque extensions are duplicated or not canonically sorted");
        }
        previous_name = Some(extension.name());
        bytes = bytes
            .checked_add(extension.name().len())
            .and_then(|bytes| bytes.checked_add(extension.value().len()))
            .ok_or("opaque extension byte count overflowed")?;
    }
    if bytes > MAX_SCCM_SERVER_OPAQUE_EXTENSION_BYTES_PER_SCOPE {
        return Err("opaque extension scope exceeds its byte bound");
    }
    Ok((extensions.len(), bytes))
}

fn serialize_opaque_extensions<S>(
    extensions: &[SccmServerOpaqueExtension],
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    validate_opaque_extension_collection(extensions).map_err(S::Error::custom)?;
    extensions.serialize(serializer)
}

fn validate_assessment_extensions(
    assessment: &SccmServerIntakeAssessment,
) -> Result<(), &'static str> {
    let mut total_count = 0usize;
    let mut total_bytes = 0usize;
    let mut add_scope = |extensions: &[SccmServerOpaqueExtension]| {
        let (count, bytes) = validate_opaque_extension_collection(extensions)?;
        total_count = total_count
            .checked_add(count)
            .ok_or("opaque extension aggregate count overflowed")?;
        total_bytes = total_bytes
            .checked_add(bytes)
            .ok_or("opaque extension aggregate bytes overflowed")?;
        if total_count > MAX_SCCM_SERVER_TOTAL_OPAQUE_EXTENSIONS
            || total_bytes > MAX_SCCM_SERVER_TOTAL_OPAQUE_EXTENSION_BYTES
        {
            return Err("opaque extension aggregate exceeds its bound");
        }
        Ok(())
    };

    add_scope(&assessment.extensions)?;
    add_scope(&assessment.privacy_extensions)?;
    add_scope(&assessment.topology.extensions)?;
    for artifact in &assessment.artifacts {
        add_scope(&artifact.extensions)?;
        add_scope(&artifact.workflow_subject_extensions)?;
        add_scope(&artifact.configured_path_provenance_extensions)?;
        add_scope(&artifact.rotation_extensions)?;
        add_scope(&artifact.collection_limit_extensions)?;
    }
    Ok(())
}

fn safe_opaque_extension_name(value: &str) -> bool {
    value
        .strip_prefix("x-cmtraceopen-opaque-v1-")
        .is_some_and(|token| {
            (1..=64).contains(&token.len())
                && token.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
                && !token.ends_with('-')
                && token
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
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
                    "synthetic:subject:dp-01"
                        | "synthetic:subject:dp-02"
                        | "synthetic:subject:sup-01"
                )
            }
            _ => false,
        };
    }
    opaque_sha256_handle(value, &format!("cmtraceopen.{domain}.sha256.v1:"))
}

fn opaque_sha256_digest<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    value.strip_prefix(prefix).filter(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn opaque_sha256_handle(value: &str, prefix: &str) -> bool {
    opaque_sha256_digest(value, prefix).is_some()
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

fn is_opaque_future_role(role: &SccmRole) -> bool {
    matches!(role, SccmRole::Unknown(value)
        if opaque_sha256_handle(value, "cmtraceopen.role.sha256.v1:"))
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
        Some(SccmRotation::Timestamped(value)) => format!("0-timestamped-{value}"),
        Some(SccmRotation::Numbered(value)) => {
            format!("1-numbered-{:010}", u32::MAX - value)
        }
        Some(SccmRotation::LoUnderscore) => "2-lo-underscore".to_owned(),
        Some(SccmRotation::Current) => "3-current".to_owned(),
        Some(SccmRotation::Unknown(_)) => "4-unknown".to_owned(),
        None => "5-not-applicable".to_owned(),
    }
}

#[derive(Debug)]
enum PreservedJsonValue {
    Unsigned(u64),
    String(String),
    Array(Vec<Self>),
    Object(Vec<(String, Self)>),
    Other,
}

struct PreservedJsonValueVisitor;

impl<'de> Visitor<'de> for PreservedJsonValueVisitor {
    type Value = PreservedJsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("any JSON value while preserving duplicate object keys")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(PreservedJsonValue::Other)
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(PreservedJsonValue::Other)
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(PreservedJsonValue::Unsigned(value))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(PreservedJsonValue::Other)
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(PreservedJsonValue::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(PreservedJsonValue::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(PreservedJsonValue::Other)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(PreservedJsonValue::Other)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(Self)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element()? {
            values.push(value);
        }
        Ok(PreservedJsonValue::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut fields = Vec::new();
        while let Some(name) = map.next_key()? {
            fields.push((name, map.next_value()?));
        }
        Ok(PreservedJsonValue::Object(fields))
    }
}

impl<'de> Deserialize<'de> for PreservedJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(PreservedJsonValueVisitor)
    }
}

#[derive(Default)]
struct OpaqueExtensionTotals {
    count: usize,
    bytes: usize,
}

impl OpaqueExtensionTotals {
    fn add(&mut self, name: &str, value: &str) -> Result<(), SccmServerIntakeError> {
        self.count = self
            .count
            .checked_add(1)
            .ok_or(SccmServerIntakeError::ManifestLimitExceeded)?;
        self.bytes = self
            .bytes
            .checked_add(name.len())
            .and_then(|bytes| bytes.checked_add(value.len()))
            .ok_or(SccmServerIntakeError::ManifestLimitExceeded)?;
        if self.count > MAX_SCCM_SERVER_TOTAL_OPAQUE_EXTENSIONS
            || self.bytes > MAX_SCCM_SERVER_TOTAL_OPAQUE_EXTENSION_BYTES
        {
            return Err(SccmServerIntakeError::ManifestLimitExceeded);
        }
        Ok(())
    }
}

fn preflight_server_manifest_extensions(manifest_json: &str) -> Result<(), SccmServerIntakeError> {
    let document: PreservedJsonValue = serde_json::from_str(manifest_json)
        .map_err(|_| SccmServerIntakeError::MalformedManifest)?;
    let PreservedJsonValue::Object(manifest) = &document else {
        return Err(SccmServerIntakeError::MalformedManifest);
    };
    validate_unique_object_fields(manifest, SccmServerIntakeError::MalformedManifest)?;
    if !matches!(
        preserved_field(manifest, "sccmManifestVersion"),
        Some(PreservedJsonValue::Unsigned(1))
    ) {
        return Ok(());
    }
    let mut totals = OpaqueExtensionTotals::default();
    validate_preserved_extensions(
        manifest,
        RawServerManifest::KNOWN_FIELDS,
        SccmServerIntakeError::MalformedManifest,
        &mut totals,
    )?;

    if let Some(PreservedJsonValue::Object(privacy)) = preserved_field(manifest, "privacy") {
        validate_unique_object_fields(privacy, SccmServerIntakeError::MalformedManifest)?;
        validate_preserved_extensions(
            privacy,
            RawServerPrivacy::KNOWN_FIELDS,
            SccmServerIntakeError::MalformedManifest,
            &mut totals,
        )?;
    }
    if let Some(PreservedJsonValue::Object(topology)) = preserved_field(manifest, "topology") {
        validate_unique_object_fields(topology, SccmServerIntakeError::InvalidTopology)?;
        validate_preserved_extensions(
            topology,
            RawServerTopology::KNOWN_FIELDS,
            SccmServerIntakeError::InvalidTopology,
            &mut totals,
        )?;
    }
    if let Some(PreservedJsonValue::Array(artifacts)) = preserved_field(manifest, "artifacts") {
        if artifacts.len() > MAX_SCCM_SERVER_MANIFEST_ARTIFACTS {
            return Err(SccmServerIntakeError::ManifestLimitExceeded);
        }
        for artifact in artifacts {
            let PreservedJsonValue::Object(artifact) = artifact else {
                continue;
            };
            validate_unique_object_fields(artifact, SccmServerIntakeError::InvalidArtifact)?;
            validate_preserved_extensions(
                artifact,
                RawServerArtifact::KNOWN_FIELDS,
                SccmServerIntakeError::InvalidArtifact,
                &mut totals,
            )?;
            for (field, known) in [
                ("workflowSubject", RawWorkflowSubject::KNOWN_FIELDS),
                (
                    "configuredPathProvenance",
                    RawConfiguredPathProvenance::KNOWN_FIELDS,
                ),
                ("rotation", RawServerRotation::KNOWN_FIELDS),
                ("collectionLimit", RawCollectionLimit::KNOWN_FIELDS),
            ] {
                if let Some(PreservedJsonValue::Object(nested)) = preserved_field(artifact, field) {
                    validate_unique_object_fields(nested, SccmServerIntakeError::InvalidArtifact)?;
                    validate_preserved_extensions(
                        nested,
                        known,
                        SccmServerIntakeError::InvalidArtifact,
                        &mut totals,
                    )?;
                }
            }
        }
    }
    Ok(())
}

fn validate_unique_object_fields(
    object: &[(String, PreservedJsonValue)],
    scope_error: SccmServerIntakeError,
) -> Result<(), SccmServerIntakeError> {
    let mut seen = BTreeSet::new();
    if object.iter().any(|(name, _)| !seen.insert(name.as_str())) {
        return Err(scope_error);
    }
    Ok(())
}

fn preserved_field<'a>(
    object: &'a [(String, PreservedJsonValue)],
    name: &str,
) -> Option<&'a PreservedJsonValue> {
    object
        .iter()
        .find_map(|(field, value)| (field == name).then_some(value))
}

fn validate_preserved_extensions(
    object: &[(String, PreservedJsonValue)],
    known_fields: &[&str],
    scope_error: SccmServerIntakeError,
    totals: &mut OpaqueExtensionTotals,
) -> Result<(), SccmServerIntakeError> {
    let mut seen = BTreeSet::new();
    let mut count = 0usize;
    let mut bytes = 0usize;
    for (name, value) in object {
        if known_fields.contains(&name.as_str()) {
            continue;
        }
        let PreservedJsonValue::String(value) = value else {
            return Err(scope_error);
        };
        if !seen.insert(name.as_str())
            || !safe_opaque_extension_name(name)
            || !opaque_sha256_handle(value, "cmtraceopen.extension.sha256.v1:")
        {
            return Err(scope_error);
        }
        count += 1;
        bytes += name.len() + value.len();
        if count > MAX_SCCM_SERVER_OPAQUE_EXTENSIONS
            || bytes > MAX_SCCM_SERVER_OPAQUE_EXTENSION_BYTES_PER_SCOPE
        {
            return Err(scope_error);
        }
        totals.add(name, value)?;
    }
    Ok(())
}

macro_rules! define_raw_server_wire {
    (
        struct $name:ident {
            $(
                $(#[$field_meta:meta])*
                $wire_name:literal => $field_name:ident: $field_type:ty
            ),* $(,)?
        }
    ) => {
        #[derive(Debug, Deserialize)]
        struct $name {
            $(
                $(#[$field_meta])*
                #[serde(rename = $wire_name)]
                $field_name: $field_type,
            )*
            #[serde(flatten)]
            extensions: BTreeMap<String, Value>,
        }

        impl $name {
            const KNOWN_FIELDS: &'static [&'static str] = &[$($wire_name),*];
        }
    };
}

define_raw_server_wire! {
    struct RawServerManifest {
        "sccmManifestVersion" => sccm_manifest_version: u32,
        #[serde(default)]
        "syntheticFixture" => synthetic_fixture: bool,
        "proposalOnly" => proposal_only: Option<bool>,
        "privacy" => privacy: Option<RawServerPrivacy>,
        "bundleRole" => bundle_role: String,
        "topology" => topology: RawServerTopology,
        "inputOrderIsDeliberatelyUnsorted" => input_order_is_deliberately_unsorted: Option<bool>,
        "artifacts" => artifacts: Vec<RawServerArtifact>,
    }
}

define_raw_server_wire! {
    struct RawServerPrivacy {
        "synthetic" => synthetic: bool,
        "rawPaths" => raw_paths: String,
    }
}

define_raw_server_wire! {
    struct RawServerTopology {
        "captureHost" => capture_host: String,
        "siteCode" => site_code: String,
        "rolesObserved" => roles_observed: Vec<SccmRole>,
    }
}

define_raw_server_wire! {
    struct RawServerArtifact {
        "artifactId" => artifact_id: String,
        "producerRole" => producer_role: SccmRole,
        "producerHostHandle" => producer_host_handle: Option<String>,
        "workflowSubject" => workflow_subject: Option<RawWorkflowSubject>,
        "sourceId" => source_id: String,
        "sourceKind" => source_kind: String,
        "sourceVersion" => source_version: Option<String>,
        "originalPath" => original_path: String,
        "originalBasename" => original_basename: String,
        "configuredPathProvenance" => configured_path_provenance: RawConfiguredPathProvenance,
        "defaultCandidateState" => default_candidate_state: Option<String>,
        "rotation" => rotation: RawServerRotation,
        "captureState" => capture_state: SccmCoverageState,
        "collectionDetail" => collection_detail: Option<String>,
        "skipReason" => skip_reason: Option<String>,
        "unsupportedReason" => unsupported_reason: Option<String>,
        "encoding" => encoding: Option<String>,
        "collectionLimit" => collection_limit: Option<RawCollectionLimit>,
        "truncated" => truncated: Option<bool>,
        "fragmentComplete" => fragment_complete: Option<bool>,
        "collectedUtc" => collected_utc: String,
        "relativePath" => relative_path: Option<String>,
        "bytesCopied" => bytes_copied: u64,
    }
}

define_raw_server_wire! {
    struct RawWorkflowSubject {
        "role" => role: SccmRole,
        "instanceHandle" => instance_handle: Option<String>,
        "basis" => basis: Option<String>,
    }
}

define_raw_server_wire! {
    struct RawConfiguredPathProvenance {
        "state" => state: String,
        "pathClass" => path_class: Option<String>,
        "pathFingerprint" => path_fingerprint: String,
    }
}

define_raw_server_wire! {
    struct RawServerRotation {
        "kind" => kind: String,
        "value" => value: Option<Value>,
        "lineageId" => lineage_id: String,
    }
}

define_raw_server_wire! {
    struct RawCollectionLimit {
        "byteLimit" => byte_limit: u64,
        "limitApplied" => limit_applied: bool,
    }
}

#[cfg(test)]
mod artifact_family_integrity_key_tests {
    use super::*;

    #[test]
    fn artifact_family_integrity_keys_match_the_frozen_serialized_mapping() {
        let cases = [
            (SccmArtifactFamily::ClientSetup, "clientSetup"),
            (SccmArtifactFamily::ClientHealth, "clientHealth"),
            (SccmArtifactFamily::ClientIdentity, "clientIdentity"),
            (SccmArtifactFamily::ClientLocation, "clientLocation"),
            (SccmArtifactFamily::ClientPolicy, "clientPolicy"),
            (SccmArtifactFamily::ClientContent, "clientContent"),
            (SccmArtifactFamily::ClientApplication, "clientApplication"),
            (SccmArtifactFamily::ClientUpdates, "clientUpdates"),
            (SccmArtifactFamily::ClientTaskSequence, "clientTaskSequence"),
            (SccmArtifactFamily::SiteComponent, "siteComponent"),
            (SccmArtifactFamily::SiteStatus, "siteStatus"),
            (SccmArtifactFamily::ManagementPoint, "managementPoint"),
            (SccmArtifactFamily::DistributionPoint, "distributionPoint"),
            (
                SccmArtifactFamily::SoftwareUpdatePoint,
                "softwareUpdatePoint",
            ),
            (SccmArtifactFamily::Hierarchy, "hierarchy"),
            (SccmArtifactFamily::Provider, "provider"),
            (SccmArtifactFamily::AdminService, "adminService"),
            (
                SccmArtifactFamily::Unknown("opaqueFamily".to_owned()),
                "opaqueFamily",
            ),
        ];

        for (family, expected) in cases {
            assert_eq!(artifact_family_integrity_key(&family), expected);
            assert_eq!(
                serde_json::to_value(family).expect("family must serialize"),
                Value::String(expected.to_owned())
            );
        }
    }
}

#[cfg(test)]
mod opaque_extension_boundary_tests {
    use super::*;

    const EXPECTED_MAX_TOTAL_OPAQUE_EXTENSIONS: usize = 1_024;

    fn valid_extension(name: &str, ordinal: usize) -> SccmServerOpaqueExtension {
        SccmServerOpaqueExtension {
            schema_version: 1,
            name: name.to_owned(),
            value: format!("cmtraceopen.extension.sha256.v1:{ordinal:064x}"),
        }
    }

    #[test]
    fn opaque_extension_validation_distinguishes_unsupported_schema_version() {
        let extension = SccmServerOpaqueExtension {
            schema_version: 2,
            name: "x-cmtraceopen-opaque-v1-safe".to_owned(),
            value: "cmtraceopen.extension.sha256.v1:0000000000000000000000000000000000000000000000000000000000000001"
                .to_owned(),
        };

        assert_eq!(
            extension.validate(),
            Err(SccmServerOpaqueExtensionError::UnsupportedSchemaVersion { schema_version: 2 })
        );
    }

    #[test]
    fn raw_manifest_known_fields_match_the_generated_wire_contracts() {
        assert_eq!(
            RawServerManifest::KNOWN_FIELDS,
            [
                "sccmManifestVersion",
                "syntheticFixture",
                "proposalOnly",
                "privacy",
                "bundleRole",
                "topology",
                "inputOrderIsDeliberatelyUnsorted",
                "artifacts",
            ]
        );
        assert_eq!(RawServerPrivacy::KNOWN_FIELDS, ["synthetic", "rawPaths"]);
        assert_eq!(
            RawServerTopology::KNOWN_FIELDS,
            ["captureHost", "siteCode", "rolesObserved"]
        );
        assert_eq!(
            RawWorkflowSubject::KNOWN_FIELDS,
            ["role", "instanceHandle", "basis"]
        );
        assert_eq!(
            RawConfiguredPathProvenance::KNOWN_FIELDS,
            ["state", "pathClass", "pathFingerprint"]
        );
        assert_eq!(
            RawServerRotation::KNOWN_FIELDS,
            ["kind", "value", "lineageId"]
        );
        assert_eq!(
            RawCollectionLimit::KNOWN_FIELDS,
            ["byteLimit", "limitApplied"]
        );
        assert_eq!(
            RawServerArtifact::KNOWN_FIELDS,
            [
                "artifactId",
                "producerRole",
                "producerHostHandle",
                "workflowSubject",
                "sourceId",
                "sourceKind",
                "sourceVersion",
                "originalPath",
                "originalBasename",
                "configuredPathProvenance",
                "defaultCandidateState",
                "rotation",
                "captureState",
                "collectionDetail",
                "skipReason",
                "unsupportedReason",
                "encoding",
                "collectionLimit",
                "truncated",
                "fragmentComplete",
                "collectedUtc",
                "relativePath",
                "bytesCopied",
            ]
        );
    }

    fn empty_assessment() -> SccmServerIntakeAssessment {
        assess_server_intake(
            r#"{
                "sccmManifestVersion": 1,
                "bundleRole": "server",
                "topology": {
                    "captureHost": "cmtraceopen.host.sha256.v1:0000000000000000000000000000000000000000000000000000000000000001",
                    "siteCode": "cmtraceopen.site.sha256.v1:0000000000000000000000000000000000000000000000000000000000000001",
                    "rolesObserved": ["managementPoint"]
                },
                "artifacts": []
            }"#,
            &[],
        )
        .expect("minimal production assessment is valid")
    }

    #[test]
    fn opaque_extension_serialize_rejects_unsafe_internal_mutation() {
        let extension = SccmServerOpaqueExtension {
            schema_version: 1,
            name: "real-user-extension".to_owned(),
            value: "Real User <real.user@example.com>".repeat(512),
        };

        assert!(
            serde_json::to_string(&extension).is_err(),
            "unsafe identity-bearing extensions cannot cross public serialization"
        );
    }

    #[test]
    fn opaque_extension_public_construction_and_serde_are_validated() {
        assert_eq!(
            SccmServerOpaqueExtension::try_new(
                "real-user-extension",
                "cmtraceopen.extension.sha256.v1:0000000000000000000000000000000000000000000000000000000000000001",
            ),
            Err(SccmServerOpaqueExtensionError::InvalidName)
        );
        let extension = SccmServerOpaqueExtension::try_new(
            "x-cmtraceopen-opaque-v1-safe",
            "cmtraceopen.extension.sha256.v1:0000000000000000000000000000000000000000000000000000000000000001",
        )
        .expect("safe extension construction succeeds");
        let public = serde_json::to_value(&extension).expect("safe extension serializes");
        let round_trip = serde_json::from_value::<SccmServerOpaqueExtension>(public)
            .expect("safe extension deserializes");
        assert_eq!(round_trip, extension);

        for invalid in [
            serde_json::json!({
                "schemaVersion": 2,
                "name": "x-cmtraceopen-opaque-v1-safe",
                "value": "cmtraceopen.extension.sha256.v1:0000000000000000000000000000000000000000000000000000000000000001",
            }),
            serde_json::json!({
                "schemaVersion": 1,
                "name": "real-user-extension",
                "value": "cmtraceopen.extension.sha256.v1:0000000000000000000000000000000000000000000000000000000000000001",
            }),
            serde_json::json!({
                "schemaVersion": 1,
                "name": "x-cmtraceopen-opaque-v1-safe",
                "value": "Real User <real.user@example.com>",
            }),
            serde_json::json!({
                "schemaVersion": 1,
                "name": "x-cmtraceopen-opaque-v1-safe",
                "value": "cmtraceopen.extension.sha256.v1:0000000000000000000000000000000000000000000000000000000000000001",
                "extra": "cmtraceopen.extension.sha256.v1:0000000000000000000000000000000000000000000000000000000000000002",
            }),
        ] {
            assert!(serde_json::from_value::<SccmServerOpaqueExtension>(invalid).is_err());
        }
    }

    #[test]
    fn assessment_serialize_rejects_duplicate_or_unsorted_extensions() {
        let mut duplicate = empty_assessment();
        duplicate.extensions = vec![
            valid_extension("x-cmtraceopen-opaque-v1-same", 1),
            valid_extension("x-cmtraceopen-opaque-v1-same", 2),
        ];
        assert!(serde_json::to_string(&duplicate).is_err());

        let mut unsorted = empty_assessment();
        unsorted.extensions = vec![
            valid_extension("x-cmtraceopen-opaque-v1-zulu", 3),
            valid_extension("x-cmtraceopen-opaque-v1-alpha", 4),
        ];
        assert!(serde_json::to_string(&unsorted).is_err());
    }

    #[test]
    fn assessment_serialize_bounds_per_scope_and_aggregate_extensions() {
        assert_eq!(
            EXPECTED_MAX_TOTAL_OPAQUE_EXTENSIONS, MAX_SCCM_SERVER_TOTAL_OPAQUE_EXTENSIONS,
            "the pinned aggregate extension bound must track the production contract"
        );
        let mut per_scope = empty_assessment();
        per_scope.extensions = (0..=MAX_SCCM_SERVER_OPAQUE_EXTENSIONS)
            .map(|ordinal| {
                valid_extension(
                    &format!("x-cmtraceopen-opaque-v1-item-{ordinal:02}"),
                    ordinal,
                )
            })
            .collect();
        assert!(serde_json::to_string(&per_scope).is_err());

        let mut aggregate = empty_assessment();
        let mut artifact = SccmServerArtifactAssessment {
            artifact_id: "unused".to_owned(),
            producer_role: SccmRole::ManagementPoint,
            producer_host_handle: None,
            workflow_subject_role: None,
            workflow_subject_handle: None,
            source_id: "unused".to_owned(),
            source_kind: "unused".to_owned(),
            family: SccmArtifactFamily::Unknown("unused".to_owned()),
            original_basename: None,
            rotation: None,
            rotation_lineage_handle: "unused".to_owned(),
            state: SccmCoverageState::Unsupported,
            configured_path_state: SccmServerConfiguredPathState::Supplied,
            configured_path_class: None,
            path_fingerprint: "unused".to_owned(),
            source_version: None,
            profile_eligible: false,
            collected_at_utc: "2026-07-30T00:00:00Z".to_owned(),
            relative_path: None,
            bytes_copied: 0,
            content_sha256: None,
            truncated: None,
            fragment_complete: None,
            capture_provenance: None,
            parser_eligible: false,
            extensions: (0..MAX_SCCM_SERVER_OPAQUE_EXTENSIONS)
                .map(|ordinal| {
                    valid_extension(
                        &format!("x-cmtraceopen-opaque-v1-item-{ordinal:02}"),
                        ordinal,
                    )
                })
                .collect(),
            workflow_subject_extensions: Vec::new(),
            configured_path_provenance_extensions: Vec::new(),
            rotation_extensions: Vec::new(),
            collection_limit_extensions: Vec::new(),
        };
        for ordinal in 0..=EXPECTED_MAX_TOTAL_OPAQUE_EXTENSIONS / MAX_SCCM_SERVER_OPAQUE_EXTENSIONS
        {
            artifact.artifact_id = format!("unused-{ordinal}");
            aggregate.artifacts.push(artifact.clone());
        }
        assert!(serde_json::to_string(&aggregate).is_err());
    }
}
