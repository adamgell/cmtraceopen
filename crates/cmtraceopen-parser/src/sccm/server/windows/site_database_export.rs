//! Explicit, coverage-only SCCM site-database export contract.
//!
//! This module accepts operator-supplied bytes only. It does not participate in
//! server intake, source discovery, collection, or semantic analysis.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::sccm::json_contract::{
    field, object_fields, parse_preserved_json, reject_duplicate_object_keys,
    JsonContractPreflightError, PreservedJsonValue,
};

pub const MAX_SCCM_SITE_DATABASE_EXPORT_BYTES: usize = 1_048_576;

const CONTRACT_ID: &str = "sccm-site-database-export";
const EXPORT_PROFILE_ID: &str = "sccm-site-database-export-v1";
const AUTHORIZATION_ID_PREFIX: &str = "cmtraceopen.sccm.dbexport.authorization.sha256.v1:";
const AUTHORIZER_HANDLE_PREFIX: &str = "cmtraceopen.operator.sha256.v1:";
const SITE_HANDLE_PREFIX: &str = "cmtraceopen.site.sha256.v1:";
const DATABASE_HANDLE_PREFIX: &str = "cmtraceopen.database.sha256.v1:";
const EXPORTER_HOST_HANDLE_PREFIX: &str = "cmtraceopen.host.sha256.v1:";
const SNAPSHOT_ID_PREFIX: &str = "cmtraceopen.sccm.dbexport.snapshot.sha256.v1:";
const MAX_SUMMARY_COUNT: u64 = 1_000_000_000;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SccmSiteDatabaseExportError {
    #[error("site-database export input exceeds the contract limit")]
    InputLimitExceeded,
    #[error("site-database export is not a valid JSON document")]
    MalformedDocument,
    #[error("site-database export contains a duplicate JSON key")]
    DuplicateJsonKey,
    #[error("site-database export schema version {found} is unsupported")]
    UnsupportedSchemaVersion { found: u32 },
    #[error("site-database export contains an unexpected field")]
    UnexpectedField,
    #[error("site-database export does not satisfy the fixed contract literals")]
    ContractViolation,
    #[error("site-database export authorization is invalid or inconsistent")]
    AuthorizationContractViolation,
    #[error("site-database export provenance is invalid or inconsistent")]
    ProvenanceContractViolation,
    #[error("site-database export snapshot is invalid or inconsistent")]
    SnapshotContractViolation,
    #[error("site-database export contains an invalid opaque handle")]
    InvalidOpaqueHandle,
    #[error("site-database export contains an invalid timestamp")]
    InvalidTimestamp,
    #[error("site-database export contains an out-of-range aggregate count")]
    InvalidSummaryCount,
    #[error("site-database export integrity digest does not match")]
    IntegrityMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmSiteDatabaseExportCoverageState {
    Captured,
    Partial,
    AccessDenied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmSiteDatabaseExportEvidenceDisposition {
    CoverageOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmSiteDatabaseExportCoverage {
    state: SccmSiteDatabaseExportCoverageState,
    gate_code: SccmSiteDatabaseExportCoverageState,
}

impl SccmSiteDatabaseExportCoverage {
    pub fn state(&self) -> SccmSiteDatabaseExportCoverageState {
        self.state
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmSiteDatabaseExportAssessment {
    contract_id: &'static str,
    schema_version: u32,
    coverage: SccmSiteDatabaseExportCoverage,
    #[serde(rename = "disposition")]
    evidence_disposition: SccmSiteDatabaseExportEvidenceDisposition,
}

impl SccmSiteDatabaseExportAssessment {
    pub fn coverage(&self) -> &SccmSiteDatabaseExportCoverage {
        &self.coverage
    }

    pub fn evidence_disposition(&self) -> SccmSiteDatabaseExportEvidenceDisposition {
        self.evidence_disposition
    }
}

/// Assesses one explicit operator-supplied site-database export envelope.
pub fn assess_sccm_site_database_export(
    input: &[u8],
) -> Result<SccmSiteDatabaseExportAssessment, SccmSiteDatabaseExportError> {
    if input.len() > MAX_SCCM_SITE_DATABASE_EXPORT_BYTES {
        return Err(SccmSiteDatabaseExportError::InputLimitExceeded);
    }
    let input =
        std::str::from_utf8(input).map_err(|_| SccmSiteDatabaseExportError::MalformedDocument)?;
    let preserved = parse_preserved_json(input).map_err(map_preflight_error)?;
    reject_duplicate_object_keys(&preserved).map_err(map_preflight_error)?;
    let root = object_fields(&preserved).ok_or(SccmSiteDatabaseExportError::MalformedDocument)?;
    if field(root, "snapshots").is_some() {
        return Err(SccmSiteDatabaseExportError::SnapshotContractViolation);
    }
    let schema_version = match field(root, "schemaVersion") {
        Some(PreservedJsonValue::Unsigned(found)) => {
            u32::try_from(*found).map_err(|_| SccmSiteDatabaseExportError::MalformedDocument)?
        }
        _ => return Err(SccmSiteDatabaseExportError::MalformedDocument),
    };
    if schema_version != 1 {
        return Err(SccmSiteDatabaseExportError::UnsupportedSchemaVersion {
            found: schema_version,
        });
    }

    let envelope: WireEnvelope = serde_json::from_str(input).map_err(map_wire_error)?;
    validate_envelope(&envelope)?;
    validate_integrity(&envelope)?;

    let state = match envelope.capture_state {
        WireCaptureState::Captured => SccmSiteDatabaseExportCoverageState::Captured,
        WireCaptureState::Partial => SccmSiteDatabaseExportCoverageState::Partial,
        WireCaptureState::AccessDenied => SccmSiteDatabaseExportCoverageState::AccessDenied,
    };
    Ok(SccmSiteDatabaseExportAssessment {
        contract_id: CONTRACT_ID,
        schema_version: envelope.schema_version,
        coverage: SccmSiteDatabaseExportCoverage {
            state,
            gate_code: state,
        },
        evidence_disposition: SccmSiteDatabaseExportEvidenceDisposition::CoverageOnly,
    })
}

fn map_preflight_error(error: JsonContractPreflightError) -> SccmSiteDatabaseExportError {
    match error {
        JsonContractPreflightError::Malformed => SccmSiteDatabaseExportError::MalformedDocument,
        JsonContractPreflightError::DuplicateKey => SccmSiteDatabaseExportError::DuplicateJsonKey,
    }
}

fn map_wire_error(error: serde_json::Error) -> SccmSiteDatabaseExportError {
    if error.to_string().starts_with("unknown field") {
        SccmSiteDatabaseExportError::UnexpectedField
    } else {
        SccmSiteDatabaseExportError::MalformedDocument
    }
}

fn validate_envelope(envelope: &WireEnvelope) -> Result<(), SccmSiteDatabaseExportError> {
    if envelope.contract_id != CONTRACT_ID || envelope.intent != WireIntent::CaptureMore {
        return Err(SccmSiteDatabaseExportError::ContractViolation);
    }
    if envelope.provenance.export_profile_id != EXPORT_PROFILE_ID {
        return Err(SccmSiteDatabaseExportError::ProvenanceContractViolation);
    }
    validate_authorization(&envelope.authorization)?;
    if !matches!(
        (envelope.capture_state, envelope.authorization.decision),
        (
            WireCaptureState::Captured | WireCaptureState::Partial,
            WireAuthorizationDecision::Granted
        ) | (
            WireCaptureState::AccessDenied,
            WireAuthorizationDecision::Denied
        )
    ) {
        return Err(SccmSiteDatabaseExportError::AuthorizationContractViolation);
    }
    validate_provenance(&envelope.provenance)?;
    validate_snapshot(envelope.capture_state, envelope.snapshot.as_ref())?;
    Ok(())
}

fn validate_authorization(
    authorization: &WireAuthorization,
) -> Result<(), SccmSiteDatabaseExportError> {
    if !opaque_handle(&authorization.authorization_id, AUTHORIZATION_ID_PREFIX)
        || !opaque_handle(&authorization.authorizer_handle, AUTHORIZER_HANDLE_PREFIX)
    {
        return Err(SccmSiteDatabaseExportError::InvalidOpaqueHandle);
    }
    validate_utc(&authorization.authorized_at_utc)?;
    if authorization.scope != WireAuthorizationScope::CoverageOnlySccmSiteDatabaseExport {
        return Err(SccmSiteDatabaseExportError::AuthorizationContractViolation);
    }
    Ok(())
}

fn validate_provenance(provenance: &WireProvenance) -> Result<(), SccmSiteDatabaseExportError> {
    if !opaque_handle(&provenance.site_handle, SITE_HANDLE_PREFIX)
        || !opaque_handle(&provenance.database_handle, DATABASE_HANDLE_PREFIX)
        || !opaque_handle(
            &provenance.exporter_host_handle,
            EXPORTER_HOST_HANDLE_PREFIX,
        )
    {
        return Err(SccmSiteDatabaseExportError::InvalidOpaqueHandle);
    }
    let started = validate_utc(&provenance.export_started_utc)?;
    let completed = validate_utc(&provenance.export_completed_utc)?;
    if completed < started {
        return Err(SccmSiteDatabaseExportError::ProvenanceContractViolation);
    }
    Ok(())
}

fn validate_snapshot(
    capture_state: WireCaptureState,
    snapshot: Option<&WireSnapshot>,
) -> Result<(), SccmSiteDatabaseExportError> {
    match (capture_state, snapshot) {
        (WireCaptureState::AccessDenied, None) => Ok(()),
        (WireCaptureState::Captured, Some(snapshot)) if snapshot.complete => {
            validate_snapshot_contents(snapshot)
        }
        (WireCaptureState::Partial, Some(snapshot)) if !snapshot.complete => {
            validate_snapshot_contents(snapshot)
        }
        _ => Err(SccmSiteDatabaseExportError::SnapshotContractViolation),
    }
}

fn validate_snapshot_contents(snapshot: &WireSnapshot) -> Result<(), SccmSiteDatabaseExportError> {
    if !opaque_handle(&snapshot.snapshot_id, SNAPSHOT_ID_PREFIX) {
        return Err(SccmSiteDatabaseExportError::InvalidOpaqueHandle);
    }
    validate_utc(&snapshot.captured_at_utc)?;
    if [
        snapshot.summary.active_client_count,
        snapshot.summary.managed_device_count,
        snapshot.summary.package_count,
        snapshot.summary.deployment_count,
    ]
    .into_iter()
    .any(|count| count > MAX_SUMMARY_COUNT)
    {
        return Err(SccmSiteDatabaseExportError::InvalidSummaryCount);
    }
    Ok(())
}

fn validate_utc(value: &str) -> Result<DateTime<Utc>, SccmSiteDatabaseExportError> {
    if !value.ends_with('Z') {
        return Err(SccmSiteDatabaseExportError::InvalidTimestamp);
    }
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|_| SccmSiteDatabaseExportError::InvalidTimestamp)
}

fn opaque_handle(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn validate_integrity(envelope: &WireEnvelope) -> Result<(), SccmSiteDatabaseExportError> {
    if envelope.integrity.algorithm != WireIntegrityAlgorithm::Sha256
        || !lowercase_hex_digest(&envelope.integrity.canonical_payload_sha256)
    {
        return Err(SccmSiteDatabaseExportError::IntegrityMismatch);
    }
    let canonical = CanonicalPayload {
        schema_version: envelope.schema_version,
        contract_id: &envelope.contract_id,
        intent: envelope.intent,
        capture_state: envelope.capture_state,
        authorization: &envelope.authorization,
        provenance: &envelope.provenance,
        snapshot: envelope.snapshot.as_ref(),
    };
    let material = serde_json::to_vec(&canonical)
        .map_err(|_| SccmSiteDatabaseExportError::MalformedDocument)?;
    let computed = lowercase_hex(Sha256::digest(material).as_slice());
    // The digest binds an integrity record, not a secret. Deterministic byte
    // equality is sufficient and deliberately does not claim constant time.
    if computed.as_bytes() != envelope.integrity.canonical_payload_sha256.as_bytes() {
        return Err(SccmSiteDatabaseExportError::IntegrityMismatch);
    }
    Ok(())
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn lowercase_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| {
            byte.is_ascii_digit() || (byte.is_ascii_lowercase() && byte.is_ascii_hexdigit())
        })
}

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
enum WireIntent {
    CaptureMore,
}

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
enum WireCaptureState {
    Captured,
    Partial,
    AccessDenied,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireEnvelope {
    schema_version: u32,
    contract_id: String,
    intent: WireIntent,
    capture_state: WireCaptureState,
    authorization: WireAuthorization,
    provenance: WireProvenance,
    snapshot: Option<WireSnapshot>,
    integrity: WireIntegrity,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireAuthorization {
    authorization_id: String,
    authorizer_handle: String,
    authorized_at_utc: String,
    decision: WireAuthorizationDecision,
    scope: WireAuthorizationScope,
}

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
enum WireAuthorizationDecision {
    Granted,
    Denied,
}

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
enum WireAuthorizationScope {
    CoverageOnlySccmSiteDatabaseExport,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireProvenance {
    site_handle: String,
    database_handle: String,
    exporter_host_handle: String,
    export_profile_id: String,
    export_started_utc: String,
    export_completed_utc: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireSnapshot {
    snapshot_id: String,
    captured_at_utc: String,
    complete: bool,
    summary: WireSummary,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireSummary {
    active_client_count: u64,
    managed_device_count: u64,
    package_count: u64,
    deployment_count: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireIntegrity {
    algorithm: WireIntegrityAlgorithm,
    canonical_payload_sha256: String,
}

#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
enum WireIntegrityAlgorithm {
    Sha256,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalPayload<'a> {
    schema_version: u32,
    contract_id: &'a str,
    intent: WireIntent,
    capture_state: WireCaptureState,
    authorization: &'a WireAuthorization,
    provenance: &'a WireProvenance,
    snapshot: Option<&'a WireSnapshot>,
}
