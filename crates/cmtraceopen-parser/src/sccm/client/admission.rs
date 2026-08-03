//! Crate-private sealing of canonical SCCM client evidence.
//!
//! Raw payload bytes exist only while this constructor verifies their digest
//! and normalizes their CCM logical records. Reducers receive the resulting
//! immutable-by-API capability, never bytes or caller-supplied evidence.

// This is deliberately a crate-private shared interface that lands before
// workflow reducers. No production reducer owns it in this slice, so rustc
// cannot yet observe a call site; retaining the lint allowance here avoids
// weakening workspace-wide warning policy while preserving the review gate.
#![allow(dead_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Write},
};

use encoding_rs::{UTF_16BE, UTF_16LE, UTF_8, WINDOWS_1252};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::parser::ccm::scan_logical_records_bounded;
use crate::sccm::evidence::SccmRawEvidenceSnapshot;
use crate::sccm::{
    SccmArtifact, SccmCoverageState, SccmEvidence, SccmExtractionProfile,
    SccmExtractionProfileMaturity, SccmRole, SccmTimeOrderingState,
    SCCM_EXPERIMENTAL_KEY_PROFILE_ID,
};

use super::{
    assess_client_intake, SccmClientIntakeAssessment, SccmClientIntakeBundle,
    SccmClientIntakeError, SccmClientIntakeFragment, MAX_SCCM_CLIENT_INTAKE_ARTIFACTS,
};

/// Maximum raw bytes decoded from one client payload at the parser admission
/// boundary. This is intentionally below the native physical-file cap: the
/// pure parser must remain safe for wasm and non-native callers too.
pub(crate) const MAX_SCCM_CLIENT_ADMISSION_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;
/// Maximum raw bytes admitted across one client evidence bundle.
pub(crate) const MAX_SCCM_CLIENT_ADMISSION_TOTAL_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
/// Maximum logical CCM records retained from one admitted client bundle.
pub(crate) const MAX_SCCM_CLIENT_ADMISSION_LOGICAL_RECORDS: usize = 4_096;
/// Maximum projected evidence bytes retained for one admitted client bundle.
pub(crate) const MAX_SCCM_CLIENT_ADMISSION_RETAINED_EVIDENCE_BYTES: usize = 3 * 1024 * 1024;
/// Maximum bytes streamed into a deterministic client evidence integrity seal.
pub(crate) const MAX_SCCM_CLIENT_ADMISSION_SEAL_BYTES: usize = 4 * 1024 * 1024;

/// Raw, already-captured bytes offered to the one-shot client evidence
/// admission boundary. This is an input only: the successful capability does
/// not retain this vector or any decoded raw text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SccmClientCapturedPayload {
    pub artifact_id: String,
    pub bytes: Vec<u8>,
    pub byte_length: u64,
    pub expected_sha256: String,
}

/// The bounded evidence authority internal client reducers consume.
///
/// Its fields stay private and it deliberately implements neither serde nor a
/// public constructor. `verify_integrity` recomputes the deterministic seal so
/// a reducer can fail closed if future crate-internal code corrupts it.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SccmClientAdmittedEvidence {
    evidence: Vec<SccmEvidence>,
    source_coverage: BTreeMap<String, SccmCoverageState>,
    profiles_by_artifact: BTreeMap<String, SccmExtractionProfile>,
    integrity_seal: String,
}

impl SccmClientAdmittedEvidence {
    pub(crate) fn evidence(&self) -> Result<&[SccmEvidence], SccmClientEvidenceAdmissionError> {
        self.verify_integrity()?;
        Ok(&self.evidence)
    }

    pub(crate) fn source_coverage(
        &self,
        logical_artifact_id: &str,
    ) -> Result<Option<&SccmCoverageState>, SccmClientEvidenceAdmissionError> {
        self.verify_integrity()?;
        Ok(self.source_coverage.get(logical_artifact_id))
    }

    pub(crate) fn profile_for_artifact(
        &self,
        artifact_id: &str,
    ) -> Result<Option<&SccmExtractionProfile>, SccmClientEvidenceAdmissionError> {
        self.verify_integrity()?;
        Ok(self.profiles_by_artifact.get(artifact_id))
    }

    pub(crate) fn integrity_seal(&self) -> &str {
        &self.integrity_seal
    }

    pub(crate) fn verify_integrity(&self) -> Result<(), SccmClientEvidenceAdmissionError> {
        let recomputed = compute_integrity_seal(
            &self.evidence,
            &self.source_coverage,
            &self.profiles_by_artifact,
        )?;
        (recomputed == self.integrity_seal)
            .then_some(())
            .ok_or(SccmClientEvidenceAdmissionError::IntegrityViolation)
    }

    /// Makes workflow handling of a missing, capped, malformed, or partial
    /// source explicit. The authority never turns a coverage gap into success.
    pub(crate) fn require_captured_source(
        &self,
        logical_artifact_id: &str,
    ) -> Result<(), SccmClientEvidenceAdmissionError> {
        match self.source_coverage(logical_artifact_id)? {
            Some(SccmCoverageState::Captured) => Ok(()),
            Some(_) => Err(SccmClientEvidenceAdmissionError::SourceCoverageUnavailable),
            None => Err(SccmClientEvidenceAdmissionError::UnknownSourceGroup),
        }
    }

    #[cfg(test)]
    pub(crate) fn test_only_mutate_first_message(&mut self) {
        self.evidence[0].message.push_str(" forged");
    }

    #[cfg(test)]
    pub(crate) fn test_only_mutate_first_profile(&mut self) {
        self.profiles_by_artifact
            .values_mut()
            .next()
            .expect("test admission has one selected profile")
            .profile_id
            .push_str("-forged");
    }

    #[cfg(test)]
    pub(crate) fn test_only_duplicate_first_evidence(&mut self) {
        self.evidence.push(self.evidence[0].clone());
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum SccmClientEvidenceAdmissionError {
    #[error("client evidence admission bundle is invalid: {0}")]
    InvalidBundle(SccmClientIntakeError),
    #[error("client evidence admission assessment is not the canonical bundle projection")]
    AssessmentMutation,
    #[error("client evidence admission payload count exceeds the v1 bound")]
    PayloadLimitExceeded,
    #[error("client evidence admission payload exceeds the v1 per-payload byte cap")]
    PayloadByteLimitExceeded,
    #[error("client evidence admission aggregate payload bytes exceed the v1 cap")]
    AggregatePayloadByteLimitExceeded,
    #[error("client evidence admission contains duplicate payload artifact IDs")]
    DuplicatePayload,
    #[error("client evidence admission is missing a payload for a captured fragment")]
    MissingPayload,
    #[error("client evidence admission payload has no matching canonical captured fragment")]
    ExtraPayload,
    #[error("client evidence admission payload targets a noncaptured or incomplete fragment")]
    NonAdmissibleFragment,
    #[error("client evidence admission payload length or digest is invalid")]
    PayloadIntegrityMismatch,
    #[error("client evidence admission cannot decode the declared artifact encoding")]
    InvalidEncoding,
    #[error("client evidence admission payload has no complete CCM logical record")]
    MalformedCcm,
    #[error("client evidence admission CCM framing is incomplete or ambiguous")]
    IncompleteCcmFraming,
    #[error("client evidence admission logical record count exceeds the v1 cap")]
    LogicalRecordLimitExceeded,
    #[error("client evidence admission retained evidence exceeds the v1 byte cap")]
    RetainedEvidenceLimitExceeded,
    #[error("client evidence admission integrity seal exceeds the v1 byte cap")]
    IntegritySealLimitExceeded,
    #[error("client evidence admission record timestamp provenance is not comparable")]
    InvalidTimestampProvenance,
    #[error("client evidence admission selected an unregistered extraction profile")]
    UnregisteredProfile,
    #[error("client evidence admission produced colliding logical evidence identities")]
    CollidingEvidenceIdentity,
    #[error("client evidence admission integrity seal is invalid")]
    IntegrityViolation,
    #[error("client evidence admission source group is not declared")]
    UnknownSourceGroup,
    #[error("client evidence admission source coverage is not complete captured evidence")]
    SourceCoverageUnavailable,
}

/// Reassesses a canonical client bundle and seals the logical CCM evidence it
/// derives from each exact complete captured payload.
pub(crate) fn admit_client_evidence(
    bundle: &SccmClientIntakeBundle,
    assessment: &SccmClientIntakeAssessment,
    payloads: &[SccmClientCapturedPayload],
) -> Result<SccmClientAdmittedEvidence, SccmClientEvidenceAdmissionError> {
    if payloads.len() > MAX_SCCM_CLIENT_INTAKE_ARTIFACTS {
        return Err(SccmClientEvidenceAdmissionError::PayloadLimitExceeded);
    }
    validate_payload_budget(payloads)?;

    let canonical =
        assess_client_intake(bundle).map_err(SccmClientEvidenceAdmissionError::InvalidBundle)?;
    if canonical != *assessment {
        return Err(SccmClientEvidenceAdmissionError::AssessmentMutation);
    }

    let source_coverage = canonical
        .groups
        .iter()
        .map(|group| (group.logical_artifact_id.clone(), group.coverage.clone()))
        .collect::<BTreeMap<_, _>>();
    let eligible = canonical
        .physical_artifacts
        .iter()
        .map(|fragment| {
            (fragment.coverage == SccmCoverageState::Captured
                && fragment.fragment_complete == Some(true))
            .then_some((fragment.artifact_id.clone(), fragment))
            .ok_or(SccmClientEvidenceAdmissionError::NonAdmissibleFragment)
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;

    if eligible.len() != canonical.physical_artifacts.len() {
        return Err(SccmClientEvidenceAdmissionError::NonAdmissibleFragment);
    }
    if payloads.len() != eligible.len() {
        return Err(SccmClientEvidenceAdmissionError::MissingPayload);
    }

    let mut ordered_payloads = payloads.iter().collect::<Vec<_>>();
    ordered_payloads.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
    let mut seen_payload_ids = BTreeSet::new();
    let mut evidence = Vec::new();
    let mut profiles_by_artifact = BTreeMap::new();
    let mut evidence_ids = BTreeSet::new();
    let mut evidence_references = BTreeSet::new();
    let mut retained_evidence_bytes = 0usize;
    let mut remaining_logical_records = MAX_SCCM_CLIENT_ADMISSION_LOGICAL_RECORDS;

    for payload in ordered_payloads {
        if !seen_payload_ids.insert(payload.artifact_id.as_str()) {
            return Err(SccmClientEvidenceAdmissionError::DuplicatePayload);
        }
        let fragment = eligible
            .get(&payload.artifact_id)
            .copied()
            .ok_or(SccmClientEvidenceAdmissionError::ExtraPayload)?;
        validate_payload(payload)?;

        let profile = SccmExtractionProfile::for_version(fragment.configmgr_version.as_deref());
        if !is_registered_client_profile(&profile) {
            return Err(SccmClientEvidenceAdmissionError::UnregisteredProfile);
        }
        let content = decode_payload(payload, fragment.encoding.as_deref())?;
        let artifact = artifact_for_fragment(fragment);
        let scan = scan_logical_records_bounded(
            &content,
            &fragment.basename,
            MAX_SCCM_CLIENT_ADMISSION_LOGICAL_RECORDS,
        );
        if scan.record_limit_exceeded {
            return Err(SccmClientEvidenceAdmissionError::LogicalRecordLimitExceeded);
        }
        if !scan.complete {
            return Err(SccmClientEvidenceAdmissionError::IncompleteCcmFraming);
        }
        if scan.records.is_empty() {
            return Err(SccmClientEvidenceAdmissionError::MalformedCcm);
        }
        remaining_logical_records = remaining_logical_records
            .checked_sub(scan.records.len())
            .ok_or(SccmClientEvidenceAdmissionError::LogicalRecordLimitExceeded)?;

        for record in scan.records {
            let normalized = SccmRawEvidenceSnapshot::from_record(&artifact, record).export();
            if normalized.evidence_id != normalized.reference.entry_id
                || normalized.reference.line_start.is_none()
                || normalized.reference.line_end.is_none()
                || normalized.timestamp.ordering_state != SccmTimeOrderingState::NormalizedUtc
                || normalized.timestamp.offset_minutes.is_none()
                || normalized.timestamp.utc_millis.is_none()
            {
                return Err(SccmClientEvidenceAdmissionError::InvalidTimestampProvenance);
            }
            let reference_identity = (
                normalized.reference.artifact_id.clone(),
                normalized.reference.entry_id.clone(),
                normalized.reference.line_start,
                normalized.reference.line_end,
            );
            if !evidence_ids.insert(normalized.evidence_id.clone())
                || !evidence_references.insert(reference_identity)
            {
                return Err(SccmClientEvidenceAdmissionError::CollidingEvidenceIdentity);
            }
            retained_evidence_bytes = retained_evidence_bytes
                .checked_add(retained_evidence_size(&normalized)?)
                .ok_or(SccmClientEvidenceAdmissionError::RetainedEvidenceLimitExceeded)?;
            if retained_evidence_bytes > MAX_SCCM_CLIENT_ADMISSION_RETAINED_EVIDENCE_BYTES {
                return Err(SccmClientEvidenceAdmissionError::RetainedEvidenceLimitExceeded);
            }
            evidence.push(normalized);
        }
        profiles_by_artifact.insert(fragment.artifact_id.clone(), profile);
    }

    evidence.sort_by(compare_evidence);
    let integrity_seal =
        compute_integrity_seal(&evidence, &source_coverage, &profiles_by_artifact)?;
    Ok(SccmClientAdmittedEvidence {
        evidence,
        source_coverage,
        profiles_by_artifact,
        integrity_seal,
    })
}

fn validate_payload_budget(
    payloads: &[SccmClientCapturedPayload],
) -> Result<(), SccmClientEvidenceAdmissionError> {
    let mut total_payload_bytes = 0usize;
    for payload in payloads {
        if payload.bytes.len() > MAX_SCCM_CLIENT_ADMISSION_PAYLOAD_BYTES {
            return Err(SccmClientEvidenceAdmissionError::PayloadByteLimitExceeded);
        }
        total_payload_bytes = total_payload_bytes
            .checked_add(payload.bytes.len())
            .ok_or(SccmClientEvidenceAdmissionError::AggregatePayloadByteLimitExceeded)?;
        if total_payload_bytes > MAX_SCCM_CLIENT_ADMISSION_TOTAL_PAYLOAD_BYTES {
            return Err(SccmClientEvidenceAdmissionError::AggregatePayloadByteLimitExceeded);
        }
    }
    Ok(())
}

fn validate_payload(
    payload: &SccmClientCapturedPayload,
) -> Result<(), SccmClientEvidenceAdmissionError> {
    let length = u64::try_from(payload.bytes.len())
        .map_err(|_| SccmClientEvidenceAdmissionError::PayloadIntegrityMismatch)?;
    if length != payload.byte_length || !is_lowercase_sha256(&payload.expected_sha256) {
        return Err(SccmClientEvidenceAdmissionError::PayloadIntegrityMismatch);
    }
    (digest_hex(&payload.bytes) == payload.expected_sha256)
        .then_some(())
        .ok_or(SccmClientEvidenceAdmissionError::PayloadIntegrityMismatch)
}

fn retained_evidence_size(
    evidence: &SccmEvidence,
) -> Result<usize, SccmClientEvidenceAdmissionError> {
    let execution_context_bytes = match evidence.execution_context.as_ref() {
        Some(handle) => handle
            .scheme
            .len()
            .checked_add(handle.value.len())
            .ok_or(SccmClientEvidenceAdmissionError::RetainedEvidenceLimitExceeded)?,
        None => 0,
    };
    let mut total = 0usize;
    for size in [
        evidence.evidence_id.len(),
        evidence.reference.artifact_id.len(),
        evidence.reference.entry_id.len(),
        evidence.component.as_deref().map_or(0, str::len),
        evidence.ccm_source_file.as_deref().map_or(0, str::len),
        evidence.message.len(),
        evidence
            .timestamp
            .original_display
            .as_deref()
            .map_or(0, str::len),
        execution_context_bytes,
        // Reserve fixed-field and container overhead so the retained-memory
        // cap remains conservative without serializing a second copy.
        256,
    ] {
        total = total
            .checked_add(size)
            .ok_or(SccmClientEvidenceAdmissionError::RetainedEvidenceLimitExceeded)?;
    }
    Ok(total)
}

fn decode_payload(
    payload: &SccmClientCapturedPayload,
    encoding: Option<&str>,
) -> Result<String, SccmClientEvidenceAdmissionError> {
    let encoding = match encoding {
        Some("utf-8") => UTF_8,
        Some("utf-16le") => UTF_16LE,
        Some("utf-16be") => UTF_16BE,
        Some("windows-1252") => WINDOWS_1252,
        _ => return Err(SccmClientEvidenceAdmissionError::InvalidEncoding),
    };
    let (decoded, _, had_errors) = encoding.decode(&payload.bytes);
    (!had_errors)
        .then_some(decoded.into_owned())
        .ok_or(SccmClientEvidenceAdmissionError::InvalidEncoding)
}

fn artifact_for_fragment(fragment: &SccmClientIntakeFragment) -> SccmArtifact {
    SccmArtifact {
        artifact_id: fragment.artifact_id.clone(),
        display_name: fragment.basename.clone(),
        original_path: None,
        host: None,
        role: SccmRole::Client,
        configmgr_version: fragment.configmgr_version.clone(),
        collected_at_utc: fragment.collected_at_utc.clone(),
        rotation: fragment.rotation.clone(),
        coverage: fragment.coverage.clone(),
        encoding: fragment.encoding.clone(),
    }
}

fn is_registered_client_profile(profile: &SccmExtractionProfile) -> bool {
    profile.profile_id == SCCM_EXPERIMENTAL_KEY_PROFILE_ID
        && profile.maturity == SccmExtractionProfileMaturity::Experimental
        && profile.configmgr_version_prefixes == ["5.00.9128."]
        && profile.validated_artifact_families.is_empty()
        && profile
            .selected_configmgr_version
            .as_deref()
            .is_some_and(|version| version.starts_with("5.00.9128."))
}

fn compare_evidence(left: &SccmEvidence, right: &SccmEvidence) -> std::cmp::Ordering {
    (
        left.reference.artifact_id.as_str(),
        left.reference.line_start,
        left.reference.line_end,
        left.reference.entry_id.as_str(),
        left.evidence_id.as_str(),
    )
        .cmp(&(
            right.reference.artifact_id.as_str(),
            right.reference.line_start,
            right.reference.line_end,
            right.reference.entry_id.as_str(),
            right.evidence_id.as_str(),
        ))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct IntegrityProjection<'a> {
    evidence: &'a [SccmEvidence],
    source_coverage: &'a BTreeMap<String, SccmCoverageState>,
    profiles_by_artifact: &'a BTreeMap<String, SccmExtractionProfile>,
}

struct BoundedIntegrityWriter {
    hasher: Sha256,
    byte_limit: usize,
    bytes_written: usize,
    limit_exceeded: bool,
}

impl BoundedIntegrityWriter {
    fn new(byte_limit: usize) -> Self {
        Self {
            hasher: Sha256::new(),
            byte_limit,
            bytes_written: 0,
            limit_exceeded: false,
        }
    }

    fn finish(self) -> String {
        self.hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

impl Write for BoundedIntegrityWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(next_size) = self.bytes_written.checked_add(bytes.len()) else {
            self.limit_exceeded = true;
            return Err(io::Error::other("integrity seal byte limit exceeded"));
        };
        if next_size > self.byte_limit {
            self.limit_exceeded = true;
            return Err(io::Error::other("integrity seal byte limit exceeded"));
        }
        self.hasher.update(bytes);
        self.bytes_written = next_size;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn compute_integrity_seal(
    evidence: &[SccmEvidence],
    source_coverage: &BTreeMap<String, SccmCoverageState>,
    profiles_by_artifact: &BTreeMap<String, SccmExtractionProfile>,
) -> Result<String, SccmClientEvidenceAdmissionError> {
    let mut writer = BoundedIntegrityWriter::new(MAX_SCCM_CLIENT_ADMISSION_SEAL_BYTES);
    let serialized = serde_json::to_writer(
        &mut writer,
        &IntegrityProjection {
            evidence,
            source_coverage,
            profiles_by_artifact,
        },
    );
    if serialized.is_err() {
        return Err(if writer.limit_exceeded {
            SccmClientEvidenceAdmissionError::IntegritySealLimitExceeded
        } else {
            SccmClientEvidenceAdmissionError::IntegrityViolation
        });
    }
    Ok(writer.finish())
}

fn digest_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
