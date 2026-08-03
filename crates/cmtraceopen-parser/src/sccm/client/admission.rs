//! Sealing of canonical SCCM client evidence behind an opaque capability.
//!
//! Raw payload bytes exist only while this constructor verifies their digest
//! and normalizes their CCM logical records. Reducers receive the resulting
//! immutable-by-API capability, never bytes or caller-supplied evidence.

// The public facade lands before workflow reducers, while its capability
// accessors deliberately remain crate-private. No production reducer owns
// them in this slice, so rustc cannot yet observe those call sites; retaining
// the local lint allowance avoids weakening workspace-wide warning policy.
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
use crate::sccm::catalog::classify_artifact_name;
use crate::sccm::evidence::SccmRawEvidenceSnapshot;
use crate::sccm::keys::extract_keys_from_admitted_profile;
use crate::sccm::{
    SccmArtifact, SccmArtifactFamily, SccmCoverageState, SccmEvidence, SccmExtractionProfile,
    SccmKeyExtractionResult, SccmRole, SccmTimeOrderingState,
};

use super::{
    assess_client_intake,
    intake::{is_safe_artifact_id, source_matches_group},
    SccmClientIntakeAssessment, SccmClientIntakeBundle, SccmClientIntakeError,
    SccmClientIntakeFragment, MAX_SCCM_CLIENT_INTAKE_ARTIFACTS,
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
/// This is an independent serialization-work cap: JSON escaping may reject a
/// retained-memory-bounded bundle once its escaped serialization exceeds this
/// separate hashing-work bound.
pub(crate) const MAX_SCCM_CLIENT_ADMISSION_SEAL_BYTES: usize = 4 * 1024 * 1024;

/// Raw, already-captured bytes offered to the one-shot client evidence
/// admission boundary. This is an input only: the successful capability does
/// not retain this vector or any decoded raw text.
pub struct SccmClientCapturedPayload {
    artifact_id: String,
    bytes: Vec<u8>,
}

impl SccmClientCapturedPayload {
    /// Constructs one bytes-only admission input. Artifact identity is only a
    /// routing handle; byte length and digest authority remain exclusively on
    /// the canonical intake fragment.
    pub fn new(
        artifact_id: impl Into<String>,
        bytes: Vec<u8>,
    ) -> Result<Self, SccmClientEvidenceAdmissionError> {
        let artifact_id = artifact_id.into();
        if !is_safe_artifact_id(&artifact_id) {
            return Err(SccmClientEvidenceAdmissionError::InvalidPayloadArtifactId);
        }
        if bytes.len() > MAX_SCCM_CLIENT_ADMISSION_PAYLOAD_BYTES {
            return Err(SccmClientEvidenceAdmissionError::PayloadByteLimitExceeded);
        }
        Ok(Self { artifact_id, bytes })
    }
}

/// The bounded evidence authority internal client reducers consume.
///
/// Its fields stay private and it deliberately implements neither serde nor a
/// public constructor. `verify_integrity` recomputes the deterministic seal so
/// a reducer can fail closed if future crate-internal code corrupts it.
pub struct SccmClientAdmittedEvidence {
    evidence: Vec<SccmEvidence>,
    source_coverage: BTreeMap<String, SccmCoverageState>,
    admitted_source_groups: BTreeSet<String>,
    profiles_by_artifact: BTreeMap<String, SccmExtractionProfile>,
    integrity_seal: String,
}

/// Artifact-scoped key-extraction results selected only from sealed client
/// evidence authority. Its private fields and lack of a constructor prevent a
/// generic extraction result from being substituted for admitted authority.
pub(crate) struct SccmClientAdmittedKeyExtraction {
    artifact_id: String,
    artifact_family: SccmArtifactFamily,
    results: Vec<SccmKeyExtractionResult>,
}

impl SccmClientAdmittedKeyExtraction {
    pub(crate) fn artifact_id(&self) -> &str {
        &self.artifact_id
    }

    pub(crate) fn artifact_family(&self) -> &SccmArtifactFamily {
        &self.artifact_family
    }

    pub(crate) fn results(&self) -> &[SccmKeyExtractionResult] {
        &self.results
    }
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

    pub(crate) fn extract_keys_for_artifact(
        &self,
        artifact_id: &str,
    ) -> Result<SccmClientAdmittedKeyExtraction, SccmClientEvidenceAdmissionError> {
        self.verify_integrity()?;
        let (sealed_artifact_id, profile) = self
            .profiles_by_artifact
            .get_key_value(artifact_id)
            .ok_or(SccmClientEvidenceAdmissionError::MissingAdmittedExtractionProfile)?;
        let [artifact_family] = profile.validated_artifact_families.as_slice() else {
            return Err(SccmClientEvidenceAdmissionError::IntegrityViolation);
        };
        let results = self
            .evidence
            .iter()
            .filter(|evidence| evidence.reference.artifact_id == *sealed_artifact_id)
            .map(|evidence| extract_keys_from_admitted_profile(evidence, profile))
            .collect::<Vec<_>>();
        if results.is_empty() {
            return Err(SccmClientEvidenceAdmissionError::MissingAdmittedArtifactEvidence);
        }

        Ok(SccmClientAdmittedKeyExtraction {
            artifact_id: sealed_artifact_id.clone(),
            artifact_family: artifact_family.clone(),
            results,
        })
    }

    pub(crate) fn integrity_seal(&self) -> &str {
        &self.integrity_seal
    }

    pub(crate) fn verify_integrity(&self) -> Result<(), SccmClientEvidenceAdmissionError> {
        let recomputed = compute_integrity_seal(
            &self.evidence,
            &self.source_coverage,
            &self.admitted_source_groups,
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
            Some(_) if self.admitted_source_groups.contains(logical_artifact_id) => Ok(()),
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
pub enum SccmClientEvidenceAdmissionError {
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
    #[error("client evidence admission payload artifact ID is invalid")]
    InvalidPayloadArtifactId,
    #[error("client evidence admission contains duplicate payload artifact IDs")]
    DuplicatePayload,
    #[error("client evidence admission is missing a payload for a captured fragment")]
    MissingPayload,
    #[error("client evidence admission payload has no matching canonical captured fragment")]
    ExtraPayload,
    #[error("client evidence admission payload length or digest is invalid")]
    PayloadIntegrityMismatch,
    #[error("client evidence admission captured fragment has no intake-bound length and digest")]
    MissingContentBinding,
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
    #[error("client evidence admission has no sealed extraction profile for the artifact")]
    MissingAdmittedExtractionProfile,
    #[error("client evidence admission has no sealed evidence for the artifact")]
    MissingAdmittedArtifactEvidence,
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
pub fn admit_client_evidence(
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
    let mut eligible = BTreeMap::new();
    let mut unbound_complete_captures = BTreeSet::new();
    for fragment in &canonical.physical_artifacts {
        let classified = classify_artifact_name(&fragment.basename, SccmRole::Client);
        if !classified.supported_for_diagnosis || !classified.uses_ccm_records {
            continue;
        }
        if fragment.coverage != SccmCoverageState::Captured
            || fragment.fragment_complete != Some(true)
        {
            continue;
        }
        if fragment.declared_byte_length.is_none() || fragment.content_sha256.is_none() {
            unbound_complete_captures.insert(fragment.artifact_id.as_str());
            continue;
        }
        eligible.insert(fragment.artifact_id.clone(), (fragment, classified.family));
    }
    let admitted_source_groups = canonical
        .groups
        .iter()
        .filter(|group| {
            group.fragments.iter().any(is_supported_raw_ccm_fragment)
                && group
                    .fragments
                    .iter()
                    .filter(|fragment| is_supported_raw_ccm_fragment(fragment))
                    .all(is_bound_complete_capture)
                && !canonical.capture_gaps.iter().any(|capture_gap| {
                    is_supported_raw_ccm_source(&capture_gap.basename)
                        && source_matches_group(
                            &capture_gap.basename,
                            &capture_gap.rotation,
                            &group.logical_artifact_id,
                        )
                })
        })
        .map(|group| group.logical_artifact_id.clone())
        .collect::<BTreeSet<_>>();
    if payloads
        .iter()
        .any(|payload| unbound_complete_captures.contains(payload.artifact_id.as_str()))
    {
        return Err(SccmClientEvidenceAdmissionError::MissingContentBinding);
    }
    if payloads.len() < eligible.len() {
        return Err(SccmClientEvidenceAdmissionError::MissingPayload);
    }
    if payloads.len() > eligible.len() {
        return Err(SccmClientEvidenceAdmissionError::ExtraPayload);
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
        let (fragment, family) = eligible
            .get(&payload.artifact_id)
            .ok_or(SccmClientEvidenceAdmissionError::ExtraPayload)?;
        let fragment = *fragment;
        validate_payload(payload, fragment)?;

        let profile = SccmExtractionProfile::for_artifact_family(
            fragment.configmgr_version.as_deref(),
            family,
        )
        .ok_or(SccmClientEvidenceAdmissionError::UnregisteredProfile)?;
        let content = decode_payload(payload, fragment.encoding.as_deref())?;
        let artifact = artifact_for_fragment(fragment);
        let scan =
            scan_logical_records_bounded(&content, &fragment.basename, remaining_logical_records);
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
    let integrity_seal = compute_integrity_seal(
        &evidence,
        &source_coverage,
        &admitted_source_groups,
        &profiles_by_artifact,
    )?;
    Ok(SccmClientAdmittedEvidence {
        evidence,
        source_coverage,
        admitted_source_groups,
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

fn is_supported_raw_ccm_fragment(fragment: &SccmClientIntakeFragment) -> bool {
    is_supported_raw_ccm_source(&fragment.basename)
}

fn is_supported_raw_ccm_source(basename: &str) -> bool {
    let classified = classify_artifact_name(basename, SccmRole::Client);
    classified.supported_for_diagnosis && classified.uses_ccm_records
}

fn is_bound_complete_capture(fragment: &SccmClientIntakeFragment) -> bool {
    fragment.coverage == SccmCoverageState::Captured
        && fragment.fragment_complete == Some(true)
        && fragment.declared_byte_length.is_some()
        && fragment.content_sha256.is_some()
}

fn validate_payload(
    payload: &SccmClientCapturedPayload,
    fragment: &SccmClientIntakeFragment,
) -> Result<(), SccmClientEvidenceAdmissionError> {
    let length = u64::try_from(payload.bytes.len())
        .map_err(|_| SccmClientEvidenceAdmissionError::PayloadIntegrityMismatch)?;
    let declared_length = fragment
        .declared_byte_length
        .ok_or(SccmClientEvidenceAdmissionError::MissingContentBinding)?;
    let declared_digest = fragment
        .content_sha256
        .as_deref()
        .ok_or(SccmClientEvidenceAdmissionError::MissingContentBinding)?;
    if length != declared_length || !is_lowercase_sha256(declared_digest) {
        return Err(SccmClientEvidenceAdmissionError::PayloadIntegrityMismatch);
    }
    (digest_hex(&payload.bytes) == declared_digest)
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
    let (encoding, declared_bom) = match encoding {
        Some("utf-8") => (UTF_8, Some(UnicodeBom::Utf8)),
        Some("utf-16le") => (UTF_16LE, Some(UnicodeBom::Utf16Le)),
        Some("utf-16be") => (UTF_16BE, Some(UnicodeBom::Utf16Be)),
        Some("windows-1252") => (WINDOWS_1252, None),
        _ => return Err(SccmClientEvidenceAdmissionError::InvalidEncoding),
    };
    let bytes = match recognized_unicode_bom(&payload.bytes) {
        Some((actual_bom, bom_len)) if Some(actual_bom) == declared_bom => {
            &payload.bytes[bom_len..]
        }
        Some(_) => return Err(SccmClientEvidenceAdmissionError::InvalidEncoding),
        None => payload.bytes.as_slice(),
    };
    let (decoded, had_errors) = encoding.decode_without_bom_handling(bytes);
    (!had_errors)
        .then_some(decoded.into_owned())
        .ok_or(SccmClientEvidenceAdmissionError::InvalidEncoding)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum UnicodeBom {
    Utf8,
    Utf16Le,
    Utf16Be,
    Utf32Le,
    Utf32Be,
}

fn recognized_unicode_bom(bytes: &[u8]) -> Option<(UnicodeBom, usize)> {
    if bytes.starts_with(&[0xff, 0xfe, 0x00, 0x00]) {
        Some((UnicodeBom::Utf32Le, 4))
    } else if bytes.starts_with(&[0x00, 0x00, 0xfe, 0xff]) {
        Some((UnicodeBom::Utf32Be, 4))
    } else if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        Some((UnicodeBom::Utf8, 3))
    } else if bytes.starts_with(&[0xff, 0xfe]) {
        Some((UnicodeBom::Utf16Le, 2))
    } else if bytes.starts_with(&[0xfe, 0xff]) {
        Some((UnicodeBom::Utf16Be, 2))
    } else {
        None
    }
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
    admitted_source_groups: &'a BTreeSet<String>,
    profile_assignments: &'a BTreeMap<&'a str, usize>,
    profiles: &'a [&'a SccmExtractionProfile],
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
    admitted_source_groups: &BTreeSet<String>,
    profiles_by_artifact: &BTreeMap<String, SccmExtractionProfile>,
) -> Result<String, SccmClientEvidenceAdmissionError> {
    // Many rotations legitimately select the same profile. Seal the complete
    // profile once and bind each artifact to its deterministic index so the
    // intake artifact ceiling does not multiply identical profile metadata
    // past the independent seal cap.
    let mut profile_indices = BTreeMap::<String, usize>::new();
    let mut unique_profiles = Vec::new();
    let mut profile_assignments = BTreeMap::new();
    for (artifact_id, profile) in profiles_by_artifact {
        let canonical_profile = serde_json::to_string(profile)
            .map_err(|_| SccmClientEvidenceAdmissionError::IntegrityViolation)?;
        let profile_index = match profile_indices.get(&canonical_profile) {
            Some(index) => *index,
            None => {
                let index = unique_profiles.len();
                profile_indices.insert(canonical_profile, index);
                unique_profiles.push(profile);
                index
            }
        };
        profile_assignments.insert(artifact_id.as_str(), profile_index);
    }

    let mut writer = BoundedIntegrityWriter::new(MAX_SCCM_CLIENT_ADMISSION_SEAL_BYTES);
    let serialized = serde_json::to_writer(
        &mut writer,
        &IntegrityProjection {
            evidence,
            source_coverage,
            admitted_source_groups,
            profile_assignments: &profile_assignments,
            profiles: &unique_profiles,
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
