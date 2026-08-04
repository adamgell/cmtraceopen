use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::slice;

use serde::de::Error as _;
use serde::ser::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::models::log_entry::Severity;

use super::catalog::declared_source_catalog;
use super::keys::normalize_key;
use super::models::{
    SccmCorrelationKey, SccmCorrelationKeyKind, SccmCoverageState, SccmEvidenceRef,
    SccmFindingClass, SccmKeyConfidence, SccmRole,
};

pub const MAX_SCCM_ARTIFACT_REQUEST_REASON_CHARS: usize = 240;
pub const MAX_SCCM_NEXT_ARTIFACT_REQUESTS: usize = 16;
// Shared wire bound for every opaque identifier a finding carries: finding
// ids, evidence artifact and entry ids, coverage-gap artifact ids, request
// logical ids, and extraction profile ids. Enforced inside
// is_canonical_opaque_id so no identifier path can skip it.
const MAX_SCCM_OPAQUE_ID_CHARS: usize = 256;
// Single-line display heading; twice the opaque id bound covers generated
// "<subject> <outcome>" headings without admitting unbounded text.
const MAX_SCCM_FINDING_TITLE_CHARS: usize = 512;
// Multi-sentence display paragraph shown in the finding detail pane.
const MAX_SCCM_FINDING_SUMMARY_CHARS: usize = 2048;
// Correlation-key raw and normalized values. The widest canonical form is a
// 253-character server-host FQDN; 256 leaves room for braces and prefixes
// while excluding unbounded decimal ids.
// Do not lower this. normalize_server_host self-caps a host at 253 chars, so
// a worst-case ServerHost key normalizes to 254 with a trailing-dot source
// against this 256 limit, roughly 99% of the bound and the tightest headroom
// any bound in this module carries.
// Shared with the extraction producer in keys.rs so extract_keys cannot emit a
// key this validator would reject. Crate-visible rather than public: it is an
// internal agreement between the producer and the validator, not wire surface.
pub(crate) const MAX_SCCM_CORRELATION_KEY_VALUE_CHARS: usize = 256;
// The sole registered profile is a closed synthetic-fixture contract. Its
// registration authorizes exact fixture keys, not any production ConfigMgr
// version. Adding a production profile requires separate contract review.
const REGISTERED_STABLE_CORRELATION_PROFILE_IDS: &[&str] = &["policy-client-5.00.test-v1"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmConfidence {
    None,
    Low,
    Moderate,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SccmPhase {
    Policy,
    Content,
    Enforcement,
    Unknown(String),
}

impl SccmPhase {
    fn serialized_name(&self) -> &str {
        match self {
            Self::Policy => "policy",
            Self::Content => "content",
            Self::Enforcement => "enforcement",
            Self::Unknown(value) => value,
        }
    }

    fn has_canonical_serialized_form(&self) -> bool {
        match self {
            Self::Unknown(value) => {
                !value.is_empty() && value.trim() == value && !is_known_phase_name(value)
            }
            _ => true,
        }
    }
}

impl Serialize for SccmPhase {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if !self.has_canonical_serialized_form() {
            return Err(S::Error::custom(
                "unknown SCCM phase must be canonical and must not shadow a declared phase",
            ));
        }
        serializer.serialize_str(self.serialized_name())
    }
}

impl<'de> Deserialize<'de> for SccmPhase {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let phase = match String::deserialize(deserializer)? {
            value if value == "policy" => Self::Policy,
            value if value == "content" => Self::Content,
            value if value == "enforcement" => Self::Enforcement,
            value => Self::Unknown(value),
        };
        if !phase.has_canonical_serialized_form() {
            return Err(D::Error::custom(
                "unknown SCCM phase must be canonical and must not shadow a declared phase",
            ));
        }
        Ok(phase)
    }
}

fn is_known_phase_name(value: &str) -> bool {
    matches!(value, "policy" | "content" | "enforcement")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SccmTerminalEvidenceKind {
    ObservedFailure,
    Unknown(String),
}

impl SccmTerminalEvidenceKind {
    fn serialized_name(&self) -> &str {
        match self {
            Self::ObservedFailure => "observedFailure",
            Self::Unknown(value) => value,
        }
    }

    fn has_canonical_serialized_form(&self) -> bool {
        match self {
            Self::Unknown(value) => {
                !value.is_empty() && value.trim() == value && value != "observedFailure"
            }
            Self::ObservedFailure => true,
        }
    }
}

impl Serialize for SccmTerminalEvidenceKind {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if !self.has_canonical_serialized_form() {
            return Err(S::Error::custom(
                "unknown terminal evidence kind must be canonical and must not shadow observedFailure",
            ));
        }
        serializer.serialize_str(self.serialized_name())
    }
}

impl<'de> Deserialize<'de> for SccmTerminalEvidenceKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let kind = match String::deserialize(deserializer)? {
            value if value == "observedFailure" => Self::ObservedFailure,
            value => Self::Unknown(value),
        };
        if !kind.has_canonical_serialized_form() {
            return Err(D::Error::custom(
                "unknown terminal evidence kind must be canonical and must not shadow observedFailure",
            ));
        }
        Ok(kind)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SccmTerminalEvidence {
    pub reference: SccmEvidenceRef,
    pub kind: SccmTerminalEvidenceKind,
}

impl SccmTerminalEvidence {
    pub fn observed_failure(reference: SccmEvidenceRef) -> Self {
        Self {
            reference,
            kind: SccmTerminalEvidenceKind::ObservedFailure,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SccmFindingCoverageGap {
    pub artifact_id: String,
    pub role: SccmRole,
    pub coverage: SccmCoverageState,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SccmArtifactRequest {
    pub logical_id: String,
    pub role: SccmRole,
    pub reason: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SccmArtifactRequestSerializeWire<'a> {
    logical_id: &'a str,
    role: &'a SccmRole,
    reason: &'a str,
}

impl Serialize for SccmArtifactRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        validate_artifact_requests(slice::from_ref(self)).map_err(|error| {
            S::Error::custom(format!("invalid SCCM artifact request contract: {error:?}"))
        })?;
        let reason = self.reason.trim();
        SccmArtifactRequestSerializeWire {
            logical_id: &self.logical_id,
            role: &self.role,
            reason,
        }
        .serialize(serializer)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SccmFinding {
    pub finding_id: String,
    pub class: SccmFindingClass,
    pub phase: SccmPhase,
    pub role: SccmRole,
    pub severity: Severity,
    pub confidence: SccmConfidence,
    pub title: String,
    pub summary: String,
    pub evidence: Vec<SccmEvidenceRef>,
    pub terminal_evidence: Vec<SccmTerminalEvidence>,
    pub coverage_gaps: Vec<SccmFindingCoverageGap>,
    pub correlation_keys: Vec<SccmCorrelationKey>,
    pub next_artifacts: Vec<SccmArtifactRequest>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SccmFindingSerializeWire<'a> {
    finding_id: &'a str,
    class: &'a SccmFindingClass,
    phase: &'a SccmPhase,
    role: &'a SccmRole,
    severity: &'a Severity,
    confidence: &'a SccmConfidence,
    title: &'a str,
    summary: &'a str,
    evidence: &'a [SccmEvidenceRef],
    terminal_evidence: &'a [SccmTerminalEvidence],
    coverage_gaps: &'a [SccmFindingCoverageGap],
    correlation_keys: &'a [SccmCorrelationKey],
    next_artifacts: &'a [SccmArtifactRequest],
}

impl Serialize for SccmFinding {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.validate().map_err(|error| {
            S::Error::custom(format!("invalid SCCM finding contract: {error:?}"))
        })?;
        let mut normalized = self.clone();
        normalize_finding(&mut normalized);
        normalized.validate().map_err(|error| {
            S::Error::custom(format!("invalid SCCM finding contract: {error:?}"))
        })?;
        SccmFindingSerializeWire {
            finding_id: &normalized.finding_id,
            class: &normalized.class,
            phase: &normalized.phase,
            role: &normalized.role,
            severity: &normalized.severity,
            confidence: &normalized.confidence,
            title: &normalized.title,
            summary: &normalized.summary,
            evidence: &normalized.evidence,
            terminal_evidence: &normalized.terminal_evidence,
            coverage_gaps: &normalized.coverage_gaps,
            correlation_keys: &normalized.correlation_keys,
            next_artifacts: &normalized.next_artifacts,
        }
        .serialize(serializer)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SccmFindingWire {
    finding_id: String,
    class: SccmFindingClass,
    phase: SccmPhase,
    role: SccmRole,
    severity: Severity,
    confidence: SccmConfidence,
    title: String,
    summary: String,
    evidence: Vec<SccmEvidenceRefWire>,
    terminal_evidence: Vec<SccmTerminalEvidenceWire>,
    coverage_gaps: Vec<SccmFindingCoverageGapWire>,
    correlation_keys: Vec<SccmCorrelationKeyWire>,
    next_artifacts: Vec<SccmArtifactRequestWire>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SccmEvidenceRefSerializeWire<'a> {
    artifact_id: &'a str,
    entry_id: &'a str,
    line_start: Option<u32>,
    line_end: Option<u32>,
}

impl Serialize for SccmEvidenceRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        validate_evidence_reference(self).map_err(|error| {
            S::Error::custom(format!(
                "invalid SCCM evidence reference contract: {error:?}"
            ))
        })?;
        SccmEvidenceRefSerializeWire {
            artifact_id: &self.artifact_id,
            entry_id: &self.entry_id,
            line_start: self.line_start,
            line_end: self.line_end,
        }
        .serialize(serializer)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SccmEvidenceRefWire {
    artifact_id: String,
    entry_id: String,
    line_start: Option<u32>,
    line_end: Option<u32>,
}

impl From<SccmEvidenceRefWire> for SccmEvidenceRef {
    fn from(wire: SccmEvidenceRefWire) -> Self {
        Self {
            artifact_id: wire.artifact_id,
            entry_id: wire.entry_id,
            line_start: wire.line_start,
            line_end: wire.line_end,
        }
    }
}

// SccmEvidenceRef is declared in models.rs, but its wire contract belongs
// here next to the validator it must satisfy. Every reference the crate
// accepts, whether standalone or nested in SccmEvidence or an extraction gap,
// clears the same bar a finding's own citations clear.
impl<'de> Deserialize<'de> for SccmEvidenceRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let reference = Self::from(SccmEvidenceRefWire::deserialize(deserializer)?);
        validate_evidence_reference(&reference).map_err(|error| {
            D::Error::custom(format!(
                "invalid SCCM evidence reference contract: {error:?}"
            ))
        })?;
        Ok(reference)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SccmTerminalEvidenceSerializeWire<'a> {
    reference: &'a SccmEvidenceRef,
    kind: &'a SccmTerminalEvidenceKind,
}

impl Serialize for SccmTerminalEvidence {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        validate_evidence_reference(&self.reference)
            .and_then(|()| {
                validate_terminal_evidence(slice::from_ref(&self.reference), slice::from_ref(self))
            })
            .map_err(|error| {
                S::Error::custom(format!(
                    "invalid SCCM terminal evidence contract: {error:?}"
                ))
            })?;
        SccmTerminalEvidenceSerializeWire {
            reference: &self.reference,
            kind: &self.kind,
        }
        .serialize(serializer)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SccmTerminalEvidenceWire {
    reference: SccmEvidenceRefWire,
    kind: SccmTerminalEvidenceKind,
}

impl From<SccmTerminalEvidenceWire> for SccmTerminalEvidence {
    fn from(wire: SccmTerminalEvidenceWire) -> Self {
        Self {
            reference: wire.reference.into(),
            kind: wire.kind,
        }
    }
}

// A standalone terminal evidence has no surrounding finding to cite, so it
// stands as its own citation set. That trivially satisfies the "must be cited"
// rule while still enforcing the kind gate: only observedFailure is terminal.
impl<'de> Deserialize<'de> for SccmTerminalEvidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let terminal = Self::from(SccmTerminalEvidenceWire::deserialize(deserializer)?);
        validate_evidence_reference(&terminal.reference)
            .and_then(|()| {
                validate_terminal_evidence(
                    slice::from_ref(&terminal.reference),
                    slice::from_ref(&terminal),
                )
            })
            .map_err(|error| {
                D::Error::custom(format!(
                    "invalid SCCM terminal evidence contract: {error:?}"
                ))
            })?;
        Ok(terminal)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SccmFindingCoverageGapSerializeWire<'a> {
    artifact_id: &'a str,
    role: &'a SccmRole,
    coverage: &'a SccmCoverageState,
}

impl Serialize for SccmFindingCoverageGap {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        validate_coverage_gaps(slice::from_ref(self)).map_err(|error| {
            S::Error::custom(format!("invalid SCCM coverage gap contract: {error:?}"))
        })?;
        SccmFindingCoverageGapSerializeWire {
            artifact_id: &self.artifact_id,
            role: &self.role,
            coverage: &self.coverage,
        }
        .serialize(serializer)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SccmFindingCoverageGapWire {
    artifact_id: String,
    role: SccmRole,
    coverage: SccmCoverageState,
}

impl From<SccmFindingCoverageGapWire> for SccmFindingCoverageGap {
    fn from(wire: SccmFindingCoverageGapWire) -> Self {
        Self {
            artifact_id: wire.artifact_id,
            role: wire.role,
            coverage: wire.coverage,
        }
    }
}

// A coverage gap deserialized on its own must clear the same bar it clears
// as a member of SccmFinding::coverage_gaps, so route it through the same
// deny_unknown_fields wire struct and the same validator.
impl<'de> Deserialize<'de> for SccmFindingCoverageGap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let gap = Self::from(SccmFindingCoverageGapWire::deserialize(deserializer)?);
        validate_coverage_gaps(slice::from_ref(&gap)).map_err(|error| {
            D::Error::custom(format!("invalid SCCM coverage gap contract: {error:?}"))
        })?;
        Ok(gap)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SccmCorrelationKeySerializeWire<'a> {
    kind: &'a SccmCorrelationKeyKind,
    raw: &'a str,
    normalized: &'a str,
    confidence: &'a SccmKeyConfidence,
    extraction_profile_id: Option<&'a str>,
    evidence: Option<&'a SccmEvidenceRef>,
    start: Option<usize>,
    end: Option<usize>,
}

impl Serialize for SccmCorrelationKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        validate_correlation_key_evidence(self.evidence.as_slice(), slice::from_ref(self))
            .map_err(|error| {
                S::Error::custom(format!("invalid SCCM correlation key contract: {error:?}"))
            })?;
        SccmCorrelationKeySerializeWire {
            kind: &self.kind,
            raw: &self.raw,
            normalized: &self.normalized,
            confidence: &self.confidence,
            extraction_profile_id: self.extraction_profile_id.as_deref(),
            evidence: self.evidence.as_ref(),
            start: self.start,
            end: self.end,
        }
        .serialize(serializer)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SccmCorrelationKeyWire {
    kind: SccmCorrelationKeyKind,
    raw: String,
    normalized: String,
    confidence: SccmKeyConfidence,
    extraction_profile_id: Option<String>,
    evidence: Option<SccmEvidenceRefWire>,
    start: Option<usize>,
    end: Option<usize>,
}

impl From<SccmCorrelationKeyWire> for SccmCorrelationKey {
    fn from(wire: SccmCorrelationKeyWire) -> Self {
        Self {
            kind: wire.kind,
            raw: wire.raw,
            normalized: wire.normalized,
            confidence: wire.confidence,
            extraction_profile_id: wire.extraction_profile_id,
            evidence: wire.evidence.map(Into::into),
            start: wire.start,
            end: wire.end,
        }
    }
}

// The key's own evidence reference stands in as its citation set, exactly as
// it would inside a finding. Containment is therefore self-satisfying here, so
// validate_correlation_key_evidence validates the reference itself before it
// checks containment; the wire struct nests SccmEvidenceRefWire and cannot
// rely on the SccmEvidenceRef deserializer to do it. Crucially this keeps the
// confidence gate in force: while REGISTERED_STABLE_CORRELATION_PROFILE_IDS is
// empty, no payload can deserialize a Strong or Exact key and forge
// corroboration strength.
impl<'de> Deserialize<'de> for SccmCorrelationKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let key = Self::from(SccmCorrelationKeyWire::deserialize(deserializer)?);
        let citations = key.evidence.as_slice();
        validate_correlation_key_evidence(citations, slice::from_ref(&key)).map_err(|error| {
            D::Error::custom(format!("invalid SCCM correlation key contract: {error:?}"))
        })?;
        Ok(key)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SccmArtifactRequestWire {
    logical_id: String,
    role: SccmRole,
    reason: String,
}

impl From<SccmArtifactRequestWire> for SccmArtifactRequest {
    fn from(wire: SccmArtifactRequestWire) -> Self {
        Self {
            logical_id: wire.logical_id,
            role: wire.role,
            reason: wire.reason,
        }
    }
}

// Same contract as a request carried inside SccmFinding::next_artifacts: the
// logical id must name a declared catalog source for the requested role and
// the reason must stay bounded and scoped to that artifact.
impl<'de> Deserialize<'de> for SccmArtifactRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut request = Self::from(SccmArtifactRequestWire::deserialize(deserializer)?);
        validate_artifact_requests(slice::from_ref(&request)).map_err(|error| {
            D::Error::custom(format!("invalid SCCM artifact request contract: {error:?}"))
        })?;
        request.reason = request.reason.trim().to_owned();
        Ok(request)
    }
}

impl<'de> Deserialize<'de> for SccmFinding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SccmFindingWire::deserialize(deserializer)?;
        if wire.next_artifacts.len() > MAX_SCCM_NEXT_ARTIFACT_REQUESTS {
            return Err(D::Error::custom("too many SCCM artifact requests"));
        }
        let mut finding = Self {
            finding_id: wire.finding_id,
            class: wire.class,
            phase: wire.phase,
            role: wire.role,
            severity: wire.severity,
            confidence: wire.confidence,
            title: wire.title,
            summary: wire.summary,
            evidence: wire.evidence.into_iter().map(Into::into).collect(),
            terminal_evidence: wire.terminal_evidence.into_iter().map(Into::into).collect(),
            coverage_gaps: wire.coverage_gaps.into_iter().map(Into::into).collect(),
            correlation_keys: wire.correlation_keys.into_iter().map(Into::into).collect(),
            next_artifacts: wire.next_artifacts.into_iter().map(Into::into).collect(),
        };
        validate_raw_text_bounds(&finding).map_err(|error| {
            D::Error::custom(format!("invalid SCCM finding contract: {error:?}"))
        })?;
        normalize_finding(&mut finding);
        finding.validate().map_err(|error| {
            D::Error::custom(format!("invalid SCCM finding contract: {error:?}"))
        })?;
        Ok(finding)
    }
}

impl SccmFinding {
    pub fn validate(&self) -> Result<(), SccmFindingValidationError> {
        validate_raw_text_bounds(self)?;
        validate_required_text(self)?;
        validate_roles(self)?;
        validate_all_evidence_references(self)?;
        validate_coverage_gaps(&self.coverage_gaps)?;
        validate_artifact_requests(&self.next_artifacts)?;

        if self.class == SccmFindingClass::InsufficientEvidence && self.coverage_gaps.is_empty() {
            return Err(SccmFindingValidationError::MissingCoverageGap);
        }

        if self.evidence.is_empty()
            && (self.coverage_gaps.is_empty()
                || self.class != SccmFindingClass::InsufficientEvidence)
        {
            return Err(SccmFindingValidationError::MissingEvidenceOrCoverageGap);
        }

        validate_terminal_evidence(&self.evidence, &self.terminal_evidence)?;
        validate_correlation_key_evidence(&self.evidence, &self.correlation_keys)?;

        if self.class == SccmFindingClass::InsufficientEvidence && self.next_artifacts.is_empty() {
            return Err(SccmFindingValidationError::MissingNextArtifactRequest);
        }

        let has_terminal_failure = self
            .terminal_evidence
            .iter()
            .any(|terminal| terminal.kind == SccmTerminalEvidenceKind::ObservedFailure);

        if self.class == SccmFindingClass::ConfirmedFailure
            && self.confidence == SccmConfidence::High
            && !has_terminal_failure
            && !has_profiled_key_corroboration(&self.correlation_keys)
        {
            return Err(SccmFindingValidationError::MissingTerminalEvidence);
        }

        if self.class == SccmFindingClass::LikelyContributor
            && self.confidence == SccmConfidence::High
            && !has_terminal_failure
        {
            return Err(SccmFindingValidationError::LikelyContributorConfidenceTooHigh);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SccmFindingValidationError {
    MissingRequiredField,
    InvalidRole,
    InvalidEvidenceReference,
    ConflictingEvidenceReference,
    OverlappingEvidenceReference,
    MissingEvidenceOrCoverageGap,
    MissingTerminalEvidence,
    InvalidTerminalEvidence,
    TerminalEvidenceNotCited,
    CorrelationKeyMissingEvidence,
    CorrelationKeyEvidenceNotCited,
    InvalidCorrelationKey,
    LikelyContributorConfidenceTooHigh,
    MissingCoverageGap,
    InvalidCoverageGap,
    MissingNextArtifactRequest,
    UndeclaredArtifactRequest,
    ArtifactRequestRoleMismatch,
    InvalidArtifactRequestReason,
    TooManyArtifactRequests,
}

#[derive(Debug, Clone)]
pub struct SccmFindingBuilder {
    finding_id: String,
    class: Option<SccmFindingClass>,
    phase: Option<SccmPhase>,
    role: Option<SccmRole>,
    severity: Option<Severity>,
    confidence: Option<SccmConfidence>,
    title: String,
    summary: String,
    evidence: Vec<SccmEvidenceRef>,
    terminal_evidence: Vec<SccmTerminalEvidence>,
    coverage_gaps: Vec<SccmFindingCoverageGap>,
    correlation_keys: Vec<SccmCorrelationKey>,
    next_artifacts: Vec<SccmArtifactRequest>,
}

impl SccmFindingBuilder {
    pub fn new(finding_id: impl Into<String>) -> Self {
        let finding_id = finding_id.into();
        Self {
            title: finding_id.clone(),
            summary: finding_id.clone(),
            finding_id,
            class: None,
            phase: None,
            role: None,
            severity: None,
            confidence: None,
            evidence: Vec::new(),
            terminal_evidence: Vec::new(),
            coverage_gaps: Vec::new(),
            correlation_keys: Vec::new(),
            next_artifacts: Vec::new(),
        }
    }

    pub fn class(mut self, class: SccmFindingClass) -> Self {
        self.class = Some(class);
        self
    }

    pub fn phase(mut self, phase: SccmPhase) -> Self {
        self.phase = Some(phase);
        self
    }

    pub fn role(mut self, role: SccmRole) -> Self {
        self.role = Some(role);
        self
    }

    pub fn severity(mut self, severity: Severity) -> Self {
        self.severity = Some(severity);
        self
    }

    pub fn confidence(mut self, confidence: SccmConfidence) -> Self {
        self.confidence = Some(confidence);
        self
    }

    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = title.into();
        self
    }

    pub fn summary(mut self, summary: impl Into<String>) -> Self {
        self.summary = summary.into();
        self
    }

    pub fn evidence(mut self, evidence: Vec<SccmEvidenceRef>) -> Self {
        self.evidence = evidence;
        self
    }

    pub fn terminal_evidence(mut self, terminal_evidence: Vec<SccmTerminalEvidence>) -> Self {
        self.terminal_evidence = terminal_evidence;
        self
    }

    pub fn coverage_gap(mut self, coverage_gap: SccmFindingCoverageGap) -> Self {
        self.coverage_gaps.push(coverage_gap);
        self
    }

    pub fn coverage_gaps(mut self, coverage_gaps: Vec<SccmFindingCoverageGap>) -> Self {
        self.coverage_gaps = coverage_gaps;
        self
    }

    pub fn correlation_keys(mut self, correlation_keys: Vec<SccmCorrelationKey>) -> Self {
        self.correlation_keys = correlation_keys;
        self
    }

    pub fn next_artifact(mut self, next_artifact: SccmArtifactRequest) -> Self {
        self.next_artifacts.push(next_artifact);
        self
    }

    pub fn next_artifacts(mut self, next_artifacts: Vec<SccmArtifactRequest>) -> Self {
        self.next_artifacts = next_artifacts;
        self
    }

    pub fn build(self) -> Result<SccmFinding, SccmFindingValidationError> {
        if self.next_artifacts.len() > MAX_SCCM_NEXT_ARTIFACT_REQUESTS {
            return Err(SccmFindingValidationError::TooManyArtifactRequests);
        }

        let mut finding = SccmFinding {
            finding_id: self.finding_id,
            class: self
                .class
                .ok_or(SccmFindingValidationError::MissingRequiredField)?,
            phase: self
                .phase
                .ok_or(SccmFindingValidationError::MissingRequiredField)?,
            role: self
                .role
                .ok_or(SccmFindingValidationError::MissingRequiredField)?,
            severity: self
                .severity
                .ok_or(SccmFindingValidationError::MissingRequiredField)?,
            confidence: self
                .confidence
                .ok_or(SccmFindingValidationError::MissingRequiredField)?,
            title: self.title,
            summary: self.summary,
            evidence: self.evidence,
            terminal_evidence: self.terminal_evidence,
            coverage_gaps: self.coverage_gaps,
            correlation_keys: self.correlation_keys,
            next_artifacts: self.next_artifacts,
        };
        validate_raw_text_bounds(&finding)?;
        normalize_finding(&mut finding);
        finding.validate()?;
        Ok(finding)
    }
}

fn validate_raw_text_bounds(finding: &SccmFinding) -> Result<(), SccmFindingValidationError> {
    if !has_at_most_chars(&finding.title, MAX_SCCM_FINDING_TITLE_CHARS)
        || !has_at_most_chars(&finding.summary, MAX_SCCM_FINDING_SUMMARY_CHARS)
    {
        return Err(SccmFindingValidationError::MissingRequiredField);
    }
    if finding
        .next_artifacts
        .iter()
        .any(|request| !has_at_most_chars(&request.reason, MAX_SCCM_ARTIFACT_REQUEST_REASON_CHARS))
    {
        return Err(SccmFindingValidationError::InvalidArtifactRequestReason);
    }
    Ok(())
}

fn validate_required_text(finding: &SccmFinding) -> Result<(), SccmFindingValidationError> {
    let title = finding.title.trim();
    let summary = finding.summary.trim();
    if !is_canonical_opaque_id(&finding.finding_id)
        || title.is_empty()
        || summary.is_empty()
        || !finding.phase.has_canonical_serialized_form()
    {
        return Err(SccmFindingValidationError::MissingRequiredField);
    }
    Ok(())
}

fn validate_roles(finding: &SccmFinding) -> Result<(), SccmFindingValidationError> {
    if !finding.role.has_canonical_serialized_form()
        || finding
            .coverage_gaps
            .iter()
            .any(|gap| !gap.role.has_canonical_serialized_form())
        || finding
            .next_artifacts
            .iter()
            .any(|request| !request.role.has_canonical_serialized_form())
    {
        return Err(SccmFindingValidationError::InvalidRole);
    }
    Ok(())
}

/// Every reference a finding cites, across all three citation surfaces.
fn cited_evidence_references(finding: &SccmFinding) -> impl Iterator<Item = &SccmEvidenceRef> {
    finding
        .evidence
        .iter()
        .chain(
            finding
                .terminal_evidence
                .iter()
                .map(|terminal| &terminal.reference),
        )
        .chain(
            finding
                .correlation_keys
                .iter()
                .filter_map(|key| key.evidence.as_ref()),
        )
}

fn validate_all_evidence_references(
    finding: &SccmFinding,
) -> Result<(), SccmFindingValidationError> {
    let mut references_by_identity: BTreeMap<(&str, &str), &SccmEvidenceRef> = BTreeMap::new();
    for reference in cited_evidence_references(finding) {
        validate_evidence_reference(reference)?;
        if references_by_identity
            .insert(evidence_identity(reference), reference)
            .is_some_and(|existing| {
                (existing.line_start, existing.line_end)
                    != (reference.line_start, reference.line_end)
            })
        {
            return Err(SccmFindingValidationError::ConflictingEvidenceReference);
        }
    }
    validate_disjoint_evidence_spans(&references_by_identity)
}

/// Whether two references claim overlapping physical lines of one source.
///
/// Physical extent, not an identity tuple, is the question. Two logical
/// records of one artifact occupy disjoint lines, so any overlap means at
/// least one of them is not the record it claims to be. Bounds are inclusive,
/// so equal spans are the degenerate overlap and abutting spans (`1-2` beside
/// `3-4`) are not one. A reference that carries no bounds asserts no extent and
/// therefore cannot be shown to claim another reference's lines.
///
/// This presumes bounds that already passed a validity gate. An inverted range
/// reads as empty under an inclusive test and would be silently judged disjoint
/// from everything, so the gate has to run first, not after: the spine calls
/// [`validate_evidence_reference`] on every reference before any pair reaches
/// this predicate, and a reducer that hands over unvalidated references is
/// responsible for its own gate.
pub(crate) fn evidence_references_overlap(left: &SccmEvidenceRef, right: &SccmEvidenceRef) -> bool {
    if left.artifact_id != right.artifact_id {
        return false;
    }
    matches!(
        (
            left.line_start,
            left.line_end,
            right.line_start,
            right.line_end,
        ),
        (Some(left_start), Some(left_end), Some(right_start), Some(right_end))
            if left_start <= right_end && right_start <= left_end
    )
}

/// Rejects a finding whose citations claim the same physical records twice.
///
/// Identity equality only catches an exact repeat of one range. It leaves the
/// wider hole open: `1-2` and `1-1` are different entry ids over the same
/// physical line, so both survive, each cites the same record, and
/// [`compare_evidence_refs`] then ranks one above the other on nothing but
/// span width. Both the management-point and client-policy reducers had to
/// close this in their own code; enforcing it here closes it for every finding
/// regardless of which reducer, or none, assembled it.
///
/// References arrive keyed by identity, so each entry id contributes exactly
/// one span and a repeated identity is already a
/// [`SccmFindingValidationError::ConflictingEvidenceReference`]. Sorting each
/// artifact's spans by start line lets one pass answer the question: a span
/// that clears the widest span seen so far clears every earlier one, because
/// no earlier span starts later or ends further.
fn validate_disjoint_evidence_spans(
    references_by_identity: &BTreeMap<(&str, &str), &SccmEvidenceRef>,
) -> Result<(), SccmFindingValidationError> {
    let mut by_artifact: BTreeMap<&str, Vec<&SccmEvidenceRef>> = BTreeMap::new();
    for reference in references_by_identity.values() {
        if reference.line_start.is_some() && reference.line_end.is_some() {
            by_artifact
                .entry(reference.artifact_id.as_str())
                .or_default()
                .push(reference);
        }
    }

    for mut spans in by_artifact.into_values() {
        spans.sort_by(|left, right| {
            left.line_start
                .cmp(&right.line_start)
                .then_with(|| left.line_end.cmp(&right.line_end))
        });
        let mut widest: Option<&SccmEvidenceRef> = None;
        for span in spans {
            if widest.is_some_and(|widest| evidence_references_overlap(widest, span)) {
                return Err(SccmFindingValidationError::OverlappingEvidenceReference);
            }
            if widest.is_none_or(|widest| widest.line_end < span.line_end) {
                widest = Some(span);
            }
        }
    }
    Ok(())
}

fn validate_evidence_reference(
    reference: &SccmEvidenceRef,
) -> Result<(), SccmFindingValidationError> {
    let valid_line_range = match (reference.line_start, reference.line_end) {
        (None, None) => true,
        (Some(start), Some(end)) => start > 0 && end >= start,
        _ => false,
    };
    if !is_canonical_opaque_id(&reference.artifact_id)
        || !is_canonical_opaque_id(&reference.entry_id)
        || !valid_line_range
    {
        return Err(SccmFindingValidationError::InvalidEvidenceReference);
    }
    Ok(())
}

fn validate_coverage_gaps(
    coverage_gaps: &[SccmFindingCoverageGap],
) -> Result<(), SccmFindingValidationError> {
    let mut coverage_by_artifact: BTreeMap<&str, &SccmFindingCoverageGap> = BTreeMap::new();
    for gap in coverage_gaps {
        if !is_canonical_opaque_id(&gap.artifact_id) || gap.coverage == SccmCoverageState::Captured
        {
            return Err(SccmFindingValidationError::InvalidCoverageGap);
        }

        if let Some(previous) = coverage_by_artifact.get(gap.artifact_id.as_str()) {
            if previous.role != gap.role || previous.coverage != gap.coverage {
                return Err(SccmFindingValidationError::InvalidCoverageGap);
            }
        } else {
            coverage_by_artifact.insert(gap.artifact_id.as_str(), gap);
        }
    }
    Ok(())
}

fn validate_artifact_requests(
    requests: &[SccmArtifactRequest],
) -> Result<(), SccmFindingValidationError> {
    if requests.len() > MAX_SCCM_NEXT_ARTIFACT_REQUESTS {
        return Err(SccmFindingValidationError::TooManyArtifactRequests);
    }

    let catalog = declared_source_catalog();
    for request in requests {
        if !is_canonical_opaque_id(&request.logical_id) {
            return Err(SccmFindingValidationError::UndeclaredArtifactRequest);
        }

        let mut logical_matches = catalog
            .iter()
            .filter(|entry| entry.logical_name == request.logical_id);
        let Some(first_match) = logical_matches.next() else {
            return Err(SccmFindingValidationError::UndeclaredArtifactRequest);
        };
        let requested_source = if first_match.role == request.role {
            first_match
        } else if let Some(role_match) = logical_matches.find(|entry| entry.role == request.role) {
            role_match
        } else {
            return Err(SccmFindingValidationError::ArtifactRequestRoleMismatch);
        };
        if !is_bounded_request_reason(
            &request.reason,
            &requested_source.basename,
            &requested_source.logical_name,
        ) {
            return Err(SccmFindingValidationError::InvalidArtifactRequestReason);
        }
    }
    Ok(())
}

fn is_bounded_request_reason(
    reason: &str,
    requested_basename: &str,
    requested_logical_id: &str,
) -> bool {
    let trimmed = reason.trim();
    if !has_at_most_chars(reason, MAX_SCCM_ARTIFACT_REQUEST_REASON_CHARS)
        || trimmed.is_empty()
        || !trimmed
            .chars()
            .any(|character| character.is_ascii_alphanumeric())
        || contains_rooted_path(trimmed)
        || trimmed.contains(['*', '?', '[', ']'])
    {
        return false;
    }

    let lowercase = trimmed.to_ascii_lowercase();
    let authorization = CatalogArtifactRequestScope {
        basename: requested_basename,
        logical_id: requested_logical_id,
        task_sequence_alias: requested_logical_id.eq_ignore_ascii_case("smsts"),
    };
    if !reason_scope_is_within_catalog_artifact(&lowercase, &authorization) {
        return false;
    }
    let clauses_are_bounded = request_clauses(&lowercase).all(|clause| {
        !has_unbounded_request_scope(clause, requested_basename, requested_logical_id)
    });
    clauses_are_bounded
}

fn contains_rooted_path(reason: &str) -> bool {
    let bytes = reason.as_bytes();
    bytes.iter().enumerate().any(|(index, byte)| {
        matches!(byte, b'/' | b'\\')
            && (index == 0
                || !matches!(
                    bytes[index - 1],
                    b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'-' | b'.'
                ))
    })
}

// The reason remains descriptive text: authorization comes only from the
// catalog entry already selected by logical ID and role. Each clause is
// evaluated independently so punctuation cannot lend a later modifier either
// collection intent or an artifact identity from another clause.
#[derive(Clone, Copy)]
struct CatalogArtifactRequestScope<'a> {
    basename: &'a str,
    logical_id: &'a str,
    task_sequence_alias: bool,
}

#[derive(Clone, Copy)]
struct RequestReasonToken<'a> {
    text: &'a str,
    start: usize,
    end: usize,
}

fn reason_scope_is_within_catalog_artifact(
    reason: &str,
    authorization: &CatalogArtifactRequestScope<'_>,
) -> bool {
    if has_unbounded_path_form(reason) {
        return false;
    }

    request_clauses(reason).all(|clause| {
        let tokens = tokenize_request_reason(clause);
        let identity_ranges = exact_collectable_identity_ranges(clause, authorization);
        let is_confirmation = tokens.first().is_some_and(|token| token.text == "confirm");
        let contains_collection_directive =
            tokens.iter().any(|token| is_collection_action(token.text));

        if is_confirmation {
            confirmation_clause_is_non_authorizing(clause, &tokens, &identity_ranges)
        } else if contains_collection_directive {
            collection_clause_is_catalog_bounded(clause, &tokens, &identity_ranges)
        } else {
            // A clause without a recognized collection action is never an
            // alternate authorization path. It must independently match the
            // same positive, non-authorizing evidence grammar.
            narrative_clause_is_safe_observation(clause, &tokens, &identity_ranges)
        }
    })
}

fn has_unbounded_path_form(reason: &str) -> bool {
    contains_rooted_path(reason)
        || contains_drive_designator(reason)
        || contains_environment_path(reason)
        || reason
            .as_bytes()
            .windows(3)
            .any(|window| matches!(window, b"../" | b"..\\"))
}

fn contains_drive_designator(reason: &str) -> bool {
    let bytes = reason.as_bytes();
    bytes.windows(2).enumerate().any(|(index, pair)| {
        pair[0].is_ascii_alphabetic()
            && pair[1] == b':'
            && (index == 0
                || !matches!(
                    bytes[index - 1],
                    b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_'
                ))
    })
}

fn contains_environment_path(reason: &str) -> bool {
    let percent_offsets = reason
        .match_indices('%')
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    let has_percent_expansion = percent_offsets.windows(2).any(|pair| {
        let variable = &reason[pair[0] + 1..pair[1]];
        !variable.is_empty()
            && variable
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '_')
    });
    has_percent_expansion || reason.contains("$env:")
}

fn tokenize_request_reason(reason: &str) -> Vec<RequestReasonToken<'_>> {
    let mut tokens = Vec::new();
    let mut token_start = None;

    for (index, character) in reason.char_indices() {
        if character.is_ascii_alphanumeric() || character == '_' {
            token_start.get_or_insert(index);
        } else if let Some(start) = token_start.take() {
            tokens.push(RequestReasonToken {
                text: &reason[start..index],
                start,
                end: index,
            });
        }
    }
    if let Some(start) = token_start {
        tokens.push(RequestReasonToken {
            text: &reason[start..],
            start,
            end: reason.len(),
        });
    }
    tokens
}

fn exact_collectable_identity_ranges(
    reason: &str,
    authorization: &CatalogArtifactRequestScope<'_>,
) -> Vec<(usize, usize)> {
    let basename = catalog_log_stem(authorization.basename).to_ascii_lowercase();
    let logical_id = authorization.logical_id.to_ascii_lowercase();
    let mut aliases = vec![
        format!("{basename}.log"),
        format!("{logical_id}.log"),
        format!("{basename} file"),
        format!("{logical_id} file"),
        format!("{basename} record"),
        format!("{logical_id} record"),
        format!("logs/{basename}.log"),
        format!(r"logs\{basename}.log"),
    ];
    if authorization.task_sequence_alias {
        aliases.extend([
            "task sequence log".to_owned(),
            "disk imaging task sequence log".to_owned(),
            "disk-image task sequence log".to_owned(),
        ]);
    }
    aliases.sort_by_key(|alias| std::cmp::Reverse(alias.len()));
    aliases.dedup();

    let mut ranges = aliases
        .iter()
        .flat_map(|alias| exact_alias_ranges(reason, alias))
        .collect::<Vec<_>>();
    for terminal_alias in [basename, logical_id] {
        ranges.extend(exact_terminal_alias_ranges(reason, &terminal_alias));
    }
    ranges.sort_unstable();
    ranges.dedup();
    ranges
}

fn exact_alias_ranges(reason: &str, alias: &str) -> Vec<(usize, usize)> {
    reason
        .match_indices(alias)
        .filter_map(|(start, matched)| {
            let end = start + matched.len();
            exact_identity_boundary(reason, start, end).then_some((start, end))
        })
        .collect()
}

fn exact_terminal_alias_ranges(reason: &str, alias: &str) -> Vec<(usize, usize)> {
    reason
        .match_indices(alias)
        .filter_map(|(start, matched)| {
            let end = start + matched.len();
            (exact_identity_boundary(reason, start, end) && reason[end..].trim().is_empty())
                .then_some((start, end))
        })
        .collect()
}

fn exact_identity_boundary(reason: &str, start: usize, end: usize) -> bool {
    let before = reason[..start].chars().next_back();
    let after = reason[end..].chars().next();
    before.is_none_or(|character| !is_identity_continuation(character))
        && after.is_none_or(|character| !is_identity_continuation(character))
}

fn catalog_log_stem(basename: &str) -> &str {
    basename.strip_suffix(".log").unwrap_or(basename)
}

fn is_identity_continuation(character: char) -> bool {
    character.is_ascii_alphanumeric()
        || matches!(
            character,
            '_' | '-'
                | '.'
                | '\u{2010}'
                | '\u{2011}'
                | '\u{2012}'
                | '\u{2013}'
                | '\u{2014}'
                | '\u{2015}'
                | '\u{2212}'
        )
}

fn collection_clause_is_catalog_bounded(
    clause: &str,
    tokens: &[RequestReasonToken<'_>],
    identity_ranges: &[(usize, usize)],
) -> bool {
    if identity_ranges.is_empty()
        || !collection_actions_have_exact_catalog_targets(clause, tokens, identity_ranges)
    {
        return false;
    }

    tokens.iter().enumerate().all(|(index, token)| {
        if token_is_covered_by_identity(token, identity_ranges) {
            return true;
        }
        if is_external_collection_container(token.text)
            || matches!(token.text, "data" | "everything")
        {
            return false;
        }
        if matches!(token.text, "file" | "files" | "log" | "logs") {
            return token_is_adjacent_to_identity(tokens, index, identity_ranges);
        }
        true
    })
}

fn collection_actions_have_exact_catalog_targets(
    clause: &str,
    tokens: &[RequestReasonToken<'_>],
    identity_ranges: &[(usize, usize)],
) -> bool {
    let mut action_indices = tokens
        .iter()
        .enumerate()
        .filter_map(|(index, token)| is_collection_action(token.text).then_some(index))
        .peekable();

    while let Some(action_index) = action_indices.next() {
        let segment_end = action_indices.peek().copied().unwrap_or(tokens.len());
        let has_following_action = action_indices.peek().is_some();
        if !collection_action_has_exact_catalog_target(
            clause,
            &tokens[action_index..segment_end],
            identity_ranges,
            has_following_action,
        ) {
            return false;
        }
    }
    true
}

fn collection_action_has_exact_catalog_target(
    clause: &str,
    segment: &[RequestReasonToken<'_>],
    identity_ranges: &[(usize, usize)],
    has_following_action: bool,
) -> bool {
    // Fail closed around the target shape:
    // action + bounded modifiers + exact catalog identity + optional narrative.
    // A catalog mention reached only after arbitrary target words is evidence
    // context, not authorization for those earlier words.
    let Some(action) = segment.first() else {
        return false;
    };
    let segment_end = segment.last().map_or(action.end, |token| token.end);
    let Some((target_start, target_end)) = identity_ranges
        .iter()
        .filter(|(start, end)| *start >= action.end && *end <= segment_end)
        .min_by_key(|(start, end)| (*start, std::cmp::Reverse(*end)))
        .copied()
    else {
        return false;
    };

    let leading_is_target_grammar = segment
        .iter()
        .skip(1)
        .take_while(|token| token.end <= target_start)
        .all(|token| is_catalog_target_modifier(token.text));
    if !leading_is_target_grammar || has_unbound_dotted_target(clause, segment, identity_ranges) {
        return false;
    }

    let mut trailing = segment
        .iter()
        .filter(|token| token.start >= target_end)
        .peekable();
    while trailing
        .peek()
        .is_some_and(|token| is_catalog_target_suffix(token.text))
    {
        trailing.next();
    }
    let trailing = trailing.copied().collect::<Vec<_>>();
    if trailing.is_empty() {
        return true;
    }
    if has_following_action
        && trailing
            .iter()
            .all(|token| is_action_coordinator(token.text))
    {
        return true;
    }
    if !is_collection_narrative_introducer(trailing[0].text) {
        return false;
    }
    if !narrative_suffix_is_non_authorizing(clause, &trailing, identity_ranges) {
        return false;
    }

    trailing.iter().enumerate().all(|(index, token)| {
        if !is_action_coordinator(token.text) {
            return true;
        }
        trailing
            .get(index + 1)
            .is_some_and(|next| is_safe_narrative_continuation(next.text))
    })
}

fn is_catalog_target_modifier(token: &str) -> bool {
    matches!(
        token,
        "a" | "all"
            | "an"
            | "cited"
            | "complete"
            | "current"
            | "entire"
            | "every"
            | "exact"
            | "full"
            | "named"
            | "of"
            | "requested"
            | "rotation"
            | "rotations"
            | "the"
            | "whole"
    )
}

fn is_catalog_target_suffix(token: &str) -> bool {
    matches!(token, "entry" | "file" | "record")
}

fn is_collection_narrative_introducer(token: &str) -> bool {
    matches!(
        token,
        "after"
            | "as"
            | "because"
            | "before"
            | "cited"
            | "for"
            | "from"
            | "recorded"
            | "reported"
            | "since"
            | "with"
    )
}

fn is_action_coordinator(token: &str) -> bool {
    matches!(token, "and" | "plus" | "then")
}

fn is_safe_narrative_continuation(token: &str) -> bool {
    matches!(
        token,
        "after" | "as" | "because" | "before" | "for" | "from" | "since" | "with"
    )
}

fn has_unbound_dotted_target(
    clause: &str,
    segment: &[RequestReasonToken<'_>],
    identity_ranges: &[(usize, usize)],
) -> bool {
    segment.windows(2).any(|pair| {
        clause[pair[0].end..pair[1].start].contains('.')
            && !identity_ranges
                .iter()
                .any(|(start, end)| pair[0].start >= *start && pair[1].end <= *end)
    })
}

fn confirmation_clause_is_non_authorizing(
    clause: &str,
    tokens: &[RequestReasonToken<'_>],
    identity_ranges: &[(usize, usize)],
) -> bool {
    if has_unbound_dotted_target(clause, tokens, identity_ranges)
        || tokens
            .iter()
            .any(|token| is_collection_scope_nominal(token.text))
        || has_passive_unbounded_confirmation_request(tokens, identity_ranges)
        || !confirmation_tokens_match_defined_form(tokens, identity_ranges)
    {
        return false;
    }

    let has_identity = !identity_ranges.is_empty();
    let has_retry = tokens.iter().any(|token| token.text == "retry");
    let has_root_cause = tokens
        .windows(2)
        .any(|pair| pair[0].text == "root" && pair[1].text == "cause");
    let has_assignment_or_policy = tokens
        .iter()
        .any(|token| matches!(token.text, "assignment" | "policy"));
    let has_state_observation = tokens.iter().any(|token| {
        matches!(
            token.text,
            "download" | "downloaded" | "encryption" | "image" | "imaging" | "state" | "status"
        )
    });
    let has_download_observation = tokens
        .iter()
        .any(|token| matches!(token.text, "downloaded" | "state" | "status"));

    for token in tokens {
        if is_collection_action(token.text)
            && !(token.text == "download" && has_identity && has_download_observation)
        {
            return false;
        }
        if token.text.starts_with("recurs") && !(has_identity && has_retry) {
            return false;
        }
        if token.text.starts_with("root") && !(has_identity && has_root_cause) {
            return false;
        }
        if is_wide_scope_token(token.text) && !(has_identity && has_assignment_or_policy) {
            return false;
        }
        if matches!(
            token.text,
            "directory"
                | "directories"
                | "drive"
                | "drives"
                | "filesystem"
                | "filesystems"
                | "folder"
                | "folders"
                | "volume"
                | "volumes"
                | "data"
                | "everything"
        ) {
            return false;
        }
        if matches!(token.text, "disk" | "disks" | "file" | "files")
            && !token_is_covered_by_identity(token, identity_ranges)
            && !(has_identity && has_state_observation)
        {
            return false;
        }
        if matches!(
            token.text,
            "client" | "device" | "machine" | "site" | "system"
        ) && !(has_identity && (has_assignment_or_policy || has_state_observation))
        {
            return false;
        }
    }
    true
}

fn has_passive_unbounded_confirmation_request(
    tokens: &[RequestReasonToken<'_>],
    identity_ranges: &[(usize, usize)],
) -> bool {
    tokens
        .iter()
        .enumerate()
        .any(|(auxiliary_index, auxiliary)| {
            if !is_passive_auxiliary(auxiliary.text) {
                return false;
            }

            let body = &tokens[1..];
            let has_broad_target = body.iter().any(|token| is_broad_quantifier(token.text))
                && body.iter().any(|token| {
                    is_collection_target(token.text)
                        && !token_is_covered_by_identity(token, identity_ranges)
                });
            if !has_broad_target {
                return false;
            }

            let predicate = &tokens[auxiliary_index + 1..];
            let broad_target_follows_auxiliary = predicate
                .iter()
                .any(|token| is_broad_quantifier(token.text))
                && predicate.iter().any(|token| {
                    is_collection_target(token.text)
                        && !token_is_covered_by_identity(token, identity_ranges)
                });
            let has_explicit_bounded_state_observation = !broad_target_follows_auxiliary
                && !identity_ranges.is_empty()
                && predicate.iter().any(|token| token.text == "downloaded");

            matches!(auxiliary.text, "must" | "need" | "needs" | "should")
                || broad_target_follows_auxiliary
                || predicate.iter().any(|token| {
                    matches!(
                        token.text,
                        "archived"
                            | "captured"
                            | "collected"
                            | "copied"
                            | "exported"
                            | "gathered"
                            | "included"
                            | "provided"
                            | "required"
                    )
                })
                || !has_explicit_bounded_state_observation
        })
}

fn confirmation_tokens_match_defined_form(
    tokens: &[RequestReasonToken<'_>],
    identity_ranges: &[(usize, usize)],
) -> bool {
    let Some((confirmation, body)) = tokens.split_first() else {
        return false;
    };
    if confirmation.text != "confirm" {
        return false;
    }

    let has_subject = body.iter().any(|token| {
        token_is_covered_by_identity(token, identity_ranges)
            || is_evidence_narrative_subject(token.text)
            || matches!(
                token.text,
                "behavior"
                    | "cause"
                    | "content"
                    | "download"
                    | "encryption"
                    | "image"
                    | "imaging"
                    | "retry"
            )
    });
    has_subject
        && body.iter().all(|token| {
            token_is_covered_by_identity(token, identity_ranges)
                || is_evidence_narrative_subject(token.text)
                || is_evidence_narrative_predicate(token.text)
                || matches!(
                    token.text,
                    "a" | "all"
                        | "as"
                        | "behavior"
                        | "bounded"
                        | "by"
                        | "cause"
                        | "cited"
                        | "client"
                        | "code"
                        | "complete"
                        | "content"
                        | "disk"
                        | "download"
                        | "downloaded"
                        | "encryption"
                        | "every"
                        | "file"
                        | "files"
                        | "for"
                        | "full"
                        | "ids"
                        | "image"
                        | "imaging"
                        | "in"
                        | "not"
                        | "of"
                        | "record"
                        | "recursive"
                        | "retry"
                        | "root"
                        | "system"
                        | "the"
                        | "whole"
                        | "wide"
                )
        })
}

fn narrative_clause_has_no_collection_scope(tokens: &[RequestReasonToken<'_>]) -> bool {
    let has_broad_scope = tokens.iter().any(|token| is_broad_quantifier(token.text));
    !tokens.iter().any(|token| {
        token.text.starts_with("recurs")
            || token.text.starts_with("root")
            || is_wide_scope_token(token.text)
            || is_external_collection_container(token.text)
            || matches!(token.text, "data" | "everything")
            || (has_broad_scope
                && matches!(
                    token.text,
                    "file" | "files" | "log" | "logs" | "record" | "records"
                ))
    })
}

fn narrative_clause_is_safe_observation(
    clause: &str,
    tokens: &[RequestReasonToken<'_>],
    identity_ranges: &[(usize, usize)],
) -> bool {
    narrative_tokens_are_non_authorizing(clause, tokens, identity_ranges)
        && narrative_tokens_have_evidence_observation(tokens, identity_ranges)
}

fn narrative_suffix_is_non_authorizing(
    clause: &str,
    tokens: &[RequestReasonToken<'_>],
    identity_ranges: &[(usize, usize)],
) -> bool {
    narrative_tokens_are_non_authorizing(clause, tokens, identity_ranges)
        && (narrative_tokens_have_evidence_observation(tokens, identity_ranges)
            || is_bounded_reference_suffix(tokens)
            || is_bounded_bundle_suffix(tokens)
            || is_bounded_completion_suffix(tokens))
}

fn narrative_tokens_have_evidence_observation(
    tokens: &[RequestReasonToken<'_>],
    identity_ranges: &[(usize, usize)],
) -> bool {
    tokens.iter().all(|token| {
        token_is_covered_by_identity(token, identity_ranges)
            || is_evidence_narrative_subject(token.text)
            || is_evidence_narrative_predicate(token.text)
            || is_collection_narrative_introducer(token.text)
            || is_action_coordinator(token.text)
            || matches!(
                token.text,
                "a" | "an" | "by" | "in" | "not" | "of" | "review" | "the" | "to"
            )
    }) && tokens.iter().any(|token| {
        token_is_covered_by_identity(token, identity_ranges)
            || is_evidence_narrative_subject(token.text)
    }) && tokens
        .iter()
        .any(|token| is_evidence_narrative_predicate(token.text))
}

fn is_bounded_reference_suffix(tokens: &[RequestReasonToken<'_>]) -> bool {
    tokens.first().is_some_and(|token| token.text == "cited")
        && tokens.iter().any(|token| token.text == "by")
        && tokens
            .iter()
            .any(|token| matches!(token.text, "assignment" | "entry"))
        && tokens.iter().all(|token| {
            matches!(
                token.text,
                "a" | "an"
                    | "assignment"
                    | "by"
                    | "cited"
                    | "entry"
                    | "exact"
                    | "id"
                    | "reference"
                    | "requested"
                    | "the"
            )
        })
}

fn is_bounded_bundle_suffix(tokens: &[RequestReasonToken<'_>]) -> bool {
    tokens.first().is_some_and(|token| token.text == "from")
        && tokens.iter().any(|token| token.text == "bounded")
        && tokens.iter().any(|token| token.text == "bundle")
        && tokens.iter().all(|token| {
            matches!(
                token.text,
                "a" | "an" | "bounded" | "bundle" | "from" | "requested" | "the"
            )
        })
}

fn is_bounded_completion_suffix(tokens: &[RequestReasonToken<'_>]) -> bool {
    tokens
        .first()
        .is_some_and(|token| matches!(token.text, "after" | "before"))
        && tokens.iter().any(|token| token.text == "completion")
        && tokens.iter().all(|token| {
            token
                .text
                .chars()
                .all(|character| character.is_ascii_digit())
                || matches!(
                    token.text,
                    "after" | "and" | "before" | "completion" | "plus" | "then"
                )
        })
}

fn narrative_tokens_are_non_authorizing(
    clause: &str,
    tokens: &[RequestReasonToken<'_>],
    identity_ranges: &[(usize, usize)],
) -> bool {
    narrative_clause_has_no_collection_scope(tokens)
        && !has_unbound_dotted_target(clause, tokens, identity_ranges)
        && !tokens
            .iter()
            .any(|token| is_collection_scope_nominal(token.text))
        && !has_unbound_passive_artifact_request(tokens, identity_ranges)
}

fn is_collection_scope_nominal(token: &str) -> bool {
    matches!(
        token,
        "collection" | "collections" | "inclusion" | "inclusions" | "traversal" | "traversals"
    )
}

fn has_unbound_passive_artifact_request(
    tokens: &[RequestReasonToken<'_>],
    identity_ranges: &[(usize, usize)],
) -> bool {
    tokens.iter().enumerate().any(|(index, token)| {
        is_passive_auxiliary(token.text)
            && (!passive_subject_is_evidence(tokens, index, identity_ranges)
                || !passive_predicate_is_evidence_state(tokens, index, identity_ranges))
    })
}

fn passive_subject_is_evidence(
    tokens: &[RequestReasonToken<'_>],
    auxiliary_index: usize,
    identity_ranges: &[(usize, usize)],
) -> bool {
    let subject_start = tokens[..auxiliary_index]
        .iter()
        .rposition(|token| {
            is_collection_narrative_introducer(token.text) || is_action_coordinator(token.text)
        })
        .map_or(0, |index| index + 1);

    tokens[subject_start..auxiliary_index].iter().any(|token| {
        token_is_covered_by_identity(token, identity_ranges)
            || is_evidence_narrative_subject(token.text)
    })
}

fn passive_predicate_is_evidence_state(
    tokens: &[RequestReasonToken<'_>],
    auxiliary_index: usize,
    identity_ranges: &[(usize, usize)],
) -> bool {
    let predicate = &tokens[auxiliary_index + 1..];
    if predicate.is_empty() {
        return false;
    }

    let has_exact_identity = predicate
        .iter()
        .any(|token| token_is_covered_by_identity(token, identity_ranges));
    predicate.iter().all(|token| {
        token_is_covered_by_identity(token, identity_ranges)
            || is_evidence_narrative_subject(token.text)
            || is_evidence_narrative_predicate(token.text)
            || is_collection_narrative_introducer(token.text)
            || is_action_coordinator(token.text)
            || matches!(
                token.text,
                "a" | "an" | "by" | "in" | "not" | "of" | "the" | "to"
            )
            || (has_exact_identity
                && matches!(
                    token.text,
                    "contain"
                        | "contained"
                        | "containing"
                        | "contains"
                        | "exact"
                        | "include"
                        | "included"
                        | "includes"
                        | "including"
                        | "requested"
                ))
    })
}

fn is_passive_auxiliary(token: &str) -> bool {
    matches!(
        token,
        "are"
            | "be"
            | "been"
            | "being"
            | "had"
            | "has"
            | "have"
            | "is"
            | "must"
            | "need"
            | "needs"
            | "should"
            | "was"
            | "were"
    )
}

fn is_evidence_narrative_subject(token: &str) -> bool {
    matches!(
        token,
        "access"
            | "assignment"
            | "coverage"
            | "error"
            | "evaluation"
            | "evidence"
            | "failure"
            | "finding"
            | "outcome"
            | "policy"
            | "request"
            | "response"
            | "source"
            | "state"
            | "status"
    )
}

fn is_evidence_narrative_predicate(token: &str) -> bool {
    is_passive_auxiliary(token)
        || matches!(
            token,
            "available"
                | "capped"
                | "captured"
                | "denied"
                | "failed"
                | "had"
                | "has"
                | "have"
                | "malformed"
                | "missing"
                | "partial"
                | "provided"
                | "recorded"
                | "reported"
                | "required"
                | "skipped"
                | "succeeded"
                | "unavailable"
                | "unsupported"
        )
}

fn is_wide_scope_token(token: &str) -> bool {
    token == "wide"
        || token
            .strip_suffix("wide")
            .is_some_and(|prefix| !prefix.is_empty())
}

fn is_external_collection_container(token: &str) -> bool {
    matches!(
        token,
        "client"
            | "clients"
            | "device"
            | "devices"
            | "directory"
            | "directories"
            | "disk"
            | "disks"
            | "drive"
            | "drives"
            | "filesystem"
            | "filesystems"
            | "folder"
            | "folders"
            | "machine"
            | "machines"
            | "site"
            | "sites"
            | "system"
            | "systems"
            | "volume"
            | "volumes"
    )
}

fn token_is_covered_by_identity(
    token: &RequestReasonToken<'_>,
    identity_ranges: &[(usize, usize)],
) -> bool {
    identity_ranges
        .iter()
        .any(|(start, end)| token.start >= *start && token.end <= *end)
}

fn token_is_adjacent_to_identity(
    tokens: &[RequestReasonToken<'_>],
    token_index: usize,
    identity_ranges: &[(usize, usize)],
) -> bool {
    token_index
        .checked_sub(1)
        .and_then(|index| tokens.get(index))
        .is_some_and(|token| token_is_covered_by_identity(token, identity_ranges))
        || tokens
            .get(token_index + 1)
            .is_some_and(|token| token_is_covered_by_identity(token, identity_ranges))
}

fn request_clauses(reason: &str) -> impl Iterator<Item = &str> {
    let mut clauses = Vec::new();
    let mut start = 0;
    let mut characters = reason.char_indices().peekable();

    while let Some((index, character)) = characters.next() {
        let next = characters.peek().map(|(_, next)| *next);
        let is_sentence_period =
            character == '.' && next.is_none_or(|next| !next.is_ascii_alphanumeric());
        if matches!(character, ';' | '\n' | '\r' | '!' | '?') || is_sentence_period {
            let clause = reason[start..index].trim();
            if !clause.is_empty() {
                clauses.push(clause);
            }
            start = index + character.len_utf8();
        }
    }

    let trailing = reason[start..].trim();
    if !trailing.is_empty() {
        clauses.push(trailing);
    }
    clauses.into_iter()
}

fn has_unbounded_request_scope(
    clause: &str,
    requested_basename: &str,
    requested_logical_id: &str,
) -> bool {
    let tokens = clause
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();

    tokens.iter().any(|token| is_compact_unbounded_scope(token))
        || tokens
            .iter()
            .any(|token| matches!(*token, "glob" | "globs" | "globbing"))
        || has_recursive_collection_scope(&tokens)
        || has_wide_collection_scope(&tokens)
        || has_root_collection_scope(&tokens)
        || has_unscoped_broad_collection_scope(&tokens, requested_basename, requested_logical_id)
}

fn is_collection_action(token: &str) -> bool {
    matches!(
        token,
        "archive"
            | "capture"
            | "collect"
            | "copy"
            | "download"
            | "enumerate"
            | "export"
            | "gather"
            | "inspect"
            | "obtain"
            | "read"
            | "scan"
            | "search"
            | "walk"
            | "traverse"
    )
}

fn is_collection_target(token: &str) -> bool {
    matches!(
        token,
        "file"
            | "files"
            | "directory"
            | "directories"
            | "folder"
            | "folders"
            | "drive"
            | "drives"
            | "disk"
            | "disks"
            | "volume"
            | "volumes"
            | "filesystem"
            | "filesystems"
            | "log"
            | "logs"
            | "artifact"
            | "artifacts"
            | "evidence"
    )
}

fn is_compact_unbounded_scope(token: &str) -> bool {
    ["all", "every", "entire", "whole", "full", "complete"]
        .iter()
        .any(|prefix| token.strip_prefix(prefix).is_some_and(is_collection_target))
}

fn is_collection_container(token: &str) -> bool {
    matches!(
        token,
        "client"
            | "clients"
            | "device"
            | "devices"
            | "directory"
            | "directories"
            | "disk"
            | "disks"
            | "drive"
            | "drives"
            | "filesystem"
            | "filesystems"
            | "folder"
            | "folders"
            | "machine"
            | "machines"
            | "site"
            | "sites"
            | "system"
            | "systems"
            | "volume"
            | "volumes"
    )
}

fn is_collection_scope_subject(token: &str) -> bool {
    is_collection_target(token) || matches!(token, "archive" | "collection" | "scope" | "traversal")
}

fn has_recursive_collection_scope(tokens: &[&str]) -> bool {
    let mentions_recursion = tokens.iter().any(|token| token.starts_with("recurs"));
    let describes_collection = tokens.iter().any(|token| {
        is_collection_action(token)
            || is_collection_container(token)
            || matches!(*token, "collection" | "inclusion" | "traversal")
    });
    mentions_recursion && describes_collection
}

fn has_wide_collection_scope(tokens: &[&str]) -> bool {
    tokens.iter().enumerate().any(|(index, token)| {
        let compound = token
            .strip_suffix("wide")
            .is_some_and(is_collection_container)
            && tokens
                .get(index + 1)
                .is_some_and(|target| is_collection_scope_subject(target));
        let separated = is_collection_container(token)
            && tokens.get(index + 1) == Some(&"wide")
            && tokens
                .get(index + 2)
                .is_some_and(|target| is_collection_scope_subject(target));

        compound || separated
    })
}

fn has_root_collection_scope(tokens: &[&str]) -> bool {
    tokens.iter().enumerate().any(|(root_index, token)| {
        if !token.starts_with("root") || tokens.get(root_index + 1) == Some(&"cause") {
            return false;
        }
        tokens.iter().any(|candidate| {
            is_collection_action(candidate) || is_collection_scope_subject(candidate)
        })
    })
}

fn is_broad_quantifier(token: &str) -> bool {
    matches!(
        token,
        "all" | "every" | "entire" | "whole" | "full" | "complete"
    )
}

fn has_unscoped_broad_collection_scope(
    tokens: &[&str],
    requested_basename: &str,
    requested_logical_id: &str,
) -> bool {
    tokens.iter().enumerate().any(|(quantifier_index, token)| {
        if !is_broad_quantifier(token) {
            return false;
        }

        let (scope_start, scope_end) = broad_scope_segment(tokens, quantifier_index);
        let scope = &tokens[scope_start..scope_end];
        let targets = scope
            .iter()
            .enumerate()
            .filter(|(_, candidate)| is_collection_target(candidate))
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if targets.is_empty() {
            return false;
        }

        let identity_ranges =
            requested_artifact_identity_ranges(scope, requested_basename, requested_logical_id);
        if identity_ranges.is_empty() || has_environment_collection_scope(scope) {
            return true;
        }

        targets.into_iter().any(|target_index| {
            !target_is_bounded_to_requested_artifact(
                scope,
                target_index,
                &identity_ranges,
                requested_logical_id,
            )
        })
    })
}

fn broad_scope_segment(tokens: &[&str], quantifier_index: usize) -> (usize, usize) {
    let is_boundary = |index: usize| {
        matches!(tokens[index], "plus" | "also" | "then")
            || (tokens[index] == "and"
                && tokens
                    .get(index + 1)
                    .is_some_and(|next| is_broad_quantifier(next) || is_collection_action(next)))
    };
    let start = (0..quantifier_index)
        .rev()
        .find(|index| is_boundary(*index))
        .map_or(0, |index| index + 1);
    let end = ((quantifier_index + 1)..tokens.len())
        .find(|index| is_boundary(*index))
        .unwrap_or(tokens.len());
    (start, end)
}

fn requested_artifact_identity_ranges(
    tokens: &[&str],
    requested_basename: &str,
    requested_logical_id: &str,
) -> Vec<(usize, usize)> {
    let basename_stem = catalog_log_stem(requested_basename);
    let basename = normalize_catalog_identity(basename_stem);
    let logical_id = normalize_catalog_identity(requested_logical_id);
    let mut ranges = tokens
        .iter()
        .enumerate()
        .filter(|(_, token)| **token == basename || **token == logical_id)
        .map(|(index, _)| (index, index + 1))
        .collect::<Vec<_>>();

    // Exact request authorization is established earlier from the selected
    // catalog entry and its punctuated alias. This additional range only lets
    // the broad-scope guard recognize that same basename after tokenization
    // splits a catalog identity such as `client.msi` at its punctuation.
    let basename_components = basename_stem
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .filter(|component| !component.is_empty())
        .map(normalize_catalog_identity)
        .collect::<Vec<_>>();
    if basename_components.len() > 1 {
        ranges.extend(
            tokens
                .windows(basename_components.len())
                .enumerate()
                .filter_map(|(index, window)| {
                    window
                        .iter()
                        .zip(&basename_components)
                        .all(|(token, component)| *token == component)
                        .then_some((index, index + window.len()))
                }),
        );
    }

    if logical_id == "smsts" {
        ranges.extend(tokens.windows(3).enumerate().filter_map(|(index, window)| {
            (window == ["task", "sequence", "log"]).then_some((index, index + 3))
        }));
    }
    ranges.sort_unstable();
    ranges.dedup();
    ranges
}

fn normalize_catalog_identity(identity: &str) -> String {
    identity
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || *character == '_')
        .flat_map(char::to_lowercase)
        .collect()
}

fn has_environment_collection_scope(tokens: &[&str]) -> bool {
    tokens
        .windows(2)
        .any(|pair| is_collection_container(pair[0]) && is_collection_target(pair[1]))
        || tokens.iter().enumerate().any(|(index, token)| {
            matches!(*token, "across" | "from" | "on" | "throughout" | "under")
                && tokens
                    .iter()
                    .skip(index + 1)
                    .take(3)
                    .any(|candidate| is_collection_container(candidate))
        })
}

fn target_is_bounded_to_requested_artifact(
    tokens: &[&str],
    target_index: usize,
    identity_ranges: &[(usize, usize)],
    requested_logical_id: &str,
) -> bool {
    let identity_precedes_target = identity_ranges
        .iter()
        .any(|(start, end)| *start <= target_index && target_index.saturating_sub(*end) <= 2);
    let is_state_observation = tokens.iter().any(|token| {
        matches!(
            *token,
            "download" | "downloaded" | "encryption" | "image" | "imaging" | "state" | "status"
        )
    });

    match tokens[target_index] {
        "directory" | "directories" | "disk" | "disks" | "drive" | "drives" | "filesystem"
        | "filesystems" | "folder" | "folders" | "volume" | "volumes" => {
            is_state_observation
                && (requested_logical_id.eq_ignore_ascii_case("smsts")
                    || tokens
                        .iter()
                        .any(|token| matches!(*token, "encryption" | "status")))
        }
        "file" | "files" => identity_precedes_target || is_state_observation,
        "log" | "logs" => identity_precedes_target,
        _ => true,
    }
}

fn validate_terminal_evidence(
    evidence: &[SccmEvidenceRef],
    terminal_evidence: &[SccmTerminalEvidence],
) -> Result<(), SccmFindingValidationError> {
    for terminal in terminal_evidence {
        if !evidence.contains(&terminal.reference) {
            return Err(SccmFindingValidationError::TerminalEvidenceNotCited);
        }
        if terminal.kind != SccmTerminalEvidenceKind::ObservedFailure {
            return Err(SccmFindingValidationError::InvalidTerminalEvidence);
        }
    }
    Ok(())
}

fn validate_correlation_key_evidence(
    evidence: &[SccmEvidenceRef],
    correlation_keys: &[SccmCorrelationKey],
) -> Result<(), SccmFindingValidationError> {
    for key in correlation_keys {
        let normalized = normalize_key(key.kind.clone(), &key.raw);
        let has_canonical_value = !key.raw.is_empty()
            && key.raw.trim() == key.raw
            && has_at_most_chars(&key.raw, MAX_SCCM_CORRELATION_KEY_VALUE_CHARS)
            && !key.normalized.is_empty()
            && key.normalized.trim() == key.normalized
            && has_at_most_chars(&key.normalized, MAX_SCCM_CORRELATION_KEY_VALUE_CHARS)
            && normalized.confidence == SccmKeyConfidence::Exact
            && normalized.normalized == key.normalized;
        let has_valid_span = match (key.start, key.end) {
            (None, None) => true,
            (Some(start), Some(end)) => {
                start < end && end - start == key.raw.encode_utf16().count()
            }
            _ => false,
        };
        let has_canonical_profile = key
            .extraction_profile_id
            .as_deref()
            .is_none_or(is_canonical_opaque_id);
        let has_valid_confidence = matches!(key.confidence, SccmKeyConfidence::Low)
            || key
                .extraction_profile_id
                .as_deref()
                .is_some_and(is_registered_stable_profile);
        if !has_canonical_value
            || !has_valid_span
            || !has_canonical_profile
            || !has_valid_confidence
        {
            return Err(SccmFindingValidationError::InvalidCorrelationKey);
        }

        let Some(reference) = &key.evidence else {
            return Err(SccmFindingValidationError::CorrelationKeyMissingEvidence);
        };
        // The containment check below only proves the reference is cited, and
        // a standalone key is its own citation set, which makes containment
        // self-satisfying. Validate the reference here rather than at the call
        // sites so no caller can reach the trivially satisfied check with an
        // unvalidated reference.
        validate_evidence_reference(reference)?;
        if !evidence.contains(reference) {
            return Err(SccmFindingValidationError::CorrelationKeyEvidenceNotCited);
        }
    }
    Ok(())
}

fn has_profiled_key_corroboration(keys: &[SccmCorrelationKey]) -> bool {
    for candidate in keys {
        if !is_corroborating_key(candidate) {
            continue;
        }
        let (Some(candidate_profile), Some(candidate_reference)) = (
            candidate.extraction_profile_id.as_deref(),
            candidate.evidence.as_ref(),
        ) else {
            continue;
        };
        let candidate_identity = evidence_identity(candidate_reference);
        let mut distinct_identities = vec![candidate_identity];

        for peer in keys {
            if !is_corroborating_key(peer)
                || peer.kind != candidate.kind
                || peer.normalized != candidate.normalized
                || peer.extraction_profile_id.as_deref() != Some(candidate_profile)
            {
                continue;
            }
            let Some(peer_reference) = peer.evidence.as_ref() else {
                continue;
            };
            let peer_identity = evidence_identity(peer_reference);
            if !distinct_identities.contains(&peer_identity) {
                distinct_identities.push(peer_identity);
            }
        }

        if distinct_identities.len() >= 2 {
            return true;
        }
    }
    false
}

fn is_corroborating_key(key: &SccmCorrelationKey) -> bool {
    matches!(
        key.confidence,
        SccmKeyConfidence::Strong | SccmKeyConfidence::Exact
    ) && key
        .extraction_profile_id
        .as_deref()
        .is_some_and(is_registered_stable_profile)
        && !key.normalized.trim().is_empty()
        && key.evidence.is_some()
}

fn is_registered_stable_profile(profile_id: &str) -> bool {
    REGISTERED_STABLE_CORRELATION_PROFILE_IDS.contains(&profile_id)
}

fn evidence_identity(reference: &SccmEvidenceRef) -> (&str, &str) {
    (&reference.artifact_id, &reference.entry_id)
}

fn is_canonical_opaque_id(value: &str) -> bool {
    !value.is_empty() && value.trim() == value && has_at_most_chars(value, MAX_SCCM_OPAQUE_ID_CHARS)
}

pub(crate) fn has_at_most_chars(value: &str, maximum: usize) -> bool {
    value.chars().nth(maximum).is_none()
}

fn normalize_finding(finding: &mut SccmFinding) {
    finding.title = finding.title.trim().to_owned();
    finding.summary = finding.summary.trim().to_owned();
    for request in &mut finding.next_artifacts {
        request.reason = request.reason.trim().to_owned();
    }

    finding.evidence.sort_by(compare_evidence_refs);
    finding.evidence.dedup();

    finding.terminal_evidence.sort_by(compare_terminal_evidence);
    finding.terminal_evidence.dedup();

    finding.coverage_gaps.sort_by(compare_coverage_gaps);
    finding.coverage_gaps.dedup();

    finding.correlation_keys.sort_by(compare_correlation_keys);
    finding.correlation_keys.dedup();

    finding.next_artifacts.sort_by(compare_artifact_requests);
    finding.next_artifacts.dedup();
}

fn compare_evidence_refs(left: &SccmEvidenceRef, right: &SccmEvidenceRef) -> Ordering {
    left.artifact_id
        .cmp(&right.artifact_id)
        .then_with(|| left.entry_id.cmp(&right.entry_id))
        .then_with(|| left.line_start.cmp(&right.line_start))
        .then_with(|| left.line_end.cmp(&right.line_end))
}

fn compare_terminal_evidence(
    left: &SccmTerminalEvidence,
    right: &SccmTerminalEvidence,
) -> Ordering {
    compare_evidence_refs(&left.reference, &right.reference).then_with(|| {
        left.kind
            .serialized_name()
            .cmp(right.kind.serialized_name())
    })
}

fn compare_coverage_gaps(
    left: &SccmFindingCoverageGap,
    right: &SccmFindingCoverageGap,
) -> Ordering {
    left.artifact_id
        .cmp(&right.artifact_id)
        .then_with(|| compare_roles(&left.role, &right.role))
        .then_with(|| {
            coverage_state_order(&left.coverage).cmp(&coverage_state_order(&right.coverage))
        })
}

fn compare_correlation_keys(left: &SccmCorrelationKey, right: &SccmCorrelationKey) -> Ordering {
    correlation_key_kind_order(&left.kind)
        .cmp(&correlation_key_kind_order(&right.kind))
        .then_with(|| left.normalized.cmp(&right.normalized))
        .then_with(|| {
            key_confidence_order(&left.confidence).cmp(&key_confidence_order(&right.confidence))
        })
        .then_with(|| left.extraction_profile_id.cmp(&right.extraction_profile_id))
        .then_with(|| compare_optional_evidence_refs(&left.evidence, &right.evidence))
        .then_with(|| left.raw.cmp(&right.raw))
        .then_with(|| left.start.cmp(&right.start))
        .then_with(|| left.end.cmp(&right.end))
}

fn compare_optional_evidence_refs(
    left: &Option<SccmEvidenceRef>,
    right: &Option<SccmEvidenceRef>,
) -> Ordering {
    match (left, right) {
        (Some(left), Some(right)) => compare_evidence_refs(left, right),
        (Some(_), None) => Ordering::Greater,
        (None, Some(_)) => Ordering::Less,
        (None, None) => Ordering::Equal,
    }
}

fn compare_artifact_requests(left: &SccmArtifactRequest, right: &SccmArtifactRequest) -> Ordering {
    left.logical_id
        .cmp(&right.logical_id)
        .then_with(|| compare_roles(&left.role, &right.role))
        .then_with(|| left.reason.cmp(&right.reason))
}

fn compare_roles(left: &SccmRole, right: &SccmRole) -> Ordering {
    role_order(left)
        .cmp(&role_order(right))
        .then_with(|| unknown_role_value(left).cmp(unknown_role_value(right)))
}

fn role_order(role: &SccmRole) -> u8 {
    match role {
        SccmRole::Client => 0,
        SccmRole::SiteServer => 1,
        SccmRole::ManagementPoint => 2,
        SccmRole::DistributionPoint => 3,
        SccmRole::SoftwareUpdatePoint => 4,
        SccmRole::WsUs => 5,
        SccmRole::Provider => 6,
        SccmRole::AdminService => 7,
        SccmRole::Unknown(_) => 8,
    }
}

fn unknown_role_value(role: &SccmRole) -> &str {
    match role {
        SccmRole::Unknown(value) => value,
        _ => "",
    }
}

fn coverage_state_order(coverage: &SccmCoverageState) -> u8 {
    match coverage {
        SccmCoverageState::Captured => 0,
        SccmCoverageState::Absent => 1,
        SccmCoverageState::AccessDenied => 2,
        SccmCoverageState::Capped => 3,
        SccmCoverageState::Skipped => 4,
        SccmCoverageState::Unsupported => 5,
        SccmCoverageState::ParseFailed => 6,
    }
}

fn correlation_key_kind_order(kind: &SccmCorrelationKeyKind) -> u8 {
    match kind {
        SccmCorrelationKeyKind::AssignmentId => 0,
        SccmCorrelationKeyKind::PolicyId => 1,
        SccmCorrelationKeyKind::ClientGuid => 2,
        SccmCorrelationKeyKind::PackageId => 3,
        SccmCorrelationKeyKind::ContentId => 4,
        SccmCorrelationKeyKind::SiteCode => 5,
        SccmCorrelationKeyKind::ServerHost => 6,
        SccmCorrelationKeyKind::CiId => 7,
        SccmCorrelationKeyKind::UpdateId => 8,
        SccmCorrelationKeyKind::KbId => 9,
        SccmCorrelationKeyKind::BitsJobId => 10,
        SccmCorrelationKeyKind::TaskSequenceExecutionId => 11,
        SccmCorrelationKeyKind::RequestId => 12,
        SccmCorrelationKeyKind::TopicId => 13,
        SccmCorrelationKeyKind::StateMessageId => 14,
        SccmCorrelationKeyKind::InventoryCycleId => 15,
        SccmCorrelationKeyKind::ReportId => 16,
        SccmCorrelationKeyKind::ResourceHandle => 17,
        SccmCorrelationKeyKind::ComplianceCiId => 18,
        SccmCorrelationKeyKind::BaselineId => 19,
        SccmCorrelationKeyKind::ComplianceStateId => 20,
        SccmCorrelationKeyKind::MeteringCycleId => 21,
        SccmCorrelationKeyKind::RuleId => 22,
    }
}

fn key_confidence_order(confidence: &SccmKeyConfidence) -> u8 {
    match confidence {
        SccmKeyConfidence::Low => 0,
        SccmKeyConfidence::Strong => 1,
        SccmKeyConfidence::Exact => 2,
    }
}
