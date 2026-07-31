use std::cmp::Ordering;

use serde::de::Error as _;
use serde::ser::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::models::log_entry::Severity;

use super::catalog::declared_source_catalog;
use super::models::{
    SccmCorrelationKey, SccmCorrelationKeyKind, SccmCoverageState, SccmEvidenceRef,
    SccmFindingClass, SccmKeyConfidence, SccmRole,
};

pub const MAX_SCCM_ARTIFACT_REQUEST_REASON_CHARS: usize = 240;
pub const MAX_SCCM_NEXT_ARTIFACT_REQUESTS: usize = 16;
const MAX_SCCM_COVERAGE_GAP_ARTIFACT_ID_CHARS: usize = 256;
// Intentionally empty: no extraction profile is verified as stable enough to
// authorize key-only High confidence. Adding one requires contract review.
const REGISTERED_STABLE_CORRELATION_PROFILE_IDS: &[&str] = &[];

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
}

impl Serialize for SccmPhase {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if matches!(self, Self::Unknown(value) if is_known_phase_name(value)) {
            return Err(S::Error::custom(
                "unknown SCCM phase must not shadow a declared phase",
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
        Ok(match String::deserialize(deserializer)? {
            value if value == "policy" => Self::Policy,
            value if value == "content" => Self::Content,
            value if value == "enforcement" => Self::Enforcement,
            value => Self::Unknown(value),
        })
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
}

impl Serialize for SccmTerminalEvidenceKind {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if matches!(self, Self::Unknown(value) if value == "observedFailure") {
            return Err(S::Error::custom(
                "unknown terminal evidence kind must not shadow observedFailure",
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
        Ok(match String::deserialize(deserializer)? {
            value if value == "observedFailure" => Self::ObservedFailure,
            value => Self::Unknown(value),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmFindingCoverageGap {
    pub artifact_id: String,
    pub role: SccmRole,
    pub coverage: SccmCoverageState,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmArtifactRequest {
    pub logical_id: String,
    pub role: SccmRole,
    pub reason: String,
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
        SccmFindingSerializeWire {
            finding_id: &self.finding_id,
            class: &self.class,
            phase: &self.phase,
            role: &self.role,
            severity: &self.severity,
            confidence: &self.confidence,
            title: &self.title,
            summary: &self.summary,
            evidence: &self.evidence,
            terminal_evidence: &self.terminal_evidence,
            coverage_gaps: &self.coverage_gaps,
            correlation_keys: &self.correlation_keys,
            next_artifacts: &self.next_artifacts,
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
        normalize_finding(&mut finding);
        finding.validate().map_err(|error| {
            D::Error::custom(format!("invalid SCCM finding contract: {error:?}"))
        })?;
        Ok(finding)
    }
}

impl SccmFinding {
    pub fn validate(&self) -> Result<(), SccmFindingValidationError> {
        validate_required_text(self)?;
        validate_coverage_gaps(&self.coverage_gaps)?;
        validate_artifact_requests(&self.next_artifacts)?;

        if self.class == SccmFindingClass::InsufficientEvidence && self.coverage_gaps.is_empty() {
            return Err(SccmFindingValidationError::MissingCoverageGap);
        }

        if self.evidence.is_empty() && self.coverage_gaps.is_empty() {
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
    MissingEvidenceOrCoverageGap,
    MissingTerminalEvidence,
    InvalidTerminalEvidence,
    TerminalEvidenceNotCited,
    CorrelationKeyMissingEvidence,
    CorrelationKeyEvidenceNotCited,
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
        normalize_finding(&mut finding);
        finding.validate()?;
        Ok(finding)
    }
}

fn validate_required_text(finding: &SccmFinding) -> Result<(), SccmFindingValidationError> {
    if finding.finding_id.trim().is_empty()
        || finding.title.trim().is_empty()
        || finding.summary.trim().is_empty()
        || matches!(&finding.phase, SccmPhase::Unknown(value) if value.trim().is_empty())
        || matches!(&finding.phase, SccmPhase::Unknown(value) if is_known_phase_name(value))
    {
        return Err(SccmFindingValidationError::MissingRequiredField);
    }
    Ok(())
}

fn validate_coverage_gaps(
    coverage_gaps: &[SccmFindingCoverageGap],
) -> Result<(), SccmFindingValidationError> {
    if coverage_gaps.iter().any(|gap| {
        gap.artifact_id.trim().is_empty()
            || gap.artifact_id.chars().count() > MAX_SCCM_COVERAGE_GAP_ARTIFACT_ID_CHARS
            || gap.coverage == SccmCoverageState::Captured
    }) {
        return Err(SccmFindingValidationError::InvalidCoverageGap);
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
        if !is_bounded_request_reason(&request.reason) {
            return Err(SccmFindingValidationError::InvalidArtifactRequestReason);
        }

        let mut logical_matches = catalog
            .iter()
            .filter(|entry| entry.logical_name == request.logical_id);
        let Some(first_match) = logical_matches.next() else {
            return Err(SccmFindingValidationError::UndeclaredArtifactRequest);
        };
        if first_match.role != request.role
            && !logical_matches.any(|entry| entry.role == request.role)
        {
            return Err(SccmFindingValidationError::ArtifactRequestRoleMismatch);
        }
    }
    Ok(())
}

fn is_bounded_request_reason(reason: &str) -> bool {
    let trimmed = reason.trim();
    if trimmed.is_empty()
        || trimmed.chars().count() > MAX_SCCM_ARTIFACT_REQUEST_REASON_CHARS
        || trimmed.contains(['*', '?', '[', ']'])
    {
        return false;
    }

    let lowercase = trimmed.to_ascii_lowercase();
    ![
        "entire drive",
        "whole drive",
        "drive root",
        "root drive",
        "entire disk",
        "whole disk",
        "all files",
        "recursive",
    ]
    .iter()
    .any(|unbounded| lowercase.contains(unbounded))
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
        let Some(reference) = &key.evidence else {
            return Err(SccmFindingValidationError::CorrelationKeyMissingEvidence);
        };
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

fn normalize_finding(finding: &mut SccmFinding) {
    finding.finding_id = finding.finding_id.trim().to_owned();
    finding.title = finding.title.trim().to_owned();
    finding.summary = finding.summary.trim().to_owned();
    for gap in &mut finding.coverage_gaps {
        gap.artifact_id = gap.artifact_id.trim().to_owned();
    }
    for request in &mut finding.next_artifacts {
        request.logical_id = request.logical_id.trim().to_owned();
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
        SccmCorrelationKeyKind::ClientGuid => 1,
        SccmCorrelationKeyKind::PackageId => 2,
        SccmCorrelationKeyKind::ContentId => 3,
        SccmCorrelationKeyKind::SiteCode => 4,
        SccmCorrelationKeyKind::ServerHost => 5,
        SccmCorrelationKeyKind::CiId => 6,
        SccmCorrelationKeyKind::UpdateId => 7,
        SccmCorrelationKeyKind::KbId => 8,
        SccmCorrelationKeyKind::BitsJobId => 9,
        SccmCorrelationKeyKind::TaskSequenceExecutionId => 10,
        SccmCorrelationKeyKind::RequestId => 11,
        SccmCorrelationKeyKind::TopicId => 12,
        SccmCorrelationKeyKind::StateMessageId => 13,
    }
}

fn key_confidence_order(confidence: &SccmKeyConfidence) -> u8 {
    match confidence {
        SccmKeyConfidence::Low => 0,
        SccmKeyConfidence::Strong => 1,
        SccmKeyConfidence::Exact => 2,
    }
}
