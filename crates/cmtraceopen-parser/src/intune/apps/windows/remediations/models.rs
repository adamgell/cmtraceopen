//! Public types for the Intune Windows remediation lifecycle.
//!
//! Every state here describes *what the evidence showed*. Detection and
//! remediation are modelled as separate stages with separate vocabularies, and
//! neither can be reached from a record that did not name its stage: the same
//! `exitCode = 1` means "remediation required" for detection and "the
//! remediation script failed" for remediation, so an unattributed exit code is
//! never promoted to either.

use serde::{Deserialize, Serialize};

use crate::intune::evidence::{
    IntuneAccessState, IntuneArtifactCoverage, IntuneErrorCode, IntuneEvidenceRef, IntuneFinding,
    IntuneFindingConfidence, IntuneNamedValue, IntuneObservationContext,
    INTUNE_EVIDENCE_SCHEMA_VERSION,
};

/// Schema version of the remediation snapshot.
///
/// Pinned to the shared evidence schema because every serialized field of this
/// module is either a shared contract type or an additive enum beside one.
pub const REMEDIATION_SCHEMA_VERSION: u32 = INTUNE_EVIDENCE_SCHEMA_VERSION;

/// Which supplied artifact a record came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RemediationSourceKind {
    /// `HealthScripts.log`: policy receipt, stage orchestration, and reporting.
    HealthScripts,
    /// `AgentExecutor.log`: child process launch, exit, and timeout.
    AgentExecutor,
    /// The shared IME log: agent and check-in context only.
    IntuneManagementExtension,
    /// A retained `{policyId}_{runId}` detection/remediation output artifact.
    /// Its *name* is the evidence; its contents are never parsed.
    RemediationOutput,
    /// Caller-supplied policy metadata and run cadence facts.
    PolicyMetadata,
    Unknown,
}

/// Which half of the paired lifecycle a record belongs to.
///
/// `PostRemediationDetection` is a distinct stage rather than a second
/// `Detection`, because its result answers "did the remediation work" and must
/// never overwrite the detection result that decided remediation was needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RemediationStage {
    Detection,
    Remediation,
    PostRemediationDetection,
}

/// How the run was started.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RemediationInvocation {
    Scheduled,
    OnDemand,
    Unknown,
}

/// What one record said, independent of the stage it said it about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RemediationEvent {
    PolicyReceived,
    Scheduled,
    OnDemandRequested,
    Launched,
    Completed,
    LaunchFailed,
    TimedOut,
    /// Detection reported compliant and the agent stated it would not remediate.
    RemediationNotRequired,
    OutputCaptured,
    RetryScheduled,
    ReportSubmitted,
    ReportFailed,
    ReportRetryDeferred,
    /// An embedded JSON payload that could not be parsed. Carries no key.
    MalformedPayload,
    Unclassified,
}

/// Detection stage result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DetectionOutcome {
    /// Every expected source was readable and none of them launched detection.
    NotStarted,
    /// Detection started; no completion record was supplied.
    Launched,
    /// Exit 0: the device is in the desired state and remediation is not required.
    Compliant,
    /// Exit 1: remediation is required.
    NonCompliant,
    /// The script itself failed: a launch failure, or an exit code that is
    /// neither of the two compliance codes.
    Failed,
    TimedOut,
    /// A source that would have shown detection was not usable.
    InsufficientEvidence,
}

/// Remediation stage result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RemediationOutcome {
    /// No remediation record, and nothing said it was skipped.
    NotStarted,
    /// The agent explicitly stated remediation was not required.
    Skipped,
    Launched,
    Succeeded,
    ExitedNonZero,
    FailedToLaunch,
    TimedOut,
    InsufficientEvidence,
}

/// Post-remediation detection result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PostRemediationState {
    /// No post-remediation detection was reported. This is normal: the stage is
    /// optional, and its absence is not evidence that remediation failed.
    NotEvaluated,
    Compliant,
    NonCompliant,
    Failed,
    InsufficientEvidence,
}

/// Whether the result reached the Intune service.
///
/// Deliberately separate from every execution outcome: a remediation that
/// succeeded locally and never reported looks healthy on the device and broken
/// in the portal, and conflating the two hides exactly that case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ReportingState {
    NotStarted,
    Submitted,
    Failed,
    RetryDeferred,
    InsufficientEvidence,
}

/// The furthest lifecycle point with direct evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RemediationPhase {
    PolicyReceived,
    Scheduled,
    DetectionLaunched,
    DetectionCompleted,
    RemediationLaunched,
    RemediationCompleted,
    PostRemediationCompleted,
    Reported,
}

/// The identity a run is keyed on.
///
/// Records join only on this key. Timestamp proximity, a shared component, and
/// a shared log file are explicitly not part of it, so a scheduled run and an
/// on-demand run of the same policy stay separate even when they interleave.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemediationKey {
    pub policy_id: String,
    pub run_id: Option<String>,
    pub invocation: RemediationInvocation,
}

/// The detection half of a run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectionResult {
    pub outcome: DetectionOutcome,
    /// The exit token exactly as the source wrote it, in every form observed.
    pub exit_code: Option<IntuneErrorCode>,
    pub attempts: u32,
    pub evidence: Vec<IntuneEvidenceRef>,
}

/// The remediation half of a run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemediationActionResult {
    pub outcome: RemediationOutcome,
    pub exit_code: Option<IntuneErrorCode>,
    pub attempts: u32,
    pub evidence: Vec<IntuneEvidenceRef>,
}

/// The optional post-remediation detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostRemediationResult {
    pub state: PostRemediationState,
    pub exit_code: Option<IntuneErrorCode>,
    pub evidence: Vec<IntuneEvidenceRef>,
}

/// Whether the run's result reached the service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportingResult {
    pub state: ReportingState,
    pub error_code: Option<IntuneErrorCode>,
    pub evidence: Vec<IntuneEvidenceRef>,
}

/// One reduced detection/remediation run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemediationRun {
    pub key: RemediationKey,
    pub detection: DetectionResult,
    pub remediation: RemediationActionResult,
    pub post_remediation: PostRemediationResult,
    pub reporting: ReportingResult,
    pub last_confirmed_phase: Option<RemediationPhase>,
    pub confidence: IntuneFindingConfidence,
    /// Observation ids in evidence order.
    pub observations: Vec<String>,
    pub evidence: Vec<IntuneEvidenceRef>,
    /// The smallest artifact that would advance this diagnosis.
    pub next_evidence_request: Option<String>,
    /// Fields observed in embedded payloads or supplied facts that this build
    /// does not model. Retained so adding a typed field later is a widening
    /// change rather than a re-parse.
    pub retained_facts: Vec<IntuneNamedValue>,
}

/// One classified record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemediationObservation {
    pub observation_id: String,
    pub context: IntuneObservationContext,
    pub source_kind: RemediationSourceKind,
    pub event: RemediationEvent,
    /// `None` means the record never named a stage. Such a record can describe
    /// an execution but can never decide a stage outcome.
    pub stage: Option<RemediationStage>,
    pub policy_id: Option<String>,
    pub run_id: Option<String>,
    pub invocation: RemediationInvocation,
    pub attempt: Option<u32>,
    pub exit_code: Option<IntuneErrorCode>,
    /// Verbatim record text. Classified sensitive by `context.sensitivity`
    /// because remediation records quote script output, UPNs, and command lines.
    pub message: String,
    pub retained_fields: Vec<IntuneNamedValue>,
}

/// One supplied artifact and what was read from it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemediationArtifact {
    pub artifact_id: String,
    /// The original file name, kept separate from the CCM `file=` field.
    pub file_name: String,
    /// The original path. Sensitive: it commonly contains a profile name.
    pub file_path: Option<String>,
    pub source_kind: RemediationSourceKind,
    /// Rotation ordinal when the name identifies one; 0 is the live file.
    pub rotation_ordinal: Option<u32>,
    pub access_state: IntuneAccessState,
    /// Records the CCM framer produced a complete logical record for.
    pub framed_records: u32,
    /// Lines that could not be framed, typically a record split by a rotation.
    /// These never carry a key and can never terminate a run.
    pub unframed_records: u32,
}

/// The immutable result of reducing a remediation bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemediationSnapshot {
    pub schema_version: u32,
    pub artifacts: Vec<RemediationArtifact>,
    pub runs: Vec<RemediationRun>,
    pub observations: Vec<RemediationObservation>,
    /// Observations that said something but could not be keyed to a run. They
    /// are surfaced rather than attached to the nearest run.
    pub unkeyed_observations: Vec<String>,
    pub coverage: Vec<IntuneArtifactCoverage>,
    pub findings: Vec<IntuneFinding>,
}

impl Default for RemediationSnapshot {
    fn default() -> Self {
        Self {
            schema_version: REMEDIATION_SCHEMA_VERSION,
            artifacts: Vec::new(),
            runs: Vec::new(),
            observations: Vec::new(),
            unkeyed_observations: Vec::new(),
            coverage: Vec::new(),
            findings: Vec::new(),
        }
    }
}

impl RemediationRun {
    /// Whether the lifecycle reached a point where nothing further was expected
    /// to run locally.
    ///
    /// Used for confidence and for the "local outcome versus reporting outcome"
    /// findings; it says nothing about whether the result reached the service.
    pub fn is_locally_resolved(&self) -> bool {
        match self.detection.outcome {
            DetectionOutcome::Compliant => matches!(
                self.remediation.outcome,
                RemediationOutcome::Skipped | RemediationOutcome::NotStarted
            ),
            DetectionOutcome::Failed | DetectionOutcome::TimedOut => true,
            DetectionOutcome::NonCompliant => matches!(
                self.remediation.outcome,
                RemediationOutcome::Succeeded
                    | RemediationOutcome::ExitedNonZero
                    | RemediationOutcome::FailedToLaunch
                    | RemediationOutcome::TimedOut
            ),
            DetectionOutcome::NotStarted
            | DetectionOutcome::Launched
            | DetectionOutcome::InsufficientEvidence => false,
        }
    }
}

/// Map how an artifact was accessed onto how it is reported in coverage.
pub(crate) fn coverage_status(
    access_state: &IntuneAccessState,
) -> crate::intune::evidence::IntuneArtifactStatus {
    use crate::intune::evidence::IntuneArtifactStatus as Status;
    match access_state {
        IntuneAccessState::Available => Status::Available,
        IntuneAccessState::Missing => Status::Missing,
        IntuneAccessState::PermissionDenied => Status::PermissionDenied,
        IntuneAccessState::Capped => Status::Capped,
        IntuneAccessState::Skipped => Status::Skipped,
        IntuneAccessState::Failed => Status::ParseFailed,
        IntuneAccessState::Unsupported => Status::Unsupported,
    }
}

/// Whether an artifact in this state can contribute records at all.
///
/// A capped artifact still yields the records it did contain; the cap is
/// reported through coverage so an absent signal is never read as proof.
pub(crate) fn is_readable(access_state: &IntuneAccessState) -> bool {
    matches!(
        access_state,
        IntuneAccessState::Available | IntuneAccessState::Capped
    )
}

/// Confidence ordering helper used when several signals bound a run.
pub(crate) fn lower_confidence(
    left: IntuneFindingConfidence,
    right: IntuneFindingConfidence,
) -> IntuneFindingConfidence {
    let rank = |value: &IntuneFindingConfidence| match value {
        IntuneFindingConfidence::Low => 0u8,
        IntuneFindingConfidence::Medium => 1,
        IntuneFindingConfidence::High => 2,
    };
    if rank(&left) <= rank(&right) {
        left
    } else {
        right
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(detection: DetectionOutcome, remediation: RemediationOutcome) -> RemediationRun {
        RemediationRun {
            key: RemediationKey {
                policy_id: "p".to_owned(),
                run_id: None,
                invocation: RemediationInvocation::Unknown,
            },
            detection: DetectionResult {
                outcome: detection,
                exit_code: None,
                attempts: 0,
                evidence: Vec::new(),
            },
            remediation: RemediationActionResult {
                outcome: remediation,
                exit_code: None,
                attempts: 0,
                evidence: Vec::new(),
            },
            post_remediation: PostRemediationResult {
                state: PostRemediationState::NotEvaluated,
                exit_code: None,
                evidence: Vec::new(),
            },
            reporting: ReportingResult {
                state: ReportingState::NotStarted,
                error_code: None,
                evidence: Vec::new(),
            },
            last_confirmed_phase: None,
            confidence: IntuneFindingConfidence::Low,
            observations: Vec::new(),
            evidence: Vec::new(),
            next_evidence_request: None,
            retained_facts: Vec::new(),
        }
    }

    #[test]
    fn a_compliant_detection_with_a_skipped_remediation_is_resolved() {
        assert!(run(DetectionOutcome::Compliant, RemediationOutcome::Skipped).is_locally_resolved());
    }

    #[test]
    fn a_noncompliant_detection_without_remediation_is_not_resolved() {
        assert!(
            !run(DetectionOutcome::NonCompliant, RemediationOutcome::NotStarted)
                .is_locally_resolved()
        );
    }

    #[test]
    fn a_launched_detection_is_never_resolved() {
        assert!(!run(DetectionOutcome::Launched, RemediationOutcome::NotStarted).is_locally_resolved());
    }

    #[test]
    fn coverage_status_is_bound_to_the_access_state() {
        use crate::intune::evidence::IntuneArtifactStatus as Status;
        assert_eq!(coverage_status(&IntuneAccessState::Missing), Status::Missing);
        assert_eq!(coverage_status(&IntuneAccessState::Failed), Status::ParseFailed);
        assert_eq!(coverage_status(&IntuneAccessState::Capped), Status::Capped);
    }

    #[test]
    fn only_available_and_capped_artifacts_are_read() {
        assert!(is_readable(&IntuneAccessState::Available));
        assert!(is_readable(&IntuneAccessState::Capped));
        assert!(!is_readable(&IntuneAccessState::Missing));
        assert!(!is_readable(&IntuneAccessState::Unsupported));
    }

    #[test]
    fn confidence_takes_the_weaker_of_two_signals() {
        assert_eq!(
            lower_confidence(IntuneFindingConfidence::High, IntuneFindingConfidence::Low),
            IntuneFindingConfidence::Low
        );
        assert_eq!(
            lower_confidence(
                IntuneFindingConfidence::Medium,
                IntuneFindingConfidence::High
            ),
            IntuneFindingConfidence::Medium
        );
    }

    #[test]
    fn the_snapshot_declares_the_shared_schema_version() {
        assert_eq!(
            RemediationSnapshot::default().schema_version,
            INTUNE_EVIDENCE_SCHEMA_VERSION
        );
    }
}
