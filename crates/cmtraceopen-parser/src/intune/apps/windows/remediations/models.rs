//! Public types for Intune Windows remediation evidence.
//!
//! A remediation is a *pair*: a detection script decides whether anything is
//! wrong, and a remediation script runs only if it was. The two halves have
//! different exit semantics and must never be pooled, so every state in this
//! module names the stage it belongs to.

use serde::{Deserialize, Serialize};

/// Whether a captured string may be exported as-is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RemediationSensitivity {
    Public,
    Sensitive,
}

/// A string carrying its own privacy classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemediationClassifiedString {
    pub value: String,
    pub sensitivity: RemediationSensitivity,
}

impl RemediationClassifiedString {
    pub fn public(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            sensitivity: RemediationSensitivity::Public,
        }
    }

    pub fn sensitive(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            sensitivity: RemediationSensitivity::Sensitive,
        }
    }
}

/// A source timestamp.
///
/// `normalized_utc` is populated only when the record embedded its own UTC
/// offset, which `original_offset` then reports. Without one, the underlying
/// parser can still render a UTC-looking value, but it derives it from the
/// parsing machine's local offset rather than from the evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemediationTimestamp {
    pub raw_text: String,
    pub original_offset: Option<String>,
    pub normalized_utc: Option<String>,
}

/// A pointer back to the exact record a conclusion came from.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemediationEvidenceRef {
    pub artifact_id: String,
    pub record_number: u32,
    pub line_number: Option<u32>,
}

/// Which supplied artifact a record came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RemediationSourceKind {
    /// Primary: policy receipt, orchestration, stage decisions, reporting.
    HealthScripts,
    /// Child process execution, output, timeout, exit status.
    AgentExecutor,
    /// Agent and check-in context only.
    IntuneManagementExtension,
    /// A retained `{policyId}_{runId}.output` / `.error` artifact. Its contents
    /// are never parsed; its name is the evidence.
    ScriptOutput,
    Unknown,
}

/// Which half of the pair a record speaks for.
///
/// This is the single most important distinction in the module. An exit code
/// with no stage cannot terminate either half, because `0` means "compliant"
/// for detection and "succeeded" for remediation, and guessing wrong inverts
/// the diagnosis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RemediationStage {
    Detection,
    Remediation,
    /// The detection re-run after a remediation, when one is evidenced.
    PostDetection,
}

/// How the run was triggered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RemediationInvocation {
    Scheduled,
    OnDemand,
    Unknown,
}

/// Detection-stage state. `Compliant` means no remediation was required.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DetectionState {
    NotStarted,
    Launched,
    Compliant,
    Noncompliant,
    Failed,
    TimedOut,
    InsufficientEvidence,
}

/// Remediation-stage state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RemediationRunState {
    /// Correctly not started, because detection found nothing to fix.
    Skipped,
    NotStarted,
    Launched,
    Succeeded,
    ExitedNonZero,
    FailedToLaunch,
    TimedOut,
    InsufficientEvidence,
}

/// Whether the result reached the service. Separate from the local outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RemediationReportState {
    NotObserved,
    Submitted,
    Failed,
}

/// Confidence in the reduced pair, kept separate from severity and cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RemediationConfidence {
    High,
    Medium,
    Low,
}

/// An exit token exactly as the source wrote it, plus the stage it belongs to.
///
/// The stage is not optional: a token that could not be attributed to a stage
/// never becomes a `RemediationExitToken` at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemediationExitToken {
    pub stage: RemediationStage,
    pub raw_text: String,
    pub decimal: Option<i64>,
    pub hex_text: Option<String>,
}

/// A JSON payload embedded in a record message, preserved losslessly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemediationPayload {
    pub evidence: RemediationEvidenceRef,
    /// `true` when the braces parsed as JSON. A malformed payload is reported,
    /// never repaired and never concatenated with a neighbouring record.
    pub parsed: bool,
    /// The payload verbatim. Sensitive: detection scripts emit arbitrary data.
    pub raw_text: RemediationClassifiedString,
}

/// A classified record-level signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RemediationSignal {
    PolicyReceived,
    Scheduled,
    StageLaunched,
    StageCompleted,
    StageLaunchFailed,
    StageTimedOut,
    OutputCaptured,
    RetryScheduled,
    ReportSubmitted,
    ReportFailed,
    Unclassified,
}

/// One supplied artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemediationArtifact {
    pub artifact_id: String,
    pub file_name: String,
    /// Full path is privacy-sensitive: it commonly contains a user profile name.
    pub file_path: Option<RemediationClassifiedString>,
    pub source_kind: RemediationSourceKind,
    /// Rotation ordinal when the file name identifies one; 0 is the live file.
    pub rotation_ordinal: Option<u32>,
}

/// One classified record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemediationObservation {
    pub observation_id: String,
    pub evidence: RemediationEvidenceRef,
    pub source_kind: RemediationSourceKind,
    pub timestamp: Option<RemediationTimestamp>,
    pub signal: RemediationSignal,
    /// `None` when the record did not name a stage. Such a record can never
    /// terminate a stage, no matter what exit code it carries.
    pub stage: Option<RemediationStage>,
    pub policy_id: Option<String>,
    pub run_id: Option<String>,
    pub invocation: RemediationInvocation,
    pub attempt: Option<u32>,
    pub exit_token: Option<RemediationExitToken>,
    /// Verbatim record text. Sensitive: these records quote script output.
    pub message: RemediationClassifiedString,
}

/// The identity a remediation pair is keyed on.
///
/// A scheduled run and an on-demand run of the same policy are different
/// lifecycles and are keyed apart, which is why `invocation` is in the key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemediationKey {
    pub policy_id: String,
    pub run_id: Option<String>,
    pub invocation: RemediationInvocation,
}

/// The reduced outcome of one stage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StageOutcome<S> {
    pub state: S,
    pub exit_token: Option<RemediationExitToken>,
    pub evidence: Vec<RemediationEvidenceRef>,
}

impl<S> StageOutcome<S> {
    pub fn new(state: S) -> Self {
        Self {
            state,
            exit_token: None,
            evidence: Vec::new(),
        }
    }
}

/// A reduced detection/remediation pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemediationTransaction {
    pub key: RemediationKey,
    pub detection: StageOutcome<DetectionState>,
    pub remediation: StageOutcome<RemediationRunState>,
    /// Only present when a post-remediation detection was actually evidenced.
    pub post_detection: Option<StageOutcome<DetectionState>>,
    pub report: RemediationReportState,
    /// Distinct launch attempts proven by evidence, across both stages.
    pub attempts: u32,
    pub confidence: RemediationConfidence,
    pub payloads: Vec<RemediationPayload>,
    pub observations: Vec<String>,
    pub evidence: Vec<RemediationEvidenceRef>,
    /// The smallest artifact that would advance this diagnosis.
    pub next_evidence_request: Option<String>,
}

/// What the supplied bundle did and did not cover.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemediationCoverage {
    pub artifacts: Vec<RemediationArtifact>,
    pub unclassified_records: u32,
    pub missing_expected_sources: Vec<String>,
    /// A record named a stage outcome in wording we have no rule for.
    pub unknown_version_observed: bool,
    /// Payloads that looked like JSON but did not parse.
    pub malformed_payloads: u32,
}

/// The public result of reducing a remediation bundle.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemediationAnalysis {
    pub transactions: Vec<RemediationTransaction>,
    pub observations: Vec<RemediationObservation>,
    /// Signals that could not be keyed to a policy, or exit records that named
    /// no stage. Surfaced so the gap stays visible; they terminate nothing.
    pub unkeyed_observations: Vec<String>,
    pub coverage: RemediationCoverage,
}
