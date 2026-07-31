//! Public types for Intune Windows platform-script execution evidence.
//!
//! These types describe *what the evidence showed*, not what the parser guessed.
//! Every state that implies an outcome is only reachable from an explicit record;
//! everything else lands in [`ScriptState::InsufficientEvidence`] plus a coverage
//! request naming the smallest artifact that would resolve it.

use serde::{Deserialize, Serialize};

/// Whether a captured string may be exported as-is.
///
/// `Sensitive` values are masked by the redacted export projection. The value is
/// still retained in memory so an interactive, consenting operator can see it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ScriptSensitivity {
    Public,
    Sensitive,
}

/// A string carrying its own privacy classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScriptClassifiedString {
    pub value: String,
    pub sensitivity: ScriptSensitivity,
}

impl ScriptClassifiedString {
    pub fn public(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            sensitivity: ScriptSensitivity::Public,
        }
    }

    pub fn sensitive(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            sensitivity: ScriptSensitivity::Sensitive,
        }
    }
}

/// A source timestamp. The original text is always preserved; the UTC form is
/// only populated when the source carried an offset we could resolve, so
/// ordering never silently invents a timezone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScriptTimestamp {
    pub raw_text: String,
    pub original_offset: Option<String>,
    pub normalized_utc: Option<String>,
}

/// A pointer back to the exact record a conclusion came from.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScriptEvidenceRef {
    pub artifact_id: String,
    pub record_number: u32,
    pub line_number: Option<u32>,
}

/// Which supplied artifact a record came from.
///
/// `HealthScripts` is deliberately present but supplemental: remediations own
/// that lifecycle (issue #360), and a `HealthScripts` record may only join a
/// platform-script transaction when it explicitly names the handoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ScriptSourceKind {
    IntuneManagementExtension,
    AgentExecutor,
    HealthScripts,
    ScriptOutput,
    PolicyMetadata,
    Unknown,
}

/// The context a script was launched in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ScriptExecutionContext {
    System,
    User,
    Unknown,
}

/// PowerShell host bitness, retained only when a record states it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ScriptInterpreterBitness {
    Bit32,
    Bit64,
    Unknown,
}

/// Lifecycle phases, ordered. `last_confirmed_phase` is the furthest phase with
/// direct evidence -- not the furthest phase we assume was reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ScriptPhase {
    PolicyReceived,
    Scheduled,
    Launched,
    Executed,
    Reported,
}

/// Terminal or in-flight state of one script transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ScriptState {
    PolicyReceived,
    Scheduled,
    Launched,
    ExitedZero,
    ExitedNonZero,
    FailedToLaunch,
    TimedOut,
    Retried,
    ReportSubmitted,
    ReportFailed,
    InsufficientEvidence,
}

/// Confidence in the reduced state, kept separate from severity and from cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ScriptConfidence {
    High,
    Medium,
    Low,
}

/// An exit/error token exactly as the source wrote it.
///
/// A nonzero exit is an execution *outcome*. This type deliberately carries no
/// interpretation of what the code means.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScriptExitToken {
    pub raw_text: String,
    pub decimal: Option<i64>,
    pub hex_text: Option<String>,
}

/// A classified record-level signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ScriptSignal {
    PolicyReceived,
    Scheduled,
    LaunchAttempted,
    LaunchFailed,
    ExecutionCompleted,
    ExecutionTimedOut,
    OutputCaptured,
    RetryScheduled,
    ReportSubmitted,
    ReportFailed,
    Unclassified,
}

/// One supplied artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScriptArtifact {
    pub artifact_id: String,
    pub file_name: String,
    /// Full path is privacy-sensitive: it commonly contains a user profile name.
    pub file_path: Option<ScriptClassifiedString>,
    pub source_kind: ScriptSourceKind,
    /// Rotation ordinal when the file name identifies one; 0 is the live file.
    pub rotation_ordinal: Option<u32>,
}

/// One classified record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScriptObservation {
    pub observation_id: String,
    pub evidence: ScriptEvidenceRef,
    pub source_kind: ScriptSourceKind,
    pub timestamp: Option<ScriptTimestamp>,
    pub signal: ScriptSignal,
    pub policy_id: Option<String>,
    pub run_id: Option<String>,
    pub context: ScriptExecutionContext,
    pub bitness: ScriptInterpreterBitness,
    pub attempt: Option<u32>,
    pub exit_token: Option<ScriptExitToken>,
    /// Verbatim record text. Sensitive because IME records quote command lines,
    /// UPNs, and captured stdout/stderr.
    pub message: ScriptClassifiedString,
}

/// The identity a transaction is keyed on.
///
/// Two records merge only when this key matches. Timestamp proximity, display
/// name, and a bare `AgentExecutor` component are explicitly not part of it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScriptTransactionKey {
    pub policy_id: String,
    pub run_id: Option<String>,
    pub context: ScriptExecutionContext,
}

/// A reduced platform-script execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScriptTransaction {
    pub key: ScriptTransactionKey,
    pub display_name: Option<ScriptClassifiedString>,
    pub bitness: ScriptInterpreterBitness,
    /// Observation ids in source order.
    pub observations: Vec<String>,
    pub last_confirmed_phase: Option<ScriptPhase>,
    pub state: ScriptState,
    pub exit_token: Option<ScriptExitToken>,
    /// Number of distinct launch attempts proven by evidence.
    pub attempts: u32,
    pub confidence: ScriptConfidence,
    pub evidence: Vec<ScriptEvidenceRef>,
    /// The smallest artifact that would advance this diagnosis.
    pub next_evidence_request: Option<String>,
}

/// What the supplied bundle did and did not cover.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScriptCoverage {
    pub artifacts: Vec<ScriptArtifact>,
    /// Records that parsed but carried no platform-script signal.
    pub unclassified_records: u32,
    /// Expected-but-absent sources, as artifact file names.
    pub missing_expected_sources: Vec<String>,
    /// True when a record matched a script shape we do not have a version rule
    /// for. Callers must treat affected transactions as lower confidence.
    pub unknown_version_observed: bool,
}

/// The public result of reducing a platform-script bundle.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScriptAnalysis {
    pub transactions: Vec<ScriptTransaction>,
    pub observations: Vec<ScriptObservation>,
    /// Signals that could not be keyed to a policy. These can never terminate a
    /// transaction; they are surfaced so the gap stays visible.
    pub unkeyed_observations: Vec<String>,
    pub coverage: ScriptCoverage,
}
