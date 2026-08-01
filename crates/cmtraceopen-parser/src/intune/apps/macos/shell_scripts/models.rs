//! Public types for Intune macOS shell-script execution.
//!
//! Deliberately *not* shared with the package leaf. A script has no download, no
//! signature check, and no post-install detection; a package has no execution
//! context, no timeout, and no captured output. Modelling both with one enum
//! would mean every consumer had to know which variants were reachable for which
//! workload, which is the ambiguity issue #361 exists to prevent.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::intune::evidence::{
    intune_raw_preserving_string_enum, IntuneArtifactCoverage, IntuneErrorCode, IntuneEvidenceRef,
    IntuneFinding, IntuneNamedValue, IntuneTimestamp,
};

intune_raw_preserving_string_enum! {
    /// The security context a script ran in.
    ///
    /// This is a first-class field rather than a detail: the same policy behaves
    /// differently as root and as a user, and the two log to different roots.
    pub enum ShellExecutionContext {
        System => "system",
        User => "user",
    }
}

/// Lifecycle phases in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ShellScriptPhase {
    PolicyReceived,
    Scheduled,
    Launched,
    OutputCaptured,
    Completed,
    Reported,
}

/// The terminal verdict for one script run.
///
/// As in the package leaf, reporting is tracked separately: a script that ran
/// successfully and failed to report still ran successfully.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ShellScriptOutcome {
    /// Ran to completion with exit status zero.
    Succeeded,
    /// Ran to completion with a nonzero exit status.
    ///
    /// A nonzero exit is an execution outcome, never promoted to a root cause.
    NonZeroExit,
    /// The agent could not start the script at all, so it never ran.
    LaunchFailed,
    /// The agent stopped the script before it completed.
    TimedOut,
    /// A failure was followed by a scheduled retry, so the run is not terminal.
    RetryScheduled,
    /// No record decided the outcome either way.
    InsufficientEvidence,
}

impl ShellScriptOutcome {
    pub fn is_failure(self) -> bool {
        matches!(self, Self::NonZeroExit | Self::LaunchFailed | Self::TimedOut)
    }
}

/// Whether the agent managed to report the result to the service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ShellReportingState {
    Reported,
    Failed,
    NotObserved,
}

/// What is known about the script's stdout/stderr.
///
/// `NotObserved` is not "the script produced no output": it means no record and
/// no supplied artifact said anything either way. Treating a missing artifact as
/// proof of silence is exactly the inference issue #361 forbids.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ShellOutputPresence {
    Captured,
    /// A record explicitly stated the script produced no output.
    ExplicitlyEmpty,
    NotObserved,
}

/// The identity a script run is keyed on.
///
/// Both halves are stated identifiers. Two runs of the same policy in the same
/// minute differ only by run id, which is why the key includes it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShellScriptRunKey {
    pub policy_id: String,
    pub run_id: String,
}

/// One observed phase transition, with the record that proves it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShellScriptPhaseEvent {
    pub phase: ShellScriptPhase,
    pub timestamp: Option<IntuneTimestamp>,
    pub evidence: IntuneEvidenceRef,
}

/// One script run, reduced from every record that named it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShellScriptRun {
    pub key: ShellScriptRunKey,
    /// Sensitive: a script display name is tenant configuration.
    pub display_name: Option<String>,
    pub execution_context: Option<ShellExecutionContext>,
    pub phases: Vec<ShellScriptPhaseEvent>,
    pub last_confirmed_phase: Option<ShellScriptPhase>,
    pub outcome: ShellScriptOutcome,
    pub reporting: ShellReportingState,
    pub output: ShellOutputPresence,
    /// The exit status, when a completion record stated one.
    pub exit_code: Option<IntuneErrorCode>,
    /// The error from a launch failure or timeout, when stated.
    pub error_code: Option<IntuneErrorCode>,
    pub timeout_seconds: Option<u64>,
    pub retry_count: u32,
    pub attributes: Vec<IntuneNamedValue>,
    pub evidence: Vec<IntuneEvidenceRef>,
}

/// The immutable result of analyzing one bundle for shell-script activity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShellScriptSnapshot {
    pub schema_version: u32,
    pub observed_at_utc: String,
    pub grammar_version: Option<String>,
    pub grammar_recognized: bool,
    pub runs: Vec<ShellScriptRun>,
    pub coverage: Vec<IntuneArtifactCoverage>,
    pub findings: Vec<IntuneFinding>,
    pub malformed_records: u64,
}

impl ShellScriptSnapshot {
    /// Artifact ids whose coverage is anything other than available.
    pub fn coverage_gap_ids(&self) -> Vec<String> {
        use crate::intune::evidence::IntuneArtifactStatus;
        self.coverage
            .iter()
            .filter(|entry| entry.status != IntuneArtifactStatus::Available)
            .map(|entry| entry.artifact_id.clone())
            .collect()
    }
}
