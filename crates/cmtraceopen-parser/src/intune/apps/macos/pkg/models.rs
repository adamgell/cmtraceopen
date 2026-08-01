//! Public types for Intune macOS package deployment.
//!
//! These describe *what the evidence showed*, not what the analyzer guessed.
//! Every state implying an outcome is reachable only from an explicit record;
//! everything else lands in [`PkgOutcome::InsufficientEvidence`] alongside a
//! coverage entry naming the artifact that would resolve it.

// `Deserializer`/`Serializer` are required in scope by
// `intune_raw_preserving_string_enum`, which hand-writes its serde impls.
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::intune::evidence::{
    intune_raw_preserving_string_enum, IntuneArtifactCoverage, IntuneErrorCode, IntuneEvidenceRef,
    IntuneFinding, IntuneNamedValue, IntuneTimestamp,
};

intune_raw_preserving_string_enum! {
    /// The app type a policy declared.
    ///
    /// This exists so that package terminal semantics are never applied to a
    /// type that does not have them. Issue #361 permits cataloguing other types
    /// but forbids reducing them as if they were `.pkg` installs.
    pub enum PkgAppType {
        Pkg => "pkg",
        Dmg => "dmg",
        AppBundle => "app",
        LobPkg => "lobPkg",
    }
}

impl PkgAppType {
    /// Whether this analyzer models the type's install lifecycle.
    ///
    /// Only the two `.pkg` flavors reach an installer-exit terminal state. A DMG
    /// or bare `.app` is drag-install; an installer exit code never appears for
    /// it, so treating a missing one as failure would invent a fault.
    pub fn has_installer_semantics(&self) -> bool {
        matches!(self, Self::Pkg | Self::LobPkg)
    }
}

/// Lifecycle phases in order.
///
/// `last_confirmed_phase` on a transaction is the furthest phase with direct
/// evidence, never the furthest phase we assume was reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PkgPhase {
    PolicyReceived,
    ApplicabilityEvaluated,
    Downloading,
    Staged,
    Validating,
    InstallerLaunched,
    InstallerCompleted,
    PostInstallDetection,
    Reported,
}

/// The terminal verdict for a package transaction.
///
/// Reporting is deliberately *not* part of this enum: a package that installed
/// and failed to report is still installed, and collapsing the two would make
/// the reporting-failure scenario indistinguishable from an install failure.
/// See [`PkgReportingState`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PkgOutcome {
    /// Installer exited zero and post-install detection confirmed it.
    Installed,
    /// Installer exited zero but nothing confirmed the app is present.
    ///
    /// Distinct from `Installed` because a zero exit only proves the installer
    /// returned, not that the payload landed.
    InstalledPendingDetection,
    /// Installer exited zero and detection explicitly failed.
    DetectionFailed,
    DownloadFailed,
    ValidationFailed,
    /// Installer ran and exited nonzero.
    InstallFailed,
    /// A failure was observed and a retry was scheduled after it, so the
    /// transaction is not yet terminal.
    RetryScheduled,
    /// The policy names an app type whose lifecycle this analyzer does not model.
    UnsupportedAppType,
    /// No record decided the outcome either way.
    InsufficientEvidence,
}

impl PkgOutcome {
    /// Whether this outcome represents a failed deployment.
    pub fn is_failure(self) -> bool {
        matches!(
            self,
            Self::DownloadFailed
                | Self::ValidationFailed
                | Self::InstallFailed
                | Self::DetectionFailed
        )
    }
}

/// Whether the agent managed to report the result to the service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PkgReportingState {
    Reported,
    Failed,
    NotObserved,
}

/// The identity a package transaction is keyed on.
///
/// Both halves come from stated identifiers. Two records sharing only a
/// timestamp and a component never join.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PkgTransactionKey {
    pub policy_id: Option<String>,
    pub app_id: String,
}

/// One observed phase transition, with the record that proves it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PkgPhaseEvent {
    pub phase: PkgPhase,
    pub timestamp: Option<IntuneTimestamp>,
    pub evidence: IntuneEvidenceRef,
}

/// One package deployment, reduced from every record that named it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PkgTransaction {
    pub key: PkgTransactionKey,
    /// Sensitive: an app display name identifies a tenant's catalog.
    pub display_name: Option<String>,
    pub app_type: Option<PkgAppType>,
    pub bundle_id: Option<String>,
    pub version: Option<String>,
    pub phases: Vec<PkgPhaseEvent>,
    pub last_confirmed_phase: Option<PkgPhase>,
    pub outcome: PkgOutcome,
    pub reporting: PkgReportingState,
    /// The code from the record that decided the outcome, when it stated one.
    pub error_code: Option<IntuneErrorCode>,
    pub retry_count: u32,
    /// Fields retained without interpretation, so a typed field can be added
    /// later without re-parsing.
    pub attributes: Vec<IntuneNamedValue>,
    pub evidence: Vec<IntuneEvidenceRef>,
}

/// The immutable result of analyzing one bundle of macOS agent artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PkgSnapshot {
    pub schema_version: u32,
    pub observed_at_utc: String,
    /// Which agent grammar revision the evidence declared, if any.
    pub grammar_version: Option<String>,
    /// False when no artifact declared a revision this build knows.
    pub grammar_recognized: bool,
    pub transactions: Vec<PkgTransaction>,
    pub coverage: Vec<IntuneArtifactCoverage>,
    pub findings: Vec<IntuneFinding>,
    /// Count of lines that could not be framed, across every artifact.
    pub malformed_records: u64,
}

impl PkgSnapshot {
    /// Artifact ids whose coverage is anything other than available.
    ///
    /// A finding cites these when it must reason about evidence that was never
    /// collected.
    pub fn coverage_gap_ids(&self) -> Vec<String> {
        use crate::intune::evidence::IntuneArtifactStatus;
        self.coverage
            .iter()
            .filter(|entry| entry.status != IntuneArtifactStatus::Available)
            .map(|entry| entry.artifact_id.clone())
            .collect()
    }
}
