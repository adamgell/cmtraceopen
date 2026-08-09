//! Typed observations, per-setting state, and the immutable snapshot.
//!
//! The three state tracks ([`ConfigurationReceiptState`],
//! [`ConfigurationLocalState`], [`ConfigurationServiceState`]) are deliberately
//! separate rather than collapsed into one status. Issue #363 requires the output
//! to distinguish what the device received, what its CSP did, and what the
//! service was told, because those three routinely disagree and the disagreement
//! is the diagnosis. A single field would have to pick a winner, and picking a
//! winner is exactly what the evidence does not license.

use serde::{Deserialize, Serialize};

use crate::intune::evidence::{
    IntuneArtifactCoverage, IntuneErrorCode, IntuneEvidenceRef, IntuneFinding, IntuneNamedValue,
    IntuneSensitivity, IntuneSourceKind,
};
use crate::intune::normalized::{NormalizedSettingReport, NormalizedWindowsEvent};

use super::identity::ConfigurationSettingIdentity;

/// Schema version of the serialized configuration snapshot.
pub const INTUNE_CONFIGURATION_SCHEMA_VERSION: u32 = 1;

/// Everything the pure analyzer is given for one device.
///
/// The native adapter decodes EVTX, MDM diagnostic reports, and registry facts
/// and hands them over as the shared normalized types; nothing here reads a file.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConfigurationInput {
    /// UTC instant the bundle was assembled, used only for snapshot provenance.
    pub generated_at_utc: String,
    pub events: Vec<NormalizedWindowsEvent>,
    pub reports: Vec<NormalizedSettingReport>,
    /// Coverage for every artifact that was expected, including the ones that
    /// were never read. A finding may cite one of these instead of evidence.
    pub coverage: Vec<IntuneArtifactCoverage>,
}

/// Which side of the boundary an observation came from.
///
/// A local CSP error is device evidence. A portal status is service evidence and
/// is supplemental: it describes what Intune was told, not what the CSP did.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub enum ConfigurationEvidenceSide {
    /// Read from the device: event log, MDM diagnostic report, registry, agent log.
    Device,
    /// Imported from Intune assignment or reporting data.
    Service,
    /// Source kind this build does not classify; makes no contribution.
    Unclassified,
}

/// Classify a source kind onto the device/service boundary.
///
/// `Unknown` source kinds stay [`ConfigurationEvidenceSide::Unclassified`] on
/// purpose: guessing a side for an unrecognized token would let a future source
/// silently acquire device authority it was never granted.
pub fn evidence_side(kind: &IntuneSourceKind) -> ConfigurationEvidenceSide {
    match kind {
        IntuneSourceKind::EventLog
        | IntuneSourceKind::Registry
        | IntuneSourceKind::DiagnosticReport
        | IntuneSourceKind::ImeLog
        | IntuneSourceKind::CcmLog
        | IntuneSourceKind::AgentLog
        | IntuneSourceKind::PlainTextLog
        | IntuneSourceKind::UnifiedLog
        | IntuneSourceKind::Json => ConfigurationEvidenceSide::Device,
        IntuneSourceKind::Graph | IntuneSourceKind::SuppliedFact => {
            ConfigurationEvidenceSide::Service
        }
        IntuneSourceKind::Coverage | IntuneSourceKind::Unknown(_) => {
            ConfigurationEvidenceSide::Unclassified
        }
    }
}

/// What a single observation says happened to the setting.
///
/// `Received`, `Pending`, and `Indeterminate` are non-terminal; everything else
/// is a terminal disposition and drives [`ConfigurationReceiptState::CspProcessed`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub enum ConfigurationDisposition {
    /// The resource was named but no outcome was stated.
    Received,
    Applied,
    Rejected,
    Conflict,
    Superseded,
    NotApplicable,
    Removed,
    Pending,
    /// The record named the resource but could not be interpreted.
    Indeterminate,
}

impl ConfigurationDisposition {
    /// Whether this disposition proves the CSP reached a decision.
    pub fn is_terminal(self) -> bool {
        !matches!(self, Self::Received | Self::Pending | Self::Indeterminate)
    }
}

/// The event-log records this build recognizes on the MDM Admin channel.
///
/// Only IDs whose meaning is documented by Microsoft are listed. Every other ID
/// stays [`ConfigurationEventKind::Unrecognized`]: the record is retained as
/// evidence that the device saw the resource, but it contributes no outcome.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ConfigurationEventKind {
    /// 404 — MDM ConfigurationManager command failure status.
    CommandFailure,
    /// 813 / 814 — MDM PolicyManager set policy (int / string).
    PolicySet,
    /// 815 — MDM PolicyManager delete policy.
    PolicyDeleted,
    /// Names the resource with no documented outcome.
    Unrecognized,
}

/// One device-side or service-side statement about one setting.
///
/// The observation keeps its full [`IntuneObservationContext`] through
/// `evidence_ref` plus the fields the reducer keys on. Anything not modeled is
/// carried verbatim in `named_data`.
///
/// [`IntuneObservationContext`]: crate::intune::evidence::IntuneObservationContext
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConfigurationObservation {
    pub evidence_ref: IntuneEvidenceRef,
    pub side: ConfigurationEvidenceSide,
    pub source_kind: IntuneSourceKind,
    /// Privacy classification the adapter assigned to the originating record.
    pub sensitivity: IntuneSensitivity,
    pub identity: ConfigurationSettingIdentity,
    pub disposition: ConfigurationDisposition,
    pub event_kind: Option<ConfigurationEventKind>,
    pub event_id: Option<u32>,
    /// Configuration source / policy id that issued this statement, when stated.
    pub source_id: Option<String>,
    pub enrollment_id: Option<String>,
    pub command_type: Option<String>,
    /// The setting value, if one was stated. Classified by `sensitivity`.
    pub value: Option<String>,
    pub error: Option<IntuneErrorCode>,
    /// Source id that this statement says won a conflict, when stated.
    pub winning_source_id: Option<String>,
    /// Source id that this statement says superseded the setting, when stated.
    pub superseded_by_source_id: Option<String>,
    /// Normalized UTC instant, when the source carried a usable one.
    pub occurred_at_utc: Option<String>,
    /// Whether the source timestamp survived normalization.
    pub time_is_reliable: bool,
    /// Record ordinal within its channel, when the source carried one.
    pub record_id: Option<u64>,
    /// True when the record itself was malformed or of an unsupported schema.
    pub is_uninterpretable: bool,
    pub named_data: Vec<IntuneNamedValue>,
}

/// What the device received.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ConfigurationReceiptState {
    /// Nothing names this resource.
    NoEvidence,
    /// Only service-side data names it; the device may never have seen it.
    Intended,
    /// A device-side record names it but states no outcome.
    CommandReceived,
    /// A device-side record shows the CSP reached a decision.
    CspProcessed,
}

/// What the CSP did on the device.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ConfigurationLocalState {
    NoEvidence,
    Applied,
    Rejected,
    Conflicted,
    Superseded,
    NotApplicable,
    Removed,
    /// Device-side records disagree with one another.
    Contested,
    /// A record named the resource but nothing could be concluded.
    Indeterminate,
}

/// What Intune was told.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ConfigurationServiceState {
    NoEvidence,
    /// Assignment intent only; no per-setting status was imported.
    Assigned,
    ReportedSuccess,
    ReportedFailure,
    ReportedConflict,
    ReportedSuperseded,
    ReportedNotApplicable,
    ReportedPending,
    /// Service-side rows disagree with one another.
    Contested,
}

/// The single conclusion the analyzer is willing to state.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ConfigurationResolution {
    Applied,
    Rejected,
    Conflicted,
    Superseded,
    NotApplicable,
    Removed,
    /// Device and service evidence state incompatible outcomes.
    Contradicted,
    /// The evidence names the setting but does not settle its fate.
    InsufficientEvidence,
}

/// A configuration source that made a statement about a setting.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct ConfigurationSourceStatement {
    /// Configuration source / policy id, or `null` when the record did not state one.
    pub source_id: Option<String>,
    pub side: ConfigurationEvidenceSide,
    pub disposition: ConfigurationDisposition,
    pub evidence: Vec<IntuneEvidenceRef>,
}

/// One setting transaction: everything observed about one canonical resource.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConfigurationSetting {
    pub identity: ConfigurationSettingIdentity,
    pub receipt: ConfigurationReceiptState,
    pub local: ConfigurationLocalState,
    pub service: ConfigurationServiceState,
    pub resolution: ConfigurationResolution,
    /// Distinct configuration sources seen for this resource, sorted.
    pub sources: Vec<ConfigurationSourceStatement>,
    /// Terminal error reported by the device, when one was.
    pub local_error: Option<IntuneErrorCode>,
    /// Error the service reported, when one was.
    pub service_error: Option<IntuneErrorCode>,
    /// Value the device reported applying, subject to redaction on export.
    pub applied_value: Option<String>,
    /// False when any contributing record had an unusable timestamp, which
    /// forbids resolving a contradiction by recency.
    pub time_is_reliable: bool,
    /// True when device record order and device timestamp order disagree.
    pub ordering_is_contradictory: bool,
    /// True when at least one contributing record was malformed or unsupported.
    pub has_uninterpretable_evidence: bool,
    /// True when a device record whose *direction* is known to be failure could
    /// not be assessed — a command-failure event with an unreadable status, or one
    /// the collector could not fully read.
    ///
    /// Direction survives even when detail does not. Such a record cannot state
    /// which error occurred, but it does rule out reporting the node as a clean
    /// success, which is why it is tracked separately from
    /// [`ConfigurationSetting::has_uninterpretable_evidence`]: that flag covers
    /// records whose direction is unknown as well.
    pub has_unassessable_failure: bool,
    pub observations: Vec<ConfigurationObservation>,
    pub evidence: Vec<IntuneEvidenceRef>,
}

impl ConfigurationSetting {
    /// Whether device and service evidence can be trusted to be about the same
    /// point in time. Used by the contradiction rules, which refuse to prefer
    /// whichever side is newer when this is false.
    pub fn recency_is_usable(&self) -> bool {
        self.time_is_reliable && !self.ordering_is_contradictory
    }
}

/// Immutable result of reducing one bundle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConfigurationSnapshot {
    pub schema_version: u32,
    pub generated_at_utc: String,
    /// Sorted by identity key so the serialized form is deterministic.
    pub settings: Vec<ConfigurationSetting>,
    /// Observations that named no resolvable resource at all.
    pub unattributed: Vec<ConfigurationObservation>,
    pub coverage: Vec<IntuneArtifactCoverage>,
    pub findings: Vec<IntuneFinding>,
    /// True when the values in this snapshot have been through
    /// [`redacted_configuration_snapshot`].
    ///
    /// [`redacted_configuration_snapshot`]: super::redacted_configuration_snapshot
    pub redacted: bool,
}
