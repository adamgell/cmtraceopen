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
    ///
    /// It is deliberately *not* the redaction token scope: a second-resolution
    /// timestamp is not an identifier, and two unrelated analyses can carry the
    /// same one. See [`ConfigurationInput::analysis_scope`].
    pub generated_at_utc: String,
    /// Caller-supplied identity of *this* analysis, and nothing else.
    ///
    /// It scopes the redaction token vocabulary (ADR-004): two analyses that
    /// supply *different* values do not mint the same `[redacted:…]` token for
    /// the same input value (barring hash collision), so an export cannot be
    /// joined to an unrelated one by comparing tokens. Any opaque per-analysis value works — a capture
    /// GUID, a support-case id, a digest of the collected bundle.
    ///
    /// The value is used verbatim: only a whitespace-only string counts as no
    /// scope at all, so `"a"` and `" a "` are two different analyses. The crate
    /// cannot know which bytes a caller's identity scheme treats as
    /// significant, and normalizing them would silently join exports the caller
    /// meant to keep apart.
    ///
    /// Uniqueness is the caller's obligation and cannot be checked here: this
    /// crate is pure and `wasm32-unknown-unknown` clean, so it has no clock, no
    /// entropy source, and no process state that survives a restart from which
    /// it could mint an identifier of its own. Two analyses that supply the
    /// *same* value are deliberately joinable, because that is what "one
    /// analysis" means.
    ///
    /// `None` means the caller declines the boundary: the token scope then
    /// falls back to [`ConfigurationInput::generated_at_utc`] alone, which
    /// preserves equality inside the one export and provides **no** isolation
    /// from any other export that shares that timestamp. The resulting snapshot
    /// says so — [`ConfigurationSnapshot::analysis_scope`] is `None`.
    ///
    /// The value never reaches the export verbatim; only a digest of it does.
    pub analysis_scope: Option<String>,
    /// Normalized MDM Admin-channel records the adapter decoded from EVTX.
    pub events: Vec<NormalizedWindowsEvent>,
    /// Normalized per-setting rows from an MDM diagnostic report or imported
    /// Intune reporting. The source kind on each row decides which side of the
    /// device/service boundary it speaks for.
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
        | IntuneSourceKind::UnifiedLog => ConfigurationEvidenceSide::Device,
        IntuneSourceKind::Graph | IntuneSourceKind::SuppliedFact => {
            ConfigurationEvidenceSide::Service
        }
        // `Json` says how the bytes were encoded, not where they came from: a
        // portal export and a device-side agent state file are both JSON. Granting
        // it device authority let an exported portal view resolve a setting the
        // CSP was never shown to have applied. An adapter that has a device-side
        // JSON source should declare the source kind it actually is.
        IntuneSourceKind::Json | IntuneSourceKind::Coverage | IntuneSourceKind::Unknown(_) => {
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
    /// The value was written.
    Applied,
    /// The CSP returned a terminal error.
    Rejected,
    /// Another configuration source claimed the same node.
    Conflict,
    /// Another configuration source replaced this one.
    Superseded,
    /// The CSP decided the node does not apply to this device.
    NotApplicable,
    /// The value was deleted.
    Removed,
    /// The service is still waiting for a result.
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
    /// Back-reference to the record this statement was projected from.
    pub evidence_ref: IntuneEvidenceRef,
    /// Which side of the device/service boundary the record speaks for.
    pub side: ConfigurationEvidenceSide,
    /// The source kind `side` was derived from, retained so a reader can see why.
    pub source_kind: IntuneSourceKind,
    /// Privacy classification the adapter assigned to the originating record.
    pub sensitivity: IntuneSensitivity,
    /// The canonical resource this record is about.
    pub identity: ConfigurationSettingIdentity,
    /// What this one record says happened.
    pub disposition: ConfigurationDisposition,
    /// The recognized event shape, for records projected from an event log.
    pub event_kind: Option<ConfigurationEventKind>,
    /// The raw event id, retained even when unrecognized.
    pub event_id: Option<u32>,
    /// Configuration source / policy id that issued this statement, when stated.
    pub source_id: Option<String>,
    /// Enrollment this record belongs to, when stated. Tokenized on export.
    pub enrollment_id: Option<String>,
    /// The OMA-DM command verb as written. Evidence only: it never decides a
    /// disposition, because a typed outcome outranks free text.
    pub command_type: Option<String>,
    /// The setting value, if one was stated. Classified by `sensitivity`.
    pub value: Option<String>,
    /// Status code the record carried, in every form it could be written in.
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
    /// True when the record itself was malformed, of an unsupported schema, or
    /// not fully read by the collector.
    pub is_uninterpretable: bool,
    /// Everything the record carried that this build does not model, verbatim.
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
    /// No device-side record names this resource.
    NoEvidence,
    /// The CSP wrote the value.
    Applied,
    /// The CSP returned a terminal error.
    Rejected,
    /// Another configuration source won the node.
    Conflicted,
    /// Another configuration source replaced this one.
    Superseded,
    /// The CSP decided the node does not apply here.
    NotApplicable,
    /// The CSP deleted the value.
    Removed,
    /// Device-side records disagree with one another, including the case where a
    /// success stands beside a failure record that could not be read.
    Contested,
    /// A record named the resource but nothing could be concluded.
    Indeterminate,
}

/// What Intune was told.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ConfigurationServiceState {
    /// No Intune reporting was imported for this resource.
    NoEvidence,
    /// Assignment intent only; no per-setting status was imported.
    Assigned,
    /// Intune was told the setting succeeded.
    ReportedSuccess,
    /// Intune was told the setting failed.
    ReportedFailure,
    /// Intune was told another source claimed the node.
    ReportedConflict,
    /// Intune was told another source replaced this one.
    ReportedSuperseded,
    /// Intune was told the node does not apply.
    ReportedNotApplicable,
    /// Intune is still waiting for a result.
    ReportedPending,
    /// Service-side rows disagree with one another.
    Contested,
}

/// The single conclusion the analyzer is willing to state.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ConfigurationResolution {
    /// Device evidence shows the value was written.
    Applied,
    /// Device evidence shows a terminal error.
    Rejected,
    /// Two configuration sources claimed the node and one lost.
    Conflicted,
    /// Another configuration source replaced this one.
    Superseded,
    /// The node does not apply to this device.
    NotApplicable,
    /// The value was deleted.
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
    /// Which side of the boundary this source spoke from.
    pub side: ConfigurationEvidenceSide,
    /// What this source said happened.
    pub disposition: ConfigurationDisposition,
    /// Every record that carried this statement.
    pub evidence: Vec<IntuneEvidenceRef>,
}

/// One setting transaction: everything observed about one canonical resource.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConfigurationSetting {
    /// The canonical resource every observation here is about.
    pub identity: ConfigurationSettingIdentity,
    /// What the device received.
    pub receipt: ConfigurationReceiptState,
    /// What the CSP did.
    pub local: ConfigurationLocalState,
    /// What Intune was told.
    pub service: ConfigurationServiceState,
    /// The single conclusion drawn from the three tracks above.
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
    /// Every contributing record, in a canonical order that does not depend on
    /// how the caller supplied them.
    pub observations: Vec<ConfigurationObservation>,
    /// Back-references for every contributing record, for a caller that wants the
    /// citations without the projections.
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
    /// [`INTUNE_CONFIGURATION_SCHEMA_VERSION`] at the time of reduction.
    pub schema_version: u32,
    /// Copied from the input, for provenance only.
    pub generated_at_utc: String,
    /// Opaque digest of the analysis scope every redaction token is bound to.
    ///
    /// `Some` when the caller supplied [`ConfigurationInput::analysis_scope`].
    /// Two snapshots carrying *different* digests share no token vocabulary: a
    /// token in one says nothing about a token in the other. Two carrying the
    /// *same* digest were declared by the caller to be one analysis and their
    /// tokens do compare.
    ///
    /// `None` says the caller supplied no scope, so the tokens in this snapshot
    /// are bound to [`ConfigurationSnapshot::generated_at_utc`] alone and make
    /// **no** cross-export isolation claim at all.
    ///
    /// It is a digest, not a secret and not a key: it exists so an export can
    /// name its own token scope without republishing the caller's identifier.
    /// Anyone who already knows the scope material can recompute it, and the
    /// tokens themselves remain unkeyed (ADR-004 leaves keying to the Store
    /// pilot).
    pub analysis_scope: Option<String>,
    /// Sorted by identity key so the serialized form is deterministic.
    pub settings: Vec<ConfigurationSetting>,
    /// Observations that named no resolvable resource at all.
    pub unattributed: Vec<ConfigurationObservation>,
    /// Every expected artifact and what became of it, copied from the input.
    pub coverage: Vec<IntuneArtifactCoverage>,
    /// Conclusions derived from this snapshot, in a fixed rule order.
    pub findings: Vec<IntuneFinding>,
    /// True when the values in this snapshot have been through
    /// [`redacted_configuration_snapshot`].
    ///
    /// [`redacted_configuration_snapshot`]: super::redacted_configuration_snapshot
    pub redacted: bool,
}
