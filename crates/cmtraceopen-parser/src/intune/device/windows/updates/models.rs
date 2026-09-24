//! Input, observation, and snapshot types for the Windows Update for Business leaf.
//!
//! The types split three ways, and the split is the whole point of this module:
//!
//! * **Inputs** are what a native adapter hands the crate. They are already
//!   normalized ([`crate::intune::normalized`]) or are explicit supplied facts.
//! * **Observations** are typed readings of those inputs, each carrying the
//!   [`IntuneObservationContext`] of the record it came from.
//! * The **snapshot** is the immutable reduction, and it keeps the *policy chain*
//!   and the *update chain* in separate structures that are separately queryable.
//!
//! That last separation is the correctness constraint of issue #365. "Intune
//! delivered update settings" and "Windows scanned, downloaded, or installed an
//! update" are different claims backed by different providers, and a type that
//! merged them would make conflating them the path of least resistance.

// `Serializer` and `Deserializer` are required at the expansion site of
// `intune_raw_preserving_string_enum`, which writes the impls by hand.
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::intune::evidence::{
    intune_raw_preserving_string_enum, IntuneArtifactCoverage, IntuneErrorCode, IntuneEvidenceRef,
    IntuneFinding, IntuneFindingConfidence, IntuneNamedValue, IntuneObservationContext,
};
use crate::intune::normalized::{NormalizedSettingReport, NormalizedWindowsEvent};

/// Schema version of every serialized type in this leaf.
pub const INTUNE_WINDOWS_UPDATES_SCHEMA_VERSION: u32 = 1;

/// The extraction profile this build produces and understands.
///
/// The schema version says what the envelope looks like; the profile says which
/// extraction decisions produced its contents. Two bundles can agree on the
/// envelope and still differ in what was extracted from the device, so a
/// snapshot that never states its profile cannot be reproduced or compared.
/// A bundle that declares a different profile is still analyzed, and says so in
/// its input coverage rather than being silently read as if it were this one.
pub const UPDATES_EXTRACTION_PROFILE: &str = "intune-windows-updates-1";

// ── Sources ─────────────────────────────────────────────────────────────────

intune_raw_preserving_string_enum! {
    /// Where a device is configured to get, or actually got, updates.
    ///
    /// `WindowsUpdateForBusiness` is deliberately distinct from `WindowsUpdate`:
    /// both scan the same service, but only the former means deferral and ring
    /// policy are in force, and telling an administrator "you are on Windows
    /// Update" when WUfB policy is what selected it would be misleading.
    pub enum UpdateSource {
        WindowsUpdate => "windowsUpdate",
        WindowsUpdateForBusiness => "windowsUpdateForBusiness",
        MicrosoftUpdate => "microsoftUpdate",
        Wsus => "wsus",
        MicrosoftStore => "microsoftStore",
        DeliveryOptimizationOnly => "deliveryOptimizationOnly",
    }
}

intune_raw_preserving_string_enum! {
    /// Which management authority owns the Windows Update workload.
    ///
    /// Co-management can leave the update workload with Configuration Manager
    /// while the device is still Intune-enrolled. Every conclusion about Intune
    /// update policy is void in that case, so ownership is modeled explicitly
    /// rather than assumed.
    pub enum UpdateWorkloadOwner {
        Intune => "intune",
        ConfigurationManager => "configurationManager",
        NotCoManaged => "notCoManaged",
    }
}

intune_raw_preserving_string_enum! {
    /// Supplemental log formats this leaf can corroborate with.
    ///
    /// Supplemental means exactly that: their absence never blocks a conclusion,
    /// and their presence never becomes the sole basis for one.
    pub enum SupplementalLogKind {
        ReportingEvents => "reportingEvents",
        Cbs => "cbs",
        Dism => "dism",
        WindowsUpdateLog => "windowsUpdateLog",
    }
}

// ── Inputs ──────────────────────────────────────────────────────────────────

/// Device-level facts a native adapter supplies rather than parses out of a log.
///
/// `context` is optional but strongly preferred: without it nothing here can be
/// cited, so a finding that depends on these facts degrades to a coverage
/// statement instead of an evidence-backed one.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UpdateDeviceFacts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<IntuneObservationContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows_build: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edition: Option<String>,
    /// What the caller expected this device's update source to be. Without it
    /// no source-mismatch claim is made, because there is nothing to mismatch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_update_source: Option<UpdateSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_workload_owner: Option<UpdateWorkloadOwner>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub named_data: Vec<IntuneNamedValue>,
}

/// One registry value read by a native adapter.
///
/// The hive, key, and value name live in `context.provenance.registry`, which
/// already models them; repeating them here would let the two disagree.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UpdateRegistryFact {
    pub context: IntuneObservationContext,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub named_data: Vec<IntuneNamedValue>,
}

/// A supplemental log fragment, carried as text and parsed by the generic
/// format parsers this crate already ships.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UpdateSupplementalLog {
    pub context: IntuneObservationContext,
    pub kind: SupplementalLogKind,
    pub content: String,
}

intune_raw_preserving_string_enum! {
    /// What a service-side Intune update report says about one update.
    pub enum ServiceReportedState {
        Installed => "installed",
        Failed => "failed",
        Pending => "pending",
        NotApplicable => "notApplicable",
        Unreported => "unreported",
    }
}

/// One row of an Intune update report, i.e. what the *service* believes.
///
/// Kept apart from device evidence on purpose: a service report is a claim about
/// the device made elsewhere, and it goes stale. It can contradict local
/// evidence, and when it does, the contradiction is the finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UpdateServiceReport {
    pub context: IntuneObservationContext,
    pub key: UpdateKey,
    pub state: ServiceReportedState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reported_at_utc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<IntuneErrorCode>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub named_data: Vec<IntuneNamedValue>,
}

/// Everything the leaf reduces, in one serializable bundle.
///
/// `events` is a single list rather than one list per provider. Splitting it by
/// provider at the input boundary would let a caller decide what counts as
/// update-client evidence, and that decision is precisely what this leaf must
/// own.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UpdateEvidenceBundle {
    #[serde(default)]
    pub schema_version: u32,
    /// The extraction profile the capture tool used; see
    /// [`UPDATES_EXTRACTION_PROFILE`]. `None` means the bundle did not state one,
    /// which is not the same as stating this build's profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extraction_profile: Option<String>,
    #[serde(default)]
    pub generated_at_utc: String,
    #[serde(default)]
    pub device: UpdateDeviceFacts,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<NormalizedWindowsEvent>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub setting_reports: Vec<NormalizedSettingReport>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub registry_facts: Vec<UpdateRegistryFact>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supplemental_logs: Vec<UpdateSupplementalLog>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service_reports: Vec<UpdateServiceReport>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub coverage: Vec<IntuneArtifactCoverage>,
}

// ── Keys ────────────────────────────────────────────────────────────────────

/// Identity of a single update.
///
/// All three parts are optional because the sources disagree about which they
/// carry: `Microsoft-Windows-WindowsUpdateClient` supplies `updateGuid` and
/// `updateRevisionNumber`, `ReportingEvents.log` supplies an update GUID and a
/// KB in free text, and a service report usually supplies only a KB. Two rows
/// join only when they agree on a part both actually carry; see
/// [`UpdateKey::joins`].
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct UpdateKey {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kb_article: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
}

/// Whether two update ids name the same update.
///
/// The braces and the case are punctuation, not identity: sources write an id
/// both ways, and a caller can supply a key directly rather than through
/// [`crate::intune::device::windows::updates::update_key_from`], so the
/// comparison canonicalises instead of trusting that every producer did. Without
/// this, `{a-…}` and `a-…` were two different updates and a service report
/// joined to neither.
fn same_update_id(left: &str, right: &str) -> bool {
    fn canonical(value: &str) -> &str {
        value.trim().trim_start_matches('{').trim_end_matches('}')
    }
    canonical(left).eq_ignore_ascii_case(canonical(right))
}

impl UpdateKey {
    /// Whether this key identifies anything at all.
    pub fn is_identified(&self) -> bool {
        self.update_id.is_some() || self.kb_article.is_some()
    }

    /// Whether two keys refer to the same update on explicit identifiers.
    ///
    /// Time proximity is never enough, so this deliberately has no timestamp
    /// input. Two keys join when they share an `update_id`, or when they share a
    /// `kb_article` and neither carries a *conflicting* `update_id` — and in
    /// both cases their revisions must agree, and a KB the two name differently
    /// under one id keeps them apart. A key with nothing identified joins
    /// nothing, including another empty key.
    pub fn joins(&self, other: &Self) -> bool {
        if !self.is_identified() || !other.is_identified() {
            return false;
        }
        match (&self.update_id, &other.update_id) {
            (Some(left), Some(right)) => {
                same_update_id(left, right) && self.revision_agrees(other) && self.kb_agrees(other)
            }
            _ => match (&self.kb_article, &other.kb_article) {
                // A KB match alone is not enough: a different revision of the
                // same KB is a different update, so revision must agree too.
                (Some(left), Some(right)) => {
                    left.eq_ignore_ascii_case(right) && self.revision_agrees(other)
                }
                _ => false,
            },
        }
    }

    /// A revision disagreement is a different revision of the same update, which
    /// is a separate transaction: a superseded revision failing says nothing
    /// about the revision that later installed.
    fn revision_agrees(&self, other: &Self) -> bool {
        match (&self.revision, &other.revision) {
            (Some(left), Some(right)) => left == right,
            _ => true,
        }
    }

    /// A KB disagreement under one update id is not a match either.
    ///
    /// One revision cannot carry two KB numbers, so two records that share an
    /// update id but name different KBs are not two views of one update. Joining
    /// them puts two labels on one transaction and hides whichever record lost:
    /// they stay separate until something states which label is the real one.
    fn kb_agrees(&self, other: &Self) -> bool {
        match (&self.kb_article, &other.kb_article) {
            (Some(left), Some(right)) => left.eq_ignore_ascii_case(right),
            _ => true,
        }
    }

    /// Stable, human-readable label used in finding ids.
    pub fn label(&self) -> String {
        match (&self.kb_article, &self.update_id, &self.revision) {
            (Some(kb), _, Some(revision)) => format!("{kb}.{revision}"),
            (Some(kb), _, None) => kb.clone(),
            (None, Some(id), Some(revision)) => format!("{id}.{revision}"),
            (None, Some(id), None) => id.clone(),
            (None, None, _) => "unidentified".to_owned(),
        }
    }

    /// Fold `other` into this key without overwriting anything already known.
    pub fn absorb(&mut self, other: &Self) {
        if self.update_id.is_none() {
            self.update_id.clone_from(&other.update_id);
        }
        if self.kb_article.is_none() {
            self.kb_article.clone_from(&other.kb_article);
        }
        if self.revision.is_none() {
            self.revision.clone_from(&other.revision);
        }
    }
}

// ── Policy chain observations ───────────────────────────────────────────────

/// What one policy-chain record said.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum PolicySignal {
    /// The device received or applied an update-related policy value.
    Applied,
    /// The device acknowledged the policy but has not applied it yet.
    Pending,
    /// Delivery or CSP application failed.
    DeliveryFailed,
    /// Two sources set the same node and the CSP reported a conflict.
    Conflict,
    /// The value was delivered but the CSP does not support it on this build.
    UnsupportedValue,
    /// The record states an effective update source.
    EffectiveSource,
    /// The record states which authority owns the update workload.
    WorkloadOwnership,
    /// The node was superseded by another policy.
    Superseded,
    /// The record is about update policy but says nothing decisive.
    Informational,
}

/// One typed reading of a policy-chain record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PolicyObservation {
    pub context: IntuneObservationContext,
    pub signal: PolicySignal,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<IntuneErrorCode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<UpdateSource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub named_data: Vec<IntuneNamedValue>,
}

/// A node two policy sources disagreed about.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PolicyConflict {
    /// The CSP node or setting id both sources targeted.
    pub node: String,
    /// Policy ids that claimed the node, sorted, deduplicated.
    pub policy_ids: Vec<String>,
    pub evidence: Vec<IntuneEvidenceRef>,
}

/// Terminal reading of the policy chain.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum PolicyChainState {
    /// No update policy record of any kind was present.
    #[default]
    NotObserved,
    /// Records exist but none is decisive.
    InsufficientEvidence,
    /// A CSP or MDM record reported a delivery failure.
    DeliveryFailed,
    /// Two policy sources contended for the same node.
    Conflicted,
    /// A value arrived that the CSP rejected as unsupported.
    UnsupportedValue,
    /// Update policy was applied.
    Applied,
    /// Intune does not own the update workload, so Intune policy is not in force.
    NotOwnedByIntune,
}

/// Comparison of expected against observed update source.
///
/// The three source fields are recorded independently so the report shows the
/// nuance of *how* the device was pointed at its update service: `expected` is
/// the operator's intent, `configured` is what policy/registry evidence
/// declares, and `scanned` is what the update client actually used (from its
/// own `serviceGuid`). `scanned` and `configured` can legitimately differ, and
/// neither is collapsed into the other here.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EffectiveSourceAssessment {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected: Option<UpdateSource>,
    /// What policy and registry evidence says the device is pointed at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configured: Option<UpdateSource>,
    /// What the update client actually scanned, from its own `serviceGuid`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scanned: Option<UpdateSource>,
    /// Whether the effective source satisfies `expected`.
    ///
    /// The effective source is `scanned` when present, else `configured`
    /// (scanned is what the device really used, so it wins on disagreement).
    /// `Some(true)`/`Some(false)` is emitted whenever both `expected` and an
    /// effective source are known — `configured` may be absent and a verdict is
    /// still produced from `scanned` alone. `None` only when `expected` is
    /// unknown or no source was observed at all. A `windowsUpdate` scan and a
    /// `windowsUpdateForBusiness` expectation (or vice versa) count as agreeing
    /// because both scan the same backend service; the exact `expected`/
    /// `scanned` values are preserved on this struct so the distinction stays
    /// visible in the export.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matches_expectation: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub configured_evidence: Vec<IntuneEvidenceRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scanned_evidence: Vec<IntuneEvidenceRef>,
}

/// Everything known about how Intune delivered update settings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PolicyChain {
    pub state: PolicyChainState,
    pub workload_owner: UpdateWorkloadOwner,
    pub effective_source: EffectiveSourceAssessment,
    pub observations: Vec<PolicyObservation>,
    pub conflicts: Vec<PolicyConflict>,
    pub evidence: Vec<IntuneEvidenceRef>,
    pub confidence: IntuneFindingConfidence,
}

/// Written out rather than derived because [`IntuneFindingConfidence`] lives in
/// the shared evidence module, which this leaf must not modify to add a
/// `Default` impl it alone needs.
impl Default for PolicyChain {
    fn default() -> Self {
        Self {
            state: PolicyChainState::NotObserved,
            workload_owner: UpdateWorkloadOwner::default(),
            effective_source: EffectiveSourceAssessment::default(),
            observations: Vec::new(),
            conflicts: Vec::new(),
            evidence: Vec::new(),
            confidence: IntuneFindingConfidence::Low,
        }
    }
}

impl UpdateWorkloadOwner {
    /// The wire value used when ownership was never established.
    ///
    /// The macro supplies the `Unknown(String)` fallback that preserves an
    /// unrecognized token, so "we do not know" is spelled with that same variant
    /// rather than a second, competing one.
    pub const UNKNOWN_WIRE_VALUE: &'static str = "unknown";

    /// Whether ownership is genuinely unestablished, as opposed to a value this
    /// build does not recognize.
    pub fn is_unestablished(&self) -> bool {
        matches!(self, Self::Unknown(raw) if raw == Self::UNKNOWN_WIRE_VALUE)
    }
}

impl Default for UpdateWorkloadOwner {
    fn default() -> Self {
        Self::Unknown(Self::UNKNOWN_WIRE_VALUE.to_owned())
    }
}

// ── Update chain observations ───────────────────────────────────────────────

/// A stage of the Windows Update client's own work.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum UpdatePhase {
    /// The client's detection pass. An event 26 reporting `updateCount=0` ends here, and that is what makes the chain `NoApplicableUpdate`.
    Scan,
    /// Whether a detected update applies to this device. Reaches the same verdict as a scan that found nothing, by a different event.
    Applicability,
    /// Fetching the payload of an update that applied.
    Download,
    /// Running the update's own installer.
    Install,
    /// The restart an install needs before it completes.
    Reboot,
    /// The client telling the service what it did.
    Reporting,
}

/// What happened in that stage.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum UpdateOutcome {
    /// The stage began and has not reported an end.
    Started,
    /// The stage completed as intended.
    Succeeded,
    /// The stage ended in an error.
    Failed,
    /// Held back by an active hours window, deadline, or deferral policy.
    Deferred,
    /// The stage concluded there was nothing to do.
    NotApplicable,
    /// Still outstanding, such as a restart that has not happened.
    Pending,
    /// An outcome the source could not classify. Carried rather than dropped, so the reading is not silently lost.
    Unknown,
}

/// One typed reading of an update-chain record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UpdateObservation {
    pub context: IntuneObservationContext,
    pub phase: UpdatePhase,
    pub outcome: UpdateOutcome,
    #[serde(default)]
    pub key: UpdateKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<IntuneErrorCode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activity_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<UpdateSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Set when the observation came from a supplemental format rather than the
    /// update client itself. Supplemental readings corroborate; they never
    /// establish a terminal state on their own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supplemental: Option<SupplementalLogKind>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub named_data: Vec<IntuneNamedValue>,
}

impl UpdateObservation {
    /// Whether this reading came from the Windows Update client itself.
    ///
    /// This is the predicate that keeps issue #365 honest: a claim about update
    /// *execution* must be backed by at least one observation for which this is
    /// true.
    pub fn is_update_client_evidence(&self) -> bool {
        self.supplemental.is_none()
    }
}

/// Terminal reading of one update's execution.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum UpdateTransactionState {
    /// The scan failed and nothing keyed follows it.
    ScanFailed,
    /// Nothing applied to this update. Per-update scope: `UpdateChainState::NoApplicableUpdate` says the same of the device.
    NoApplicableUpdate,
    /// The payload did not arrive.
    DownloadFailed,
    /// The installer reported an error.
    InstallFailed,
    /// Held back by active hours, a deadline, or policy.
    Deferred,
    /// Installed, waiting on a restart to complete.
    RebootPending,
    /// Installed and complete.
    Installed,
    /// Readings exist and none of them is terminal.
    InProgress,
    /// Readings exist but none can be placed in order, so no outcome is claimed.
    InsufficientEvidence,
}

/// One phase reading retained on a transaction, in observation order.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UpdatePhaseRecord {
    pub phase: UpdatePhase,
    pub outcome: UpdateOutcome,
    pub evidence: IntuneEvidenceRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supplemental: Option<SupplementalLogKind>,
}

/// Everything one update did on this device.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UpdateTransaction {
    pub key: UpdateKey,
    pub state: UpdateTransactionState,
    pub phases: Vec<UpdatePhaseRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<IntuneErrorCode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Whether every update-client reading in this transaction can be placed in
    /// time.
    ///
    /// A reading with no usable timestamp is still evidence of what happened; it
    /// cannot say *when*. A conclusion that turns on recency -- "the client's last
    /// statement was an install" -- cannot be High confidence while one of its
    /// readings is unplaceable, so the reducer answers that question here rather
    /// than leaving each rule to guess it from the outside.
    #[serde(default)]
    pub readings_are_placed: bool,
    /// Evidence produced by the update client itself.
    pub evidence: Vec<IntuneEvidenceRef>,
    /// Evidence produced by supplemental formats, kept apart so a reader can see
    /// at a glance whether a conclusion rests on CBS/DISM text alone.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub corroborating_evidence: Vec<IntuneEvidenceRef>,
    /// What the service reported for this update, when a report row joined.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_state: Option<ServiceReportedState>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service_evidence: Vec<IntuneEvidenceRef>,
    pub confidence: IntuneFindingConfidence,
    /// True when the phase readings arrived in an order that cannot have
    /// happened, e.g. an install success timestamped before its own download.
    #[serde(default)]
    pub order_contradiction: bool,
}

/// Terminal reading of the device's update execution as a whole.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum UpdateChainState {
    /// No update-client evidence of any kind was present.
    #[default]
    NotObserved,
    /// Update-client evidence exists but nothing terminal can be read from it.
    InsufficientEvidence,
    /// The device's own scan failed.
    ScanFailed,
    /// Nothing applied to the device. Device scope: `UpdateTransactionState::NoApplicableUpdate` says it of one update.
    NoApplicableUpdate,
    /// A download failed and nothing terminal follows it.
    DownloadFailed,
    /// An install failed and nothing terminal follows it.
    InstallFailed,
    /// Held back by active hours, a deadline, or policy.
    Deferred,
    /// Installed, waiting on a restart.
    RebootPending,
    /// The device's update execution completed.
    Installed,
    /// Work is underway and nothing terminal has been read.
    InProgress,
}

/// Everything known about what Windows Update actually did.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UpdateChain {
    pub state: UpdateChainState,
    pub transactions: Vec<UpdateTransaction>,
    /// Readings that carried no usable update identity. They are retained rather
    /// than dropped, but they never form a transaction, because an unkeyed
    /// failure cannot be attributed to any particular update.
    pub unkeyed_observations: Vec<UpdateObservation>,
    pub reboot_pending: Option<bool>,
    pub evidence: Vec<IntuneEvidenceRef>,
}

// ── Linkage ─────────────────────────────────────────────────────────────────

/// How, if at all, the two chains are connected.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum ChainLinkState {
    /// Nothing ties the chains together. This is the default and stays the
    /// default unless an explicit identifier says otherwise.
    NotLinked,
    /// Policy-configured source and update-client scanned source name the same
    /// service. This is the documented explicit relationship.
    SharedUpdateSource,
    /// The chains disagree about the source, which is itself a defensible link:
    /// the same fact is described two ways.
    SourceDisagreement,
}

/// The only sanctioned bridge between the policy chain and the update chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChainLinkage {
    pub state: ChainLinkState,
    pub confidence: IntuneFindingConfidence,
    /// Prose statement of what made the link defensible, or why there is none.
    pub basis: String,
    pub evidence: Vec<IntuneEvidenceRef>,
}

impl Default for ChainLinkage {
    fn default() -> Self {
        Self {
            state: ChainLinkState::NotLinked,
            confidence: IntuneFindingConfidence::Low,
            basis: "No shared identifier ties update policy delivery to update client activity."
                .to_owned(),
            evidence: Vec::new(),
        }
    }
}

// ── Coverage of the inputs themselves ───────────────────────────────────────

/// Records this build could not classify.
///
/// A leaf that silently ignores an unrecognized provider or event id reports
/// "nothing happened" when the truth is "this build does not understand what
/// happened". These counts make that difference visible.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInputCoverage {
    /// Events from a provider this leaf does not model.
    pub unknown_provider_events: u32,
    /// Events from a modeled provider whose event id this build does not map.
    pub unmapped_event_ids: u32,
    /// Sorted, deduplicated list of the unmapped ids, so a reader can act.
    pub unmapped_event_id_list: Vec<u32>,
    /// Sorted, deduplicated list of unmodeled providers seen.
    pub unknown_providers: Vec<String>,
    /// Supplemental log lines the generic parsers could not read as records.
    pub supplemental_parse_errors: u32,
    /// Records excluded before classification because nobody could read them.
    ///
    /// A record the adapter could not parse, or could not read at all, is a
    /// coverage state rather than a reading. Counting it here keeps the
    /// exclusion visible instead of letting the evidence look absent.
    #[serde(default)]
    pub unusable_records: u32,
    /// The extraction profile the bundle declared, when it declared one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extraction_profile: Option<String>,
    /// Whether that profile is one this build knows how to extract.
    ///
    /// A bundle extracted by a different profile is still analyzed, but its
    /// records were read with this build's rules: fields the other profile added
    /// are absent rather than empty, and a reader has to be told that.
    #[serde(default)]
    pub extraction_profile_unsupported: bool,
    /// Evidence refs for the unclassified records, so a finding can cite them.
    pub evidence: Vec<IntuneEvidenceRef>,
    /// Evidence refs for the records excluded as unreadable.
    ///
    /// Kept apart from [`Self::evidence`] because the two answer different
    /// questions: `evidence` is "this record was read and did not map", this is
    /// "this record could not be read at all". One shared vector made each
    /// finding cite the other's records.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unusable_evidence: Vec<IntuneEvidenceRef>,
}

impl UpdateInputCoverage {
    pub fn has_unknowns(&self) -> bool {
        self.unknown_provider_events > 0 || self.unmapped_event_ids > 0
    }
}

// ── Snapshot ────────────────────────────────────────────────────────────────

/// The immutable reduction of one evidence bundle.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UpdateSnapshot {
    pub schema_version: u32,
    pub generated_at_utc: String,
    pub device: UpdateDeviceFacts,
    pub policy_chain: PolicyChain,
    pub update_chain: UpdateChain,
    pub linkage: ChainLinkage,
    pub input_coverage: UpdateInputCoverage,
    pub coverage: Vec<IntuneArtifactCoverage>,
    pub findings: Vec<IntuneFinding>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_join_on_a_shared_update_id() {
        let left = UpdateKey {
            update_id: Some("{aaaaaaaa-0000-0000-0000-000000000001}".to_owned()),
            kb_article: None,
            revision: Some("1".to_owned()),
        };
        let right = UpdateKey {
            update_id: Some("{AAAAAAAA-0000-0000-0000-000000000001}".to_owned()),
            kb_article: Some("KB5000001".to_owned()),
            revision: Some("1".to_owned()),
        };
        assert!(left.joins(&right));
    }

    #[test]
    fn keys_do_not_join_across_revisions_of_the_same_update() {
        let left = UpdateKey {
            update_id: Some("{a}".to_owned()),
            kb_article: None,
            revision: Some("1".to_owned()),
        };
        let right = UpdateKey {
            update_id: Some("{a}".to_owned()),
            kb_article: None,
            revision: Some("2".to_owned()),
        };
        assert!(!left.joins(&right));
    }

    #[test]
    fn keys_join_across_brace_punctuation_in_a_supplied_id() {
        // A caller can hand over a key directly rather than through
        // `update_key_from`, so punctuation is normalised where it is compared,
        // not only where it is built. Otherwise the same service report silently
        // joined nothing.
        let braced = UpdateKey {
            update_id: Some("{aaaaaaaa-0000-0000-0000-000000000001}".to_owned()),
            kb_article: None,
            revision: None,
        };
        let bare = UpdateKey {
            update_id: Some("aaaaaaaa-0000-0000-0000-000000000001".to_owned()),
            kb_article: None,
            revision: None,
        };
        assert!(braced.joins(&bare));
    }

    #[test]
    fn keys_do_not_join_when_one_update_id_carries_two_kb_labels() {
        let left = UpdateKey {
            update_id: Some("{aaaaaaaa-0000-0000-0000-000000000001}".to_owned()),
            kb_article: Some("KB5000001".to_owned()),
            revision: Some("1".to_owned()),
        };
        let conflicting = UpdateKey {
            update_id: Some("{aaaaaaaa-0000-0000-0000-000000000001}".to_owned()),
            kb_article: Some("KB5000002".to_owned()),
            revision: Some("1".to_owned()),
        };
        assert!(
            !left.joins(&conflicting),
            "one revision cannot carry two KB labels, so the records stay apart"
        );

        let agreeing = UpdateKey {
            kb_article: Some("KB5000001".to_owned()),
            ..conflicting
        };
        assert!(
            left.joins(&agreeing),
            "a shared id, revision, and KB label is one update"
        );
    }

    #[test]
    fn unidentified_keys_join_nothing_including_each_other() {
        let empty = UpdateKey::default();
        assert!(!empty.joins(&empty));
    }

    #[test]
    fn keys_join_on_kb_only_when_no_update_id_contradicts() {
        let left = UpdateKey {
            update_id: None,
            kb_article: Some("KB5000001".to_owned()),
            revision: None,
        };
        let right = UpdateKey {
            update_id: Some("{b}".to_owned()),
            kb_article: Some("KB5000001".to_owned()),
            revision: None,
        };
        assert!(left.joins(&right));

        let other_kb = UpdateKey {
            update_id: None,
            kb_article: Some("KB5000002".to_owned()),
            revision: None,
        };
        assert!(!left.joins(&other_kb));
    }

    #[test]
    fn keys_do_not_join_across_revisions_of_the_same_kb() {
        let left = UpdateKey {
            update_id: None,
            kb_article: Some("KB5000001".to_owned()),
            revision: Some("1".to_owned()),
        };
        let right = UpdateKey {
            update_id: None,
            kb_article: Some("KB5000001".to_owned()),
            revision: Some("2".to_owned()),
        };
        assert!(
            !left.joins(&right),
            "a different revision of the same KB is a different update"
        );

        // Same KB, same revision still joins.
        let same = UpdateKey {
            update_id: None,
            kb_article: Some("KB5000001".to_owned()),
            revision: Some("1".to_owned()),
        };
        assert!(left.joins(&same));

        // A missing revision does not contradict a present one.
        let unspecified = UpdateKey {
            update_id: None,
            kb_article: Some("KB5000001".to_owned()),
            revision: None,
        };
        assert!(left.joins(&unspecified));
    }

    #[test]
    fn source_enum_preserves_unknown_wire_values() {
        let decoded: UpdateSource = serde_json::from_str("\"someFutureSource\"").unwrap();
        assert_eq!(
            decoded,
            UpdateSource::Unknown("someFutureSource".to_owned())
        );
        assert_eq!(
            serde_json::to_string(&decoded).unwrap(),
            "\"someFutureSource\""
        );
    }
}
