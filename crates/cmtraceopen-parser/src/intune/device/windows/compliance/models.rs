//! Typed model for Intune Windows device compliance.
//!
//! The single organizing idea here is that **four different things can each be
//! called "the device is noncompliant", and they are not interchangeable**:
//!
//! 1. a device-local setting evaluated to noncompliant;
//! 2. the aggregate result the device computed from those settings;
//! 3. the state the service currently holds, which can be arbitrarily stale;
//! 4. a downstream Conditional Access denial, which is a consequence of (3) at
//!    best and unrelated at worst.
//!
//! So each is a separate phase on [`ComplianceSnapshot`] with its own state
//! enum, and no reduction path lets one become another. A stale service record
//! cannot produce a [`ComplianceSettingState::Noncompliant`], and an access
//! denial cannot produce any local state at all.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::intune::evidence::{
    intune_raw_preserving_string_enum, IntuneArtifactCoverage, IntuneErrorCode, IntuneEvidenceRef,
    IntuneFinding, IntuneNamedValue, IntuneObservationContext, IntuneTimestamp,
};
use crate::intune::normalized::{NormalizedSettingReport, NormalizedWindowsEvent};

/// Schema version for every serialized type in this module.
pub const INTUNE_COMPLIANCE_SCHEMA_VERSION: u32 = 1;

// ── Scope and identity ──────────────────────────────────────────────────────

/// Whether a policy or setting was targeted at the device or at a user.
///
/// This is load-bearing rather than decorative: a user-targeted setting that was
/// never evaluated because no user was signed in is a *coverage* fact, and
/// treating it as a local failure is the specific mistake this module exists to
/// avoid.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub enum ComplianceScope {
    Device,
    User,
    Unknown,
}

/// The identifiers a compliance setting can be keyed on.
///
/// All three are optional because different sources supply different subsets:
/// an MDM event usually carries an OMA-DM node URI, an exported report row
/// usually carries policy and setting GUIDs. Observations are only merged when
/// they share a derived grouping token; see [`ComplianceSettingEvaluation::grouping_token`].
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceSettingKey {
    pub policy_id: Option<String>,
    pub setting_id: Option<String>,
    pub setting_uri: Option<String>,
}

impl ComplianceSettingKey {
    /// Whether the key carries any identifier at all.
    pub fn is_identified(&self) -> bool {
        [&self.policy_id, &self.setting_id, &self.setting_uri]
            .into_iter()
            .any(|part| {
                part.as_deref()
                    .is_some_and(|value| !value.trim().is_empty())
            })
    }

    /// The token two observations must agree on to be merged.
    ///
    /// Returns `None` for an unidentified key. Epic #356 forbids creating a
    /// correlation from an unknown identifier or from time proximity, so an
    /// observation with no identity is never merged into another one.
    pub fn grouping_token(&self) -> Option<String> {
        let normalize = |value: &Option<String>| {
            value
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_ascii_lowercase)
        };

        if let Some(uri) = normalize(&self.setting_uri) {
            return Some(format!("uri:{uri}"));
        }
        match (normalize(&self.policy_id), normalize(&self.setting_id)) {
            (Some(policy), Some(setting)) => Some(format!("policy:{policy}/setting:{setting}")),
            (Some(policy), None) => Some(format!("policy:{policy}")),
            (None, Some(setting)) => Some(format!("setting:{setting}")),
            (None, None) => None,
        }
    }
}

// ── Local evaluation states ─────────────────────────────────────────────────

/// The result of evaluating one compliance setting **on the device**.
///
/// `Noncompliant` is reachable only from a local evaluation source. No service
/// record, report submission outcome, or access decision can produce it.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub enum ComplianceSettingState {
    Compliant,
    Noncompliant,
    /// The device tried to evaluate the setting and the evaluation itself failed.
    EvaluationError,
    /// The setting does not apply to this device (edition, SKU, hardware).
    NotApplicable,
    /// The setting was received but no evaluation happened in this context.
    NotEvaluated,
    /// A local precondition (for example an unmet CSP dependency) blocked evaluation.
    PrerequisiteUnmet,
    /// Two definite local sources disagree; neither is preferred over the other.
    Contradictory,
    /// A source mentioned the setting without stating a usable result.
    InsufficientEvidence,
}

impl ComplianceSettingState {
    /// Whether this state is a definite claim about the setting.
    ///
    /// Only definite states can contradict each other; mixing a definite state
    /// with an indefinite one is not a contradiction, it is one source knowing
    /// more than another.
    pub fn is_definite(self) -> bool {
        matches!(
            self,
            Self::Compliant | Self::Noncompliant | Self::EvaluationError | Self::NotApplicable
        )
    }
}

/// Whether a compliance policy was known to the device.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub enum CompliancePolicyState {
    Received,
    NotReceived,
    Unknown,
}

/// Whether a local precondition for evaluation was satisfied.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub enum CompliancePrerequisiteState {
    Met,
    Unmet,
    Unknown,
}

/// Outcome of a custom-compliance (HealthScripts) discovery run.
///
/// `ScriptFailed` and `DiscoveryNoncompliant` are deliberately distinct. A
/// script that crashed produced no verdict at all; reporting that as "the device
/// is noncompliant" invents a result the evidence does not contain.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub enum ComplianceCustomState {
    DiscoveryCompliant,
    DiscoveryNoncompliant,
    /// The script did not complete: nonzero exit, timeout, or launch failure.
    ScriptFailed,
    /// The script completed but its output could not be interpreted as a verdict.
    OutputInvalid,
    NotRun,
    Unknown,
}

// ── Aggregate ───────────────────────────────────────────────────────────────

/// The device-wide result derived from the local setting evaluations.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub enum ComplianceAggregateState {
    Compliant,
    Noncompliant,
    EvaluationError,
    NotEvaluated,
    InsufficientEvidence,
}

/// Why the aggregate landed where it did.
///
/// Carried explicitly so a consumer never has to re-derive the reason from the
/// counts, and so "compliant" and "nothing was evaluated" cannot be confused.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub enum ComplianceAggregateRationale {
    LocalSettingNoncompliant,
    CustomComplianceDiscoveryNoncompliant,
    LocalEvaluationError,
    CustomComplianceScriptFailed,
    ContradictoryLocalEvidence,
    AllEvaluatedSettingsCompliant,
    NoSettingEvaluated,
    NoLocalSourceAvailable,
}

// ── Reporting and service state ─────────────────────────────────────────────

/// State of the device's own compliance report submission.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub enum ComplianceReportState {
    Queued,
    Submitted,
    Failed,
    /// A submission succeeded, but it predates the most recent local evaluation.
    Stale,
    Unknown,
}

intune_raw_preserving_string_enum! {
    /// The compliance state the service holds for this device.
    ///
    /// Raw-preserving because this vocabulary is the service's, not ours, and it
    /// grows. An unrecognized token round-trips verbatim instead of collapsing
    /// into a state we would then reason about incorrectly.
    pub enum ComplianceServiceState {
        Compliant => "compliant",
        Noncompliant => "noncompliant",
        InGracePeriod => "inGracePeriod",
        ConfigManager => "configManager",
        Error => "error",
        NotEvaluated => "notEvaluated",
        NotApplicable => "notApplicable",
    }
}

/// Whether a service-held record reflects the most recent local evaluation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub enum ComplianceServiceFreshness {
    /// Reported at or after the most recent local evaluation.
    Fresh,
    /// Reported before the most recent local evaluation, so it cannot describe it.
    Stale,
    /// One of the two timestamps is missing; freshness is unknowable.
    Unknown,
}

// ── Downstream access ───────────────────────────────────────────────────────

/// A sign-in outcome supplied as supplemental downstream evidence.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub enum ComplianceAccessDecision {
    Granted,
    Denied,
    Interrupted,
    Unknown,
}

/// How strongly an access decision can be tied to a compliance record.
///
/// This is the guard rail for the whole module. An access decision only reaches
/// [`ComplianceAccessLinkage::MatchedComplianceState`] when a device or user key
/// matches *and* both sides carry a usable timestamp. Everything else is
/// explicitly uncorrelated, and the rules refuse to make a causal claim for it.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub enum ComplianceAccessLinkage {
    MatchedComplianceState,
    /// Keys were present on both sides and did not match.
    IdentityMismatch,
    /// No compliance record exists to match against.
    NoMatchingComplianceEvidence,
    /// A candidate record exists but identity or time provenance is missing.
    InsufficientProvenance,
}

/// Whether a user was available for user-scoped evaluation.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub enum ComplianceUserContext {
    UserPresent,
    NoUserSession,
    /// The collector did not report whether a user session existed. This is the
    /// default because assuming either answer changes how an unevaluated
    /// user-scoped setting reads.
    #[default]
    Unknown,
}

// ── Supplied facts (inputs this module owns) ────────────────────────────────
//
// Windows events and setting-report rows are *not* redefined here: they arrive
// as `crate::intune::normalized` types, which are shared with the sibling
// configuration and update leaves. The three fact types below have no shared
// counterpart, so they are defined here and nowhere else.

/// One custom-compliance (HealthScripts) discovery outcome.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceCustomFact {
    pub context: IntuneObservationContext,
    pub policy_id: Option<String>,
    pub run_id: Option<String>,
    pub setting_name: Option<String>,
    pub outcome: ComplianceCustomState,
    pub error: Option<IntuneErrorCode>,
    /// Raw script output. Always redacted by the export projection.
    pub raw_output: Option<String>,
    pub named_data: Vec<IntuneNamedValue>,
}

/// One service-reported compliance record imported with capture provenance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceServiceFact {
    pub context: IntuneObservationContext,
    pub policy_id: Option<String>,
    pub setting_id: Option<String>,
    pub state: ComplianceServiceState,
    pub reported_at: Option<IntuneTimestamp>,
    pub device_key: Option<String>,
    pub user_key: Option<String>,
    pub named_data: Vec<IntuneNamedValue>,
}

/// One sign-in / Conditional Access outcome, supplemental evidence only.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceAccessFact {
    pub context: IntuneObservationContext,
    pub decision: ComplianceAccessDecision,
    pub failure_code: Option<IntuneErrorCode>,
    pub occurred_at: Option<IntuneTimestamp>,
    pub device_key: Option<String>,
    pub user_key: Option<String>,
    pub resource: Option<String>,
    pub named_data: Vec<IntuneNamedValue>,
}

/// Device, tenant, enrollment, and active-user context supplied by the collector.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceDeviceContextFact {
    pub context: IntuneObservationContext,
    pub device_key: Option<String>,
    pub tenant_key: Option<String>,
    pub enrollment_id: Option<String>,
    pub windows_build: Option<String>,
    pub active_user_key: Option<String>,
    /// `Some(false)` means "we checked and no user was signed in", which is what
    /// makes an unevaluated user-scoped setting explainable rather than mysterious.
    pub user_session_present: Option<bool>,
    pub named_data: Vec<IntuneNamedValue>,
}

/// Everything the reducer consumes.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceInput {
    pub generated_at_utc: String,
    pub events: Vec<NormalizedWindowsEvent>,
    pub setting_reports: Vec<NormalizedSettingReport>,
    pub custom_compliance: Vec<ComplianceCustomFact>,
    pub service_results: Vec<ComplianceServiceFact>,
    pub access_decisions: Vec<ComplianceAccessFact>,
    pub device_context: Option<ComplianceDeviceContextFact>,
    pub coverage: Vec<IntuneArtifactCoverage>,
}

// ── Snapshot phases ─────────────────────────────────────────────────────────

/// Device, tenant, and user context as reduced for the snapshot.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceDeviceContextView {
    pub device_key: Option<String>,
    pub tenant_key: Option<String>,
    pub enrollment_id: Option<String>,
    pub windows_build: Option<String>,
    pub active_user_key: Option<String>,
    pub user_evaluation_context: ComplianceUserContext,
    pub evidence: Vec<IntuneEvidenceRef>,
}

/// One compliance policy the device is known to have received, or not.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompliancePolicyObservation {
    pub policy_id: String,
    pub state: CompliancePolicyState,
    pub scope: ComplianceScope,
    pub evidence: Vec<IntuneEvidenceRef>,
}

/// One local precondition for evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompliancePrerequisite {
    pub name: String,
    pub state: CompliancePrerequisiteState,
    pub detail: Option<String>,
    pub evidence: Vec<IntuneEvidenceRef>,
}

/// One setting, reduced from every local observation that shares its key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceSettingEvaluation {
    pub key: ComplianceSettingKey,
    /// The token the merge was performed on. Exposed so a consumer can see
    /// *why* two observations were treated as the same setting.
    pub grouping_token: String,
    pub scope: ComplianceScope,
    pub state: ComplianceSettingState,
    pub display_name: Option<String>,
    pub error: Option<IntuneErrorCode>,
    pub evaluated_at: Option<IntuneTimestamp>,
    /// Every definite state observed, in sorted order. More than one entry means
    /// the sources disagreed and `state` is [`ComplianceSettingState::Contradictory`].
    pub observed_states: Vec<ComplianceSettingState>,
    /// The evaluation claims a time after the snapshot was generated.
    pub time_contradiction: bool,
    /// Two merged sources declared different values for the same identifier.
    ///
    /// The merge still happens — the sources agreed on the token they were
    /// grouped by — but the disagreement is surfaced rather than silently
    /// resolved first-wins.
    pub identity_contradiction: bool,
    pub evidence: Vec<IntuneEvidenceRef>,
    pub named_data: Vec<IntuneNamedValue>,
}

/// One custom-compliance discovery result, reduced.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceCustomEvaluation {
    pub policy_id: Option<String>,
    pub run_id: Option<String>,
    pub setting_name: Option<String>,
    pub state: ComplianceCustomState,
    pub error: Option<IntuneErrorCode>,
    pub raw_output: Option<String>,
    pub evidence: Vec<IntuneEvidenceRef>,
    pub named_data: Vec<IntuneNamedValue>,
}

/// Phase 1: what the device itself evaluated.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceLocalPhase {
    pub policies: Vec<CompliancePolicyObservation>,
    pub prerequisites: Vec<CompliancePrerequisite>,
    pub settings: Vec<ComplianceSettingEvaluation>,
    pub custom_compliance: Vec<ComplianceCustomEvaluation>,
    /// Local observations that named no setting identity and were therefore
    /// never merged into an evaluation.
    pub unkeyed_observations: Vec<IntuneEvidenceRef>,
    pub latest_evaluation_at_utc: Option<String>,
    pub evidence: Vec<IntuneEvidenceRef>,
}

/// Phase 2: the device-wide result derived from phase 1.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceAggregatePhase {
    pub state: ComplianceAggregateState,
    pub rationale: ComplianceAggregateRationale,
    pub compliant_count: usize,
    pub noncompliant_count: usize,
    pub error_count: usize,
    pub not_applicable_count: usize,
    pub not_evaluated_count: usize,
    pub contradictory_count: usize,
    pub evidence: Vec<IntuneEvidenceRef>,
}

impl Default for ComplianceAggregatePhase {
    fn default() -> Self {
        Self {
            state: ComplianceAggregateState::InsufficientEvidence,
            rationale: ComplianceAggregateRationale::NoLocalSourceAvailable,
            compliant_count: 0,
            noncompliant_count: 0,
            error_count: 0,
            not_applicable_count: 0,
            not_evaluated_count: 0,
            contradictory_count: 0,
            evidence: Vec::new(),
        }
    }
}

/// One service-held record, reduced with its freshness relative to phase 1.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceServiceResult {
    pub policy_id: Option<String>,
    pub setting_id: Option<String>,
    pub state: ComplianceServiceState,
    pub reported_at: Option<IntuneTimestamp>,
    pub freshness: ComplianceServiceFreshness,
    pub device_key: Option<String>,
    pub user_key: Option<String>,
    pub evidence: Vec<IntuneEvidenceRef>,
}

/// Phase 3: what the device submitted and what the service currently holds.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceReportingPhase {
    pub state: ComplianceReportState,
    pub report_id: Option<String>,
    pub last_submission_at: Option<IntuneTimestamp>,
    pub error: Option<IntuneErrorCode>,
    pub service_results: Vec<ComplianceServiceResult>,
    pub service_freshness: ComplianceServiceFreshness,
    /// The service state contradicts the locally derived aggregate.
    pub service_disagrees_with_local: bool,
    pub evidence: Vec<IntuneEvidenceRef>,
}

impl Default for ComplianceReportingPhase {
    fn default() -> Self {
        Self {
            state: ComplianceReportState::Unknown,
            report_id: None,
            last_submission_at: None,
            error: None,
            service_results: Vec::new(),
            service_freshness: ComplianceServiceFreshness::Unknown,
            service_disagrees_with_local: false,
            evidence: Vec::new(),
        }
    }
}

/// One access decision and how well it could be tied to compliance evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceAccessObservation {
    pub decision: ComplianceAccessDecision,
    pub linkage: ComplianceAccessLinkage,
    pub failure_code: Option<IntuneErrorCode>,
    pub occurred_at: Option<IntuneTimestamp>,
    pub device_key: Option<String>,
    pub user_key: Option<String>,
    pub resource: Option<String>,
    /// The compliance evidence the match was made against. Empty unless
    /// `linkage` is [`ComplianceAccessLinkage::MatchedComplianceState`].
    pub matched_evidence: Vec<IntuneEvidenceRef>,
    pub evidence: Vec<IntuneEvidenceRef>,
}

/// Phase 4: downstream impact only. Never a cause.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceAccessPhase {
    pub decisions: Vec<ComplianceAccessObservation>,
    pub evidence: Vec<IntuneEvidenceRef>,
}

/// The immutable reduction of one compliance evidence bundle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceSnapshot {
    pub schema_version: u32,
    pub generated_at_utc: String,
    pub device_context: ComplianceDeviceContextView,
    pub local_evaluation: ComplianceLocalPhase,
    pub aggregate: ComplianceAggregatePhase,
    pub reporting: ComplianceReportingPhase,
    pub access_impact: ComplianceAccessPhase,
    pub coverage: Vec<IntuneArtifactCoverage>,
    pub findings: Vec<IntuneFinding>,
}

impl Default for ComplianceSnapshot {
    fn default() -> Self {
        Self {
            schema_version: INTUNE_COMPLIANCE_SCHEMA_VERSION,
            generated_at_utc: String::new(),
            device_context: ComplianceDeviceContextView::default(),
            local_evaluation: ComplianceLocalPhase::default(),
            aggregate: ComplianceAggregatePhase::default(),
            reporting: ComplianceReportingPhase::default(),
            access_impact: ComplianceAccessPhase::default(),
            coverage: Vec::new(),
            findings: Vec::new(),
        }
    }
}

// ── Shared evidence helpers ─────────────────────────────────────────────────

/// Sort and de-duplicate evidence references in place.
///
/// Every list a rule or phase emits goes through this, so the serialized output
/// is byte-identical across runs regardless of source iteration order.
pub(super) fn normalize_evidence(evidence: &mut Vec<IntuneEvidenceRef>) {
    evidence.sort();
    evidence.dedup();
}

/// Clone, sort, and de-duplicate an evidence iterator.
pub(super) fn collect_evidence<'a>(
    evidence: impl IntoIterator<Item = &'a IntuneEvidenceRef>,
) -> Vec<IntuneEvidenceRef> {
    let mut collected = evidence.into_iter().cloned().collect::<Vec<_>>();
    normalize_evidence(&mut collected);
    collected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setting_key_prefers_the_uri_when_present() {
        let key = ComplianceSettingKey {
            policy_id: Some("p".to_owned()),
            setting_id: Some("s".to_owned()),
            setting_uri: Some("./Device/Vendor/MSFT/Policy/Result/X".to_owned()),
        };
        assert_eq!(
            key.grouping_token().as_deref(),
            Some("uri:./device/vendor/msft/policy/result/x")
        );
    }

    #[test]
    fn an_unidentified_key_has_no_grouping_token() {
        let key = ComplianceSettingKey {
            policy_id: Some("   ".to_owned()),
            setting_id: None,
            setting_uri: None,
        };
        assert!(!key.is_identified());
        assert_eq!(key.grouping_token(), None);
    }

    #[test]
    fn only_definite_states_can_contradict() {
        assert!(ComplianceSettingState::Noncompliant.is_definite());
        assert!(!ComplianceSettingState::NotEvaluated.is_definite());
        assert!(!ComplianceSettingState::InsufficientEvidence.is_definite());
    }

    #[test]
    fn service_state_preserves_an_unrecognized_token() {
        let decoded: ComplianceServiceState = serde_json::from_str("\"someFutureState\"").unwrap();
        assert_eq!(
            decoded,
            ComplianceServiceState::Unknown("someFutureState".to_owned())
        );
        assert_eq!(
            serde_json::to_string(&decoded).unwrap(),
            "\"someFutureState\""
        );
    }

    #[test]
    fn snapshot_wire_form_is_camel_case() {
        let encoded = serde_json::to_string(&ComplianceSnapshot::default()).unwrap();
        assert!(encoded.contains("\"schemaVersion\""));
        assert!(encoded.contains("\"localEvaluation\""));
        assert!(encoded.contains("\"accessImpact\""));
    }
}
