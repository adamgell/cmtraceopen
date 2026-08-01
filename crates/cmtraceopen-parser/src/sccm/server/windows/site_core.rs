//! Server-local site-core and status-system analysis for issue #327.
//!
//! The reducer owns evidence produced by the site server itself: the site
//! component manager family (`server-sitecomp`) and the status/state system
//! family (`server-status`). It reduces complete logical records into
//! component-keyed transactions along
//! `ComponentStart -> ComponentWork -> InboxOrQueue -> StatusOrStateProcessing
//! -> HealthyOrTerminal`.
//!
//! Scope boundaries this module never crosses:
//!
//! * Management Point, Distribution Point, Software Update Point, hierarchy
//!   transport and Provider/Admin Service evidence belongs to other lanes.
//!   `mpcontrol.log` is site-server produced but carries a Management Point
//!   workflow subject, so it stays with the `server-mp-policy` source and is
//!   never admitted here.
//! * No client impact, downstream-role availability or cross-side causal
//!   statement is derivable from this analyzer; those claims are declared
//!   prohibited on every result.
//!
//! Only the `sccm-site-core` v1 extraction profile is selected, and only for
//! the synthetic `5.00.TEST` corpus version. A fact requires a complete logical
//! record, an exact profile-validated component and work-item key, the
//! declared producer component for its source family, and a source whose
//! catalogued basename, family and rotation all agree with its manifest
//! declaration.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::models::log_entry::Severity;
use crate::sccm::{
    classify_artifact_name, SccmArtifact, SccmArtifactFamily, SccmArtifactRequest, SccmConfidence,
    SccmCoverageState, SccmEvidence, SccmEvidenceRef, SccmFinding, SccmFindingBuilder,
    SccmFindingClass, SccmFindingCoverageGap, SccmPhase, SccmRole, SccmRotation,
    SccmTerminalEvidence, SccmTimeOrderingState, SccmTimestamp,
};

pub const SCCM_SITE_CORE_ANALYSIS_SCHEMA_VERSION: u32 = 1;
pub const SCCM_SITE_CORE_PROFILE_ID: &str = "sccm-site-core";
pub const SCCM_SITE_CORE_PROFILE_VERSION: u32 = 1;
pub const SCCM_SITE_CORE_PROFILE_STABILITY: &str = "experimental";
pub const SCCM_SITE_CORE_COMPONENT_GROUP: &str = "server-sitecomp";
pub const SCCM_SITE_CORE_STATUS_GROUP: &str = "server-status";

/// The only ConfigMgr build this profile is validated against.
const SITE_CORE_PROFILE_VERSION_TOKEN: &str = "5.00.TEST";
/// Producer components this profile is validated against. `hman.log` and
/// `statesys.log` are declared members of the same groups, but no fixture
/// validates the component they record, so they carry no entry here and can
/// only become coverage.
const VALIDATED_PRODUCERS: [(&str, &str); 2] = [
    ("sitecomp", "SMS_SITE_COMPONENT_MANAGER"),
    ("statmgr", "SMS_STATUS_MANAGER"),
];
/// Floor for a bounded recapture request after a capture limit truncated a
/// source. Requests never ask for an unbounded file.
const RECAPTURE_FLOOR_BYTES: u64 = 4096;

const STATE_CHAIN: [SccmSiteCorePhase; 5] = [
    SccmSiteCorePhase::ComponentStart,
    SccmSiteCorePhase::ComponentWork,
    SccmSiteCorePhase::InboxOrQueue,
    SccmSiteCorePhase::StatusOrStateProcessing,
    SccmSiteCorePhase::HealthyOrTerminal,
];

const PROHIBITED_CLAIMS: [SccmSiteCoreProhibitedClaim; 3] = [
    SccmSiteCoreProhibitedClaim::AbsentDownstreamRole,
    SccmSiteCoreProhibitedClaim::ClientImpact,
    SccmSiteCoreProhibitedClaim::CrossSideCausality,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SccmSiteCoreTopology {
    pub site_code: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SccmSiteCoreSource {
    pub artifact: SccmArtifact,
    pub source_group: String,
    pub rotation_lineage: String,
    pub fragment_complete: Option<bool>,
    pub physical_line_end: Option<u32>,
    pub capture_limit_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SccmSiteCoreBundle {
    pub topology: SccmSiteCoreTopology,
    pub sources: Vec<SccmSiteCoreSource>,
    pub evidence: Vec<SccmEvidence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmSiteCoreWorkflow {
    SiteCore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmSiteCorePhase {
    ComponentStart,
    ComponentWork,
    InboxOrQueue,
    StatusOrStateProcessing,
    HealthyOrTerminal,
}

impl SccmSiteCorePhase {
    fn serialized_name(self) -> &'static str {
        match self {
            Self::ComponentStart => "componentStart",
            Self::ComponentWork => "componentWork",
            Self::InboxOrQueue => "inboxOrQueue",
            Self::StatusOrStateProcessing => "statusOrStateProcessing",
            Self::HealthyOrTerminal => "healthyOrTerminal",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmSiteCoreState {
    Healthy,
    TerminalFailure,
    BlockedOrDeferred,
    Recovered,
    Incomplete,
    ParseGap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmSiteCoreConfidence {
    None,
    Low,
    Moderate,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmSiteCoreDiagnosticMeaning {
    CoverageOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmSiteCoreProhibitedClaim {
    AbsentDownstreamRole,
    ClientImpact,
    CrossSideCausality,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmSiteCoreProfile {
    pub id: String,
    pub version: u32,
    pub stability: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmSiteCoreTransactionKey {
    pub profile_id: String,
    pub profile_version: u32,
    pub site_code: String,
    pub component_id: String,
    pub work_item_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmSiteCoreEvidence {
    pub artifact_id: String,
    pub entry_id: String,
    pub line_start: u32,
    pub line_end: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub complete_logical_record: Option<bool>,
}

impl SccmSiteCoreEvidence {
    fn reference(&self) -> SccmEvidenceRef {
        SccmEvidenceRef {
            artifact_id: self.artifact_id.clone(),
            entry_id: self.entry_id.clone(),
            line_start: Some(self.line_start),
            line_end: Some(self.line_end),
        }
    }

    fn sort_key(&self) -> (&str, u32, u32, &str) {
        (
            self.artifact_id.as_str(),
            self.line_start,
            self.line_end,
            self.entry_id.as_str(),
        )
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmSiteCoreRequestScope {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub component_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub work_item_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotation_lineage: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmSiteCoreArtifactRequest {
    pub logical_name: String,
    pub role: SccmRole,
    pub reason_code: String,
    pub basenames: Vec<String>,
    pub rotations: Vec<String>,
    pub max_artifacts: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_bytes_per_artifact: Option<u64>,
    pub scope: SccmSiteCoreRequestScope,
}

impl SccmSiteCoreArtifactRequest {
    fn sort_key(&self) -> (&str, &str, &str, &SccmSiteCoreRequestScope) {
        (
            self.logical_name.as_str(),
            role_sort_key(&self.role),
            self.reason_code.as_str(),
            &self.scope,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmSiteCoreResult {
    pub result_id: String,
    pub transaction_key: SccmSiteCoreTransactionKey,
    pub state: SccmSiteCoreState,
    pub last_successful_phase: Option<SccmSiteCorePhase>,
    pub finding_class: Option<SccmFindingClass>,
    pub confidence: SccmSiteCoreConfidence,
    pub confidence_ceiling: SccmSiteCoreConfidence,
    pub evidence: Vec<SccmSiteCoreEvidence>,
    pub coverage_gap_artifact_ids: Vec<String>,
    pub next_artifacts: Vec<SccmSiteCoreArtifactRequest>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmSiteCoreObservation {
    pub observation_id: String,
    pub state: SccmSiteCoreState,
    pub last_successful_phase: Option<SccmSiteCorePhase>,
    pub finding_class: SccmFindingClass,
    pub confidence: SccmSiteCoreConfidence,
    pub confidence_ceiling: SccmSiteCoreConfidence,
    pub evidence: Vec<SccmSiteCoreEvidence>,
    pub coverage_gap_artifact_ids: Vec<String>,
    pub next_artifacts: Vec<SccmSiteCoreArtifactRequest>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmSiteCoreCoverageGap {
    pub artifact_id: String,
    pub state: SccmCoverageState,
    pub diagnostic_meaning: SccmSiteCoreDiagnosticMeaning,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<SccmSiteCoreEvidence>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmSiteCoreFinding {
    #[serde(flatten)]
    pub finding: SccmFinding,
    pub subject_id: String,
    pub last_successful_phase: Option<SccmSiteCorePhase>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmSiteCoreAnalysis {
    pub schema_version: u32,
    pub workflow: SccmSiteCoreWorkflow,
    pub profile: SccmSiteCoreProfile,
    pub state_chain: Vec<SccmSiteCorePhase>,
    pub results: Vec<SccmSiteCoreResult>,
    pub unlinked_observations: Vec<SccmSiteCoreObservation>,
    pub coverage_gaps: Vec<SccmSiteCoreCoverageGap>,
    pub findings: Vec<SccmSiteCoreFinding>,
    pub artifact_requests: Vec<SccmSiteCoreArtifactRequest>,
    pub prohibited_claims: Vec<SccmSiteCoreProhibitedClaim>,
    pub cross_side_correlation_performed: bool,
}

/// Reduce a site-core evidence bundle into component-keyed transactions,
/// source-local observations, coverage gaps and bounded next-artifact requests.
pub fn analyze_site_core(bundle: &SccmSiteCoreBundle) -> SccmSiteCoreAnalysis {
    let site_code = normalize_site_code(&bundle.topology.site_code);
    let context = SiteCoreContext::new(bundle);
    let facts = collect_facts(&context, site_code.as_deref());
    let fragments = collect_fragments(&context);
    let coverage_gaps = collect_coverage_gaps(&context, &fragments);
    let coverage = CoverageView::new(&coverage_gaps, &fragments);

    let mut results = Vec::new();
    let mut findings = Vec::new();
    for (key, facts) in group_facts(facts) {
        let reduced = reduce_transaction(&context, &coverage, key, &facts);
        if let Some(finding) = reduced.finding {
            findings.push(finding);
        }
        results.push(reduced.result);
    }

    let mut unlinked_observations = Vec::new();
    append_fragment_observations(
        &fragments,
        &coverage,
        &mut unlinked_observations,
        &mut findings,
    );

    results.sort_by(|left, right| left.result_id.cmp(&right.result_id));
    unlinked_observations.sort_by(|left, right| left.observation_id.cmp(&right.observation_id));
    findings.sort_by(|left, right| {
        left.subject_id
            .cmp(&right.subject_id)
            .then_with(|| left.finding.finding_id.cmp(&right.finding.finding_id))
    });

    let artifact_requests = collect_artifact_requests(&results, &unlinked_observations);

    SccmSiteCoreAnalysis {
        schema_version: SCCM_SITE_CORE_ANALYSIS_SCHEMA_VERSION,
        workflow: SccmSiteCoreWorkflow::SiteCore,
        profile: SccmSiteCoreProfile {
            id: SCCM_SITE_CORE_PROFILE_ID.to_owned(),
            version: SCCM_SITE_CORE_PROFILE_VERSION,
            stability: SCCM_SITE_CORE_PROFILE_STABILITY.to_owned(),
        },
        state_chain: STATE_CHAIN.to_vec(),
        results,
        unlinked_observations,
        coverage_gaps,
        findings,
        artifact_requests,
        prohibited_claims: PROHIBITED_CLAIMS.to_vec(),
        cross_side_correlation_performed: false,
    }
}

// ---------------------------------------------------------------------------
// Source admission
// ---------------------------------------------------------------------------

/// The admitted view of one bundle. Shape admission runs once so no later
/// stage can silently re-derive a different source set, and every whole-bundle
/// question a per-record or per-transaction stage would otherwise ask is
/// answered here once as well.
struct SiteCoreContext<'a> {
    bundle: &'a SccmSiteCoreBundle,
    sources: BTreeMap<&'a str, AdmittedSource<'a>>,
    /// Whether each record in `bundle.evidence`, by position, holds an identity
    /// no other record contests.
    evidence_identity_is_unique: Vec<bool>,
    /// The unparsed physical tail of each admitted source, if it has one.
    truncated_tails: BTreeMap<&'a str, SccmSiteCoreEvidence>,
}

impl<'a> SiteCoreContext<'a> {
    fn new(bundle: &'a SccmSiteCoreBundle) -> Self {
        let sources = admitted_sources(bundle);
        let truncated_tails = truncated_tails(bundle, &sources);
        Self {
            bundle,
            sources,
            evidence_identity_is_unique: unique_evidence_identities(bundle),
            truncated_tails,
        }
    }

    fn truncated_tail(&self, artifact_id: &str) -> Option<SccmSiteCoreEvidence> {
        self.truncated_tails.get(artifact_id).cloned()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SiteCoreGroup {
    Component,
    Status,
}

impl SiteCoreGroup {
    fn id(self) -> &'static str {
        match self {
            Self::Component => SCCM_SITE_CORE_COMPONENT_GROUP,
            Self::Status => SCCM_SITE_CORE_STATUS_GROUP,
        }
    }

    fn slug(self) -> &'static str {
        match self {
            Self::Component => "component",
            Self::Status => "status",
        }
    }

    fn family(self) -> SccmArtifactFamily {
        match self {
            Self::Component => SccmArtifactFamily::SiteComponent,
            Self::Status => SccmArtifactFamily::SiteStatus,
        }
    }

    fn logical_names(self) -> &'static [&'static str] {
        match self {
            Self::Component => &["sitecomp", "hman"],
            Self::Status => &["statmgr", "statesys"],
        }
    }

    fn entry_phase(self) -> SccmSiteCorePhase {
        match self {
            Self::Component => SccmSiteCorePhase::ComponentStart,
            Self::Status => SccmSiteCorePhase::StatusOrStateProcessing,
        }
    }

    fn from_id(value: &str) -> Option<Self> {
        match value {
            SCCM_SITE_CORE_COMPONENT_GROUP => Some(Self::Component),
            SCCM_SITE_CORE_STATUS_GROUP => Some(Self::Status),
            _ => None,
        }
    }
}

/// A source that passed shape admission: role, group, catalogued basename,
/// family, rotation, lineage and profile version all agree. `producer` is the
/// component whose records this profile is validated to read; a shape-admitted
/// source without one stays visible as coverage but can never yield a fact.
struct AdmittedSource<'a> {
    source: &'a SccmSiteCoreSource,
    group: SiteCoreGroup,
    basename: String,
    producer: Option<&'static str>,
}

/// Sources are filtered to the site-server role and the two declared site-core
/// groups *before* being collected by artifact id, so an artifact belonging to
/// another role can never shadow a site-core source. An artifact id that
/// appears more than once anywhere in the bundle is ambiguous and is dropped
/// outright rather than resolved by vector order.
fn admitted_sources<'a>(bundle: &'a SccmSiteCoreBundle) -> BTreeMap<&'a str, AdmittedSource<'a>> {
    let mut occurrences: BTreeMap<&str, usize> = BTreeMap::new();
    for source in &bundle.sources {
        *occurrences
            .entry(source.artifact.artifact_id.as_str())
            .or_default() += 1;
    }

    bundle
        .sources
        .iter()
        .filter_map(|source| {
            let group = SiteCoreGroup::from_id(&source.source_group)?;
            if source.artifact.role != SccmRole::SiteServer {
                return None;
            }
            let admitted = admit_source(source, group)?;
            let artifact_id = source.artifact.artifact_id.as_str();
            (safe_opaque_id(artifact_id) && occurrences.get(artifact_id) == Some(&1))
                .then_some((artifact_id, admitted))
        })
        .collect()
}

fn admit_source<'a>(
    source: &'a SccmSiteCoreSource,
    group: SiteCoreGroup,
) -> Option<AdmittedSource<'a>> {
    if source.artifact.configmgr_version.as_deref() != Some(SITE_CORE_PROFILE_VERSION_TOKEN) {
        return None;
    }
    let classified = classify_artifact_name(&source.artifact.display_name, SccmRole::SiteServer);
    let matches_group = classified.supported_for_diagnosis
        && classified.family == group.family()
        && group
            .logical_names()
            .iter()
            .any(|logical_name| *logical_name == classified.logical_name)
        && classified.rotation == source.artifact.rotation
        && classified.basename == source.rotation_lineage;
    matches_group.then(|| AdmittedSource {
        source,
        group,
        basename: source.artifact.display_name.clone(),
        producer: VALIDATED_PRODUCERS
            .iter()
            .find(|(logical_name, _)| *logical_name == classified.logical_name)
            .map(|(_, producer)| *producer),
    })
}

// ---------------------------------------------------------------------------
// Fact extraction
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FactOutcome {
    Succeeded,
    Failed,
    Deferred,
}

/// Declared site-core status vocabulary. Each marker fixes the phase it
/// answers for, its outcome, whether it is a terminal statement, whether it is
/// a recovery statement, and the source family entitled to record it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StatusMarker {
    phase: SccmSiteCorePhase,
    outcome: FactOutcome,
    terminal: bool,
    recovery: bool,
    group: SiteCoreGroup,
}

fn status_marker(status_id: &str) -> Option<StatusMarker> {
    let marker = match status_id {
        "SC_COMPONENT_START_OK" => StatusMarker {
            phase: SccmSiteCorePhase::ComponentStart,
            outcome: FactOutcome::Succeeded,
            terminal: false,
            recovery: false,
            group: SiteCoreGroup::Component,
        },
        "SC_COMPONENT_WORK_OK" => StatusMarker {
            phase: SccmSiteCorePhase::ComponentWork,
            outcome: FactOutcome::Succeeded,
            terminal: false,
            recovery: false,
            group: SiteCoreGroup::Component,
        },
        "SC_INBOX_ACCEPTED" => StatusMarker {
            phase: SccmSiteCorePhase::InboxOrQueue,
            outcome: FactOutcome::Succeeded,
            terminal: false,
            recovery: false,
            group: SiteCoreGroup::Component,
        },
        "SC_INBOX_BACKLOG" => StatusMarker {
            phase: SccmSiteCorePhase::InboxOrQueue,
            outcome: FactOutcome::Deferred,
            terminal: false,
            recovery: false,
            group: SiteCoreGroup::Component,
        },
        "SC_COMPONENT_TERMINAL_FAILURE" => StatusMarker {
            phase: SccmSiteCorePhase::HealthyOrTerminal,
            outcome: FactOutcome::Failed,
            terminal: true,
            recovery: false,
            group: SiteCoreGroup::Component,
        },
        "SC_STATUS_PROCESSING_OK" => StatusMarker {
            phase: SccmSiteCorePhase::StatusOrStateProcessing,
            outcome: FactOutcome::Succeeded,
            terminal: false,
            recovery: false,
            group: SiteCoreGroup::Status,
        },
        "SC_STATUS_TERMINAL_FAILURE" => StatusMarker {
            phase: SccmSiteCorePhase::HealthyOrTerminal,
            outcome: FactOutcome::Failed,
            terminal: true,
            recovery: false,
            group: SiteCoreGroup::Status,
        },
        "SC_COMPONENT_HEALTHY" => StatusMarker {
            phase: SccmSiteCorePhase::HealthyOrTerminal,
            outcome: FactOutcome::Succeeded,
            terminal: true,
            recovery: false,
            group: SiteCoreGroup::Status,
        },
        "SC_COMPONENT_RECOVERED" => StatusMarker {
            phase: SccmSiteCorePhase::HealthyOrTerminal,
            outcome: FactOutcome::Succeeded,
            terminal: true,
            recovery: true,
            group: SiteCoreGroup::Status,
        },
        _ => return None,
    };
    Some(marker)
}

#[derive(Debug, Clone)]
struct SiteCoreFact {
    key: SccmSiteCoreTransactionKey,
    marker: StatusMarker,
    reference: SccmEvidenceRef,
    timestamp: SccmTimestamp,
}

impl SiteCoreFact {
    fn ordering_millis(&self) -> Option<i64> {
        (self.timestamp.ordering_state == SccmTimeOrderingState::NormalizedUtc)
            .then_some(self.timestamp.utc_millis)
            .flatten()
    }

    fn evidence(&self) -> SccmSiteCoreEvidence {
        let (terminal, recovery) = match (self.marker.outcome, self.marker.recovery) {
            (_, true) => (Some(true), Some(true)),
            (FactOutcome::Failed, _) if self.marker.terminal => (Some(true), None),
            (FactOutcome::Deferred, _) => (Some(false), None),
            _ => (None, None),
        };
        SccmSiteCoreEvidence {
            artifact_id: self.reference.artifact_id.clone(),
            entry_id: self.reference.entry_id.clone(),
            line_start: self.reference.line_start.unwrap_or_default(),
            line_end: self.reference.line_end.unwrap_or_default(),
            terminal,
            recovery,
            complete_logical_record: None,
        }
    }
}

fn collect_facts(context: &SiteCoreContext<'_>, site_code: Option<&str>) -> Vec<SiteCoreFact> {
    let Some(site_code) = site_code else {
        return Vec::new();
    };

    context
        .bundle
        .evidence
        .iter()
        .enumerate()
        .filter_map(|(position, evidence)| {
            let admitted = context
                .sources
                .get(evidence.reference.artifact_id.as_str())?;
            if !source_carries_facts(admitted)
                || evidence.role != SccmRole::SiteServer
                || !evidence_reference_fits_source(evidence, admitted)
                || !context.evidence_identity_is_unique[position]
            {
                return None;
            }
            parse_fact(evidence, admitted, site_code)
        })
        .collect()
}

/// Bytes retained beside a manifest state that is neither `captured` nor
/// `capped` are coverage-only. A captured source that still carries an
/// incomplete region is a fragment, not a fact source.
fn source_carries_facts(admitted: &AdmittedSource<'_>) -> bool {
    if admitted.producer.is_none() {
        return false;
    }
    match admitted.source.artifact.coverage {
        SccmCoverageState::Captured => admitted.source.fragment_complete != Some(false),
        SccmCoverageState::Capped => true,
        _ => false,
    }
}

fn parse_fact(
    evidence: &SccmEvidence,
    admitted: &AdmittedSource<'_>,
    site_code: &str,
) -> Option<SiteCoreFact> {
    if evidence.component.as_deref() != admitted.producer {
        return None;
    }
    let message = evidence.message.as_str();
    if token_value(message, "profileId")? != SCCM_SITE_CORE_PROFILE_ID
        || token_value(message, "profileVersion")? != SCCM_SITE_CORE_PROFILE_VERSION.to_string()
    {
        return None;
    }
    let record_site_code = normalize_site_code(&token_value(message, "site")?)?;
    if record_site_code != site_code {
        return None;
    }

    let marker = status_marker(&token_value(message, "statusId")?)?;
    if marker.group != admitted.group {
        return None;
    }
    let declared_outcome = match token_value(message, "outcome")?.as_str() {
        "success" => FactOutcome::Succeeded,
        "failure" => FactOutcome::Failed,
        "deferred" => FactOutcome::Deferred,
        _ => return None,
    };
    let declared_terminal = match token_value(message, "terminal")?.as_str() {
        "true" => true,
        "false" => false,
        _ => return None,
    };
    if declared_outcome != marker.outcome || declared_terminal != marker.terminal {
        return None;
    }

    let component_id = validated_identifier(&token_value(message, "componentId")?)?;
    let work_item_id = validated_identifier(&token_value(message, "workItemId")?)?;

    Some(SiteCoreFact {
        key: SccmSiteCoreTransactionKey {
            profile_id: SCCM_SITE_CORE_PROFILE_ID.to_owned(),
            profile_version: SCCM_SITE_CORE_PROFILE_VERSION,
            site_code: record_site_code,
            component_id,
            work_item_id,
        },
        marker,
        reference: evidence.reference.clone(),
        timestamp: evidence.timestamp.clone(),
    })
}

fn group_facts(
    facts: Vec<SiteCoreFact>,
) -> BTreeMap<SccmSiteCoreTransactionKey, Vec<SiteCoreFact>> {
    let mut grouped: BTreeMap<SccmSiteCoreTransactionKey, Vec<SiteCoreFact>> = BTreeMap::new();
    for fact in facts {
        grouped.entry(fact.key.clone()).or_default().push(fact);
    }
    for facts in grouped.values_mut() {
        facts.sort_by(compare_facts);
    }
    grouped
}

/// Facts are ordered by usable UTC instant first so that recency decisions are
/// chronological when — and only when — chronology is comparable. Records
/// without usable ordering fall back to their stable evidence identity so the
/// result never depends on input order.
fn compare_facts(left: &SiteCoreFact, right: &SiteCoreFact) -> Ordering {
    left.ordering_millis()
        .cmp(&right.ordering_millis())
        .then_with(|| compare_references(&left.reference, &right.reference))
}

// ---------------------------------------------------------------------------
// Transaction reduction
// ---------------------------------------------------------------------------

struct ReducedTransaction {
    result: SccmSiteCoreResult,
    finding: Option<SccmSiteCoreFinding>,
}

fn reduce_transaction(
    context: &SiteCoreContext<'_>,
    coverage: &CoverageView<'_>,
    key: SccmSiteCoreTransactionKey,
    facts: &[SiteCoreFact],
) -> ReducedTransaction {
    let coverage_gap_artifact_ids = coverage.transaction_gap_ids.as_slice();
    let chronology_usable = facts.iter().all(|fact| fact.ordering_millis().is_some());
    let conflicting = has_same_instant_conflict(facts);

    let last_success = facts
        .iter()
        .rfind(|fact| fact.marker.outcome == FactOutcome::Succeeded);
    let last_successful_phase = last_success.map(|fact| fact.marker.phase);
    let terminal_failure = facts
        .iter()
        .rfind(|fact| fact.marker.outcome == FactOutcome::Failed && fact.marker.terminal);
    let terminal_success = facts
        .iter()
        .rfind(|fact| fact.marker.outcome == FactOutcome::Succeeded && fact.marker.terminal);
    let deferred = facts
        .iter()
        .rfind(|fact| fact.marker.outcome == FactOutcome::Deferred);

    let recovered = matches!(
        (terminal_success, terminal_failure),
        (Some(success), Some(failure))
            if chronology_usable
                && success.ordering_millis() > failure.ordering_millis()
    );

    let (state, candidate_class, base_confidence, decisive) = if conflicting {
        (
            SccmSiteCoreState::Incomplete,
            Some(SccmFindingClass::InsufficientEvidence),
            SccmSiteCoreConfidence::None,
            None,
        )
    } else if recovered {
        (
            SccmSiteCoreState::Recovered,
            Some(SccmFindingClass::Symptom),
            SccmSiteCoreConfidence::High,
            terminal_success,
        )
    } else if terminal_failure.is_some() {
        (
            SccmSiteCoreState::TerminalFailure,
            Some(SccmFindingClass::ConfirmedFailure),
            SccmSiteCoreConfidence::High,
            terminal_failure,
        )
    } else if terminal_success.is_some() {
        (
            SccmSiteCoreState::Healthy,
            None,
            SccmSiteCoreConfidence::High,
            terminal_success,
        )
    } else if deferred.is_some() {
        (
            SccmSiteCoreState::BlockedOrDeferred,
            Some(SccmFindingClass::BlockedOrDeferred),
            SccmSiteCoreConfidence::Low,
            deferred,
        )
    } else {
        (
            SccmSiteCoreState::Incomplete,
            Some(SccmFindingClass::InsufficientEvidence),
            SccmSiteCoreConfidence::None,
            None,
        )
    };

    let confidence_ceiling = confidence_ceiling(facts, state, chronology_usable, conflicting);
    let confidence = base_confidence.min(confidence_ceiling);
    let next_artifacts = next_artifacts_for_state(context, &key, facts, state);

    let mut evidence = facts.iter().map(SiteCoreFact::evidence).collect::<Vec<_>>();
    evidence.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
    evidence.dedup();

    let result_id = format!(
        "site-core/{}/{}/{}",
        key.site_code, key.component_id, key.work_item_id
    );
    let finding = candidate_class.and_then(|class| {
        build_finding(
            coverage,
            TransactionFinding {
                subject_id: &result_id,
                class,
                phase: decisive
                    .map(|fact| fact.marker.phase)
                    .or(last_successful_phase)
                    .unwrap_or(SccmSiteCorePhase::ComponentStart),
                last_successful_phase,
                confidence,
                state,
                evidence: &evidence,
                decisive,
                coverage_gap_artifact_ids,
                next_artifacts: &next_artifacts,
            },
        )
    });
    // The class a consumer reads is a projection of the finding that was
    // actually emitted, never a parallel claim about one. A class the shared
    // contract refused to validate is withdrawn with its finding: the state,
    // the cited evidence and the next-artifact request still say what is known
    // and what is missing, which is the whole of what the reducer can prove.
    let finding_class = finding
        .as_ref()
        .map(|emitted| emitted.finding.class.clone());

    ReducedTransaction {
        result: SccmSiteCoreResult {
            result_id,
            transaction_key: key,
            state,
            last_successful_phase,
            finding_class,
            confidence,
            confidence_ceiling,
            evidence,
            coverage_gap_artifact_ids: coverage_gap_artifact_ids.to_vec(),
            next_artifacts,
        },
        finding,
    }
}

/// Two facts at the same instant, in the same phase, disagreeing about the
/// outcome cannot select a winner without letting vector order decide.
///
/// Facts are bucketed by the pair that has to match rather than compared
/// pairwise: a bucket is in conflict exactly when it does not agree with its
/// own first outcome, and one busy component key can hold thousands of records.
fn has_same_instant_conflict(facts: &[SiteCoreFact]) -> bool {
    let mut outcomes: BTreeMap<(SccmSiteCorePhase, i64), FactOutcome> = BTreeMap::new();
    for fact in facts {
        let Some(millis) = fact.ordering_millis() else {
            continue;
        };
        let first = outcomes
            .entry((fact.marker.phase, millis))
            .or_insert(fact.marker.outcome);
        if *first != fact.marker.outcome {
            return true;
        }
    }
    false
}

fn confidence_ceiling(
    facts: &[SiteCoreFact],
    state: SccmSiteCoreState,
    chronology_usable: bool,
    conflicting: bool,
) -> SccmSiteCoreConfidence {
    if conflicting || facts.is_empty() || state == SccmSiteCoreState::Incomplete {
        return SccmSiteCoreConfidence::None;
    }
    if !chronology_usable || state == SccmSiteCoreState::BlockedOrDeferred {
        return SccmSiteCoreConfidence::Low;
    }
    let has_entry_evidence = facts
        .iter()
        .any(|fact| fact.marker.phase == SccmSiteCorePhase::ComponentStart);
    if has_entry_evidence {
        SccmSiteCoreConfidence::High
    } else {
        SccmSiteCoreConfidence::Moderate
    }
}

/// The smallest next artifact bundle when evidence stops. A confirmed terminal
/// outcome and a healthy or recovered completion need nothing further.
fn next_artifacts_for_state(
    context: &SiteCoreContext<'_>,
    key: &SccmSiteCoreTransactionKey,
    facts: &[SiteCoreFact],
    state: SccmSiteCoreState,
) -> Vec<SccmSiteCoreArtifactRequest> {
    if matches!(
        state,
        SccmSiteCoreState::Healthy
            | SccmSiteCoreState::TerminalFailure
            | SccmSiteCoreState::Recovered
            | SccmSiteCoreState::ParseGap
    ) {
        return Vec::new();
    }

    let scope = SccmSiteCoreRequestScope {
        component_id: Some(key.component_id.clone()),
        work_item_id: Some(key.work_item_id.clone()),
        rotation_lineage: None,
    };

    // A capture limit that truncated the family which carried the last
    // evidence is the nearest boundary: request that one source again under a
    // larger bounded limit.
    if let Some(request) = capped_recapture_request(context, facts, &scope) {
        return vec![request];
    }

    let statuses = status_group_candidates(context);
    let basenames = if statuses.is_empty() {
        vec!["statmgr.log".to_owned()]
    } else {
        statuses
    };
    let rotations = vec!["current".to_owned(), "loUnderscore".to_owned()];
    vec![SccmSiteCoreArtifactRequest {
        logical_name: SCCM_SITE_CORE_STATUS_GROUP.to_owned(),
        role: SccmRole::SiteServer,
        reason_code: "matching-status-terminal-evidence-missing".to_owned(),
        max_artifacts: basenames.len() * rotations.len(),
        basenames,
        rotations,
        max_bytes_per_artifact: None,
        scope,
    }]
}

fn capped_recapture_request(
    context: &SiteCoreContext<'_>,
    facts: &[SiteCoreFact],
    scope: &SccmSiteCoreRequestScope,
) -> Option<SccmSiteCoreArtifactRequest> {
    let cited = facts
        .iter()
        .map(|fact| fact.reference.artifact_id.as_str())
        .collect::<BTreeSet<_>>();
    let (_, admitted) = context.sources.iter().find(|(artifact_id, admitted)| {
        cited.contains(*artifact_id)
            && admitted.source.artifact.coverage == SccmCoverageState::Capped
            && context.truncated_tails.contains_key(*artifact_id)
    })?;

    let limit = admitted.source.capture_limit_bytes.unwrap_or_default();
    let requested = RECAPTURE_FLOOR_BYTES.max(limit.saturating_mul(2).next_power_of_two());
    Some(SccmSiteCoreArtifactRequest {
        logical_name: admitted.group.id().to_owned(),
        role: SccmRole::SiteServer,
        reason_code: "capped-before-next-phase".to_owned(),
        basenames: vec![admitted.basename.clone()],
        rotations: vec![rotation_name(&admitted.source.artifact.rotation)?],
        max_artifacts: 1,
        max_bytes_per_artifact: Some(requested),
        scope: scope.clone(),
    })
}

fn status_group_candidates(context: &SiteCoreContext<'_>) -> Vec<String> {
    let mut basenames = context
        .sources
        .values()
        .filter(|admitted| admitted.group == SiteCoreGroup::Status)
        .map(|admitted| admitted.basename.clone())
        .collect::<Vec<_>>();
    basenames.sort();
    basenames.dedup();
    basenames
}

// ---------------------------------------------------------------------------
// Fragments and coverage
// ---------------------------------------------------------------------------

struct FragmentArtifact {
    group: SiteCoreGroup,
    lineage: String,
    basename: String,
    rotation: SccmRotation,
    rotation_rank: u8,
    evidence: SccmSiteCoreEvidence,
}

/// A captured source that cannot yield a complete logical record for part of
/// its physical range. The unparsed tail is cited by its physical line range;
/// the reference can never collide with a parsed record because it starts
/// after the last complete record.
///
/// The producer gate applies here for the same reason it applies to facts: an
/// unparsed region of a family this profile has no validated producer for says
/// nothing about the family's records, only that bytes were collected. Reading
/// it as a source anomaly would let an unsupported family reach a diagnosis
/// through the fragment path that the fact path denies it.
fn collect_fragments(context: &SiteCoreContext<'_>) -> Vec<FragmentArtifact> {
    let mut fragments = context
        .sources
        .values()
        .filter(|admitted| {
            admitted.producer.is_some()
                && admitted.source.artifact.coverage == SccmCoverageState::Captured
        })
        .filter_map(|admitted| {
            let tail = context.truncated_tail(&admitted.source.artifact.artifact_id)?;
            Some(FragmentArtifact {
                group: admitted.group,
                lineage: admitted.source.rotation_lineage.clone(),
                basename: admitted.basename.clone(),
                rotation: admitted.source.artifact.rotation.clone(),
                rotation_rank: rotation_rank(&admitted.source.artifact.rotation),
                evidence: tail,
            })
        })
        .collect::<Vec<_>>();
    fragments.sort_by(|left, right| left.evidence.sort_key().cmp(&right.evidence.sort_key()));
    fragments
}

/// The unparsed physical tail of every admitted source, resolved in one pass
/// over the bundle. Three stages need this answer and one of them needs it per
/// transaction, so deriving it on demand would rescan the whole evidence vector
/// once per caller.
fn truncated_tails<'a>(
    bundle: &'a SccmSiteCoreBundle,
    sources: &BTreeMap<&'a str, AdmittedSource<'a>>,
) -> BTreeMap<&'a str, SccmSiteCoreEvidence> {
    let mut parsed_line_ends: BTreeMap<&str, u32> = BTreeMap::new();
    for evidence in &bundle.evidence {
        let line_end = parsed_line_ends
            .entry(evidence.reference.artifact_id.as_str())
            .or_default();
        *line_end = (*line_end).max(evidence.reference.line_end.unwrap_or_default());
    }

    sources
        .iter()
        .filter_map(|(artifact_id, admitted)| {
            let tail = truncated_tail(
                artifact_id,
                admitted.source.physical_line_end?,
                parsed_line_ends
                    .get(artifact_id)
                    .copied()
                    .unwrap_or_default(),
            )?;
            Some((*artifact_id, tail))
        })
        .collect()
}

fn truncated_tail(
    artifact_id: &str,
    physical_line_end: u32,
    parsed_line_end: u32,
) -> Option<SccmSiteCoreEvidence> {
    let tail_start = parsed_line_end.checked_add(1)?;
    if tail_start > physical_line_end {
        return None;
    }
    Some(SccmSiteCoreEvidence {
        artifact_id: artifact_id.to_owned(),
        entry_id: format!("{artifact_id}:{tail_start}-{physical_line_end}"),
        line_start: tail_start,
        line_end: physical_line_end,
        terminal: None,
        recovery: None,
        complete_logical_record: Some(false),
    })
}

fn collect_coverage_gaps(
    context: &SiteCoreContext<'_>,
    fragments: &[FragmentArtifact],
) -> Vec<SccmSiteCoreCoverageGap> {
    let fragment_by_artifact = fragments
        .iter()
        .map(|fragment| {
            (
                fragment.evidence.artifact_id.as_str(),
                fragment.evidence.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();

    let mut gaps: BTreeMap<String, SccmSiteCoreCoverageGap> = BTreeMap::new();
    for source in &context.bundle.sources {
        if SiteCoreGroup::from_id(&source.source_group).is_none()
            || source.artifact.role != SccmRole::SiteServer
        {
            continue;
        }
        let artifact_id = source.artifact.artifact_id.as_str();
        let admitted = context.sources.get(artifact_id);
        let (state, evidence) = match (admitted, &source.artifact.coverage) {
            // A declared source family this profile has no validated producer
            // for. Its bytes are coverage, never a component outcome.
            (Some(admitted), SccmCoverageState::Captured | SccmCoverageState::Capped)
                if admitted.producer.is_none() =>
            {
                (SccmCoverageState::Unsupported, None)
            }
            // An interpretable source that produced no complete record for
            // part of its range. The unparsed tail is cited where there is one,
            // but a source the manifest already declares incomplete is a gap
            // whether or not the incompleteness left a tail behind: the same
            // flag withholds its facts in `source_carries_facts`.
            (Some(_), SccmCoverageState::Captured) => {
                match (
                    fragment_by_artifact.get(artifact_id),
                    source.fragment_complete,
                ) {
                    (Some(evidence), _) => (SccmCoverageState::ParseFailed, Some(evidence.clone())),
                    (None, Some(false)) => (SccmCoverageState::ParseFailed, None),
                    (None, _) => continue,
                }
            }
            (Some(_), SccmCoverageState::Capped) => (
                SccmCoverageState::Capped,
                context.truncated_tail(artifact_id),
            ),
            (Some(_), state) => (state.clone(), None),
            // A source this profile cannot interpret, or whose identity is
            // ambiguous, is coverage-only and never a diagnosis.
            (None, _) => (SccmCoverageState::Unsupported, None),
        };
        if state == SccmCoverageState::Captured {
            continue;
        }
        gaps.entry(artifact_id.to_owned())
            .or_insert(SccmSiteCoreCoverageGap {
                artifact_id: artifact_id.to_owned(),
                state,
                diagnostic_meaning: SccmSiteCoreDiagnosticMeaning::CoverageOnly,
                evidence,
            });
    }
    gaps.into_values().collect()
}

/// The single coverage view every downstream claim reads.
///
/// `collect_coverage_gaps` decides what each artifact's coverage state is, and
/// nothing after it re-derives that from the manifest. A finding that cited a
/// state of its own would let the analysis publish two answers for one
/// artifact, and the one inside the finding is the one a reader trusts.
struct CoverageView<'a> {
    states: BTreeMap<&'a str, SccmCoverageState>,
    /// Gaps a transaction cites. A fragment artifact is excluded because its
    /// unparsed region is already carried by its own source-local observation.
    transaction_gap_ids: Vec<String>,
}

impl<'a> CoverageView<'a> {
    fn new(gaps: &'a [SccmSiteCoreCoverageGap], fragments: &[FragmentArtifact]) -> Self {
        let fragment_artifact_ids = fragments
            .iter()
            .map(|fragment| fragment.evidence.artifact_id.as_str())
            .collect::<BTreeSet<_>>();
        Self {
            states: gaps
                .iter()
                .map(|gap| (gap.artifact_id.as_str(), gap.state.clone()))
                .collect(),
            transaction_gap_ids: gaps
                .iter()
                .map(|gap| gap.artifact_id.clone())
                .filter(|artifact_id| !fragment_artifact_ids.contains(artifact_id.as_str()))
                .collect(),
        }
    }

    /// Project one published gap onto the shared finding contract. An artifact
    /// with no published gap has nothing to cite, so it contributes nothing.
    fn finding_gap(&self, artifact_id: &str) -> Option<SccmFindingCoverageGap> {
        Some(SccmFindingCoverageGap {
            artifact_id: artifact_id.to_owned(),
            role: SccmRole::SiteServer,
            coverage: self.states.get(artifact_id)?.clone(),
        })
    }

    fn finding_gaps<'b>(
        &self,
        artifact_ids: impl IntoIterator<Item = &'b String>,
    ) -> Vec<SccmFindingCoverageGap> {
        artifact_ids
            .into_iter()
            .filter_map(|artifact_id| self.finding_gap(artifact_id))
            .collect()
    }
}

/// Fragment observations are source-local: they never advance a phase, join a
/// record across a rotation boundary, or infer a terminal outcome.
///
/// A lineage whose fragments span more than one rotation lost its records to a
/// rollover, which is a pure coverage loss and can only be insufficient
/// evidence. A single-rotation fragment is an anomaly in the source itself, so
/// it is reported as a low-confidence symptom and never as a fact.
fn append_fragment_observations(
    fragments: &[FragmentArtifact],
    coverage: &CoverageView<'_>,
    observations: &mut Vec<SccmSiteCoreObservation>,
    findings: &mut Vec<SccmSiteCoreFinding>,
) {
    let mut by_lineage: BTreeMap<(SiteCoreGroup, &str), Vec<&FragmentArtifact>> = BTreeMap::new();
    for fragment in fragments {
        by_lineage
            .entry((fragment.group, fragment.lineage.as_str()))
            .or_default()
            .push(fragment);
    }

    let mut rotation_boundary: Vec<&FragmentArtifact> = Vec::new();
    let mut rotation_boundary_requests = Vec::new();
    let mut malformed: BTreeMap<SiteCoreGroup, (Vec<&FragmentArtifact>, Vec<_>)> = BTreeMap::new();

    for ((group, lineage), lineage_fragments) in by_lineage {
        let spans_rotations = lineage_fragments
            .iter()
            .map(|fragment| fragment.rotation_rank)
            .collect::<BTreeSet<_>>()
            .len()
            > 1;
        let request = fragment_request(group, lineage, &lineage_fragments, spans_rotations);
        if spans_rotations {
            rotation_boundary.extend(lineage_fragments);
            rotation_boundary_requests.push(request);
        } else {
            let entry = malformed.entry(group).or_default();
            entry.0.extend(lineage_fragments);
            entry.1.push(request);
        }
    }

    if !rotation_boundary.is_empty() {
        if let Some((observation, finding)) = build_observation(
            "rotation-boundary-fragments",
            SiteCoreGroup::Component,
            SccmFindingClass::InsufficientEvidence,
            SccmSiteCoreConfidence::None,
            rotation_boundary,
            rotation_boundary_requests,
            coverage,
        ) {
            observations.push(observation);
            findings.push(finding);
        }
    }
    for (group, (group_fragments, requests)) in malformed {
        if let Some((observation, finding)) = build_observation(
            &format!("malformed-{}-record", group.slug()),
            group,
            SccmFindingClass::Symptom,
            SccmSiteCoreConfidence::Low,
            group_fragments,
            requests,
            coverage,
        ) {
            observations.push(observation);
            findings.push(finding);
        }
    }
}

/// An observation always names a finding class, so it is published only
/// together with the finding that carries it. If the shared contract refuses
/// the finding, the fragment is still reported as a coverage gap by
/// `collect_coverage_gaps`; what is withheld is the classification, not the
/// artifact.
fn build_observation(
    observation_id: &str,
    group: SiteCoreGroup,
    class: SccmFindingClass,
    confidence: SccmSiteCoreConfidence,
    fragments: Vec<&FragmentArtifact>,
    mut next_artifacts: Vec<SccmSiteCoreArtifactRequest>,
    coverage: &CoverageView<'_>,
) -> Option<(SccmSiteCoreObservation, SccmSiteCoreFinding)> {
    let mut evidence = fragments
        .iter()
        .map(|fragment| fragment.evidence.clone())
        .collect::<Vec<_>>();
    evidence.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
    evidence.dedup();
    let mut coverage_gap_artifact_ids = evidence
        .iter()
        .map(|item| item.artifact_id.clone())
        .collect::<Vec<_>>();
    coverage_gap_artifact_ids.sort();
    coverage_gap_artifact_ids.dedup();
    next_artifacts.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
    next_artifacts.dedup();

    let gaps = coverage.finding_gaps(&coverage_gap_artifact_ids);
    let finding = build_observation_finding(
        observation_id,
        class.clone(),
        group.entry_phase(),
        confidence,
        &evidence,
        gaps,
        &next_artifacts,
    )?;

    let observation = SccmSiteCoreObservation {
        observation_id: observation_id.to_owned(),
        state: SccmSiteCoreState::ParseGap,
        last_successful_phase: None,
        finding_class: finding.finding.class.clone(),
        confidence,
        confidence_ceiling: confidence,
        evidence,
        coverage_gap_artifact_ids,
        next_artifacts,
    };
    Some((observation, finding))
}

fn fragment_request(
    group: SiteCoreGroup,
    lineage: &str,
    fragments: &[&FragmentArtifact],
    rotation_boundary: bool,
) -> SccmSiteCoreArtifactRequest {
    let mut ordered = fragments.to_vec();
    ordered.sort_by(|left, right| {
        left.rotation_rank
            .cmp(&right.rotation_rank)
            .then_with(|| left.basename.cmp(&right.basename))
    });
    let mut basenames = Vec::new();
    let mut rotations = Vec::new();
    let mut pairs = BTreeSet::new();
    for fragment in &ordered {
        let Some(rotation) = rotation_name(&fragment.rotation) else {
            continue;
        };
        if !pairs.insert((fragment.basename.clone(), rotation.clone())) {
            continue;
        }
        if !basenames.contains(&fragment.basename) {
            basenames.push(fragment.basename.clone());
        }
        if !rotations.contains(&rotation) {
            rotations.push(rotation);
        }
    }

    SccmSiteCoreArtifactRequest {
        logical_name: group.id().to_owned(),
        role: SccmRole::SiteServer,
        reason_code: if rotation_boundary {
            "complete-logical-record-required".to_owned()
        } else {
            format!("complete-{}-record-required", group.slug())
        },
        basenames,
        rotations,
        max_artifacts: pairs.len(),
        max_bytes_per_artifact: None,
        scope: SccmSiteCoreRequestScope {
            component_id: None,
            work_item_id: None,
            rotation_lineage: Some(lineage.to_owned()),
        },
    }
}

// ---------------------------------------------------------------------------
// Shared findings
// ---------------------------------------------------------------------------

/// Everything a transaction finding cites. Grouping the inputs keeps the
/// finding a projection of one reduced transaction rather than a loose
/// argument list that could drift out of step with it.
struct TransactionFinding<'a> {
    subject_id: &'a str,
    class: SccmFindingClass,
    phase: SccmSiteCorePhase,
    last_successful_phase: Option<SccmSiteCorePhase>,
    confidence: SccmSiteCoreConfidence,
    state: SccmSiteCoreState,
    evidence: &'a [SccmSiteCoreEvidence],
    decisive: Option<&'a SiteCoreFact>,
    coverage_gap_artifact_ids: &'a [String],
    next_artifacts: &'a [SccmSiteCoreArtifactRequest],
}

fn build_finding(
    coverage: &CoverageView<'_>,
    subject: TransactionFinding<'_>,
) -> Option<SccmSiteCoreFinding> {
    let cited = subject
        .evidence
        .iter()
        .map(SccmSiteCoreEvidence::reference)
        .collect::<Vec<_>>();
    let terminal_evidence = match (&subject.class, subject.decisive) {
        (SccmFindingClass::ConfirmedFailure, Some(fact)) => {
            vec![SccmTerminalEvidence::observed_failure(
                fact.reference.clone(),
            )]
        }
        _ => Vec::new(),
    };
    let gaps = coverage.finding_gaps(subject.coverage_gap_artifact_ids);
    let summary = match subject.last_successful_phase {
        Some(phase) => format!(
            "The last confirmed successful phase is {}; later phases are bounded to cited evidence.",
            phase.serialized_name()
        ),
        None => "No site component phase is confirmed by the cited evidence.".to_owned(),
    };

    let finding = SccmFindingBuilder::new(format!("finding:site-core:{}", subject.subject_id))
        .class(subject.class)
        .phase(SccmPhase::Unknown(
            subject.phase.serialized_name().to_owned(),
        ))
        .role(SccmRole::SiteServer)
        .severity(match subject.state {
            SccmSiteCoreState::TerminalFailure => Severity::Error,
            _ => Severity::Warning,
        })
        .confidence(shared_confidence(subject.confidence))
        .title("Site component and status evidence")
        .summary(summary)
        .evidence(cited)
        .terminal_evidence(terminal_evidence)
        .coverage_gaps(gaps)
        .next_artifacts(shared_requests(subject.next_artifacts))
        .build()
        .ok()?;

    Some(SccmSiteCoreFinding {
        finding,
        subject_id: subject.subject_id.to_owned(),
        last_successful_phase: subject.last_successful_phase,
    })
}

fn build_observation_finding(
    subject_id: &str,
    class: SccmFindingClass,
    phase: SccmSiteCorePhase,
    confidence: SccmSiteCoreConfidence,
    evidence: &[SccmSiteCoreEvidence],
    gaps: Vec<SccmFindingCoverageGap>,
    next_artifacts: &[SccmSiteCoreArtifactRequest],
) -> Option<SccmSiteCoreFinding> {
    let finding = SccmFindingBuilder::new(format!("finding:site-core:{subject_id}"))
        .class(class)
        .phase(SccmPhase::Unknown(phase.serialized_name().to_owned()))
        .role(SccmRole::SiteServer)
        .severity(Severity::Warning)
        .confidence(shared_confidence(confidence))
        .title("Site core source-local evidence")
        .summary("The observation is source-local and cannot establish a component outcome.")
        .evidence(
            evidence
                .iter()
                .map(SccmSiteCoreEvidence::reference)
                .collect(),
        )
        .coverage_gaps(gaps)
        .next_artifacts(shared_requests(next_artifacts))
        .build()
        .ok()?;
    Some(SccmSiteCoreFinding {
        finding,
        subject_id: subject_id.to_owned(),
        last_successful_phase: None,
    })
}

fn shared_confidence(confidence: SccmSiteCoreConfidence) -> SccmConfidence {
    match confidence {
        SccmSiteCoreConfidence::None => SccmConfidence::None,
        SccmSiteCoreConfidence::Low => SccmConfidence::Low,
        SccmSiteCoreConfidence::Moderate => SccmConfidence::Moderate,
        SccmSiteCoreConfidence::High => SccmConfidence::High,
    }
}

/// Project the bounded site-core request onto the shared catalogued request
/// contract. Each requested basename becomes one catalogued logical source, so
/// the shared reason can never widen beyond the artifact it names.
fn shared_requests(requests: &[SccmSiteCoreArtifactRequest]) -> Vec<SccmArtifactRequest> {
    let mut shared = requests
        .iter()
        .flat_map(|request| request.basenames.iter())
        .filter_map(|basename| {
            let classified = classify_artifact_name(basename, SccmRole::SiteServer);
            classified
                .supported_for_diagnosis
                .then(|| SccmArtifactRequest {
                    logical_id: classified.logical_name.clone(),
                    role: SccmRole::SiteServer,
                    reason: format!("Collect the complete {} file.", classified.basename),
                })
        })
        .collect::<Vec<_>>();
    shared.sort_by(|left, right| left.logical_id.cmp(&right.logical_id));
    shared.dedup();
    shared
}

fn collect_artifact_requests(
    results: &[SccmSiteCoreResult],
    observations: &[SccmSiteCoreObservation],
) -> Vec<SccmSiteCoreArtifactRequest> {
    let mut requests = results
        .iter()
        .flat_map(|result| result.next_artifacts.iter())
        .chain(
            observations
                .iter()
                .flat_map(|observation| observation.next_artifacts.iter()),
        )
        .cloned()
        .collect::<Vec<_>>();
    requests.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
    requests.dedup();
    requests
}

// ---------------------------------------------------------------------------
// Exact-token extraction and identity guards
// ---------------------------------------------------------------------------

/// Exact-token extraction that fails closed. A label preceded by anything other
/// than a token boundary is an embedded label, and a label that appears twice
/// is ambiguous; both yield no value rather than a guess.
fn validated_token_value(message: &str, label: &str) -> Option<Option<String>> {
    let lowercase = message.to_ascii_lowercase();
    let needle = format!("{}=", label.to_ascii_lowercase());
    let mut value = None;
    for (label_start, _) in lowercase.match_indices(&needle) {
        let exact_label_boundary = label_start == 0
            || message[..label_start]
                .chars()
                .next_back()
                .is_some_and(is_token_boundary);
        if !exact_label_boundary {
            return None;
        }
        let remainder = &message[label_start + needle.len()..];
        let end = remainder.find(is_token_boundary).unwrap_or(remainder.len());
        if end == 0 {
            return None;
        }
        if value.replace(remainder[..end].to_owned()).is_some() {
            return None;
        }
    }
    Some(value)
}

fn token_value(message: &str, label: &str) -> Option<String> {
    validated_token_value(message, label)?
}

fn is_token_boundary(character: char) -> bool {
    character.is_whitespace() || matches!(character, ',' | ';' | '&')
}

fn validated_identifier(value: &str) -> Option<String> {
    (!value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')))
    .then(|| value.to_owned())
}

fn normalize_site_code(value: &str) -> Option<String> {
    (value.len() == 3
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit()))
    .then(|| value.to_owned())
}

fn safe_opaque_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

fn evidence_reference_fits_source(evidence: &SccmEvidence, admitted: &AdmittedSource<'_>) -> bool {
    let reference = &evidence.reference;
    safe_opaque_id(&reference.artifact_id)
        && safe_opaque_id(&reference.entry_id)
        && evidence.evidence_id == reference.entry_id
        && matches!(
            (reference.line_start, reference.line_end),
            (Some(start), Some(end)) if start > 0 && end >= start
        )
        && admitted
            .source
            .physical_line_end
            .zip(reference.line_end)
            .is_some_and(|(physical_end, line_end)| physical_end > 0 && line_end <= physical_end)
}

/// Two evidence records that share an identity, or whose physical ranges
/// overlap within one artifact, cannot both be authoritative. Neither is
/// admitted.
///
/// The question is answered for the whole bundle at once, by position, because
/// the alternative is a rescan of every record for every record: a stock
/// ConfigMgr server log holds tens of thousands of records and none of them
/// collide, so the scan that only stops early on a collision never stops early.
/// A record is contested when it shares an evidence id or an entry id with
/// another, or when its physical range meets another range in the same
/// artifact; the three are independent, so each is decided by its own pass.
fn unique_evidence_identities(bundle: &SccmSiteCoreBundle) -> Vec<bool> {
    let mut unique = vec![true; bundle.evidence.len()];
    mark_repeated_keys(
        &mut unique,
        bundle
            .evidence
            .iter()
            .map(|evidence| evidence.evidence_id.as_str()),
    );
    mark_repeated_keys(
        &mut unique,
        bundle
            .evidence
            .iter()
            .map(|evidence| evidence.reference.entry_id.as_str()),
    );
    mark_met_ranges(&mut unique, bundle);
    unique
}

fn mark_repeated_keys<'a>(unique: &mut [bool], keys: impl Iterator<Item = &'a str>) {
    let mut positions: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (position, key) in keys.enumerate() {
        positions.entry(key).or_default().push(position);
    }
    for repeated in positions.into_values().filter(|group| group.len() > 1) {
        for position in repeated {
            unique[position] = false;
        }
    }
}

/// Two ranges meet when `left.start <= right.end` and `right.start <= left.end`.
/// Sorting one artifact's ranges by start turns the first half of that test into
/// a prefix: the candidates whose start is at or before this range's end are
/// exactly the leading run. This range meets one of them when the largest end in
/// that run, excluding this range itself, reaches this range's start, so the
/// running largest and runner-up ends answer every range in one more pass.
///
/// The runner-up is what lets a range be excluded from its own prefix, and the
/// arithmetic never assumes `start <= end`: a reference whose range is inverted
/// is decided by the same test as any other rather than being read as empty.
fn mark_met_ranges(unique: &mut [bool], bundle: &SccmSiteCoreBundle) {
    let mut by_artifact: BTreeMap<&str, Vec<(u32, u32, usize)>> = BTreeMap::new();
    for (position, evidence) in bundle.evidence.iter().enumerate() {
        let reference = &evidence.reference;
        if let (Some(start), Some(end)) = (reference.line_start, reference.line_end) {
            by_artifact
                .entry(reference.artifact_id.as_str())
                .or_default()
                .push((start, end, position));
        }
    }

    for mut ranges in by_artifact.into_values() {
        ranges.sort_unstable();
        let mut largest_ends: Vec<(u32, usize, Option<u32>)> = Vec::with_capacity(ranges.len());
        let mut largest: Option<(u32, usize)> = None;
        let mut runner_up: Option<u32> = None;
        for (index, &(_, end, _)) in ranges.iter().enumerate() {
            match largest {
                Some((current, _)) if end > current => {
                    runner_up = Some(current);
                    largest = Some((end, index));
                }
                Some(_) => {
                    if runner_up.is_none_or(|value| end > value) {
                        runner_up = Some(end);
                    }
                }
                None => largest = Some((end, index)),
            }
            let (end, holder) = largest.expect("a largest end exists after the first range");
            largest_ends.push((end, holder, runner_up));
        }

        for (index, &(start, end, position)) in ranges.iter().enumerate() {
            let reachable = ranges.partition_point(|(candidate, _, _)| *candidate <= end);
            if reachable == 0 {
                continue;
            }
            let (largest_end, holder, runner_up) = largest_ends[reachable - 1];
            let contender = if holder == index {
                runner_up
            } else {
                Some(largest_end)
            };
            if contender.is_some_and(|candidate_end| candidate_end >= start) {
                unique[position] = false;
            }
        }
    }
}

fn compare_references(left: &SccmEvidenceRef, right: &SccmEvidenceRef) -> Ordering {
    left.artifact_id
        .cmp(&right.artifact_id)
        .then_with(|| left.line_start.cmp(&right.line_start))
        .then_with(|| left.line_end.cmp(&right.line_end))
        .then_with(|| left.entry_id.cmp(&right.entry_id))
}

fn rotation_name(rotation: &SccmRotation) -> Option<String> {
    Some(match rotation {
        SccmRotation::Current => "current".to_owned(),
        SccmRotation::LoUnderscore => "loUnderscore".to_owned(),
        SccmRotation::Numbered(value) => format!("numbered-{value}"),
        SccmRotation::Timestamped(value) => format!("timestamped-{value}"),
        SccmRotation::Unknown(_) => return None,
    })
}

fn rotation_rank(rotation: &SccmRotation) -> u8 {
    match rotation {
        SccmRotation::Current => 0,
        SccmRotation::LoUnderscore => 1,
        SccmRotation::Numbered(_) => 2,
        SccmRotation::Timestamped(_) => 3,
        SccmRotation::Unknown(_) => 4,
    }
}

fn role_sort_key(role: &SccmRole) -> &str {
    match role {
        SccmRole::Client => "client",
        SccmRole::SiteServer => "siteServer",
        SccmRole::ManagementPoint => "managementPoint",
        SccmRole::DistributionPoint => "distributionPoint",
        SccmRole::SoftwareUpdatePoint => "softwareUpdatePoint",
        SccmRole::WsUs => "wsUs",
        SccmRole::Provider => "provider",
        SccmRole::AdminService => "adminService",
        SccmRole::Unknown(value) => value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two references meet when they name the same artifact and their physical
    /// ranges intersect. This is the definition `mark_met_ranges` answers by
    /// sorting rather than by comparing every pair, so it is stated once here
    /// and the pre-pass is held to it.
    fn references_overlap(left: &SccmEvidenceRef, right: &SccmEvidenceRef) -> bool {
        if left.artifact_id != right.artifact_id {
            return false;
        }
        matches!(
            (
                left.line_start,
                left.line_end,
                right.line_start,
                right.line_end,
            ),
            (Some(left_start), Some(left_end), Some(right_start), Some(right_end))
                if left_start <= right_end && right_start <= left_end
        )
    }

    /// The pairwise definition of contested identity, kept as the reference the
    /// bundle-wide pre-pass has to reproduce exactly.
    fn identity_is_unique_pairwise(bundle: &SccmSiteCoreBundle, evidence: &SccmEvidence) -> bool {
        bundle
            .evidence
            .iter()
            .filter(|candidate| {
                candidate.evidence_id == evidence.evidence_id
                    || candidate.reference.entry_id == evidence.reference.entry_id
                    || references_overlap(&candidate.reference, &evidence.reference)
            })
            .take(2)
            .count()
            == 1
    }

    fn evidence(
        evidence_id: &str,
        artifact_id: &str,
        entry_id: &str,
        line_start: Option<u32>,
        line_end: Option<u32>,
    ) -> SccmEvidence {
        SccmEvidence {
            evidence_id: evidence_id.to_owned(),
            reference: SccmEvidenceRef {
                artifact_id: artifact_id.to_owned(),
                entry_id: entry_id.to_owned(),
                line_start,
                line_end,
            },
            role: SccmRole::SiteServer,
            component: Some("SMS_SITE_COMPONENT_MANAGER".to_owned()),
            ccm_source_file: None,
            message: String::new(),
            timestamp: SccmTimestamp {
                original_display: None,
                offset_minutes: None,
                utc_millis: None,
                ordering_state: SccmTimeOrderingState::OffsetMissing,
            },
            execution_context: None,
        }
    }

    fn bundle_of(evidence: Vec<SccmEvidence>) -> SccmSiteCoreBundle {
        SccmSiteCoreBundle {
            topology: SccmSiteCoreTopology {
                site_code: "LAB".to_owned(),
            },
            sources: Vec::new(),
            evidence,
        }
    }

    /// Every shape the pre-pass has to agree with the pairwise reference on:
    /// clean records, a repeated evidence id, a shared entry id under distinct
    /// evidence ids, touching and nested ranges, equal ranges in *different*
    /// artifacts (which never meet), a missing bound, and an inverted range,
    /// which meets a range that spans it but not one that does not.
    #[test]
    fn the_identity_pre_pass_reproduces_the_pairwise_definition() {
        let bundle = bundle_of(vec![
            evidence("a1", "art-a", "a1", Some(1), Some(2)),
            evidence("a2", "art-a", "a2", Some(3), Some(4)),
            evidence("a3", "art-a", "a3", Some(4), Some(9)),
            evidence("a4", "art-a", "a4", Some(20), Some(40)),
            evidence("a5", "art-a", "a5", Some(25), Some(30)),
            evidence("a6", "art-a", "a6", Some(60), Some(60)),
            evidence("a6", "art-a", "a7", Some(70), Some(70)),
            evidence("a8", "art-a", "shared", Some(80), Some(80)),
            evidence("a9", "art-a", "shared", Some(90), Some(90)),
            evidence("a10", "art-a", "a10", None, Some(100)),
            evidence("a11", "art-a", "a11", Some(110), None),
            evidence("a12", "art-a", "a12", Some(500), Some(400)),
            evidence("a13", "art-a", "a13", Some(300), Some(600)),
            evidence("a14", "art-a", "a14", Some(1000), Some(900)),
            evidence("b1", "art-b", "b1", Some(1), Some(2)),
            evidence("b2", "art-b", "b2", Some(3), Some(4)),
        ]);

        let expected = bundle
            .evidence
            .iter()
            .map(|record| identity_is_unique_pairwise(&bundle, record))
            .collect::<Vec<_>>();
        assert_eq!(unique_evidence_identities(&bundle), expected);
        // The reference itself has to be discriminating, or agreeing with it
        // would prove nothing.
        assert!(expected.iter().any(|unique| *unique));
        assert!(expected.iter().any(|unique| !*unique));
    }

    #[test]
    fn the_identity_pre_pass_agrees_on_a_bundle_with_no_collisions() {
        let bundle = bundle_of(
            (0..64u32)
                .map(|index| {
                    let line = index * 2 + 1;
                    evidence(
                        &format!("clean-{index}"),
                        "art-a",
                        &format!("clean-{index}"),
                        Some(line),
                        Some(line),
                    )
                })
                .collect(),
        );

        let expected = bundle
            .evidence
            .iter()
            .map(|record| identity_is_unique_pairwise(&bundle, record))
            .collect::<Vec<_>>();
        assert!(expected.iter().all(|unique| *unique));
        assert_eq!(unique_evidence_identities(&bundle), expected);
    }
}
