//! Role-local SCCM site-core and status analysis.
//!
//! This reducer consumes only the normalized server-intake assessment. It does
//! not reconstruct manifest state, inspect files, infer an installed role from
//! a default path, or correlate a client with a server by time.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::models::log_entry::Severity;
use crate::sccm::{
    classify_artifact_name, SccmArtifactFamily, SccmArtifactRequest, SccmConfidence,
    SccmCoverageState, SccmEvidence, SccmEvidenceRef, SccmFinding, SccmFindingBuilder,
    SccmFindingClass, SccmFindingCoverageGap, SccmPhase, SccmRole, SccmTerminalEvidence,
    SccmTimeOrderingState, SccmTimestamp,
};

use super::{
    SccmServerArtifactAssessment, SccmServerConfiguredPathState, SccmServerIntakeAssessment,
};

pub const SCCM_SITE_CORE_ANALYSIS_SCHEMA_VERSION: u32 = 1;
pub const SCCM_SITE_CORE_PROFILE_ID: &str = "sccm-site-core";
pub const SCCM_SITE_CORE_PROFILE_VERSION: u32 = 1;
pub const SCCM_SITE_CORE_PROFILE_STABILITY: &str = "experimental";
pub const SCCM_SITE_CORE_COMPONENT_GROUP: &str = "server-sitecomp";
pub const SCCM_SITE_CORE_STATUS_GROUP: &str = "server-status";

const SITE_CORE_PROFILE_VERSION_TOKEN: &str = "5.00.TEST";
const RECAPTURE_FLOOR_BYTES: u64 = 4096;

const STATE_CHAIN: [SccmSiteCorePhase; 5] = [
    SccmSiteCorePhase::ComponentStart,
    SccmSiteCorePhase::ComponentWork,
    SccmSiteCorePhase::InboxOrQueue,
    SccmSiteCorePhase::StatusOrStateProcessing,
    SccmSiteCorePhase::HealthyOrTerminal,
];

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
    Contradictory,
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

#[derive(Debug, Clone, PartialEq, Serialize)]
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
    pub site_handle: String,
    pub producer_host_handle: String,
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
    pub producer_host_handle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub component_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub work_item_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotation_lineage_handle: Option<String>,
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
    pub finding_class: SccmFindingClass,
    pub confidence: SccmSiteCoreConfidence,
    pub coverage_gap_artifact_ids: Vec<String>,
    pub next_artifacts: Vec<SccmSiteCoreArtifactRequest>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmSiteCoreCoverageGap {
    pub artifact_id: String,
    pub source_id: String,
    pub state: SccmCoverageState,
    pub diagnostic_meaning: SccmSiteCoreDiagnosticMeaning,
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
    pub cross_side_correlation_performed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SiteCoreGroup {
    Component,
    Status,
}

impl SiteCoreGroup {
    fn source_id(self) -> &'static str {
        match self {
            Self::Component => SCCM_SITE_CORE_COMPONENT_GROUP,
            Self::Status => SCCM_SITE_CORE_STATUS_GROUP,
        }
    }

    fn family(self) -> SccmArtifactFamily {
        match self {
            Self::Component => SccmArtifactFamily::SiteComponent,
            Self::Status => SccmArtifactFamily::SiteStatus,
        }
    }

    fn expected_component(self) -> &'static str {
        match self {
            Self::Component => "SMS_SITE_COMPONENT_MANAGER",
            Self::Status => "SMS_STATUS_MANAGER",
        }
    }

    fn from_source_id(value: &str) -> Option<Self> {
        match value {
            SCCM_SITE_CORE_COMPONENT_GROUP => Some(Self::Component),
            SCCM_SITE_CORE_STATUS_GROUP => Some(Self::Status),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
struct AdmittedSource<'a> {
    artifact: &'a SccmServerArtifactAssessment,
    group: SiteCoreGroup,
    fact_eligible: bool,
}

struct SiteCoreContext<'a> {
    sources: BTreeMap<&'a str, AdmittedSource<'a>>,
    evidence_identity_is_unique: Vec<bool>,
    coverage_gaps: Vec<SccmSiteCoreCoverageGap>,
}

impl<'a> SiteCoreContext<'a> {
    fn new(intake: &'a SccmServerIntakeAssessment) -> Self {
        let sources = admitted_sources(intake);
        let coverage_gaps = collect_coverage_gaps(intake, &sources);
        Self {
            sources,
            evidence_identity_is_unique: unique_evidence_identities(&intake.evidence),
            coverage_gaps,
        }
    }
}

pub fn analyze_site_core(intake: &SccmServerIntakeAssessment) -> SccmSiteCoreAnalysis {
    let context = SiteCoreContext::new(intake);
    let mut grouped = BTreeMap::<SccmSiteCoreTransactionKey, Vec<SiteCoreFact>>::new();
    for (position, evidence) in intake.evidence.iter().enumerate() {
        let Some(source) = context.sources.get(evidence.reference.artifact_id.as_str()) else {
            continue;
        };
        if !source.fact_eligible
            || evidence.role != SccmRole::SiteServer
            || !context.evidence_identity_is_unique[position]
            || !reference_is_complete(evidence)
        {
            continue;
        }
        if let Some(fact) = parse_fact(evidence, source, &intake.topology.site_handle) {
            grouped.entry(fact.key.clone()).or_default().push(fact);
        }
    }

    let mut results = Vec::new();
    let mut findings = Vec::new();
    for (key, mut facts) in grouped {
        facts.sort_by(compare_facts);
        let gap_ids = coverage_gap_ids_for_key(&context, &key);
        let mut reduced = reduce_transaction(key, &facts, &context, &gap_ids);
        if let Some(class) = reduced.finding_class.clone() {
            if let Some(finding) = build_result_finding(&reduced, class, &facts, &context) {
                findings.push(finding);
            } else {
                reduced.finding_class = None;
            }
        }
        results.push(reduced);
    }

    results.sort_by(|left, right| left.result_id.cmp(&right.result_id));
    findings.sort_by(|left, right| {
        left.subject_id
            .cmp(&right.subject_id)
            .then_with(|| left.finding.finding_id.cmp(&right.finding.finding_id))
    });

    let mut unlinked_observations = coverage_observations(&context.coverage_gaps, &context);
    unlinked_observations.sort_by(|left, right| left.observation_id.cmp(&right.observation_id));
    for observation in &unlinked_observations {
        if let Some(finding) = build_observation_finding(observation, &context) {
            findings.push(finding);
        }
    }
    findings.sort_by(|left, right| {
        left.subject_id
            .cmp(&right.subject_id)
            .then_with(|| left.finding.finding_id.cmp(&right.finding.finding_id))
    });

    let mut artifact_requests = results
        .iter()
        .flat_map(|result| result.next_artifacts.iter())
        .chain(
            unlinked_observations
                .iter()
                .flat_map(|observation| observation.next_artifacts.iter()),
        )
        .cloned()
        .collect::<Vec<_>>();
    artifact_requests.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
    artifact_requests.dedup();

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
        coverage_gaps: context.coverage_gaps,
        findings,
        artifact_requests,
        cross_side_correlation_performed: false,
    }
}

fn admitted_sources<'a>(
    intake: &'a SccmServerIntakeAssessment,
) -> BTreeMap<&'a str, AdmittedSource<'a>> {
    let mut occurrences = BTreeMap::<&str, usize>::new();
    for artifact in &intake.artifacts {
        *occurrences
            .entry(artifact.artifact_id.as_str())
            .or_default() += 1;
    }

    intake
        .artifacts
        .iter()
        .filter_map(|artifact| {
            let group = SiteCoreGroup::from_source_id(&artifact.source_id)?;
            if artifact.producer_role != SccmRole::SiteServer
                || artifact.workflow_subject_role.is_some()
                || occurrences.get(artifact.artifact_id.as_str()) != Some(&1)
            {
                return None;
            }
            let shape_valid = source_shape_is_valid(artifact, group);
            Some((
                artifact.artifact_id.as_str(),
                AdmittedSource {
                    artifact,
                    group,
                    fact_eligible: shape_valid && source_carries_facts(artifact),
                },
            ))
        })
        .collect()
}

fn source_shape_is_valid(artifact: &SccmServerArtifactAssessment, group: SiteCoreGroup) -> bool {
    let Some(basename) = artifact.original_basename.as_deref() else {
        return false;
    };
    let classified = classify_artifact_name(basename, SccmRole::SiteServer);
    let validated_logical_source = match group {
        SiteCoreGroup::Component => classified.logical_name == "sitecomp",
        SiteCoreGroup::Status => classified.logical_name == "statmgr",
    };
    validated_logical_source
        && artifact.source_id == group.source_id()
        && artifact.family == group.family()
        && artifact.rotation.is_some()
        && classified.supported_for_diagnosis
        && classified.family == group.family()
        && classified.role == SccmRole::SiteServer
        && artifact.parser_eligible
        && artifact
            .producer_host_handle
            .as_deref()
            .is_some_and(|host| {
                !host.is_empty()
                    && host.len() <= 256
                    && host.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'-' | b'_')
                    })
            })
}

fn source_carries_facts(artifact: &SccmServerArtifactAssessment) -> bool {
    let provenance_is_usable = artifact
        .capture_provenance
        .as_ref()
        .is_some_and(|provenance| {
            provenance.schema_version == 1
                && provenance.encoding == "utf-8"
                && !provenance.limit_applied
                && provenance.byte_limit >= artifact.bytes_copied
                && provenance.byte_limit > 0
        });
    artifact.state == SccmCoverageState::Captured
        && artifact.profile_eligible
        && artifact.source_version.as_deref() == Some(SITE_CORE_PROFILE_VERSION_TOKEN)
        && artifact.fragment_complete != Some(false)
        && artifact.truncated != Some(true)
        && artifact.bytes_copied > 0
        && artifact.relative_path.is_some()
        && artifact.content_sha256.as_deref().is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        && provenance_is_usable
}

fn coverage_gap_ids_for_key(
    context: &SiteCoreContext<'_>,
    key: &SccmSiteCoreTransactionKey,
) -> Vec<String> {
    context
        .coverage_gaps
        .iter()
        .filter(|gap| {
            context
                .sources
                .get(gap.artifact_id.as_str())
                .is_some_and(|source| {
                    source.artifact.producer_host_handle.as_deref()
                        == Some(key.producer_host_handle.as_str())
                })
        })
        .map(|gap| gap.artifact_id.clone())
        .collect()
}

fn collect_coverage_gaps(
    intake: &SccmServerIntakeAssessment,
    sources: &BTreeMap<&str, AdmittedSource<'_>>,
) -> Vec<SccmSiteCoreCoverageGap> {
    let mut gaps = Vec::new();
    for source in sources.values() {
        if source.fact_eligible || absent_default_is_superseded(source.artifact, sources) {
            continue;
        }
        let state = if source.artifact.state == SccmCoverageState::Captured {
            if source.artifact.fragment_complete == Some(false)
                || source.artifact.truncated == Some(true)
            {
                SccmCoverageState::ParseFailed
            } else {
                SccmCoverageState::Unsupported
            }
        } else {
            source.artifact.state.clone()
        };
        gaps.push(SccmSiteCoreCoverageGap {
            artifact_id: source.artifact.artifact_id.clone(),
            source_id: source.artifact.source_id.clone(),
            state,
            diagnostic_meaning: SccmSiteCoreDiagnosticMeaning::CoverageOnly,
        });
    }
    gaps.sort_by(|left, right| {
        left.artifact_id
            .cmp(&right.artifact_id)
            .then_with(|| left.source_id.cmp(&right.source_id))
            .then_with(|| coverage_sort_key(&left.state).cmp(coverage_sort_key(&right.state)))
    });
    gaps.dedup_by(|left, right| {
        left.artifact_id == right.artifact_id
            && left.source_id == right.source_id
            && left.state == right.state
    });

    // An assessment may be externally reordered, but it must not manufacture a
    // gap for an artifact that does not exist in the assessment.
    let artifact_ids = intake
        .artifacts
        .iter()
        .map(|artifact| artifact.artifact_id.as_str())
        .collect::<BTreeSet<_>>();
    gaps.retain(|gap| artifact_ids.contains(gap.artifact_id.as_str()));
    gaps
}

fn absent_default_is_superseded(
    artifact: &SccmServerArtifactAssessment,
    sources: &BTreeMap<&str, AdmittedSource<'_>>,
) -> bool {
    artifact.state == SccmCoverageState::Absent
        && artifact.configured_path_state == SccmServerConfiguredPathState::DefaultCandidate
        && sources.values().any(|candidate| {
            candidate.fact_eligible
                && candidate.artifact.artifact_id != artifact.artifact_id
                && candidate.artifact.source_id == artifact.source_id
                && candidate.artifact.producer_role == artifact.producer_role
                && candidate.artifact.producer_host_handle == artifact.producer_host_handle
                && candidate.artifact.workflow_subject_role == artifact.workflow_subject_role
                && candidate.artifact.workflow_subject_handle == artifact.workflow_subject_handle
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FactOutcome {
    Succeeded,
    Failed,
    Deferred,
}

impl FactOutcome {
    fn token(self) -> &'static str {
        match self {
            Self::Succeeded => "success",
            Self::Failed => "failure",
            Self::Deferred => "deferred",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct StatusMarker {
    phase: SccmSiteCorePhase,
    outcome: FactOutcome,
    terminal: bool,
    recovery: bool,
    group: SiteCoreGroup,
}

fn status_marker(value: &str) -> Option<StatusMarker> {
    Some(match value {
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
    })
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

    fn public_evidence(&self) -> SccmSiteCoreEvidence {
        SccmSiteCoreEvidence {
            artifact_id: self.reference.artifact_id.clone(),
            entry_id: self.reference.entry_id.clone(),
            line_start: self.reference.line_start.unwrap_or_default(),
            line_end: self.reference.line_end.unwrap_or_default(),
            terminal: match self.marker.outcome {
                FactOutcome::Failed if self.marker.terminal => Some(true),
                FactOutcome::Deferred => Some(false),
                _ if self.marker.recovery => Some(true),
                _ => None,
            },
            recovery: self.marker.recovery.then_some(true),
            complete_logical_record: None,
        }
    }
}

fn parse_fact(
    evidence: &SccmEvidence,
    source: &AdmittedSource<'_>,
    site_handle: &str,
) -> Option<SiteCoreFact> {
    if evidence.component.as_deref() != Some(source.group.expected_component()) {
        return None;
    }
    let message = evidence.message.as_str();
    if token_value(message, "profileId")? != SCCM_SITE_CORE_PROFILE_ID
        || token_value(message, "profileVersion")? != SCCM_SITE_CORE_PROFILE_VERSION.to_string()
        || site_handle != "synthetic:site:lab"
        || token_value(message, "site")? != "LAB"
    {
        return None;
    }

    let component_id = validated_identifier(&token_value(message, "componentId")?)?;
    let work_item_id = validated_identifier(&token_value(message, "workItemId")?)?;
    let marker = status_marker(&token_value(message, "statusId")?)?;
    if marker.group != source.group
        || token_value(message, "outcome")? != marker.outcome.token()
        || token_value(message, "terminal")? != if marker.terminal { "true" } else { "false" }
    {
        return None;
    }

    Some(SiteCoreFact {
        key: SccmSiteCoreTransactionKey {
            profile_id: SCCM_SITE_CORE_PROFILE_ID.to_owned(),
            profile_version: SCCM_SITE_CORE_PROFILE_VERSION,
            site_handle: site_handle.to_owned(),
            producer_host_handle: source.artifact.producer_host_handle.clone()?,
            component_id,
            work_item_id,
        },
        marker,
        reference: evidence.reference.clone(),
        timestamp: evidence.timestamp.clone(),
    })
}

fn reduce_transaction(
    key: SccmSiteCoreTransactionKey,
    facts: &[SiteCoreFact],
    context: &SiteCoreContext<'_>,
    coverage_gap_artifact_ids: &[String],
) -> SccmSiteCoreResult {
    let comparable = facts.iter().all(|fact| fact.ordering_millis().is_some());
    let contradictory = comparable && has_same_instant_conflict(facts);
    let successes = facts
        .iter()
        .filter(|fact| fact.marker.outcome == FactOutcome::Succeeded)
        .collect::<Vec<_>>();
    let last_successful_phase = facts
        .iter()
        .rev()
        .find(|fact| fact.marker.outcome == FactOutcome::Succeeded)
        .map(|fact| fact.marker.phase);
    let last_terminal = facts.iter().rev().find(|fact| fact.marker.terminal);
    let has_prior_failure = last_terminal.is_some_and(|terminal| {
        terminal.marker.outcome == FactOutcome::Succeeded
            && facts.iter().any(|fact| {
                fact.marker.terminal
                    && fact.marker.outcome == FactOutcome::Failed
                    && fact
                        .ordering_millis()
                        .zip(terminal.ordering_millis())
                        .is_some_and(|(failure, recovery)| failure < recovery)
            })
    });
    let has_deferred = facts
        .iter()
        .any(|fact| fact.marker.outcome == FactOutcome::Deferred);
    let has_component_progress = successes.iter().any(|fact| {
        matches!(
            fact.marker.phase,
            SccmSiteCorePhase::ComponentStart | SccmSiteCorePhase::ComponentWork
        )
    });
    let terminal_is_last = last_terminal.is_some_and(|terminal| {
        terminal.ordering_millis().is_some_and(|terminal_time| {
            facts.iter().all(|fact| {
                std::ptr::eq(fact, terminal)
                    || fact
                        .ordering_millis()
                        .is_some_and(|fact_time| fact_time < terminal_time)
            })
        })
    });
    let success_progress_is_ordered =
        last_terminal.is_some_and(|terminal| observed_success_progress_is_ordered(facts, terminal));
    let full_success_chain =
        last_terminal.is_some_and(|terminal| complete_success_chain_is_ordered(facts, terminal));

    let (state, finding_class, confidence) = if contradictory {
        (
            SccmSiteCoreState::Contradictory,
            Some(SccmFindingClass::Symptom),
            SccmSiteCoreConfidence::Low,
        )
    } else if !comparable {
        (
            SccmSiteCoreState::Incomplete,
            Some(SccmFindingClass::InsufficientEvidence),
            SccmSiteCoreConfidence::None,
        )
    } else if let Some(terminal) = last_terminal {
        match terminal.marker.outcome {
            FactOutcome::Failed
                if terminal_is_last && has_component_progress && success_progress_is_ordered =>
            {
                (
                    SccmSiteCoreState::TerminalFailure,
                    Some(SccmFindingClass::ConfirmedFailure),
                    SccmSiteCoreConfidence::High,
                )
            }
            FactOutcome::Succeeded
                if terminal_is_last && terminal.marker.recovery && has_prior_failure =>
            {
                (
                    SccmSiteCoreState::Recovered,
                    Some(SccmFindingClass::Symptom),
                    SccmSiteCoreConfidence::High,
                )
            }
            FactOutcome::Succeeded
                if terminal_is_last && !terminal.marker.recovery && full_success_chain =>
            {
                (
                    SccmSiteCoreState::Healthy,
                    None,
                    SccmSiteCoreConfidence::High,
                )
            }
            _ => (
                SccmSiteCoreState::Incomplete,
                Some(SccmFindingClass::InsufficientEvidence),
                SccmSiteCoreConfidence::None,
            ),
        }
    } else if has_deferred {
        (
            SccmSiteCoreState::BlockedOrDeferred,
            Some(SccmFindingClass::BlockedOrDeferred),
            SccmSiteCoreConfidence::Low,
        )
    } else {
        (
            SccmSiteCoreState::Incomplete,
            Some(SccmFindingClass::InsufficientEvidence),
            SccmSiteCoreConfidence::None,
        )
    };

    let mut evidence = facts
        .iter()
        .map(SiteCoreFact::public_evidence)
        .collect::<Vec<_>>();
    evidence.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
    evidence.dedup();
    let next_artifacts = next_artifacts_for_state(state, &key, facts, context);
    let result_id = format!(
        "site-core:{}:{}:{}:{}",
        key.site_handle, key.producer_host_handle, key.component_id, key.work_item_id
    );

    SccmSiteCoreResult {
        result_id,
        transaction_key: key,
        state,
        last_successful_phase,
        finding_class,
        confidence,
        confidence_ceiling: confidence,
        evidence,
        coverage_gap_artifact_ids: coverage_gap_artifact_ids.to_vec(),
        next_artifacts,
    }
}

fn observed_success_progress_is_ordered(facts: &[SiteCoreFact], terminal: &SiteCoreFact) -> bool {
    let Some(terminal_time) = terminal.ordering_millis() else {
        return false;
    };
    let mut previous_phase = None;
    let mut observed = false;
    for fact in facts.iter().filter(|fact| {
        !std::ptr::eq(*fact, terminal) && fact.marker.outcome == FactOutcome::Succeeded
    }) {
        let Some(instant) = fact.ordering_millis() else {
            return false;
        };
        if instant >= terminal_time || previous_phase.is_some_and(|phase| fact.marker.phase < phase)
        {
            return false;
        }
        previous_phase = Some(fact.marker.phase);
        observed = true;
    }
    observed
}

fn complete_success_chain_is_ordered(facts: &[SiteCoreFact], terminal: &SiteCoreFact) -> bool {
    let Some(terminal_time) = terminal.ordering_millis() else {
        return false;
    };
    let mut previous_time = None;
    for phase in &STATE_CHAIN[..4] {
        let Some(instant) = facts
            .iter()
            .filter(|fact| {
                fact.marker.outcome == FactOutcome::Succeeded && fact.marker.phase == *phase
            })
            .filter_map(SiteCoreFact::ordering_millis)
            .find(|instant| {
                *instant < terminal_time && previous_time.is_none_or(|previous| *instant > previous)
            })
        else {
            return false;
        };
        previous_time = Some(instant);
    }
    true
}

fn has_same_instant_conflict(facts: &[SiteCoreFact]) -> bool {
    let mut outcomes = BTreeMap::<(i64, SccmSiteCorePhase), FactOutcome>::new();
    facts.iter().any(|fact| {
        let Some(instant) = fact.ordering_millis() else {
            return false;
        };
        outcomes
            .insert((instant, fact.marker.phase), fact.marker.outcome)
            .is_some_and(|previous| previous != fact.marker.outcome)
    })
}

fn next_artifacts_for_state(
    state: SccmSiteCoreState,
    key: &SccmSiteCoreTransactionKey,
    facts: &[SiteCoreFact],
    context: &SiteCoreContext<'_>,
) -> Vec<SccmSiteCoreArtifactRequest> {
    if state == SccmSiteCoreState::BlockedOrDeferred {
        return vec![status_request(
            "matching-status-terminal-evidence-missing",
            Some(key),
        )];
    }
    if state != SccmSiteCoreState::Incomplete {
        return Vec::new();
    }

    if let Some(source) = context.sources.values().find(|source| {
        source.artifact.state == SccmCoverageState::Capped
            && facts
                .iter()
                .any(|fact| fact.reference.artifact_id == source.artifact.artifact_id)
    }) {
        return vec![recapture_request(source.artifact, Some(key))];
    }
    if facts
        .iter()
        .any(|fact| fact.marker.group == SiteCoreGroup::Component)
        && !facts
            .iter()
            .any(|fact| fact.marker.group == SiteCoreGroup::Status)
    {
        return vec![status_request(
            "matching-status-evidence-missing",
            Some(key),
        )];
    }
    Vec::new()
}

fn status_request(
    reason_code: &str,
    key: Option<&SccmSiteCoreTransactionKey>,
) -> SccmSiteCoreArtifactRequest {
    SccmSiteCoreArtifactRequest {
        logical_name: SCCM_SITE_CORE_STATUS_GROUP.to_owned(),
        role: SccmRole::SiteServer,
        reason_code: reason_code.to_owned(),
        basenames: vec!["statmgr.log".to_owned(), "statmgr.lo_".to_owned()],
        rotations: vec!["current".to_owned(), "loUnderscore".to_owned()],
        max_artifacts: 2,
        max_bytes_per_artifact: None,
        scope: SccmSiteCoreRequestScope {
            producer_host_handle: key.map(|key| key.producer_host_handle.clone()),
            component_id: key.map(|key| key.component_id.clone()),
            work_item_id: key.map(|key| key.work_item_id.clone()),
            rotation_lineage_handle: None,
        },
    }
}

fn recapture_request(
    artifact: &SccmServerArtifactAssessment,
    key: Option<&SccmSiteCoreTransactionKey>,
) -> SccmSiteCoreArtifactRequest {
    let current_limit = artifact
        .capture_provenance
        .as_ref()
        .map(|provenance| provenance.byte_limit)
        .unwrap_or(RECAPTURE_FLOOR_BYTES);
    let requested = current_limit.saturating_mul(2).max(RECAPTURE_FLOOR_BYTES);
    let bounded = requested.checked_next_power_of_two().unwrap_or(1u64 << 63);
    SccmSiteCoreArtifactRequest {
        logical_name: artifact.source_id.clone(),
        role: SccmRole::SiteServer,
        reason_code: "capped-before-next-phase".to_owned(),
        basenames: artifact.original_basename.clone().into_iter().collect(),
        rotations: artifact
            .rotation
            .as_ref()
            .and_then(rotation_name)
            .into_iter()
            .collect(),
        max_artifacts: 1,
        max_bytes_per_artifact: Some(bounded),
        scope: SccmSiteCoreRequestScope {
            producer_host_handle: key
                .map(|key| key.producer_host_handle.clone())
                .or_else(|| artifact.producer_host_handle.clone()),
            component_id: key.map(|key| key.component_id.clone()),
            work_item_id: key.map(|key| key.work_item_id.clone()),
            rotation_lineage_handle: Some(artifact.rotation_lineage_handle.clone()),
        },
    }
}

fn coverage_observations(
    gaps: &[SccmSiteCoreCoverageGap],
    context: &SiteCoreContext<'_>,
) -> Vec<SccmSiteCoreObservation> {
    gaps.iter()
        .filter(|gap| {
            matches!(
                gap.state,
                SccmCoverageState::Capped | SccmCoverageState::ParseFailed
            )
        })
        .map(|gap| {
            let request = context
                .sources
                .get(gap.artifact_id.as_str())
                .map(|source| match gap.state {
                    SccmCoverageState::Capped => recapture_request(source.artifact, None),
                    _ => complete_source_request(source.artifact),
                })
                .into_iter()
                .collect();
            SccmSiteCoreObservation {
                observation_id: format!("site-core:coverage:{}", gap.artifact_id),
                state: SccmSiteCoreState::ParseGap,
                finding_class: SccmFindingClass::InsufficientEvidence,
                confidence: SccmSiteCoreConfidence::None,
                coverage_gap_artifact_ids: vec![gap.artifact_id.clone()],
                next_artifacts: request,
            }
        })
        .collect()
}

fn complete_source_request(artifact: &SccmServerArtifactAssessment) -> SccmSiteCoreArtifactRequest {
    SccmSiteCoreArtifactRequest {
        logical_name: artifact.source_id.clone(),
        role: SccmRole::SiteServer,
        reason_code: "complete-logical-record-required".to_owned(),
        basenames: artifact.original_basename.clone().into_iter().collect(),
        rotations: artifact
            .rotation
            .as_ref()
            .and_then(rotation_name)
            .into_iter()
            .collect(),
        max_artifacts: 1,
        max_bytes_per_artifact: None,
        scope: SccmSiteCoreRequestScope {
            producer_host_handle: artifact.producer_host_handle.clone(),
            component_id: None,
            work_item_id: None,
            rotation_lineage_handle: Some(artifact.rotation_lineage_handle.clone()),
        },
    }
}

fn build_result_finding(
    result: &SccmSiteCoreResult,
    class: SccmFindingClass,
    facts: &[SiteCoreFact],
    context: &SiteCoreContext<'_>,
) -> Option<SccmSiteCoreFinding> {
    let terminal_evidence = if class == SccmFindingClass::ConfirmedFailure {
        facts
            .iter()
            .rev()
            .find(|fact| fact.marker.terminal && fact.marker.outcome == FactOutcome::Failed)
            .map(|fact| {
                vec![SccmTerminalEvidence::observed_failure(
                    fact.reference.clone(),
                )]
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let finding = SccmFindingBuilder::new(format!("finding:{}", result.result_id))
        .class(class)
        .phase(SccmPhase::Unknown(
            result
                .last_successful_phase
                .unwrap_or(SccmSiteCorePhase::ComponentStart)
                .serialized_name()
                .to_owned(),
        ))
        .role(SccmRole::SiteServer)
        .severity(if result.state == SccmSiteCoreState::TerminalFailure {
            Severity::Error
        } else {
            Severity::Warning
        })
        .confidence(shared_confidence(result.confidence))
        .title("Site component and status evidence")
        .summary(match result.last_successful_phase {
            Some(phase) => format!(
                "The last confirmed successful phase is {}; later phases are bounded to cited evidence.",
                phase.serialized_name()
            ),
            None => "No site component phase is confirmed by the cited evidence.".to_owned(),
        })
        .evidence(
            result
                .evidence
                .iter()
                .map(SccmSiteCoreEvidence::reference)
                .collect(),
        )
        .terminal_evidence(terminal_evidence)
        .coverage_gaps(finding_gaps(
            &result.coverage_gap_artifact_ids,
            context,
        ))
        .next_artifacts(shared_requests(&result.next_artifacts))
        .build()
        .ok()?;
    Some(SccmSiteCoreFinding {
        finding,
        subject_id: result.result_id.clone(),
        last_successful_phase: result.last_successful_phase,
    })
}

fn build_observation_finding(
    observation: &SccmSiteCoreObservation,
    context: &SiteCoreContext<'_>,
) -> Option<SccmSiteCoreFinding> {
    let finding = SccmFindingBuilder::new(format!("finding:{}", observation.observation_id))
        .class(observation.finding_class.clone())
        .phase(SccmPhase::Unknown("siteCoreCoverage".to_owned()))
        .role(SccmRole::SiteServer)
        .severity(Severity::Warning)
        .confidence(shared_confidence(observation.confidence))
        .title("Site core coverage gap")
        .summary("The source is incomplete and cannot establish a component outcome.")
        .coverage_gaps(finding_gaps(
            &observation.coverage_gap_artifact_ids,
            context,
        ))
        .next_artifacts(shared_requests(&observation.next_artifacts))
        .build()
        .ok()?;
    Some(SccmSiteCoreFinding {
        finding,
        subject_id: observation.observation_id.clone(),
        last_successful_phase: None,
    })
}

fn finding_gaps(
    artifact_ids: &[String],
    context: &SiteCoreContext<'_>,
) -> Vec<SccmFindingCoverageGap> {
    context
        .coverage_gaps
        .iter()
        .filter(|gap| artifact_ids.contains(&gap.artifact_id))
        .map(|gap| SccmFindingCoverageGap {
            artifact_id: gap.artifact_id.clone(),
            role: SccmRole::SiteServer,
            coverage: gap.state.clone(),
        })
        .collect()
}

fn shared_requests(requests: &[SccmSiteCoreArtifactRequest]) -> Vec<SccmArtifactRequest> {
    let mut shared = requests
        .iter()
        .flat_map(|request| request.basenames.iter())
        .filter_map(|basename| {
            let classified = classify_artifact_name(basename, SccmRole::SiteServer);
            classified
                .supported_for_diagnosis
                .then(|| SccmArtifactRequest {
                    logical_id: classified.logical_name,
                    role: SccmRole::SiteServer,
                    reason: format!("Collect the complete {} file.", classified.basename),
                })
        })
        .collect::<Vec<_>>();
    shared.sort_by(|left, right| {
        left.logical_id
            .cmp(&right.logical_id)
            .then_with(|| left.reason.cmp(&right.reason))
    });
    shared.dedup();
    shared
}

fn shared_confidence(confidence: SccmSiteCoreConfidence) -> SccmConfidence {
    match confidence {
        SccmSiteCoreConfidence::None => SccmConfidence::None,
        SccmSiteCoreConfidence::Low => SccmConfidence::Low,
        SccmSiteCoreConfidence::Moderate => SccmConfidence::Moderate,
        SccmSiteCoreConfidence::High => SccmConfidence::High,
    }
}

fn validated_token_value(message: &str, label: &str) -> Option<Option<String>> {
    let lowercase = message.to_ascii_lowercase();
    let needle = format!("{}=", label.to_ascii_lowercase());
    let mut value = None;
    for (label_start, _) in lowercase.match_indices(&needle) {
        let exact_boundary = label_start == 0
            || message[..label_start]
                .chars()
                .next_back()
                .is_some_and(is_token_boundary);
        if !exact_boundary {
            return None;
        }
        let remainder = &message[label_start + needle.len()..];
        let end = remainder.find(is_token_boundary).unwrap_or(remainder.len());
        if end == 0 || value.replace(remainder[..end].to_owned()).is_some() {
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

fn reference_is_complete(evidence: &SccmEvidence) -> bool {
    evidence.evidence_id == evidence.reference.entry_id
        && matches!(
            (evidence.reference.line_start, evidence.reference.line_end),
            (Some(start), Some(end)) if start > 0 && end >= start
        )
}

fn unique_evidence_identities(evidence: &[SccmEvidence]) -> Vec<bool> {
    let mut unique = vec![true; evidence.len()];
    mark_repeated_keys(
        &mut unique,
        evidence.iter().map(|record| record.evidence_id.as_str()),
    );
    mark_repeated_keys(
        &mut unique,
        evidence
            .iter()
            .map(|record| record.reference.entry_id.as_str()),
    );
    mark_overlapping_ranges(&mut unique, evidence);
    unique
}

fn mark_repeated_keys<'a>(unique: &mut [bool], keys: impl Iterator<Item = &'a str>) {
    let mut positions = BTreeMap::<&str, Vec<usize>>::new();
    for (position, key) in keys.enumerate() {
        positions.entry(key).or_default().push(position);
    }
    for repeated in positions
        .into_values()
        .filter(|positions| positions.len() > 1)
    {
        for position in repeated {
            unique[position] = false;
        }
    }
}

fn mark_overlapping_ranges(unique: &mut [bool], evidence: &[SccmEvidence]) {
    let mut by_artifact = BTreeMap::<&str, Vec<(u32, u32, usize)>>::new();
    for (position, record) in evidence.iter().enumerate() {
        if let (Some(start), Some(end)) = (record.reference.line_start, record.reference.line_end) {
            by_artifact
                .entry(record.reference.artifact_id.as_str())
                .or_default()
                .push((start, end, position));
        }
    }
    for ranges in by_artifact.values_mut() {
        ranges.sort_unstable();
        let mut active: Option<(u32, usize)> = None;
        for &(start, end, position) in ranges.iter() {
            if let Some((active_end, active_position)) = active {
                if start <= active_end {
                    unique[position] = false;
                    unique[active_position] = false;
                }
            }
            if active.is_none_or(|(active_end, _)| end > active_end) {
                active = Some((end, position));
            }
        }
    }
}

fn compare_facts(left: &SiteCoreFact, right: &SiteCoreFact) -> Ordering {
    left.ordering_millis()
        .cmp(&right.ordering_millis())
        .then_with(|| left.marker.phase.cmp(&right.marker.phase))
        .then_with(|| compare_references(&left.reference, &right.reference))
}

fn compare_references(left: &SccmEvidenceRef, right: &SccmEvidenceRef) -> Ordering {
    left.artifact_id
        .cmp(&right.artifact_id)
        .then_with(|| left.line_start.cmp(&right.line_start))
        .then_with(|| left.line_end.cmp(&right.line_end))
        .then_with(|| left.entry_id.cmp(&right.entry_id))
}

fn rotation_name(rotation: &crate::sccm::SccmRotation) -> Option<String> {
    Some(match rotation {
        crate::sccm::SccmRotation::Current => "current".to_owned(),
        crate::sccm::SccmRotation::LoUnderscore => "loUnderscore".to_owned(),
        crate::sccm::SccmRotation::Numbered(value) => format!("numbered-{value}"),
        crate::sccm::SccmRotation::Timestamped(value) => format!("timestamped-{value}"),
        crate::sccm::SccmRotation::Unknown(_) => return None,
    })
}

fn coverage_sort_key(state: &SccmCoverageState) -> &'static str {
    match state {
        SccmCoverageState::Captured => "captured",
        SccmCoverageState::Absent => "absent",
        SccmCoverageState::AccessDenied => "accessDenied",
        SccmCoverageState::Capped => "capped",
        SccmCoverageState::Skipped => "skipped",
        SccmCoverageState::Unsupported => "unsupported",
        SccmCoverageState::ParseFailed => "parseFailed",
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
