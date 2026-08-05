//! Role-local SCCM site-core and status analysis.
//!
//! This reducer consumes only the normalized server-intake assessment. It does
//! not reconstruct manifest state, inspect files, infer an installed role from
//! a default path, or correlate a client with a server by time.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::models::log_entry::Severity;
use crate::sccm::{
    classify_artifact_name, SccmArtifactFamily, SccmArtifactRequest, SccmConfidence,
    SccmCoverageState, SccmEvidence, SccmEvidenceRef, SccmFinding, SccmFindingBuilder,
    SccmFindingClass, SccmFindingCoverageGap, SccmPhase, SccmRole, SccmTerminalEvidence,
    SccmTimeOrderingState, SccmTimestamp,
};

use super::intake::CoverageIdentityKey;
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
const MAX_SITE_CORE_REQUEST_ARTIFACTS: usize = 2;
const INTAKE_AUTHORITY_ARTIFACT_ID: &str = "site-core-intake-authority";
const INTAKE_AUTHORITY_SOURCE_ID: &str = "server-site-core-intake";
const INTAKE_AUTHORITY_REASON_CODE: &str = "intake-authority-invalid";

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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmSiteCoreArtifactCandidate {
    pub basename: String,
    pub rotation: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmSiteCoreArtifactRequest {
    pub logical_name: String,
    pub role: SccmRole,
    pub reason_code: String,
    pub candidates: Vec<SccmSiteCoreArtifactCandidate>,
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
    pub evidence: Vec<SccmSiteCoreEvidence>,
    pub coverage_gap_artifact_ids: Vec<String>,
    pub next_artifacts: Vec<SccmSiteCoreArtifactRequest>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmSiteCoreCoverageGap {
    pub artifact_id: String,
    pub source_id: String,
    pub state: SccmCoverageState,
    pub reason_code: String,
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
    rejection_reason: Option<&'static str>,
}

struct SiteCoreContext<'a> {
    artifacts: &'a [SccmServerArtifactAssessment],
    sources: BTreeMap<&'a str, AdmittedSource<'a>>,
    intake_authority_is_bound: bool,
    evidence_identity_is_unique: Vec<bool>,
    coverage_gaps: Vec<SccmSiteCoreCoverageGap>,
    coverage_gap_producer_hosts: BTreeMap<String, String>,
}

impl<'a> SiteCoreContext<'a> {
    fn new(intake: &'a SccmServerIntakeAssessment) -> Self {
        let intake_authority_is_bound = intake.adapter_authority_is_intake_bound();
        if !intake_authority_is_bound {
            // The public assessment fields are no longer authoritative once the
            // private intake seal fails. Keep the coverage failure explicit, but
            // do not use caller-mutable artifact identities or topology to scope
            // a collection request.
            return Self {
                artifacts: &[],
                sources: BTreeMap::new(),
                intake_authority_is_bound,
                evidence_identity_is_unique: Vec::new(),
                coverage_gaps: vec![SccmSiteCoreCoverageGap {
                    artifact_id: INTAKE_AUTHORITY_ARTIFACT_ID.to_owned(),
                    source_id: INTAKE_AUTHORITY_SOURCE_ID.to_owned(),
                    state: SccmCoverageState::ParseFailed,
                    reason_code: INTAKE_AUTHORITY_REASON_CODE.to_owned(),
                    diagnostic_meaning: SccmSiteCoreDiagnosticMeaning::CoverageOnly,
                }],
                coverage_gap_producer_hosts: BTreeMap::new(),
            };
        }

        let evidence_identity_is_unique = unique_evidence_identities(&intake.evidence);
        let collision_artifact_ids =
            evidence_collision_artifact_ids(&intake.evidence, &evidence_identity_is_unique);
        let (evidence_source_rejections, unresolved_evidence_gaps) =
            evidence_source_rejections(intake);
        // Deliberate defense in depth: the complete adapter seal currently
        // includes topology, while Site Core also keeps its topology-specific
        // authority contract explicit at the point that topology scopes facts.
        let coverage_congruent =
            intake.topology_authority_is_intake_bound() && site_core_coverage_is_congruent(intake);
        let sources = admitted_sources(
            intake,
            &collision_artifact_ids,
            &evidence_source_rejections,
            coverage_congruent,
        );
        let mut coverage_gaps = collect_coverage_gaps(intake, &sources);
        coverage_gaps.extend(unresolved_evidence_gaps);
        sort_and_dedup_coverage_gaps(&mut coverage_gaps);
        Self {
            artifacts: &intake.artifacts,
            sources,
            intake_authority_is_bound,
            evidence_identity_is_unique,
            coverage_gaps,
            coverage_gap_producer_hosts: BTreeMap::new(),
        }
    }

    fn add_undeclared_peer_source_gaps(
        &mut self,
        grouped: &BTreeMap<SccmSiteCoreTransactionKey, Vec<SiteCoreFact>>,
    ) {
        for (observed_group, required_group, reason_code) in [
            (
                SiteCoreGroup::Component,
                SiteCoreGroup::Status,
                "required-status-source-not-declared",
            ),
            (
                SiteCoreGroup::Status,
                SiteCoreGroup::Component,
                "required-component-source-not-declared",
            ),
        ] {
            let producer_hosts = grouped
                .iter()
                .filter(|(_, facts)| facts.iter().any(|fact| fact.marker.group == observed_group))
                .map(|(key, _)| key.producer_host_handle.clone())
                .collect::<BTreeSet<_>>();
            for producer_host_handle in producer_hosts {
                let compatible_source_exists = self.sources.values().any(|source| {
                    source.group == required_group
                        && source.artifact.producer_role == SccmRole::SiteServer
                        && source.artifact.producer_host_handle.as_deref()
                            == Some(producer_host_handle.as_str())
                        && source.artifact.workflow_subject_role.is_none()
                        && source.artifact.workflow_subject_handle.is_none()
                        && (source.fact_eligible
                            || self.coverage_gaps.iter().any(|gap| {
                                gap.artifact_id == source.artifact.artifact_id
                                    && gap.source_id == source.artifact.source_id
                            }))
                });
                if compatible_source_exists {
                    continue;
                }
                let artifact_id = stable_opaque_id(
                    "site-core:missing-source:v1:",
                    &[required_group.source_id(), &producer_host_handle],
                );
                self.coverage_gap_producer_hosts
                    .insert(artifact_id.clone(), producer_host_handle);
                self.coverage_gaps.push(SccmSiteCoreCoverageGap {
                    artifact_id,
                    source_id: required_group.source_id().to_owned(),
                    state: SccmCoverageState::Absent,
                    reason_code: reason_code.to_owned(),
                    diagnostic_meaning: SccmSiteCoreDiagnosticMeaning::CoverageOnly,
                });
            }
        }
        sort_and_dedup_coverage_gaps(&mut self.coverage_gaps);
    }
}

pub fn analyze_site_core(intake: &SccmServerIntakeAssessment) -> SccmSiteCoreAnalysis {
    let mut context = SiteCoreContext::new(intake);
    let mut grouped = BTreeMap::<SccmSiteCoreTransactionKey, Vec<SiteCoreFact>>::new();
    let mut record_observations = Vec::new();
    if context.intake_authority_is_bound {
        for (position, evidence) in intake.evidence.iter().enumerate() {
            let Some(source) = context.sources.get(evidence.reference.artifact_id.as_str()) else {
                continue;
            };
            if let Some(reason_code) = evidence_record_rejection_reason(evidence, source.group) {
                if is_profile_record_candidate(&evidence.message) {
                    record_observations.push(rejected_record_observation(
                        evidence,
                        source,
                        reason_code,
                    ));
                }
                continue;
            }
            if !source.fact_eligible || !context.evidence_identity_is_unique[position] {
                continue;
            }
            match parse_fact(evidence, source, &intake.topology.site_handle) {
                ProfileRecordParse::Accepted(fact) => {
                    grouped.entry(fact.key.clone()).or_default().push(*fact);
                }
                ProfileRecordParse::Rejected(reason_code) => {
                    record_observations.push(rejected_record_observation(
                        evidence,
                        source,
                        reason_code,
                    ));
                }
                ProfileRecordParse::NotCandidate => {}
            }
        }
    }
    context.add_undeclared_peer_source_gaps(&grouped);

    let mut results = Vec::new();
    let mut findings = Vec::new();
    for (key, mut facts) in grouped {
        facts.sort_by(compare_facts);
        let gap_ids = coverage_gap_ids_for_key(&context, &key);
        let reduced = reduce_transaction(key, &facts, &context, &gap_ids);
        if let Some(class) = reduced.finding_class.clone() {
            if let Some(finding) = build_result_finding(&reduced, class, &facts, &context) {
                findings.push(finding);
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
    unlinked_observations.extend(record_observations);
    unlinked_observations.sort_by(|left, right| left.observation_id.cmp(&right.observation_id));
    unlinked_observations.dedup_by(|left, right| left.observation_id == right.observation_id);
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
    collision_artifact_ids: &BTreeSet<String>,
    evidence_source_rejections: &BTreeMap<String, &'static str>,
    coverage_congruent: bool,
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
            if occurrences.get(artifact.artifact_id.as_str()) != Some(&1) {
                return None;
            }
            let shape_valid = source_shape_is_valid(artifact, group);
            let rejection_reason = if artifact.producer_role != SccmRole::SiteServer
                || artifact.workflow_subject_role.is_some()
                || artifact.workflow_subject_handle.is_some()
            {
                Some("source-role-or-subject-rejected")
            } else if !coverage_congruent {
                Some("intake-coverage-incongruent")
            } else if collision_artifact_ids.contains(&artifact.artifact_id) {
                Some("evidence-identity-collision")
            } else if let Some(reason_code) = evidence_source_rejections.get(&artifact.artifact_id)
            {
                Some(*reason_code)
            } else if !shape_valid {
                Some("source-shape-invalid")
            } else if artifact.state != SccmCoverageState::Captured {
                Some(coverage_rejection_reason(&artifact.state))
            } else if !source_carries_facts(artifact) {
                Some("source-profile-or-provenance-unusable")
            } else {
                None
            };
            Some((
                artifact.artifact_id.as_str(),
                AdmittedSource {
                    artifact,
                    group,
                    fact_eligible: rejection_reason.is_none(),
                    rejection_reason,
                },
            ))
        })
        .collect()
}

fn evidence_source_rejections(
    intake: &SccmServerIntakeAssessment,
) -> (BTreeMap<String, &'static str>, Vec<SccmSiteCoreCoverageGap>) {
    let mut groups_by_artifact = BTreeMap::<&str, Vec<SiteCoreGroup>>::new();
    let mut artifact_ids = BTreeSet::<&str>::new();
    for artifact in &intake.artifacts {
        artifact_ids.insert(artifact.artifact_id.as_str());
        if let Some(group) = SiteCoreGroup::from_source_id(&artifact.source_id) {
            groups_by_artifact
                .entry(artifact.artifact_id.as_str())
                .or_default()
                .push(group);
        }
    }

    let mut source_rejections = BTreeMap::<String, &'static str>::new();
    let mut unresolved_gaps = Vec::new();
    for evidence in &intake.evidence {
        match groups_by_artifact.get(evidence.reference.artifact_id.as_str()) {
            Some(groups) if groups.len() == 1 => {
                if let Some(reason_code) = evidence_record_rejection_reason(evidence, groups[0]) {
                    source_rejections
                        .entry(evidence.reference.artifact_id.clone())
                        .and_modify(|current| {
                            if reason_code < *current {
                                *current = reason_code;
                            }
                        })
                        .or_insert(reason_code);
                }
            }
            None if is_profile_record_candidate(&evidence.message) => {
                let Some(group) = evidence_component_group(evidence.component.as_deref()) else {
                    continue;
                };
                unresolved_gaps.push(SccmSiteCoreCoverageGap {
                    artifact_id: unresolved_coverage_artifact_id(
                        evidence,
                        artifact_ids.contains(evidence.reference.artifact_id.as_str()),
                    ),
                    source_id: group.source_id().to_owned(),
                    state: SccmCoverageState::ParseFailed,
                    reason_code: "evidence-source-unresolved".to_owned(),
                    diagnostic_meaning: SccmSiteCoreDiagnosticMeaning::CoverageOnly,
                });
            }
            _ => {}
        }
    }
    sort_and_dedup_coverage_gaps(&mut unresolved_gaps);
    (source_rejections, unresolved_gaps)
}

fn evidence_record_rejection_reason(
    evidence: &SccmEvidence,
    source_group: SiteCoreGroup,
) -> Option<&'static str> {
    if evidence.role != SccmRole::SiteServer {
        return Some("evidence-role-rejected");
    }
    if !reference_is_complete(evidence) {
        return Some("evidence-reference-rejected");
    }
    evidence_component_group(evidence.component.as_deref())
        .is_some_and(|evidence_group| evidence_group != source_group)
        .then_some("evidence-source-attribution-rejected")
}

fn evidence_component_group(component: Option<&str>) -> Option<SiteCoreGroup> {
    match component? {
        "SMS_SITE_COMPONENT_MANAGER" | "SMS_HIERARCHY_MANAGER" => Some(SiteCoreGroup::Component),
        "SMS_STATUS_MANAGER" | "SMS_STATE_SYSTEM" => Some(SiteCoreGroup::Status),
        _ => None,
    }
}

fn unresolved_coverage_artifact_id(evidence: &SccmEvidence, is_foreign_source: bool) -> String {
    if !is_foreign_source && safe_site_core_opaque_id(&evidence.reference.artifact_id) {
        evidence.reference.artifact_id.clone()
    } else {
        stable_opaque_id(
            "site-core:rejected-artifact:v1:",
            &[&evidence.reference.artifact_id, &evidence.evidence_id],
        )
    }
}

fn coverage_rejection_reason(state: &SccmCoverageState) -> &'static str {
    match state {
        SccmCoverageState::Captured => "source-contract-rejected",
        SccmCoverageState::Absent => "required-source-absent",
        SccmCoverageState::AccessDenied => "required-source-access-denied",
        SccmCoverageState::Capped => "required-source-capped",
        SccmCoverageState::Skipped => "required-source-skipped",
        SccmCoverageState::Unsupported => "required-source-unsupported",
        SccmCoverageState::ParseFailed => "required-source-parse-failed",
    }
}

fn source_shape_is_valid(artifact: &SccmServerArtifactAssessment, group: SiteCoreGroup) -> bool {
    let Some(basename) = artifact.original_basename.as_deref() else {
        return false;
    };
    let classified = classify_artifact_name(basename, SccmRole::SiteServer);
    let validated_logical_source = match group {
        SiteCoreGroup::Component => matches!(classified.logical_name.as_str(), "sitecomp" | "hman"),
        SiteCoreGroup::Status => matches!(classified.logical_name.as_str(), "statmgr" | "statesys"),
    };
    validated_logical_source
        && safe_site_core_opaque_id(&artifact.artifact_id)
        && safe_site_core_opaque_id(&artifact.rotation_lineage_handle)
        && artifact.source_id == group.source_id()
        && artifact.family == group.family()
        && artifact.rotation.as_ref() == Some(&classified.rotation)
        && classified.supported_for_diagnosis
        && classified.family == group.family()
        && classified.role == SccmRole::SiteServer
        && artifact.parser_eligible
        && artifact
            .producer_host_handle
            .as_deref()
            .is_some_and(safe_site_core_host)
}

fn expected_evidence_component(artifact: &SccmServerArtifactAssessment) -> Option<&'static str> {
    let basename = artifact.original_basename.as_deref()?;
    let classified = classify_artifact_name(basename, SccmRole::SiteServer);
    Some(match classified.logical_name.as_str() {
        "sitecomp" => "SMS_SITE_COMPONENT_MANAGER",
        "hman" => "SMS_HIERARCHY_MANAGER",
        "statmgr" => "SMS_STATUS_MANAGER",
        "statesys" => "SMS_STATE_SYSTEM",
        _ => return None,
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
                .coverage_gap_producer_hosts
                .get(&gap.artifact_id)
                .is_some_and(|producer| producer == &key.producer_host_handle)
                || context
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
    let mut occurrences = BTreeMap::<&str, usize>::new();
    for artifact in &intake.artifacts {
        if SiteCoreGroup::from_source_id(&artifact.source_id).is_some() {
            *occurrences
                .entry(artifact.artifact_id.as_str())
                .or_default() += 1;
        }
    }

    let mut gaps = Vec::new();
    for artifact in &intake.artifacts {
        let Some(_group) = SiteCoreGroup::from_source_id(&artifact.source_id) else {
            continue;
        };
        let duplicate_identity = occurrences.get(artifact.artifact_id.as_str()) != Some(&1);
        let source = sources.get(artifact.artifact_id.as_str());
        if !duplicate_identity
            && source.is_some_and(|source| {
                source.fact_eligible || absent_default_is_superseded(source.artifact, sources)
            })
        {
            continue;
        }
        let reason_code = if duplicate_identity {
            "duplicate-source-identity"
        } else {
            source
                .and_then(|source| source.rejection_reason)
                .unwrap_or("source-contract-rejected")
        };
        let state = if duplicate_identity
            || matches!(
                reason_code,
                "source-role-or-subject-rejected"
                    | "intake-coverage-incongruent"
                    | "evidence-identity-collision"
                    | "evidence-reference-rejected"
                    | "evidence-role-rejected"
                    | "evidence-source-attribution-rejected"
                    | "source-shape-invalid"
                    | "source-contract-rejected"
            ) {
            SccmCoverageState::ParseFailed
        } else if artifact.state == SccmCoverageState::Captured {
            if artifact.fragment_complete == Some(false) || artifact.truncated == Some(true) {
                SccmCoverageState::ParseFailed
            } else {
                SccmCoverageState::Unsupported
            }
        } else {
            artifact.state.clone()
        };
        let artifact_id = if safe_site_core_opaque_id(&artifact.artifact_id) {
            artifact.artifact_id.clone()
        } else {
            stable_opaque_id(
                "site-core:rejected-artifact:v1:",
                &[&artifact.artifact_id, &artifact.source_id],
            )
        };
        gaps.push(SccmSiteCoreCoverageGap {
            artifact_id,
            source_id: artifact.source_id.clone(),
            state,
            reason_code: reason_code.to_owned(),
            diagnostic_meaning: SccmSiteCoreDiagnosticMeaning::CoverageOnly,
        });
    }
    sort_and_dedup_coverage_gaps(&mut gaps);
    gaps
}

fn sort_and_dedup_coverage_gaps(gaps: &mut Vec<SccmSiteCoreCoverageGap>) {
    gaps.sort_by(|left, right| {
        left.artifact_id
            .cmp(&right.artifact_id)
            .then_with(|| left.source_id.cmp(&right.source_id))
            .then_with(|| coverage_sort_key(&left.state).cmp(coverage_sort_key(&right.state)))
            .then_with(|| left.reason_code.cmp(&right.reason_code))
    });
    gaps.dedup_by(|left, right| {
        left.artifact_id == right.artifact_id
            && left.source_id == right.source_id
            && left.state == right.state
            && left.reason_code == right.reason_code
    });
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

enum ProfileRecordParse {
    NotCandidate,
    Rejected(&'static str),
    Accepted(Box<SiteCoreFact>),
}

fn parse_fact(
    evidence: &SccmEvidence,
    source: &AdmittedSource<'_>,
    site_handle: &str,
) -> ProfileRecordParse {
    let message = evidence.message.as_str();
    if !is_profile_record_candidate(message) {
        return ProfileRecordParse::NotCandidate;
    }
    if evidence.component.as_deref() != expected_evidence_component(source.artifact) {
        return ProfileRecordParse::Rejected("profile-component-source-mismatch");
    }
    if !profile_labels_are_closed(message) {
        return ProfileRecordParse::Rejected("profile-field-schema-rejected");
    }
    let Some(profile_id) = token_value(message, "profileId") else {
        return ProfileRecordParse::Rejected("profile-identity-missing");
    };
    let Some(profile_version) = token_value(message, "profileVersion") else {
        return ProfileRecordParse::Rejected("profile-version-missing");
    };
    let Some(site) = token_value(message, "site") else {
        return ProfileRecordParse::Rejected("profile-site-missing");
    };
    if profile_id != SCCM_SITE_CORE_PROFILE_ID
        || profile_version != SCCM_SITE_CORE_PROFILE_VERSION.to_string()
        || site_handle != "synthetic:site:lab"
        || site != "LAB"
    {
        return ProfileRecordParse::Rejected("profile-identity-rejected");
    }

    let Some(component_id) =
        token_value(message, "componentId").and_then(|value| validated_component_id(&value))
    else {
        return ProfileRecordParse::Rejected("profile-component-id-rejected");
    };
    let Some(work_item_id) =
        token_value(message, "workItemId").and_then(|value| validated_work_item_id(&value))
    else {
        return ProfileRecordParse::Rejected("profile-work-item-id-rejected");
    };
    let Some(marker) = token_value(message, "statusId").and_then(|value| status_marker(&value))
    else {
        return ProfileRecordParse::Rejected("profile-status-id-rejected");
    };
    let Some(outcome) = token_value(message, "outcome") else {
        return ProfileRecordParse::Rejected("profile-outcome-missing");
    };
    let Some(terminal) = token_value(message, "terminal") else {
        return ProfileRecordParse::Rejected("profile-terminal-missing");
    };
    if marker.group != source.group
        || outcome != marker.outcome.token()
        || terminal != if marker.terminal { "true" } else { "false" }
        || !queue_depth_matches_marker(message, marker)
    {
        return ProfileRecordParse::Rejected("profile-status-schema-rejected");
    }

    ProfileRecordParse::Accepted(Box::new(SiteCoreFact {
        key: SccmSiteCoreTransactionKey {
            profile_id: SCCM_SITE_CORE_PROFILE_ID.to_owned(),
            profile_version: SCCM_SITE_CORE_PROFILE_VERSION,
            site_handle: site_handle.to_owned(),
            producer_host_handle: source
                .artifact
                .producer_host_handle
                .clone()
                .expect("fact-eligible sources have a validated producer host"),
            component_id,
            work_item_id,
        },
        marker,
        reference: evidence.reference.clone(),
        timestamp: evidence.timestamp.clone(),
    }))
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
    let has_deferred = has_unrecovered_deferred(facts);
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
    let result_id = stable_opaque_id(
        "site-core:result:v1:",
        &[
            &key.site_handle,
            &key.producer_host_handle,
            &key.component_id,
            &key.work_item_id,
        ],
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

fn has_unrecovered_deferred(facts: &[SiteCoreFact]) -> bool {
    facts
        .iter()
        .filter(|fact| fact.marker.outcome == FactOutcome::Deferred)
        .any(|deferred| {
            let Some(deferred_time) = deferred.ordering_millis() else {
                return true;
            };
            !facts.iter().any(|candidate| {
                candidate.marker.phase == deferred.marker.phase
                    && candidate.marker.outcome == FactOutcome::Succeeded
                    && candidate
                        .ordering_millis()
                        .is_some_and(|success_time| success_time > deferred_time)
            })
        })
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
            key,
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
        return recapture_request(source.artifact, Some(key))
            .into_iter()
            .collect();
    }
    if facts
        .iter()
        .any(|fact| fact.marker.group == SiteCoreGroup::Component)
        && !facts
            .iter()
            .any(|fact| fact.marker.group == SiteCoreGroup::Status)
    {
        return vec![status_request("matching-status-evidence-missing", key)];
    }
    if facts
        .iter()
        .any(|fact| fact.marker.group == SiteCoreGroup::Status)
        && !facts
            .iter()
            .any(|fact| fact.marker.group == SiteCoreGroup::Component)
    {
        return vec![component_request(
            "matching-component-evidence-missing",
            key,
        )];
    }
    Vec::new()
}

fn status_request(
    reason_code: &str,
    key: &SccmSiteCoreTransactionKey,
) -> SccmSiteCoreArtifactRequest {
    matching_group_request(SiteCoreGroup::Status, reason_code, key)
}

fn component_request(
    reason_code: &str,
    key: &SccmSiteCoreTransactionKey,
) -> SccmSiteCoreArtifactRequest {
    matching_group_request(SiteCoreGroup::Component, reason_code, key)
}

fn matching_group_request(
    group: SiteCoreGroup,
    reason_code: &str,
    key: &SccmSiteCoreTransactionKey,
) -> SccmSiteCoreArtifactRequest {
    group_request(
        group,
        reason_code,
        SccmSiteCoreRequestScope {
            producer_host_handle: Some(key.producer_host_handle.clone()),
            component_id: Some(key.component_id.clone()),
            work_item_id: Some(key.work_item_id.clone()),
            rotation_lineage_handle: None,
        },
    )
}

fn recapture_request(
    artifact: &SccmServerArtifactAssessment,
    key: Option<&SccmSiteCoreTransactionKey>,
) -> Option<SccmSiteCoreArtifactRequest> {
    let candidate = request_candidate(artifact)?;
    let scope = request_scope_for_artifact(artifact, key)?;
    let current_limit = artifact
        .capture_provenance
        .as_ref()
        .map(|provenance| provenance.byte_limit)
        .unwrap_or(RECAPTURE_FLOOR_BYTES);
    let requested = current_limit.saturating_mul(2).max(RECAPTURE_FLOOR_BYTES);
    let bounded = requested.checked_next_power_of_two().unwrap_or(1u64 << 63);
    Some(SccmSiteCoreArtifactRequest {
        logical_name: artifact.source_id.clone(),
        role: SccmRole::SiteServer,
        reason_code: "capped-before-next-phase".to_owned(),
        candidates: vec![candidate],
        max_artifacts: 1,
        max_bytes_per_artifact: Some(bounded),
        scope,
    })
}

fn coverage_observations(
    gaps: &[SccmSiteCoreCoverageGap],
    context: &SiteCoreContext<'_>,
) -> Vec<SccmSiteCoreObservation> {
    gaps.iter()
        .map(|gap| {
            let request = coverage_request(gap, context).into_iter().collect();
            SccmSiteCoreObservation {
                observation_id: stable_opaque_id(
                    "site-core:observation:v1:",
                    &[
                        &gap.artifact_id,
                        &gap.source_id,
                        coverage_sort_key(&gap.state),
                        &gap.reason_code,
                    ],
                ),
                state: SccmSiteCoreState::ParseGap,
                finding_class: SccmFindingClass::InsufficientEvidence,
                confidence: SccmSiteCoreConfidence::None,
                evidence: Vec::new(),
                coverage_gap_artifact_ids: vec![gap.artifact_id.clone()],
                next_artifacts: request,
            }
        })
        .collect()
}

fn rejected_record_observation(
    evidence: &SccmEvidence,
    source: &AdmittedSource<'_>,
    reason_code: &str,
) -> SccmSiteCoreObservation {
    let retained_evidence = reference_is_complete(evidence).then(|| SccmSiteCoreEvidence {
        artifact_id: evidence.reference.artifact_id.clone(),
        entry_id: evidence.reference.entry_id.clone(),
        line_start: evidence
            .reference
            .line_start
            .expect("complete reference start"),
        line_end: evidence.reference.line_end.expect("complete reference end"),
        terminal: None,
        recovery: None,
        complete_logical_record: Some(true),
    });
    let request = complete_source_request(source.artifact, reason_code).or_else(|| {
        request_scope_for_artifact(source.artifact, None)
            .map(|scope| group_request(source.group, reason_code, scope))
    });
    SccmSiteCoreObservation {
        observation_id: stable_opaque_id(
            "site-core:observation:v1:",
            &[
                &evidence.reference.artifact_id,
                &evidence.reference.entry_id,
                reason_code,
            ],
        ),
        state: SccmSiteCoreState::ParseGap,
        finding_class: SccmFindingClass::Symptom,
        confidence: SccmSiteCoreConfidence::Low,
        evidence: retained_evidence.into_iter().collect(),
        coverage_gap_artifact_ids: Vec::new(),
        next_artifacts: request.into_iter().collect(),
    }
}

fn coverage_request(
    gap: &SccmSiteCoreCoverageGap,
    context: &SiteCoreContext<'_>,
) -> Option<SccmSiteCoreArtifactRequest> {
    let group = SiteCoreGroup::from_source_id(&gap.source_id)?;
    if let Some(producer_host_handle) = context.coverage_gap_producer_hosts.get(&gap.artifact_id) {
        let scope = SccmSiteCoreRequestScope {
            producer_host_handle: Some(producer_host_handle.clone()),
            component_id: None,
            work_item_id: None,
            rotation_lineage_handle: None,
        };
        return request_scope_is_specific(&scope)
            .then(|| group_request(group, &gap.reason_code, scope));
    }
    if let Some(source) = context.sources.get(gap.artifact_id.as_str()) {
        if gap.state == SccmCoverageState::Capped {
            if let Some(request) = recapture_request(source.artifact, None) {
                return Some(request);
            }
        } else if let Some(request) = complete_source_request(source.artifact, &gap.reason_code) {
            return Some(request);
        }
        let scope = request_scope_for_artifact(source.artifact, None)?;
        return Some(group_request(group, &gap.reason_code, scope));
    }
    let scope = request_scope_for_gap(gap, context)?;
    Some(group_request(group, &gap.reason_code, scope))
}

fn complete_source_request(
    artifact: &SccmServerArtifactAssessment,
    reason_code: &str,
) -> Option<SccmSiteCoreArtifactRequest> {
    let candidate = request_candidate(artifact)?;
    let scope = request_scope_for_artifact(artifact, None)?;
    Some(SccmSiteCoreArtifactRequest {
        logical_name: artifact.source_id.clone(),
        role: SccmRole::SiteServer,
        reason_code: reason_code.to_owned(),
        candidates: vec![candidate],
        max_artifacts: 1,
        max_bytes_per_artifact: None,
        scope,
    })
}

fn group_request(
    group: SiteCoreGroup,
    reason_code: &str,
    scope: SccmSiteCoreRequestScope,
) -> SccmSiteCoreArtifactRequest {
    let stem = match group {
        SiteCoreGroup::Component => "sitecomp",
        SiteCoreGroup::Status => "statmgr",
    };
    SccmSiteCoreArtifactRequest {
        logical_name: group.source_id().to_owned(),
        role: SccmRole::SiteServer,
        reason_code: reason_code.to_owned(),
        candidates: vec![
            SccmSiteCoreArtifactCandidate {
                basename: format!("{stem}.log"),
                rotation: "current".to_owned(),
            },
            SccmSiteCoreArtifactCandidate {
                basename: format!("{stem}.lo_"),
                rotation: "loUnderscore".to_owned(),
            },
        ],
        max_artifacts: MAX_SITE_CORE_REQUEST_ARTIFACTS,
        max_bytes_per_artifact: None,
        scope,
    }
}

fn request_scope_for_gap(
    gap: &SccmSiteCoreCoverageGap,
    context: &SiteCoreContext<'_>,
) -> Option<SccmSiteCoreRequestScope> {
    let exact_artifacts = context
        .artifacts
        .iter()
        .filter(|artifact| {
            artifact.artifact_id == gap.artifact_id && artifact.source_id == gap.source_id
        })
        .collect::<Vec<_>>();
    let artifacts = if exact_artifacts.is_empty() {
        context
            .artifacts
            .iter()
            .filter(|artifact| artifact.source_id == gap.source_id)
            .collect()
    } else {
        exact_artifacts
    };
    consensus_request_scope(&artifacts)
}

fn request_scope_for_artifact(
    artifact: &SccmServerArtifactAssessment,
    key: Option<&SccmSiteCoreTransactionKey>,
) -> Option<SccmSiteCoreRequestScope> {
    let producer_host_handle = key
        .map(|key| key.producer_host_handle.as_str())
        .or(artifact.producer_host_handle.as_deref())
        .filter(|value| safe_site_core_opaque_id(value))
        .map(str::to_owned);
    let component_id = key
        .and_then(|key| validated_component_id(&key.component_id))
        .filter(|value| safe_site_core_opaque_id(value));
    let work_item_id = key
        .and_then(|key| validated_work_item_id(&key.work_item_id))
        .filter(|value| safe_site_core_opaque_id(value));
    let rotation_lineage_handle = safe_site_core_opaque_id(&artifact.rotation_lineage_handle)
        .then(|| artifact.rotation_lineage_handle.clone());
    let scope = SccmSiteCoreRequestScope {
        producer_host_handle,
        component_id,
        work_item_id,
        rotation_lineage_handle,
    };
    request_scope_is_specific(&scope).then_some(scope)
}

fn consensus_request_scope(
    artifacts: &[&SccmServerArtifactAssessment],
) -> Option<SccmSiteCoreRequestScope> {
    let producer_host_handle = consensus_scope_value(artifacts, |artifact| {
        artifact.producer_host_handle.as_deref()
    });
    let rotation_lineage_handle = consensus_scope_value(artifacts, |artifact| {
        Some(artifact.rotation_lineage_handle.as_str())
    });
    let scope = SccmSiteCoreRequestScope {
        producer_host_handle,
        component_id: None,
        work_item_id: None,
        rotation_lineage_handle,
    };
    request_scope_is_specific(&scope).then_some(scope)
}

fn consensus_scope_value(
    artifacts: &[&SccmServerArtifactAssessment],
    value: impl Fn(&SccmServerArtifactAssessment) -> Option<&str>,
) -> Option<String> {
    let first = value(*artifacts.first()?)?;
    (safe_site_core_opaque_id(first)
        && artifacts.iter().all(|artifact| {
            value(artifact)
                .is_some_and(|candidate| candidate == first && safe_site_core_opaque_id(candidate))
        }))
    .then(|| first.to_owned())
}

fn request_scope_is_specific(scope: &SccmSiteCoreRequestScope) -> bool {
    scope
        .producer_host_handle
        .as_deref()
        .is_some_and(safe_site_core_opaque_id)
        || scope
            .component_id
            .as_deref()
            .is_some_and(safe_site_core_opaque_id)
        || scope
            .work_item_id
            .as_deref()
            .is_some_and(safe_site_core_opaque_id)
        || scope
            .rotation_lineage_handle
            .as_deref()
            .is_some_and(safe_site_core_opaque_id)
}

fn request_candidate(
    artifact: &SccmServerArtifactAssessment,
) -> Option<SccmSiteCoreArtifactCandidate> {
    let basename = artifact.original_basename.as_ref()?;
    let rotation = artifact.rotation.as_ref()?;
    let classified = classify_artifact_name(basename, SccmRole::SiteServer);
    (classified.supported_for_diagnosis
        && classified.role == SccmRole::SiteServer
        && classified.family == artifact.family
        && &classified.rotation == rotation)
        .then(|| SccmSiteCoreArtifactCandidate {
            basename: basename.clone(),
            rotation: rotation_name(rotation).expect("classified rotations are declared"),
        })
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
    let finding = SccmFindingBuilder::new(stable_opaque_id(
        "site-core:finding:v1:",
        &[&result.result_id],
    ))
        .class(class)
        .phase(SccmPhase::Unknown(
            result
                .last_successful_phase
                .map(SccmSiteCorePhase::serialized_name)
                .unwrap_or("siteCoreUnconfirmed")
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
    let is_coverage_gap = !observation.coverage_gap_artifact_ids.is_empty();
    let (phase, title, summary) = if is_coverage_gap {
        (
            "siteCoreCoverage",
            "Site core coverage gap",
            "The source is incomplete and cannot establish a component outcome.",
        )
    } else {
        (
            "siteCoreProfile",
            "Unrecognized site core profile record",
            "A source-local record was retained as a symptom but did not match the selected extraction profile.",
        )
    };
    let finding = SccmFindingBuilder::new(stable_opaque_id(
        "site-core:finding:v1:",
        &[&observation.observation_id],
    ))
    .class(observation.finding_class.clone())
    .phase(SccmPhase::Unknown(phase.to_owned()))
    .role(SccmRole::SiteServer)
    .severity(Severity::Warning)
    .confidence(shared_confidence(observation.confidence))
    .title(title)
    .summary(summary)
    .evidence(
        observation
            .evidence
            .iter()
            .map(SccmSiteCoreEvidence::reference)
            .collect(),
    )
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
        .flat_map(|request| request.candidates.iter())
        .filter_map(|candidate| {
            let classified = classify_artifact_name(&candidate.basename, SccmRole::SiteServer);
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

fn is_profile_record_candidate(message: &str) -> bool {
    let lowercase = message.to_ascii_lowercase();
    lowercase.contains("profileid=") || lowercase.contains("statusid=sc_")
}

fn profile_labels_are_closed(message: &str) -> bool {
    message.split(is_token_boundary).all(|token| {
        let Some((label, _)) = token.split_once('=') else {
            return true;
        };
        matches!(
            label.to_ascii_lowercase().as_str(),
            "profileid"
                | "profileversion"
                | "site"
                | "componentid"
                | "workitemid"
                | "statusid"
                | "outcome"
                | "terminal"
                | "queuedepth"
        )
    })
}

fn validated_component_id(value: &str) -> Option<String> {
    matches!(value, "SMS_EXECUTIVE" | "SMS_DISTRIBUTION_MANAGER").then(|| value.to_owned())
}

fn validated_work_item_id(value: &str) -> Option<String> {
    let suffix = value.strip_prefix("SC-")?;
    (!suffix.is_empty()
        && value.len() <= 64
        && suffix.split('-').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        }))
    .then(|| value.to_owned())
}

fn queue_depth_matches_marker(message: &str, marker: StatusMarker) -> bool {
    let Some(queue_depth) = validated_token_value(message, "queueDepth") else {
        return false;
    };
    match (marker.outcome, queue_depth) {
        (FactOutcome::Deferred, Some(value)) => value
            .parse::<u32>()
            .is_ok_and(|depth| (1..=1_000_000).contains(&depth)),
        (FactOutcome::Deferred, None) => false,
        (_, None) => true,
        (_, Some(_)) => false,
    }
}

fn reference_is_complete(evidence: &SccmEvidence) -> bool {
    safe_site_core_opaque_id(&evidence.evidence_id)
        && safe_site_core_opaque_id(&evidence.reference.artifact_id)
        && safe_site_core_opaque_id(&evidence.reference.entry_id)
        && evidence.evidence_id == evidence.reference.entry_id
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

fn evidence_collision_artifact_ids(
    evidence: &[SccmEvidence],
    identity_is_unique: &[bool],
) -> BTreeSet<String> {
    evidence
        .iter()
        .zip(identity_is_unique)
        .filter(|(_, unique)| !**unique)
        .map(|(record, _)| record.reference.artifact_id.clone())
        .collect()
}

fn site_core_coverage_is_congruent(intake: &SccmServerIntakeAssessment) -> bool {
    let mut expected = BTreeMap::<CoverageIdentityKey, Vec<String>>::new();
    for artifact in &intake.artifacts {
        if SiteCoreGroup::from_source_id(&artifact.source_id).is_none() {
            continue;
        }
        expected
            .entry(CoverageIdentityKey::from_artifact(artifact))
            .or_default()
            .push(artifact.artifact_id.clone());
    }

    let mut observed = BTreeMap::<CoverageIdentityKey, Vec<String>>::new();
    for coverage in &intake.coverage {
        if SiteCoreGroup::from_source_id(&coverage.source_id).is_none() {
            continue;
        }
        observed
            .entry(CoverageIdentityKey::from_coverage(coverage))
            .or_default()
            .extend(coverage.artifact_ids.iter().cloned());
    }
    for artifact_ids in expected.values_mut().chain(observed.values_mut()) {
        artifact_ids.sort();
    }
    expected == observed
}

fn safe_site_core_opaque_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.trim() == value
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b':' | b'_' | b'-'))
}

fn safe_site_core_host(value: &str) -> bool {
    let existing_opaque_shape = !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'-' | b'_'));
    let synthetic_digest = value
        .strip_prefix("synthetic:host:sha256.v1:")
        .is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        });
    existing_opaque_shape || synthetic_digest
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

fn stable_opaque_id(prefix: &str, parts: &[&str]) -> String {
    const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";

    let mut digest = Sha256::new();
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part.as_bytes());
    }
    let digest = digest.finalize();
    let mut encoded = String::with_capacity(prefix.len() + digest.len() * 2);
    encoded.push_str(prefix);
    for byte in digest {
        encoded.push(char::from(LOWER_HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(LOWER_HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}
