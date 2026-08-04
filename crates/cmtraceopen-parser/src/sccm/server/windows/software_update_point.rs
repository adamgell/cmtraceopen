//! Server-local Software Update Point and WSUS workflow analysis.
//!
//! The reducer consumes only the integrity-bound canonical server intake. It
//! does not consume client analyzer output and deliberately leaves cross-side
//! correlation to issue #333.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::sccm::{SccmCoverageState, SccmEvidence, SccmRole, SccmTimeOrderingState};

use super::{SccmServerArtifactAssessment, SccmServerIntakeAssessment};

pub const SCCM_SOFTWARE_UPDATE_POINT_SYNC_SOURCE_ID: &str = "server-sup-sync";
pub const SCCM_SOFTWARE_UPDATE_POINT_WSUS_SOURCE_ID: &str = "server-sup-wsus";
pub const SCCM_SOFTWARE_UPDATE_POINT_PROFILE_ID: &str = "sup-server-5.00.test-v1";
pub const SCCM_SOFTWARE_UPDATE_POINT_SOURCE_VERSION: &str = "5.00.TEST.0001";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmSoftwareUpdatePointWorkflow {
    SoftwareUpdatePoint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmSoftwareUpdatePointPhase {
    Configure,
    Synchronize,
    ImportOrProcessMetadata,
    ValidateWsus,
    PublishAvailability,
    HealthyOrTerminal,
}

impl SccmSoftwareUpdatePointPhase {
    fn rank(self) -> usize {
        match self {
            Self::Configure => 0,
            Self::Synchronize => 1,
            Self::ImportOrProcessMetadata => 2,
            Self::ValidateWsus => 3,
            Self::PublishAvailability => 4,
            Self::HealthyOrTerminal => 5,
        }
    }

    fn observation_suffix(self, disposition: SccmSoftwareUpdatePointDisposition) -> &'static str {
        if disposition == SccmSoftwareUpdatePointDisposition::Retrying {
            return "retry";
        }
        match self {
            Self::Configure => "configure",
            Self::Synchronize => "synchronize",
            Self::ImportOrProcessMetadata => "import",
            Self::ValidateWsus => "validate",
            Self::PublishAvailability => "publish",
            Self::HealthyOrTerminal => "terminal",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmSoftwareUpdatePointDisposition {
    Succeeded,
    Failed,
    Retrying,
    Deferred,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmSoftwareUpdatePointState {
    Succeeded,
    Failed,
    Deferred,
    Incomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmSoftwareUpdatePointClassification {
    Success,
    ConfirmedFailure,
    BlockedOrDeferred,
    InsufficientEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmSoftwareUpdatePointConfidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmSoftwareUpdatePointKeyConfidence {
    Exact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmSoftwareUpdatePointTopologyCompatibility {
    Exact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmSoftwareUpdatePointProfileSelection {
    SelectedSynthetic,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmSoftwareUpdatePointMissingPathInterpretation {
    SourceCoverageOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmSoftwareUpdatePointSourceLocalClassification {
    RotationSplit,
    MalformedEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmSoftwareUpdatePointRequestReason {
    CoverageAbsent,
    CoverageAccessDenied,
    CoverageCapped,
    CoverageMalformed,
    CoverageRotationSplit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmSoftwareUpdatePointAnalysisContract {
    pub independent_reducer: bool,
    pub consumes_client_output: bool,
    pub cross_side_correlation_performed: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmSoftwareUpdatePointExtractionProfile {
    pub selection_state: SccmSoftwareUpdatePointProfileSelection,
    pub profile_id: Option<String>,
    pub validated_role: Option<SccmRole>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmSoftwareUpdatePointRoleAssessment {
    pub software_update_point_observed: bool,
    pub role_absent_inferred: bool,
    pub missing_default_path_interpretation: SccmSoftwareUpdatePointMissingPathInterpretation,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmSoftwareUpdatePointCoverage {
    pub artifact_id: String,
    pub state: SccmCoverageState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmSoftwareUpdatePointKey {
    pub sync_run_id: String,
    pub site_code: String,
    pub sup_handle: String,
    pub update_id: Option<String>,
    pub kb_id: Option<String>,
    pub confidence: SccmSoftwareUpdatePointKeyConfidence,
    pub extraction_profile_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmSoftwareUpdatePointEvidence {
    pub artifact_id: String,
    pub start_line: u32,
    pub end_line: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmSoftwareUpdatePointObservation {
    pub observation_id: String,
    pub phase: SccmSoftwareUpdatePointPhase,
    pub disposition: SccmSoftwareUpdatePointDisposition,
    pub terminal: bool,
    pub evidence: Vec<SccmSoftwareUpdatePointEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmSoftwareUpdatePointTransaction {
    pub transaction_id: String,
    pub key: SccmSoftwareUpdatePointKey,
    pub topology_compatibility: SccmSoftwareUpdatePointTopologyCompatibility,
    pub correlation_eligible: bool,
    pub state: SccmSoftwareUpdatePointState,
    pub classification: SccmSoftwareUpdatePointClassification,
    pub confidence: SccmSoftwareUpdatePointConfidence,
    pub confidence_ceiling: SccmSoftwareUpdatePointConfidence,
    pub last_successful_phase: Option<SccmSoftwareUpdatePointPhase>,
    pub next_source_id: Option<String>,
    pub coverage_gap_artifact_ids: Vec<String>,
    pub observations: Vec<SccmSoftwareUpdatePointObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmSoftwareUpdatePointSourceLocalObservation {
    pub observation_id: String,
    pub classification: SccmSoftwareUpdatePointSourceLocalClassification,
    pub confidence: SccmSoftwareUpdatePointConfidence,
    pub confidence_ceiling: SccmSoftwareUpdatePointConfidence,
    pub correlation_eligible: bool,
    pub artifact_ids: Vec<String>,
    pub evidence: Vec<SccmSoftwareUpdatePointEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmSoftwareUpdatePointArtifactRequest {
    pub sup_handle: String,
    pub source_id: String,
    pub reason_code: SccmSoftwareUpdatePointRequestReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmSoftwareUpdatePointCorrelationHandoff {
    pub issue: String,
    pub performed: bool,
    pub time_only_eligible: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmSoftwareUpdatePointAnalysis {
    pub workflow: SccmSoftwareUpdatePointWorkflow,
    pub state_chain: Vec<SccmSoftwareUpdatePointPhase>,
    pub analysis_contract: SccmSoftwareUpdatePointAnalysisContract,
    pub extraction_profile: SccmSoftwareUpdatePointExtractionProfile,
    pub role_assessment: SccmSoftwareUpdatePointRoleAssessment,
    pub coverage: Vec<SccmSoftwareUpdatePointCoverage>,
    pub transactions: Vec<SccmSoftwareUpdatePointTransaction>,
    pub source_local_observations: Vec<SccmSoftwareUpdatePointSourceLocalObservation>,
    pub artifact_requests: Vec<SccmSoftwareUpdatePointArtifactRequest>,
    pub client_causal_claims: Vec<String>,
    pub correlation_handoff: SccmSoftwareUpdatePointCorrelationHandoff,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FactKey {
    sync_run_id: String,
    site_code: String,
    sup_handle: String,
    update_id: Option<String>,
    kb_id: Option<String>,
    profile_id: String,
}

#[derive(Debug, Clone)]
struct Fact {
    key: FactKey,
    phase: SccmSoftwareUpdatePointPhase,
    disposition: SccmSoftwareUpdatePointDisposition,
    terminal: bool,
    evidence: SccmSoftwareUpdatePointEvidence,
    utc_millis: i64,
}

pub fn analyze_software_update_point(
    intake: &SccmServerIntakeAssessment,
) -> SccmSoftwareUpdatePointAnalysis {
    if !intake.adapter_authority_is_intake_bound() || !intake.topology_authority_is_intake_bound() {
        return empty_analysis(false);
    }

    let scoped_artifacts = intake
        .artifacts
        .iter()
        .filter(|artifact| is_scoped_artifact(artifact))
        .collect::<Vec<_>>();
    let sup_observed = intake
        .topology
        .roles_observed
        .contains(&SccmRole::SoftwareUpdatePoint);
    let synthetic_profile_selected = scoped_artifacts
        .iter()
        .any(|artifact| artifact.source_id == SCCM_SOFTWARE_UPDATE_POINT_SYNC_SOURCE_ID)
        && scoped_artifacts.iter().all(|artifact| {
            artifact.source_id != SCCM_SOFTWARE_UPDATE_POINT_SYNC_SOURCE_ID
                || (artifact.profile_eligible
                    && artifact.source_version.as_deref()
                        == Some(SCCM_SOFTWARE_UPDATE_POINT_SOURCE_VERSION))
        });

    let mut coverage = scoped_artifacts
        .iter()
        .map(|artifact| SccmSoftwareUpdatePointCoverage {
            artifact_id: artifact.artifact_id.clone(),
            state: artifact.state.clone(),
        })
        .collect::<Vec<_>>();
    coverage.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));

    let gap_artifacts = scoped_artifacts
        .iter()
        .copied()
        .filter(|artifact| {
            artifact.producer_role != SccmRole::Client
                && (artifact.state != SccmCoverageState::Captured
                    || artifact.fragment_complete == Some(false))
        })
        .collect::<Vec<_>>();
    let artifact_requests = artifact_requests(&gap_artifacts);
    let source_local_observations = source_local_observations(&scoped_artifacts);

    let mut facts_by_key = BTreeMap::<FactKey, Vec<Fact>>::new();
    for artifact in &scoped_artifacts {
        if !synthetic_profile_selected || !artifact_admits_transaction_facts(artifact) {
            continue;
        }
        for evidence in intake
            .evidence
            .iter()
            .filter(|evidence| evidence.reference.artifact_id == artifact.artifact_id)
        {
            if let Some(fact) = parse_fact(intake, artifact, evidence) {
                facts_by_key.entry(fact.key.clone()).or_default().push(fact);
            }
        }
    }

    reject_conflicting_transaction_keys(&mut facts_by_key);
    let mut transactions = facts_by_key
        .into_iter()
        .filter_map(|(key, facts)| reduce_transaction(key, facts, &scoped_artifacts))
        .collect::<Vec<_>>();
    transactions.sort_by(|left, right| left.transaction_id.cmp(&right.transaction_id));

    SccmSoftwareUpdatePointAnalysis {
        workflow: SccmSoftwareUpdatePointWorkflow::SoftwareUpdatePoint,
        state_chain: state_chain(),
        analysis_contract: analysis_contract(),
        extraction_profile: extraction_profile(synthetic_profile_selected),
        role_assessment: role_assessment(sup_observed),
        coverage,
        transactions,
        source_local_observations,
        artifact_requests,
        client_causal_claims: Vec::new(),
        correlation_handoff: correlation_handoff(),
    }
}

fn empty_analysis(sup_observed: bool) -> SccmSoftwareUpdatePointAnalysis {
    SccmSoftwareUpdatePointAnalysis {
        workflow: SccmSoftwareUpdatePointWorkflow::SoftwareUpdatePoint,
        state_chain: state_chain(),
        analysis_contract: analysis_contract(),
        extraction_profile: extraction_profile(false),
        role_assessment: role_assessment(sup_observed),
        coverage: Vec::new(),
        transactions: Vec::new(),
        source_local_observations: Vec::new(),
        artifact_requests: Vec::new(),
        client_causal_claims: Vec::new(),
        correlation_handoff: correlation_handoff(),
    }
}

fn state_chain() -> Vec<SccmSoftwareUpdatePointPhase> {
    vec![
        SccmSoftwareUpdatePointPhase::Configure,
        SccmSoftwareUpdatePointPhase::Synchronize,
        SccmSoftwareUpdatePointPhase::ImportOrProcessMetadata,
        SccmSoftwareUpdatePointPhase::ValidateWsus,
        SccmSoftwareUpdatePointPhase::PublishAvailability,
        SccmSoftwareUpdatePointPhase::HealthyOrTerminal,
    ]
}

fn analysis_contract() -> SccmSoftwareUpdatePointAnalysisContract {
    SccmSoftwareUpdatePointAnalysisContract {
        independent_reducer: true,
        consumes_client_output: false,
        cross_side_correlation_performed: false,
    }
}

fn extraction_profile(selected: bool) -> SccmSoftwareUpdatePointExtractionProfile {
    if selected {
        SccmSoftwareUpdatePointExtractionProfile {
            selection_state: SccmSoftwareUpdatePointProfileSelection::SelectedSynthetic,
            profile_id: Some(SCCM_SOFTWARE_UPDATE_POINT_PROFILE_ID.to_owned()),
            validated_role: Some(SccmRole::SoftwareUpdatePoint),
        }
    } else {
        SccmSoftwareUpdatePointExtractionProfile {
            selection_state: SccmSoftwareUpdatePointProfileSelection::Unavailable,
            profile_id: None,
            validated_role: None,
        }
    }
}

fn role_assessment(sup_observed: bool) -> SccmSoftwareUpdatePointRoleAssessment {
    SccmSoftwareUpdatePointRoleAssessment {
        software_update_point_observed: sup_observed,
        role_absent_inferred: false,
        missing_default_path_interpretation:
            SccmSoftwareUpdatePointMissingPathInterpretation::SourceCoverageOnly,
    }
}

fn correlation_handoff() -> SccmSoftwareUpdatePointCorrelationHandoff {
    SccmSoftwareUpdatePointCorrelationHandoff {
        issue: "#333".to_owned(),
        performed: false,
        time_only_eligible: false,
    }
}

fn is_scoped_artifact(artifact: &SccmServerArtifactAssessment) -> bool {
    artifact.workflow_subject_role == Some(SccmRole::SoftwareUpdatePoint)
        && matches!(
            artifact.source_id.as_str(),
            SCCM_SOFTWARE_UPDATE_POINT_SYNC_SOURCE_ID | SCCM_SOFTWARE_UPDATE_POINT_WSUS_SOURCE_ID
        )
}

fn artifact_admits_transaction_facts(artifact: &SccmServerArtifactAssessment) -> bool {
    artifact.source_id == SCCM_SOFTWARE_UPDATE_POINT_SYNC_SOURCE_ID
        && artifact.state == SccmCoverageState::Captured
        && artifact.fragment_complete != Some(false)
        && artifact.parser_eligible
        && artifact.profile_eligible
        && artifact.source_version.as_deref() == Some(SCCM_SOFTWARE_UPDATE_POINT_SOURCE_VERSION)
        && artifact.workflow_subject_role == Some(SccmRole::SoftwareUpdatePoint)
        && artifact.workflow_subject_handle.is_some()
        && matches!(
            (
                artifact.producer_role.clone(),
                artifact.original_basename.as_deref()
            ),
            (SccmRole::SiteServer, Some("WCM.log" | "wsyncmgr.log"))
                | (
                    SccmRole::SoftwareUpdatePoint,
                    Some("SUPSetup.log" | "WSUSCtrl.log")
                )
        )
}

fn parse_fact(
    intake: &SccmServerIntakeAssessment,
    artifact: &SccmServerArtifactAssessment,
    evidence: &SccmEvidence,
) -> Option<Fact> {
    let fields = parse_fixture_fields(&evidence.message)?;
    if fields.contains_key("ClientHandle") {
        return None;
    }
    let phase = parse_phase(fields.get("Phase")?)?;
    if !phase_allowed_for_artifact(artifact.original_basename.as_deref()?, phase) {
        return None;
    }
    let disposition = parse_disposition(fields.get("Disposition")?)?;
    let terminal = match fields.get("Terminal")?.as_str() {
        "true" => true,
        "false" => false,
        _ => return None,
    };
    if !coherent_disposition(phase, disposition, terminal) {
        return None;
    }

    let sync_run_id = fields.get("SyncRunId")?.clone();
    let site_code = fields.get("SiteCode")?.clone();
    let sup_handle = fields.get("SupHandle")?.clone();
    let profile_id = fields.get("ProfileId")?.clone();
    if !site_code_is_topology_compatible(&site_code, &intake.topology.site_handle)
        || artifact.workflow_subject_handle.as_deref() != Some(sup_handle.as_str())
        || profile_id != SCCM_SOFTWARE_UPDATE_POINT_PROFILE_ID
    {
        return None;
    }
    let (update_id, kb_id) = match (fields.get("UpdateId"), fields.get("KbId")) {
        (Some(update_id), Some(kb_id)) => (Some(update_id.clone()), Some(kb_id.clone())),
        (None, None) => (None, None),
        _ => return None,
    };
    let start_line = evidence.reference.line_start?;
    let end_line = evidence.reference.line_end?;
    let utc_millis = evidence.timestamp.utc_millis?;
    if start_line == 0
        || end_line < start_line
        || evidence.timestamp.ordering_state != SccmTimeOrderingState::NormalizedUtc
    {
        return None;
    }

    Some(Fact {
        key: FactKey {
            sync_run_id,
            site_code,
            sup_handle,
            update_id,
            kb_id,
            profile_id,
        },
        phase,
        disposition,
        terminal,
        evidence: SccmSoftwareUpdatePointEvidence {
            artifact_id: evidence.reference.artifact_id.clone(),
            start_line,
            end_line,
        },
        utc_millis,
    })
}

fn site_code_is_topology_compatible(site_code: &str, site_handle: &str) -> bool {
    site_code == site_handle || (site_code == "LAB" && site_handle == "synthetic:site:lab")
}

fn parse_fixture_fields(message: &str) -> Option<BTreeMap<&str, String>> {
    let message = message.strip_prefix("[sccm-public-message-v1] ")?;
    let mut segments = message.split(';').map(str::trim);
    if segments.next()? != "SYNTHETIC FIXTURE" {
        return None;
    }
    let allowed = [
        "Phase",
        "Disposition",
        "Terminal",
        "SyncRunId",
        "SiteCode",
        "SupHandle",
        "ProfileId",
        "UpdateId",
        "KbId",
        "ClientHandle",
    ];
    let mut fields = BTreeMap::new();
    for segment in segments {
        let (name, value) = segment.split_once('=')?;
        if !allowed.contains(&name)
            || value.is_empty()
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b':' | b'_' | b'-')
            })
            || fields.insert(name, value.to_owned()).is_some()
        {
            return None;
        }
    }
    Some(fields)
}

fn parse_phase(value: &str) -> Option<SccmSoftwareUpdatePointPhase> {
    Some(match value {
        "configure" => SccmSoftwareUpdatePointPhase::Configure,
        "synchronize" => SccmSoftwareUpdatePointPhase::Synchronize,
        "importOrProcessMetadata" => SccmSoftwareUpdatePointPhase::ImportOrProcessMetadata,
        "validateWsus" => SccmSoftwareUpdatePointPhase::ValidateWsus,
        "publishAvailability" => SccmSoftwareUpdatePointPhase::PublishAvailability,
        "healthyOrTerminal" => SccmSoftwareUpdatePointPhase::HealthyOrTerminal,
        _ => return None,
    })
}

fn parse_disposition(value: &str) -> Option<SccmSoftwareUpdatePointDisposition> {
    Some(match value {
        "succeeded" => SccmSoftwareUpdatePointDisposition::Succeeded,
        "failed" => SccmSoftwareUpdatePointDisposition::Failed,
        "retrying" => SccmSoftwareUpdatePointDisposition::Retrying,
        "deferred" => SccmSoftwareUpdatePointDisposition::Deferred,
        _ => return None,
    })
}

fn coherent_disposition(
    phase: SccmSoftwareUpdatePointPhase,
    disposition: SccmSoftwareUpdatePointDisposition,
    terminal: bool,
) -> bool {
    match (disposition, terminal) {
        (SccmSoftwareUpdatePointDisposition::Succeeded, true) => {
            phase == SccmSoftwareUpdatePointPhase::HealthyOrTerminal
        }
        (SccmSoftwareUpdatePointDisposition::Succeeded, false) => true,
        (SccmSoftwareUpdatePointDisposition::Failed, true) => true,
        (
            SccmSoftwareUpdatePointDisposition::Retrying
            | SccmSoftwareUpdatePointDisposition::Deferred,
            false,
        ) => true,
        _ => false,
    }
}

fn phase_allowed_for_artifact(basename: &str, phase: SccmSoftwareUpdatePointPhase) -> bool {
    matches!(
        (basename, phase),
        ("WCM.log", SccmSoftwareUpdatePointPhase::Configure)
            | (
                "wsyncmgr.log",
                SccmSoftwareUpdatePointPhase::Synchronize
                    | SccmSoftwareUpdatePointPhase::ImportOrProcessMetadata
                    | SccmSoftwareUpdatePointPhase::PublishAvailability
                    | SccmSoftwareUpdatePointPhase::HealthyOrTerminal
            )
            | (
                "SUPSetup.log",
                SccmSoftwareUpdatePointPhase::Configure
                    | SccmSoftwareUpdatePointPhase::HealthyOrTerminal
            )
            | (
                "WSUSCtrl.log",
                SccmSoftwareUpdatePointPhase::ValidateWsus
                    | SccmSoftwareUpdatePointPhase::HealthyOrTerminal
            )
    )
}

fn reject_conflicting_transaction_keys(facts_by_key: &mut BTreeMap<FactKey, Vec<Fact>>) {
    let mut base_key_counts = BTreeMap::<(String, String, String, String), usize>::new();
    for key in facts_by_key.keys() {
        *base_key_counts
            .entry((
                key.sync_run_id.clone(),
                key.site_code.clone(),
                key.sup_handle.clone(),
                key.profile_id.clone(),
            ))
            .or_default() += 1;
    }
    facts_by_key.retain(|key, _| {
        base_key_counts.get(&(
            key.sync_run_id.clone(),
            key.site_code.clone(),
            key.sup_handle.clone(),
            key.profile_id.clone(),
        )) == Some(&1)
    });
}

fn reduce_transaction(
    key: FactKey,
    mut facts: Vec<Fact>,
    scoped_artifacts: &[&SccmServerArtifactAssessment],
) -> Option<SccmSoftwareUpdatePointTransaction> {
    facts.sort_by(|left, right| {
        (left.utc_millis, left.phase.rank()).cmp(&(right.utc_millis, right.phase.rank()))
    });
    if facts
        .first()
        .is_none_or(|fact| fact.phase != SccmSoftwareUpdatePointPhase::Configure)
        || !fact_chain_is_valid(&facts)
    {
        return None;
    }

    let mut last_successful_phase = None;
    let mut terminal_success = false;
    let mut terminal_failure = false;
    let mut deferred = false;
    let observations = facts
        .iter()
        .enumerate()
        .map(|(index, fact)| {
            if fact.disposition == SccmSoftwareUpdatePointDisposition::Succeeded {
                last_successful_phase = Some(fact.phase);
                terminal_success |= fact.terminal;
            } else if fact.disposition == SccmSoftwareUpdatePointDisposition::Failed {
                terminal_failure |= fact.terminal;
            } else {
                deferred = true;
            }
            SccmSoftwareUpdatePointObservation {
                observation_id: format!(
                    "{}-{:02}-{}",
                    key.sync_run_id,
                    index + 1,
                    fact.phase.observation_suffix(fact.disposition)
                ),
                phase: fact.phase,
                disposition: fact.disposition,
                terminal: fact.terminal,
                evidence: vec![fact.evidence.clone()],
            }
        })
        .collect::<Vec<_>>();

    let subject_artifacts = scoped_artifacts
        .iter()
        .copied()
        .filter(|artifact| artifact.workflow_subject_handle.as_deref() == Some(&key.sup_handle))
        .collect::<Vec<_>>();
    let gap_artifacts = subject_artifacts
        .iter()
        .copied()
        .filter(|artifact| {
            artifact.state != SccmCoverageState::Captured
                || artifact.fragment_complete == Some(false)
        })
        .collect::<Vec<_>>();
    let mut coverage_gap_artifact_ids = gap_artifacts
        .iter()
        .map(|artifact| artifact.artifact_id.clone())
        .collect::<Vec<_>>();
    coverage_gap_artifact_ids.sort();
    coverage_gap_artifact_ids.dedup();
    let required_gap = gap_artifacts
        .iter()
        .any(|artifact| artifact.source_id == SCCM_SOFTWARE_UPDATE_POINT_SYNC_SOURCE_ID);
    // The profile-defined supplement is sealed by intake but has no reviewed
    // semantic extractor yet. Its mere presence, including a captured payload,
    // therefore keeps otherwise conclusive output at medium confidence.
    let optional_supplement_uninterpreted = subject_artifacts
        .iter()
        .any(|artifact| artifact.source_id == SCCM_SOFTWARE_UPDATE_POINT_WSUS_SOURCE_ID);

    let (state, classification, confidence) = if required_gap {
        (
            SccmSoftwareUpdatePointState::Incomplete,
            SccmSoftwareUpdatePointClassification::InsufficientEvidence,
            SccmSoftwareUpdatePointConfidence::Low,
        )
    } else if terminal_success && !terminal_failure {
        (
            SccmSoftwareUpdatePointState::Succeeded,
            SccmSoftwareUpdatePointClassification::Success,
            if optional_supplement_uninterpreted {
                SccmSoftwareUpdatePointConfidence::Medium
            } else {
                SccmSoftwareUpdatePointConfidence::High
            },
        )
    } else if terminal_failure && !terminal_success {
        (
            SccmSoftwareUpdatePointState::Failed,
            SccmSoftwareUpdatePointClassification::ConfirmedFailure,
            if optional_supplement_uninterpreted {
                SccmSoftwareUpdatePointConfidence::Medium
            } else {
                SccmSoftwareUpdatePointConfidence::High
            },
        )
    } else if deferred && !terminal_failure && !terminal_success {
        (
            SccmSoftwareUpdatePointState::Deferred,
            SccmSoftwareUpdatePointClassification::BlockedOrDeferred,
            SccmSoftwareUpdatePointConfidence::Medium,
        )
    } else {
        (
            SccmSoftwareUpdatePointState::Incomplete,
            SccmSoftwareUpdatePointClassification::InsufficientEvidence,
            SccmSoftwareUpdatePointConfidence::Low,
        )
    };
    let next_source_id = (state == SccmSoftwareUpdatePointState::Incomplete)
        .then(|| {
            gap_artifacts
                .iter()
                .filter(|artifact| artifact.source_id == SCCM_SOFTWARE_UPDATE_POINT_SYNC_SOURCE_ID)
                .map(|artifact| artifact.source_id.as_str())
                .min()
                .map(str::to_owned)
        })
        .flatten();
    let transaction_id = match &key.update_id {
        Some(update_id) => format!(
            "sup:{}:{}:{}:{}",
            key.sync_run_id, key.site_code, key.sup_handle, update_id
        ),
        None => format!(
            "sup:{}:{}:{}",
            key.sync_run_id, key.site_code, key.sup_handle
        ),
    };

    Some(SccmSoftwareUpdatePointTransaction {
        transaction_id,
        key: SccmSoftwareUpdatePointKey {
            sync_run_id: key.sync_run_id,
            site_code: key.site_code,
            sup_handle: key.sup_handle,
            update_id: key.update_id,
            kb_id: key.kb_id,
            confidence: SccmSoftwareUpdatePointKeyConfidence::Exact,
            extraction_profile_id: key.profile_id,
        },
        topology_compatibility: SccmSoftwareUpdatePointTopologyCompatibility::Exact,
        correlation_eligible: true,
        state,
        classification,
        confidence,
        confidence_ceiling: confidence,
        last_successful_phase,
        next_source_id,
        coverage_gap_artifact_ids,
        observations,
    })
}

fn fact_chain_is_valid(facts: &[Fact]) -> bool {
    let mut previous_phase = None;
    let mut previous_utc = None;
    let mut terminal_seen = false;
    let mut evidence = BTreeSet::new();
    for fact in facts {
        if terminal_seen
            || previous_phase.is_some_and(|phase| fact.phase.rank() <= phase)
            || previous_utc.is_some_and(|utc| fact.utc_millis <= utc)
            || !evidence.insert((
                fact.evidence.artifact_id.as_str(),
                fact.evidence.start_line,
                fact.evidence.end_line,
            ))
        {
            return false;
        }
        if let Some(previous) = previous_phase {
            if fact.phase.rank() != previous + 1 {
                return false;
            }
        }
        previous_phase = Some(fact.phase.rank());
        previous_utc = Some(fact.utc_millis);
        terminal_seen = fact.terminal;
    }
    true
}

fn source_local_observations(
    scoped_artifacts: &[&SccmServerArtifactAssessment],
) -> Vec<SccmSoftwareUpdatePointSourceLocalObservation> {
    let mut observations = Vec::new();
    let mut ordinal = 1usize;
    let mut split_groups = BTreeMap::<(String, String, String, String), Vec<String>>::new();
    for artifact in scoped_artifacts.iter().filter(|artifact| {
        artifact.producer_role != SccmRole::Client
            && artifact.state == SccmCoverageState::Captured
            && artifact.fragment_complete == Some(false)
    }) {
        split_groups
            .entry((
                artifact.producer_host_handle.clone().unwrap_or_default(),
                artifact.workflow_subject_handle.clone().unwrap_or_default(),
                artifact.source_id.clone(),
                artifact.rotation_lineage_handle.clone(),
            ))
            .or_default()
            .push(artifact.artifact_id.clone());
    }
    for mut artifact_ids in split_groups.into_values().filter(|ids| ids.len() > 1) {
        artifact_ids.sort();
        let prefix = artifact_prefix(&artifact_ids[0]);
        observations.push(source_local_observation(
            format!("{prefix}-{ordinal:02}-split"),
            SccmSoftwareUpdatePointSourceLocalClassification::RotationSplit,
            artifact_ids,
            Vec::new(),
        ));
        ordinal += 1;
    }

    let mut malformed_artifacts = scoped_artifacts
        .iter()
        .filter(|artifact| {
            artifact.producer_role != SccmRole::Client
                && artifact.state == SccmCoverageState::ParseFailed
        })
        .copied()
        .collect::<Vec<_>>();
    malformed_artifacts.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
    for artifact in malformed_artifacts {
        let prefix = artifact_prefix(&artifact.artifact_id);
        observations.push(source_local_observation(
            format!("{prefix}-{ordinal:02}-malformed"),
            SccmSoftwareUpdatePointSourceLocalClassification::MalformedEvidence,
            vec![artifact.artifact_id.clone()],
            Vec::new(),
        ));
        ordinal += 1;
    }

    observations.sort_by(|left, right| left.observation_id.cmp(&right.observation_id));
    observations
}

fn artifact_prefix(artifact_id: &str) -> &str {
    artifact_id.split('-').next().unwrap_or("source")
}

fn source_local_observation(
    observation_id: String,
    classification: SccmSoftwareUpdatePointSourceLocalClassification,
    artifact_ids: Vec<String>,
    evidence: Vec<SccmSoftwareUpdatePointEvidence>,
) -> SccmSoftwareUpdatePointSourceLocalObservation {
    SccmSoftwareUpdatePointSourceLocalObservation {
        observation_id,
        classification,
        confidence: SccmSoftwareUpdatePointConfidence::Low,
        confidence_ceiling: SccmSoftwareUpdatePointConfidence::Low,
        correlation_eligible: false,
        artifact_ids,
        evidence,
    }
}

fn artifact_requests(
    gap_artifacts: &[&SccmServerArtifactAssessment],
) -> Vec<SccmSoftwareUpdatePointArtifactRequest> {
    let mut requests = BTreeSet::new();
    for artifact in gap_artifacts {
        if artifact.source_id != SCCM_SOFTWARE_UPDATE_POINT_SYNC_SOURCE_ID {
            continue;
        }
        let state_reason = match artifact.state {
            SccmCoverageState::Absent => Some(SccmSoftwareUpdatePointRequestReason::CoverageAbsent),
            SccmCoverageState::AccessDenied => {
                Some(SccmSoftwareUpdatePointRequestReason::CoverageAccessDenied)
            }
            SccmCoverageState::Capped => Some(SccmSoftwareUpdatePointRequestReason::CoverageCapped),
            SccmCoverageState::ParseFailed => {
                Some(SccmSoftwareUpdatePointRequestReason::CoverageMalformed)
            }
            SccmCoverageState::Captured
            | SccmCoverageState::Skipped
            | SccmCoverageState::Unsupported => None,
        };
        if let Some(reason_code) = state_reason {
            let Some(sup_handle) = artifact.workflow_subject_handle.clone() else {
                continue;
            };
            requests.insert(SccmSoftwareUpdatePointArtifactRequest {
                sup_handle,
                source_id: artifact.source_id.clone(),
                reason_code,
            });
        }
        if artifact.fragment_complete == Some(false) {
            let Some(sup_handle) = artifact.workflow_subject_handle.clone() else {
                continue;
            };
            requests.insert(SccmSoftwareUpdatePointArtifactRequest {
                sup_handle,
                source_id: artifact.source_id.clone(),
                reason_code: SccmSoftwareUpdatePointRequestReason::CoverageRotationSplit,
            });
        }
    }
    requests.into_iter().collect()
}
