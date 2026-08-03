//! Server-local Management Point analysis for issue #328.
//!
//! The only selected extraction profile in this slice is
//! `mp-server-5.00.test-v1` for the synthetic `5.00.TEST` corpus. A
//! transaction requires an exact request ID, optional exact policy ID, safe
//! client handle, canonical site code, compatible Management Point handle,
//! source ownership, complete physical provenance, and usable ordering
//! provenance. `counterpart_ready_facts` are the contractual #333 handoff;
//! this module never performs client/server correlation or infers a client
//! cause.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use thiserror::Error;

use crate::models::log_entry::Severity;
use crate::sccm::findings::evidence_references_overlap;
use crate::sccm::{
    classify_artifact_name, SccmArtifact, SccmArtifactFamily, SccmArtifactRequest, SccmConfidence,
    SccmCoverageState, SccmEvidence, SccmEvidenceRef, SccmFinding, SccmFindingBuilder,
    SccmFindingClass, SccmFindingCoverageGap, SccmKeyConfidence, SccmPhase, SccmRole,
    SccmTerminalEvidence, SccmTimestamp,
};

use super::intake::{SccmServerArtifactAssessment, SccmServerIntakeAssessment};

pub const SCCM_MANAGEMENT_POINT_ANALYSIS_SCHEMA_VERSION: u32 = 1;
pub const SCCM_MANAGEMENT_POINT_TEST_PROFILE_ID: &str = "mp-server-5.00.test-v1";

const MP_TEST_VERSION: &str = "5.00.TEST";
const MP_AUTH_GROUP: &str = "server-mp-auth";
const MP_POLICY_GROUP: &str = "server-mp-policy";
const MP_IIS_GROUP: &str = "server-mp-iis";

/// Canonical server intake rejected a source or topology before it reached
/// Management Point reduction. Callers must retain the intake assessment and
/// its coverage output rather than attempting a role diagnosis from a partial
/// substitute bundle.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum SccmManagementPointIntakeError {
    #[error("canonical server intake has no compatible Management Point topology")]
    TopologyMismatch,
    #[error("canonical Management Point source has an incompatible producer role: {artifact_id}")]
    RoleMismatch { artifact_id: String },
    #[error(
        "canonical Management Point source has an unsupported extraction profile: {artifact_id}"
    )]
    ProfileMismatch { artifact_id: String },
    #[error("canonical server intake has an incompatible Management Point source: {artifact_id}")]
    SourceMismatch { artifact_id: String },
    #[error("canonical Management Point source is incomplete or non-captured: {artifact_id}")]
    IncompleteSource { artifact_id: String },
}

const STATE_CHAIN: [SccmManagementPointPhase; 6] = [
    SccmManagementPointPhase::ReceiveRequest,
    SccmManagementPointPhase::Authenticate,
    SccmManagementPointPhase::RegisterOrIdentify,
    SccmManagementPointPhase::ResolveLocationOrPolicy,
    SccmManagementPointPhase::Respond,
    SccmManagementPointPhase::RecordOutcome,
];

#[derive(Debug, Clone, PartialEq)]
pub struct SccmManagementPointTopology {
    pub site_code: String,
    pub management_point_host_handle: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SccmManagementPointSource {
    pub artifact: SccmArtifact,
    pub source_group: String,
    pub producer: String,
    pub fragment_complete: Option<bool>,
    pub physical_line_end: Option<u32>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SccmManagementPointBundle {
    pub topology: SccmManagementPointTopology,
    pub sources: Vec<SccmManagementPointSource>,
    pub evidence: Vec<SccmEvidence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmServerWorkflow {
    ManagementPoint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmManagementPointPhase {
    ReceiveRequest,
    Authenticate,
    RegisterOrIdentify,
    ResolveLocationOrPolicy,
    Respond,
    RecordOutcome,
}

impl SccmManagementPointPhase {
    fn serialized_name(self) -> &'static str {
        match self {
            Self::ReceiveRequest => "receiveRequest",
            Self::Authenticate => "authenticate",
            Self::RegisterOrIdentify => "registerOrIdentify",
            Self::ResolveLocationOrPolicy => "resolveLocationOrPolicy",
            Self::Respond => "respond",
            Self::RecordOutcome => "recordOutcome",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmManagementPointState {
    Succeeded,
    Failed,
    Deferred,
    Incomplete,
    Contradictory,
    Observed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmManagementPointClassification {
    Success,
    ConfirmedFailure,
    BlockedOrDeferred,
    InsufficientEvidence,
    ContradictoryEvidence,
    LowConfidenceSymptom,
    IncompatibleKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmManagementPointConfidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmManagementPointKey {
    pub request_id: String,
    pub policy_id: Option<String>,
    pub client_handle: String,
    pub site_code: String,
    pub management_point_host_handle: String,
    pub confidence: SccmKeyConfidence,
    pub extraction_profile_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmManagementPointArtifactRequest {
    pub logical_artifact_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmManagementPointObservation {
    pub observation_id: String,
    pub phase: SccmManagementPointPhase,
    pub state: SccmManagementPointState,
    pub classification: SccmManagementPointClassification,
    pub timestamp: SccmTimestamp,
    pub evidence: Vec<SccmEvidenceRef>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmManagementPointTransaction {
    pub transaction_id: String,
    pub key: SccmManagementPointKey,
    pub phase: SccmManagementPointPhase,
    pub state: SccmManagementPointState,
    pub last_successful_phase: Option<SccmManagementPointPhase>,
    pub classification: SccmManagementPointClassification,
    pub confidence: SccmManagementPointConfidence,
    pub evidence: Vec<SccmEvidenceRef>,
    pub observations: Vec<SccmManagementPointObservation>,
    pub coverage_gap_artifact_ids: Vec<String>,
    pub next_artifacts: Vec<SccmManagementPointArtifactRequest>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmManagementPointSourceLocalObservation {
    pub observation_id: String,
    pub phase: SccmManagementPointPhase,
    pub state: SccmManagementPointState,
    pub classification: SccmManagementPointClassification,
    pub confidence: SccmManagementPointConfidence,
    pub correlation_eligible: bool,
    pub evidence: Vec<SccmEvidenceRef>,
    pub next_artifacts: Vec<SccmManagementPointArtifactRequest>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmManagementPointCoverageGap {
    pub logical_artifact_id: String,
    pub role: SccmRole,
    pub state: SccmCoverageState,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmManagementPointCounterpartReadyFact {
    pub transaction_id: String,
    pub key: SccmManagementPointKey,
    pub phase: SccmManagementPointPhase,
    pub state: SccmManagementPointState,
    pub classification: SccmManagementPointClassification,
    pub confidence: SccmManagementPointConfidence,
    pub timestamp: SccmTimestamp,
    pub evidence: SccmEvidenceRef,
    pub terminal_evidence: Option<SccmEvidenceRef>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmManagementPointFinding {
    #[serde(flatten)]
    pub finding: SccmFinding,
    pub subject_id: String,
    pub last_successful_phase: Option<SccmManagementPointPhase>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmManagementPointAnalysis {
    pub schema_version: u32,
    pub workflow: SccmServerWorkflow,
    pub state_chain: Vec<SccmManagementPointPhase>,
    pub transactions: Vec<SccmManagementPointTransaction>,
    pub source_local_observations: Vec<SccmManagementPointSourceLocalObservation>,
    pub findings: Vec<SccmManagementPointFinding>,
    pub coverage_gaps: Vec<SccmManagementPointCoverageGap>,
    pub artifact_requests: Vec<SccmManagementPointArtifactRequest>,
    pub counterpart_ready_facts: Vec<SccmManagementPointCounterpartReadyFact>,
    pub cross_side_correlation_performed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FactOutcome {
    Succeeded,
    Failed,
    Deferred,
}

#[derive(Debug, Clone)]
struct ManagementPointFact {
    request_id: String,
    policy_id: Option<String>,
    client_handle: String,
    site_code: String,
    management_point_host_handle: String,
    phase: SccmManagementPointPhase,
    outcome: FactOutcome,
    terminal: bool,
    reference: SccmEvidenceRef,
    timestamp: SccmTimestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PhaseDecisionKind {
    Succeeded,
    Failed,
    Deferred,
    Contradictory,
    UnusableTime,
}

struct PhaseDecision<'a> {
    kind: PhaseDecisionKind,
    decisive: Vec<&'a ManagementPointFact>,
    ordering_millis: Option<i64>,
}

struct ReducedTransaction {
    transaction: SccmManagementPointTransaction,
    finding: Option<SccmManagementPointFinding>,
    counterpart_fact: Option<SccmManagementPointCounterpartReadyFact>,
    coverage_gap: Option<SccmManagementPointCoverageGap>,
}

/// Reduce Management Point evidence only after canonical server intake has
/// admitted its topology, artifact provenance, and CCM records for the
/// synthetic `mp-server-5.00.test-v1` profile. This adapter admits only the
/// literal `synthetic:site:lab` site handle and exact `5.00.TEST` source
/// version; canonical non-synthetic intake bundles intentionally return
/// [`SccmManagementPointIntakeError::TopologyMismatch`].
///
/// This is the server-intake entry point. It preserves the intake artifact IDs
/// and producer-host handles exactly; it never reconstructs role facts from a
/// caller-supplied path or raw log payload.
pub fn analyze_management_point_from_server_intake(
    assessment: &SccmServerIntakeAssessment,
) -> Result<SccmManagementPointAnalysis, SccmManagementPointIntakeError> {
    if !assessment.adapter_authority_is_intake_bound() {
        return Err(SccmManagementPointIntakeError::SourceMismatch {
            artifact_id: "management-point-intake-projection".to_owned(),
        });
    }
    if !assessment
        .topology
        .roles_observed
        .contains(&SccmRole::ManagementPoint)
    {
        return Err(SccmManagementPointIntakeError::TopologyMismatch);
    }

    let site_code = canonical_intake_site_code(&assessment.topology.site_handle)
        .ok_or(SccmManagementPointIntakeError::TopologyMismatch)?;
    let mut sources = Vec::new();
    let mut host_handles = BTreeSet::new();

    for artifact in assessment.artifacts.iter().filter(|artifact| {
        matches!(artifact.source_id.as_str(), MP_AUTH_GROUP | MP_POLICY_GROUP)
            && artifact.workflow_subject_role.is_none()
    }) {
        if artifact.producer_role != SccmRole::ManagementPoint {
            return Err(SccmManagementPointIntakeError::RoleMismatch {
                artifact_id: artifact.artifact_id.clone(),
            });
        }
        if artifact.state != SccmCoverageState::Captured
            || artifact.fragment_complete == Some(false)
            || artifact.truncated == Some(true)
            || !artifact.parser_eligible
        {
            return Err(SccmManagementPointIntakeError::IncompleteSource {
                artifact_id: artifact.artifact_id.clone(),
            });
        }
        if !assessment.coverage.iter().any(|coverage| {
            coverage.producer_role == SccmRole::ManagementPoint
                && coverage.workflow_subject_role.is_none()
                && coverage.source_id == artifact.source_id
                && coverage.state == artifact.state
                && coverage.artifact_ids.contains(&artifact.artifact_id)
        }) {
            return Err(SccmManagementPointIntakeError::SourceMismatch {
                artifact_id: artifact.artifact_id.clone(),
            });
        }
        if !artifact.profile_eligible || !management_point_profile_is_admitted(artifact) {
            return Err(SccmManagementPointIntakeError::ProfileMismatch {
                artifact_id: artifact.artifact_id.clone(),
            });
        }

        let host_handle = artifact
            .producer_host_handle
            .as_deref()
            .filter(|handle| valid_management_point_handle(handle))
            .ok_or(SccmManagementPointIntakeError::TopologyMismatch)?;
        host_handles.insert(host_handle.to_owned());

        let producer = canonical_intake_producer(artifact)?;
        let rotation = artifact.rotation.clone().ok_or_else(|| {
            SccmManagementPointIntakeError::SourceMismatch {
                artifact_id: artifact.artifact_id.clone(),
            }
        })?;
        let display_name = artifact.original_basename.clone().ok_or_else(|| {
            SccmManagementPointIntakeError::SourceMismatch {
                artifact_id: artifact.artifact_id.clone(),
            }
        })?;
        // Intake seals every logical-record range before this adapter runs.
        // The assessment has no independent physical line count, so this bound
        // is derived from that sealed evidence; `evidence_reference_fits_source`
        // cannot reject an otherwise-admitted range against its own maximum.
        // Relaxing the seal would make this caller-controlled and requires
        // re-review.
        let physical_line_end = assessment
            .evidence
            .iter()
            .filter(|evidence| evidence.reference.artifact_id == artifact.artifact_id)
            .filter_map(|evidence| evidence.reference.line_end)
            .max();

        sources.push(SccmManagementPointSource {
            artifact: SccmArtifact {
                artifact_id: artifact.artifact_id.clone(),
                display_name,
                original_path: None,
                host: Some(host_handle.to_owned()),
                role: artifact.producer_role.clone(),
                configmgr_version: artifact.source_version.clone(),
                collected_at_utc: Some(artifact.collected_at_utc.clone()),
                rotation,
                coverage: artifact.state.clone(),
                encoding: artifact
                    .capture_provenance
                    .as_ref()
                    .map(|provenance| provenance.encoding.clone()),
            },
            source_group: artifact.source_id.clone(),
            producer,
            // The canonical intake contract expresses a complete capture with
            // neither truncation nor fragment flags. The legacy fixture
            // reducer uses an explicit complete bit, so translate only that
            // canonical state at this adapter boundary.
            fragment_complete: canonical_fragment_complete(artifact),
            physical_line_end,
        });
    }

    if sources.is_empty() {
        return Err(SccmManagementPointIntakeError::SourceMismatch {
            artifact_id: "management-point-source-set".to_owned(),
        });
    }
    let management_point_host_handle = if host_handles.len() == 1 {
        host_handles.into_iter().next().expect("one host handle")
    } else {
        return Err(SccmManagementPointIntakeError::TopologyMismatch);
    };

    sources.sort_by(|left, right| left.artifact.artifact_id.cmp(&right.artifact.artifact_id));
    let admitted_artifact_ids = sources
        .iter()
        .map(|source| source.artifact.artifact_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut evidence = assessment
        .evidence
        .iter()
        .filter(|evidence| {
            evidence.role == SccmRole::ManagementPoint
                && admitted_artifact_ids.contains(evidence.reference.artifact_id.as_str())
        })
        .cloned()
        .collect::<Vec<_>>();
    evidence.sort_by(|left, right| left.evidence_id.cmp(&right.evidence_id));

    Ok(analyze_management_point_fixture(
        &SccmManagementPointBundle {
            topology: SccmManagementPointTopology {
                site_code,
                management_point_host_handle,
            },
            sources,
            evidence,
        },
    ))
}

fn canonical_fragment_complete(artifact: &SccmServerArtifactAssessment) -> Option<bool> {
    match (
        artifact.state.clone(),
        artifact.truncated,
        artifact.fragment_complete,
    ) {
        (SccmCoverageState::Captured, None, None) => Some(true),
        _ => artifact.fragment_complete,
    }
}

/// Maps the sole synthetic site handle admitted by this adapter. Opaque
/// production handles intentionally do not select the test-only profile.
fn canonical_intake_site_code(site_handle: &str) -> Option<String> {
    (site_handle == "synthetic:site:lab").then(|| "LAB".to_owned())
}

fn management_point_profile_is_admitted(artifact: &SccmServerArtifactAssessment) -> bool {
    artifact.source_version.as_deref() == Some("5.00.TEST")
        && artifact.source_kind == "ccmLog"
        && artifact.family == SccmArtifactFamily::ManagementPoint
}

fn canonical_intake_producer(
    artifact: &SccmServerArtifactAssessment,
) -> Result<String, SccmManagementPointIntakeError> {
    let basename = artifact.original_basename.as_deref();
    let producer = match (artifact.source_id.as_str(), basename) {
        (MP_AUTH_GROUP, Some("MP_GetAuth.log")) => "MP_GetAuth",
        (MP_AUTH_GROUP, Some("MP_CliReg.log")) => "MP_CliReg",
        (MP_AUTH_GROUP, Some("MP_RegistrationManager.log")) => "MP_RegistrationManager",
        (MP_POLICY_GROUP, Some("MP_GetPolicy.log")) => "MP_GetPolicy",
        (MP_POLICY_GROUP, Some("MP_Location.log")) => "MP_Location",
        _ => {
            return Err(SccmManagementPointIntakeError::SourceMismatch {
                artifact_id: artifact.artifact_id.clone(),
            });
        }
    };
    Ok(producer.to_owned())
}

/// Legacy synthetic-fixture hook. Production callers must enter through
/// [`analyze_management_point_from_server_intake`].
pub(crate) fn analyze_management_point_fixture(
    bundle: &SccmManagementPointBundle,
) -> SccmManagementPointAnalysis {
    let source_by_artifact = bundle
        .sources
        .iter()
        .filter(|source| {
            safe_opaque_id(&source.artifact.artifact_id)
                && artifact_id_is_unique(bundle, &source.artifact.artifact_id)
        })
        .map(|source| (source.artifact.artifact_id.as_str(), source))
        .collect::<BTreeMap<_, _>>();

    let topology_site_code = normalize_site_code(&bundle.topology.site_code);
    let topology_is_valid = topology_site_code.is_some()
        && valid_management_point_handle(&bundle.topology.management_point_host_handle);
    let mut facts_by_request: BTreeMap<String, Vec<ManagementPointFact>> = BTreeMap::new();
    let mut rejected_references = Vec::new();

    for evidence in &bundle.evidence {
        let Some(source) = source_by_artifact.get(evidence.reference.artifact_id.as_str()) else {
            continue;
        };
        if is_supplemental_source(source) {
            continue;
        }
        if source.artifact.coverage != SccmCoverageState::Captured
            || source.fragment_complete != Some(true)
        {
            // Bytes retained beside a noncaptured manifest state are
            // coverage-only. They cannot become malformed evidence or an
            // outcome.
            continue;
        }
        if !source_is_admitted(source)
            || !evidence_reference_fits_source(evidence, source)
            || !evidence_identity_is_unique(bundle, evidence)
            || evidence.role != SccmRole::ManagementPoint
            || !topology_is_valid
        {
            if evidence_reference_fits_source(evidence, source) {
                rejected_references.push(evidence.reference.clone());
            }
            continue;
        }

        match parse_fact(evidence, source) {
            Some(fact)
                if topology_site_code.as_deref() == Some(fact.site_code.as_str())
                    && fact.management_point_host_handle
                        == bundle.topology.management_point_host_handle =>
            {
                facts_by_request
                    .entry(fact.request_id.clone())
                    .or_default()
                    .push(fact);
            }
            _ => rejected_references.push(evidence.reference.clone()),
        }
    }

    let mut transactions = Vec::new();
    let mut findings = Vec::new();
    let mut counterpart_ready_facts = Vec::new();
    let mut coverage_gaps = Vec::new();
    let mut consumed_gap_groups = BTreeSet::new();

    for facts in facts_by_request.values_mut() {
        sort_facts(facts);
        if let Some(reduced) = reduce_transaction(facts, bundle) {
            if let Some(gap) = reduced.coverage_gap {
                consumed_gap_groups.insert(gap.logical_artifact_id.clone());
                coverage_gaps.push(gap);
            }
            if let Some(finding) = reduced.finding {
                findings.push(finding);
            }
            if let Some(fact) = reduced.counterpart_fact {
                counterpart_ready_facts.push(fact);
            }
            transactions.push(reduced.transaction);
        } else {
            rejected_references.extend(facts.iter().map(|fact| fact.reference.clone()));
        }
    }

    let mut source_local_observations = Vec::new();
    append_rotation_fragment_observation(
        bundle,
        &mut source_local_observations,
        &mut findings,
        &mut coverage_gaps,
        &mut consumed_gap_groups,
    );
    append_rejected_observations(
        bundle,
        &mut rejected_references,
        &mut source_local_observations,
        &mut findings,
    );
    append_unconsumed_explicit_coverage(
        bundle,
        &mut source_local_observations,
        &mut findings,
        &mut coverage_gaps,
        &mut consumed_gap_groups,
    );

    normalize_analysis(
        &mut transactions,
        &mut source_local_observations,
        &mut findings,
        &mut coverage_gaps,
        &mut counterpart_ready_facts,
    );
    let artifact_requests = collect_artifact_requests(&transactions, &source_local_observations);

    SccmManagementPointAnalysis {
        schema_version: SCCM_MANAGEMENT_POINT_ANALYSIS_SCHEMA_VERSION,
        workflow: SccmServerWorkflow::ManagementPoint,
        state_chain: STATE_CHAIN.to_vec(),
        transactions,
        source_local_observations,
        findings,
        coverage_gaps,
        artifact_requests,
        counterpart_ready_facts,
        cross_side_correlation_performed: false,
    }
}

fn reduce_transaction(
    facts: &[ManagementPointFact],
    bundle: &SccmManagementPointBundle,
) -> Option<ReducedTransaction> {
    let request_fact = facts.iter().find(|fact| {
        fact.phase == SccmManagementPointPhase::ReceiveRequest
            && fact.outcome == FactOutcome::Succeeded
    })?;
    let key = build_transaction_key(facts, request_fact)?;

    let mut observations = facts
        .iter()
        .enumerate()
        .map(|(index, fact)| observation_for_fact(&key.request_id, index, fact))
        .collect::<Vec<_>>();
    observations.sort_by(compare_observations);

    let mut last_successful_phase = None;
    let mut previous_millis = None;
    let mut phase = SccmManagementPointPhase::ReceiveRequest;
    let mut state = SccmManagementPointState::Incomplete;
    let mut classification = SccmManagementPointClassification::InsufficientEvidence;
    let mut confidence = SccmManagementPointConfidence::Medium;
    let mut decisive_facts = Vec::new();
    let mut gap = None;
    let mut next_artifacts = Vec::new();

    for current_phase in STATE_CHAIN {
        phase = current_phase;
        let phase_facts = facts
            .iter()
            .filter(|fact| fact.phase == current_phase)
            .collect::<Vec<_>>();
        if phase_facts.is_empty() {
            phase = last_successful_phase.unwrap_or(current_phase);
            state = SccmManagementPointState::Incomplete;
            classification = SccmManagementPointClassification::InsufficientEvidence;
            confidence = SccmManagementPointConfidence::Medium;
            let missing_group = group_for_phase(current_phase);
            let request =
                workflow_request_for_group(missing_group, missing_phase_reason(current_phase));
            next_artifacts.push(request);
            gap = Some(SccmManagementPointCoverageGap {
                logical_artifact_id: missing_group.to_owned(),
                role: SccmRole::ManagementPoint,
                state: coverage_for_group(bundle, missing_group),
            });
            break;
        }

        let decision = resolve_phase(&phase_facts);
        decisive_facts = decision.decisive.clone();
        let inverted = previous_millis
            .zip(decision.ordering_millis)
            .is_some_and(|(previous, current)| current <= previous);
        if inverted {
            state = SccmManagementPointState::Contradictory;
            classification = SccmManagementPointClassification::ContradictoryEvidence;
            confidence = SccmManagementPointConfidence::Low;
            next_artifacts.push(workflow_request_for_group(
                group_for_phase(current_phase),
                chronology_reason(current_phase),
            ));
            break;
        }

        match decision.kind {
            PhaseDecisionKind::Succeeded => {
                last_successful_phase = Some(current_phase);
                previous_millis = decision.ordering_millis;
                state = SccmManagementPointState::Succeeded;
                classification = SccmManagementPointClassification::Success;
                confidence = SccmManagementPointConfidence::High;
            }
            PhaseDecisionKind::Failed => {
                state = SccmManagementPointState::Failed;
                classification = SccmManagementPointClassification::ConfirmedFailure;
                confidence = SccmManagementPointConfidence::High;
                break;
            }
            PhaseDecisionKind::Deferred => {
                state = SccmManagementPointState::Deferred;
                classification = SccmManagementPointClassification::BlockedOrDeferred;
                confidence = SccmManagementPointConfidence::Medium;
                next_artifacts.push(workflow_request_for_group(
                    group_for_phase(current_phase),
                    deferred_reason(current_phase),
                ));
                break;
            }
            PhaseDecisionKind::Contradictory => {
                state = SccmManagementPointState::Contradictory;
                classification = SccmManagementPointClassification::ContradictoryEvidence;
                confidence = SccmManagementPointConfidence::Low;
                next_artifacts.push(workflow_request_for_group(
                    group_for_phase(current_phase),
                    contradiction_reason(current_phase),
                ));
                break;
            }
            PhaseDecisionKind::UnusableTime => {
                state = SccmManagementPointState::Incomplete;
                classification = SccmManagementPointClassification::InsufficientEvidence;
                confidence = SccmManagementPointConfidence::Medium;
                let source_group = group_for_phase(current_phase);
                next_artifacts.push(workflow_request_for_group(
                    source_group,
                    timestamp_reason(current_phase),
                ));
                gap = Some(SccmManagementPointCoverageGap {
                    logical_artifact_id: source_group.to_owned(),
                    role: SccmRole::ManagementPoint,
                    state: SccmCoverageState::ParseFailed,
                });
                break;
            }
        }
    }

    let transaction_id = format!("mp:request:{}", key.request_id);
    let evidence = merge_references(facts.iter().map(|fact| fact.reference.clone()));
    let coverage_gap_artifact_ids = gap
        .iter()
        .map(|gap| gap.logical_artifact_id.clone())
        .collect::<Vec<_>>();
    let transaction = SccmManagementPointTransaction {
        transaction_id: transaction_id.clone(),
        key: key.clone(),
        phase,
        state,
        last_successful_phase,
        classification,
        confidence,
        evidence,
        observations,
        coverage_gap_artifact_ids,
        next_artifacts: next_artifacts.clone(),
    };

    let finding =
        build_transaction_finding(&transaction, &decisive_facts, gap.as_ref(), &next_artifacts);
    let counterpart_fact =
        build_counterpart_fact(&transaction, &decisive_facts, &transaction_id, &key);

    Some(ReducedTransaction {
        transaction,
        finding,
        counterpart_fact,
        coverage_gap: gap,
    })
}

fn build_transaction_key(
    facts: &[ManagementPointFact],
    request_fact: &ManagementPointFact,
) -> Option<SccmManagementPointKey> {
    if facts.iter().any(|fact| {
        fact.request_id != request_fact.request_id
            || fact.client_handle != request_fact.client_handle
            || fact.site_code != request_fact.site_code
            || fact.management_point_host_handle != request_fact.management_point_host_handle
    }) {
        return None;
    }

    let policy_ids = facts
        .iter()
        .filter_map(|fact| fact.policy_id.as_deref())
        .collect::<BTreeSet<_>>();
    if policy_ids.len() > 1 {
        return None;
    }

    Some(SccmManagementPointKey {
        request_id: request_fact.request_id.clone(),
        policy_id: policy_ids.first().map(|value| (*value).to_owned()),
        client_handle: request_fact.client_handle.clone(),
        site_code: request_fact.site_code.clone(),
        management_point_host_handle: request_fact.management_point_host_handle.clone(),
        confidence: SccmKeyConfidence::Exact,
        extraction_profile_id: SCCM_MANAGEMENT_POINT_TEST_PROFILE_ID.to_owned(),
    })
}

fn observation_for_fact(
    request_id: &str,
    index: usize,
    fact: &ManagementPointFact,
) -> SccmManagementPointObservation {
    let (state, classification) = match fact.outcome {
        FactOutcome::Succeeded => (
            SccmManagementPointState::Succeeded,
            SccmManagementPointClassification::Success,
        ),
        FactOutcome::Failed => (
            SccmManagementPointState::Failed,
            SccmManagementPointClassification::ConfirmedFailure,
        ),
        FactOutcome::Deferred => (
            SccmManagementPointState::Deferred,
            SccmManagementPointClassification::BlockedOrDeferred,
        ),
    };
    SccmManagementPointObservation {
        observation_id: format!(
            "observation:mp:{request_id}:{index:02}:{}",
            fact.phase.serialized_name()
        ),
        phase: fact.phase,
        state,
        classification,
        timestamp: fact.timestamp.clone(),
        evidence: vec![fact.reference.clone()],
    }
}

fn resolve_phase<'a>(facts: &[&'a ManagementPointFact]) -> PhaseDecision<'a> {
    if facts.iter().any(|fact| {
        fact.timestamp.utc_millis.is_none()
            || !matches!(
                fact.timestamp.ordering_state,
                crate::sccm::SccmTimeOrderingState::NormalizedUtc
            )
    }) {
        return PhaseDecision {
            kind: PhaseDecisionKind::UnusableTime,
            decisive: facts.to_vec(),
            ordering_millis: None,
        };
    }

    let Some(latest) = latest_fact(facts.iter().copied()) else {
        return PhaseDecision {
            kind: PhaseDecisionKind::UnusableTime,
            decisive: facts.to_vec(),
            ordering_millis: None,
        };
    };
    let instant = latest.timestamp.utc_millis;
    let same_instant = facts
        .iter()
        .copied()
        .filter(|fact| fact.timestamp.utc_millis == instant)
        .collect::<Vec<_>>();
    if same_instant
        .iter()
        .any(|fact| fact.outcome != latest.outcome)
    {
        return PhaseDecision {
            kind: PhaseDecisionKind::Contradictory,
            decisive: same_instant,
            ordering_millis: instant,
        };
    }

    PhaseDecision {
        kind: match latest.outcome {
            FactOutcome::Succeeded => PhaseDecisionKind::Succeeded,
            FactOutcome::Failed if latest.terminal => PhaseDecisionKind::Failed,
            FactOutcome::Deferred => PhaseDecisionKind::Deferred,
            FactOutcome::Failed => PhaseDecisionKind::UnusableTime,
        },
        decisive: vec![latest],
        ordering_millis: instant,
    }
}

fn latest_fact<'a>(
    facts: impl Iterator<Item = &'a ManagementPointFact>,
) -> Option<&'a ManagementPointFact> {
    facts.max_by(|left, right| {
        left.timestamp
            .utc_millis
            .cmp(&right.timestamp.utc_millis)
            .then_with(|| compare_references(&left.reference, &right.reference))
    })
}

fn build_transaction_finding(
    transaction: &SccmManagementPointTransaction,
    decisive_facts: &[&ManagementPointFact],
    gap: Option<&SccmManagementPointCoverageGap>,
    requests: &[SccmManagementPointArtifactRequest],
) -> Option<SccmManagementPointFinding> {
    if transaction.classification == SccmManagementPointClassification::Success {
        return None;
    }

    let evidence = if decisive_facts.is_empty() {
        transaction.evidence.last().cloned().into_iter().collect()
    } else {
        merge_references(decisive_facts.iter().map(|fact| fact.reference.clone()))
    };
    let shared_class = match transaction.classification {
        SccmManagementPointClassification::ConfirmedFailure => SccmFindingClass::ConfirmedFailure,
        SccmManagementPointClassification::BlockedOrDeferred => SccmFindingClass::BlockedOrDeferred,
        SccmManagementPointClassification::InsufficientEvidence => {
            SccmFindingClass::InsufficientEvidence
        }
        SccmManagementPointClassification::ContradictoryEvidence
        | SccmManagementPointClassification::LowConfidenceSymptom
        | SccmManagementPointClassification::IncompatibleKey
        | SccmManagementPointClassification::Success => SccmFindingClass::Symptom,
    };
    let shared_confidence = match transaction.confidence {
        SccmManagementPointConfidence::Low => SccmConfidence::Low,
        SccmManagementPointConfidence::Medium => SccmConfidence::Moderate,
        SccmManagementPointConfidence::High => SccmConfidence::High,
    };
    let terminal_evidence = if shared_class == SccmFindingClass::ConfirmedFailure {
        decisive_facts
            .iter()
            .filter(|fact| fact.outcome == FactOutcome::Failed && fact.terminal)
            .map(|fact| SccmTerminalEvidence::observed_failure(fact.reference.clone()))
            .collect()
    } else {
        Vec::new()
    };
    let coverage_gap = gap.map(shared_gap);
    let shared_requests = requests
        .iter()
        .filter_map(shared_request)
        .collect::<Vec<_>>();

    let mut builder = SccmFindingBuilder::new(format!(
        "finding:mp:{}:{}",
        transaction.key.request_id,
        transaction.phase.serialized_name()
    ))
    .class(shared_class)
    .phase(SccmPhase::Unknown(
        transaction.phase.serialized_name().to_owned(),
    ))
    .role(SccmRole::ManagementPoint)
    .severity(if transaction.state == SccmManagementPointState::Failed {
        Severity::Error
    } else {
        Severity::Warning
    })
    .confidence(shared_confidence)
    .title("Management Point request evidence")
    .summary("The Management Point request state is bounded to the cited server-local evidence.")
    .evidence(evidence)
    .terminal_evidence(terminal_evidence)
    .next_artifacts(shared_requests);
    if let Some(coverage_gap) = coverage_gap {
        builder = builder.coverage_gap(coverage_gap);
    }
    let finding = builder.build().ok()?;
    Some(SccmManagementPointFinding {
        finding,
        subject_id: transaction.transaction_id.clone(),
        last_successful_phase: transaction.last_successful_phase,
    })
}

fn build_counterpart_fact(
    transaction: &SccmManagementPointTransaction,
    decisive_facts: &[&ManagementPointFact],
    transaction_id: &str,
    key: &SccmManagementPointKey,
) -> Option<SccmManagementPointCounterpartReadyFact> {
    if key.policy_id.is_none()
        || key.confidence != SccmKeyConfidence::Exact
        || transaction.confidence != SccmManagementPointConfidence::High
        || !matches!(
            transaction.state,
            SccmManagementPointState::Succeeded | SccmManagementPointState::Failed
        )
    {
        return None;
    }

    let fact = decisive_facts
        .iter()
        .copied()
        .filter(|fact| fact.policy_id.as_deref() == key.policy_id.as_deref())
        .filter(|fact| fact.phase == transaction.phase)
        .filter(|fact| {
            matches!(
                (transaction.state, fact.outcome, fact.terminal),
                (
                    SccmManagementPointState::Succeeded,
                    FactOutcome::Succeeded,
                    _
                ) | (SccmManagementPointState::Failed, FactOutcome::Failed, true)
            )
        })
        .filter(|fact| {
            matches!(
                fact.timestamp.ordering_state,
                crate::sccm::SccmTimeOrderingState::NormalizedUtc
            ) && fact.timestamp.utc_millis.is_some()
        })
        .max_by(|left, right| {
            left.phase
                .cmp(&right.phase)
                .then_with(|| left.timestamp.utc_millis.cmp(&right.timestamp.utc_millis))
                .then_with(|| compare_references(&left.reference, &right.reference))
        })?;

    Some(SccmManagementPointCounterpartReadyFact {
        transaction_id: transaction_id.to_owned(),
        key: key.clone(),
        phase: fact.phase,
        state: transaction.state,
        classification: transaction.classification,
        confidence: transaction.confidence,
        timestamp: fact.timestamp.clone(),
        evidence: fact.reference.clone(),
        terminal_evidence: (transaction.state == SccmManagementPointState::Failed)
            .then(|| fact.reference.clone()),
    })
}

fn parse_fact(
    evidence: &SccmEvidence,
    source: &SccmManagementPointSource,
) -> Option<ManagementPointFact> {
    if source.artifact.configmgr_version.as_deref() != Some(MP_TEST_VERSION)
        || evidence.component.as_deref() != Some(source.producer.as_str())
    {
        return None;
    }
    let message = evidence.message.as_str();
    let (phase, outcome, terminal) = parse_phase_outcome(message, &source.producer)?;
    let result = validated_result_value(message)?;
    if (terminal && result.is_none_or(|value| value == 0))
        || (!terminal && result.is_some_and(|value| value != 0))
    {
        return None;
    }

    let request_id = normalize_uuid(&token_value(message, "RequestId")?)?;
    let policy_id = match validated_token_value(message, "PolicyId")? {
        Some(value) => Some(normalize_uuid(&value)?),
        None => None,
    };
    let client_handle = token_value(message, "ClientHandle")?;
    let site_code = normalize_site_code(&token_value(message, "SiteCode")?)?;
    let management_point_host_handle = token_value(message, "MPHandle")?;
    if !valid_safe_handle(&client_handle, "safe:client:")
        || !valid_management_point_handle(&management_point_host_handle)
    {
        return None;
    }

    Some(ManagementPointFact {
        request_id,
        policy_id,
        client_handle,
        site_code,
        management_point_host_handle,
        phase,
        outcome,
        terminal,
        reference: evidence.reference.clone(),
        timestamp: evidence.timestamp.clone(),
    })
}

fn parse_phase_outcome(
    message: &str,
    producer: &str,
) -> Option<(SccmManagementPointPhase, FactOutcome, bool)> {
    let lowercase = event_payload(message)?.to_ascii_lowercase();
    let succeeded = FactOutcome::Succeeded;
    let failed = FactOutcome::Failed;
    let deferred = FactOutcome::Deferred;

    match producer {
        "MP_GetAuth" if has_event_marker(&lowercase, "receive request succeeded") => {
            Some((SccmManagementPointPhase::ReceiveRequest, succeeded, false))
        }
        "MP_GetAuth" if has_event_marker(&lowercase, "authenticate succeeded") => {
            Some((SccmManagementPointPhase::Authenticate, succeeded, false))
        }
        "MP_GetAuth" if has_event_marker(&lowercase, "authenticate failed terminal") => {
            Some((SccmManagementPointPhase::Authenticate, failed, true))
        }
        "MP_CliReg" | "MP_RegistrationManager"
            if has_event_marker(&lowercase, "register or identify succeeded") =>
        {
            Some((
                SccmManagementPointPhase::RegisterOrIdentify,
                succeeded,
                false,
            ))
        }
        "MP_CliReg" | "MP_RegistrationManager"
            if has_event_marker(&lowercase, "register or identify failed terminal") =>
        {
            Some((SccmManagementPointPhase::RegisterOrIdentify, failed, true))
        }
        "MP_Location" if has_event_marker(&lowercase, "resolve location succeeded") => Some((
            SccmManagementPointPhase::ResolveLocationOrPolicy,
            succeeded,
            false,
        )),
        "MP_Location" if has_event_marker(&lowercase, "resolve location failed terminal") => {
            Some((
                SccmManagementPointPhase::ResolveLocationOrPolicy,
                failed,
                true,
            ))
        }
        "MP_GetPolicy" if has_event_marker(&lowercase, "resolve policy succeeded") => Some((
            SccmManagementPointPhase::ResolveLocationOrPolicy,
            succeeded,
            false,
        )),
        "MP_GetPolicy" if has_event_marker(&lowercase, "resolve policy failed terminal") => Some((
            SccmManagementPointPhase::ResolveLocationOrPolicy,
            failed,
            true,
        )),
        "MP_GetPolicy" if has_event_marker(&lowercase, "respond deferred") => {
            Some((SccmManagementPointPhase::Respond, deferred, false))
        }
        "MP_GetPolicy" if has_event_marker(&lowercase, "respond succeeded") => {
            Some((SccmManagementPointPhase::Respond, succeeded, false))
        }
        "MP_GetPolicy" if has_event_marker(&lowercase, "respond failed terminal") => {
            Some((SccmManagementPointPhase::Respond, failed, true))
        }
        "MP_GetPolicy" if has_event_marker(&lowercase, "record outcome succeeded") => {
            Some((SccmManagementPointPhase::RecordOutcome, succeeded, false))
        }
        "MP_GetPolicy" if has_event_marker(&lowercase, "record outcome failed terminal") => {
            Some((SccmManagementPointPhase::RecordOutcome, failed, true))
        }
        _ => None,
    }
}

fn has_event_marker(message: &str, marker: &str) -> bool {
    message.strip_prefix(marker).is_some_and(|suffix| {
        suffix
            .chars()
            .next()
            .is_none_or(|character| character.is_ascii_whitespace())
    })
}

fn event_payload(message: &str) -> Option<&str> {
    let projected = message
        .strip_prefix("[sccm-public-message-v1] ")
        .unwrap_or(message)
        .trim_start();
    if projected.starts_with("SYNTHETIC FIXTURE ") {
        return projected.split_once(": ").map(|(_, payload)| payload);
    }
    Some(projected)
}

fn source_is_admitted(source: &SccmManagementPointSource) -> bool {
    if source.artifact.role != SccmRole::ManagementPoint
        || source.artifact.configmgr_version.as_deref() != Some(MP_TEST_VERSION)
    {
        return false;
    }
    let expected_logical_id = match (source.source_group.as_str(), source.producer.as_str()) {
        (MP_AUTH_GROUP, "MP_GetAuth") => "mpGetAuth",
        (MP_AUTH_GROUP, "MP_CliReg") => "mpCliReg",
        (MP_AUTH_GROUP, "MP_RegistrationManager") => "mpRegistrationManager",
        (MP_POLICY_GROUP, "MP_GetPolicy") => "mpGetPolicy",
        (MP_POLICY_GROUP, "MP_Location") => "mpLocation",
        _ => return false,
    };
    let classified =
        classify_artifact_name(&source.artifact.display_name, SccmRole::ManagementPoint);
    classified.logical_name == expected_logical_id
        && classified.family == SccmArtifactFamily::ManagementPoint
        && classified.supported_for_diagnosis
        && classified.rotation == source.artifact.rotation
}

/// Supplemental sources are subject-scoped inputs, never MP-produced
/// evidence. `mpcontrol.log` is produced by the site-server MP control
/// workflow about the Management Point, so it is only supplemental when
/// the bundle models it under the site-server producer role declared in
/// the shared catalog; an MP-produced claim fails closed as rejected
/// evidence instead.
fn is_supplemental_source(source: &SccmManagementPointSource) -> bool {
    if source.source_group == MP_IIS_GROUP {
        return true;
    }
    if source.source_group != MP_POLICY_GROUP || source.artifact.role != SccmRole::SiteServer {
        return false;
    }
    let classified = classify_artifact_name(&source.artifact.display_name, SccmRole::SiteServer);
    classified.logical_name == "mpcontrol"
        && classified.family == SccmArtifactFamily::ManagementPoint
}

fn validated_token_value(message: &str, label: &str) -> Option<Option<String>> {
    let lowercase = message.to_ascii_lowercase();
    let needle = format!("{}=", label.to_ascii_lowercase());
    let mut value = None;
    for (label_start, _) in lowercase.match_indices(&needle) {
        let exact_label_boundary = label_start == 0
            || message[..label_start]
                .chars()
                .next_back()
                .is_some_and(is_key_token_boundary);
        if !exact_label_boundary {
            return None;
        }

        let remainder = &message[label_start + needle.len()..];
        let parsed = if let Some(braced) = remainder.strip_prefix('{') {
            let end = braced.find('}')?;
            let suffix = &braced[end + 1..];
            let exact_value_boundary = suffix.chars().next().is_none_or(is_key_token_boundary);
            if !exact_value_boundary || end == 0 {
                return None;
            }
            braced[..end].to_owned()
        } else {
            let end = remainder
                .find(is_key_token_boundary)
                .unwrap_or(remainder.len());
            if end == 0 {
                return None;
            }
            remainder[..end].to_owned()
        };
        if value.replace(parsed).is_some() {
            return None;
        }
    }
    Some(value)
}

fn is_key_token_boundary(character: char) -> bool {
    character.is_whitespace() || matches!(character, ',' | ';' | '&')
}

fn token_value(message: &str, label: &str) -> Option<String> {
    validated_token_value(message, label)?
}

fn normalize_uuid(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let valid = bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
        && bytes
            .iter()
            .any(|byte| byte.is_ascii_hexdigit() && *byte != b'0');
    valid.then(|| value.to_ascii_lowercase())
}

fn validated_result_value(message: &str) -> Option<Option<u32>> {
    let Some(value) = validated_token_value(message, "Result")? else {
        return Some(None);
    };
    let hex = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))?;
    (hex.len() == 8 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| u32::from_str_radix(hex, 16).ok())
        .flatten()
        .map(Some)
}

fn normalize_site_code(value: &str) -> Option<String> {
    (value.len() == 3 && value.bytes().all(|byte| byte.is_ascii_alphanumeric()))
        .then(|| value.to_ascii_uppercase())
}

fn valid_safe_handle(value: &str, prefix: &str) -> bool {
    let Some(payload) = value.strip_prefix(prefix) else {
        return false;
    };
    !payload.is_empty()
        && payload.len() <= 128
        && payload
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && payload
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        && !payload.contains("..")
        && payload
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_management_point_handle(value: &str) -> bool {
    valid_safe_handle(value, "safe:mp:")
        || value == "synthetic:host:mp-01"
        || opaque_host_handle(value)
}

fn opaque_host_handle(value: &str) -> bool {
    value
        .strip_prefix("cmtraceopen.host.sha256.v1:")
        .is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

#[cfg(test)]
#[path = "management_point_tests.rs"]
mod management_point_tests;

fn safe_opaque_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

fn artifact_id_is_unique(bundle: &SccmManagementPointBundle, artifact_id: &str) -> bool {
    bundle
        .sources
        .iter()
        .filter(|source| source.artifact.artifact_id == artifact_id)
        .take(2)
        .count()
        == 1
}

fn evidence_identity_is_unique(
    bundle: &SccmManagementPointBundle,
    evidence: &SccmEvidence,
) -> bool {
    bundle
        .evidence
        .iter()
        .filter(|candidate| {
            candidate.evidence_id == evidence.evidence_id
                || candidate.reference.entry_id == evidence.reference.entry_id
                || evidence_references_overlap(&candidate.reference, &evidence.reference)
        })
        .take(2)
        .count()
        == 1
}

fn safe_evidence_reference(reference: &SccmEvidenceRef) -> bool {
    safe_opaque_id(&reference.artifact_id)
        && safe_opaque_id(&reference.entry_id)
        && matches!(
            (reference.line_start, reference.line_end),
            (Some(start), Some(end)) if start > 0 && end >= start
        )
}

fn evidence_reference_fits_source(
    evidence: &SccmEvidence,
    source: &SccmManagementPointSource,
) -> bool {
    safe_evidence_reference(&evidence.reference)
        && evidence.evidence_id == evidence.reference.entry_id
        && source.physical_line_end.is_some_and(|physical_end| {
            physical_end > 0
                && evidence
                    .reference
                    .line_end
                    .is_some_and(|line_end| line_end <= physical_end)
        })
}

fn sort_facts(facts: &mut [ManagementPointFact]) {
    facts.sort_by(|left, right| {
        left.phase
            .cmp(&right.phase)
            .then_with(|| left.timestamp.utc_millis.cmp(&right.timestamp.utc_millis))
            .then_with(|| compare_references(&left.reference, &right.reference))
    });
}

fn compare_references(left: &SccmEvidenceRef, right: &SccmEvidenceRef) -> Ordering {
    left.artifact_id
        .cmp(&right.artifact_id)
        .then_with(|| left.line_start.cmp(&right.line_start))
        .then_with(|| left.line_end.cmp(&right.line_end))
        .then_with(|| left.entry_id.cmp(&right.entry_id))
}

fn merge_references(references: impl IntoIterator<Item = SccmEvidenceRef>) -> Vec<SccmEvidenceRef> {
    let mut references = references
        .into_iter()
        .filter(|reference| {
            matches!(
                (reference.line_start, reference.line_end),
                (Some(start), Some(end)) if start > 0 && end >= start
            )
        })
        .collect::<Vec<_>>();
    references.sort_by(compare_references);
    references.dedup();
    references
}

fn physical_reference(source: &SccmManagementPointSource) -> Option<SccmEvidenceRef> {
    let line_end = source.physical_line_end?;
    (line_end > 0 && safe_opaque_id(&source.artifact.artifact_id)).then(|| SccmEvidenceRef {
        artifact_id: source.artifact.artifact_id.clone(),
        entry_id: format!("{}:physical:1-{line_end}", source.artifact.artifact_id),
        line_start: Some(1),
        line_end: Some(line_end),
    })
}

fn append_rotation_fragment_observation(
    bundle: &SccmManagementPointBundle,
    observations: &mut Vec<SccmManagementPointSourceLocalObservation>,
    findings: &mut Vec<SccmManagementPointFinding>,
    coverage_gaps: &mut Vec<SccmManagementPointCoverageGap>,
    consumed_gap_groups: &mut BTreeSet<String>,
) {
    let evidence = merge_references(
        bundle
            .sources
            .iter()
            .filter(|source| {
                source.artifact.role == SccmRole::ManagementPoint
                    && source.source_group == MP_AUTH_GROUP
                    && source.artifact.coverage == SccmCoverageState::Captured
                    && source.fragment_complete == Some(false)
            })
            .filter_map(physical_reference),
    );
    if evidence.is_empty() {
        return;
    }

    let request = workflow_request_for_group(
        MP_AUTH_GROUP,
        "Collect a complete bounded MP_GetAuth.log record; physical rotation fragments are coverage-only.",
    );
    observations.push(SccmManagementPointSourceLocalObservation {
        observation_id: "observation:rotation-fragments".to_owned(),
        phase: SccmManagementPointPhase::ReceiveRequest,
        state: SccmManagementPointState::Incomplete,
        classification: SccmManagementPointClassification::InsufficientEvidence,
        confidence: SccmManagementPointConfidence::Low,
        correlation_eligible: false,
        evidence: evidence.clone(),
        next_artifacts: vec![request.clone()],
    });
    let gap = SccmManagementPointCoverageGap {
        logical_artifact_id: MP_AUTH_GROUP.to_owned(),
        role: SccmRole::ManagementPoint,
        state: SccmCoverageState::ParseFailed,
    };
    if let Some(finding) = build_source_local_finding(
        "finding:mp-rotation-fragments",
        "observation:rotation-fragments",
        SccmManagementPointPhase::ReceiveRequest,
        SccmManagementPointClassification::InsufficientEvidence,
        evidence,
        Some(&gap),
        &[request],
    ) {
        findings.push(finding);
    }
    coverage_gaps.push(gap);
    consumed_gap_groups.insert(MP_AUTH_GROUP.to_owned());
}

/// Rejected records surface one observation per owning source group so
/// each remediation hint requests the group the rejected record actually
/// belongs to instead of defaulting to the authentication family.
fn append_rejected_observations(
    bundle: &SccmManagementPointBundle,
    rejected: &mut Vec<SccmEvidenceRef>,
    observations: &mut Vec<SccmManagementPointSourceLocalObservation>,
    findings: &mut Vec<SccmManagementPointFinding>,
) {
    rejected.sort_by(compare_references);
    rejected.dedup();
    if rejected.is_empty() {
        return;
    }

    let rotation = bundle
        .sources
        .iter()
        .any(|source| source.fragment_complete == Some(false));
    let mut references_by_group: BTreeMap<&'static str, Vec<SccmEvidenceRef>> = BTreeMap::new();
    for reference in rejected.iter() {
        references_by_group
            .entry(owning_group_for_reference(bundle, reference))
            .or_default()
            .push(reference.clone());
    }

    for (group, references) in references_by_group {
        let unrelated = references.iter().any(|reference| {
            bundle
                .evidence
                .iter()
                .filter(|evidence| evidence.reference == *reference)
                .any(|evidence| {
                    token_value(&evidence.message, "RequestId").is_none()
                        && (token_value(&evidence.message, "AssignmentId").is_some()
                            || token_value(&evidence.message, "ClientId").is_some())
                })
        });
        let rejection = if unrelated {
            MpRejection::UnrelatedClientLikeKey
        } else if rotation {
            MpRejection::RotationMalformed
        } else {
            MpRejection::Malformed
        };
        let phase = entry_phase_for_group(group);
        let classification = rejection.classification();
        let observation_id = format!("observation:{}:{group}", rejection.id_stem());
        let request = workflow_request_for_group(group, &rejection.reason(group));
        let evidence = merge_references(references);
        observations.push(SccmManagementPointSourceLocalObservation {
            observation_id: observation_id.clone(),
            phase,
            state: SccmManagementPointState::Observed,
            classification,
            confidence: SccmManagementPointConfidence::Low,
            correlation_eligible: false,
            evidence: evidence.clone(),
            next_artifacts: vec![request.clone()],
        });
        if let Some(finding) = build_source_local_finding(
            &format!("finding:{}:{group}", rejection.id_stem()),
            &observation_id,
            phase,
            classification,
            evidence,
            None,
            &[request],
        ) {
            findings.push(finding);
        }
    }
}

/// Why a Management Point record was rejected. The variant fixes the
/// observation identity and classification; the owning source group fixes
/// the phase and the artifact the remediation hint requests.
#[derive(Clone, Copy)]
enum MpRejection {
    UnrelatedClientLikeKey,
    RotationMalformed,
    Malformed,
}

impl MpRejection {
    fn id_stem(self) -> &'static str {
        match self {
            Self::UnrelatedClientLikeKey => "unrelated-client-like-key",
            Self::RotationMalformed => "rotation-malformed",
            Self::Malformed => "mp-malformed",
        }
    }

    fn classification(self) -> SccmManagementPointClassification {
        match self {
            Self::UnrelatedClientLikeKey => SccmManagementPointClassification::IncompatibleKey,
            Self::RotationMalformed | Self::Malformed => {
                SccmManagementPointClassification::LowConfidenceSymptom
            }
        }
    }

    fn reason(self, group: &str) -> String {
        let log = workflow_log_for_group(group);
        match self {
            Self::UnrelatedClientLikeKey => {
                format!("Capture bounded {log} evidence with the exact versioned request key.")
            }
            Self::RotationMalformed => format!(
                "Collect a supported-version {log} record containing a complete exact request key."
            ),
            Self::Malformed => {
                format!("Collect bounded {log} evidence under the validated extraction profile.")
            }
        }
    }
}

/// The source group that owns a rejected reference. Supplemental and
/// unknown owners keep the authentication-family default because that is
/// the only remaining group able to carry the request key the rejected
/// record failed to produce. `any` rather than `find` keeps the answer
/// independent of source ordering when an artifact id is duplicated.
fn owning_group_for_reference(
    bundle: &SccmManagementPointBundle,
    reference: &SccmEvidenceRef,
) -> &'static str {
    let policy_owned = bundle.sources.iter().any(|source| {
        source.artifact.artifact_id == reference.artifact_id
            && source.source_group == MP_POLICY_GROUP
    });
    if policy_owned {
        MP_POLICY_GROUP
    } else {
        MP_AUTH_GROUP
    }
}

/// The phase a source group answers for: the inverse of [`group_for_phase`],
/// so an observation never cites a phase that maps back to another group.
fn entry_phase_for_group(group: &str) -> SccmManagementPointPhase {
    if group == MP_POLICY_GROUP {
        SccmManagementPointPhase::ResolveLocationOrPolicy
    } else {
        SccmManagementPointPhase::ReceiveRequest
    }
}

fn workflow_log_for_group(group: &str) -> &'static str {
    if group == MP_POLICY_GROUP {
        "MP_GetPolicy.log"
    } else {
        "MP_GetAuth.log"
    }
}

fn append_unconsumed_explicit_coverage(
    bundle: &SccmManagementPointBundle,
    observations: &mut Vec<SccmManagementPointSourceLocalObservation>,
    findings: &mut Vec<SccmManagementPointFinding>,
    coverage_gaps: &mut Vec<SccmManagementPointCoverageGap>,
    consumed_gap_groups: &mut BTreeSet<String>,
) {
    for group in [MP_AUTH_GROUP, MP_POLICY_GROUP] {
        if consumed_gap_groups.contains(group) {
            continue;
        }
        let sources = bundle
            .sources
            .iter()
            .filter(|source| source.source_group == group)
            .collect::<Vec<_>>();
        if sources.is_empty()
            || sources.iter().any(|source| {
                source.artifact.coverage == SccmCoverageState::Captured
                    && source.fragment_complete == Some(true)
                    && source
                        .physical_line_end
                        .is_some_and(|line_end| line_end > 0)
                    && artifact_id_is_unique(bundle, &source.artifact.artifact_id)
                    && source_is_admitted(source)
            })
        {
            continue;
        }
        if observations.iter().any(|observation| {
            observation
                .next_artifacts
                .iter()
                .any(|request| request.logical_artifact_id == group)
        }) {
            continue;
        }

        let state = coverage_for_group(bundle, group);
        let request = workflow_request_for_group(
            group,
            if group == MP_AUTH_GROUP {
                "Capture bounded MP_GetAuth.log coverage before evaluating Management Point requests."
            } else {
                "Capture bounded MP_GetPolicy.log coverage before evaluating later Management Point phases."
            },
        );
        let observation_id = format!("observation:coverage:{group}");
        observations.push(SccmManagementPointSourceLocalObservation {
            observation_id: observation_id.clone(),
            phase: entry_phase_for_group(group),
            state: SccmManagementPointState::Incomplete,
            classification: SccmManagementPointClassification::InsufficientEvidence,
            confidence: SccmManagementPointConfidence::Low,
            correlation_eligible: false,
            evidence: Vec::new(),
            next_artifacts: vec![request.clone()],
        });
        let gap = SccmManagementPointCoverageGap {
            logical_artifact_id: group.to_owned(),
            role: SccmRole::ManagementPoint,
            state,
        };
        if let Some(finding) = build_source_local_finding(
            &format!("finding:mp-coverage:{group}"),
            &observation_id,
            entry_phase_for_group(group),
            SccmManagementPointClassification::InsufficientEvidence,
            Vec::new(),
            Some(&gap),
            &[request],
        ) {
            findings.push(finding);
        }
        coverage_gaps.push(gap);
        consumed_gap_groups.insert(group.to_owned());
    }
}

fn build_source_local_finding(
    finding_id: &str,
    subject_id: &str,
    phase: SccmManagementPointPhase,
    classification: SccmManagementPointClassification,
    evidence: Vec<SccmEvidenceRef>,
    gap: Option<&SccmManagementPointCoverageGap>,
    requests: &[SccmManagementPointArtifactRequest],
) -> Option<SccmManagementPointFinding> {
    let class = if classification == SccmManagementPointClassification::InsufficientEvidence {
        SccmFindingClass::InsufficientEvidence
    } else {
        SccmFindingClass::Symptom
    };
    let mut builder = SccmFindingBuilder::new(finding_id)
        .class(class)
        .phase(SccmPhase::Unknown(phase.serialized_name().to_owned()))
        .role(SccmRole::ManagementPoint)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .title("Management Point source-local evidence")
        .summary("The observation is source-local and is not eligible for cross-side correlation.")
        .evidence(evidence)
        .next_artifacts(
            requests
                .iter()
                .filter_map(shared_request)
                .collect::<Vec<_>>(),
        );
    if let Some(gap) = gap {
        builder = builder.coverage_gap(shared_gap(gap));
    }
    Some(SccmManagementPointFinding {
        finding: builder.build().ok()?,
        subject_id: subject_id.to_owned(),
        last_successful_phase: None,
    })
}

fn workflow_request_for_group(group: &str, reason: &str) -> SccmManagementPointArtifactRequest {
    SccmManagementPointArtifactRequest {
        logical_artifact_id: group.to_owned(),
        reason: reason.to_owned(),
    }
}

fn shared_request(request: &SccmManagementPointArtifactRequest) -> Option<SccmArtifactRequest> {
    let logical_id = match request.logical_artifact_id.as_str() {
        MP_AUTH_GROUP => "mpGetAuth",
        MP_POLICY_GROUP => "mpGetPolicy",
        _ => return None,
    };
    Some(SccmArtifactRequest {
        logical_id: logical_id.to_owned(),
        role: SccmRole::ManagementPoint,
        reason: match request.logical_artifact_id.as_str() {
            MP_AUTH_GROUP => "Collect the complete MP_GetAuth.log file.",
            MP_POLICY_GROUP => "Collect the complete MP_GetPolicy.log file.",
            _ => return None,
        }
        .to_owned(),
    })
}

fn shared_gap(gap: &SccmManagementPointCoverageGap) -> SccmFindingCoverageGap {
    SccmFindingCoverageGap {
        artifact_id: gap.logical_artifact_id.clone(),
        role: gap.role.clone(),
        coverage: gap.state.clone(),
    }
}

fn group_for_phase(phase: SccmManagementPointPhase) -> &'static str {
    match phase {
        SccmManagementPointPhase::ReceiveRequest
        | SccmManagementPointPhase::Authenticate
        | SccmManagementPointPhase::RegisterOrIdentify => MP_AUTH_GROUP,
        SccmManagementPointPhase::ResolveLocationOrPolicy
        | SccmManagementPointPhase::Respond
        | SccmManagementPointPhase::RecordOutcome => MP_POLICY_GROUP,
    }
}

fn missing_phase_reason(phase: SccmManagementPointPhase) -> &'static str {
    match phase {
        SccmManagementPointPhase::ReceiveRequest
        | SccmManagementPointPhase::Authenticate
        | SccmManagementPointPhase::RegisterOrIdentify => {
            "Capture bounded MP_GetAuth.log evidence before evaluating the missing authentication-family phase."
        }
        SccmManagementPointPhase::ResolveLocationOrPolicy
        | SccmManagementPointPhase::Respond
        | SccmManagementPointPhase::RecordOutcome => {
            "Capture bounded MP_GetPolicy.log evidence before evaluating the missing policy-family phase."
        }
    }
}

fn contradiction_reason(phase: SccmManagementPointPhase) -> &'static str {
    match group_for_phase(phase) {
        MP_AUTH_GROUP => {
            "Recapture bounded MP_GetAuth.log evidence to resolve the same-instant authentication-family contradiction."
        }
        _ => {
            "Recapture bounded MP_GetPolicy.log evidence to resolve the same-instant policy-family contradiction."
        }
    }
}

fn chronology_reason(phase: SccmManagementPointPhase) -> &'static str {
    match group_for_phase(phase) {
        MP_AUTH_GROUP => {
            "Recapture bounded MP_GetAuth.log evidence with usable ordering provenance for this phase."
        }
        _ => {
            "Recapture bounded MP_GetPolicy.log evidence with usable ordering provenance for this phase."
        }
    }
}

fn timestamp_reason(phase: SccmManagementPointPhase) -> &'static str {
    chronology_reason(phase)
}

fn deferred_reason(phase: SccmManagementPointPhase) -> &'static str {
    match group_for_phase(phase) {
        MP_AUTH_GROUP => {
            "Capture a later bounded MP_GetAuth.log terminal outcome for the same exact request key."
        }
        _ => {
            "Capture a later bounded MP_GetPolicy.log terminal outcome for the same exact request key."
        }
    }
}

fn coverage_for_group(bundle: &SccmManagementPointBundle, group: &str) -> SccmCoverageState {
    let states = bundle
        .sources
        .iter()
        .filter(|source| source.source_group == group && !is_supplemental_source(source))
        .map(|source| {
            if source.artifact.coverage == SccmCoverageState::Captured
                && (source.fragment_complete != Some(true)
                    || source
                        .physical_line_end
                        .is_none_or(|line_end| line_end == 0))
            {
                SccmCoverageState::ParseFailed
            } else {
                source.artifact.coverage.clone()
            }
        })
        .collect::<Vec<_>>();
    for preferred in [
        SccmCoverageState::AccessDenied,
        SccmCoverageState::Capped,
        SccmCoverageState::ParseFailed,
        SccmCoverageState::Unsupported,
        SccmCoverageState::Skipped,
        SccmCoverageState::Absent,
    ] {
        if states.contains(&preferred) {
            return preferred;
        }
    }
    if states.contains(&SccmCoverageState::Captured) {
        return SccmCoverageState::ParseFailed;
    }
    SccmCoverageState::Absent
}

fn compare_observations(
    left: &SccmManagementPointObservation,
    right: &SccmManagementPointObservation,
) -> Ordering {
    left.phase
        .cmp(&right.phase)
        .then_with(|| left.timestamp.utc_millis.cmp(&right.timestamp.utc_millis))
        .then_with(|| left.observation_id.cmp(&right.observation_id))
}

fn normalize_analysis(
    transactions: &mut [SccmManagementPointTransaction],
    observations: &mut [SccmManagementPointSourceLocalObservation],
    findings: &mut [SccmManagementPointFinding],
    coverage_gaps: &mut Vec<SccmManagementPointCoverageGap>,
    counterpart_facts: &mut [SccmManagementPointCounterpartReadyFact],
) {
    transactions.sort_by(|left, right| left.transaction_id.cmp(&right.transaction_id));
    observations.sort_by(|left, right| left.observation_id.cmp(&right.observation_id));
    findings.sort_by(|left, right| {
        left.subject_id
            .cmp(&right.subject_id)
            .then_with(|| left.finding.finding_id.cmp(&right.finding.finding_id))
    });
    coverage_gaps.sort_by(|left, right| {
        left.logical_artifact_id
            .cmp(&right.logical_artifact_id)
            .then_with(|| coverage_order(&left.state).cmp(&coverage_order(&right.state)))
    });
    coverage_gaps.dedup_by(|right, left| {
        right.logical_artifact_id == left.logical_artifact_id
            && right.role == left.role
            && right.state == left.state
    });
    counterpart_facts.sort_by(|left, right| {
        left.transaction_id
            .cmp(&right.transaction_id)
            .then_with(|| compare_references(&left.evidence, &right.evidence))
    });
}

fn collect_artifact_requests(
    transactions: &[SccmManagementPointTransaction],
    observations: &[SccmManagementPointSourceLocalObservation],
) -> Vec<SccmManagementPointArtifactRequest> {
    let mut requests = transactions
        .iter()
        .flat_map(|transaction| transaction.next_artifacts.iter())
        .chain(
            observations
                .iter()
                .flat_map(|observation| observation.next_artifacts.iter()),
        )
        .cloned()
        .collect::<Vec<_>>();
    requests.sort_by(|left, right| {
        left.logical_artifact_id
            .cmp(&right.logical_artifact_id)
            .then_with(|| left.reason.cmp(&right.reason))
    });
    requests.dedup();
    requests
}

fn coverage_order(state: &SccmCoverageState) -> u8 {
    match state {
        SccmCoverageState::Captured => 0,
        SccmCoverageState::Absent => 1,
        SccmCoverageState::AccessDenied => 2,
        SccmCoverageState::Capped => 3,
        SccmCoverageState::Skipped => 4,
        SccmCoverageState::Unsupported => 5,
        SccmCoverageState::ParseFailed => 6,
    }
}
