//! SCCM client policy and assignment reduction over sealed client admission.
//!
//! The public entry point accepts the canonical intake inputs because they are
//! the only public way to obtain the opaque admitted-evidence capability. Raw
//! normalized evidence, extraction profiles, keys, and findings are never
//! accepted from callers.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use thiserror::Error;

use crate::models::log_entry::Severity;
use crate::sccm::{
    SccmArtifactFamily, SccmArtifactRequest, SccmClientAdmittedEvidence, SccmClientCapturedPayload,
    SccmClientEvidenceAdmissionError, SccmClientIntakeAssessment, SccmClientIntakeBundle,
    SccmConfidence, SccmCorrelationKey, SccmCorrelationKeyKind, SccmCoverageState, SccmEvidence,
    SccmEvidenceRef, SccmExtractionGapKind, SccmFinding, SccmFindingBuilder, SccmFindingClass,
    SccmFindingCoverageGap, SccmFindingValidationError, SccmKeyConfidence, SccmPhase, SccmRole,
    SccmRotation, SccmTerminalEvidence, SccmTimeOrderingState, SccmTimestamp,
    SCCM_POLICY_KEY_PROFILE_ID,
};

use super::admit_client_evidence;

const POLICY_AGENT_GROUP: &str = "client-policy-agent";
const POLICY_STATE_GROUP: &str = "client-policy-state";
const CLIENT_LOCATION_GROUP: &str = "client-location";

type EvidenceIdentity = (String, String, Option<u32>, Option<u32>);

const PHASES: [SccmPolicyPhase; 7] = [
    SccmPolicyPhase::Request,
    SccmPolicyPhase::Download,
    SccmPolicyPhase::TransferAuth,
    SccmPolicyPhase::Persist,
    SccmPolicyPhase::Schedule,
    SccmPolicyPhase::Evaluate,
    SccmPolicyPhase::Report,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmPolicyPhase {
    Request,
    Download,
    TransferAuth,
    Persist,
    Schedule,
    Evaluate,
    Report,
}

impl SccmPolicyPhase {
    fn rank(self) -> u8 {
        match self {
            Self::Request => 0,
            Self::Download => 1,
            Self::TransferAuth => 2,
            Self::Persist => 3,
            Self::Schedule => 4,
            Self::Evaluate => 5,
            Self::Report => 6,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmPolicyObservationOutcome {
    Succeeded,
    Failed,
    Deferred,
    Observed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmPolicyState {
    Succeeded,
    Failed,
    Deferred,
    Incomplete,
    Contradictory,
    Observed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmPolicyClassification {
    Success,
    ConfirmedFailure,
    BlockedOrDeferred,
    InsufficientEvidence,
    ContradictoryEvidence,
    LowConfidenceSymptom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmPolicyCondition {
    NoAssignment,
    StaleAssignment,
    TransferAuthenticationFailure,
    DownloadFailure,
    ProcessingFailure,
    SchedulerBlocked,
    EvaluationFailure,
    ReportingFailure,
    CoverageGap,
    UnknownProfile,
    MalformedKey,
    OrderingUnavailable,
    ConflictingEvidence,
    RotationSplit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmPolicyProfileSelectionState {
    Selected,
    UnvalidatedVersion,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmPolicyExtractionProfile {
    pub selection_state: SccmPolicyProfileSelectionState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    /// The only validated policy profile is the committed synthetic fixture
    /// profile. This is not a claim of stability for any production ConfigMgr
    /// version.
    pub synthetic_fixture_only: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmPolicyCoverage {
    pub logical_artifact_id: String,
    pub state: SccmCoverageState,
    pub artifact_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmPolicyProfileGap {
    pub artifact_id: String,
    pub condition: SccmPolicyCondition,
    pub selected_configmgr_version: Option<String>,
    pub evidence: Option<SccmEvidenceRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmPolicyTransactionKey {
    pub assignment_id: String,
    pub policy_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    pub extraction_profile_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmPolicyObservation {
    pub observation_id: String,
    pub phase: SccmPolicyPhase,
    pub outcome: SccmPolicyObservationOutcome,
    pub terminal: bool,
    pub timestamp: SccmTimestamp,
    pub evidence: SccmEvidenceRef,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmPolicyTransaction {
    pub transaction_id: String,
    pub key: SccmPolicyTransactionKey,
    pub phase: SccmPolicyPhase,
    pub state: SccmPolicyState,
    pub classification: SccmPolicyClassification,
    pub condition: Option<SccmPolicyCondition>,
    pub last_confirmed_phase: Option<SccmPolicyPhase>,
    pub confidence: SccmConfidence,
    pub correlation_keys: Vec<SccmCorrelationKey>,
    pub observations: Vec<SccmPolicyObservation>,
    pub evidence: Vec<SccmEvidenceRef>,
    pub coverage_gaps: Vec<SccmFindingCoverageGap>,
    pub next_artifacts: Vec<SccmArtifactRequest>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmPolicySourceLocalObservation {
    pub observation_id: String,
    pub state: SccmPolicyState,
    pub classification: SccmPolicyClassification,
    pub condition: SccmPolicyCondition,
    pub confidence: SccmConfidence,
    pub correlation_eligible: bool,
    pub artifact_ids: Vec<String>,
    pub evidence: Vec<SccmEvidenceRef>,
    pub next_artifacts: Vec<SccmArtifactRequest>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmPolicyAnalysis {
    pub workflow: String,
    pub state_chain: Vec<SccmPolicyPhase>,
    pub extraction_profile: SccmPolicyExtractionProfile,
    pub coverage: Vec<SccmPolicyCoverage>,
    pub profile_gaps: Vec<SccmPolicyProfileGap>,
    pub transactions: Vec<SccmPolicyTransaction>,
    pub source_local_observations: Vec<SccmPolicySourceLocalObservation>,
    pub findings: Vec<SccmFinding>,
    pub artifact_requests: Vec<SccmArtifactRequest>,
    pub cross_source_correlation_performed: bool,
    pub time_only_causality_allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SccmPolicyError {
    #[error("client policy evidence admission failed: {0}")]
    Admission(#[from] SccmClientEvidenceAdmissionError),
    #[error("client policy finding failed the shared finding contract: {0:?}")]
    InvalidFinding(SccmFindingValidationError),
    #[error("client policy admitted evidence did not retain its integrity seal")]
    IntegrityViolation,
}

#[derive(Debug, Clone)]
struct PolicyFact {
    assignment_id: String,
    policy_id: String,
    request_id: Option<String>,
    phase: SccmPolicyPhase,
    outcome: SccmPolicyObservationOutcome,
    condition: Option<SccmPolicyCondition>,
    terminal: bool,
    timestamp: SccmTimestamp,
    reference: SccmEvidenceRef,
    keys: Vec<SccmCorrelationKey>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PhaseResolution {
    Succeeded,
    Failed,
    Deferred,
    Contradictory,
}

#[derive(Debug)]
struct ReducedTransaction {
    transaction: SccmPolicyTransaction,
    finding: Option<SccmFinding>,
}

/// Reduces one client policy bundle through canonical intake and sealed raw
/// CCM admission. Callers cannot supply normalized evidence, profiles, keys,
/// or findings to this boundary.
pub fn analyze_client_policy(
    bundle: &SccmClientIntakeBundle,
    assessment: &SccmClientIntakeAssessment,
    payloads: &[SccmClientCapturedPayload],
) -> Result<SccmPolicyAnalysis, SccmPolicyError> {
    let admitted = admit_client_evidence(bundle, assessment, payloads)?;
    admitted.verify_integrity()?;
    reduce_policy(assessment, &admitted)
}

fn reduce_policy(
    assessment: &SccmClientIntakeAssessment,
    admitted: &SccmClientAdmittedEvidence,
) -> Result<SccmPolicyAnalysis, SccmPolicyError> {
    let evidence = admitted.evidence()?;
    let policy_evidence = evidence
        .iter()
        .filter(|entry| is_policy_component(entry.component.as_deref()))
        .collect::<Vec<_>>();
    let extraction_by_evidence = extraction_results(admitted, &policy_evidence)?;

    let mut profile_gaps = Vec::new();
    let mut source_local_observations = rotation_observations(assessment);
    let mut facts = Vec::new();
    for entry in policy_evidence {
        let identity = evidence_identity(&entry.reference);
        let Some(extraction) = extraction_by_evidence.get(&identity) else {
            return Err(SccmPolicyError::IntegrityViolation);
        };
        if extraction
            .gaps
            .iter()
            .any(|gap| gap.kind == SccmExtractionGapKind::UnvalidatedVersion)
        {
            profile_gaps.push(SccmPolicyProfileGap {
                artifact_id: entry.reference.artifact_id.clone(),
                condition: SccmPolicyCondition::UnknownProfile,
                selected_configmgr_version: extraction
                    .gaps
                    .first()
                    .and_then(|gap| gap.selected_configmgr_version.clone()),
                evidence: Some(entry.reference.clone()),
            });
            source_local_observations.push(source_local_from_evidence(
                entry,
                SccmPolicyCondition::UnknownProfile,
                request_for_group(POLICY_AGENT_GROUP, SccmPolicyCondition::UnknownProfile),
            ));
            continue;
        }
        if extraction
            .gaps
            .iter()
            .any(|gap| gap.kind == SccmExtractionGapKind::MalformedCandidate)
        {
            profile_gaps.push(SccmPolicyProfileGap {
                artifact_id: entry.reference.artifact_id.clone(),
                condition: SccmPolicyCondition::MalformedKey,
                selected_configmgr_version: None,
                evidence: Some(entry.reference.clone()),
            });
        }

        let Some(phase) = phase_from_message(&entry.message) else {
            if message_has_no_assignment(&entry.message) {
                source_local_observations.push(source_local_from_evidence(
                    entry,
                    SccmPolicyCondition::NoAssignment,
                    Vec::new(),
                ));
            }
            continue;
        };
        let Some(outcome) = outcome_from_message(&entry.message) else {
            continue;
        };
        let Some(assignment_id) =
            unique_exact_key(extraction, SccmCorrelationKeyKind::AssignmentId)
        else {
            source_local_observations.push(source_local_from_evidence(
                entry,
                SccmPolicyCondition::MalformedKey,
                request_for_group(POLICY_AGENT_GROUP, SccmPolicyCondition::MalformedKey),
            ));
            continue;
        };
        let Some(policy_id) = unique_exact_key(extraction, SccmCorrelationKeyKind::PolicyId) else {
            source_local_observations.push(source_local_from_evidence(
                entry,
                SccmPolicyCondition::MalformedKey,
                request_for_group(POLICY_AGENT_GROUP, SccmPolicyCondition::MalformedKey),
            ));
            continue;
        };
        let request_id = optional_unique_exact_key(extraction, SccmCorrelationKeyKind::RequestId);
        let keys = extraction
            .keys
            .iter()
            .filter(|key| allowed_policy_key(&key.kind))
            .cloned()
            .collect();
        facts.push(PolicyFact {
            assignment_id,
            policy_id,
            request_id,
            phase,
            outcome,
            condition: condition_from_message(&entry.message, phase, outcome),
            terminal: entry.message.to_ascii_lowercase().contains("terminal"),
            timestamp: entry.timestamp.clone(),
            reference: entry.reference.clone(),
            keys,
        });
    }

    let conflicting_assignments = conflicting_assignment_ids(&facts);
    let mut grouped = BTreeMap::<(String, String), Vec<PolicyFact>>::new();
    for fact in facts {
        if conflicting_assignments.contains(&fact.assignment_id) {
            source_local_observations.push(source_local_from_fact(
                &fact,
                SccmPolicyCondition::ConflictingEvidence,
            ));
            continue;
        }
        grouped
            .entry((fact.assignment_id.clone(), fact.policy_id.clone()))
            .or_default()
            .push(fact);
    }

    let mut transactions = Vec::new();
    let mut findings = Vec::new();
    for (_, facts) in grouped {
        let reduced = reduce_transaction(assessment, facts)?;
        if let Some(finding) = reduced.finding {
            findings.push(finding);
        }
        transactions.push(reduced.transaction);
    }
    transactions.sort_by(|left, right| left.transaction_id.cmp(&right.transaction_id));
    findings.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
    profile_gaps.sort_by(profile_gap_order);
    profile_gaps.dedup();
    source_local_observations.sort_by(|left, right| left.observation_id.cmp(&right.observation_id));
    source_local_observations.dedup_by(|left, right| left.observation_id == right.observation_id);
    let cross_source_correlation_performed = transactions
        .iter()
        .any(|transaction| transaction_spans_source_groups(assessment, transaction));

    let mut artifact_requests = transactions
        .iter()
        .flat_map(|transaction| transaction.next_artifacts.iter().cloned())
        .chain(
            source_local_observations
                .iter()
                .flat_map(|observation| observation.next_artifacts.iter().cloned()),
        )
        .collect::<Vec<_>>();
    artifact_requests.sort_by(request_order);
    artifact_requests.dedup_by(|left, right| request_order(left, right).is_eq());

    let extraction_profile = if !profile_gaps.is_empty() {
        SccmPolicyExtractionProfile {
            selection_state: SccmPolicyProfileSelectionState::UnvalidatedVersion,
            profile_id: None,
            synthetic_fixture_only: true,
        }
    } else if assessment
        .physical_artifacts
        .iter()
        .any(|fragment| is_policy_basename(&fragment.basename))
    {
        SccmPolicyExtractionProfile {
            selection_state: SccmPolicyProfileSelectionState::Selected,
            profile_id: Some(SCCM_POLICY_KEY_PROFILE_ID.to_owned()),
            synthetic_fixture_only: true,
        }
    } else {
        SccmPolicyExtractionProfile {
            selection_state: SccmPolicyProfileSelectionState::Unavailable,
            profile_id: None,
            synthetic_fixture_only: true,
        }
    };

    Ok(SccmPolicyAnalysis {
        workflow: "policyAndAssignment".to_owned(),
        state_chain: PHASES.to_vec(),
        extraction_profile,
        coverage: policy_coverage(assessment),
        profile_gaps,
        transactions,
        source_local_observations,
        findings,
        artifact_requests,
        cross_source_correlation_performed,
        time_only_causality_allowed: false,
    })
}

fn transaction_spans_source_groups(
    assessment: &SccmClientIntakeAssessment,
    transaction: &SccmPolicyTransaction,
) -> bool {
    let artifact_ids = transaction
        .evidence
        .iter()
        .map(|reference| reference.artifact_id.as_str())
        .collect::<BTreeSet<_>>();
    assessment
        .groups
        .iter()
        .filter(|group| {
            group
                .fragments
                .iter()
                .any(|fragment| artifact_ids.contains(fragment.artifact_id.as_str()))
        })
        .take(2)
        .count()
        > 1
}

fn extraction_results(
    admitted: &SccmClientAdmittedEvidence,
    evidence: &[&SccmEvidence],
) -> Result<BTreeMap<EvidenceIdentity, crate::sccm::SccmKeyExtractionResult>, SccmPolicyError> {
    let artifact_ids = evidence
        .iter()
        .map(|entry| entry.reference.artifact_id.clone())
        .collect::<BTreeSet<_>>();
    let mut results = BTreeMap::new();
    for artifact_id in artifact_ids {
        let extraction = admitted.extract_keys_for_artifact(&artifact_id)?;
        if extraction.artifact_family() != &SccmArtifactFamily::ClientPolicy {
            continue;
        }
        let artifact_evidence = evidence
            .iter()
            .filter(|entry| entry.reference.artifact_id == artifact_id)
            .collect::<Vec<_>>();
        if artifact_evidence.len() != extraction.results().len() {
            return Err(SccmPolicyError::IntegrityViolation);
        }
        for (entry, result) in artifact_evidence.into_iter().zip(extraction.results()) {
            results.insert(evidence_identity(&entry.reference), result.clone());
        }
    }
    Ok(results)
}

fn reduce_transaction(
    assessment: &SccmClientIntakeAssessment,
    mut facts: Vec<PolicyFact>,
) -> Result<ReducedTransaction, SccmPolicyError> {
    facts.sort_by(fact_order);
    let assignment_id = facts[0].assignment_id.clone();
    let policy_id = facts[0].policy_id.clone();
    let transaction_id = format!("policy:assignment:{assignment_id}");
    let request_ids = facts
        .iter()
        .filter_map(|fact| fact.request_id.clone())
        .collect::<BTreeSet<_>>();
    let request_id = (request_ids.len() == 1)
        .then(|| request_ids.iter().next().cloned())
        .flatten();

    let mut observations = facts.iter().map(observation_from_fact).collect::<Vec<_>>();
    observations.sort_by(observation_order);
    let mut evidence = facts
        .iter()
        .map(|fact| fact.reference.clone())
        .collect::<Vec<_>>();
    evidence.sort_by(evidence_order);
    evidence.dedup();
    let mut correlation_keys = facts
        .iter()
        .flat_map(|fact| fact.keys.iter().cloned())
        .collect::<Vec<_>>();
    correlation_keys.sort_by(correlation_key_order);
    correlation_keys.dedup();

    let mut resolutions = BTreeMap::new();
    let mut representatives = BTreeMap::new();
    for phase in PHASES {
        let phase_facts = facts
            .iter()
            .filter(|fact| fact.phase == phase)
            .collect::<Vec<_>>();
        if phase_facts.is_empty() {
            continue;
        }
        let (resolution, representative) = resolve_phase(&phase_facts);
        resolutions.insert(phase, resolution);
        representatives.insert(phase, representative.reference.clone());
    }

    let chronology_conflict = cross_phase_chronology_conflict(&facts);
    let decisive = PHASES.iter().find_map(|phase| {
        resolutions.get(phase).and_then(|resolution| {
            (*resolution != PhaseResolution::Succeeded).then_some((*phase, *resolution))
        })
    });

    let (phase, state, classification, condition, last_confirmed_phase, mut confidence) =
        if let Some((_earlier, later)) = chronology_conflict {
            (
                later,
                SccmPolicyState::Contradictory,
                SccmPolicyClassification::ContradictoryEvidence,
                Some(SccmPolicyCondition::OrderingUnavailable),
                last_confirmed_successful_prefix(&facts),
                SccmConfidence::Low,
            )
        } else if let Some((phase, resolution)) = decisive {
            let last = last_success_before(&resolutions, phase);
            match resolution {
                PhaseResolution::Failed => {
                    let condition = facts
                        .iter()
                        .find(|fact| {
                            fact.phase == phase
                                && fact.outcome == SccmPolicyObservationOutcome::Failed
                        })
                        .and_then(|fact| fact.condition)
                        .or(Some(default_failure_condition(phase)));
                    let terminal = facts.iter().any(|fact| {
                        fact.phase == phase
                            && fact.outcome == SccmPolicyObservationOutcome::Failed
                            && fact.terminal
                    });
                    if terminal {
                        (
                            phase,
                            SccmPolicyState::Failed,
                            SccmPolicyClassification::ConfirmedFailure,
                            condition,
                            last,
                            SccmConfidence::High,
                        )
                    } else {
                        (
                            phase,
                            SccmPolicyState::Observed,
                            SccmPolicyClassification::LowConfidenceSymptom,
                            condition,
                            last,
                            SccmConfidence::Low,
                        )
                    }
                }
                PhaseResolution::Deferred => (
                    phase,
                    SccmPolicyState::Deferred,
                    SccmPolicyClassification::BlockedOrDeferred,
                    facts
                        .iter()
                        .find(|fact| {
                            fact.phase == phase
                                && fact.outcome == SccmPolicyObservationOutcome::Deferred
                        })
                        .and_then(|fact| fact.condition)
                        .or(Some(SccmPolicyCondition::SchedulerBlocked)),
                    last,
                    SccmConfidence::High,
                ),
                PhaseResolution::Contradictory => (
                    phase,
                    SccmPolicyState::Contradictory,
                    SccmPolicyClassification::ContradictoryEvidence,
                    Some(
                        if facts.iter().filter(|fact| fact.phase == phase).any(|fact| {
                            fact.timestamp.ordering_state != SccmTimeOrderingState::NormalizedUtc
                        }) {
                            SccmPolicyCondition::OrderingUnavailable
                        } else {
                            SccmPolicyCondition::ConflictingEvidence
                        },
                    ),
                    last,
                    SccmConfidence::Low,
                ),
                PhaseResolution::Succeeded => unreachable!(),
            }
        } else if resolutions.get(&SccmPolicyPhase::Report) == Some(&PhaseResolution::Succeeded) {
            (
                SccmPolicyPhase::Report,
                SccmPolicyState::Succeeded,
                SccmPolicyClassification::Success,
                None,
                Some(SccmPolicyPhase::Report),
                SccmConfidence::High,
            )
        } else {
            let last = last_contiguous_success(&resolutions);
            let missing = first_missing_required_phase(&resolutions, last);
            (
                missing,
                SccmPolicyState::Incomplete,
                SccmPolicyClassification::InsufficientEvidence,
                Some(SccmPolicyCondition::CoverageGap),
                last,
                SccmConfidence::Moderate,
            )
        };

    let mut coverage_gaps = relevant_coverage_gaps(assessment, phase, state, condition);
    let mut next_artifacts = next_artifacts_for(phase, state, condition);
    if condition == Some(SccmPolicyCondition::TransferAuthenticationFailure) {
        confidence = SccmConfidence::Moderate;
        let location_gap = finding_gap_for_group(assessment, CLIENT_LOCATION_GROUP);
        if let Some(gap) = location_gap {
            coverage_gaps.push(gap);
        }
        next_artifacts = request_for_group(
            CLIENT_LOCATION_GROUP,
            SccmPolicyCondition::TransferAuthenticationFailure,
        );
    }
    coverage_gaps.sort_by(coverage_gap_order);
    coverage_gaps.dedup();
    next_artifacts.sort_by(request_order);
    next_artifacts.dedup_by(|left, right| request_order(left, right).is_eq());

    let transaction = SccmPolicyTransaction {
        transaction_id: transaction_id.clone(),
        key: SccmPolicyTransactionKey {
            assignment_id,
            policy_id,
            request_id,
            extraction_profile_id: SCCM_POLICY_KEY_PROFILE_ID.to_owned(),
        },
        phase,
        state,
        classification,
        condition,
        last_confirmed_phase,
        confidence,
        correlation_keys,
        observations,
        evidence,
        coverage_gaps,
        next_artifacts,
    };
    let finding = build_transaction_finding(&transaction, &facts, &representatives)?;
    Ok(ReducedTransaction {
        transaction,
        finding,
    })
}

fn build_transaction_finding(
    transaction: &SccmPolicyTransaction,
    facts: &[PolicyFact],
    representatives: &BTreeMap<SccmPolicyPhase, SccmEvidenceRef>,
) -> Result<Option<SccmFinding>, SccmPolicyError> {
    if transaction.state == SccmPolicyState::Succeeded {
        return Ok(None);
    }
    let mut finding_evidence = if transaction.state == SccmPolicyState::Contradictory {
        facts
            .iter()
            .filter(|fact| fact.phase == transaction.phase)
            .map(|fact| fact.reference.clone())
            .collect::<Vec<_>>()
    } else {
        representatives
            .get(&transaction.phase)
            .cloned()
            .into_iter()
            .collect::<Vec<_>>()
    };
    if finding_evidence.is_empty() {
        finding_evidence = transaction.evidence.last().cloned().into_iter().collect();
    }
    finding_evidence.sort_by(evidence_order);
    finding_evidence.dedup();

    let terminal_evidence = if transaction.state == SccmPolicyState::Failed {
        facts
            .iter()
            .filter(|fact| {
                fact.phase == transaction.phase
                    && fact.outcome == SccmPolicyObservationOutcome::Failed
                    && fact.terminal
            })
            .map(|fact| SccmTerminalEvidence::observed_failure(fact.reference.clone()))
            .collect()
    } else {
        Vec::new()
    };
    let finding_keys = transaction
        .correlation_keys
        .iter()
        .filter(|key| {
            key.evidence
                .as_ref()
                .is_some_and(|reference| finding_evidence.contains(reference))
        })
        .cloned()
        .collect();
    let class = match transaction.state {
        SccmPolicyState::Failed => SccmFindingClass::ConfirmedFailure,
        SccmPolicyState::Deferred => SccmFindingClass::BlockedOrDeferred,
        SccmPolicyState::Incomplete if !transaction.coverage_gaps.is_empty() => {
            SccmFindingClass::InsufficientEvidence
        }
        SccmPolicyState::Incomplete
        | SccmPolicyState::Contradictory
        | SccmPolicyState::Observed => SccmFindingClass::Symptom,
        SccmPolicyState::Succeeded => return Ok(None),
    };
    let finding = SccmFindingBuilder::new(format!(
        "finding:{}:{:?}",
        transaction.transaction_id, transaction.phase
    ))
    .class(class)
    .phase(SccmPhase::Policy)
    .role(SccmRole::Client)
    .severity(if transaction.state == SccmPolicyState::Failed {
        Severity::Error
    } else {
        Severity::Warning
    })
    .confidence(transaction.confidence)
    .title("Client policy workflow evidence")
    .summary("The client policy result is bounded to sealed client-side CCM evidence; no management-point or application outcome is inferred.")
    .evidence(finding_evidence)
    .terminal_evidence(terminal_evidence)
    .coverage_gaps(transaction.coverage_gaps.clone())
    .correlation_keys(finding_keys)
    .next_artifacts(transaction.next_artifacts.clone())
    .build()
    .map_err(SccmPolicyError::InvalidFinding)?;
    Ok(Some(finding))
}

fn resolve_phase<'a>(facts: &[&'a PolicyFact]) -> (PhaseResolution, &'a PolicyFact) {
    let outcomes = facts
        .iter()
        .map(|fact| fact.outcome)
        .collect::<BTreeSet<_>>();
    if outcomes.len() == 1 {
        let representative = facts
            .iter()
            .copied()
            .max_by(|left, right| comparable_fact_order(left, right))
            .expect("phase has facts");
        return (
            resolution_for_outcome(representative.outcome),
            representative,
        );
    }
    if facts.iter().any(|fact| {
        fact.timestamp.ordering_state != SccmTimeOrderingState::NormalizedUtc
            || fact.timestamp.utc_millis.is_none()
    }) {
        return (PhaseResolution::Contradictory, facts[0]);
    }
    let latest_utc = facts
        .iter()
        .filter_map(|fact| fact.timestamp.utc_millis)
        .max()
        .expect("comparable phase facts have UTC");
    let latest = facts
        .iter()
        .copied()
        .filter(|fact| fact.timestamp.utc_millis == Some(latest_utc))
        .collect::<Vec<_>>();
    let latest_outcomes = latest
        .iter()
        .map(|fact| fact.outcome)
        .collect::<BTreeSet<_>>();
    if latest_outcomes.len() != 1 {
        return (PhaseResolution::Contradictory, latest[0]);
    }
    let representative = latest
        .into_iter()
        .max_by(|left, right| evidence_order(&left.reference, &right.reference))
        .expect("latest facts are nonempty");
    (
        resolution_for_outcome(representative.outcome),
        representative,
    )
}

fn resolution_for_outcome(outcome: SccmPolicyObservationOutcome) -> PhaseResolution {
    match outcome {
        SccmPolicyObservationOutcome::Succeeded => PhaseResolution::Succeeded,
        SccmPolicyObservationOutcome::Failed => PhaseResolution::Failed,
        SccmPolicyObservationOutcome::Deferred => PhaseResolution::Deferred,
        SccmPolicyObservationOutcome::Observed => PhaseResolution::Contradictory,
    }
}

fn cross_phase_chronology_conflict(
    facts: &[PolicyFact],
) -> Option<(SccmPolicyPhase, SccmPolicyPhase)> {
    for earlier in facts {
        for later in facts {
            if earlier.phase.rank() >= later.phase.rank() {
                continue;
            }
            let comparable = earlier.timestamp.ordering_state
                == SccmTimeOrderingState::NormalizedUtc
                && later.timestamp.ordering_state == SccmTimeOrderingState::NormalizedUtc
                && earlier.timestamp.utc_millis.is_some()
                && later.timestamp.utc_millis.is_some();
            if !comparable || earlier.timestamp.utc_millis >= later.timestamp.utc_millis {
                return Some((earlier.phase, later.phase));
            }
        }
    }
    None
}

fn last_success_before(
    resolutions: &BTreeMap<SccmPolicyPhase, PhaseResolution>,
    phase: SccmPolicyPhase,
) -> Option<SccmPolicyPhase> {
    PHASES
        .iter()
        .copied()
        .filter(|candidate| candidate.rank() < phase.rank())
        .filter(|candidate| resolutions.get(candidate) == Some(&PhaseResolution::Succeeded))
        .max_by_key(|candidate| candidate.rank())
}

fn last_contiguous_success(
    resolutions: &BTreeMap<SccmPolicyPhase, PhaseResolution>,
) -> Option<SccmPolicyPhase> {
    let mut last = None;
    for phase in PHASES {
        if phase == SccmPolicyPhase::TransferAuth && !resolutions.contains_key(&phase) {
            continue;
        }
        if resolutions.get(&phase) != Some(&PhaseResolution::Succeeded) {
            break;
        }
        last = Some(phase);
    }
    last
}

fn last_confirmed_successful_prefix(facts: &[PolicyFact]) -> Option<SccmPolicyPhase> {
    let mut last_phase = None;
    let mut last_utc_millis = None;
    for phase in PHASES {
        let phase_facts = facts
            .iter()
            .filter(|fact| fact.phase == phase)
            .collect::<Vec<_>>();
        if phase_facts.is_empty() {
            if phase == SccmPolicyPhase::TransferAuth {
                continue;
            }
            break;
        }
        let (resolution, representative) = resolve_phase(&phase_facts);
        if resolution != PhaseResolution::Succeeded
            || representative.timestamp.ordering_state != SccmTimeOrderingState::NormalizedUtc
        {
            break;
        }
        let Some(utc_millis) = representative.timestamp.utc_millis else {
            break;
        };
        if last_utc_millis.is_some_and(|confirmed| utc_millis <= confirmed) {
            break;
        }
        last_phase = Some(phase);
        last_utc_millis = Some(utc_millis);
    }
    last_phase
}

fn first_missing_required_phase(
    resolutions: &BTreeMap<SccmPolicyPhase, PhaseResolution>,
    last: Option<SccmPolicyPhase>,
) -> SccmPolicyPhase {
    PHASES
        .iter()
        .copied()
        .filter(|phase| *phase != SccmPolicyPhase::TransferAuth)
        .find(|phase| {
            last.is_none_or(|confirmed| phase.rank() > confirmed.rank())
                && !resolutions.contains_key(phase)
        })
        .unwrap_or(SccmPolicyPhase::Report)
}

fn phase_from_message(message: &str) -> Option<SccmPolicyPhase> {
    let value = message.to_ascii_lowercase();
    if value.contains("authentication") || value.contains("transfer auth") {
        Some(SccmPolicyPhase::TransferAuth)
    } else if value.contains("request") {
        Some(SccmPolicyPhase::Request)
    } else if value.contains("download") {
        Some(SccmPolicyPhase::Download)
    } else if value.contains("persist") || value.contains("processing corrupt") {
        Some(SccmPolicyPhase::Persist)
    } else if value.contains("schedule") || value.contains("stale assignment") {
        Some(SccmPolicyPhase::Schedule)
    } else if value.contains("evaluate") {
        Some(SccmPolicyPhase::Evaluate)
    } else if value.contains("report") || value.contains("status") {
        Some(SccmPolicyPhase::Report)
    } else {
        None
    }
}

fn outcome_from_message(message: &str) -> Option<SccmPolicyObservationOutcome> {
    let value = message.to_ascii_lowercase();
    if value.contains("failed") || value.contains("corrupt") {
        Some(SccmPolicyObservationOutcome::Failed)
    } else if value.contains("deferred") || value.contains("blocked") || value.contains("stale") {
        Some(SccmPolicyObservationOutcome::Deferred)
    } else if value.contains("succeeded") || value.contains("complete") {
        Some(SccmPolicyObservationOutcome::Succeeded)
    } else {
        None
    }
}

fn condition_from_message(
    message: &str,
    phase: SccmPolicyPhase,
    outcome: SccmPolicyObservationOutcome,
) -> Option<SccmPolicyCondition> {
    let value = message.to_ascii_lowercase();
    if value.contains("stale") {
        Some(SccmPolicyCondition::StaleAssignment)
    } else if outcome == SccmPolicyObservationOutcome::Deferred {
        Some(SccmPolicyCondition::SchedulerBlocked)
    } else if outcome == SccmPolicyObservationOutcome::Failed {
        Some(
            if value.contains("authentication") || value.contains("transfer auth") {
                SccmPolicyCondition::TransferAuthenticationFailure
            } else if value.contains("corrupt") || phase == SccmPolicyPhase::Persist {
                SccmPolicyCondition::ProcessingFailure
            } else {
                default_failure_condition(phase)
            },
        )
    } else {
        None
    }
}

fn default_failure_condition(phase: SccmPolicyPhase) -> SccmPolicyCondition {
    match phase {
        SccmPolicyPhase::Request | SccmPolicyPhase::TransferAuth => {
            SccmPolicyCondition::TransferAuthenticationFailure
        }
        SccmPolicyPhase::Download => SccmPolicyCondition::DownloadFailure,
        SccmPolicyPhase::Persist => SccmPolicyCondition::ProcessingFailure,
        SccmPolicyPhase::Schedule => SccmPolicyCondition::SchedulerBlocked,
        SccmPolicyPhase::Evaluate => SccmPolicyCondition::EvaluationFailure,
        SccmPolicyPhase::Report => SccmPolicyCondition::ReportingFailure,
    }
}

fn message_has_no_assignment(message: &str) -> bool {
    let value = message.to_ascii_lowercase();
    value.contains("no assignment") || value.contains("no policy assignment")
}

fn conflicting_assignment_ids(facts: &[PolicyFact]) -> BTreeSet<String> {
    let mut policies = BTreeMap::<String, BTreeSet<String>>::new();
    for fact in facts {
        policies
            .entry(fact.assignment_id.clone())
            .or_default()
            .insert(fact.policy_id.clone());
    }
    policies
        .into_iter()
        .filter_map(|(assignment, policies)| (policies.len() > 1).then_some(assignment))
        .collect()
}

fn unique_exact_key(
    extraction: &crate::sccm::SccmKeyExtractionResult,
    kind: SccmCorrelationKeyKind,
) -> Option<String> {
    let values = extraction
        .keys
        .iter()
        .filter(|key| key.kind == kind && key.confidence == SccmKeyConfidence::Exact)
        .map(|key| key.normalized.clone())
        .collect::<BTreeSet<_>>();
    (values.len() == 1)
        .then(|| values.into_iter().next())
        .flatten()
}

fn optional_unique_exact_key(
    extraction: &crate::sccm::SccmKeyExtractionResult,
    kind: SccmCorrelationKeyKind,
) -> Option<String> {
    unique_exact_key(extraction, kind)
}

fn allowed_policy_key(kind: &SccmCorrelationKeyKind) -> bool {
    matches!(
        kind,
        SccmCorrelationKeyKind::AssignmentId
            | SccmCorrelationKeyKind::PolicyId
            | SccmCorrelationKeyKind::RequestId
            | SccmCorrelationKeyKind::StateMessageId
            | SccmCorrelationKeyKind::SiteCode
    )
}

fn policy_coverage(assessment: &SccmClientIntakeAssessment) -> Vec<SccmPolicyCoverage> {
    [POLICY_AGENT_GROUP, POLICY_STATE_GROUP]
        .into_iter()
        .filter_map(|logical_artifact_id| {
            assessment.group(logical_artifact_id).map(|group| {
                let mut artifact_ids = group
                    .fragments
                    .iter()
                    .map(|fragment| fragment.artifact_id.clone())
                    .collect::<Vec<_>>();
                artifact_ids.sort();
                artifact_ids.dedup();
                SccmPolicyCoverage {
                    logical_artifact_id: logical_artifact_id.to_owned(),
                    state: group.coverage.clone(),
                    artifact_ids,
                }
            })
        })
        .collect()
}

fn relevant_coverage_gaps(
    assessment: &SccmClientIntakeAssessment,
    phase: SccmPolicyPhase,
    state: SccmPolicyState,
    condition: Option<SccmPolicyCondition>,
) -> Vec<SccmFindingCoverageGap> {
    if condition == Some(SccmPolicyCondition::TransferAuthenticationFailure) {
        return finding_gap_for_group(assessment, CLIENT_LOCATION_GROUP)
            .into_iter()
            .collect();
    }
    if state != SccmPolicyState::Incomplete {
        return Vec::new();
    }
    let group = if phase.rank() >= SccmPolicyPhase::Evaluate.rank() {
        POLICY_STATE_GROUP
    } else {
        POLICY_AGENT_GROUP
    };
    finding_gap_for_group(assessment, group)
        .into_iter()
        .collect()
}

fn finding_gap_for_group(
    assessment: &SccmClientIntakeAssessment,
    group: &str,
) -> Option<SccmFindingCoverageGap> {
    let coverage = assessment.group(group)?.coverage.clone();
    (coverage != SccmCoverageState::Captured).then(|| SccmFindingCoverageGap {
        artifact_id: group.to_owned(),
        role: SccmRole::Client,
        coverage,
    })
}

fn next_artifacts_for(
    phase: SccmPolicyPhase,
    state: SccmPolicyState,
    condition: Option<SccmPolicyCondition>,
) -> Vec<SccmArtifactRequest> {
    if state == SccmPolicyState::Succeeded || state == SccmPolicyState::Failed {
        return Vec::new();
    }
    if condition == Some(SccmPolicyCondition::TransferAuthenticationFailure) {
        return request_for_group(CLIENT_LOCATION_GROUP, condition.expect("condition"));
    }
    let group = if phase.rank() >= SccmPolicyPhase::Evaluate.rank() {
        POLICY_STATE_GROUP
    } else {
        POLICY_AGENT_GROUP
    };
    request_for_group(group, condition.unwrap_or(SccmPolicyCondition::CoverageGap))
}

fn request_for_group(group: &str, condition: SccmPolicyCondition) -> Vec<SccmArtifactRequest> {
    let (logical_id, reason) = match group {
        CLIENT_LOCATION_GROUP => (
            "clientLocation",
            "Collect the complete ClientLocation.log file.",
        ),
        POLICY_STATE_GROUP => ("ciAgent", "Collect the complete CIAgent.log file."),
        _ if matches!(
            condition,
            SccmPolicyCondition::SchedulerBlocked | SccmPolicyCondition::StaleAssignment
        ) =>
        {
            ("scheduler", "Collect the complete Scheduler.log file.")
        }
        _ => ("policyAgent", "Collect the complete PolicyAgent.log file."),
    };
    vec![SccmArtifactRequest {
        logical_id: logical_id.to_owned(),
        role: SccmRole::Client,
        reason: reason.to_owned(),
    }]
}

fn rotation_observations(
    assessment: &SccmClientIntakeAssessment,
) -> Vec<SccmPolicySourceLocalObservation> {
    let Some(group) = assessment.group(POLICY_AGENT_GROUP) else {
        return Vec::new();
    };
    let mut lineages = BTreeMap::<String, (Vec<String>, bool, bool)>::new();
    for fragment in &group.fragments {
        if fragment.fragment_complete == Some(false) {
            if let Some(lineage) = &fragment.rotation_lineage {
                let (artifact_ids, has_current, has_lo) =
                    lineages.entry(lineage.clone()).or_default();
                artifact_ids.push(fragment.artifact_id.clone());
                *has_current |= fragment.rotation == SccmRotation::Current;
                *has_lo |= fragment.rotation == SccmRotation::LoUnderscore;
            }
        }
    }
    lineages
        .into_iter()
        .filter_map(|(lineage, (mut artifact_ids, has_current, has_lo))| {
            artifact_ids.sort();
            artifact_ids.dedup();
            (has_current && has_lo).then(|| SccmPolicySourceLocalObservation {
                observation_id: format!(
                    "policy-source:rotation:{}:{}",
                    artifact_ids.join("+"),
                    lineage
                ),
                state: SccmPolicyState::Incomplete,
                classification: SccmPolicyClassification::InsufficientEvidence,
                condition: SccmPolicyCondition::RotationSplit,
                confidence: SccmConfidence::Low,
                correlation_eligible: false,
                artifact_ids,
                evidence: Vec::new(),
                next_artifacts: request_for_group(
                    POLICY_AGENT_GROUP,
                    SccmPolicyCondition::RotationSplit,
                ),
            })
        })
        .collect()
}

fn source_local_from_evidence(
    evidence: &SccmEvidence,
    condition: SccmPolicyCondition,
    next_artifacts: Vec<SccmArtifactRequest>,
) -> SccmPolicySourceLocalObservation {
    let reference = evidence.reference.clone();
    SccmPolicySourceLocalObservation {
        observation_id: format!(
            "policy-source:{}:{}-{}:{condition:?}",
            reference.artifact_id,
            reference.line_start.unwrap_or(0),
            reference.line_end.unwrap_or(0)
        ),
        state: SccmPolicyState::Observed,
        classification: SccmPolicyClassification::LowConfidenceSymptom,
        condition,
        confidence: SccmConfidence::Low,
        correlation_eligible: false,
        artifact_ids: vec![reference.artifact_id.clone()],
        evidence: vec![reference],
        next_artifacts,
    }
}

fn source_local_from_fact(
    fact: &PolicyFact,
    condition: SccmPolicyCondition,
) -> SccmPolicySourceLocalObservation {
    let reference = fact.reference.clone();
    SccmPolicySourceLocalObservation {
        observation_id: format!(
            "policy-source:{}:{}-{}:{condition:?}",
            reference.artifact_id,
            reference.line_start.unwrap_or(0),
            reference.line_end.unwrap_or(0)
        ),
        state: SccmPolicyState::Contradictory,
        classification: SccmPolicyClassification::ContradictoryEvidence,
        condition,
        confidence: SccmConfidence::Low,
        correlation_eligible: false,
        artifact_ids: vec![reference.artifact_id.clone()],
        evidence: vec![reference],
        next_artifacts: request_for_group(POLICY_AGENT_GROUP, condition),
    }
}

fn observation_from_fact(fact: &PolicyFact) -> SccmPolicyObservation {
    SccmPolicyObservation {
        observation_id: format!(
            "policy-observation:{}:{}-{}:{:?}:{:?}",
            fact.reference.artifact_id,
            fact.reference.line_start.unwrap_or(0),
            fact.reference.line_end.unwrap_or(0),
            fact.phase,
            fact.outcome
        ),
        phase: fact.phase,
        outcome: fact.outcome,
        terminal: fact.terminal,
        timestamp: fact.timestamp.clone(),
        evidence: fact.reference.clone(),
    }
}

fn is_policy_component(component: Option<&str>) -> bool {
    component.is_some_and(|component| {
        matches!(
            component.to_ascii_lowercase().as_str(),
            "policyagent" | "scheduler" | "ciagent" | "statemessage" | "statusagent"
        )
    })
}

fn is_policy_basename(basename: &str) -> bool {
    matches!(
        basename.to_ascii_lowercase().as_str(),
        "policyagent.log"
            | "policyagent.lo_"
            | "scheduler.log"
            | "ciagent.log"
            | "statemessage.log"
            | "statusagent.log"
    )
}

fn evidence_identity(reference: &SccmEvidenceRef) -> EvidenceIdentity {
    (
        reference.artifact_id.clone(),
        reference.entry_id.clone(),
        reference.line_start,
        reference.line_end,
    )
}

fn fact_order(left: &PolicyFact, right: &PolicyFact) -> Ordering {
    left.phase
        .rank()
        .cmp(&right.phase.rank())
        .then_with(|| comparable_fact_order(left, right))
}

fn comparable_fact_order(left: &PolicyFact, right: &PolicyFact) -> Ordering {
    left.timestamp
        .utc_millis
        .cmp(&right.timestamp.utc_millis)
        .then_with(|| evidence_order(&left.reference, &right.reference))
}

fn observation_order(left: &SccmPolicyObservation, right: &SccmPolicyObservation) -> Ordering {
    left.phase
        .rank()
        .cmp(&right.phase.rank())
        .then_with(|| evidence_order(&left.evidence, &right.evidence))
        .then_with(|| left.observation_id.cmp(&right.observation_id))
}

fn evidence_order(left: &SccmEvidenceRef, right: &SccmEvidenceRef) -> Ordering {
    left.artifact_id
        .cmp(&right.artifact_id)
        .then_with(|| left.line_start.cmp(&right.line_start))
        .then_with(|| left.line_end.cmp(&right.line_end))
        .then_with(|| left.entry_id.cmp(&right.entry_id))
}

fn correlation_key_order(left: &SccmCorrelationKey, right: &SccmCorrelationKey) -> Ordering {
    key_kind_order(&left.kind)
        .cmp(&key_kind_order(&right.kind))
        .then_with(|| left.normalized.cmp(&right.normalized))
        .then_with(|| optional_evidence_order(left.evidence.as_ref(), right.evidence.as_ref()))
}

fn key_kind_order(kind: &SccmCorrelationKeyKind) -> u8 {
    match kind {
        SccmCorrelationKeyKind::AssignmentId => 0,
        SccmCorrelationKeyKind::PolicyId => 1,
        SccmCorrelationKeyKind::RequestId => 2,
        SccmCorrelationKeyKind::StateMessageId => 3,
        SccmCorrelationKeyKind::SiteCode => 4,
        _ => 5,
    }
}

fn coverage_gap_order(left: &SccmFindingCoverageGap, right: &SccmFindingCoverageGap) -> Ordering {
    left.artifact_id.cmp(&right.artifact_id).then_with(|| {
        coverage_state_order(&left.coverage).cmp(&coverage_state_order(&right.coverage))
    })
}

fn coverage_state_order(state: &SccmCoverageState) -> u8 {
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

fn request_order(left: &SccmArtifactRequest, right: &SccmArtifactRequest) -> Ordering {
    left.logical_id
        .cmp(&right.logical_id)
        .then_with(|| left.reason.cmp(&right.reason))
}

fn profile_gap_order(left: &SccmPolicyProfileGap, right: &SccmPolicyProfileGap) -> Ordering {
    left.artifact_id
        .cmp(&right.artifact_id)
        .then_with(|| optional_evidence_order(left.evidence.as_ref(), right.evidence.as_ref()))
}

fn optional_evidence_order(
    left: Option<&SccmEvidenceRef>,
    right: Option<&SccmEvidenceRef>,
) -> Ordering {
    match (left, right) {
        (Some(left), Some(right)) => evidence_order(left, right),
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}
