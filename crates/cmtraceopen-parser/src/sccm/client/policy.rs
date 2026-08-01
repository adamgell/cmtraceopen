use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::models::log_entry::Severity;

use crate::sccm::{
    extract_signals, SccmArtifact, SccmArtifactRequest, SccmConfidence, SccmCoverageState,
    SccmEvidence, SccmEvidenceRef, SccmFinding, SccmFindingBuilder, SccmFindingClass,
    SccmFindingCoverageGap, SccmNormalizedBundle, SccmPhase, SccmRole, SccmRotation,
    SccmTerminalEvidence,
};

pub const SCCM_POLICY_ANALYSIS_SCHEMA_VERSION: u32 = 1;
pub const SCCM_POLICY_TEST_PROFILE_ID: &str = "policy-client-5.00.test-v1";

/// Labels admitted by the frozen key profile named by
/// [`SCCM_POLICY_TEST_PROFILE_ID`].
///
/// Extraction is closed over this list: an unlisted label is never read, and an
/// admitted label is only read when it occurs exactly once at an exact token
/// boundary. Ambiguous, duplicate, and embedded labels fail closed so a record
/// that cannot be keyed unambiguously never becomes exact evidence.
const POLICY_PROFILE_LABELS: [&str; 7] = [
    "AssignmentId",
    "ClientHandle",
    "PolicyId",
    "RequestId",
    "Result",
    "SelectedManagementPointHostHandle",
    "SiteCode",
];

const POLICY_AGENT_GROUP: &str = "client-policy-agent";
const POLICY_STATE_GROUP: &str = "client-policy-state";
const CLIENT_LOCATION_GROUP: &str = "client-location";

const POLICY_PHASES: [SccmPolicyPhase; 6] = [
    SccmPolicyPhase::Request,
    SccmPolicyPhase::Download,
    SccmPolicyPhase::Persist,
    SccmPolicyPhase::Schedule,
    SccmPolicyPhase::Evaluate,
    SccmPolicyPhase::Report,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmClientWorkflow {
    Policy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmPolicyPhase {
    Request,
    Download,
    Persist,
    Schedule,
    Evaluate,
    Report,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmWorkflowState {
    Succeeded,
    Failed,
    Deferred,
    Incomplete,
    Contradictory,
    Observed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmWorkflowClassification {
    Success,
    ConfirmedFailure,
    BlockedOrDeferred,
    InsufficientEvidence,
    ContradictoryEvidence,
    LowConfidenceSymptom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmWorkflowConfidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmPolicyKey {
    pub assignment_id: String,
    pub policy_id: String,
    pub request_id: String,
    pub client_handle: String,
    pub site_code: String,
    pub management_point_host_handle: String,
    pub extraction_profile_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmPolicyCounterpartReadyFact {
    pub phase: SccmPolicyPhase,
    pub extraction_profile_id: String,
    pub evidence: SccmEvidenceRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmWorkflowArtifactRequest {
    pub logical_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmWorkflowTransaction {
    pub transaction_id: String,
    pub key: SccmPolicyKey,
    pub counterpart_ready_fact: SccmPolicyCounterpartReadyFact,
    pub phase: SccmPolicyPhase,
    pub state: SccmWorkflowState,
    pub last_successful_phase: Option<SccmPolicyPhase>,
    pub classification: SccmWorkflowClassification,
    pub confidence: SccmWorkflowConfidence,
    pub evidence: Vec<SccmEvidenceRef>,
    pub coverage_gap_artifact_ids: Vec<String>,
    pub next_artifacts: Vec<SccmWorkflowArtifactRequest>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmSourceLocalObservation {
    pub observation_id: String,
    pub phase: Option<SccmPolicyPhase>,
    pub state: SccmWorkflowState,
    pub classification: SccmWorkflowClassification,
    pub confidence: SccmWorkflowConfidence,
    pub correlation_eligible: bool,
    pub evidence: Vec<SccmEvidenceRef>,
    pub next_artifacts: Vec<SccmWorkflowArtifactRequest>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmWorkflowAnalysis {
    pub schema_version: u32,
    pub workflow: SccmClientWorkflow,
    pub transactions: Vec<SccmWorkflowTransaction>,
    pub source_local_observations: Vec<SccmSourceLocalObservation>,
    pub findings: Vec<SccmFinding>,
    pub coverage_gaps: Vec<SccmFindingCoverageGap>,
    pub artifact_requests: Vec<SccmWorkflowArtifactRequest>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum FactOutcome {
    Succeeded,
    Failed,
    Deferred,
}

#[derive(Debug, Clone)]
struct PolicyFact {
    assignment_id: String,
    policy_id: String,
    phase: SccmPolicyPhase,
    outcome: FactOutcome,
    /// The declared source that recorded this fact.
    ///
    /// Carried on the fact so a repair request can name the file that holds the
    /// evidence. Without it the reducer can only guess from the phase, and the
    /// guess is wrong whenever a phase has more than one admissible source.
    source: &'static PolicySource,
    reference: SccmEvidenceRef,
    utc_millis: Option<i64>,
    time_comparable: bool,
    request_key: Option<SccmPolicyKey>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PhaseResolution {
    Succeeded,
    Failed,
    Deferred,
    Contradictory(RequestCause),
}

/// Why the reducer needs another artifact.
///
/// Request wording is keyed on this rather than on the phase, so a reason can
/// never assert a state the evidence does not have. A missing phase and a
/// deferred phase can both land on the scheduler, and only one of them is a
/// retry. [`RequestCause::UnusableTime`] and [`RequestCause::InvertedTime`] are
/// separated for the same reason: an unreadable offset and two valid offsets in
/// the wrong order need different wording and different remedies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestCause {
    MissingPhase,
    Deferred,
    ConflictingOutcomes,
    UnusableTime,
    InvertedTime,
    LocationContext,
}

/// One repair, named by the sources that would actually supply it.
///
/// The group answers the coverage question and the sources answer the collection
/// question, and both are read off the artifact holding the evidence rather than
/// off the phase. Deriving them from the phase is what let `Scheduler.log` and
/// `PolicyEvaluator.log` be undeliverable: no phase maps to them.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PolicyRepair {
    group: &'static str,
    sources: Vec<&'static PolicySource>,
    cause: RequestCause,
}

/// One declared client policy source: its file basename, its catalog logical
/// name, and the logical group whose coverage it answers for.
///
/// Group membership and request naming read the same row, so a source can never
/// be citable for coverage yet unnameable in a request.
#[derive(Debug, PartialEq, Eq)]
struct PolicySource {
    basename: &'static str,
    logical_name: &'static str,
    group: &'static str,
}

static POLICY_SOURCES: [PolicySource; 11] = [
    PolicySource {
        basename: "PolicyAgent",
        logical_name: "policyAgent",
        group: POLICY_AGENT_GROUP,
    },
    PolicySource {
        basename: "PolicyAgentProvider",
        logical_name: "policyAgentProvider",
        group: POLICY_AGENT_GROUP,
    },
    PolicySource {
        basename: "PolicyEvaluator",
        logical_name: "policyEvaluator",
        group: POLICY_AGENT_GROUP,
    },
    PolicySource {
        basename: "Scheduler",
        logical_name: "scheduler",
        group: POLICY_AGENT_GROUP,
    },
    PolicySource {
        basename: "CIAgent",
        logical_name: "ciAgent",
        group: POLICY_STATE_GROUP,
    },
    PolicySource {
        basename: "CIDownloader",
        logical_name: "ciDownloader",
        group: POLICY_STATE_GROUP,
    },
    PolicySource {
        basename: "StateMessage",
        logical_name: "stateMessage",
        group: POLICY_STATE_GROUP,
    },
    PolicySource {
        basename: "StatusAgent",
        logical_name: "statusAgent",
        group: POLICY_STATE_GROUP,
    },
    PolicySource {
        basename: "ClientLocation",
        logical_name: "clientLocation",
        group: CLIENT_LOCATION_GROUP,
    },
    PolicySource {
        basename: "LocationServices",
        logical_name: "locationServices",
        group: CLIENT_LOCATION_GROUP,
    },
    PolicySource {
        basename: "CcmMessaging",
        logical_name: "ccmMessaging",
        group: CLIENT_LOCATION_GROUP,
    },
];

struct ReductionContext<'a> {
    bundle: &'a SccmNormalizedBundle,
}

/// A confirmed terminal failure the proven chain could not reach.
///
/// The transaction stops at the first phase it cannot prove, so a failure
/// recorded past that point is not transaction evidence. Discarding it would
/// hide an Error-severity fact behind a moderate evidence gap, so it is carried
/// out of the reduction and reported as a source-local observation instead.
struct UnreachedFailure {
    phase: SccmPolicyPhase,
    evidence: Vec<SccmEvidenceRef>,
}

struct ReducedTransaction {
    transaction: SccmWorkflowTransaction,
    finding: Option<SccmFinding>,
    coverage_gaps: Vec<SccmFindingCoverageGap>,
    unreached_failure: Option<UnreachedFailure>,
    /// The repairs behind `transaction.next_artifacts`, kept so the caller can
    /// name the same sources without re-deriving them from a group.
    repairs: Vec<PolicyRepair>,
}

pub fn analyze_client_policy(bundle: &SccmNormalizedBundle) -> SccmWorkflowAnalysis {
    let (artifact_by_id, ambiguous_artifact_ids) = admissible_client_artifacts(bundle);
    let context = ReductionContext { bundle };

    let mut parsed_facts = Vec::new();
    let mut rejected_policy_evidence = Vec::new();
    let mut normalized_evidence_ids = BTreeSet::new();

    for evidence in &bundle.evidence {
        if !is_safe_evidence_reference(&evidence.reference) {
            continue;
        }
        if ambiguous_artifact_ids.contains(evidence.reference.artifact_id.as_str()) {
            // No artifact can speak for this id, so the record cannot be
            // admitted. It stays a visible local symptom rather than vanishing.
            rejected_policy_evidence.push(evidence.reference.clone());
            continue;
        }
        let Some(artifact) = artifact_by_id.get(evidence.reference.artifact_id.as_str()) else {
            continue;
        };
        if !is_admitted_policy_artifact(artifact) {
            continue;
        }
        normalized_evidence_ids.insert(artifact.artifact_id.as_str());

        if !is_validated_policy_version(artifact.configmgr_version.as_deref()) {
            rejected_policy_evidence.push(evidence.reference.clone());
            continue;
        }

        match parse_policy_fact(evidence, artifact) {
            Some(fact) => parsed_facts.push(fact),
            None => rejected_policy_evidence.push(evidence.reference.clone()),
        }
    }

    let mut facts_by_assignment: BTreeMap<String, Vec<PolicyFact>> = BTreeMap::new();
    for fact in quarantine_overlapping_evidence(parsed_facts, &mut rejected_policy_evidence) {
        facts_by_assignment
            .entry(fact.assignment_id.clone())
            .or_default()
            .push(fact);
    }

    let mut transactions = Vec::new();
    let mut findings = Vec::new();
    let mut coverage_gaps = Vec::new();
    let mut source_local_observations = Vec::new();

    for facts in facts_by_assignment.values_mut() {
        sort_facts(facts);
        if let Some(reduced) = reduce_policy_transaction(facts, &context) {
            coverage_gaps.extend(reduced.coverage_gaps);
            if let Some(finding) = reduced.finding {
                findings.push(finding);
            }
            if let Some(unreached) = reduced.unreached_failure {
                let requests = reduced.transaction.next_artifacts.clone();
                source_local_observations.push(SccmSourceLocalObservation {
                    observation_id: format!(
                        "policy:source-local:unreached-failure:{}",
                        reduced.transaction.key.assignment_id
                    ),
                    phase: Some(unreached.phase),
                    state: SccmWorkflowState::Failed,
                    classification: SccmWorkflowClassification::ConfirmedFailure,
                    // The record is proven terminal, its place in the chain is
                    // not, so it never carries the High of a proven chain.
                    confidence: SccmWorkflowConfidence::Medium,
                    correlation_eligible: false,
                    evidence: unreached.evidence.clone(),
                    next_artifacts: requests.clone(),
                });
                if let Some(finding) = build_unreached_failure_finding(
                    &reduced.transaction.key.assignment_id,
                    unreached.phase,
                    unreached.evidence,
                    finding_requests(&reduced.repairs),
                ) {
                    findings.push(finding);
                }
            }
            transactions.push(reduced.transaction);
        } else {
            rejected_policy_evidence.extend(facts.iter().map(|fact| fact.reference.clone()));
        }
    }

    let partial_policy_artifacts = partial_policy_artifacts(bundle, &normalized_evidence_ids);
    if !partial_policy_artifacts.is_empty() {
        let evidence = physical_fragment_references(&partial_policy_artifacts);
        let request = workflow_request(
            POLICY_AGENT_GROUP,
            "Recapture a bounded complete PolicyAgent logical record across current and supported rotation.",
        );
        source_local_observations.push(SccmSourceLocalObservation {
            observation_id: "policy:source-local:rotation-split".to_owned(),
            phase: None,
            state: SccmWorkflowState::Incomplete,
            classification: SccmWorkflowClassification::InsufficientEvidence,
            confidence: SccmWorkflowConfidence::Low,
            correlation_eligible: false,
            evidence: evidence.clone(),
            next_artifacts: vec![request.clone()],
        });
        let gap = SccmFindingCoverageGap {
            artifact_id: POLICY_AGENT_GROUP.to_owned(),
            role: SccmRole::Client,
            coverage: SccmCoverageState::Partial,
        };
        coverage_gaps.push(gap.clone());
        if let Some(finding) = build_rotation_partial_finding(evidence, gap) {
            findings.push(finding);
        }
    }

    sort_and_deduplicate_evidence(&mut rejected_policy_evidence);
    if !rejected_policy_evidence.is_empty() {
        let request = workflow_request(
            POLICY_AGENT_GROUP,
            "Capture bounded policy-agent evidence under a validated ConfigMgr version profile with a complete exact key.",
        );
        source_local_observations.push(SccmSourceLocalObservation {
            observation_id: "policy:source-local:malformed".to_owned(),
            phase: None,
            state: SccmWorkflowState::Observed,
            classification: SccmWorkflowClassification::LowConfidenceSymptom,
            confidence: SccmWorkflowConfidence::Low,
            correlation_eligible: false,
            evidence: rejected_policy_evidence.clone(),
            next_artifacts: vec![request],
        });
        if let Some(finding) = build_malformed_finding(rejected_policy_evidence) {
            findings.push(finding);
        }
    }

    coverage_gaps.extend(unavailable_client_policy_sources(bundle));
    normalize_analysis(
        &mut transactions,
        &mut source_local_observations,
        &mut findings,
        &mut coverage_gaps,
    );
    let artifact_requests = collect_workflow_requests(&transactions, &source_local_observations);

    SccmWorkflowAnalysis {
        schema_version: SCCM_POLICY_ANALYSIS_SCHEMA_VERSION,
        workflow: SccmClientWorkflow::Policy,
        transactions,
        source_local_observations,
        findings,
        coverage_gaps,
        artifact_requests,
    }
}

fn reduce_policy_transaction(
    facts: &[PolicyFact],
    context: &ReductionContext<'_>,
) -> Option<ReducedTransaction> {
    let request_facts = facts
        .iter()
        .filter(|fact| fact.phase == SccmPolicyPhase::Request)
        .collect::<Vec<_>>();
    let request_key = request_facts
        .iter()
        .find_map(|fact| fact.request_key.as_ref())?
        .clone();
    if request_facts
        .iter()
        .any(|fact| fact.request_key.as_ref() != Some(&request_key))
        || facts.iter().any(|fact| {
            fact.assignment_id != request_key.assignment_id
                || fact.policy_id != request_key.policy_id
        })
    {
        return None;
    }

    let counterpart_reference = request_facts
        .iter()
        .map(|fact| &fact.reference)
        .min_by(|left, right| compare_evidence_refs(left, right))?
        .clone();

    let mut last_successful_phase = None;
    let mut current_phase = SccmPolicyPhase::Request;
    let mut state = SccmWorkflowState::Incomplete;
    let mut classification = SccmWorkflowClassification::InsufficientEvidence;
    let mut confidence = SccmWorkflowConfidence::Medium;
    let mut coverage_gap_artifact_ids = Vec::new();
    let mut repairs: Vec<PolicyRepair> = Vec::new();
    let mut terminal_failure_references = Vec::new();

    for phase in POLICY_PHASES {
        let phase_facts = facts
            .iter()
            .filter(|fact| fact.phase == phase)
            .collect::<Vec<_>>();
        if phase_facts.is_empty() {
            current_phase = last_successful_phase.unwrap_or(SccmPolicyPhase::Request);
            let repair = repair_for_missing_phase(phase);
            coverage_gap_artifact_ids.push(repair.group.to_owned());
            repairs.push(repair);
            break;
        }

        current_phase = phase;
        match resolve_phase(&phase_facts) {
            PhaseResolution::Succeeded => {
                last_successful_phase = Some(phase);
                if phase == SccmPolicyPhase::Report {
                    state = SccmWorkflowState::Succeeded;
                    classification = SccmWorkflowClassification::Success;
                    confidence = SccmWorkflowConfidence::High;
                }
            }
            PhaseResolution::Failed => {
                state = SccmWorkflowState::Failed;
                classification = SccmWorkflowClassification::ConfirmedFailure;
                confidence = SccmWorkflowConfidence::High;
                terminal_failure_references.extend(
                    phase_facts
                        .iter()
                        .filter(|fact| fact.outcome == FactOutcome::Failed)
                        .map(|fact| fact.reference.clone()),
                );
                if phase == SccmPolicyPhase::Request
                    && group_has_no_captured_source(context, CLIENT_LOCATION_GROUP)
                {
                    confidence = SccmWorkflowConfidence::Medium;
                    coverage_gap_artifact_ids.push(CLIENT_LOCATION_GROUP.to_owned());
                    repairs.push(client_location_repair());
                }
                break;
            }
            PhaseResolution::Deferred => {
                state = SccmWorkflowState::Deferred;
                classification = SccmWorkflowClassification::BlockedOrDeferred;
                confidence = SccmWorkflowConfidence::High;
                let deferred = phase_facts
                    .iter()
                    .filter(|fact| fact.outcome == FactOutcome::Deferred)
                    .copied()
                    .collect::<Vec<_>>();
                repairs.extend(repair_from_facts(&deferred, RequestCause::Deferred));
                break;
            }
            PhaseResolution::Contradictory(cause) => {
                state = SccmWorkflowState::Contradictory;
                classification = SccmWorkflowClassification::ContradictoryEvidence;
                confidence = SccmWorkflowConfidence::Low;
                repairs.extend(repair_from_facts(&phase_facts, cause));
                break;
            }
        }
    }

    // A chronology break disowns the order the loop's request presupposes: a
    // phase can only be called missing once the surrounding phases can be
    // sequenced. The break replaces the request rather than joining it, so one
    // finding asks for one repair. The coverage gap the loop recorded stays,
    // because an absent source is absent whatever the clocks say.
    if let Some(repair) = cross_phase_time_inversion_repair(facts, current_phase) {
        state = SccmWorkflowState::Contradictory;
        classification = SccmWorkflowClassification::ContradictoryEvidence;
        confidence = SccmWorkflowConfidence::Low;
        last_successful_phase = None;
        terminal_failure_references.clear();
        repairs.clear();
        repairs.push(repair);
    } else if state != SccmWorkflowState::Contradictory {
        // Two sources can only be placed in sequence by comparable time. A
        // contradiction already carries the most conservative answer, so only a
        // transaction still claiming an order is capped here.
        if let Some(repair) = unprovable_chronology_repair(facts, current_phase) {
            if state == SccmWorkflowState::Succeeded {
                state = SccmWorkflowState::Incomplete;
                classification = SccmWorkflowClassification::InsufficientEvidence;
            }
            confidence = SccmWorkflowConfidence::Low;
            last_successful_phase = None;
            coverage_gap_artifact_ids.push(repair.group.to_owned());
            repairs.clear();
            repairs.push(repair);
        }
    }

    coverage_gap_artifact_ids.sort();
    coverage_gap_artifact_ids.dedup();
    let mut next_artifacts = repairs.iter().map(workflow_request_for).collect::<Vec<_>>();
    next_artifacts.sort_by(|left, right| {
        left.logical_id
            .cmp(&right.logical_id)
            .then_with(|| left.reason.cmp(&right.reason))
    });
    next_artifacts.dedup();

    let mut evidence = facts
        .iter()
        .filter(|fact| fact.phase <= current_phase)
        .map(|fact| fact.reference.clone())
        .collect::<Vec<_>>();
    sort_and_deduplicate_evidence(&mut evidence);

    let unreached_failure = unreached_terminal_failure(facts, current_phase);

    let transaction_id = format!("policy:assignment:{}", request_key.assignment_id);
    let transaction = SccmWorkflowTransaction {
        transaction_id: transaction_id.clone(),
        key: request_key,
        counterpart_ready_fact: SccmPolicyCounterpartReadyFact {
            phase: SccmPolicyPhase::Request,
            extraction_profile_id: SCCM_POLICY_TEST_PROFILE_ID.to_owned(),
            evidence: counterpart_reference,
        },
        phase: current_phase,
        state,
        last_successful_phase,
        classification,
        confidence,
        evidence: evidence.clone(),
        coverage_gap_artifact_ids: coverage_gap_artifact_ids.clone(),
        next_artifacts: next_artifacts.clone(),
    };

    let gaps = coverage_gap_artifact_ids
        .iter()
        .flat_map(|logical_id| coverage_gaps_for_group(context, logical_id))
        .collect::<Vec<_>>();
    let finding = build_transaction_finding(
        &transaction,
        evidence,
        terminal_failure_references,
        gaps.clone(),
        &repairs,
    );

    Some(ReducedTransaction {
        transaction,
        finding,
        coverage_gaps: gaps,
        unreached_failure,
        repairs,
    })
}

fn resolve_phase(facts: &[&PolicyFact]) -> PhaseResolution {
    let mut outcomes = facts
        .iter()
        .map(|fact| fact.outcome)
        .collect::<BTreeSet<_>>()
        .into_iter();
    let Some(only) = outcomes.next() else {
        return PhaseResolution::Contradictory(RequestCause::ConflictingOutcomes);
    };
    if outcomes.next().is_none() {
        return resolution_for_outcome(only);
    }

    // Every mixed phase, including a deferred one, is decided by the latest
    // usable state. That is what lets a later same-artifact success recover an
    // earlier Deferred instead of freezing the phase as contradictory.
    latest_comparable_outcome(facts).unwrap_or_else(|| {
        // An unresolvable phase is either a genuine disagreement or a phase
        // whose records cannot be ordered at all. The remedies differ, so the
        // cause is carried into the request rather than flattened.
        PhaseResolution::Contradictory(if facts.iter().all(|fact| is_time_comparable(fact)) {
            RequestCause::ConflictingOutcomes
        } else {
            RequestCause::UnusableTime
        })
    })
}

/// The client artifacts that may authorize admission, keyed by artifact id.
///
/// Returns the usable map and the set of ids that no artifact can speak for.
/// Collecting into a map is last-wins, so a repeated id would otherwise make
/// artifact vector order the admission authority. Role scoping alone is not
/// enough: two client artifacts can carry the same id and disagree about
/// basename or coverage. This is the artifact-level twin of
/// [`quarantine_overlapping_evidence`]: an id that cannot be resolved is
/// withheld rather than guessed. An exactly repeated entry is not a conflict,
/// because every copy would answer identically.
///
/// The reported ambiguity is scoped, not global. An id is only reported when
/// one of the colliding artifacts would otherwise have been admitted as policy
/// evidence, because that is the only case where the clash costs this reducer a
/// source. A duplicated `AppEnforce.log` id is a real intake defect but not a
/// policy symptom, and escalating it would fabricate a policy finding and a
/// `PolicyAgent.log` request out of a log this reducer never reads.
fn admissible_client_artifacts(
    bundle: &SccmNormalizedBundle,
) -> (BTreeMap<&str, &SccmArtifact>, BTreeSet<&str>) {
    let mut candidates: BTreeMap<&str, Vec<&SccmArtifact>> = BTreeMap::new();
    for artifact in bundle
        .artifacts
        .iter()
        .filter(|artifact| artifact.role == SccmRole::Client)
    {
        candidates
            .entry(artifact.artifact_id.as_str())
            .or_default()
            .push(artifact);
    }

    let mut by_id = BTreeMap::new();
    let mut ambiguous = BTreeSet::new();
    for (id, artifacts) in candidates {
        let Some(first) = artifacts.first().copied() else {
            continue;
        };
        if artifacts.iter().all(|artifact| *artifact == first) {
            by_id.insert(id, first);
        } else if artifacts
            .iter()
            .any(|artifact| is_admitted_policy_artifact(artifact))
        {
            ambiguous.insert(id);
        }
    }
    (by_id, ambiguous)
}

/// Whether two references claim overlapping physical lines of one source.
///
/// Physical extent, not an identity tuple, is the question. Two logical records
/// from one artifact occupy disjoint lines, so any overlap means at least one
/// of them is not the record it claims to be. An equal range is the degenerate
/// overlap and is caught by the same test.
fn evidence_references_overlap(left: &SccmEvidenceRef, right: &SccmEvidenceRef) -> bool {
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

/// Drops every fact whose physical lines are claimed by another fact.
///
/// Comparing identity tuples only catches an exact repeat of one range. It
/// leaves the wider hole open: a record spanning 1-2 and a record spanning 1-1
/// are different identities over the same physical line, so both survive, and
/// [`compare_evidence_refs`] then ranks the wider range higher and lets it
/// decide the phase. One physical line proving two phases is the same hole seen
/// from the other side. Every participant in an overlap is quarantined into the
/// rejected set and proves nothing, which is the rule the management-point
/// reducer already applies.
fn quarantine_overlapping_evidence(
    facts: Vec<PolicyFact>,
    rejected: &mut Vec<SccmEvidenceRef>,
) -> Vec<PolicyFact> {
    let overlapping = {
        let mut by_artifact: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
        for (index, fact) in facts.iter().enumerate() {
            by_artifact
                .entry(fact.reference.artifact_id.as_str())
                .or_default()
                .push(index);
        }

        let mut overlapping = BTreeSet::new();
        for indexes in by_artifact.values() {
            for (position, &left) in indexes.iter().enumerate() {
                for &right in &indexes[position + 1..] {
                    if evidence_references_overlap(&facts[left].reference, &facts[right].reference)
                    {
                        overlapping.insert(left);
                        overlapping.insert(right);
                    }
                }
            }
        }
        overlapping
    };
    if overlapping.is_empty() {
        return facts;
    }

    let mut kept = Vec::new();
    for (index, fact) in facts.into_iter().enumerate() {
        if overlapping.contains(&index) {
            rejected.push(fact.reference);
        } else {
            kept.push(fact);
        }
    }
    kept
}

fn latest_comparable_outcome(facts: &[&PolicyFact]) -> Option<PhaseResolution> {
    let same_artifact = facts
        .iter()
        .map(|fact| fact.reference.artifact_id.as_str())
        .collect::<BTreeSet<_>>()
        .len()
        == 1;
    if same_artifact {
        return facts
            .iter()
            .max_by(|left, right| compare_evidence_refs(&left.reference, &right.reference))
            .map(|fact| resolution_for_outcome(fact.outcome));
    }

    if facts.iter().any(|fact| !fact.time_comparable) {
        return None;
    }
    let latest = facts.iter().max_by_key(|fact| fact.utc_millis)?;
    let latest_time = latest.utc_millis?;
    if facts
        .iter()
        .filter(|fact| fact.utc_millis == Some(latest_time))
        .map(|fact| fact.outcome)
        .collect::<BTreeSet<_>>()
        .len()
        != 1
    {
        return None;
    }
    Some(resolution_for_outcome(latest.outcome))
}

fn resolution_for_outcome(outcome: FactOutcome) -> PhaseResolution {
    match outcome {
        FactOutcome::Succeeded => PhaseResolution::Succeeded,
        FactOutcome::Failed => PhaseResolution::Failed,
        FactOutcome::Deferred => PhaseResolution::Deferred,
    }
}

fn parse_policy_fact(evidence: &SccmEvidence, artifact: &SccmArtifact) -> Option<PolicyFact> {
    let (phase, outcome) = classify_policy_record(&evidence.message)?;
    let source = policy_source(&artifact.display_name)?;
    if !source_allows_phase(&artifact.display_name, phase) {
        return None;
    }
    // Two-sided, not one-sided. A terminal marker without an explicit nonzero
    // result proves nothing, and a success or deferral carrying one contradicts
    // its own marker. A record whose marker and result code disagree cannot be
    // read either way, so neither direction becomes exact phase evidence.
    if has_terminal_failure_signal(&evidence.message) != (outcome == FactOutcome::Failed) {
        return None;
    }

    let assignment_id = extract_uuid_label(&evidence.message, "AssignmentId")?;
    let policy_id = extract_uuid_label(&evidence.message, "PolicyId")?;
    let request_key = if phase == SccmPolicyPhase::Request {
        Some(SccmPolicyKey {
            assignment_id: assignment_id.clone(),
            policy_id: policy_id.clone(),
            request_id: extract_uuid_label(&evidence.message, "RequestId")?,
            client_handle: extract_safe_handle(&evidence.message, "ClientHandle", "safe:client:")?,
            site_code: extract_site_code(&evidence.message)?,
            management_point_host_handle: extract_safe_handle(
                &evidence.message,
                "SelectedManagementPointHostHandle",
                "safe:mp:",
            )?,
            extraction_profile_id: SCCM_POLICY_TEST_PROFILE_ID.to_owned(),
        })
    } else {
        None
    };

    Some(PolicyFact {
        assignment_id,
        policy_id,
        phase,
        outcome,
        source,
        reference: evidence.reference.clone(),
        utc_millis: evidence.timestamp.utc_millis,
        time_comparable: matches!(
            evidence.timestamp.ordering_state,
            crate::sccm::SccmTimeOrderingState::NormalizedUtc
        ) && evidence.timestamp.utc_millis.is_some(),
        request_key,
    })
}

fn classify_policy_record(message: &str) -> Option<(SccmPolicyPhase, FactOutcome)> {
    let normalized = message.to_ascii_lowercase();
    let candidates = [
        (
            "request authentication failed terminal",
            SccmPolicyPhase::Request,
            FactOutcome::Failed,
        ),
        (
            "request succeeded",
            SccmPolicyPhase::Request,
            FactOutcome::Succeeded,
        ),
        (
            "download failed terminal",
            SccmPolicyPhase::Download,
            FactOutcome::Failed,
        ),
        (
            "download succeeded",
            SccmPolicyPhase::Download,
            FactOutcome::Succeeded,
        ),
        (
            "persist failed terminal",
            SccmPolicyPhase::Persist,
            FactOutcome::Failed,
        ),
        (
            "persist succeeded",
            SccmPolicyPhase::Persist,
            FactOutcome::Succeeded,
        ),
        (
            "schedule deferred",
            SccmPolicyPhase::Schedule,
            FactOutcome::Deferred,
        ),
        (
            "schedule succeeded",
            SccmPolicyPhase::Schedule,
            FactOutcome::Succeeded,
        ),
        (
            "evaluate failed terminal",
            SccmPolicyPhase::Evaluate,
            FactOutcome::Failed,
        ),
        (
            "evaluate succeeded",
            SccmPolicyPhase::Evaluate,
            FactOutcome::Succeeded,
        ),
        (
            "report failed terminal",
            SccmPolicyPhase::Report,
            FactOutcome::Failed,
        ),
        (
            "report succeeded",
            SccmPolicyPhase::Report,
            FactOutcome::Succeeded,
        ),
    ];

    let mut matched = candidates
        .into_iter()
        .filter(|(marker, _, _)| contains_token_sequence(&normalized, marker));
    let first = matched.next()?;
    if matched.next().is_some() {
        return None;
    }
    Some((first.1, first.2))
}

fn contains_token_sequence(message: &str, marker: &str) -> bool {
    let mut search_from = 0;
    while let Some(relative_start) = message[search_from..].find(marker) {
        let start = search_from + relative_start;
        let end = start + marker.len();
        if starts_on_word_boundary(message, start) && ends_on_word_boundary(message, end) {
            return true;
        }
        search_from = end;
    }
    false
}

/// Whether a token starting at `start` is not welded onto a preceding word.
fn starts_on_word_boundary(message: &str, start: usize) -> bool {
    !message[..start]
        .chars()
        .next_back()
        .is_some_and(is_policy_word_character)
}

/// Whether a token ending at `end` is not welded onto a following word.
fn ends_on_word_boundary(message: &str, end: usize) -> bool {
    !message[end..]
        .chars()
        .next()
        .is_some_and(is_policy_word_character)
}

/// Characters that can be part of a policy marker or label token.
///
/// This is deliberately expressed as what belongs *inside* a word rather than
/// as a list of separators: an enumerated separator set silently admits every
/// punctuation mark nobody thought to list. Matching is by character, not raw
/// byte, so a multibyte letter cannot masquerade as a separator.
///
/// A period is excluded because a trailing period ends a sentence far more
/// often than it continues an identifier.
fn is_policy_word_character(character: char) -> bool {
    character.is_alphanumeric() || matches!(character, '-' | '_')
}

fn extract_uuid_label(message: &str, label: &str) -> Option<String> {
    let token = extract_label_token(message, label)?;
    let value = token.strip_prefix('{').unwrap_or(token);
    let value = value.strip_suffix('}').unwrap_or(value);
    if is_canonical_uuid(value) {
        Some(value.to_ascii_lowercase())
    } else {
        None
    }
}

fn extract_safe_handle(message: &str, label: &str, prefix: &str) -> Option<String> {
    let token = extract_label_token(message, label)?;
    let suffix = token.strip_prefix(prefix)?;
    if suffix.is_empty()
        || !suffix.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
    {
        return None;
    }
    Some(token.to_owned())
}

fn extract_site_code(message: &str) -> Option<String> {
    let token = extract_label_token(message, "SiteCode")?;
    if token.len() == 3
        && token
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        Some(token.to_owned())
    } else {
        None
    }
}

fn has_terminal_failure_signal(message: &str) -> bool {
    if extract_signals(message)
        .iter()
        .any(|signal| signal.numeric.is_some_and(|numeric| numeric != 0))
    {
        return true;
    }

    let Some(value) = extract_label_token(message, "Result") else {
        return false;
    };
    let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    else {
        return false;
    };
    hex.len() == 8
        && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
        && u32::from_str_radix(hex, 16).is_ok_and(|numeric| numeric != 0)
}

/// The repair named by the earliest source in a cross-artifact time inversion.
///
/// Both sides of an inversion are normalized UTC by construction, so this is
/// never an offset problem and the cause says so. Only the earliest record
/// taking part is named: fanning out to every group involved would put two
/// unrelated log families in one finding, and neither of the two clocks can be
/// singled out as the wrong one anyway.
fn cross_phase_time_inversion_repair(
    facts: &[PolicyFact],
    current_phase: SccmPolicyPhase,
) -> Option<PolicyRepair> {
    let mut inverted: Vec<&PolicyFact> = Vec::new();
    for earlier in facts.iter().filter(|fact| fact.phase <= current_phase) {
        for later in facts.iter().filter(|fact| fact.phase <= current_phase) {
            if earlier.phase >= later.phase
                || earlier.reference.artifact_id == later.reference.artifact_id
                || !earlier.time_comparable
                || !later.time_comparable
            {
                continue;
            }
            let (Some(earlier_utc), Some(later_utc)) = (earlier.utc_millis, later.utc_millis)
            else {
                continue;
            };
            if earlier_utc > later_utc {
                inverted.push(earlier);
                inverted.push(later);
            }
        }
    }

    let earliest = earliest_link(&inverted)?;
    repair_from_facts(&[earliest], RequestCause::InvertedTime)
}

/// The repair named by the earliest source whose time provenance breaks the chain.
///
/// Ordering two artifacts requires comparable time on both sides. Skipping such
/// a pair would silently drop the only chronology guard the reducer has, so the
/// break is reported and the ordered claim is capped instead. Phases inside one
/// artifact keep their source-local order and never break the chain. Only the
/// earliest broken link is named, so the caller asks for one repair rather than
/// mixing unrelated groups into a single finding.
fn unprovable_chronology_repair(
    facts: &[PolicyFact],
    current_phase: SccmPolicyPhase,
) -> Option<PolicyRepair> {
    let observed = facts
        .iter()
        .filter(|fact| fact.phase <= current_phase)
        .collect::<Vec<_>>();

    let has_unorderable_pair = observed.iter().any(|earlier| {
        observed.iter().any(|later| {
            earlier.phase < later.phase
                && earlier.reference.artifact_id != later.reference.artifact_id
                && !(is_time_comparable(earlier) && is_time_comparable(later))
        })
    });
    if !has_unorderable_pair {
        return None;
    }

    let unusable = observed
        .into_iter()
        .filter(|fact| !is_time_comparable(fact))
        .collect::<Vec<_>>();
    let earliest = earliest_link(&unusable)?;
    repair_from_facts(&[earliest], RequestCause::UnusableTime)
}

/// The earliest record in a broken chain, by phase then by reference.
///
/// The reference tie-break keeps the answer independent of input order when two
/// sources record the same phase.
fn earliest_link<'a>(facts: &[&'a PolicyFact]) -> Option<&'a PolicyFact> {
    facts
        .iter()
        .min_by(|left, right| {
            left.phase
                .cmp(&right.phase)
                .then_with(|| compare_evidence_refs(&left.reference, &right.reference))
        })
        .copied()
}

fn is_time_comparable(fact: &PolicyFact) -> bool {
    fact.time_comparable && fact.utc_millis.is_some()
}

/// Reads one label admitted by the frozen policy key profile.
///
/// Returns `None` for any label outside [`POLICY_PROFILE_LABELS`], so the
/// profile, not the call site, decides what may be keyed.
fn extract_label_token<'a>(message: &'a str, label: &str) -> Option<&'a str> {
    if !POLICY_PROFILE_LABELS.contains(&label) {
        return None;
    }
    extract_exactly_one_label_token(message, label)
}

/// Reads the single exact-boundary occurrence of `label` in `message`.
///
/// Occurrences that start inside a longer word (`NotRequestId=`) are not
/// occurrences of the label at all, and two or more admissible occurrences are
/// ambiguous, so both cases return `None` rather than silently taking the first
/// match.
fn extract_exactly_one_label_token<'a>(message: &'a str, label: &str) -> Option<&'a str> {
    let normalized = message.to_ascii_lowercase();
    let marker = format!("{}=", label.to_ascii_lowercase());
    let mut token = None;
    let mut search_from = 0;

    while let Some(relative_start) = normalized[search_from..].find(&marker) {
        let start = search_from + relative_start;
        let value_start = start + marker.len();
        search_from = value_start;
        if !starts_on_word_boundary(message, start) {
            continue;
        }
        if token.is_some() {
            return None;
        }
        token = Some(label_value_token(message, value_start));
    }

    token.flatten()
}

fn label_value_token(message: &str, value_start: usize) -> Option<&str> {
    let remainder = &message[value_start..];
    let end = remainder
        .find(is_label_token_boundary)
        .unwrap_or(remainder.len());
    let token = &remainder[..end];
    (!token.is_empty()).then_some(token)
}

/// Characters that end a label's value token.
///
/// This is a terminator set, not a word boundary. The two are different
/// questions: a value stops at the delimiters that surround it, while a label
/// starts wherever the preceding character cannot belong to a word.
fn is_label_token_boundary(character: char) -> bool {
    character.is_ascii_whitespace() || matches!(character, ',' | ';' | ']' | '<' | '"' | '\'')
}

fn is_canonical_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn source_allows_phase(display_name: &str, phase: SccmPolicyPhase) -> bool {
    let basename = canonical_basename(display_name);
    match phase {
        SccmPolicyPhase::Request | SccmPolicyPhase::Persist => {
            matches!(basename, "PolicyAgent" | "PolicyAgentProvider")
        }
        SccmPolicyPhase::Download => {
            matches!(
                basename,
                "PolicyAgent" | "PolicyAgentProvider" | "CIDownloader"
            )
        }
        SccmPolicyPhase::Schedule => basename == "Scheduler",
        SccmPolicyPhase::Evaluate => matches!(basename, "CIAgent" | "PolicyEvaluator"),
        SccmPolicyPhase::Report => matches!(basename, "StateMessage" | "StatusAgent"),
    }
}

fn canonical_basename(display_name: &str) -> &str {
    let file_name = display_name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(display_name);
    if let Some(value) = file_name.strip_suffix(".lo_") {
        value
    } else if let Some(value) = file_name.strip_suffix(".log") {
        value
    } else {
        file_name
    }
}

/// The declared policy source a captured file belongs to.
fn policy_source(display_name: &str) -> Option<&'static PolicySource> {
    let basename = canonical_basename(display_name);
    POLICY_SOURCES
        .iter()
        .find(|source| source.basename == basename)
}

fn policy_group(display_name: &str) -> Option<&'static str> {
    policy_source(display_name).map(|source| source.group)
}

fn is_admitted_policy_artifact(artifact: &SccmArtifact) -> bool {
    artifact.role == SccmRole::Client
        && artifact.coverage == SccmCoverageState::Captured
        && matches!(
            policy_group(&artifact.display_name),
            Some(POLICY_AGENT_GROUP) | Some(POLICY_STATE_GROUP)
        )
}

fn is_validated_policy_version(version: Option<&str>) -> bool {
    let Some(version) = version else {
        return false;
    };
    let components = version.split('.').collect::<Vec<_>>();
    components.len() == 4
        && components[0] == "5"
        && components[1] == "00"
        && components[2] == "TEST"
        && components[3].len() == 4
        && components[3].bytes().all(|byte| byte.is_ascii_digit())
}

fn is_safe_evidence_reference(reference: &SccmEvidenceRef) -> bool {
    is_safe_opaque_id(&reference.artifact_id)
        && is_safe_opaque_id(&reference.entry_id)
        && matches!(
            (reference.line_start, reference.line_end),
            (Some(start), Some(end)) if start > 0 && start <= end
        )
}

fn is_safe_opaque_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}

fn sort_facts(facts: &mut [PolicyFact]) {
    facts.sort_by(|left, right| {
        left.phase
            .cmp(&right.phase)
            .then_with(|| compare_fact_order(left, right))
    });
}

fn compare_fact_order(left: &PolicyFact, right: &PolicyFact) -> Ordering {
    match (
        left.time_comparable.then_some(left.utc_millis).flatten(),
        right.time_comparable.then_some(right.utc_millis).flatten(),
    ) {
        (Some(left_time), Some(right_time)) => left_time
            .cmp(&right_time)
            .then_with(|| compare_evidence_refs(&left.reference, &right.reference)),
        _ => compare_evidence_refs(&left.reference, &right.reference),
    }
}

fn compare_evidence_refs(left: &SccmEvidenceRef, right: &SccmEvidenceRef) -> Ordering {
    left.artifact_id
        .cmp(&right.artifact_id)
        .then_with(|| left.line_start.cmp(&right.line_start))
        .then_with(|| left.line_end.cmp(&right.line_end))
        .then_with(|| left.entry_id.cmp(&right.entry_id))
}

fn sort_and_deduplicate_evidence(evidence: &mut Vec<SccmEvidenceRef>) {
    evidence.sort_by(compare_evidence_refs);
    evidence.dedup();
}

fn required_group_for_phase(phase: SccmPolicyPhase) -> &'static str {
    match phase {
        SccmPolicyPhase::Request
        | SccmPolicyPhase::Download
        | SccmPolicyPhase::Persist
        | SccmPolicyPhase::Schedule => POLICY_AGENT_GROUP,
        SccmPolicyPhase::Evaluate | SccmPolicyPhase::Report => POLICY_STATE_GROUP,
    }
}

/// The basename that would supply a phase nobody recorded.
///
/// A missing phase has no fact, so there is no artifact to read the answer off.
/// The phase's own canonical source is named instead, which is the one case
/// where deriving from the phase is the only thing the evidence allows. It must
/// stay inside [`required_group_for_phase`] so a finding keeps one group.
fn required_source_for_phase(phase: SccmPolicyPhase) -> &'static str {
    match phase {
        SccmPolicyPhase::Request | SccmPolicyPhase::Download | SccmPolicyPhase::Persist => {
            "PolicyAgent"
        }
        SccmPolicyPhase::Schedule => "Scheduler",
        SccmPolicyPhase::Evaluate => "CIAgent",
        SccmPolicyPhase::Report => "StateMessage",
    }
}

/// The repair for the client-location context a request failure needs.
///
/// No policy fact carries this group, so there is no artifact to read it off.
/// The declared source is named directly.
fn client_location_repair() -> PolicyRepair {
    PolicyRepair {
        group: CLIENT_LOCATION_GROUP,
        sources: policy_source("ClientLocation").into_iter().collect(),
        cause: RequestCause::LocationContext,
    }
}

fn repair_for_missing_phase(phase: SccmPolicyPhase) -> PolicyRepair {
    PolicyRepair {
        group: required_group_for_phase(phase),
        sources: policy_source(required_source_for_phase(phase))
            .into_iter()
            .collect(),
        cause: RequestCause::MissingPhase,
    }
}

/// The repair named by a set of facts that share one cause.
///
/// One finding carries one logical group, so the group of the earliest record
/// decides, and every source of that group among the same facts is named. The
/// group is read off the artifact, never off the phase: `CIDownloader.log`
/// carries Download but answers for the policy-state family, and
/// `PolicyEvaluator.log` carries Evaluate but answers for the policy-agent one.
fn repair_from_facts(facts: &[&PolicyFact], cause: RequestCause) -> Option<PolicyRepair> {
    let group = facts
        .iter()
        .min_by(|left, right| compare_evidence_refs(&left.reference, &right.reference))?
        .source
        .group;
    let mut sources = facts
        .iter()
        .filter(|fact| fact.source.group == group)
        .map(|fact| fact.source)
        .collect::<Vec<_>>();
    sources.sort_by_key(|source| source.logical_name);
    sources.dedup();
    Some(PolicyRepair {
        group,
        sources,
        cause,
    })
}

fn workflow_request(logical_id: &str, reason: &str) -> SccmWorkflowArtifactRequest {
    SccmWorkflowArtifactRequest {
        logical_id: logical_id.to_owned(),
        reason: reason.to_owned(),
    }
}

/// Builds the group-level artifact request from the state that caused it.
///
/// Every reason is selected by cause first, so no wording can assert a state
/// the evidence does not have. The group only refines which sources to name.
fn workflow_request_for(repair: &PolicyRepair) -> SccmWorkflowArtifactRequest {
    let reason = match (repair.cause, repair.group) {
        (RequestCause::LocationContext, _) => {
            "Capture bounded client-side location and transport context; do not infer a management-point cause."
        }
        (RequestCause::Deferred, _) => {
            "Recapture bounded scheduler evidence for the deferred policy retry."
        }
        (RequestCause::UnusableTime, POLICY_STATE_GROUP) => {
            "Recapture bounded policy-state evidence with a valid timestamp offset; do not order by display time."
        }
        (RequestCause::UnusableTime, _) => {
            "Recapture bounded policy-agent evidence with a valid timestamp offset; do not order by display time."
        }
        // Both sides of an inversion are already normalized UTC, so nothing may
        // claim the offset is unusable. What the evidence does show is two
        // sources whose clocks disagree about the phase order.
        (RequestCause::InvertedTime, POLICY_STATE_GROUP) => {
            "Recapture bounded policy-state evidence from a source whose clock agrees with the rest of the capture; the recorded times contradict the phase order."
        }
        (RequestCause::InvertedTime, _) => {
            "Recapture bounded policy-agent evidence from a source whose clock agrees with the rest of the capture; the recorded times contradict the phase order."
        }
        (RequestCause::ConflictingOutcomes, POLICY_STATE_GROUP) => {
            "Recapture bounded policy-state evidence to resolve the conflicting client policy outcome."
        }
        (RequestCause::ConflictingOutcomes, _) => {
            "Recapture bounded policy-agent evidence to resolve the conflicting client policy outcome."
        }
        (RequestCause::MissingPhase, POLICY_STATE_GROUP) => {
            "Capture bounded policy-state evidence for the missing client policy phase."
        }
        (RequestCause::MissingPhase, POLICY_AGENT_GROUP) => {
            "Capture bounded policy-agent evidence for the missing client policy phase."
        }
        (RequestCause::MissingPhase, _) => "Capture the bounded named SCCM client artifact.",
    };
    workflow_request(repair.group, reason)
}

/// Coverage gaps for one logical group, keeping every explicit non-outcome.
///
/// A group can hold both a captured source and an unavailable one. Reporting a
/// single group-level state would let the captured sibling erase the other
/// source's AccessDenied, Capped, Skipped, Unsupported, or ParseFailed state,
/// so each unavailable source keeps its own citation and state. Only a group
/// that is fully captured, yet still failed to yield the phase, falls back to a
/// synthesized partial gap.
fn coverage_gaps_for_group(
    context: &ReductionContext<'_>,
    logical_id: &str,
) -> Vec<SccmFindingCoverageGap> {
    let artifacts = client_group_artifacts(context, logical_id).collect::<Vec<_>>();
    if artifacts.is_empty() {
        return vec![SccmFindingCoverageGap {
            artifact_id: logical_id.to_owned(),
            role: SccmRole::Client,
            coverage: SccmCoverageState::Absent,
        }];
    }

    let mut gaps = artifacts
        .iter()
        .filter(|artifact| artifact.coverage != SccmCoverageState::Captured)
        .filter(|artifact| is_safe_opaque_id(&artifact.artifact_id))
        .map(|artifact| SccmFindingCoverageGap {
            artifact_id: artifact.artifact_id.clone(),
            role: SccmRole::Client,
            coverage: artifact.coverage.clone(),
        })
        .collect::<Vec<_>>();
    if gaps.is_empty() {
        gaps.push(SccmFindingCoverageGap {
            artifact_id: logical_id.to_owned(),
            role: SccmRole::Client,
            coverage: SccmCoverageState::Partial,
        });
    }
    gaps.sort_by(|left, right| {
        left.artifact_id.cmp(&right.artifact_id).then_with(|| {
            coverage_priority(&left.coverage).cmp(&coverage_priority(&right.coverage))
        })
    });
    gaps
}

/// Whether a logical group has no captured source at all.
///
/// This is the admission question, not the citation question: it asks whether
/// the group can still contribute evidence, so a captured sibling does answer
/// it. Citations use [`coverage_gaps_for_group`].
///
/// A group with no artifacts at all is the strongest form of "no captured
/// source", not an exemption. Guarding on a non-empty group would let deleting
/// the one record of an absence raise confidence above a bundle that recorded
/// it, which is the one direction a fail-closed reducer must never move. Its
/// citation twin agrees: [`coverage_gaps_for_group`] maps the same empty group
/// to [`SccmCoverageState::Absent`].
fn group_has_no_captured_source(context: &ReductionContext<'_>, logical_id: &str) -> bool {
    client_group_artifacts(context, logical_id)
        .all(|artifact| artifact.coverage != SccmCoverageState::Captured)
}

/// The confirmed terminal failures recorded past the last proven phase.
///
/// The transaction cites only what it can place in the chain, so these records
/// are outside its evidence. They are still proven terminal failures under a
/// validated profile, so they leave the reduction rather than being dropped.
/// Only the earliest unreached failing phase is reported, so one observation
/// names one phase rather than merging unrelated failures.
fn unreached_terminal_failure(
    facts: &[PolicyFact],
    current_phase: SccmPolicyPhase,
) -> Option<UnreachedFailure> {
    let phase = facts
        .iter()
        .filter(|fact| fact.phase > current_phase && fact.outcome == FactOutcome::Failed)
        .map(|fact| fact.phase)
        .min()?;
    let mut evidence = facts
        .iter()
        .filter(|fact| fact.phase == phase && fact.outcome == FactOutcome::Failed)
        .map(|fact| fact.reference.clone())
        .collect::<Vec<_>>();
    sort_and_deduplicate_evidence(&mut evidence);
    Some(UnreachedFailure { phase, evidence })
}

/// The client-role artifacts belonging to one logical policy group.
///
/// Every coverage question this reducer asks is a question about the client, so
/// membership is decided by role and basename together. Routing all of them
/// through one selector keeps a future group query from silently omitting the
/// role and letting an out-of-scope artifact answer for the client.
fn client_group_artifacts<'a>(
    context: &'a ReductionContext<'_>,
    logical_id: &'a str,
) -> impl Iterator<Item = &'a SccmArtifact> {
    context.bundle.artifacts.iter().filter(move |artifact| {
        artifact.role == SccmRole::Client
            && policy_group(&artifact.display_name) == Some(logical_id)
    })
}

/// Every client policy source that is not fully captured.
///
/// Coverage is a property of the capture, not of the verdict. Reporting these
/// only when a phase went missing would hide an AccessDenied, Capped, Skipped,
/// Unsupported, ParseFailed, or Partial source behind a chain that happened to
/// succeed through its siblings, so the non-outcome is cited whatever the
/// transaction concluded.
fn unavailable_client_policy_sources(bundle: &SccmNormalizedBundle) -> Vec<SccmFindingCoverageGap> {
    bundle
        .artifacts
        .iter()
        .filter(|artifact| {
            artifact.role == SccmRole::Client
                && artifact.coverage != SccmCoverageState::Captured
                && policy_group(&artifact.display_name).is_some()
                && is_safe_opaque_id(&artifact.artifact_id)
        })
        .map(|artifact| SccmFindingCoverageGap {
            artifact_id: artifact.artifact_id.clone(),
            role: SccmRole::Client,
            coverage: artifact.coverage.clone(),
        })
        .collect()
}

fn coverage_priority(state: &SccmCoverageState) -> u8 {
    match state {
        SccmCoverageState::Partial => 0,
        SccmCoverageState::Capped => 1,
        SccmCoverageState::AccessDenied => 2,
        SccmCoverageState::ParseFailed => 3,
        SccmCoverageState::Absent => 4,
        SccmCoverageState::Skipped => 5,
        SccmCoverageState::Unsupported => 6,
        SccmCoverageState::Captured => 7,
    }
}

fn partial_policy_artifacts<'a>(
    bundle: &'a SccmNormalizedBundle,
    normalized_evidence_ids: &BTreeSet<&str>,
) -> Vec<&'a SccmArtifact> {
    let candidates = bundle
        .artifacts
        .iter()
        .filter(|artifact| {
            artifact.role == SccmRole::Client
                && artifact.coverage == SccmCoverageState::Captured
                && policy_group(&artifact.display_name) == Some(POLICY_AGENT_GROUP)
                && !normalized_evidence_ids.contains(artifact.artifact_id.as_str())
        })
        .collect::<Vec<_>>();
    let has_rotation = candidates
        .iter()
        .any(|artifact| !matches!(artifact.rotation, SccmRotation::Current));
    if candidates.len() >= 2 && has_rotation {
        candidates
    } else {
        Vec::new()
    }
}

fn physical_fragment_references(artifacts: &[&SccmArtifact]) -> Vec<SccmEvidenceRef> {
    let mut references = artifacts
        .iter()
        .filter(|artifact| is_safe_opaque_id(&artifact.artifact_id))
        .map(|artifact| SccmEvidenceRef {
            artifact_id: artifact.artifact_id.clone(),
            entry_id: format!("{}:physical:1-1", artifact.artifact_id),
            line_start: Some(1),
            line_end: Some(1),
        })
        .collect::<Vec<_>>();
    sort_and_deduplicate_evidence(&mut references);
    references
}

fn build_transaction_finding(
    transaction: &SccmWorkflowTransaction,
    evidence: Vec<SccmEvidenceRef>,
    terminal_failure_references: Vec<SccmEvidenceRef>,
    coverage_gaps: Vec<SccmFindingCoverageGap>,
    repairs: &[PolicyRepair],
) -> Option<SccmFinding> {
    if transaction.classification == SccmWorkflowClassification::Success {
        return None;
    }

    let (class, severity, confidence, title) = match transaction.classification {
        SccmWorkflowClassification::ConfirmedFailure => (
            SccmFindingClass::ConfirmedFailure,
            Severity::Error,
            shared_confidence(transaction.confidence),
            "Client policy phase failed",
        ),
        SccmWorkflowClassification::BlockedOrDeferred => (
            SccmFindingClass::BlockedOrDeferred,
            Severity::Warning,
            shared_confidence(transaction.confidence),
            "Client policy phase is deferred",
        ),
        SccmWorkflowClassification::InsufficientEvidence => (
            SccmFindingClass::InsufficientEvidence,
            Severity::Warning,
            shared_confidence(transaction.confidence),
            "Client policy evidence is incomplete",
        ),
        SccmWorkflowClassification::ContradictoryEvidence => (
            SccmFindingClass::Symptom,
            Severity::Warning,
            SccmConfidence::Low,
            "Client policy evidence is contradictory",
        ),
        SccmWorkflowClassification::LowConfidenceSymptom => (
            SccmFindingClass::Symptom,
            Severity::Warning,
            SccmConfidence::Low,
            "Client policy symptom needs validated evidence",
        ),
        SccmWorkflowClassification::Success => return None,
    };

    let terminal_evidence = terminal_failure_references
        .into_iter()
        .map(SccmTerminalEvidence::observed_failure)
        .collect::<Vec<_>>();
    let next_artifacts = finding_requests(repairs);
    SccmFindingBuilder::new(format!(
        "finding:policy:{}:{}",
        phase_name(transaction.phase),
        transaction.key.assignment_id
    ))
    .class(class)
    .phase(SccmPhase::Policy)
    .role(SccmRole::Client)
    .severity(severity)
    .confidence(confidence)
    .title(title)
    .summary(format!(
        "Client-side policy evidence stopped at the {} phase.",
        phase_name(transaction.phase)
    ))
    .evidence(evidence)
    .terminal_evidence(terminal_evidence)
    .coverage_gaps(coverage_gaps)
    .next_artifacts(next_artifacts)
    .build()
    .ok()
}

/// Turns repairs into requests for the files that would actually supply them.
///
/// The repair already carries the sources, so this never has to guess a file
/// from a group. Expanding a group into its whole membership is what made a
/// deferred `Scheduler.log` retry ask for `PolicyAgent.log`.
fn finding_requests(repairs: &[PolicyRepair]) -> Vec<SccmArtifactRequest> {
    let mut requests = repairs
        .iter()
        .flat_map(|repair| repair.sources.iter())
        .map(|source| SccmArtifactRequest {
            logical_id: source.logical_name.to_owned(),
            role: SccmRole::Client,
            reason: format!("Collect the complete {} file.", source.basename),
        })
        .collect::<Vec<_>>();
    requests.sort_by(|left, right| {
        left.logical_id
            .cmp(&right.logical_id)
            .then_with(|| left.reason.cmp(&right.reason))
    });
    requests
        .dedup_by(|left, right| left.logical_id == right.logical_id && left.reason == right.reason);
    requests
}

fn build_rotation_partial_finding(
    evidence: Vec<SccmEvidenceRef>,
    coverage_gap: SccmFindingCoverageGap,
) -> Option<SccmFinding> {
    SccmFindingBuilder::new("finding:policy-rotation-split")
        .class(SccmFindingClass::InsufficientEvidence)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .title("Policy record is split across physical rotations")
        .summary("Partial PolicyAgent fragments cannot create a policy transaction.")
        .evidence(evidence)
        .coverage_gap(coverage_gap)
        .next_artifact(SccmArtifactRequest {
            logical_id: "policyAgent".to_owned(),
            role: SccmRole::Client,
            reason: "Collect the complete PolicyAgent file.".to_owned(),
        })
        .build()
        .ok()
}

fn build_unreached_failure_finding(
    assignment_id: &str,
    phase: SccmPolicyPhase,
    evidence: Vec<SccmEvidenceRef>,
    next_artifacts: Vec<SccmArtifactRequest>,
) -> Option<SccmFinding> {
    let terminal_evidence = evidence
        .iter()
        .cloned()
        .map(SccmTerminalEvidence::observed_failure)
        .collect::<Vec<_>>();
    SccmFindingBuilder::new(format!(
        "finding:policy-unreached-failure:{assignment_id}"
    ))
    .class(SccmFindingClass::ConfirmedFailure)
    .phase(SccmPhase::Policy)
    .role(SccmRole::Client)
    .severity(Severity::Error)
    // The failure is proven; only its place in the chain is not.
    .confidence(SccmConfidence::Moderate)
    .title("Client policy failure is outside the proven chain")
    .summary(format!(
        "A terminal client policy failure was recorded at the {} phase, but the captured evidence cannot place it in the transaction.",
        phase_name(phase)
    ))
    .evidence(evidence)
    .terminal_evidence(terminal_evidence)
    .next_artifacts(next_artifacts)
    .build()
    .ok()
}

fn build_malformed_finding(evidence: Vec<SccmEvidenceRef>) -> Option<SccmFinding> {
    SccmFindingBuilder::new("finding:policy-malformed")
        .class(SccmFindingClass::Symptom)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .title("Policy evidence did not match a validated profile")
        .summary("The client policy record remains a low-confidence local symptom.")
        .evidence(evidence)
        .next_artifact(SccmArtifactRequest {
            logical_id: "policyAgent".to_owned(),
            role: SccmRole::Client,
            reason: "Collect the complete PolicyAgent file.".to_owned(),
        })
        .build()
        .ok()
}

fn shared_confidence(confidence: SccmWorkflowConfidence) -> SccmConfidence {
    match confidence {
        SccmWorkflowConfidence::Low => SccmConfidence::Low,
        SccmWorkflowConfidence::Medium => SccmConfidence::Moderate,
        SccmWorkflowConfidence::High => SccmConfidence::High,
    }
}

fn phase_name(phase: SccmPolicyPhase) -> &'static str {
    match phase {
        SccmPolicyPhase::Request => "request",
        SccmPolicyPhase::Download => "download",
        SccmPolicyPhase::Persist => "persist",
        SccmPolicyPhase::Schedule => "schedule",
        SccmPolicyPhase::Evaluate => "evaluate",
        SccmPolicyPhase::Report => "report",
    }
}

fn normalize_analysis(
    transactions: &mut [SccmWorkflowTransaction],
    observations: &mut [SccmSourceLocalObservation],
    findings: &mut [SccmFinding],
    coverage_gaps: &mut Vec<SccmFindingCoverageGap>,
) {
    transactions.sort_by(|left, right| left.transaction_id.cmp(&right.transaction_id));
    observations.sort_by(|left, right| left.observation_id.cmp(&right.observation_id));
    findings.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
    coverage_gaps.sort_by(|left, right| {
        left.artifact_id.cmp(&right.artifact_id).then_with(|| {
            coverage_priority(&left.coverage).cmp(&coverage_priority(&right.coverage))
        })
    });
    coverage_gaps.dedup_by(|left, right| {
        left.artifact_id == right.artifact_id
            && left.role == right.role
            && left.coverage == right.coverage
    });
}

fn collect_workflow_requests(
    transactions: &[SccmWorkflowTransaction],
    observations: &[SccmSourceLocalObservation],
) -> Vec<SccmWorkflowArtifactRequest> {
    let mut requests = transactions
        .iter()
        .flat_map(|transaction| transaction.next_artifacts.iter().cloned())
        .chain(
            observations
                .iter()
                .flat_map(|observation| observation.next_artifacts.iter().cloned()),
        )
        .collect::<Vec<_>>();
    requests.sort_by(|left, right| {
        left.logical_id
            .cmp(&right.logical_id)
            .then_with(|| left.reason.cmp(&right.reason))
    });
    requests.dedup();
    requests
}
