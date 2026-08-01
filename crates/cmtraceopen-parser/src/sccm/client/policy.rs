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
    Contradictory,
}

struct ReductionContext<'a> {
    bundle: &'a SccmNormalizedBundle,
}

struct ReducedTransaction {
    transaction: SccmWorkflowTransaction,
    finding: Option<SccmFinding>,
    coverage_gaps: Vec<SccmFindingCoverageGap>,
}

pub fn analyze_client_policy(bundle: &SccmNormalizedBundle) -> SccmWorkflowAnalysis {
    let artifact_by_id = bundle
        .artifacts
        .iter()
        .map(|artifact| (artifact.artifact_id.as_str(), artifact))
        .collect::<BTreeMap<_, _>>();
    let context = ReductionContext { bundle };

    let mut facts_by_assignment: BTreeMap<String, Vec<PolicyFact>> = BTreeMap::new();
    let mut rejected_policy_evidence = Vec::new();
    let mut normalized_evidence_ids = BTreeSet::new();

    for evidence in &bundle.evidence {
        let Some(artifact) = artifact_by_id.get(evidence.reference.artifact_id.as_str()) else {
            continue;
        };
        if !is_admitted_policy_artifact(artifact)
            || !is_safe_evidence_reference(&evidence.reference)
        {
            continue;
        }
        normalized_evidence_ids.insert(artifact.artifact_id.as_str());

        if !is_validated_policy_version(artifact.configmgr_version.as_deref()) {
            rejected_policy_evidence.push(evidence.reference.clone());
            continue;
        }

        match parse_policy_fact(evidence, artifact) {
            Some(fact) => facts_by_assignment
                .entry(fact.assignment_id.clone())
                .or_default()
                .push(fact),
            None => rejected_policy_evidence.push(evidence.reference.clone()),
        }
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
    let mut next_artifacts = Vec::new();
    let mut terminal_failure_references = Vec::new();

    for phase in POLICY_PHASES {
        let phase_facts = facts
            .iter()
            .filter(|fact| fact.phase == phase)
            .collect::<Vec<_>>();
        if phase_facts.is_empty() {
            current_phase = last_successful_phase.unwrap_or(SccmPolicyPhase::Request);
            let logical_id = required_group_for_phase(phase);
            coverage_gap_artifact_ids.push(logical_id.to_owned());
            next_artifacts.push(request_for_group(logical_id, phase));
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
                    && coverage_gap_for_group(context, CLIENT_LOCATION_GROUP).is_some()
                {
                    confidence = SccmWorkflowConfidence::Medium;
                    coverage_gap_artifact_ids.push(CLIENT_LOCATION_GROUP.to_owned());
                    next_artifacts.push(request_for_group(
                        CLIENT_LOCATION_GROUP,
                        SccmPolicyPhase::Request,
                    ));
                }
                break;
            }
            PhaseResolution::Deferred => {
                state = SccmWorkflowState::Deferred;
                classification = SccmWorkflowClassification::BlockedOrDeferred;
                confidence = SccmWorkflowConfidence::High;
                next_artifacts.push(request_for_group(POLICY_AGENT_GROUP, phase));
                break;
            }
            PhaseResolution::Contradictory => {
                state = SccmWorkflowState::Contradictory;
                classification = SccmWorkflowClassification::ContradictoryEvidence;
                confidence = SccmWorkflowConfidence::Low;
                next_artifacts.push(request_for_group(required_group_for_phase(phase), phase));
                break;
            }
        }
    }

    let inverted_groups = cross_phase_time_inversion_groups(facts, current_phase);
    if !inverted_groups.is_empty() {
        state = SccmWorkflowState::Contradictory;
        classification = SccmWorkflowClassification::ContradictoryEvidence;
        confidence = SccmWorkflowConfidence::Low;
        last_successful_phase = None;
        terminal_failure_references.clear();
        for logical_id in inverted_groups {
            next_artifacts.push(request_for_group(logical_id, current_phase));
        }
    }

    coverage_gap_artifact_ids.sort();
    coverage_gap_artifact_ids.dedup();
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
        .map(|logical_id| {
            coverage_gap_for_group(context, logical_id).unwrap_or(SccmFindingCoverageGap {
                artifact_id: logical_id.clone(),
                role: SccmRole::Client,
                coverage: SccmCoverageState::Partial,
            })
        })
        .collect::<Vec<_>>();
    let finding = build_transaction_finding(
        &transaction,
        evidence,
        terminal_failure_references,
        gaps.clone(),
    );

    Some(ReducedTransaction {
        transaction,
        finding,
        coverage_gaps: gaps,
    })
}

fn resolve_phase(facts: &[&PolicyFact]) -> PhaseResolution {
    let has_deferred = facts
        .iter()
        .any(|fact| fact.outcome == FactOutcome::Deferred);
    let has_success = facts
        .iter()
        .any(|fact| fact.outcome == FactOutcome::Succeeded);
    let has_failure = facts.iter().any(|fact| fact.outcome == FactOutcome::Failed);

    if has_deferred && (has_success || has_failure) {
        return PhaseResolution::Contradictory;
    }
    if has_deferred {
        return PhaseResolution::Deferred;
    }
    if has_success && has_failure {
        return latest_comparable_outcome(facts).unwrap_or(PhaseResolution::Contradictory);
    }
    if has_failure {
        PhaseResolution::Failed
    } else {
        PhaseResolution::Succeeded
    }
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
    if !source_allows_phase(&artifact.display_name, phase) {
        return None;
    }
    if outcome == FactOutcome::Failed && !has_terminal_failure_signal(&evidence.message) {
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
        let left_ok = start == 0 || is_marker_boundary(message.as_bytes()[start - 1]);
        let right_ok = end == message.len() || is_marker_boundary(message.as_bytes()[end]);
        if left_ok && right_ok {
            return true;
        }
        search_from = end;
    }
    false
}

/// A phase marker only matches when both of its edges sit on a real separator.
///
/// Word-joining bytes stay inside the token so compound text such as
/// `not-Request succeeded-ish` is never read as the exact `Request succeeded`
/// marker.
fn is_marker_boundary(byte: u8) -> bool {
    !byte.is_ascii_alphanumeric() && !matches!(byte, b'-' | b'_')
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

fn cross_phase_time_inversion_groups(
    facts: &[PolicyFact],
    current_phase: SccmPolicyPhase,
) -> BTreeSet<&'static str> {
    let mut groups = BTreeSet::new();
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
                groups.insert(required_group_for_phase(earlier.phase));
                groups.insert(required_group_for_phase(later.phase));
            }
        }
    }
    groups
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
        if !is_label_boundary_start(message, start) {
            continue;
        }
        if token.is_some() {
            return None;
        }
        token = Some(label_value_token(message, value_start));
    }

    token.flatten()
}

fn is_label_boundary_start(message: &str, start: usize) -> bool {
    start == 0
        || message[..start]
            .chars()
            .next_back()
            .is_some_and(is_label_token_boundary)
}

fn label_value_token(message: &str, value_start: usize) -> Option<&str> {
    let remainder = &message[value_start..];
    let end = remainder
        .find(is_label_token_boundary)
        .unwrap_or(remainder.len());
    let token = &remainder[..end];
    (!token.is_empty()).then_some(token)
}

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

fn policy_group(display_name: &str) -> Option<&'static str> {
    match canonical_basename(display_name) {
        "PolicyAgent" | "PolicyAgentProvider" | "PolicyEvaluator" | "Scheduler" => {
            Some(POLICY_AGENT_GROUP)
        }
        "CIAgent" | "CIDownloader" | "StateMessage" | "StatusAgent" => Some(POLICY_STATE_GROUP),
        "ClientLocation" | "LocationServices" | "CcmMessaging" => Some(CLIENT_LOCATION_GROUP),
        _ => None,
    }
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

fn workflow_request(logical_id: &str, reason: &str) -> SccmWorkflowArtifactRequest {
    SccmWorkflowArtifactRequest {
        logical_id: logical_id.to_owned(),
        reason: reason.to_owned(),
    }
}

fn request_for_group(logical_id: &str, phase: SccmPolicyPhase) -> SccmWorkflowArtifactRequest {
    let reason = match logical_id {
        CLIENT_LOCATION_GROUP => {
            "Capture bounded client-side location and transport context; do not infer a management-point cause."
        }
        POLICY_AGENT_GROUP if phase == SccmPolicyPhase::Schedule => {
            "Recapture bounded scheduler evidence for the deferred policy retry."
        }
        POLICY_AGENT_GROUP => {
            "Capture bounded policy-agent evidence for the missing client policy phase."
        }
        POLICY_STATE_GROUP => {
            "Capture bounded CIAgent and StateMessage evidence for Evaluate and Report."
        }
        _ => "Capture the bounded named SCCM client artifact.",
    };
    workflow_request(logical_id, reason)
}

fn coverage_gap_for_group(
    context: &ReductionContext<'_>,
    logical_id: &str,
) -> Option<SccmFindingCoverageGap> {
    let mut states = context
        .bundle
        .artifacts
        .iter()
        .filter(|artifact| policy_group(&artifact.display_name) == Some(logical_id))
        .map(|artifact| artifact.coverage.clone())
        .collect::<Vec<_>>();
    if states.is_empty() || states.contains(&SccmCoverageState::Captured) {
        return None;
    }
    states.sort_by_key(coverage_priority);
    Some(SccmFindingCoverageGap {
        artifact_id: logical_id.to_owned(),
        role: SccmRole::Client,
        coverage: states.remove(0),
    })
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
    let next_artifacts = specific_finding_requests(&transaction.next_artifacts);
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

fn specific_finding_requests(requests: &[SccmWorkflowArtifactRequest]) -> Vec<SccmArtifactRequest> {
    let mut specific = Vec::new();
    for request in requests {
        match request.logical_id.as_str() {
            CLIENT_LOCATION_GROUP => specific.push(SccmArtifactRequest {
                logical_id: "clientLocation".to_owned(),
                role: SccmRole::Client,
                reason: "Collect the complete ClientLocation file.".to_owned(),
            }),
            POLICY_AGENT_GROUP => specific.push(SccmArtifactRequest {
                logical_id: "policyAgent".to_owned(),
                role: SccmRole::Client,
                reason: "Collect the complete PolicyAgent file.".to_owned(),
            }),
            POLICY_STATE_GROUP => {
                specific.push(SccmArtifactRequest {
                    logical_id: "ciAgent".to_owned(),
                    role: SccmRole::Client,
                    reason: "Collect the complete CIAgent file.".to_owned(),
                });
                specific.push(SccmArtifactRequest {
                    logical_id: "stateMessage".to_owned(),
                    role: SccmRole::Client,
                    reason: "Collect the complete StateMessage file.".to_owned(),
                });
            }
            _ => {}
        }
    }
    specific.sort_by(|left, right| {
        left.logical_id
            .cmp(&right.logical_id)
            .then_with(|| left.reason.cmp(&right.reason))
    });
    specific
        .dedup_by(|left, right| left.logical_id == right.logical_id && left.reason == right.reason);
    specific
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
