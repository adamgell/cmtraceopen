//! Pure Task Sequence reduction over the sealed SCCM client evidence boundary.
//!
//! The only reviewed profile is the synthetic `5.00.TEST.0000` corpus. This
//! module makes no native Windows acceptance claim. Execution identity and
//! observed `_SMSTSLogPath` values remain reducer-private; exported values carry
//! only opaque transaction ordinals, typed path classes, and exact evidence
//! references.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::sccm::{
    SccmArtifactFamily, SccmCoverageState, SccmEvidence, SccmEvidenceRef, SccmExtractionProfile,
    SccmRotation, SccmTimeOrderingState,
};

use super::{
    SccmClientAdmittedEvidence, SccmClientEvidenceAdmissionError, SccmTaskSequencePathClass,
    TASK_SEQUENCE_TEST_PROFILE_ID, TASK_SEQUENCE_TEST_VERSION,
};

const TASK_SEQUENCE_LOGICAL_ARTIFACT_ID: &str = "client-task-sequence-smsts";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmTaskSequencePhase {
    Start,
    Preflight,
    DiskOrImage,
    SetupWindows,
    InstallClient,
    InstallSoftware,
    PostAction,
    Complete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmTaskSequenceState {
    InProgress,
    BlockedOrDeferred,
    Failed,
    Succeeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmTaskSequenceClassification {
    Success,
    ConfirmedFailure,
    BlockedOrDeferred,
    InsufficientEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmTaskSequenceConfidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmTaskSequenceOrderingState {
    NormalizedUtc,
    Ambiguous,
    OffsetMissing,
    OffsetInvalid,
    TimestampMissing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmTaskSequenceIdentityProof {
    pub extraction_profile_id: String,
    pub evidence: Vec<SccmEvidenceRef>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmTaskSequencePathObservation {
    pub artifact_id: String,
    pub path_class: SccmTaskSequencePathClass,
    pub rotation: SccmRotation,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmTaskSequenceCoverageGap {
    pub artifact_id: String,
    pub coverage: SccmTaskSequenceCoverageState,
    pub path_class: SccmTaskSequencePathClass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmTaskSequenceCoverageState {
    Partial,
    Absent,
    AccessDenied,
    Capped,
    Skipped,
    Unsupported,
    ParseFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmTaskSequenceNextEvidence {
    pub logical_artifact_id: String,
    pub path_class: SccmTaskSequencePathClass,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmTaskSequenceTransaction {
    pub transaction_id: String,
    pub identity_proof: SccmTaskSequenceIdentityProof,
    pub evidence: Vec<SccmEvidenceRef>,
    pub path_sequence: Vec<SccmTaskSequencePathObservation>,
    pub phase: SccmTaskSequencePhase,
    pub state: SccmTaskSequenceState,
    pub last_successful_phase: SccmTaskSequencePhase,
    pub classification: SccmTaskSequenceClassification,
    pub confidence: SccmTaskSequenceConfidence,
    pub ordering_state: SccmTaskSequenceOrderingState,
    pub terminal_evidence: Option<SccmEvidenceRef>,
    pub next_evidence: Option<SccmTaskSequenceNextEvidence>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmTaskSequenceFinding {
    pub finding_id: String,
    pub transaction_id: Option<String>,
    pub classification: SccmTaskSequenceClassification,
    pub phase: Option<SccmTaskSequencePhase>,
    pub confidence: SccmTaskSequenceConfidence,
    pub evidence: Vec<SccmEvidenceRef>,
    pub coverage_gaps: Vec<SccmTaskSequenceCoverageGap>,
    pub next_evidence: Option<SccmTaskSequenceNextEvidence>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmTaskSequenceAnalysis {
    pub transactions: Vec<SccmTaskSequenceTransaction>,
    pub findings: Vec<SccmTaskSequenceFinding>,
    pub coverage_gaps: Vec<SccmTaskSequenceCoverageGap>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ExecutionIdentity {
    execution_id: String,
    package_id: String,
    advertisement_id: String,
    run_context: String,
}

#[derive(Debug, Clone)]
struct Observation {
    identity: ExecutionIdentity,
    evidence: SccmEvidenceRef,
    path_class: SccmTaskSequencePathClass,
    rotation: SccmRotation,
    phase: SccmTaskSequencePhase,
    state: SccmTaskSequenceState,
    terminal: bool,
    ordering_state: SccmTimeOrderingState,
    utc_millis: Option<i64>,
}

#[derive(Debug, Clone)]
struct UnlinkedObservation {
    evidence: SccmEvidenceRef,
    path_class: SccmTaskSequencePathClass,
}

pub fn analyze_client_task_sequence(
    admitted: &SccmClientAdmittedEvidence,
) -> Result<SccmTaskSequenceAnalysis, SccmClientEvidenceAdmissionError> {
    let sealed = admitted.task_sequence_evidence()?;
    let evidence = sealed.evidence;
    let sources = sealed.sources;
    let mut groups: BTreeMap<ExecutionIdentity, Vec<Observation>> = BTreeMap::new();
    let mut rotated = Vec::new();
    let mut unlinked = Vec::new();

    for record in evidence {
        let Some(source) = sources.get(&record.reference.artifact_id) else {
            continue;
        };
        let Some(profile) = sealed.profiles.get(&record.reference.artifact_id) else {
            unlinked.push(UnlinkedObservation {
                evidence: record.reference.clone(),
                path_class: source.path_class,
            });
            continue;
        };
        let Some(observation) =
            extract_observation(record, source.path_class, &source.rotation, profile)
        else {
            unlinked.push(UnlinkedObservation {
                evidence: record.reference.clone(),
                path_class: source.path_class,
            });
            continue;
        };

        if matches!(source.rotation, SccmRotation::Current) {
            groups
                .entry(observation.identity.clone())
                .or_default()
                .push(observation);
        } else {
            rotated.push(observation);
        }
    }

    for observation in rotated {
        if let Some(group) = groups.get_mut(&observation.identity) {
            group.push(observation);
        } else {
            unlinked.push(UnlinkedObservation {
                evidence: observation.evidence,
                path_class: observation.path_class,
            });
        }
    }

    let mut transactions = groups
        .into_values()
        .enumerate()
        .map(|(index, observations)| reduce_group(index + 1, observations))
        .collect::<Vec<_>>();
    transactions.sort_by(|left, right| left.transaction_id.cmp(&right.transaction_id));

    let mut coverage_gaps = sources
        .iter()
        .filter(|(_, source)| {
            source.coverage != SccmCoverageState::Captured || source.fragment_complete != Some(true)
        })
        .map(|(artifact_id, source)| SccmTaskSequenceCoverageGap {
            artifact_id: artifact_id.clone(),
            coverage: task_sequence_coverage(source),
            path_class: source.path_class,
        })
        .collect::<Vec<_>>();
    if coverage_gaps.is_empty() {
        if let Some(coverage) = sealed
            .coverage
            .filter(|coverage| **coverage != SccmCoverageState::Captured)
        {
            coverage_gaps.push(SccmTaskSequenceCoverageGap {
                artifact_id: TASK_SEQUENCE_LOGICAL_ARTIFACT_ID.to_owned(),
                coverage: coverage_state(coverage),
                path_class: SccmTaskSequencePathClass::Unknown,
            });
        }
    }
    coverage_gaps.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));

    let mut findings = transactions
        .iter()
        .filter(|transaction| transaction.classification != SccmTaskSequenceClassification::Success)
        .map(finding_for_transaction)
        .collect::<Vec<_>>();
    unlinked.sort_by(|left, right| compare_evidence_refs(&left.evidence, &right.evidence));
    findings.extend(
        unlinked
            .into_iter()
            .enumerate()
            .map(|(index, observation)| finding_for_unlinked(index + 1, observation)),
    );
    if !coverage_gaps.is_empty() {
        findings.push(finding_for_coverage(&coverage_gaps));
    }
    findings.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));

    Ok(SccmTaskSequenceAnalysis {
        transactions,
        findings,
        coverage_gaps,
    })
}

fn task_sequence_coverage(
    source: &super::admission::SccmClientAdmittedTaskSequenceSource,
) -> SccmTaskSequenceCoverageState {
    if source.coverage == SccmCoverageState::Captured && source.fragment_complete != Some(true) {
        return SccmTaskSequenceCoverageState::Partial;
    }
    coverage_state(&source.coverage)
}

fn coverage_state(coverage: &SccmCoverageState) -> SccmTaskSequenceCoverageState {
    match coverage {
        SccmCoverageState::Captured => SccmTaskSequenceCoverageState::Partial,
        SccmCoverageState::Absent => SccmTaskSequenceCoverageState::Absent,
        SccmCoverageState::AccessDenied => SccmTaskSequenceCoverageState::AccessDenied,
        SccmCoverageState::Capped => SccmTaskSequenceCoverageState::Capped,
        SccmCoverageState::Skipped => SccmTaskSequenceCoverageState::Skipped,
        SccmCoverageState::Unsupported => SccmTaskSequenceCoverageState::Unsupported,
        SccmCoverageState::ParseFailed => SccmTaskSequenceCoverageState::ParseFailed,
    }
}

fn extract_observation(
    evidence: &SccmEvidence,
    admitted_path_class: SccmTaskSequencePathClass,
    rotation: &SccmRotation,
    profile: &SccmExtractionProfile,
) -> Option<Observation> {
    if !is_reviewed_profile(profile) {
        return None;
    }

    let execution_id = capture_field(&evidence.message, "executionId")?;
    let package_id = capture_field(&evidence.message, "taskSequencePackageId")?;
    let advertisement_id = capture_field(&evidence.message, "advertisementId")?;
    let run_context = capture_field(&evidence.message, "runContext")?;
    let phase = parse_phase(capture_field(&evidence.message, "phase")?)?;
    let state = parse_state(capture_field(&evidence.message, "state")?)?;
    let terminal = parse_bool(capture_field(&evidence.message, "terminal")?)?;
    let observed_path_class = capture_field(&evidence.message, "_SMSTSLogPath")
        .map(classify_observed_path)
        .unwrap_or(SccmTaskSequencePathClass::Unknown);

    if !is_uuid(execution_id)
        || !is_fixed_alphanumeric(package_id, 8)
        || !is_fixed_alphanumeric(advertisement_id, 8)
        || !is_opaque_token(run_context)
        || observed_path_class != SccmTaskSequencePathClass::Unknown
            && observed_path_class != admitted_path_class
    {
        return None;
    }

    Some(Observation {
        identity: ExecutionIdentity {
            execution_id: execution_id.to_ascii_lowercase(),
            package_id: package_id.to_ascii_uppercase(),
            advertisement_id: advertisement_id.to_ascii_uppercase(),
            run_context: run_context.to_ascii_lowercase(),
        },
        evidence: evidence.reference.clone(),
        path_class: observed_path_class,
        rotation: rotation.clone(),
        phase,
        state,
        terminal,
        ordering_state: evidence.timestamp.ordering_state.clone(),
        utc_millis: evidence.timestamp.utc_millis,
    })
}

fn is_reviewed_profile(profile: &SccmExtractionProfile) -> bool {
    profile.profile_id == TASK_SEQUENCE_TEST_PROFILE_ID
        && profile.selected_configmgr_version.as_deref() == Some(TASK_SEQUENCE_TEST_VERSION)
        && profile.configmgr_version_prefixes == [TASK_SEQUENCE_TEST_VERSION]
        && profile.validated_artifact_families == [SccmArtifactFamily::ClientTaskSequence]
}

fn capture_field<'a>(message: &'a str, label: &str) -> Option<&'a str> {
    message.split_ascii_whitespace().find_map(|token| {
        let (candidate_label, value) = token.split_once('=')?;
        candidate_label
            .eq_ignore_ascii_case(label)
            .then_some(value)
            .filter(|value| !value.is_empty())
    })
}

fn parse_phase(value: &str) -> Option<SccmTaskSequencePhase> {
    match value {
        "start" => Some(SccmTaskSequencePhase::Start),
        "preflight" => Some(SccmTaskSequencePhase::Preflight),
        "diskOrImage" => Some(SccmTaskSequencePhase::DiskOrImage),
        "setupWindows" => Some(SccmTaskSequencePhase::SetupWindows),
        "installClient" => Some(SccmTaskSequencePhase::InstallClient),
        "installSoftware" => Some(SccmTaskSequencePhase::InstallSoftware),
        "postAction" => Some(SccmTaskSequencePhase::PostAction),
        "complete" => Some(SccmTaskSequencePhase::Complete),
        _ => None,
    }
}

fn parse_state(value: &str) -> Option<SccmTaskSequenceState> {
    match value {
        "inProgress" => Some(SccmTaskSequenceState::InProgress),
        "blockedOrDeferred" => Some(SccmTaskSequenceState::BlockedOrDeferred),
        "failed" => Some(SccmTaskSequenceState::Failed),
        "succeeded" => Some(SccmTaskSequenceState::Succeeded),
        _ => None,
    }
}

fn parse_bool(value: &str) -> Option<bool> {
    match value {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn classify_observed_path(value: &str) -> SccmTaskSequencePathClass {
    match value {
        "SYNTHETIC://winpe/Windows/temp/smstslog/smsts.log" => SccmTaskSequencePathClass::WinPe,
        "SYNTHETIC://setup/smstslog/smsts.log" => SccmTaskSequencePathClass::Setup,
        "SYNTHETIC://full-os/_SMSTaskSequence/Logs/smstslog/smsts.log" => {
            SccmTaskSequencePathClass::FullOs
        }
        "SYNTHETIC://client/CCM/Logs/smsts.log"
        | "SYNTHETIC://client/CCM/Logs/smstslog/smsts.log"
        | "SYNTHETIC://client/root-a/CCM/Logs/smstslog/smsts.log"
        | "SYNTHETIC://client/root-b/CCM/Logs/smstslog/smsts.log" => {
            SccmTaskSequencePathClass::Client
        }
        _ => SccmTaskSequencePathClass::Unknown,
    }
}

fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

fn is_fixed_alphanumeric(value: &str, width: usize) -> bool {
    value.len() == width && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

fn is_opaque_token(value: &str) -> bool {
    value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

fn reduce_group(index: usize, mut observations: Vec<Observation>) -> SccmTaskSequenceTransaction {
    observations.sort_by(compare_observations);
    let ordering_is_normalized = observations.iter().all(|observation| {
        observation.ordering_state == SccmTimeOrderingState::NormalizedUtc
            && observation.utc_millis.is_some()
    });
    let timestamps_are_unique = observations
        .iter()
        .filter_map(|observation| observation.utc_millis)
        .collect::<BTreeSet<_>>()
        .len()
        == observations.len();
    let phases_are_monotonic = observations
        .windows(2)
        .all(|pair| pair[0].phase <= pair[1].phase);
    let ordering_is_safe = ordering_is_normalized && timestamps_are_unique && phases_are_monotonic;
    let final_observation = observations
        .last()
        .expect("an execution group contains at least one observation");
    let (classification, confidence) = classify_transaction(final_observation, ordering_is_safe);
    let evidence = observations
        .iter()
        .map(|observation| observation.evidence.clone())
        .collect::<Vec<_>>();
    let terminal_evidence = final_observation
        .terminal
        .then(|| final_observation.evidence.clone());

    SccmTaskSequenceTransaction {
        transaction_id: format!("task-sequence-{index:04}"),
        identity_proof: SccmTaskSequenceIdentityProof {
            extraction_profile_id: TASK_SEQUENCE_TEST_PROFILE_ID.to_owned(),
            evidence: evidence.clone(),
        },
        evidence,
        path_sequence: observations
            .iter()
            .map(|observation| SccmTaskSequencePathObservation {
                artifact_id: observation.evidence.artifact_id.clone(),
                path_class: observation.path_class,
                rotation: observation.rotation.clone(),
            })
            .collect(),
        phase: final_observation.phase,
        state: final_observation.state,
        last_successful_phase: last_successful_phase(final_observation),
        classification,
        confidence,
        ordering_state: if ordering_is_safe {
            SccmTaskSequenceOrderingState::NormalizedUtc
        } else if ordering_is_normalized {
            SccmTaskSequenceOrderingState::Ambiguous
        } else {
            task_sequence_ordering_state(&final_observation.ordering_state)
        },
        terminal_evidence,
        next_evidence: next_evidence(final_observation.phase, classification),
    }
}

fn task_sequence_ordering_state(
    ordering_state: &SccmTimeOrderingState,
) -> SccmTaskSequenceOrderingState {
    match ordering_state {
        SccmTimeOrderingState::NormalizedUtc => SccmTaskSequenceOrderingState::NormalizedUtc,
        SccmTimeOrderingState::OffsetMissing => SccmTaskSequenceOrderingState::OffsetMissing,
        SccmTimeOrderingState::OffsetInvalid => SccmTaskSequenceOrderingState::OffsetInvalid,
        SccmTimeOrderingState::TimestampMissing => SccmTaskSequenceOrderingState::TimestampMissing,
    }
}

fn compare_observations(left: &Observation, right: &Observation) -> Ordering {
    left.utc_millis
        .cmp(&right.utc_millis)
        .then_with(|| left.phase.cmp(&right.phase))
        .then_with(|| compare_evidence_refs(&left.evidence, &right.evidence))
}

fn compare_evidence_refs(left: &SccmEvidenceRef, right: &SccmEvidenceRef) -> Ordering {
    (
        left.artifact_id.as_str(),
        left.line_start,
        left.line_end,
        left.entry_id.as_str(),
    )
        .cmp(&(
            right.artifact_id.as_str(),
            right.line_start,
            right.line_end,
            right.entry_id.as_str(),
        ))
}

fn classify_transaction(
    final_observation: &Observation,
    ordering_is_safe: bool,
) -> (SccmTaskSequenceClassification, SccmTaskSequenceConfidence) {
    if !ordering_is_safe {
        return (
            SccmTaskSequenceClassification::InsufficientEvidence,
            SccmTaskSequenceConfidence::Low,
        );
    }
    match (
        final_observation.phase,
        final_observation.state,
        final_observation.terminal,
    ) {
        (_, SccmTaskSequenceState::Failed, true) => (
            SccmTaskSequenceClassification::ConfirmedFailure,
            SccmTaskSequenceConfidence::High,
        ),
        (SccmTaskSequencePhase::Complete, SccmTaskSequenceState::Succeeded, true) => (
            SccmTaskSequenceClassification::Success,
            SccmTaskSequenceConfidence::High,
        ),
        (_, SccmTaskSequenceState::BlockedOrDeferred, false) => (
            SccmTaskSequenceClassification::BlockedOrDeferred,
            SccmTaskSequenceConfidence::Medium,
        ),
        _ => (
            SccmTaskSequenceClassification::InsufficientEvidence,
            SccmTaskSequenceConfidence::Medium,
        ),
    }
}

fn last_successful_phase(observation: &Observation) -> SccmTaskSequencePhase {
    if observation.state == SccmTaskSequenceState::Succeeded {
        return observation.phase;
    }
    match observation.phase {
        SccmTaskSequencePhase::Start | SccmTaskSequencePhase::Preflight => {
            SccmTaskSequencePhase::Start
        }
        SccmTaskSequencePhase::DiskOrImage => SccmTaskSequencePhase::Preflight,
        SccmTaskSequencePhase::SetupWindows => SccmTaskSequencePhase::DiskOrImage,
        SccmTaskSequencePhase::InstallClient => SccmTaskSequencePhase::SetupWindows,
        SccmTaskSequencePhase::InstallSoftware => SccmTaskSequencePhase::InstallClient,
        SccmTaskSequencePhase::PostAction => SccmTaskSequencePhase::InstallSoftware,
        SccmTaskSequencePhase::Complete => SccmTaskSequencePhase::PostAction,
    }
}

fn next_evidence(
    phase: SccmTaskSequencePhase,
    classification: SccmTaskSequenceClassification,
) -> Option<SccmTaskSequenceNextEvidence> {
    if matches!(
        classification,
        SccmTaskSequenceClassification::Success | SccmTaskSequenceClassification::ConfirmedFailure
    ) {
        return None;
    }
    let (path_class, reason) = match phase {
        SccmTaskSequencePhase::Start | SccmTaskSequencePhase::Preflight => (
            SccmTaskSequencePathClass::Setup,
            "Collect the post-format Task Sequence continuation.",
        ),
        SccmTaskSequencePhase::DiskOrImage => (
            SccmTaskSequencePathClass::FullOs,
            "Collect the relocated pre-client Task Sequence continuation.",
        ),
        SccmTaskSequencePhase::SetupWindows => (
            SccmTaskSequencePathClass::Client,
            "Collect the post-client Task Sequence continuation.",
        ),
        _ => (
            SccmTaskSequencePathClass::Client,
            "Collect the next complete client Task Sequence record.",
        ),
    };
    Some(SccmTaskSequenceNextEvidence {
        logical_artifact_id: TASK_SEQUENCE_LOGICAL_ARTIFACT_ID.to_owned(),
        path_class,
        reason: reason.to_owned(),
    })
}

fn finding_for_transaction(transaction: &SccmTaskSequenceTransaction) -> SccmTaskSequenceFinding {
    SccmTaskSequenceFinding {
        finding_id: format!("{}-finding", transaction.transaction_id),
        transaction_id: Some(transaction.transaction_id.clone()),
        classification: transaction.classification,
        phase: Some(transaction.phase),
        confidence: transaction.confidence,
        evidence: transaction.evidence.clone(),
        coverage_gaps: Vec::new(),
        next_evidence: transaction.next_evidence.clone(),
    }
}

fn finding_for_unlinked(index: usize, observation: UnlinkedObservation) -> SccmTaskSequenceFinding {
    SccmTaskSequenceFinding {
        finding_id: format!("task-sequence-unlinked-{index:04}"),
        transaction_id: None,
        classification: SccmTaskSequenceClassification::InsufficientEvidence,
        phase: None,
        confidence: SccmTaskSequenceConfidence::Low,
        evidence: vec![observation.evidence],
        coverage_gaps: Vec::new(),
        next_evidence: Some(SccmTaskSequenceNextEvidence {
            logical_artifact_id: TASK_SEQUENCE_LOGICAL_ARTIFACT_ID.to_owned(),
            path_class: observation.path_class,
            reason: "Collect a complete record under a reviewed Task Sequence profile.".to_owned(),
        }),
    }
}

fn finding_for_coverage(coverage_gaps: &[SccmTaskSequenceCoverageGap]) -> SccmTaskSequenceFinding {
    let path_class = coverage_gaps
        .first()
        .map(|gap| gap.path_class)
        .unwrap_or(SccmTaskSequencePathClass::Unknown);
    SccmTaskSequenceFinding {
        finding_id: "task-sequence-coverage-0001".to_owned(),
        transaction_id: None,
        classification: SccmTaskSequenceClassification::InsufficientEvidence,
        phase: None,
        confidence: SccmTaskSequenceConfidence::Low,
        evidence: Vec::new(),
        coverage_gaps: coverage_gaps.to_vec(),
        next_evidence: Some(SccmTaskSequenceNextEvidence {
            logical_artifact_id: TASK_SEQUENCE_LOGICAL_ARTIFACT_ID.to_owned(),
            path_class,
            reason: "Collect a complete Task Sequence logical record from the active path."
                .to_owned(),
        }),
    }
}
