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
use sha2::{Digest, Sha256};

use crate::sccm::{
    SccmArtifactFamily, SccmCoverageState, SccmEvidence, SccmEvidenceRef, SccmExtractionProfile,
    SccmRotation, SccmTimeOrderingState,
};

use super::{
    SccmClientAdmittedEvidence, SccmClientEvidenceAdmissionError, SccmTaskSequencePathClass,
    SccmTaskSequenceProvenance, TASK_SEQUENCE_TEST_PROFILE_ID, TASK_SEQUENCE_TEST_VERSION,
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
    pub relocation_ordinal: u32,
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
    pub evidence: Vec<SccmTaskSequenceEvidenceCitation>,
    pub coverage_gaps: Vec<SccmTaskSequenceCoverageGap>,
    pub next_evidence: Option<SccmTaskSequenceNextEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmTaskSequenceEvidenceCitation {
    pub artifact_id: String,
    pub line_start: u32,
    pub line_end: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmTaskSequenceKeyConfidence {
    None,
    Candidate,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmTaskSequenceSourceLocalObservation {
    pub observation_id: String,
    pub artifact_id: String,
    pub key_confidence: SccmTaskSequenceKeyConfidence,
    pub confidence: SccmTaskSequenceConfidence,
    pub correlation_eligible: bool,
    pub phase_hint: Option<SccmTaskSequencePhase>,
    pub state_hint: Option<SccmTaskSequenceState>,
    pub evidence: Option<SccmTaskSequenceEvidenceCitation>,
    pub path_class: SccmTaskSequencePathClass,
    pub rotation: SccmRotation,
    pub coverage: SccmCoverageState,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmTaskSequenceAnalysis {
    pub transactions: Vec<SccmTaskSequenceTransaction>,
    pub source_local_observations: Vec<SccmTaskSequenceSourceLocalObservation>,
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
    relocation_lineage: String,
    relocation_ordinal: u32,
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
    rotation: SccmRotation,
    key_confidence: SccmTaskSequenceKeyConfidence,
    phase_hint: Option<SccmTaskSequencePhase>,
    state_hint: Option<SccmTaskSequenceState>,
    reason: &'static str,
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
        let Some(provenance) = source.provenance.as_ref() else {
            continue;
        };
        let Some(profile) = sealed.profiles.get(&record.reference.artifact_id) else {
            unlinked.push(UnlinkedObservation {
                evidence: record.reference.clone(),
                path_class: provenance.path_class,
                rotation: source.rotation.clone(),
                key_confidence: SccmTaskSequenceKeyConfidence::None,
                phase_hint: None,
                state_hint: None,
                reason: "No sealed extraction profile owns this physical source.",
            });
            continue;
        };
        if !is_reviewed_profile(profile) {
            unlinked.push(unlinked_observation(
                record,
                provenance.path_class,
                &source.rotation,
                "Key-looking fields from an unrecognized source version cannot be promoted by an unverified extraction profile.",
            ));
            continue;
        }
        let Some(observation) = extract_observation(record, provenance, &source.rotation, profile)
        else {
            unlinked.push(unlinked_observation(
                record,
                provenance.path_class,
                &source.rotation,
                "A path, timestamp, display name, or partial key cannot substitute for the complete record-local execution key.",
            ));
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
                rotation: observation.rotation,
                key_confidence: SccmTaskSequenceKeyConfidence::Candidate,
                phase_hint: Some(observation.phase),
                state_hint: Some(observation.state),
                reason: "A rotated record without a current record for the same exact execution remains source-local.",
            });
        }
    }

    let mut transactions = Vec::new();
    for observations in groups.into_values() {
        let relocation_lineages = observations
            .iter()
            .map(|observation| observation.relocation_lineage.as_str())
            .collect::<BTreeSet<_>>();
        if relocation_lineages.len() == 1 {
            transactions.push(reduce_group(observations));
        } else {
            unlinked.extend(
                observations
                    .into_iter()
                    .map(|observation| UnlinkedObservation {
                        evidence: observation.evidence,
                        path_class: observation.path_class,
                        rotation: observation.rotation,
                        key_confidence: SccmTaskSequenceKeyConfidence::Candidate,
                        phase_hint: Some(observation.phase),
                        state_hint: Some(observation.state),
                        reason: "An execution identity observed across distinct sealed relocation lineages cannot be correlated.",
                    }),
            );
        }
    }
    transactions.sort_by(|left, right| left.transaction_id.cmp(&right.transaction_id));

    let mut coverage_gaps = sources
        .iter()
        .filter(|(_, source)| {
            source.coverage != SccmCoverageState::Captured || source.fragment_complete != Some(true)
        })
        .map(|(artifact_id, source)| SccmTaskSequenceCoverageGap {
            artifact_id: artifact_id.clone(),
            coverage: task_sequence_coverage(source),
            path_class: source
                .provenance
                .as_ref()
                .map_or(SccmTaskSequencePathClass::Unknown, |provenance| {
                    provenance.path_class
                }),
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

    unlinked.sort_by(|left, right| compare_evidence_refs(&left.evidence, &right.evidence));
    let mut source_local_observations = unlinked
        .into_iter()
        .map(source_local_observation)
        .collect::<Vec<_>>();
    source_local_observations.extend(sources.iter().filter_map(|(artifact_id, source)| {
        let physical = source.physical_evidence.as_ref()?;
        (source.coverage == SccmCoverageState::Captured && source.fragment_complete != Some(true))
            .then(|| source_local_fragment_observation(artifact_id, source, physical))
    }));
    source_local_observations.sort_by(|left, right| left.observation_id.cmp(&right.observation_id));

    let mut findings = transactions
        .iter()
        .filter(|transaction| transaction.classification != SccmTaskSequenceClassification::Success)
        .map(finding_for_transaction)
        .collect::<Vec<_>>();
    let uncovered_source_observations = source_local_observations
        .iter()
        .filter(|observation| {
            !coverage_gaps
                .iter()
                .any(|gap| gap.artifact_id == observation.artifact_id)
        })
        .collect::<Vec<_>>();
    findings.extend(
        uncovered_source_observations
            .iter()
            .map(|observation| finding_for_source_locals(&[*observation])),
    );
    if !coverage_gaps.is_empty() {
        findings.push(finding_for_coverage(
            &coverage_gaps,
            &source_local_observations,
        ));
    }
    findings.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));

    Ok(SccmTaskSequenceAnalysis {
        transactions,
        source_local_observations,
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
    provenance: &SccmTaskSequenceProvenance,
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
    if !is_uuid(execution_id)
        || !is_fixed_alphanumeric(package_id, 8)
        || !is_fixed_alphanumeric(advertisement_id, 8)
        || !is_opaque_token(run_context)
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
        path_class: provenance.path_class,
        relocation_lineage: provenance.relocation_lineage.clone(),
        relocation_ordinal: provenance.relocation_ordinal,
        rotation: rotation.clone(),
        phase,
        state,
        terminal,
        ordering_state: evidence.timestamp.ordering_state.clone(),
        utc_millis: evidence.timestamp.utc_millis,
    })
}

fn unlinked_observation(
    evidence: &SccmEvidence,
    path_class: SccmTaskSequencePathClass,
    rotation: &SccmRotation,
    reason: &'static str,
) -> UnlinkedObservation {
    let has_candidate_key = [
        "executionId",
        "taskSequencePackageId",
        "advertisementId",
        "runContext",
    ]
    .iter()
    .all(|label| capture_field(&evidence.message, label).is_some());
    UnlinkedObservation {
        evidence: evidence.reference.clone(),
        path_class,
        rotation: rotation.clone(),
        key_confidence: if has_candidate_key {
            SccmTaskSequenceKeyConfidence::Candidate
        } else {
            SccmTaskSequenceKeyConfidence::None
        },
        phase_hint: capture_field(&evidence.message, "phase").and_then(parse_phase),
        state_hint: capture_field(&evidence.message, "state").and_then(parse_state),
        reason,
    }
}

fn source_local_observation(
    observation: UnlinkedObservation,
) -> SccmTaskSequenceSourceLocalObservation {
    let citation = evidence_citation(&observation.evidence);
    let observation_id = stable_opaque_id(
        "cmtraceopen.task-sequence.observation.sha256.v1:",
        &[
            citation.artifact_id.as_str(),
            &citation.line_start.to_string(),
            &citation.line_end.to_string(),
        ],
    );
    SccmTaskSequenceSourceLocalObservation {
        observation_id,
        artifact_id: citation.artifact_id.clone(),
        key_confidence: observation.key_confidence,
        confidence: SccmTaskSequenceConfidence::Low,
        correlation_eligible: false,
        phase_hint: observation.phase_hint,
        state_hint: observation.state_hint,
        evidence: Some(citation),
        path_class: observation.path_class,
        rotation: observation.rotation,
        coverage: SccmCoverageState::Captured,
        reason: observation.reason.to_owned(),
    }
}

fn source_local_fragment_observation(
    artifact_id: &str,
    source: &super::admission::SccmClientAdmittedTaskSequenceSource,
    physical: &super::admission::SccmClientAdmittedTaskSequencePhysicalEvidence,
) -> SccmTaskSequenceSourceLocalObservation {
    let citation = SccmTaskSequenceEvidenceCitation {
        artifact_id: artifact_id.to_owned(),
        line_start: physical.line_start,
        line_end: physical.line_end,
    };
    SccmTaskSequenceSourceLocalObservation {
        observation_id: stable_opaque_id(
            "cmtraceopen.task-sequence.observation.sha256.v1:",
            &[
                artifact_id,
                &physical.line_start.to_string(),
                &physical.line_end.to_string(),
                "physical-fragment",
            ],
        ),
        artifact_id: artifact_id.to_owned(),
        key_confidence: if physical.key_candidate {
            SccmTaskSequenceKeyConfidence::Candidate
        } else {
            SccmTaskSequenceKeyConfidence::None
        },
        confidence: SccmTaskSequenceConfidence::Low,
        correlation_eligible: false,
        phase_hint: None,
        state_hint: None,
        evidence: Some(citation),
        path_class: source
            .provenance
            .as_ref()
            .map_or(SccmTaskSequencePathClass::Unknown, |provenance| {
                provenance.path_class
            }),
        rotation: source.rotation.clone(),
        coverage: source.coverage.clone(),
        reason:
            "An incomplete physical rotation fragment is not independently a logical CCM record."
                .to_owned(),
    }
}

fn evidence_citation(reference: &SccmEvidenceRef) -> SccmTaskSequenceEvidenceCitation {
    SccmTaskSequenceEvidenceCitation {
        artifact_id: reference.artifact_id.clone(),
        line_start: reference
            .line_start
            .expect("admission requires a physical start line"),
        line_end: reference
            .line_end
            .expect("admission requires a physical end line"),
    }
}

fn is_reviewed_profile(profile: &SccmExtractionProfile) -> bool {
    profile.profile_id == TASK_SEQUENCE_TEST_PROFILE_ID
        && profile.selected_configmgr_version.as_deref() == Some(TASK_SEQUENCE_TEST_VERSION)
        && profile.configmgr_version_prefixes == [TASK_SEQUENCE_TEST_VERSION]
        && profile.validated_artifact_families == [SccmArtifactFamily::ClientTaskSequence]
}

fn capture_field<'a>(message: &'a str, label: &str) -> Option<&'a str> {
    let mut values = message.split_ascii_whitespace().filter_map(|token| {
        let (candidate_label, value) = token.split_once('=')?;
        (candidate_label.eq_ignore_ascii_case(label) && !value.is_empty()).then_some(value)
    });
    let value = values.next()?;
    values.next().is_none().then_some(value)
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

fn reduce_group(mut observations: Vec<Observation>) -> SccmTaskSequenceTransaction {
    let identity = observations
        .first()
        .expect("an execution group contains at least one observation")
        .identity
        .clone();
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
    let relocation_ordinals_are_unique = observations
        .iter()
        .map(|observation| {
            (
                observation.relocation_lineage.as_str(),
                observation.relocation_ordinal,
            )
        })
        .collect::<BTreeSet<_>>()
        .len()
        == observations.len();
    if relocation_ordinals_are_unique {
        observations.sort_by(compare_relocation_observations);
    } else if ordering_is_normalized && timestamps_are_unique {
        observations.sort_by(compare_observations);
    } else {
        observations.sort_by(|left, right| compare_evidence_refs(&left.evidence, &right.evidence));
    }
    let phases_are_monotonic = observations
        .windows(2)
        .all(|pair| pair[0].phase <= pair[1].phase);
    // The reviewed four-field key has no attempt discriminator or recovery
    // marker. A record after any terminal record therefore cannot be called a
    // retry or continuation; keep the whole execution ambiguous until a future
    // profile supplies explicit record-local attempt authority.
    let terminal_is_final = observations
        .iter()
        .enumerate()
        .all(|(index, observation)| !observation.terminal || index + 1 == observations.len());
    let ordering_is_safe = ordering_is_normalized
        && (relocation_ordinals_are_unique || timestamps_are_unique)
        && phases_are_monotonic
        && terminal_is_final;
    let representative = if ordering_is_safe {
        observations
            .last()
            .expect("an execution group contains at least one observation")
    } else {
        observations
            .iter()
            .max_by(|left, right| {
                left.phase
                    .cmp(&right.phase)
                    .then_with(|| compare_evidence_refs(&left.evidence, &right.evidence))
            })
            .expect("an execution group contains at least one observation")
    };
    let (classification, confidence) = classify_transaction(representative, ordering_is_safe);
    let evidence = observations
        .iter()
        .map(|observation| observation.evidence.clone())
        .collect::<Vec<_>>();
    let terminal_evidence =
        (ordering_is_safe && representative.terminal).then(|| representative.evidence.clone());
    let ordering_state = if ordering_is_safe {
        SccmTaskSequenceOrderingState::NormalizedUtc
    } else if observations.len() > 1 {
        SccmTaskSequenceOrderingState::Ambiguous
    } else {
        task_sequence_ordering_state(&representative.ordering_state)
    };

    SccmTaskSequenceTransaction {
        transaction_id: stable_opaque_id(
            "cmtraceopen.task-sequence.transaction.sha256.v1:",
            &[
                &identity.execution_id,
                &identity.package_id,
                &identity.advertisement_id,
                &identity.run_context,
            ],
        ),
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
                relocation_ordinal: observation.relocation_ordinal,
            })
            .collect(),
        phase: representative.phase,
        state: representative.state,
        last_successful_phase: last_successful_phase(representative),
        classification,
        confidence,
        ordering_state,
        terminal_evidence,
        next_evidence: next_evidence(representative, classification),
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
        .then_with(|| compare_evidence_refs(&left.evidence, &right.evidence))
}

fn compare_relocation_observations(left: &Observation, right: &Observation) -> Ordering {
    left.relocation_lineage
        .cmp(&right.relocation_lineage)
        .then_with(|| left.relocation_ordinal.cmp(&right.relocation_ordinal))
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
    observation: &Observation,
    classification: SccmTaskSequenceClassification,
) -> Option<SccmTaskSequenceNextEvidence> {
    if matches!(
        classification,
        SccmTaskSequenceClassification::Success | SccmTaskSequenceClassification::ConfirmedFailure
    ) {
        return None;
    }
    let (path_class, reason) = match observation.phase {
        SccmTaskSequencePhase::Start | SccmTaskSequencePhase::Preflight
            if observation.path_class == SccmTaskSequencePathClass::Client =>
        {
            (
                SccmTaskSequencePathClass::Client,
                "Collect the next complete client Task Sequence record.",
            )
        }
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
        finding_id: stable_opaque_id(
            "cmtraceopen.task-sequence.finding.sha256.v1:",
            &[&transaction.transaction_id, "transaction"],
        ),
        transaction_id: Some(transaction.transaction_id.clone()),
        classification: transaction.classification,
        phase: Some(transaction.phase),
        confidence: transaction.confidence,
        evidence: transaction.evidence.iter().map(evidence_citation).collect(),
        coverage_gaps: Vec::new(),
        next_evidence: None,
    }
}

fn finding_for_source_locals(
    observations: &[&SccmTaskSequenceSourceLocalObservation],
) -> SccmTaskSequenceFinding {
    let mut identity_parts = vec!["source-local"];
    identity_parts.extend(
        observations
            .iter()
            .map(|observation| observation.observation_id.as_str()),
    );
    let evidence = observations
        .iter()
        .filter_map(|observation| observation.evidence.clone())
        .collect::<Vec<_>>();
    let path_class = observations
        .first()
        .map(|observation| observation.path_class)
        .unwrap_or(SccmTaskSequencePathClass::Unknown);
    SccmTaskSequenceFinding {
        finding_id: stable_opaque_id(
            "cmtraceopen.task-sequence.finding.sha256.v1:",
            &identity_parts,
        ),
        transaction_id: None,
        classification: SccmTaskSequenceClassification::InsufficientEvidence,
        phase: None,
        confidence: SccmTaskSequenceConfidence::Low,
        evidence,
        coverage_gaps: Vec::new(),
        next_evidence: observations
            .iter()
            .any(|observation| {
                observation.key_confidence == SccmTaskSequenceKeyConfidence::Candidate
            })
            .then(|| SccmTaskSequenceNextEvidence {
                logical_artifact_id: TASK_SEQUENCE_LOGICAL_ARTIFACT_ID.to_owned(),
                path_class,
                reason: "Add or apply a reviewed extraction profile before correlation.".to_owned(),
            }),
    }
}

fn finding_for_coverage(
    coverage_gaps: &[SccmTaskSequenceCoverageGap],
    observations: &[SccmTaskSequenceSourceLocalObservation],
) -> SccmTaskSequenceFinding {
    let path_class = coverage_gaps
        .first()
        .map(|gap| gap.path_class)
        .unwrap_or(SccmTaskSequencePathClass::Unknown);
    let mut identity_parts = vec!["coverage"];
    identity_parts.extend(coverage_gaps.iter().map(|gap| gap.artifact_id.as_str()));
    let evidence = observations
        .iter()
        .filter(|observation| {
            coverage_gaps
                .iter()
                .any(|gap| gap.artifact_id == observation.artifact_id)
        })
        .filter_map(|observation| observation.evidence.clone())
        .collect::<Vec<_>>();
    let finding_coverage_gaps = if evidence.is_empty() {
        coverage_gaps.to_vec()
    } else {
        Vec::new()
    };
    SccmTaskSequenceFinding {
        finding_id: stable_opaque_id(
            "cmtraceopen.task-sequence.finding.sha256.v1:",
            &identity_parts,
        ),
        transaction_id: None,
        classification: SccmTaskSequenceClassification::InsufficientEvidence,
        phase: None,
        confidence: SccmTaskSequenceConfidence::Low,
        evidence,
        coverage_gaps: finding_coverage_gaps,
        next_evidence: Some(SccmTaskSequenceNextEvidence {
            logical_artifact_id: TASK_SEQUENCE_LOGICAL_ARTIFACT_ID.to_owned(),
            path_class,
            reason: "Collect a complete Task Sequence logical record from the active path."
                .to_owned(),
        }),
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
