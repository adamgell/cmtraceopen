use std::collections::BTreeMap;

use regex::Regex;
use serde::{Deserialize, Serialize};

use super::super::catalog::{classify_artifact_name, SccmArtifactFamily};
use super::super::keys::normalize_key;
use super::super::models::{
    SccmArtifact, SccmCorrelationKey, SccmCorrelationKeyKind, SccmCoverageState, SccmEvidence,
    SccmEvidenceRef, SccmKeyConfidence, SccmRole, SccmRotation,
};

const TASK_SEQUENCE_PROFILE_ID: &str = "task-sequence-client-5.00.test-v1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmTaskSequencePathClass {
    #[serde(rename = "winpe")]
    WinPe,
    Setup,
    FullOs,
    Client,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SccmTaskSequenceFragment {
    pub artifact: SccmArtifact,
    pub path_class: SccmTaskSequencePathClass,
    pub relocation_ordinal: u32,
    pub evidence: Vec<SccmEvidence>,
}

impl SccmTaskSequenceFragment {
    pub fn new(
        artifact: SccmArtifact,
        path_class: SccmTaskSequencePathClass,
        relocation_ordinal: u32,
        evidence: Vec<SccmEvidence>,
    ) -> Self {
        Self {
            artifact,
            path_class,
            relocation_ordinal,
            evidence,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmTaskSequencePath {
    pub artifact_id: String,
    pub path_class: SccmTaskSequencePathClass,
    pub relocation_ordinal: u32,
    pub rotation: SccmRotation,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SccmTaskSequenceTransaction {
    pub keys: Vec<SccmCorrelationKey>,
    pub evidence: Vec<SccmEvidenceRef>,
    pub path_sequence: Vec<SccmTaskSequencePath>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmTaskSequenceCoverageGap {
    pub artifact_id: String,
    pub coverage: SccmCoverageState,
    pub path_class: SccmTaskSequencePathClass,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmTaskSequenceUnlinkedFragment {
    pub artifact_id: String,
    pub evidence: Vec<SccmEvidenceRef>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SccmTaskSequenceAnalysis {
    pub transactions: Vec<SccmTaskSequenceTransaction>,
    pub coverage_gaps: Vec<SccmTaskSequenceCoverageGap>,
    pub unlinked_fragments: Vec<SccmTaskSequenceUnlinkedFragment>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ExecutionIdentity {
    execution_id: String,
    package_id: String,
    advertisement_id: String,
    run_context: String,
}

#[derive(Debug, Clone)]
struct KeyObservation {
    identity: ExecutionIdentity,
    evidence: SccmEvidenceRef,
    execution_key: SccmCorrelationKey,
}

pub fn analyze_client_task_sequence(
    fragments: &[SccmTaskSequenceFragment],
) -> SccmTaskSequenceAnalysis {
    let mut ordered = fragments.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|fragment| {
        (
            fragment.relocation_ordinal,
            fragment.artifact.artifact_id.clone(),
        )
    });

    let mut groups: BTreeMap<
        ExecutionIdentity,
        Vec<(usize, &SccmTaskSequenceFragment, KeyObservation)>,
    > = BTreeMap::new();
    let mut coverage_gaps = Vec::new();
    let mut unlinked_fragments = Vec::new();
    let mut rotated_observations = Vec::new();

    for (order, fragment) in ordered.into_iter().enumerate() {
        if fragment.artifact.role != SccmRole::Client {
            unlinked_fragments.push(unlinked(fragment, "artifact role is not client"));
            continue;
        }
        let catalog = classify_artifact_name(&fragment.artifact.display_name, SccmRole::Client);
        if catalog.family != SccmArtifactFamily::ClientTaskSequence {
            unlinked_fragments.push(unlinked(
                fragment,
                "artifact is not declared Task Sequence evidence",
            ));
            continue;
        }
        if !catalog.supported_for_diagnosis || catalog.rotation != fragment.artifact.rotation {
            unlinked_fragments.push(unlinked(
                fragment,
                "artifact rotation is not an explicitly supported Task Sequence form",
            ));
            continue;
        }

        if fragment.artifact.coverage != SccmCoverageState::Captured {
            coverage_gaps.push(SccmTaskSequenceCoverageGap {
                artifact_id: fragment.artifact.artifact_id.clone(),
                coverage: fragment.artifact.coverage.clone(),
                path_class: fragment.path_class.clone(),
            });
            continue;
        }

        if fragment.evidence.is_empty() {
            unlinked_fragments.push(unlinked(
                fragment,
                "captured artifact has no normalized evidence",
            ));
            continue;
        }

        let observations = fragment.evidence.iter().filter_map(|evidence| {
            extract_observation(evidence, fragment.artifact.configmgr_version.as_deref())
        });

        let observations = observations.collect::<Vec<_>>();
        if observations.is_empty() {
            unlinked_fragments.push(unlinked(
                fragment,
                "no complete validated execution identity was observed in one record",
            ));
            continue;
        }

        if matches!(fragment.artifact.rotation, SccmRotation::Current) {
            for observation in observations {
                groups
                    .entry(observation.identity.clone())
                    .or_default()
                    .push((order, fragment, observation));
            }
        } else {
            rotated_observations.extend(
                observations
                    .into_iter()
                    .map(|observation| (order, fragment, observation)),
            );
        }
    }

    for (order, fragment, observation) in rotated_observations {
        if groups.contains_key(&observation.identity) {
            groups
                .entry(observation.identity.clone())
                .or_default()
                .push((order, fragment, observation));
        } else {
            unlinked_fragments.push(unlinked(
                fragment,
                "rotated physical fragment has no exact current execution identity to join",
            ));
        }
    }

    let transactions = groups
        .into_values()
        .map(|group| {
            let mut group = group;
            group.sort_by_key(|(order, _, _)| *order);
            let first = &group[0].2;
            SccmTaskSequenceTransaction {
                keys: vec![first.execution_key.clone()],
                evidence: group
                    .iter()
                    .map(|(_, _, observation)| observation.evidence.clone())
                    .collect(),
                path_sequence: group
                    .iter()
                    .map(|(_, fragment, _)| SccmTaskSequencePath {
                        artifact_id: fragment.artifact.artifact_id.clone(),
                        path_class: fragment.path_class.clone(),
                        relocation_ordinal: fragment.relocation_ordinal,
                        rotation: fragment.artifact.rotation.clone(),
                    })
                    .collect(),
            }
        })
        .collect();

    coverage_gaps.sort_by_key(|gap| gap.artifact_id.clone());
    unlinked_fragments.sort_by_key(|fragment| fragment.artifact_id.clone());

    SccmTaskSequenceAnalysis {
        transactions,
        coverage_gaps,
        unlinked_fragments,
    }
}

fn unlinked(fragment: &SccmTaskSequenceFragment, reason: &str) -> SccmTaskSequenceUnlinkedFragment {
    SccmTaskSequenceUnlinkedFragment {
        artifact_id: fragment.artifact.artifact_id.clone(),
        evidence: fragment
            .evidence
            .iter()
            .map(|evidence| evidence.reference.clone())
            .collect(),
        reason: reason.to_owned(),
    }
}

fn extract_observation(evidence: &SccmEvidence, version: Option<&str>) -> Option<KeyObservation> {
    if !version.is_some_and(|version| version.starts_with("5.00.TEST.")) {
        return None;
    }

    let execution_id = capture(&evidence.message, "executionId")?;
    let package_id = capture(&evidence.message, "taskSequencePackageId")?;
    let advertisement_id = capture(&evidence.message, "advertisementId")?;
    let run_context = capture(&evidence.message, "runContext")?;
    let execution_key = normalize_key(
        SccmCorrelationKeyKind::TaskSequenceExecutionId,
        &execution_id,
    );
    if !is_uuid(&execution_key.normalized)
        || execution_key.confidence != SccmKeyConfidence::Exact
        || !is_token(&package_id)
        || !is_token(&advertisement_id)
        || !is_token(&run_context)
    {
        return None;
    }

    let mut execution_key = execution_key;
    execution_key.extraction_profile_id = Some(TASK_SEQUENCE_PROFILE_ID.to_owned());
    execution_key.confidence = SccmKeyConfidence::Exact;
    execution_key.evidence = Some(evidence.reference.clone());
    Some(KeyObservation {
        identity: ExecutionIdentity {
            execution_id: execution_key.normalized.clone(),
            package_id: package_id.to_ascii_lowercase(),
            advertisement_id: advertisement_id.to_ascii_lowercase(),
            run_context: run_context.to_ascii_lowercase(),
        },
        evidence: evidence.reference.clone(),
        execution_key,
    })
}

fn capture(message: &str, label: &str) -> Option<String> {
    let pattern = format!(r"(?i)(?:^|[^A-Za-z0-9_]){label}=([A-Za-z0-9_.{{}}-]+)");
    Regex::new(&pattern)
        .ok()?
        .captures(message)
        .and_then(|captures| captures.get(1).map(|value| value.as_str().to_owned()))
}

fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            matches!(index, 8 | 13 | 18 | 23)
                .then_some(byte == b'-')
                .unwrap_or(byte.is_ascii_hexdigit())
        })
}

fn is_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}
