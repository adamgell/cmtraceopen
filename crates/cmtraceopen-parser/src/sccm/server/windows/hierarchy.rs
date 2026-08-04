//! Evidence-bound SCCM hierarchy and replication analysis.
//!
//! The extractor consumes already framed CCM logical records. The committed
//! corpus is synthetic and selects one closed test profile; this module makes
//! no native Windows or live ConfigMgr validation claim.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::models::log_entry::Severity;
use crate::sccm::keys::SCCM_HIERARCHY_KEY_PROFILE_ID;
use crate::sccm::{
    extract_keys, SccmArtifactFamily, SccmArtifactRequest, SccmConfidence, SccmCorrelationKey,
    SccmCorrelationKeyKind, SccmCoverageState, SccmEvidenceRef, SccmExtractionProfile, SccmFinding,
    SccmFindingBuilder, SccmFindingClass, SccmFindingCoverageGap, SccmPhase, SccmRole,
    SccmRotation, SccmTerminalEvidence, SccmTimeOrderingState, SccmTimestamp,
};

use super::intake::{
    SccmServerArtifactAssessment, SccmServerHierarchyLinkTopology, SccmServerIntakeAssessment,
};

const PUBLIC_MESSAGE_PREFIX: &str = "[sccm-public-message-v1] ";
const FIXTURE_MARKER: &str = "SYNTHETIC FIXTURE";
pub const SCCM_HIERARCHY_PROFILE_ID: &str = SCCM_HIERARCHY_KEY_PROFILE_ID;
pub const SCCM_HIERARCHY_SOURCE_VERSION: &str = "5.00.TEST";
pub const SCCM_HIERARCHY_PROFILE_VERSION: u32 = 1;

// Exact raw-payload registry for the synthetic profile. A caller can invoke
// canonical intake, but cannot turn arbitrary CCM text into reviewed hierarchy
// facts by reusing one of the public fixture artifact IDs.
const SYNTHETIC_PROFILE_PAYLOADS: &[(&str, &str)] = &[
    (
        "absent-01-sender",
        "e2b8000d9c61a1d8cc8fc5adf67aa09ef18c0ac83aa6c2be82bb31ab96cf7d43",
    ),
    (
        "backlog-01-replmgr",
        "5076cad377b0161380e205b6da68743f77d9cca3b1ce38be518283f7a9b6b4a3",
    ),
    (
        "clock-01-sender",
        "0d0f5f0e21da23617b45afeb469cd315bd250c19d61e98ceda4d8982d9b1e8c7",
    ),
    (
        "clock-02-despool",
        "e6f19320c96b7939a25124bb8bfaa3699e9762c08e6a2f7c86d0290cd98c24a1",
    ),
    (
        "generic-01-sender",
        "1e16a6a63b19610c91ea714fa74d82328b5d1e64f5d680d43842312c19722530",
    ),
    (
        "healthy-01-replmgr",
        "46c5657073e106c6543283d2374dd4c16a4018288a27b2fca4f5581bd7dd0a94",
    ),
    (
        "healthy-01-replmgr",
        "8dfae54db00614bd99b39b77dc7d6fed838be518bc2e7c44045057382303734d",
    ),
    (
        "healthy-01-replmgr",
        "03b983e6f7282d3c919e46cc44e721521c41f0b32bf7ffd5559d9c95374f954a",
    ),
    (
        "healthy-02-sender",
        "7147bd84db5386ecb685519a9393b26ddd1280ce179ff3bf5acac8c05f9e004a",
    ),
    (
        "healthy-02-sender",
        "60755b460ccc3bd4c77ad30c8bf8b3e0c72091c7e9e05da8061e79c4e1799687",
    ),
    (
        "healthy-03-despool",
        "6fecb3909732f086f2cd3ec0244a345373f6754e5e53e948a20c414ece8a6d49",
    ),
    (
        "healthy-04-rcmctrl",
        "12b3a0d0210606312c744e38d34f54c4f4210b8e1def4acab85fbaf05cb023c7",
    ),
    (
        "incomplete-01-replmgr",
        "179bf0e10615d0ffa0a5ec72748e79d6b8ec86e26d285d75b33592c91fbde25e",
    ),
    (
        "mismatch-01-sender",
        "6f0813d7bf0309401adaac19ac96fe4b674ab8491d3dc5f581f529c9fa108dcd",
    ),
    (
        "mismatch-02-despool",
        "8d08a41bc7d735ecbaae4c8dc18285f1a77b65e30fb3903fa3e83b4d7be40a8b",
    ),
    (
        "receiver-01-sender",
        "efa57e6e8b95133d4fa1be54998eec8959e4c85ad0a28221adff44d93e48ff9f",
    ),
    (
        "receiver-02-despool",
        "34ae490e3409e3f3f3c63257a6d72c60e73e05383b8dbdec7747856ae514bc83",
    ),
    (
        "recovery-01-sender",
        "9ae1d3697976dfe61cf7aa3638086d91602b7f28ed41f1af4a6edc0e31b2652b",
    ),
    (
        "recovery-02-despool",
        "c391334f761c4acb88c0dfb21edaa870ba9d8da51d315dfbc948e337fb71b2a2",
    ),
    (
        "rotation-01-current",
        "b678f0249923f82c2fdbd3e532209c45aa81921bdbf542ba655056bb5f102705",
    ),
    (
        "rotation-02-lo",
        "550fdcc7fae3b2f9f8586676cd964e21f265e0bc766d26c455bf816ba52221ab",
    ),
    (
        "sender-failure-01-chd",
        "52f2b9609a19a966680e063994d2656fd93a89929e5d6a6f46978c9cfd0ddb08",
    ),
    (
        "sender-failure-01-chd",
        "2b47b825171f2acf95895adb206f79ec65afb4c1126a535866127a1b907ba990",
    ),
];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmHierarchyDirection {
    Origin,
    Target,
    Both,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmHierarchyCoverage {
    pub artifact_id: String,
    pub source_id: String,
    pub producer_role: SccmRole,
    pub producer_host_handle: String,
    pub state: SccmCoverageState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmHierarchyPhase {
    Initiate,
    QueueOrSerialize,
    Send,
    Receive,
    Process,
    Acknowledge,
    HealthyOrTerminal,
}

impl SccmHierarchyPhase {
    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "initiate" => Self::Initiate,
            "queueOrSerialize" => Self::QueueOrSerialize,
            "send" => Self::Send,
            "receive" => Self::Receive,
            "process" => Self::Process,
            "acknowledge" => Self::Acknowledge,
            "healthyOrTerminal" => Self::HealthyOrTerminal,
            _ => return None,
        })
    }

    fn rank(&self) -> usize {
        match self {
            Self::Initiate => 0,
            Self::QueueOrSerialize => 1,
            Self::Send => 2,
            Self::Receive => 3,
            Self::Process => 4,
            Self::Acknowledge => 5,
            Self::HealthyOrTerminal => 6,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmHierarchyDisposition {
    Succeeded,
    Failed,
    Retrying,
}

impl SccmHierarchyDisposition {
    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "succeeded" => Self::Succeeded,
            "failed" => Self::Failed,
            "retrying" => Self::Retrying,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmHierarchyObservation {
    pub observation_id: String,
    pub phase: SccmHierarchyPhase,
    pub disposition: SccmHierarchyDisposition,
    pub terminal: bool,
    pub evidence: Vec<SccmEvidenceRef>,
    #[serde(skip)]
    pub timestamp: SccmTimestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmHierarchyKey {
    pub message_id: String,
    pub link_id: String,
    pub origin_site_code: String,
    pub target_site_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmHierarchyTopologyCompatibility {
    Exact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmHierarchyTimestampOrdering {
    Usable,
    UnusableInvalidOffset,
    UnusableMissingOffset,
    UnusableMissingTimestamp,
    Contradictory,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmHierarchyState {
    Succeeded,
    Failed,
    Deferred,
    Recovered,
    Incomplete,
    Contradictory,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmHierarchyRemoteCausality {
    EvidenceBound,
    NotEstablished,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmHierarchyArtifactRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
    pub source_id: String,
    pub producer_role: SccmRole,
    pub direction: SccmHierarchyDirection,
    pub origin_site_code: String,
    pub target_site_code: String,
    pub basenames: Vec<String>,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmHierarchyTransaction {
    pub transaction_id: String,
    pub key: SccmHierarchyKey,
    pub correlation_keys: Vec<SccmCorrelationKey>,
    pub topology_compatibility: SccmHierarchyTopologyCompatibility,
    pub timestamp_ordering: SccmHierarchyTimestampOrdering,
    pub terminal_evidence: bool,
    pub state: SccmHierarchyState,
    pub finding_class: Option<SccmFindingClass>,
    pub confidence: SccmConfidence,
    pub confidence_ceiling: SccmConfidence,
    pub producer_role: SccmRole,
    pub source_version: String,
    pub origin_host_handle: String,
    pub target_host_handle: Option<String>,
    pub last_successful_phase: Option<SccmHierarchyPhase>,
    pub remote_causality: SccmHierarchyRemoteCausality,
    pub correlation_eligible: bool,
    pub coverage_gap_artifact_ids: Vec<String>,
    pub next_artifacts: Vec<SccmHierarchyArtifactRequest>,
    pub observations: Vec<SccmHierarchyObservation>,
    pub evidence: Vec<SccmEvidenceRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmHierarchyProfileSelectionState {
    SelectedSynthetic,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmHierarchyExtractionProfile {
    pub selection_state: SccmHierarchyProfileSelectionState,
    pub profile_id: Option<String>,
    pub profile_version: u32,
    pub source_version: Option<String>,
    pub validated_role: Option<SccmRole>,
    pub synthetic_fixture_only: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmHierarchySourceLocalObservation {
    pub observation_id: String,
    pub finding_class: SccmFindingClass,
    pub confidence: SccmConfidence,
    pub correlation_eligible: bool,
    pub artifact_ids: Vec<String>,
    pub evidence: Vec<SccmEvidenceRef>,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmHierarchyAnalysis {
    pub workflow: String,
    pub state_chain: Vec<SccmHierarchyPhase>,
    pub extraction_profile: SccmHierarchyExtractionProfile,
    pub transactions: Vec<SccmHierarchyTransaction>,
    pub coverage: Vec<SccmHierarchyCoverage>,
    pub source_local_observations: Vec<SccmHierarchySourceLocalObservation>,
    pub artifact_requests: Vec<SccmHierarchyArtifactRequest>,
    pub findings: Vec<SccmFinding>,
    pub cross_side_causal_claims: Vec<String>,
    pub native_validation_performed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SccmHierarchyError {
    UntrustedIntake,
    InvalidFindingContract,
}

pub fn analyze_hierarchy_replication(
    intake: &SccmServerIntakeAssessment,
) -> Result<SccmHierarchyAnalysis, SccmHierarchyError> {
    if !intake.adapter_authority_is_intake_bound() {
        return Err(SccmHierarchyError::UntrustedIntake);
    }
    let mut artifacts = intake
        .artifacts
        .iter()
        .filter(|artifact| artifact.family == SccmArtifactFamily::Hierarchy)
        .collect::<Vec<_>>();
    artifacts.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
    let profile_selected = !artifacts.is_empty()
        && !intake.topology.hierarchy_links.is_empty()
        && artifacts.iter().all(|artifact| {
            artifact.producer_role == SccmRole::SiteServer
                && artifact.profile_eligible
                && artifact.source_version.as_deref() == Some(SCCM_HIERARCHY_SOURCE_VERSION)
                && (!matches!(
                    artifact.state,
                    SccmCoverageState::Captured
                        | SccmCoverageState::Capped
                        | SccmCoverageState::ParseFailed
                ) || registered_profile_provenance(artifact))
        });
    let mut coverage = Vec::new();
    let mut source_local_observations = Vec::new();
    let mut grouped = BTreeMap::<String, Candidate>::new();

    for artifact in &artifacts {
        let state = artifact.state.clone();
        coverage.push(SccmHierarchyCoverage {
            artifact_id: artifact.artifact_id.clone(),
            source_id: artifact.source_id.clone(),
            producer_role: artifact.producer_role.clone(),
            producer_host_handle: artifact.producer_host_handle.clone().unwrap_or_default(),
            state,
        });

        if !profile_selected
            || artifact.state != SccmCoverageState::Captured
            || !sealed_profile_artifact(artifact)
        {
            if artifact.state == SccmCoverageState::Captured || !profile_selected {
                source_local_observations.push(source_local(
                    artifact,
                    "unvalidatedProfile",
                    Vec::new(),
                ));
            } else if matches!(
                artifact.state,
                SccmCoverageState::Capped | SccmCoverageState::ParseFailed
            ) {
                source_local_observations.push(source_local(artifact, "coverageOnly", Vec::new()));
            }
            continue;
        }

        let profile = SccmExtractionProfile::for_artifact_family(
            artifact.source_version.as_deref(),
            &artifact.family,
        );
        for evidence in intake
            .evidence
            .iter()
            .filter(|evidence| evidence.reference.artifact_id == artifact.artifact_id)
        {
            let Some(parsed) = parse_public_record(&evidence.message) else {
                if looks_like_hierarchy_record(&evidence.message) {
                    source_local_observations.push(source_local(
                        artifact,
                        "topologyOrGrammarMismatch",
                        vec![evidence.reference.clone()],
                    ));
                }
                continue;
            };
            let extracted = extract_keys(evidence, &profile);
            if !extracted.gaps.is_empty()
                || !extracted_keys_match_record(&extracted.keys, &parsed)
                || parsed.profile_id.as_deref().is_some_and(|profile_id| {
                    profile_id != "hierarchy-server-5.00.test-v1"
                        && profile_id != SCCM_HIERARCHY_PROFILE_ID
                })
                || !exact_message_id(&parsed.message_id)
                || !exact_link_id(&parsed.link_id)
                || !exact_site_code(&parsed.origin_site)
                || !exact_site_code(&parsed.target_site)
                || !record_topology_matches(intake, artifact, &parsed)
                || !phase_owned(artifact, &parsed.phase)
            {
                source_local_observations.push(source_local(
                    artifact,
                    "topologyOrGrammarMismatch",
                    vec![evidence.reference.clone()],
                ));
                continue;
            }

            let key = SccmHierarchyKey {
                message_id: parsed.message_id,
                link_id: parsed.link_id,
                origin_site_code: parsed.origin_site,
                target_site_code: parsed.target_site,
            };
            let group_key = transaction_id(&key);
            let candidate = grouped.entry(group_key).or_insert_with(|| Candidate {
                key,
                correlation_keys: Vec::new(),
                observations: Vec::new(),
                evidence: Vec::new(),
                directions: BTreeSet::new(),
            });
            candidate
                .directions
                .insert(artifact_direction(artifact).expect("sealed hierarchy source"));
            candidate.correlation_keys.extend(extracted.keys);
            let reference = evidence.reference.clone();
            candidate.observations.push(SccmHierarchyObservation {
                observation_id: observation_id(
                    &reference,
                    &parsed.phase,
                    &parsed.disposition,
                    parsed.terminal,
                ),
                phase: parsed.phase,
                disposition: parsed.disposition,
                terminal: parsed.terminal,
                evidence: vec![reference.clone()],
                timestamp: evidence.timestamp.clone(),
            });
            candidate.evidence.push(reference);
        }
    }

    coverage.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
    let (rotation_observations, rotation_requests) = rotation_split_outputs(intake, &artifacts);
    let rotation_artifact_ids = rotation_observations
        .iter()
        .flat_map(|observation| observation.artifact_ids.iter())
        .collect::<BTreeSet<_>>();
    source_local_observations.retain(|observation| {
        !observation
            .artifact_ids
            .iter()
            .any(|artifact_id| rotation_artifact_ids.contains(artifact_id))
    });
    source_local_observations.extend(rotation_observations);
    let mut artifact_requests = coverage_requests(intake, &artifacts);
    artifact_requests.retain(|request| {
        !rotation_requests.iter().any(|rotation| {
            request.source_id == rotation.source_id
                && request.direction == rotation.direction
                && request.target_site_code == rotation.target_site_code
                && request
                    .basenames
                    .iter()
                    .all(|basename| rotation.basenames.contains(basename))
        })
    });
    artifact_requests.extend(rotation_requests);
    artifact_requests.sort_by(request_order);
    artifact_requests.dedup_by(|left, right| request_order(left, right).is_eq());

    let mut transactions = grouped
        .into_values()
        .filter_map(|mut candidate| {
            candidate.observations.sort_by(observation_order);
            candidate.evidence.sort_by(evidence_order);
            candidate.evidence.dedup();
            candidate.correlation_keys.sort_by(correlation_key_order);
            candidate.correlation_keys.dedup();
            let ordering = timestamp_ordering(&candidate.observations);
            let contradictory = ordering == SccmHierarchyTimestampOrdering::Contradictory
                || has_contradiction(&candidate.observations);
            let terminal_failure = candidate.observations.iter().any(|observation| {
                observation.terminal && observation.disposition == SccmHierarchyDisposition::Failed
            });
            let retrying = candidate
                .observations
                .iter()
                .any(|observation| observation.disposition == SccmHierarchyDisposition::Retrying);
            let terminal_success = candidate.observations.iter().any(|observation| {
                observation.terminal
                    && observation.disposition == SccmHierarchyDisposition::Succeeded
            });
            let gaps = missing_required_artifacts(intake, &artifacts, &candidate.key);
            if candidate.observations.len() == 1
                && !terminal_failure
                && !terminal_success
                && !retrying
                && gaps.is_empty()
            {
                let observation = &candidate.observations[0];
                source_local_observations.push(SccmHierarchySourceLocalObservation {
                    observation_id: format!("{}-unlinked", observation.observation_id),
                    finding_class: SccmFindingClass::InsufficientEvidence,
                    confidence: SccmConfidence::Low,
                    correlation_eligible: false,
                    artifact_ids: vec![observation_artifact_id(observation).to_owned()],
                    evidence: candidate.evidence,
                    reason_code: "unlinkedTopologyCandidate".to_owned(),
                });
                return None;
            }
            let unusable_time = ordering != SccmHierarchyTimestampOrdering::Usable;
            let (state, finding_class) = if contradictory {
                (
                    SccmHierarchyState::Contradictory,
                    Some(SccmFindingClass::Symptom),
                )
            } else if unusable_time || !gaps.is_empty() {
                (
                    SccmHierarchyState::Incomplete,
                    Some(SccmFindingClass::InsufficientEvidence),
                )
            } else if terminal_failure {
                (
                    SccmHierarchyState::Failed,
                    Some(SccmFindingClass::ConfirmedFailure),
                )
            } else if terminal_success && retrying {
                (SccmHierarchyState::Recovered, None)
            } else if terminal_success {
                (SccmHierarchyState::Succeeded, None)
            } else if retrying {
                (
                    SccmHierarchyState::Deferred,
                    Some(SccmFindingClass::BlockedOrDeferred),
                )
            } else {
                (
                    SccmHierarchyState::Incomplete,
                    Some(SccmFindingClass::InsufficientEvidence),
                )
            };
            let confidence = match state {
                SccmHierarchyState::Succeeded
                | SccmHierarchyState::Failed
                | SccmHierarchyState::Recovered => SccmConfidence::High,
                SccmHierarchyState::Deferred => SccmConfidence::Moderate,
                SccmHierarchyState::Incomplete | SccmHierarchyState::Contradictory => {
                    SccmConfidence::Low
                }
            };
            let transaction_id = transaction_id(&candidate.key);
            let last_successful_phase = candidate
                .observations
                .iter()
                .filter(|observation| {
                    observation.disposition == SccmHierarchyDisposition::Succeeded
                })
                .max_by_key(|observation| observation.phase.rank())
                .map(|observation| observation.phase.clone());
            let remote_causality = if candidate.directions.len() == 2
                && ordering == SccmHierarchyTimestampOrdering::Usable
                && gaps.is_empty()
                && !contradictory
            {
                SccmHierarchyRemoteCausality::EvidenceBound
            } else {
                SccmHierarchyRemoteCausality::NotEstablished
            };
            let next_artifacts = artifact_requests
                .iter()
                .filter(|request| {
                    request.origin_site_code == candidate.key.origin_site_code
                        && request.target_site_code == candidate.key.target_site_code
                })
                .map(|request| {
                    let mut request = request.clone();
                    request.transaction_id = Some(transaction_id.clone());
                    request
                })
                .collect::<Vec<_>>();
            let topology = topology_link(intake, &candidate.key)?;
            let target_host_handle = Some(topology.target_host_handle.clone());
            let correlation_eligible = matches!(
                state,
                SccmHierarchyState::Succeeded
                    | SccmHierarchyState::Failed
                    | SccmHierarchyState::Recovered
            ) && remote_causality
                == SccmHierarchyRemoteCausality::EvidenceBound;
            Some(SccmHierarchyTransaction {
                transaction_id,
                key: candidate.key,
                correlation_keys: candidate.correlation_keys,
                topology_compatibility: SccmHierarchyTopologyCompatibility::Exact,
                timestamp_ordering: ordering,
                terminal_evidence: candidate
                    .observations
                    .iter()
                    .any(|observation| observation.terminal),
                state,
                finding_class,
                confidence,
                confidence_ceiling: confidence,
                producer_role: SccmRole::SiteServer,
                source_version: SCCM_HIERARCHY_SOURCE_VERSION.to_owned(),
                origin_host_handle: topology.origin_host_handle.clone(),
                target_host_handle,
                last_successful_phase,
                remote_causality,
                correlation_eligible,
                coverage_gap_artifact_ids: gaps,
                next_artifacts,
                observations: candidate.observations,
                evidence: candidate.evidence,
            })
        })
        .collect::<Vec<_>>();
    transactions.sort_by(|left, right| left.transaction_id.cmp(&right.transaction_id));
    for transaction in &mut transactions {
        if transaction.timestamp_ordering == SccmHierarchyTimestampOrdering::Usable {
            continue;
        }
        let mut requests = invalid_time_requests(intake, transaction);
        transaction.next_artifacts.extend(requests.iter().cloned());
        transaction.next_artifacts.sort_by(request_order);
        transaction
            .next_artifacts
            .dedup_by(|left, right| request_order(left, right).is_eq());
        artifact_requests.append(&mut requests);
    }
    let transaction_scopes = transactions
        .iter()
        .map(|transaction| {
            (
                transaction.key.origin_site_code.clone(),
                transaction.key.target_site_code.clone(),
            )
        })
        .collect::<BTreeSet<_>>();
    artifact_requests.retain(|request| {
        request.transaction_id.is_some()
            || !transaction_scopes.contains(&(
                request.origin_site_code.clone(),
                request.target_site_code.clone(),
            ))
    });
    artifact_requests.extend(
        transactions
            .iter()
            .flat_map(|transaction| transaction.next_artifacts.iter().cloned()),
    );
    artifact_requests.sort_by(request_order);
    artifact_requests.dedup_by(|left, right| request_order(left, right).is_eq());
    source_local_observations.sort_by(|left, right| left.observation_id.cmp(&right.observation_id));
    let findings = transactions
        .iter()
        .map(|transaction| build_finding(transaction, &coverage))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect();

    Ok(SccmHierarchyAnalysis {
        workflow: "hierarchyAndReplication".to_owned(),
        state_chain: state_chain(),
        extraction_profile: SccmHierarchyExtractionProfile {
            selection_state: if profile_selected {
                SccmHierarchyProfileSelectionState::SelectedSynthetic
            } else {
                SccmHierarchyProfileSelectionState::Unavailable
            },
            profile_id: profile_selected.then(|| SCCM_HIERARCHY_PROFILE_ID.to_owned()),
            profile_version: SCCM_HIERARCHY_PROFILE_VERSION,
            source_version: profile_selected.then(|| SCCM_HIERARCHY_SOURCE_VERSION.to_owned()),
            validated_role: profile_selected.then_some(SccmRole::SiteServer),
            synthetic_fixture_only: true,
        },
        transactions,
        coverage,
        source_local_observations,
        artifact_requests,
        findings,
        cross_side_causal_claims: Vec::new(),
        native_validation_performed: false,
    })
}

fn state_chain() -> Vec<SccmHierarchyPhase> {
    vec![
        SccmHierarchyPhase::Initiate,
        SccmHierarchyPhase::QueueOrSerialize,
        SccmHierarchyPhase::Send,
        SccmHierarchyPhase::Receive,
        SccmHierarchyPhase::Process,
        SccmHierarchyPhase::Acknowledge,
        SccmHierarchyPhase::HealthyOrTerminal,
    ]
}

struct Candidate {
    key: SccmHierarchyKey,
    correlation_keys: Vec<SccmCorrelationKey>,
    observations: Vec<SccmHierarchyObservation>,
    evidence: Vec<SccmEvidenceRef>,
    directions: BTreeSet<SccmHierarchyDirection>,
}

struct ParsedRecord {
    phase: SccmHierarchyPhase,
    disposition: SccmHierarchyDisposition,
    terminal: bool,
    message_id: String,
    link_id: String,
    origin_site: String,
    target_site: String,
    profile_id: Option<String>,
}

fn topology_link<'a>(
    intake: &'a SccmServerIntakeAssessment,
    key: &SccmHierarchyKey,
) -> Option<&'a SccmServerHierarchyLinkTopology> {
    intake.topology.hierarchy_links.iter().find(|link| {
        link.origin_site_code == key.origin_site_code
            && link.target_site_code == key.target_site_code
            && link.origin_host_handle != link.target_host_handle
    })
}

fn record_topology_matches(
    intake: &SccmServerIntakeAssessment,
    artifact: &SccmServerArtifactAssessment,
    parsed: &ParsedRecord,
) -> bool {
    let key = SccmHierarchyKey {
        message_id: parsed.message_id.clone(),
        link_id: parsed.link_id.clone(),
        origin_site_code: parsed.origin_site.clone(),
        target_site_code: parsed.target_site.clone(),
    };
    let Some(link) = topology_link(intake, &key) else {
        return false;
    };
    match artifact_direction(artifact) {
        Some(SccmHierarchyDirection::Origin) => {
            artifact.producer_host_handle.as_deref() == Some(link.origin_host_handle.as_str())
        }
        Some(SccmHierarchyDirection::Target) => {
            artifact.producer_host_handle.as_deref() == Some(link.target_host_handle.as_str())
        }
        Some(SccmHierarchyDirection::Both) | None => false,
    }
}

fn sealed_profile_artifact(artifact: &SccmServerArtifactAssessment) -> bool {
    artifact.state == SccmCoverageState::Captured
        && artifact.parser_eligible
        && registered_profile_provenance(artifact)
        && declared_source(artifact)
}

fn registered_profile_provenance(artifact: &SccmServerArtifactAssessment) -> bool {
    let provenance_ok = artifact
        .capture_provenance
        .as_ref()
        .is_some_and(|provenance| {
            provenance.schema_version == 1
                && provenance.encoding == "utf-8"
                && provenance.byte_limit > 0
                && provenance.limit_applied == (artifact.state == SccmCoverageState::Capped)
        });
    artifact.profile_eligible
        && artifact.source_version.as_deref() == Some(SCCM_HIERARCHY_SOURCE_VERSION)
        && artifact.content_sha256.as_deref().is_some_and(|digest| {
            SYNTHETIC_PROFILE_PAYLOADS
                .iter()
                .any(|(artifact_id, expected)| {
                    *artifact_id == artifact.artifact_id && *expected == digest
                })
        })
        && provenance_ok
        && chrono::DateTime::parse_from_rfc3339(&artifact.collected_at_utc).is_ok()
        && !artifact.rotation_lineage_handle.is_empty()
}

fn artifact_direction(artifact: &SccmServerArtifactAssessment) -> Option<SccmHierarchyDirection> {
    match artifact.original_basename.as_deref()? {
        "replmgr.log" | "sender.log" | "sender.lo_" => Some(SccmHierarchyDirection::Origin),
        "despool.log" | "rcmctrl.log" => Some(SccmHierarchyDirection::Target),
        _ => None,
    }
}

fn declared_source(artifact: &SccmServerArtifactAssessment) -> bool {
    artifact.producer_role == SccmRole::SiteServer
        && matches!(
            (
                artifact.source_id.as_str(),
                artifact.original_basename.as_deref(),
                artifact_direction(artifact)
            ),
            (
                "server-hierarchy-control",
                Some("replmgr.log"),
                Some(SccmHierarchyDirection::Origin)
            ) | (
                "server-hierarchy-control",
                Some("rcmctrl.log"),
                Some(SccmHierarchyDirection::Target)
            ) | (
                "server-hierarchy-transfer",
                Some("sender.log"),
                Some(SccmHierarchyDirection::Origin)
            ) | (
                "server-hierarchy-transfer",
                Some("sender.lo_"),
                Some(SccmHierarchyDirection::Origin)
            ) | (
                "server-hierarchy-transfer",
                Some("despool.log"),
                Some(SccmHierarchyDirection::Target)
            )
        )
}

fn phase_owned(artifact: &SccmServerArtifactAssessment, phase: &SccmHierarchyPhase) -> bool {
    matches!(
        (artifact.original_basename.as_deref(), phase),
        (
            Some("replmgr.log"),
            SccmHierarchyPhase::Initiate | SccmHierarchyPhase::QueueOrSerialize
        ) | (Some("sender.log" | "sender.lo_"), SccmHierarchyPhase::Send)
            | (
                Some("despool.log"),
                SccmHierarchyPhase::Receive
                    | SccmHierarchyPhase::Process
                    | SccmHierarchyPhase::HealthyOrTerminal
            )
            | (
                Some("rcmctrl.log"),
                SccmHierarchyPhase::Acknowledge | SccmHierarchyPhase::HealthyOrTerminal
            )
    )
}

fn extracted_keys_match_record(keys: &[SccmCorrelationKey], parsed: &ParsedRecord) -> bool {
    let exact = |kind: SccmCorrelationKeyKind, value: &str| {
        keys.iter().filter(|key| key.kind == kind).count() == 1
            && keys.iter().any(|key| {
                key.kind == kind
                    && key.normalized == value
                    && key.extraction_profile_id.as_deref() == Some(SCCM_HIERARCHY_PROFILE_ID)
            })
    };
    let mut sites = keys
        .iter()
        .filter(|key| key.kind == SccmCorrelationKeyKind::SiteCode)
        .map(|key| key.normalized.as_str())
        .collect::<Vec<_>>();
    sites.sort_unstable();
    let mut expected_sites = vec![parsed.origin_site.as_str(), parsed.target_site.as_str()];
    expected_sites.sort_unstable();
    exact(
        SccmCorrelationKeyKind::HierarchyMessageId,
        &parsed.message_id,
    ) && exact(SccmCorrelationKeyKind::HierarchyLinkId, &parsed.link_id)
        && sites == expected_sites
}

fn parse_public_record(message: &str) -> Option<ParsedRecord> {
    let body = message.strip_prefix(PUBLIC_MESSAGE_PREFIX)?;
    let mut fields = BTreeMap::new();
    let mut segments = body.split(';').map(str::trim);
    let first = segments.next()?;
    let mut pending = Some(first);
    if first == FIXTURE_MARKER {
        pending = None;
    }
    const ALLOWED_FIELDS: &[&str] = &[
        "Phase",
        "Disposition",
        "Terminal",
        "MessageId",
        "LinkId",
        "OriginSite",
        "TargetSite",
        "ProfileId",
    ];
    for segment in pending.into_iter().chain(segments) {
        let (name, value) = segment.split_once('=')?;
        if !ALLOWED_FIELDS.contains(&name)
            || value.is_empty()
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            || fields.insert(name, value).is_some()
        {
            return None;
        }
    }
    let terminal = match *fields.get("Terminal")? {
        "true" => true,
        "false" => false,
        _ => return None,
    };
    let phase = SccmHierarchyPhase::parse(fields.get("Phase")?)?;
    let disposition = SccmHierarchyDisposition::parse(fields.get("Disposition")?)?;
    if (terminal && disposition == SccmHierarchyDisposition::Retrying)
        || (terminal
            && disposition == SccmHierarchyDisposition::Succeeded
            && phase != SccmHierarchyPhase::HealthyOrTerminal)
    {
        return None;
    }
    Some(ParsedRecord {
        phase,
        disposition,
        terminal,
        message_id: (*fields.get("MessageId")?).to_owned(),
        link_id: (*fields.get("LinkId")?).to_owned(),
        origin_site: (*fields.get("OriginSite")?).to_owned(),
        target_site: (*fields.get("TargetSite")?).to_owned(),
        profile_id: fields.get("ProfileId").map(|value| (*value).to_owned()),
    })
}

fn looks_like_hierarchy_record(message: &str) -> bool {
    ["Phase=", "Disposition=", "MessageId=", "LinkId="]
        .iter()
        .any(|label| message.contains(label))
}

fn exact_message_id(value: &str) -> bool {
    exact_hierarchy_id(value, "msg-")
}

fn exact_link_id(value: &str) -> bool {
    exact_hierarchy_id(value, "link-")
}

fn exact_hierarchy_id(value: &str, prefix: &str) -> bool {
    value.len() <= 128
        && value.strip_prefix(prefix).is_some_and(|suffix| {
            !suffix.is_empty()
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
}

fn exact_site_code(value: &str) -> bool {
    value.len() == 3 && value.bytes().all(|byte| byte.is_ascii_uppercase())
}

fn transaction_id(key: &SccmHierarchyKey) -> String {
    format!(
        "hierarchy:{}:{}:{}:{}",
        key.message_id, key.origin_site_code, key.target_site_code, key.link_id
    )
}

fn phase_name(phase: &SccmHierarchyPhase) -> &'static str {
    match phase {
        SccmHierarchyPhase::Initiate => "initiate",
        SccmHierarchyPhase::QueueOrSerialize => "queueOrSerialize",
        SccmHierarchyPhase::Send => "send",
        SccmHierarchyPhase::Receive => "receive",
        SccmHierarchyPhase::Process => "process",
        SccmHierarchyPhase::Acknowledge => "acknowledge",
        SccmHierarchyPhase::HealthyOrTerminal => "healthyOrTerminal",
    }
}

fn observation_id(
    reference: &SccmEvidenceRef,
    phase: &SccmHierarchyPhase,
    disposition: &SccmHierarchyDisposition,
    terminal: bool,
) -> String {
    let suffix = if terminal && *disposition == SccmHierarchyDisposition::Succeeded {
        "terminal"
    } else if *disposition == SccmHierarchyDisposition::Retrying {
        "retry"
    } else if *phase == SccmHierarchyPhase::QueueOrSerialize {
        "queue"
    } else if *disposition == SccmHierarchyDisposition::Failed {
        "failure"
    } else {
        phase_name(phase)
    };
    format!(
        "hierarchy-observation:{}:{}-{}:{suffix}",
        reference.artifact_id,
        reference.line_start.unwrap_or(0),
        reference.line_end.unwrap_or(0)
    )
}

fn observation_artifact_id(observation: &SccmHierarchyObservation) -> &str {
    observation
        .evidence
        .first()
        .map_or("", |reference| reference.artifact_id.as_str())
}

fn observation_line_start(observation: &SccmHierarchyObservation) -> Option<u32> {
    observation
        .evidence
        .first()
        .and_then(|reference| reference.line_start)
}

fn observation_order(
    left: &SccmHierarchyObservation,
    right: &SccmHierarchyObservation,
) -> Ordering {
    left.phase
        .rank()
        .cmp(&right.phase.rank())
        .then_with(|| observation_artifact_id(left).cmp(observation_artifact_id(right)))
        .then_with(|| observation_line_start(left).cmp(&observation_line_start(right)))
        .then_with(|| left.observation_id.cmp(&right.observation_id))
}

fn evidence_order(left: &SccmEvidenceRef, right: &SccmEvidenceRef) -> Ordering {
    left.artifact_id
        .cmp(&right.artifact_id)
        .then_with(|| left.line_start.cmp(&right.line_start))
        .then_with(|| left.line_end.cmp(&right.line_end))
        .then_with(|| left.entry_id.cmp(&right.entry_id))
}

fn timestamp_ordering(observations: &[SccmHierarchyObservation]) -> SccmHierarchyTimestampOrdering {
    for observation in observations {
        match observation.timestamp.ordering_state {
            SccmTimeOrderingState::NormalizedUtc if observation.timestamp.utc_millis.is_some() => {}
            SccmTimeOrderingState::OffsetInvalid => {
                return SccmHierarchyTimestampOrdering::UnusableInvalidOffset
            }
            SccmTimeOrderingState::OffsetMissing => {
                return SccmHierarchyTimestampOrdering::UnusableMissingOffset
            }
            SccmTimeOrderingState::TimestampMissing | SccmTimeOrderingState::NormalizedUtc => {
                return SccmHierarchyTimestampOrdering::UnusableMissingTimestamp
            }
        }
    }
    for (index, left) in observations.iter().enumerate() {
        for right in &observations[index + 1..] {
            if left.phase.rank() >= right.phase.rank() {
                continue;
            }
            let (Some(left_millis), Some(right_millis)) =
                (left.timestamp.utc_millis, right.timestamp.utc_millis)
            else {
                return SccmHierarchyTimestampOrdering::UnusableMissingTimestamp;
            };
            if left_millis > right_millis {
                return SccmHierarchyTimestampOrdering::Contradictory;
            }
            if left_millis == right_millis {
                let same_artifact = observation_artifact_id(left) == observation_artifact_id(right);
                let physical_order = same_artifact
                    && observation_line_start(left)
                        .zip(observation_line_start(right))
                        .is_some_and(|(left_line, right_line)| left_line < right_line);
                if !physical_order {
                    return SccmHierarchyTimestampOrdering::Contradictory;
                }
            }
        }
    }
    SccmHierarchyTimestampOrdering::Usable
}

fn has_contradiction(observations: &[SccmHierarchyObservation]) -> bool {
    observations.iter().enumerate().any(|(index, left)| {
        observations[index + 1..].iter().any(|right| {
            left.phase == right.phase
                && (matches!(
                    (&left.disposition, &right.disposition),
                    (
                        SccmHierarchyDisposition::Succeeded,
                        SccmHierarchyDisposition::Failed
                    ) | (
                        SccmHierarchyDisposition::Failed,
                        SccmHierarchyDisposition::Succeeded
                    )
                ) || (left.disposition == right.disposition && left.terminal != right.terminal))
        })
    })
}

fn missing_required_artifacts(
    intake: &SccmServerIntakeAssessment,
    artifacts: &[&SccmServerArtifactAssessment],
    key: &SccmHierarchyKey,
) -> Vec<String> {
    let Some(link) = topology_link(intake, key) else {
        return Vec::new();
    };
    let mut gaps = artifacts
        .iter()
        .filter(|artifact| artifact.state != SccmCoverageState::Captured)
        .filter(|artifact| {
            let producer = artifact.producer_host_handle.as_deref();
            match artifact_direction(artifact) {
                Some(SccmHierarchyDirection::Origin) => {
                    producer == Some(link.origin_host_handle.as_str())
                }
                Some(SccmHierarchyDirection::Target) => {
                    producer == Some(link.target_host_handle.as_str())
                }
                Some(SccmHierarchyDirection::Both) | None => false,
            }
        })
        .map(|artifact| artifact.artifact_id.clone())
        .collect::<Vec<_>>();
    gaps.sort();
    gaps
}

fn source_local(
    artifact: &SccmServerArtifactAssessment,
    reason_code: &str,
    evidence: Vec<SccmEvidenceRef>,
) -> SccmHierarchySourceLocalObservation {
    let evidence_identity = evidence.first().map_or_else(
        || "no-line".to_owned(),
        |reference| {
            format!(
                "{}-{}",
                reference.line_start.unwrap_or(0),
                reference.line_end.unwrap_or(0)
            )
        },
    );
    SccmHierarchySourceLocalObservation {
        observation_id: format!(
            "hierarchy-source:{}:{evidence_identity}:{reason_code}",
            artifact.artifact_id
        ),
        finding_class: SccmFindingClass::InsufficientEvidence,
        confidence: SccmConfidence::Low,
        correlation_eligible: false,
        artifact_ids: vec![artifact.artifact_id.clone()],
        evidence,
        reason_code: reason_code.to_owned(),
    }
}

fn coverage_requests(
    intake: &SccmServerIntakeAssessment,
    artifacts: &[&SccmServerArtifactAssessment],
) -> Vec<SccmHierarchyArtifactRequest> {
    let mut requests = Vec::new();
    for artifact in artifacts {
        let reason_code = match artifact.state {
            SccmCoverageState::Absent => Some("coverageAbsent"),
            SccmCoverageState::Capped => Some("coverageCapped"),
            SccmCoverageState::AccessDenied => Some("coverageAccessDenied"),
            SccmCoverageState::ParseFailed => Some("coverageParseFailed"),
            _ => None,
        };
        let Some(reason_code) = reason_code else {
            continue;
        };
        let Some((direction, origin_site_code, target_site_code)) =
            exact_artifact_scope(intake, artifact)
        else {
            continue;
        };
        requests.push(SccmHierarchyArtifactRequest {
            transaction_id: None,
            source_id: artifact.source_id.clone(),
            producer_role: artifact.producer_role.clone(),
            direction,
            origin_site_code,
            target_site_code,
            basenames: artifact.original_basename.iter().cloned().collect(),
            reason_code: reason_code.to_owned(),
        });
    }
    requests.sort_by(request_order);
    requests.dedup_by(|left, right| request_order(left, right).is_eq());
    requests
}

fn exact_artifact_scope(
    intake: &SccmServerIntakeAssessment,
    artifact: &SccmServerArtifactAssessment,
) -> Option<(SccmHierarchyDirection, String, String)> {
    let direction = artifact_direction(artifact)?;
    let host = artifact.producer_host_handle.as_deref()?;
    let mut targets = intake
        .topology
        .hierarchy_links
        .iter()
        .filter(|link| match direction {
            SccmHierarchyDirection::Origin => link.origin_host_handle == host,
            SccmHierarchyDirection::Target => link.target_host_handle == host,
            SccmHierarchyDirection::Both => false,
        })
        .map(|link| (link.origin_site_code.clone(), link.target_site_code.clone()))
        .collect::<Vec<_>>();
    targets.sort();
    targets.dedup();
    (targets.len() == 1).then(|| {
        let (origin_site_code, target_site_code) = targets.remove(0);
        (direction, origin_site_code, target_site_code)
    })
}

fn rotation_split_outputs(
    intake: &SccmServerIntakeAssessment,
    artifacts: &[&SccmServerArtifactAssessment],
) -> (
    Vec<SccmHierarchySourceLocalObservation>,
    Vec<SccmHierarchyArtifactRequest>,
) {
    type RotationKey = (
        String,
        String,
        SccmHierarchyDirection,
        String,
        String,
        String,
    );
    let mut groups = BTreeMap::<RotationKey, Vec<&SccmServerArtifactAssessment>>::new();
    for artifact in artifacts {
        if artifact.rotation_lineage_handle.is_empty()
            || !matches!(
                artifact.state,
                SccmCoverageState::Captured
                    | SccmCoverageState::Capped
                    | SccmCoverageState::ParseFailed
            )
        {
            continue;
        }
        let Some((direction, origin_site_code, target_site_code)) =
            exact_artifact_scope(intake, artifact)
        else {
            continue;
        };
        let Some(host) = artifact.producer_host_handle.clone() else {
            continue;
        };
        groups
            .entry((
                artifact.source_id.clone(),
                host,
                direction,
                origin_site_code,
                target_site_code,
                artifact.rotation_lineage_handle.clone(),
            ))
            .or_default()
            .push(artifact);
    }

    let mut observations = Vec::new();
    let mut requests = Vec::new();
    for ((source_id, _, direction, origin_site_code, target_site_code, lineage), mut pair) in groups
    {
        if pair.len() != 2 || !canonical_current_lo_pair(&pair) {
            continue;
        }
        pair.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
        let artifact_ids = pair
            .iter()
            .map(|artifact| artifact.artifact_id.clone())
            .collect::<Vec<_>>();
        let mut basenames = pair
            .iter()
            .filter_map(|artifact| artifact.original_basename.clone())
            .collect::<Vec<_>>();
        basenames.sort();
        observations.push(SccmHierarchySourceLocalObservation {
            observation_id: format!(
                "hierarchy-rotation:{}:{}:{}",
                artifact_ids[0], artifact_ids[1], lineage
            ),
            finding_class: SccmFindingClass::InsufficientEvidence,
            confidence: SccmConfidence::Low,
            correlation_eligible: false,
            artifact_ids,
            evidence: Vec::new(),
            reason_code: "rotationSplit".to_owned(),
        });
        requests.push(SccmHierarchyArtifactRequest {
            transaction_id: None,
            source_id,
            producer_role: SccmRole::SiteServer,
            direction,
            origin_site_code,
            target_site_code,
            basenames,
            reason_code: "coverageRotationSplit".to_owned(),
        });
    }
    (observations, requests)
}

fn invalid_time_requests(
    intake: &SccmServerIntakeAssessment,
    transaction: &SccmHierarchyTransaction,
) -> Vec<SccmHierarchyArtifactRequest> {
    let reason_code = match transaction.timestamp_ordering {
        SccmHierarchyTimestampOrdering::UnusableInvalidOffset
        | SccmHierarchyTimestampOrdering::UnusableMissingOffset
        | SccmHierarchyTimestampOrdering::UnusableMissingTimestamp => "invalidOffset",
        SccmHierarchyTimestampOrdering::Contradictory => "contradictoryOrdering",
        SccmHierarchyTimestampOrdering::Usable => return Vec::new(),
    };
    let mut groups =
        BTreeMap::<String, (BTreeSet<SccmHierarchyDirection>, BTreeSet<String>)>::new();
    for reference in &transaction.evidence {
        let Some(artifact) = intake
            .artifacts
            .iter()
            .find(|artifact| artifact.artifact_id == reference.artifact_id)
        else {
            continue;
        };
        let (Some(direction), Some(basename)) = (
            artifact_direction(artifact),
            artifact.original_basename.as_ref(),
        ) else {
            continue;
        };
        let group = groups.entry(artifact.source_id.clone()).or_default();
        group.0.insert(direction);
        group.1.insert(basename.clone());
    }
    groups
        .into_iter()
        .map(
            |(source_id, (directions, basenames))| SccmHierarchyArtifactRequest {
                transaction_id: Some(transaction.transaction_id.clone()),
                source_id,
                producer_role: SccmRole::SiteServer,
                direction: if directions.len() == 2 {
                    SccmHierarchyDirection::Both
                } else {
                    directions
                        .into_iter()
                        .next()
                        .unwrap_or(SccmHierarchyDirection::Origin)
                },
                origin_site_code: transaction.key.origin_site_code.clone(),
                target_site_code: transaction.key.target_site_code.clone(),
                basenames: basenames.into_iter().collect(),
                reason_code: reason_code.to_owned(),
            },
        )
        .collect()
}

fn canonical_current_lo_pair(pair: &[&SccmServerArtifactAssessment]) -> bool {
    let current = pair
        .iter()
        .filter(|artifact| artifact.rotation == Some(SccmRotation::Current))
        .count();
    let lo = pair
        .iter()
        .filter(|artifact| artifact.rotation == Some(SccmRotation::LoUnderscore))
        .count();
    current == 1
        && lo == 1
        && pair.iter().all(|artifact| {
            artifact.source_id == pair[0].source_id
                && artifact.producer_role == pair[0].producer_role
                && artifact.producer_host_handle == pair[0].producer_host_handle
                && artifact.rotation_lineage_handle == pair[0].rotation_lineage_handle
        })
}

fn build_finding(
    transaction: &SccmHierarchyTransaction,
    coverage: &[SccmHierarchyCoverage],
) -> Result<Option<SccmFinding>, SccmHierarchyError> {
    let Some(mut class) = transaction.finding_class.clone() else {
        return Ok(None);
    };
    let coverage_gaps = transaction
        .coverage_gap_artifact_ids
        .iter()
        .filter_map(|artifact_id| {
            coverage
                .iter()
                .find(|coverage| &coverage.artifact_id == artifact_id)
                .map(|coverage| SccmFindingCoverageGap {
                    artifact_id: artifact_id.clone(),
                    role: SccmRole::SiteServer,
                    coverage: coverage.state.clone(),
                })
        })
        .collect::<Vec<_>>();
    if class == SccmFindingClass::InsufficientEvidence && coverage_gaps.is_empty() {
        class = SccmFindingClass::Symptom;
    }
    let terminal_evidence = if class == SccmFindingClass::ConfirmedFailure {
        transaction
            .observations
            .iter()
            .filter(|observation| {
                observation.terminal && observation.disposition == SccmHierarchyDisposition::Failed
            })
            .flat_map(|observation| observation.evidence.iter().cloned())
            .map(SccmTerminalEvidence::observed_failure)
            .collect()
    } else {
        Vec::new()
    };
    let next_artifacts = shared_requests(&transaction.next_artifacts);
    let finding = SccmFindingBuilder::new(format!("hierarchy-finding:{}", transaction.transaction_id))
        .class(class)
        .phase(SccmPhase::Unknown(format!(
            "hierarchy{}",
            transaction
                .last_successful_phase
                .as_ref()
                .map(phase_name)
                .unwrap_or("Unconfirmed")
        )))
        .role(SccmRole::SiteServer)
        .severity(if transaction.state == SccmHierarchyState::Failed {
            Severity::Error
        } else {
            Severity::Warning
        })
        .confidence(transaction.confidence)
        .title("Hierarchy replication evidence")
        .summary("The hierarchy outcome is bounded to canonical intake evidence and the selected transaction topology.")
        .evidence(transaction.evidence.clone())
        .terminal_evidence(terminal_evidence)
        .coverage_gaps(coverage_gaps)
        .correlation_keys(transaction.correlation_keys.clone())
        .next_artifacts(next_artifacts)
        .build()
        .map_err(|_| SccmHierarchyError::InvalidFindingContract)?;
    Ok(Some(finding))
}

fn shared_requests(requests: &[SccmHierarchyArtifactRequest]) -> Vec<SccmArtifactRequest> {
    let mut shared = requests
        .iter()
        .flat_map(|request| request.basenames.iter())
        .filter_map(|basename| {
            let logical_id = basename
                .strip_suffix(".log")
                .or_else(|| basename.strip_suffix(".lo_"))?;
            Some(SccmArtifactRequest {
                logical_id: logical_id.to_owned(),
                role: SccmRole::SiteServer,
                reason: format!("Collect the complete {basename} file."),
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

fn correlation_key_order(left: &SccmCorrelationKey, right: &SccmCorrelationKey) -> Ordering {
    hierarchy_key_order(&left.kind)
        .cmp(&hierarchy_key_order(&right.kind))
        .then_with(|| left.normalized.cmp(&right.normalized))
        .then_with(|| {
            left.evidence
                .as_ref()
                .map(|reference| reference.entry_id.as_str())
                .cmp(
                    &right
                        .evidence
                        .as_ref()
                        .map(|reference| reference.entry_id.as_str()),
                )
        })
}

fn hierarchy_key_order(kind: &SccmCorrelationKeyKind) -> u8 {
    match kind {
        SccmCorrelationKeyKind::HierarchyLinkId => 0,
        SccmCorrelationKeyKind::HierarchyMessageId => 1,
        SccmCorrelationKeyKind::SiteCode => 2,
        SccmCorrelationKeyKind::AssignmentId => 3,
        SccmCorrelationKeyKind::PolicyId => 4,
        SccmCorrelationKeyKind::ClientGuid => 5,
        SccmCorrelationKeyKind::PackageId => 6,
        SccmCorrelationKeyKind::ContentId => 7,
        SccmCorrelationKeyKind::ServerHost => 8,
        SccmCorrelationKeyKind::CiId => 9,
        SccmCorrelationKeyKind::UpdateId => 10,
        SccmCorrelationKeyKind::KbId => 11,
        SccmCorrelationKeyKind::BitsJobId => 12,
        SccmCorrelationKeyKind::TaskSequenceExecutionId => 13,
        SccmCorrelationKeyKind::RequestId => 14,
        SccmCorrelationKeyKind::TopicId => 15,
        SccmCorrelationKeyKind::StateMessageId => 16,
        SccmCorrelationKeyKind::InventoryCycleId => 17,
        SccmCorrelationKeyKind::ReportId => 18,
        SccmCorrelationKeyKind::ResourceHandle => 19,
        SccmCorrelationKeyKind::ComplianceCiId => 20,
        SccmCorrelationKeyKind::BaselineId => 21,
        SccmCorrelationKeyKind::ComplianceStateId => 22,
        SccmCorrelationKeyKind::MeteringCycleId => 23,
        SccmCorrelationKeyKind::RuleId => 24,
    }
}

fn request_order(
    left: &SccmHierarchyArtifactRequest,
    right: &SccmHierarchyArtifactRequest,
) -> Ordering {
    (
        left.transaction_id.as_deref(),
        left.source_id.as_str(),
        &left.direction,
        left.origin_site_code.as_str(),
        left.target_site_code.as_str(),
        left.reason_code.as_str(),
        &left.basenames,
    )
        .cmp(&(
            right.transaction_id.as_deref(),
            right.source_id.as_str(),
            &right.direction,
            right.origin_site_code.as_str(),
            right.target_site_code.as_str(),
            right.reason_code.as_str(),
            &right.basenames,
        ))
}
