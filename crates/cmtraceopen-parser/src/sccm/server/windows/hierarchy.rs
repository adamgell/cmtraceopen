//! Evidence-bound SCCM hierarchy and replication analysis.
//!
//! The extractor consumes already framed CCM logical records. The committed
//! corpus is synthetic and selects one closed test profile; this module makes
//! no native Windows or live ConfigMgr validation claim.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::sccm::{
    normalize_ccm_artifact, SccmArtifact, SccmConfidence, SccmCoverageState, SccmEvidenceRef,
    SccmFindingClass, SccmKeyConfidence, SccmRole, SccmTimeOrderingState, SccmTimestamp,
};

const PUBLIC_MESSAGE_PREFIX: &str = "[sccm-public-message-v1] ";
const FIXTURE_MARKER: &str = "SYNTHETIC FIXTURE";
pub const SCCM_HIERARCHY_PROFILE_ID: &str = "hierarchy-server-5.00.test-v1";
pub const SCCM_HIERARCHY_SOURCE_VERSION: &str = "5.00.TEST.0001";
pub const SCCM_HIERARCHY_PROFILE_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmHierarchyTarget {
    pub site_code: String,
    pub host_handle: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmHierarchyTopology {
    pub origin_site_code: String,
    pub target_site_code: String,
    pub origin_host_handle: String,
    pub target_host_handle: String,
    #[serde(default)]
    pub additional_targets: Vec<SccmHierarchyTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmHierarchyDirection {
    Origin,
    Target,
    Both,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmHierarchyArtifact {
    pub artifact: SccmArtifact,
    pub source_id: String,
    pub direction: SccmHierarchyDirection,
    pub producer_host_handle: String,
    pub rotation_lineage_id: String,
    pub fragment_complete: bool,
    #[serde(skip)]
    pub content: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmHierarchyBundle {
    pub profile_id: String,
    pub source_version: String,
    pub topology: SccmHierarchyTopology,
    pub artifacts: Vec<SccmHierarchyArtifact>,
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
    pub confidence: SccmKeyConfidence,
    pub extraction_profile_id: String,
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
    pub source_id: String,
    pub producer_role: SccmRole,
    pub direction: SccmHierarchyDirection,
    pub target_site_code: String,
    pub basenames: Vec<String>,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmHierarchyTransaction {
    pub transaction_id: String,
    pub key: SccmHierarchyKey,
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
    pub cross_side_causal_claims: Vec<String>,
    pub native_validation_performed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SccmHierarchyError {
    InvalidTopology,
}

pub fn analyze_hierarchy_replication(
    bundle: &SccmHierarchyBundle,
) -> Result<SccmHierarchyAnalysis, SccmHierarchyError> {
    validate_topology(&bundle.topology)?;
    let profile_selected = bundle.profile_id == SCCM_HIERARCHY_PROFILE_ID
        && bundle.source_version == SCCM_HIERARCHY_SOURCE_VERSION
        && bundle.artifacts.iter().all(|artifact| {
            artifact.artifact.configmgr_version.as_deref() == Some(SCCM_HIERARCHY_SOURCE_VERSION)
        });
    let mut coverage = Vec::new();
    let mut source_local_observations = Vec::new();
    let mut grouped = BTreeMap::<String, Candidate>::new();
    let mut invalid_time_requests =
        BTreeMap::<String, (BTreeSet<SccmHierarchyDirection>, BTreeSet<String>)>::new();

    let mut artifacts = bundle.artifacts.iter().collect::<Vec<_>>();
    artifacts.sort_by(|left, right| left.artifact.artifact_id.cmp(&right.artifact.artifact_id));
    for artifact in artifacts {
        let topology_ok = artifact_topology_matches(artifact, &bundle.topology);
        let state = artifact.artifact.coverage.clone();
        coverage.push(SccmHierarchyCoverage {
            artifact_id: artifact.artifact.artifact_id.clone(),
            source_id: artifact.source_id.clone(),
            producer_role: artifact.artifact.role.clone(),
            producer_host_handle: artifact.producer_host_handle.clone(),
            state,
        });

        if artifact.artifact.coverage != SccmCoverageState::Captured
            || !topology_ok
            || !profile_selected
            || artifact.artifact.configmgr_version.as_deref() != Some(SCCM_HIERARCHY_SOURCE_VERSION)
            || !artifact.fragment_complete
            || artifact.rotation_lineage_id.trim().is_empty()
            || !declared_source(artifact)
        {
            if !profile_selected
                || artifact.artifact.configmgr_version.as_deref()
                    != Some(SCCM_HIERARCHY_SOURCE_VERSION)
            {
                source_local_observations.push(source_local(
                    artifact,
                    "unvalidatedProfile",
                    Vec::new(),
                ));
            } else if !topology_ok {
                source_local_observations.push(source_local(
                    artifact,
                    "topologyMismatch",
                    Vec::new(),
                ));
            }
            continue;
        }

        let records = normalize_ccm_artifact(artifact.artifact.clone(), &artifact.content);
        for evidence in records {
            let Some(parsed) = parse_public_record(&evidence.message) else {
                continue;
            };
            if parsed
                .profile_id
                .as_deref()
                .is_some_and(|profile_id| profile_id != SCCM_HIERARCHY_PROFILE_ID)
                || !exact_message_id(&parsed.message_id)
                || !exact_link_id(&parsed.link_id)
                || !exact_site_code(&parsed.origin_site)
                || !exact_site_code(&parsed.target_site)
                || parsed.origin_site != bundle.topology.origin_site_code
                || target_host_for(&bundle.topology, &parsed.target_site).is_none()
                || !record_topology_matches(artifact, &parsed, &bundle.topology)
                || !phase_owned(artifact, &parsed.phase)
            {
                source_local_observations.push(source_local(
                    artifact,
                    "topologyOrGrammarMismatch",
                    vec![evidence.reference],
                ));
                continue;
            }

            let key = SccmHierarchyKey {
                message_id: parsed.message_id,
                link_id: parsed.link_id,
                origin_site_code: parsed.origin_site,
                target_site_code: parsed.target_site,
                confidence: SccmKeyConfidence::Exact,
                extraction_profile_id: SCCM_HIERARCHY_PROFILE_ID.to_owned(),
            };
            let group_key = transaction_id(&key);
            if evidence.timestamp.ordering_state != SccmTimeOrderingState::NormalizedUtc
                || evidence.timestamp.utc_millis.is_none()
            {
                let request = invalid_time_requests
                    .entry(key.target_site_code.clone())
                    .or_default();
                request.0.insert(artifact.direction.clone());
                request.1.insert(artifact.artifact.display_name.clone());
            }
            let candidate = grouped.entry(group_key).or_insert_with(|| Candidate {
                key,
                observations: Vec::new(),
                evidence: Vec::new(),
                directions: BTreeSet::new(),
            });
            candidate.directions.insert(artifact.direction.clone());
            let reference = evidence.reference;
            candidate.observations.push(SccmHierarchyObservation {
                observation_id: observation_id(
                    &reference.artifact_id,
                    &parsed.phase,
                    &parsed.disposition,
                    parsed.terminal,
                ),
                phase: parsed.phase,
                disposition: parsed.disposition,
                terminal: parsed.terminal,
                evidence: vec![reference.clone()],
                timestamp: evidence.timestamp,
            });
            candidate.evidence.push(reference);
        }
    }

    coverage.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
    source_local_observations.extend(fragment_observations(&bundle.artifacts));
    let mut artifact_requests = artifact_requests(bundle, &coverage);
    artifact_requests.extend(invalid_time_requests.into_iter().map(
        |(target_site_code, (directions, basenames))| SccmHierarchyArtifactRequest {
            source_id: "server-hierarchy-transfer".to_owned(),
            producer_role: SccmRole::SiteServer,
            direction: if directions.len() == 2 {
                SccmHierarchyDirection::Both
            } else {
                directions
                    .into_iter()
                    .next()
                    .unwrap_or(SccmHierarchyDirection::Origin)
            },
            target_site_code,
            basenames: basenames.into_iter().collect(),
            reason_code: "invalidOffset".to_owned(),
        },
    ));
    artifact_requests.sort_by(request_order);
    artifact_requests.dedup_by(|left, right| request_order(left, right).is_eq());

    let mut transactions = grouped
        .into_values()
        .filter_map(|mut candidate| {
            candidate.observations.sort_by(observation_order);
            candidate.evidence.sort_by(evidence_order);
            candidate.evidence.dedup();
            let ordering = timestamp_ordering(&candidate.observations);
            let contradictory = has_contradiction(&candidate.observations);
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
            let gaps = missing_required_artifacts(&coverage, &candidate.observations);
            if candidate.observations.len() == 1
                && !terminal_failure
                && !terminal_success
                && !retrying
                && gaps.is_empty()
            {
                let observation = &candidate.observations[0];
                source_local_observations.push(SccmHierarchySourceLocalObservation {
                    observation_id: format!(
                        "{}-unlinked",
                        artifact_prefix(observation_artifact_id(observation))
                    ),
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
                    Some(SccmFindingClass::InsufficientEvidence),
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
                .filter(|request| request.target_site_code == candidate.key.target_site_code)
                .cloned()
                .collect::<Vec<_>>();
            let target_host_handle =
                target_host_for(&bundle.topology, &candidate.key.target_site_code)
                    .map(str::to_owned);
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
                origin_host_handle: bundle.topology.origin_host_handle.clone(),
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
    source_local_observations.sort_by(|left, right| left.observation_id.cmp(&right.observation_id));

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

fn validate_topology(topology: &SccmHierarchyTopology) -> Result<(), SccmHierarchyError> {
    if !exact_site_code(&topology.origin_site_code)
        || !exact_site_code(&topology.target_site_code)
        || topology.origin_host_handle.is_empty()
        || topology.target_host_handle.is_empty()
        || topology.origin_site_code == topology.target_site_code
        || topology.origin_host_handle == topology.target_host_handle
    {
        return Err(SccmHierarchyError::InvalidTopology);
    }
    let mut sites = BTreeSet::from([
        topology.origin_site_code.as_str(),
        topology.target_site_code.as_str(),
    ]);
    let mut hosts = BTreeSet::from([
        topology.origin_host_handle.as_str(),
        topology.target_host_handle.as_str(),
    ]);
    if topology.additional_targets.iter().any(|target| {
        !exact_site_code(&target.site_code)
            || target.host_handle.is_empty()
            || !sites.insert(&target.site_code)
            || !hosts.insert(&target.host_handle)
    }) {
        return Err(SccmHierarchyError::InvalidTopology);
    }
    Ok(())
}

fn artifact_topology_matches(
    artifact: &SccmHierarchyArtifact,
    topology: &SccmHierarchyTopology,
) -> bool {
    match artifact.direction {
        SccmHierarchyDirection::Origin => {
            artifact.producer_host_handle == topology.origin_host_handle
        }
        SccmHierarchyDirection::Target => {
            topology.target_host_handle == artifact.producer_host_handle
                || topology
                    .additional_targets
                    .iter()
                    .any(|target| target.host_handle == artifact.producer_host_handle)
        }
        SccmHierarchyDirection::Both => false,
    }
}

fn target_host_for<'a>(topology: &'a SccmHierarchyTopology, site_code: &str) -> Option<&'a str> {
    if topology.target_site_code == site_code {
        return Some(&topology.target_host_handle);
    }
    topology
        .additional_targets
        .iter()
        .find(|target| target.site_code == site_code)
        .map(|target| target.host_handle.as_str())
}

fn record_topology_matches(
    artifact: &SccmHierarchyArtifact,
    parsed: &ParsedRecord,
    topology: &SccmHierarchyTopology,
) -> bool {
    match artifact.direction {
        SccmHierarchyDirection::Origin => {
            artifact.producer_host_handle == topology.origin_host_handle
        }
        SccmHierarchyDirection::Target => {
            target_host_for(topology, &parsed.target_site)
                == Some(artifact.producer_host_handle.as_str())
        }
        SccmHierarchyDirection::Both => false,
    }
}

fn declared_source(artifact: &SccmHierarchyArtifact) -> bool {
    matches!(artifact.artifact.role, SccmRole::SiteServer)
        && matches!(
            (
                artifact.source_id.as_str(),
                artifact.artifact.display_name.as_str(),
                &artifact.direction
            ),
            (
                "server-hierarchy-control",
                "replmgr.log",
                SccmHierarchyDirection::Origin
            ) | (
                "server-hierarchy-control",
                "rcmctrl.log",
                SccmHierarchyDirection::Target
            ) | (
                "server-hierarchy-transfer",
                "sender.log",
                SccmHierarchyDirection::Origin
            ) | (
                "server-hierarchy-transfer",
                "sender.lo_",
                SccmHierarchyDirection::Origin
            ) | (
                "server-hierarchy-transfer",
                "despool.log",
                SccmHierarchyDirection::Target
            )
        )
}

fn phase_owned(artifact: &SccmHierarchyArtifact, phase: &SccmHierarchyPhase) -> bool {
    matches!(
        (artifact.artifact.display_name.as_str(), phase),
        (
            "replmgr.log",
            SccmHierarchyPhase::Initiate | SccmHierarchyPhase::QueueOrSerialize
        ) | ("sender.log" | "sender.lo_", SccmHierarchyPhase::Send)
            | (
                "despool.log",
                SccmHierarchyPhase::Receive
                    | SccmHierarchyPhase::Process
                    | SccmHierarchyPhase::HealthyOrTerminal
            )
            | (
                "rcmctrl.log",
                SccmHierarchyPhase::Acknowledge | SccmHierarchyPhase::HealthyOrTerminal
            )
    )
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
    artifact_id: &str,
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
    format!("{}-{suffix}", artifact_prefix(artifact_id))
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
    for pair in observations.windows(2) {
        let (left, right) = (&pair[0], &pair[1]);
        let (Some(left_millis), Some(right_millis)) =
            (left.timestamp.utc_millis, right.timestamp.utc_millis)
        else {
            return SccmHierarchyTimestampOrdering::UnusableMissingTimestamp;
        };
        if observation_artifact_id(right) != observation_artifact_id(left)
            && right_millis <= left_millis
        {
            return SccmHierarchyTimestampOrdering::Contradictory;
        }
        if observation_artifact_id(right) == observation_artifact_id(left)
            && right_millis < left_millis
        {
            return SccmHierarchyTimestampOrdering::Contradictory;
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
    coverage: &[SccmHierarchyCoverage],
    observations: &[SccmHierarchyObservation],
) -> Vec<String> {
    let seen = observations
        .iter()
        .map(observation_artifact_id)
        .collect::<BTreeSet<_>>();
    coverage
        .iter()
        .filter(|artifact| artifact.state != SccmCoverageState::Captured)
        .filter(|artifact| !seen.contains(artifact.artifact_id.as_str()))
        .map(|artifact| artifact.artifact_id.clone())
        .collect()
}

fn source_local(
    artifact: &SccmHierarchyArtifact,
    reason_code: &str,
    evidence: Vec<SccmEvidenceRef>,
) -> SccmHierarchySourceLocalObservation {
    SccmHierarchySourceLocalObservation {
        observation_id: format!(
            "{}-{}",
            artifact_prefix(&artifact.artifact.artifact_id),
            reason_code
        ),
        finding_class: SccmFindingClass::InsufficientEvidence,
        confidence: SccmConfidence::Low,
        correlation_eligible: false,
        artifact_ids: vec![artifact.artifact.artifact_id.clone()],
        evidence,
        reason_code: reason_code.to_owned(),
    }
}

fn fragment_observations(
    artifacts: &[SccmHierarchyArtifact],
) -> Vec<SccmHierarchySourceLocalObservation> {
    let mut groups = BTreeMap::<&str, Vec<&SccmHierarchyArtifact>>::new();
    for artifact in artifacts
        .iter()
        .filter(|artifact| !artifact.fragment_complete)
    {
        groups
            .entry(&artifact.rotation_lineage_id)
            .or_default()
            .push(artifact);
    }
    groups
        .into_values()
        .map(|mut artifacts| {
            artifacts
                .sort_by(|left, right| left.artifact.artifact_id.cmp(&right.artifact.artifact_id));
            let artifact_ids = artifacts
                .iter()
                .map(|artifact| artifact.artifact.artifact_id.clone())
                .collect::<Vec<_>>();
            let reason_code = if artifacts.len() > 1 {
                "rotationSplit"
            } else {
                "coverageOnly"
            };
            SccmHierarchySourceLocalObservation {
                observation_id: format!("{}-{reason_code}", artifact_prefix(&artifact_ids[0])),
                finding_class: SccmFindingClass::InsufficientEvidence,
                confidence: SccmConfidence::Low,
                correlation_eligible: false,
                artifact_ids,
                evidence: Vec::new(),
                reason_code: reason_code.to_owned(),
            }
        })
        .collect()
}

fn artifact_requests(
    bundle: &SccmHierarchyBundle,
    coverage: &[SccmHierarchyCoverage],
) -> Vec<SccmHierarchyArtifactRequest> {
    let mut requests = Vec::new();
    for item in coverage {
        let Some(artifact) = bundle
            .artifacts
            .iter()
            .find(|artifact| artifact.artifact.artifact_id == item.artifact_id)
        else {
            continue;
        };
        let reason_code = match item.state {
            SccmCoverageState::Absent => Some("coverageAbsent"),
            SccmCoverageState::Capped => Some("coverageCapped"),
            _ => None,
        };
        let Some(reason_code) = reason_code else {
            continue;
        };
        requests.push(SccmHierarchyArtifactRequest {
            source_id: item.source_id.clone(),
            producer_role: item.producer_role.clone(),
            direction: artifact.direction.clone(),
            target_site_code: bundle.topology.target_site_code.clone(),
            basenames: vec![artifact.artifact.display_name.clone()],
            reason_code: reason_code.to_owned(),
        });
    }
    let mut rotation_groups = BTreeMap::<&str, Vec<&SccmHierarchyArtifact>>::new();
    for artifact in bundle
        .artifacts
        .iter()
        .filter(|artifact| !artifact.fragment_complete)
    {
        rotation_groups
            .entry(&artifact.rotation_lineage_id)
            .or_default()
            .push(artifact);
    }
    for artifacts in rotation_groups
        .into_values()
        .filter(|group| group.len() > 1)
    {
        requests.retain(|request| {
            !artifacts.iter().any(|artifact| {
                request.source_id == artifact.source_id
                    && request.reason_code == "coverageRotationSplit"
            })
        });
        let mut basenames = artifacts
            .iter()
            .map(|artifact| artifact.artifact.display_name.clone())
            .collect::<Vec<_>>();
        basenames.sort();
        basenames.dedup();
        requests.push(SccmHierarchyArtifactRequest {
            source_id: artifacts[0].source_id.clone(),
            producer_role: SccmRole::SiteServer,
            direction: artifacts[0].direction.clone(),
            target_site_code: bundle.topology.target_site_code.clone(),
            basenames,
            reason_code: "coverageRotationSplit".to_owned(),
        });
    }
    requests.sort_by(request_order);
    requests.dedup_by(|left, right| request_order(left, right).is_eq());
    requests
}

fn request_order(
    left: &SccmHierarchyArtifactRequest,
    right: &SccmHierarchyArtifactRequest,
) -> Ordering {
    (
        left.source_id.as_str(),
        &left.direction,
        left.target_site_code.as_str(),
        left.reason_code.as_str(),
        &left.basenames,
    )
        .cmp(&(
            right.source_id.as_str(),
            &right.direction,
            right.target_site_code.as_str(),
            right.reason_code.as_str(),
            &right.basenames,
        ))
}

fn artifact_prefix(artifact_id: &str) -> &str {
    artifact_id
        .rsplit_once('-')
        .map_or(artifact_id, |(prefix, _)| prefix)
}
