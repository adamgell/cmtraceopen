use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{
    normalize_ccm_artifact, normalize_key, SccmArtifact, SccmCorrelationKeyKind, SccmRole,
};
use super::{SccmCoverageState, SccmEvidenceRef, SccmKeyConfidence};
use super::{SccmTimeOrderingState, SccmTimestamp};

const PUBLIC_MESSAGE_PREFIX: &str = "[sccm-public-message-v1] ";
const FIXTURE_MARKER: &str = "SYNTHETIC FIXTURE";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmHierarchyTopology {
    pub origin_site_code: String,
    pub target_site_code: String,
    pub origin_host_handle: String,
    pub target_host_handle: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmHierarchyDirection {
    Origin,
    Target,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmHierarchyCoverageState {
    Captured,
    Absent,
    AccessDenied,
    Capped,
    Skipped,
    Unsupported,
    ParseFailed,
    ProfileMismatch,
    TopologyMismatch,
    IncompleteRotation,
}

impl From<&SccmCoverageState> for SccmHierarchyCoverageState {
    fn from(value: &SccmCoverageState) -> Self {
        match value {
            SccmCoverageState::Captured => Self::Captured,
            SccmCoverageState::Absent => Self::Absent,
            SccmCoverageState::AccessDenied => Self::AccessDenied,
            SccmCoverageState::Capped => Self::Capped,
            SccmCoverageState::Skipped => Self::Skipped,
            SccmCoverageState::Unsupported => Self::Unsupported,
            SccmCoverageState::ParseFailed => Self::ParseFailed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmHierarchyCoverage {
    pub artifact_id: String,
    pub source_id: String,
    pub state: SccmHierarchyCoverageState,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmHierarchyObservation {
    pub artifact_id: String,
    pub line_start: u32,
    pub line_end: u32,
    pub phase: SccmHierarchyPhase,
    pub disposition: SccmHierarchyDisposition,
    pub terminal: bool,
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
    Mismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmHierarchyTimestampOrdering {
    Usable,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmHierarchyState {
    Succeeded,
    Failed,
    BlockedOrDeferred,
    Incomplete,
    Contradictory,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmHierarchyClassification {
    Success,
    ConfirmedFailure,
    BlockedOrDeferred,
    InsufficientEvidence,
    ContradictoryEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmHierarchyConfidence {
    Low,
    Moderate,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmHierarchyTransaction {
    pub transaction_id: String,
    pub key: SccmHierarchyKey,
    pub topology_compatibility: SccmHierarchyTopologyCompatibility,
    pub timestamp_ordering: SccmHierarchyTimestampOrdering,
    pub terminal_evidence: bool,
    pub state: SccmHierarchyState,
    pub classification: SccmHierarchyClassification,
    pub confidence: SccmHierarchyConfidence,
    pub coverage_gap_artifact_ids: Vec<String>,
    pub observations: Vec<SccmHierarchyObservation>,
    pub evidence: Vec<SccmEvidenceRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmHierarchyAnalysis {
    pub transactions: Vec<SccmHierarchyTransaction>,
    pub coverage: Vec<SccmHierarchyCoverage>,
    pub topology_mismatch_artifact_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SccmHierarchyError {
    InvalidProfile,
    InvalidTopology,
}

pub fn analyze_hierarchy_replication(
    bundle: &SccmHierarchyBundle,
) -> Result<SccmHierarchyAnalysis, SccmHierarchyError> {
    validate_topology(&bundle.topology)?;
    if bundle.profile_id.trim().is_empty() || bundle.source_version.trim().is_empty() {
        return Err(SccmHierarchyError::InvalidProfile);
    }

    let mut coverage = Vec::new();
    let mut mismatches = Vec::new();
    let mut grouped = BTreeMap::<String, Candidate>::new();

    let mut artifacts = bundle.artifacts.iter().collect::<Vec<_>>();
    artifacts.sort_by(|left, right| left.artifact.artifact_id.cmp(&right.artifact.artifact_id));
    for artifact in artifacts {
        let topology_ok = artifact_topology_matches(artifact, &bundle.topology);
        let mut state = SccmHierarchyCoverageState::from(&artifact.artifact.coverage);
        if !topology_ok {
            state = SccmHierarchyCoverageState::TopologyMismatch;
            mismatches.push(artifact.artifact.artifact_id.clone());
        } else if artifact.artifact.configmgr_version.as_deref()
            != Some(bundle.source_version.as_str())
        {
            state = SccmHierarchyCoverageState::ProfileMismatch;
        } else if !artifact.fragment_complete || artifact.rotation_lineage_id.trim().is_empty() {
            state = SccmHierarchyCoverageState::IncompleteRotation;
        }
        coverage.push(SccmHierarchyCoverage {
            artifact_id: artifact.artifact.artifact_id.clone(),
            source_id: artifact.source_id.clone(),
            state,
        });

        if artifact.artifact.coverage != SccmCoverageState::Captured
            || !topology_ok
            || artifact.artifact.configmgr_version.as_deref()
                != Some(bundle.source_version.as_str())
            || !artifact.fragment_complete
            || artifact.rotation_lineage_id.trim().is_empty()
            || !declared_source(artifact)
        {
            continue;
        }

        let records = normalize_ccm_artifact(artifact.artifact.clone(), &artifact.content);
        for evidence in records {
            let Some(parsed) = parse_public_record(&evidence.message) else {
                continue;
            };
            if parsed.profile_id != bundle.profile_id
                || !exact_key(&parsed.message_id, SccmCorrelationKeyKind::ContentId)
                || !exact_key(&parsed.link_id, SccmCorrelationKeyKind::ContentId)
                || !exact_key(&parsed.origin_site, SccmCorrelationKeyKind::SiteCode)
                || !exact_key(&parsed.target_site, SccmCorrelationKeyKind::SiteCode)
                || parsed.origin_site != bundle.topology.origin_site_code
                || parsed.target_site != bundle.topology.target_site_code
                || !phase_owned(artifact, &parsed.phase)
            {
                continue;
            }

            let key = SccmHierarchyKey {
                message_id: parsed.message_id,
                link_id: parsed.link_id,
                origin_site_code: parsed.origin_site,
                target_site_code: parsed.target_site,
                confidence: SccmKeyConfidence::Exact,
                extraction_profile_id: parsed.profile_id,
            };
            let group_key = transaction_id(&key);
            let candidate = grouped.entry(group_key).or_insert_with(|| Candidate {
                key,
                observations: Vec::new(),
                evidence: Vec::new(),
            });
            let line_start = evidence.reference.line_start.unwrap_or_default();
            let line_end = evidence.reference.line_end.unwrap_or(line_start);
            candidate.observations.push(SccmHierarchyObservation {
                artifact_id: evidence.reference.artifact_id.clone(),
                line_start,
                line_end,
                phase: parsed.phase,
                disposition: parsed.disposition,
                terminal: parsed.terminal,
                timestamp: evidence.timestamp,
            });
            candidate.evidence.push(evidence.reference);
        }
    }

    coverage.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
    mismatches.sort();
    mismatches.dedup();

    let mut transactions = grouped
        .into_values()
        .map(|mut candidate| {
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
            let complete_success = STATE_CHAIN.iter().all(|phase| {
                candidate.observations.iter().any(|observation| {
                    phase_name(&observation.phase) == *phase
                        && observation.disposition == SccmHierarchyDisposition::Succeeded
                })
            });
            let gaps = missing_required_artifacts(&coverage, &candidate.observations);
            let (state, classification) = if contradictory {
                (
                    SccmHierarchyState::Contradictory,
                    SccmHierarchyClassification::ContradictoryEvidence,
                )
            } else if terminal_failure {
                (
                    SccmHierarchyState::Failed,
                    SccmHierarchyClassification::ConfirmedFailure,
                )
            } else if complete_success && ordering == SccmHierarchyTimestampOrdering::Usable {
                (
                    SccmHierarchyState::Succeeded,
                    SccmHierarchyClassification::Success,
                )
            } else if retrying {
                (
                    SccmHierarchyState::BlockedOrDeferred,
                    SccmHierarchyClassification::BlockedOrDeferred,
                )
            } else {
                (
                    SccmHierarchyState::Incomplete,
                    SccmHierarchyClassification::InsufficientEvidence,
                )
            };
            let confidence = if state == SccmHierarchyState::Succeeded {
                SccmHierarchyConfidence::High
            } else if ordering == SccmHierarchyTimestampOrdering::Usable
                && !matches!(state, SccmHierarchyState::Contradictory)
            {
                SccmHierarchyConfidence::Moderate
            } else {
                SccmHierarchyConfidence::Low
            };
            let transaction_id = transaction_id(&candidate.key);
            SccmHierarchyTransaction {
                transaction_id,
                key: candidate.key,
                topology_compatibility: SccmHierarchyTopologyCompatibility::Exact,
                timestamp_ordering: ordering,
                terminal_evidence: candidate
                    .observations
                    .iter()
                    .any(|observation| observation.terminal),
                state,
                classification,
                confidence,
                coverage_gap_artifact_ids: gaps,
                observations: candidate.observations,
                evidence: candidate.evidence,
            }
        })
        .collect::<Vec<_>>();
    transactions.sort_by(|left, right| left.transaction_id.cmp(&right.transaction_id));

    Ok(SccmHierarchyAnalysis {
        transactions,
        coverage,
        topology_mismatch_artifact_ids: mismatches,
    })
}

const STATE_CHAIN: &[&str] = &[
    "initiate",
    "queueOrSerialize",
    "send",
    "receive",
    "process",
    "acknowledge",
    "healthyOrTerminal",
];

struct Candidate {
    key: SccmHierarchyKey,
    observations: Vec<SccmHierarchyObservation>,
    evidence: Vec<SccmEvidenceRef>,
}

struct ParsedRecord {
    phase: SccmHierarchyPhase,
    disposition: SccmHierarchyDisposition,
    terminal: bool,
    message_id: String,
    link_id: String,
    origin_site: String,
    target_site: String,
    profile_id: String,
}

fn validate_topology(topology: &SccmHierarchyTopology) -> Result<(), SccmHierarchyError> {
    if topology.origin_site_code.is_empty()
        || topology.target_site_code.is_empty()
        || topology.origin_host_handle.is_empty()
        || topology.target_host_handle.is_empty()
        || topology.origin_site_code == topology.target_site_code
    {
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
            artifact.producer_host_handle == topology.target_host_handle
        }
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
    if segments.next()? != FIXTURE_MARKER {
        return None;
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
    for segment in segments {
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
    Some(ParsedRecord {
        phase: SccmHierarchyPhase::parse(fields.get("Phase")?)?,
        disposition: SccmHierarchyDisposition::parse(fields.get("Disposition")?)?,
        terminal,
        message_id: (*fields.get("MessageId")?).to_owned(),
        link_id: (*fields.get("LinkId")?).to_owned(),
        origin_site: (*fields.get("OriginSite")?).to_owned(),
        target_site: (*fields.get("TargetSite")?).to_owned(),
        profile_id: (*fields.get("ProfileId")?).to_owned(),
    })
}

fn exact_key(value: &str, kind: SccmCorrelationKeyKind) -> bool {
    let key = normalize_key(kind, value);
    key.confidence == SccmKeyConfidence::Exact && key.normalized == value
}

fn transaction_id(key: &SccmHierarchyKey) -> String {
    format!(
        "hierarchy:{}:{}:{}:{}:{}",
        key.message_id,
        key.origin_site_code,
        key.target_site_code,
        key.link_id,
        key.extraction_profile_id
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

fn observation_order(
    left: &SccmHierarchyObservation,
    right: &SccmHierarchyObservation,
) -> Ordering {
    left.phase
        .rank()
        .cmp(&right.phase.rank())
        .then_with(|| left.artifact_id.cmp(&right.artifact_id))
        .then_with(|| left.line_start.cmp(&right.line_start))
        .then_with(|| left.line_end.cmp(&right.line_end))
}

fn evidence_order(left: &SccmEvidenceRef, right: &SccmEvidenceRef) -> Ordering {
    left.artifact_id
        .cmp(&right.artifact_id)
        .then_with(|| left.line_start.cmp(&right.line_start))
        .then_with(|| left.line_end.cmp(&right.line_end))
        .then_with(|| left.entry_id.cmp(&right.entry_id))
}

fn timestamp_ordering(observations: &[SccmHierarchyObservation]) -> SccmHierarchyTimestampOrdering {
    if observations.iter().any(|observation| {
        !matches!(
            observation.timestamp.ordering_state,
            SccmTimeOrderingState::NormalizedUtc
        ) || observation.timestamp.utc_millis.is_none()
    }) {
        return SccmHierarchyTimestampOrdering::Unknown;
    }
    for pair in observations.windows(2) {
        let (left, right) = (&pair[0], &pair[1]);
        let (Some(left_millis), Some(right_millis)) =
            (left.timestamp.utc_millis, right.timestamp.utc_millis)
        else {
            return SccmHierarchyTimestampOrdering::Unknown;
        };
        if right.artifact_id != left.artifact_id && right_millis <= left_millis {
            return SccmHierarchyTimestampOrdering::Unknown;
        }
        if right.artifact_id == left.artifact_id && right_millis < left_millis {
            return SccmHierarchyTimestampOrdering::Unknown;
        }
    }
    SccmHierarchyTimestampOrdering::Usable
}

fn has_contradiction(observations: &[SccmHierarchyObservation]) -> bool {
    let mut by_phase = BTreeMap::<usize, (SccmHierarchyDisposition, bool)>::new();
    observations.iter().any(|observation| {
        by_phase
            .insert(
                observation.phase.rank(),
                (observation.disposition.clone(), observation.terminal),
            )
            .is_some_and(|previous| {
                previous.0 != observation.disposition || previous.1 != observation.terminal
            })
    })
}

fn missing_required_artifacts(
    coverage: &[SccmHierarchyCoverage],
    observations: &[SccmHierarchyObservation],
) -> Vec<String> {
    let seen = observations
        .iter()
        .map(|observation| observation.artifact_id.as_str())
        .collect::<BTreeSet<_>>();
    coverage
        .iter()
        .filter(|artifact| artifact.state != SccmHierarchyCoverageState::Captured)
        .filter(|artifact| !seen.contains(artifact.artifact_id.as_str()))
        .map(|artifact| artifact.artifact_id.clone())
        .collect()
}
