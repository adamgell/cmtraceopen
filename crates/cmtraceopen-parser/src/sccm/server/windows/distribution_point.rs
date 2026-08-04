//! Canonical-intake adapter for Distribution Point source evidence.
//!
//! The source adapter admits only declared DP CCM sources from normalized,
//! integrity-bound server intake. The content reducer then applies one exact
//! versioned fact profile to source-local package lifecycle evidence. It makes
//! no client-impact or cross-side causal claim.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use thiserror::Error;

use crate::models::log_entry::Severity;
use crate::sccm::{
    classify_artifact_name, SccmArtifactFamily, SccmArtifactRequest, SccmCoverageState,
    SccmEvidence, SccmEvidenceRef, SccmRole, SccmRotation, SccmTimeOrderingState, SccmTimestamp,
};

use super::{
    declared_server_source_catalog, SccmServerArtifactAssessment, SccmServerCoverage,
    SccmServerIntakeAssessment, SccmServerSourceKind,
};

pub const SCCM_DISTRIBUTION_POINT_ANALYSIS_SCHEMA_VERSION: u32 = 1;
pub const SCCM_DISTRIBUTION_POINT_INTAKE_PROFILE_ID: &str = "sccm-dp-intake-envelope";
pub const SCCM_DISTRIBUTION_POINT_INTAKE_PROFILE_VERSION: u32 = 1;
pub const SCCM_DISTRIBUTION_POINT_SOURCE_ID: &str = "server-dp-distribution";
pub const SCCM_DISTRIBUTION_POINT_CONTENT_ANALYSIS_SCHEMA_VERSION: u32 = 1;
pub const SCCM_DISTRIBUTION_POINT_CONTENT_PROFILE_ID: &str = "dp-server-5.00.test-v1";
pub const SCCM_DISTRIBUTION_POINT_CONTENT_PROFILE_VERSION: u32 = 1;
const SCCM_DISTRIBUTION_POINT_CONTENT_SOURCE_VERSION: &str = "5.00.TEST.0001";
const SCCM_DISTRIBUTION_POINT_INTAKE_AUTHORITY_REASON: &str =
    "Canonical server intake authority could not be verified.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmDistributionPointWorkflow {
    DistributionPointContent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmDistributionPointProfile {
    pub id: String,
    pub version: u32,
    pub stability: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmDistributionPointSourceObservation {
    pub artifact_id: String,
    pub producer_role: SccmRole,
    pub producer_host_handle: Option<String>,
    pub workflow_subject_role: Option<SccmRole>,
    pub workflow_subject_handle: Option<String>,
    pub source_id: String,
    pub source_version: Option<String>,
    pub rotation: Option<SccmRotation>,
    pub rotation_lineage_handle: String,
    pub evidence: SccmEvidenceRef,
    pub timestamp: SccmTimestamp,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmDistributionPointCoverageGap {
    pub source_id: String,
    pub producer_role: Option<SccmRole>,
    pub workflow_subject_role: Option<SccmRole>,
    pub state: Option<SccmCoverageState>,
    pub artifact_ids: Vec<String>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmDistributionPointAnalysis {
    pub schema_version: u32,
    pub workflow: SccmDistributionPointWorkflow,
    pub profile: SccmDistributionPointProfile,
    pub source_observations: Vec<SccmDistributionPointSourceObservation>,
    pub coverage_gaps: Vec<SccmDistributionPointCoverageGap>,
    pub artifact_requests: Vec<SccmArtifactRequest>,
    pub cross_side_correlation_performed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmDistributionPointContentPhase {
    ReceiveContent,
    Distribute,
    Transfer,
    Validate,
    MakeAvailable,
    ServeOrReport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmDistributionPointContentState {
    Succeeded,
    Failed,
    Retrying,
    Blocked,
    Deferred,
    Contradictory,
    Incomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmDistributionPointContentClassification {
    Success,
    ConfirmedFailure,
    BlockedOrDeferred,
    ContradictoryEvidence,
    InsufficientEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmDistributionPointContentConfidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmDistributionPointContentScope {
    DistributionPointContent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmDistributionPointContentDisposition {
    Succeeded,
    Failed,
    Retrying,
    Blocked,
    Deferred,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmDistributionPointContentKey {
    pub package_id: String,
    pub content_id: String,
    pub content_version: u32,
    pub topology_site_handle: String,
    pub site_code: String,
    pub distribution_point_handle: String,
    pub extraction_profile_id: String,
    pub extraction_profile_version: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmDistributionPointContentObservation {
    pub phase: SccmDistributionPointContentPhase,
    pub disposition: SccmDistributionPointContentDisposition,
    pub terminal: bool,
    pub source_id: String,
    pub timestamp: SccmTimestamp,
    pub evidence: SccmEvidenceRef,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmDistributionPointContentTransaction {
    pub transaction_id: String,
    pub key: SccmDistributionPointContentKey,
    pub state: SccmDistributionPointContentState,
    pub classification: SccmDistributionPointContentClassification,
    pub confidence: SccmDistributionPointContentConfidence,
    pub severity: Severity,
    pub scope: SccmDistributionPointContentScope,
    pub last_proven_phase: Option<SccmDistributionPointContentPhase>,
    pub stop_phase: Option<SccmDistributionPointContentPhase>,
    pub recovered: bool,
    pub content_version_mismatch: bool,
    pub evidence: Vec<SccmEvidenceRef>,
    pub terminal_evidence: Vec<SccmEvidenceRef>,
    pub next_artifact: Option<SccmArtifactRequest>,
    pub observations: Vec<SccmDistributionPointContentObservation>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmDistributionPointContentAnalysis {
    pub schema_version: u32,
    pub workflow: SccmDistributionPointWorkflow,
    pub profile: SccmDistributionPointProfile,
    pub transactions: Vec<SccmDistributionPointContentTransaction>,
    pub coverage_gaps: Vec<SccmDistributionPointCoverageGap>,
    pub artifact_requests: Vec<SccmArtifactRequest>,
    pub cross_side_correlation_performed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SccmDistributionPointContentIntakeError {
    #[error("canonical server intake authority could not be verified")]
    IntakeAuthority,
    #[error("Distribution Point topology is not compatible with the admitted profile")]
    Topology,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct DistributionPointFactKey {
    package_id: String,
    content_id: String,
    content_version: u32,
    site_code: String,
    distribution_point_handle: String,
}

#[derive(Debug, Clone)]
struct DistributionPointFact {
    key: DistributionPointFactKey,
    phase: SccmDistributionPointContentPhase,
    disposition: SccmDistributionPointContentDisposition,
    terminal: bool,
    source_id: String,
    reference: SccmEvidenceRef,
    timestamp: SccmTimestamp,
}

/// Private canonical transaction envelope. Facts only originate from an
/// integrity-bound server intake assessment; callers cannot construct or
/// submit source facts directly.
#[derive(Debug)]
struct DistributionPointTransactionEnvelope {
    topology_site_handle: String,
    key: DistributionPointFactKey,
    facts: Vec<DistributionPointFact>,
}

/// Project only complete, profile-eligible logical CCM records from the
/// canonical server intake. The output is source-local and intentionally does
/// not interpret message text as a package/content success or failure.
pub fn analyze_distribution_point(
    intake: &SccmServerIntakeAssessment,
) -> SccmDistributionPointAnalysis {
    if !intake.adapter_authority_is_intake_bound() || !intake.topology_authority_is_intake_bound() {
        return intake_authority_invalid_analysis();
    }

    let artifact_id_counts =
        intake
            .artifacts
            .iter()
            .fold(BTreeMap::<&str, usize>::new(), |mut counts, artifact| {
                *counts.entry(artifact.artifact_id.as_str()).or_default() += 1;
                counts
            });
    let evidence_by_artifact = intake.evidence.iter().fold(
        BTreeMap::<&str, Vec<&SccmEvidence>>::new(),
        |mut grouped, evidence| {
            grouped
                .entry(evidence.reference.artifact_id.as_str())
                .or_default()
                .push(evidence);
            grouped
        },
    );
    let artifacts = intake
        .artifacts
        .iter()
        .filter(|artifact| {
            artifact_id_counts
                .get(artifact.artifact_id.as_str())
                .is_some_and(|count| *count == 1)
                && is_dp_distribution_artifact(artifact)
                && artifact_metadata_is_congruent(intake, artifact, &artifact_id_counts)
                && evidence_by_artifact
                    .get(artifact.artifact_id.as_str())
                    .is_some_and(|evidence| canonical_evidence_set(artifact, evidence))
        })
        .map(|artifact| (artifact.artifact_id.as_str(), artifact))
        .collect::<BTreeMap<_, _>>();

    let mut source_observations = intake
        .evidence
        .iter()
        .filter_map(|evidence| {
            let artifact = artifacts.get(evidence.reference.artifact_id.as_str())?;
            admitted_for_source_observation(artifact, evidence).then(|| {
                SccmDistributionPointSourceObservation {
                    artifact_id: artifact.artifact_id.clone(),
                    producer_role: artifact.producer_role.clone(),
                    producer_host_handle: artifact.producer_host_handle.clone(),
                    workflow_subject_role: artifact.workflow_subject_role.clone(),
                    workflow_subject_handle: artifact.workflow_subject_handle.clone(),
                    source_id: artifact.source_id.clone(),
                    source_version: artifact.source_version.clone(),
                    rotation: artifact.rotation.clone(),
                    rotation_lineage_handle: artifact.rotation_lineage_handle.clone(),
                    evidence: evidence.reference.clone(),
                    timestamp: evidence.timestamp.clone(),
                }
            })
        })
        .collect::<Vec<_>>();
    source_observations.sort_by(|left, right| {
        source_observation_sort_key(left).cmp(&source_observation_sort_key(right))
    });

    let mut coverage_gaps = coverage_gaps(intake, &source_observations);
    coverage_gaps.sort_by_key(coverage_gap_sort_key);

    let artifact_requests = artifact_requests(&coverage_gaps);

    SccmDistributionPointAnalysis {
        schema_version: SCCM_DISTRIBUTION_POINT_ANALYSIS_SCHEMA_VERSION,
        workflow: SccmDistributionPointWorkflow::DistributionPointContent,
        profile: SccmDistributionPointProfile {
            id: SCCM_DISTRIBUTION_POINT_INTAKE_PROFILE_ID.to_owned(),
            version: SCCM_DISTRIBUTION_POINT_INTAKE_PROFILE_VERSION,
            stability: "experimental".to_owned(),
        },
        source_observations,
        coverage_gaps,
        artifact_requests,
        cross_side_correlation_performed: false,
    }
}

/// Reduce the approved DP package profile from canonical server intake.
/// Source messages are evidence only after their artifact, coverage, topology,
/// version, role, and physical line authority have passed the sealed adapter.
pub fn analyze_distribution_point_content_from_server_intake(
    intake: &SccmServerIntakeAssessment,
) -> Result<SccmDistributionPointContentAnalysis, SccmDistributionPointContentIntakeError> {
    if !intake.adapter_authority_is_intake_bound() || !intake.topology_authority_is_intake_bound() {
        return Err(SccmDistributionPointContentIntakeError::IntakeAuthority);
    }
    if !intake
        .topology
        .roles_observed
        .contains(&SccmRole::DistributionPoint)
    {
        return Err(SccmDistributionPointContentIntakeError::Topology);
    }

    let bounded = analyze_distribution_point(intake);
    let evidence_by_entry_id = intake
        .evidence
        .iter()
        .map(|evidence| (evidence.reference.entry_id.as_str(), evidence))
        .collect::<BTreeMap<_, _>>();
    let artifacts_by_id = intake
        .artifacts
        .iter()
        .map(|artifact| (artifact.artifact_id.as_str(), artifact))
        .collect::<BTreeMap<_, _>>();
    let expected_site_code =
        selected_content_profile_site_code(intake.topology.site_handle.as_str());
    let mut facts_by_key = BTreeMap::<DistributionPointFactKey, Vec<DistributionPointFact>>::new();
    let mut semantic_gaps =
        BTreeMap::<(String, String, String), SccmDistributionPointCoverageGap>::new();

    for observation in &bounded.source_observations {
        let Some(evidence) = evidence_by_entry_id.get(observation.evidence.entry_id.as_str())
        else {
            continue;
        };
        let Some(artifact) = artifacts_by_id.get(observation.artifact_id.as_str()) else {
            continue;
        };
        let Some(fact) =
            parse_distribution_point_fact(observation, artifact, evidence, expected_site_code)
        else {
            note_semantic_gap(
                &mut semantic_gaps,
                artifacts_by_id
                    .get(observation.artifact_id.as_str())
                    .copied(),
            );
            continue;
        };
        facts_by_key.entry(fact.key.clone()).or_default().push(fact);
    }

    let mut transactions = Vec::new();
    for (key, facts) in facts_by_key {
        transactions.push(reduce_transaction(DistributionPointTransactionEnvelope {
            topology_site_handle: intake.topology.site_handle.clone(),
            key,
            facts,
        }));
    }
    let mut versions_by_identity = BTreeMap::<(String, String, String), BTreeSet<u32>>::new();
    for transaction in &transactions {
        versions_by_identity
            .entry((
                transaction.key.package_id.clone(),
                transaction.key.content_id.clone(),
                transaction.key.distribution_point_handle.clone(),
            ))
            .or_default()
            .insert(transaction.key.content_version);
    }
    for transaction in &mut transactions {
        transaction.content_version_mismatch = versions_by_identity
            .get(&(
                transaction.key.package_id.clone(),
                transaction.key.content_id.clone(),
                transaction.key.distribution_point_handle.clone(),
            ))
            .is_some_and(|versions| versions.len() > 1);
    }
    transactions.sort_by(|left, right| left.key.cmp(&right.key));

    let mut coverage_gaps = bounded.coverage_gaps;
    coverage_gaps.extend(semantic_gaps.into_values().map(|mut gap| {
        gap.artifact_ids.sort();
        gap.artifact_ids.dedup();
        gap
    }));
    coverage_gaps.sort_by(|left, right| {
        coverage_gap_sort_key(left)
            .cmp(&coverage_gap_sort_key(right))
            .then_with(|| left.reason.cmp(&right.reason))
    });
    coverage_gaps.dedup();
    let mut artifact_requests = artifact_requests(&coverage_gaps);
    artifact_requests.extend(
        transactions
            .iter()
            .filter_map(|transaction| transaction.next_artifact.clone()),
    );
    artifact_requests.sort_by(|left, right| {
        (
            left.logical_id.as_str(),
            role_sort_key(&left.role),
            left.reason.as_str(),
        )
            .cmp(&(
                right.logical_id.as_str(),
                role_sort_key(&right.role),
                right.reason.as_str(),
            ))
    });
    artifact_requests.dedup_by(|left, right| {
        left.logical_id == right.logical_id
            && left.role == right.role
            && left.reason == right.reason
    });
    if !coverage_gaps.is_empty() {
        for transaction in &mut transactions {
            if transaction.confidence == SccmDistributionPointContentConfidence::High {
                transaction.confidence = SccmDistributionPointContentConfidence::Medium;
            }
        }
    }

    Ok(SccmDistributionPointContentAnalysis {
        schema_version: SCCM_DISTRIBUTION_POINT_CONTENT_ANALYSIS_SCHEMA_VERSION,
        workflow: SccmDistributionPointWorkflow::DistributionPointContent,
        profile: SccmDistributionPointProfile {
            id: SCCM_DISTRIBUTION_POINT_CONTENT_PROFILE_ID.to_owned(),
            version: SCCM_DISTRIBUTION_POINT_CONTENT_PROFILE_VERSION,
            stability: "experimental".to_owned(),
        },
        transactions,
        coverage_gaps,
        artifact_requests,
        cross_side_correlation_performed: false,
    })
}

fn note_semantic_gap(
    gaps: &mut BTreeMap<(String, String, String), SccmDistributionPointCoverageGap>,
    artifact: Option<&SccmServerArtifactAssessment>,
) {
    let Some(artifact) = artifact else {
        return;
    };
    let key = (
        artifact.source_id.clone(),
        role_sort_key(&artifact.producer_role).to_owned(),
        artifact
            .workflow_subject_role
            .as_ref()
            .map(role_sort_key)
            .unwrap_or_default()
            .to_owned(),
    );
    gaps.entry(key)
        .and_modify(|gap| gap.artifact_ids.push(artifact.artifact_id.clone()))
        .or_insert_with(|| SccmDistributionPointCoverageGap {
            source_id: artifact.source_id.clone(),
            producer_role: Some(artifact.producer_role.clone()),
            workflow_subject_role: artifact.workflow_subject_role.clone(),
            state: Some(SccmCoverageState::Captured),
            artifact_ids: vec![artifact.artifact_id.clone()],
            reason: "Captured Distribution Point evidence did not match the selected content profile or complete a supported transaction."
                .to_owned(),
        });
}

fn parse_distribution_point_fact(
    observation: &SccmDistributionPointSourceObservation,
    artifact: &SccmServerArtifactAssessment,
    evidence: &SccmEvidence,
    expected_site_code: Option<&str>,
) -> Option<DistributionPointFact> {
    let phase = exact_message_token(&evidence.message, "Phase").and_then(content_phase)?;
    let disposition = exact_message_token(&evidence.message, "Disposition")?;
    let terminal = exact_message_token(&evidence.message, "Terminal")?;
    let package_id = exact_message_token(&evidence.message, "PackageId")?;
    let content_id = exact_message_token(&evidence.message, "ContentId")?;
    let content_version = exact_message_token(&evidence.message, "ContentVersion")?
        .parse::<u32>()
        .ok()
        .filter(|version| *version > 0)?;
    let site_code = exact_message_token(&evidence.message, "SiteCode")?;
    let distribution_point_handle = exact_message_token(&evidence.message, "DpHandle")?;
    let disposition = content_disposition(disposition)?;

    if observation.source_version.as_deref() != Some(SCCM_DISTRIBUTION_POINT_CONTENT_SOURCE_VERSION)
        || !safe_package_id(package_id)
        || !safe_content_id(content_id)
        || !safe_site_code(site_code)
        || expected_site_code != Some(site_code)
        || !safe_distribution_point_handle(distribution_point_handle)
        || !matches!(
            evidence.timestamp.ordering_state,
            SccmTimeOrderingState::NormalizedUtc
        )
        || evidence.timestamp.offset_minutes.is_none()
        || evidence.timestamp.utc_millis.is_none()
    {
        return None;
    }

    let expected_source = match phase {
        SccmDistributionPointContentPhase::ReceiveContent
        | SccmDistributionPointContentPhase::Distribute => {
            observation.producer_role == SccmRole::SiteServer
                && artifact.original_basename.as_deref() == Some("distmgr.log")
        }
        SccmDistributionPointContentPhase::Transfer => {
            observation.producer_role == SccmRole::SiteServer
                && artifact.original_basename.as_deref() == Some("PkgXferMgr.log")
        }
        SccmDistributionPointContentPhase::Validate
        | SccmDistributionPointContentPhase::MakeAvailable => {
            observation.producer_role == SccmRole::DistributionPoint
                && artifact.original_basename.as_deref() == Some("SMSDPProv.log")
                && observation.source_id == SCCM_DISTRIBUTION_POINT_SOURCE_ID
        }
        SccmDistributionPointContentPhase::ServeOrReport => {
            observation.producer_role == SccmRole::DistributionPoint
                && artifact.original_basename.as_deref() == Some("SMSdpmon.log")
                && observation.source_id == "server-dp-serve"
        }
    };
    let observed_distribution_point = match observation.producer_role {
        SccmRole::SiteServer => observation.workflow_subject_handle.as_deref(),
        SccmRole::DistributionPoint => {
            canonical_dp_subject_for_host(observation.producer_host_handle.as_deref())
        }
        _ => None,
    };
    let expected_terminal = expected_terminal(phase, disposition)?;
    if !expected_source
        || observed_distribution_point != Some(distribution_point_handle)
        || terminal != if expected_terminal { "true" } else { "false" }
    {
        return None;
    }

    Some(DistributionPointFact {
        key: DistributionPointFactKey {
            package_id: package_id.to_owned(),
            content_id: content_id.to_owned(),
            content_version,
            site_code: site_code.to_owned(),
            distribution_point_handle: distribution_point_handle.to_owned(),
        },
        phase,
        disposition,
        terminal: expected_terminal,
        source_id: observation.source_id.clone(),
        reference: evidence.reference.clone(),
        timestamp: evidence.timestamp.clone(),
    })
}

fn canonical_dp_subject_for_host(host: Option<&str>) -> Option<&'static str> {
    match host {
        Some("synthetic:host:mp-01") => Some("synthetic:subject:dp-01"),
        Some("synthetic:host:wsus-01") => Some("synthetic:subject:dp-02"),
        _ => None,
    }
}

fn expected_terminal(
    phase: SccmDistributionPointContentPhase,
    disposition: SccmDistributionPointContentDisposition,
) -> Option<bool> {
    use SccmDistributionPointContentDisposition as Disposition;
    use SccmDistributionPointContentPhase as Phase;
    match (phase, disposition) {
        (Phase::ServeOrReport, Disposition::Succeeded) => Some(true),
        (Phase::ReceiveContent | Phase::MakeAvailable, Disposition::Succeeded) => Some(false),
        (Phase::Distribute | Phase::Transfer | Phase::Validate, Disposition::Succeeded) => {
            Some(false)
        }
        (Phase::Distribute | Phase::Transfer | Phase::Validate, Disposition::Failed) => Some(true),
        (
            Phase::Distribute | Phase::Transfer | Phase::Validate,
            Disposition::Retrying | Disposition::Blocked | Disposition::Deferred,
        ) => Some(false),
        _ => None,
    }
}

fn selected_content_profile_site_code(topology_site_handle: &str) -> Option<&'static str> {
    match topology_site_handle {
        "synthetic:site:lab" => Some("LAB"),
        _ => None,
    }
}

fn reduce_transaction(
    mut envelope: DistributionPointTransactionEnvelope,
) -> SccmDistributionPointContentTransaction {
    envelope.facts.sort_by(|left, right| {
        (
            left.phase,
            left.timestamp.utc_millis,
            left.reference.entry_id.as_str(),
        )
            .cmp(&(
                right.phase,
                right.timestamp.utc_millis,
                right.reference.entry_id.as_str(),
            ))
    });
    let required_phases = [
        SccmDistributionPointContentPhase::ReceiveContent,
        SccmDistributionPointContentPhase::Distribute,
        SccmDistributionPointContentPhase::Transfer,
        SccmDistributionPointContentPhase::Validate,
        SccmDistributionPointContentPhase::MakeAvailable,
    ];
    let mut selected = Vec::new();
    let mut previous_timestamp = None;
    let mut last_proven_phase = None;
    let mut recovered = false;
    let mut outcome = None;

    for phase in required_phases
        .into_iter()
        .chain([SccmDistributionPointContentPhase::ServeOrReport])
    {
        let phase_facts = envelope
            .facts
            .iter()
            .filter(|fact| fact.phase == phase)
            .filter(|fact| {
                fact.timestamp.utc_millis.is_some_and(|timestamp| {
                    previous_timestamp.is_none_or(|previous| timestamp > previous)
                })
            })
            .cloned()
            .collect::<Vec<_>>();

        if phase_facts.is_empty() {
            if phase == SccmDistributionPointContentPhase::ServeOrReport {
                outcome = Some(if envelope.facts.iter().any(|fact| fact.phase == phase) {
                    SccmDistributionPointContentState::Contradictory
                } else {
                    SccmDistributionPointContentState::Succeeded
                });
            } else {
                let has_non_monotonic_or_downstream =
                    envelope.facts.iter().any(|fact| fact.phase >= phase);
                outcome = Some(if has_non_monotonic_or_downstream {
                    SccmDistributionPointContentState::Contradictory
                } else {
                    SccmDistributionPointContentState::Incomplete
                });
            }
            break;
        }

        let latest_timestamp = phase_facts
            .iter()
            .filter_map(|fact| fact.timestamp.utc_millis)
            .max()
            .expect("admitted DP facts carry normalized UTC");
        let latest_dispositions = phase_facts
            .iter()
            .filter(|fact| fact.timestamp.utc_millis == Some(latest_timestamp))
            .map(|fact| fact.disposition)
            .collect::<BTreeSet<_>>();
        selected.extend(phase_facts.iter().cloned());

        if latest_dispositions.len() != 1 {
            outcome = Some(SccmDistributionPointContentState::Contradictory);
            break;
        }
        let disposition = *latest_dispositions
            .first()
            .expect("latest DP phase has a disposition");
        if disposition == SccmDistributionPointContentDisposition::Succeeded {
            recovered |= phase_facts.iter().any(|fact| {
                fact.timestamp.utc_millis != Some(latest_timestamp)
                    && fact.disposition != SccmDistributionPointContentDisposition::Succeeded
            });
            last_proven_phase = Some(phase);
            previous_timestamp = Some(latest_timestamp);
            if phase == SccmDistributionPointContentPhase::ServeOrReport {
                outcome = Some(SccmDistributionPointContentState::Succeeded);
                break;
            }
            continue;
        }

        let has_downstream = envelope.facts.iter().any(|fact| {
            fact.phase > phase
                && fact
                    .timestamp
                    .utc_millis
                    .is_some_and(|timestamp| timestamp > latest_timestamp)
        });
        outcome = Some(if has_downstream {
            SccmDistributionPointContentState::Contradictory
        } else {
            match disposition {
                SccmDistributionPointContentDisposition::Failed => {
                    SccmDistributionPointContentState::Failed
                }
                SccmDistributionPointContentDisposition::Retrying => {
                    SccmDistributionPointContentState::Retrying
                }
                SccmDistributionPointContentDisposition::Blocked => {
                    SccmDistributionPointContentState::Blocked
                }
                SccmDistributionPointContentDisposition::Deferred => {
                    SccmDistributionPointContentState::Deferred
                }
                SccmDistributionPointContentDisposition::Succeeded => unreachable!(),
            }
        });
        break;
    }

    let state = outcome.unwrap_or(SccmDistributionPointContentState::Incomplete);
    let stop_phase = if state == SccmDistributionPointContentState::Succeeded {
        None
    } else {
        required_phases
            .into_iter()
            .find(|phase| Some(*phase) > last_proven_phase)
            .or_else(|| {
                envelope
                    .facts
                    .iter()
                    .any(|fact| fact.phase == SccmDistributionPointContentPhase::ServeOrReport)
                    .then_some(SccmDistributionPointContentPhase::ServeOrReport)
            })
    };

    let key = SccmDistributionPointContentKey {
        package_id: envelope.key.package_id,
        content_id: envelope.key.content_id,
        content_version: envelope.key.content_version,
        topology_site_handle: envelope.topology_site_handle,
        site_code: envelope.key.site_code,
        distribution_point_handle: envelope.key.distribution_point_handle,
        extraction_profile_id: SCCM_DISTRIBUTION_POINT_CONTENT_PROFILE_ID.to_owned(),
        extraction_profile_version: SCCM_DISTRIBUTION_POINT_CONTENT_PROFILE_VERSION,
    };
    let transaction_id = distribution_point_transaction_id(&key);
    let evidence = selected
        .iter()
        .map(|fact| fact.reference.clone())
        .collect::<Vec<_>>();
    let terminal_evidence = selected
        .iter()
        .filter(|fact| {
            fact.terminal && fact.disposition == SccmDistributionPointContentDisposition::Failed
        })
        .map(|fact| fact.reference.clone())
        .collect::<Vec<_>>();
    let observations = selected
        .into_iter()
        .map(|fact| SccmDistributionPointContentObservation {
            phase: fact.phase,
            disposition: fact.disposition,
            terminal: fact.terminal,
            source_id: fact.source_id,
            timestamp: fact.timestamp,
            evidence: fact.reference,
        })
        .collect::<Vec<_>>();
    let (classification, confidence, severity) = content_outcome_contract(state, last_proven_phase);
    let next_artifact = if matches!(
        state,
        SccmDistributionPointContentState::Failed | SccmDistributionPointContentState::Succeeded
    ) {
        None
    } else {
        stop_phase.map(artifact_request_for_phase)
    };

    SccmDistributionPointContentTransaction {
        transaction_id,
        key,
        state,
        classification,
        confidence,
        severity,
        scope: SccmDistributionPointContentScope::DistributionPointContent,
        last_proven_phase,
        stop_phase,
        recovered,
        content_version_mismatch: false,
        evidence,
        terminal_evidence,
        next_artifact,
        observations,
    }
}

fn content_outcome_contract(
    state: SccmDistributionPointContentState,
    last_proven_phase: Option<SccmDistributionPointContentPhase>,
) -> (
    SccmDistributionPointContentClassification,
    SccmDistributionPointContentConfidence,
    Severity,
) {
    match state {
        SccmDistributionPointContentState::Succeeded => (
            SccmDistributionPointContentClassification::Success,
            if last_proven_phase == Some(SccmDistributionPointContentPhase::ServeOrReport) {
                SccmDistributionPointContentConfidence::High
            } else {
                SccmDistributionPointContentConfidence::Medium
            },
            Severity::Success,
        ),
        SccmDistributionPointContentState::Failed => (
            SccmDistributionPointContentClassification::ConfirmedFailure,
            SccmDistributionPointContentConfidence::High,
            Severity::Error,
        ),
        SccmDistributionPointContentState::Retrying
        | SccmDistributionPointContentState::Blocked
        | SccmDistributionPointContentState::Deferred => (
            SccmDistributionPointContentClassification::BlockedOrDeferred,
            SccmDistributionPointContentConfidence::Medium,
            Severity::Warning,
        ),
        SccmDistributionPointContentState::Contradictory => (
            SccmDistributionPointContentClassification::ContradictoryEvidence,
            SccmDistributionPointContentConfidence::Low,
            Severity::Error,
        ),
        SccmDistributionPointContentState::Incomplete => (
            SccmDistributionPointContentClassification::InsufficientEvidence,
            SccmDistributionPointContentConfidence::Low,
            Severity::Warning,
        ),
    }
}

fn artifact_request_for_phase(phase: SccmDistributionPointContentPhase) -> SccmArtifactRequest {
    match phase {
        SccmDistributionPointContentPhase::ReceiveContent
        | SccmDistributionPointContentPhase::Distribute => SccmArtifactRequest {
            logical_id: "distmgr".to_owned(),
            role: SccmRole::SiteServer,
            reason: "Collect the complete distmgr.log file.".to_owned(),
        },
        SccmDistributionPointContentPhase::Transfer => SccmArtifactRequest {
            logical_id: "pkgXferMgr".to_owned(),
            role: SccmRole::SiteServer,
            reason: "Collect the complete PkgXferMgr.log file.".to_owned(),
        },
        SccmDistributionPointContentPhase::Validate
        | SccmDistributionPointContentPhase::MakeAvailable => SccmArtifactRequest {
            logical_id: "smsDpProv".to_owned(),
            role: SccmRole::DistributionPoint,
            reason: "Collect the complete SMSDPProv.log file.".to_owned(),
        },
        SccmDistributionPointContentPhase::ServeOrReport => SccmArtifactRequest {
            logical_id: "smsDpmon".to_owned(),
            role: SccmRole::DistributionPoint,
            reason: "Collect the complete SMSdpmon.log file.".to_owned(),
        },
    }
}

fn distribution_point_transaction_id(key: &SccmDistributionPointContentKey) -> String {
    format!(
        "dp:topology-site={}:site={}:package={}:content={}:content-version={}:dp={}:profile={}:profile-version={}",
        key.topology_site_handle,
        key.site_code,
        key.package_id,
        key.content_id,
        key.content_version,
        key.distribution_point_handle,
        key.extraction_profile_id,
        key.extraction_profile_version,
    )
}

fn exact_message_token<'a>(message: &'a str, label: &str) -> Option<&'a str> {
    let prefix = format!("{label}=");
    let mut values = message
        .split(';')
        .map(str::trim)
        .filter_map(|segment| segment.strip_prefix(&prefix));
    let value = values.next()?;
    values.next().is_none().then_some(value)
}

fn content_phase(value: &str) -> Option<SccmDistributionPointContentPhase> {
    match value {
        "receiveContent" => Some(SccmDistributionPointContentPhase::ReceiveContent),
        "distribute" => Some(SccmDistributionPointContentPhase::Distribute),
        "transfer" => Some(SccmDistributionPointContentPhase::Transfer),
        "validate" => Some(SccmDistributionPointContentPhase::Validate),
        "makeAvailable" => Some(SccmDistributionPointContentPhase::MakeAvailable),
        "serveOrReport" => Some(SccmDistributionPointContentPhase::ServeOrReport),
        _ => None,
    }
}

fn content_disposition(value: &str) -> Option<SccmDistributionPointContentDisposition> {
    match value {
        "succeeded" => Some(SccmDistributionPointContentDisposition::Succeeded),
        "failed" => Some(SccmDistributionPointContentDisposition::Failed),
        "retrying" => Some(SccmDistributionPointContentDisposition::Retrying),
        "blocked" => Some(SccmDistributionPointContentDisposition::Blocked),
        "deferred" => Some(SccmDistributionPointContentDisposition::Deferred),
        _ => None,
    }
}

fn safe_package_id(value: &str) -> bool {
    (3..=32).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

fn safe_content_id(value: &str) -> bool {
    (3..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn safe_site_code(value: &str) -> bool {
    value.len() == 3 && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

fn safe_distribution_point_handle(value: &str) -> bool {
    matches!(value, "synthetic:subject:dp-01" | "synthetic:subject:dp-02")
}

fn intake_authority_invalid_analysis() -> SccmDistributionPointAnalysis {
    let coverage_gaps = vec![SccmDistributionPointCoverageGap {
        source_id: SCCM_DISTRIBUTION_POINT_SOURCE_ID.to_owned(),
        producer_role: None,
        workflow_subject_role: Some(SccmRole::DistributionPoint),
        state: Some(SccmCoverageState::ParseFailed),
        artifact_ids: Vec::new(),
        reason: SCCM_DISTRIBUTION_POINT_INTAKE_AUTHORITY_REASON.to_owned(),
    }];
    let artifact_requests = artifact_requests(&coverage_gaps);

    SccmDistributionPointAnalysis {
        schema_version: SCCM_DISTRIBUTION_POINT_ANALYSIS_SCHEMA_VERSION,
        workflow: SccmDistributionPointWorkflow::DistributionPointContent,
        profile: SccmDistributionPointProfile {
            id: SCCM_DISTRIBUTION_POINT_INTAKE_PROFILE_ID.to_owned(),
            version: SCCM_DISTRIBUTION_POINT_INTAKE_PROFILE_VERSION,
            stability: "experimental".to_owned(),
        },
        source_observations: Vec::new(),
        coverage_gaps,
        artifact_requests,
        cross_side_correlation_performed: false,
    }
}

fn is_dp_distribution_artifact(artifact: &SccmServerArtifactAssessment) -> bool {
    let Some(basename) = artifact.original_basename.as_deref() else {
        return false;
    };
    let classified = classify_artifact_name(basename, artifact.producer_role.clone());

    matches!(
        artifact.source_id.as_str(),
        SCCM_DISTRIBUTION_POINT_SOURCE_ID | "server-dp-serve"
    ) && artifact.source_kind == "ccmLog"
        && artifact.family == SccmArtifactFamily::DistributionPoint
        && classified.supported_for_diagnosis
        && declared_server_source_catalog().iter().any(|spec| {
            spec.source_id == artifact.source_id
                && spec.producer_role == artifact.producer_role
                && spec.workflow_subject_role.as_ref() == artifact.workflow_subject_role.as_ref()
                && spec.source_kind == SccmServerSourceKind::CcmLog
                && spec
                    .logical_names
                    .iter()
                    .any(|logical_name| *logical_name == classified.logical_name)
        })
}

fn admitted_for_source_observation(
    artifact: &SccmServerArtifactAssessment,
    evidence: &SccmEvidence,
) -> bool {
    artifact.state == SccmCoverageState::Captured
        && artifact.profile_eligible
        && artifact.parser_eligible
        && artifact.fragment_complete != Some(false)
        && evidence.role == artifact.producer_role
        && evidence.timestamp.ordering_state == SccmTimeOrderingState::NormalizedUtc
}

fn artifact_metadata_is_congruent(
    intake: &SccmServerIntakeAssessment,
    artifact: &SccmServerArtifactAssessment,
    artifact_id_counts: &BTreeMap<&str, usize>,
) -> bool {
    artifact.state == SccmCoverageState::Captured
        && artifact.profile_eligible
        && artifact.parser_eligible
        && artifact.fragment_complete != Some(false)
        && rotation_is_canonical_for_artifact(artifact)
        && safe_assessed_handle(&intake.topology.capture_host_handle)
        && safe_assessed_handle(&intake.topology.site_handle)
        && artifact
            .producer_host_handle
            .as_deref()
            .is_some_and(safe_assessed_handle)
        && subject_handle_is_congruent(artifact)
        && topology_is_congruent(intake, artifact)
        && coverage_is_congruent(intake, artifact, artifact_id_counts)
}

fn rotation_is_canonical_for_artifact(artifact: &SccmServerArtifactAssessment) -> bool {
    let Some(basename) = artifact.original_basename.as_deref() else {
        return false;
    };
    let classified = classify_artifact_name(basename, artifact.producer_role.clone());
    artifact.rotation.as_ref() == Some(&classified.rotation)
        && safe_assessed_handle(&artifact.rotation_lineage_handle)
}

fn safe_assessed_handle(value: &str) -> bool {
    !value.is_empty()
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && value.len() <= 256
}

fn subject_handle_is_congruent(artifact: &SccmServerArtifactAssessment) -> bool {
    match (
        &artifact.producer_role,
        artifact.workflow_subject_role.as_ref(),
        artifact.workflow_subject_handle.as_deref(),
    ) {
        (SccmRole::SiteServer, Some(SccmRole::DistributionPoint), Some(handle)) => {
            safe_assessed_handle(handle)
        }
        (SccmRole::DistributionPoint, None, None) => true,
        _ => false,
    }
}

fn topology_is_congruent(
    intake: &SccmServerIntakeAssessment,
    artifact: &SccmServerArtifactAssessment,
) -> bool {
    role_occurrences(&intake.topology.roles_observed, &artifact.producer_role) == 1
        && artifact
            .workflow_subject_role
            .as_ref()
            .is_none_or(|role| role_occurrences(&intake.topology.roles_observed, role) == 1)
}

fn role_occurrences(roles: &[SccmRole], expected: &SccmRole) -> usize {
    roles.iter().filter(|role| *role == expected).count()
}

fn coverage_is_congruent(
    intake: &SccmServerIntakeAssessment,
    artifact: &SccmServerArtifactAssessment,
    artifact_id_counts: &BTreeMap<&str, usize>,
) -> bool {
    let memberships = intake
        .coverage
        .iter()
        .filter(|coverage| {
            coverage
                .artifact_ids
                .iter()
                .any(|artifact_id| artifact_id == &artifact.artifact_id)
        })
        .collect::<Vec<_>>();
    let Some(coverage) = memberships.first() else {
        return false;
    };
    memberships.len() == 1
        && coverage
            .artifact_ids
            .iter()
            .filter(|artifact_id| *artifact_id == &artifact.artifact_id)
            .count()
            == 1
        && coverage.producer_role == artifact.producer_role
        && coverage.producer_host_handle == artifact.producer_host_handle
        && coverage.workflow_subject_role == artifact.workflow_subject_role
        && coverage.workflow_subject_handle == artifact.workflow_subject_handle
        && coverage.source_id == artifact.source_id
        && coverage.state == artifact.state
        && coverage.artifact_ids.iter().all(|artifact_id| {
            artifact_id_counts
                .get(artifact_id.as_str())
                .is_some_and(|count| *count == 1)
                && intake.artifacts.iter().any(|candidate| {
                    candidate.artifact_id == *artifact_id
                        && candidate.producer_role == coverage.producer_role
                        && candidate.producer_host_handle == coverage.producer_host_handle
                        && candidate.workflow_subject_role == coverage.workflow_subject_role
                        && candidate.workflow_subject_handle == coverage.workflow_subject_handle
                        && candidate.source_id == coverage.source_id
                        && candidate.state == coverage.state
                        && is_dp_distribution_artifact(candidate)
                        && rotation_is_canonical_for_artifact(candidate)
                })
        })
}

fn canonical_evidence_set(
    artifact: &SccmServerArtifactAssessment,
    evidence: &[&SccmEvidence],
) -> bool {
    if evidence.is_empty() {
        return false;
    }

    let mut ranges = Vec::with_capacity(evidence.len());
    let mut evidence_ids = BTreeSet::new();
    let mut entry_ids = BTreeSet::new();
    for item in evidence {
        let (Some(line_start), Some(line_end)) =
            (item.reference.line_start, item.reference.line_end)
        else {
            return false;
        };
        let expected_entry_id = format!("{}:{line_start}-{line_end}", artifact.artifact_id);
        if line_start == 0
            || line_end < line_start
            || item.reference.artifact_id != artifact.artifact_id
            || item.reference.entry_id != expected_entry_id
            || item.evidence_id != item.reference.entry_id
            || !evidence_ids.insert(item.evidence_id.as_str())
            || !entry_ids.insert(item.reference.entry_id.as_str())
            || item.role != artifact.producer_role
            || item.timestamp.ordering_state != SccmTimeOrderingState::NormalizedUtc
            || item.timestamp.offset_minutes.is_none()
            || item.timestamp.utc_millis.is_none()
        {
            return false;
        }
        ranges.push((line_start, line_end));
    }

    ranges.sort_unstable();
    ranges
        .windows(2)
        .all(|pair| pair[0].1.checked_add(1) == Some(pair[1].0))
}

fn coverage_gaps(
    intake: &SccmServerIntakeAssessment,
    observations: &[SccmDistributionPointSourceObservation],
) -> Vec<SccmDistributionPointCoverageGap> {
    let observed_artifact_ids = observations
        .iter()
        .map(|observation| observation.artifact_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut gaps = intake
        .coverage
        .iter()
        .filter(|coverage| is_dp_distribution_coverage(coverage))
        .filter_map(|coverage| {
            let mut artifact_ids = coverage.artifact_ids.clone();
            artifact_ids.sort();
            let all_admitted = coverage.state == SccmCoverageState::Captured
                && !artifact_ids.is_empty()
                && artifact_ids
                    .iter()
                    .all(|artifact_id| observed_artifact_ids.contains(artifact_id.as_str()));
            (!all_admitted).then(|| SccmDistributionPointCoverageGap {
                source_id: coverage.source_id.clone(),
                producer_role: Some(coverage.producer_role.clone()),
                workflow_subject_role: coverage.workflow_subject_role.clone(),
                state: Some(coverage.state.clone()),
                artifact_ids,
                reason: coverage_gap_reason(coverage, &observed_artifact_ids),
            })
        })
        .collect::<Vec<_>>();

    if !intake.coverage.iter().any(is_dp_distribution_coverage) {
        gaps.push(SccmDistributionPointCoverageGap {
            source_id: SCCM_DISTRIBUTION_POINT_SOURCE_ID.to_owned(),
            producer_role: None,
            workflow_subject_role: Some(SccmRole::DistributionPoint),
            state: None,
            artifact_ids: Vec::new(),
            reason: "No declared Distribution Point distribution source was supplied.".to_owned(),
        });
    }

    gaps
}

fn is_dp_distribution_coverage(coverage: &SccmServerCoverage) -> bool {
    coverage.source_id == SCCM_DISTRIBUTION_POINT_SOURCE_ID
        && matches!(
            (
                &coverage.producer_role,
                coverage.workflow_subject_role.as_ref()
            ),
            (SccmRole::SiteServer, Some(SccmRole::DistributionPoint))
                | (SccmRole::DistributionPoint, None)
        )
}

fn coverage_gap_reason(
    coverage: &SccmServerCoverage,
    observed_artifact_ids: &BTreeSet<&str>,
) -> String {
    if coverage.state != SccmCoverageState::Captured {
        return format!(
            "Distribution Point source coverage is {}; recollect the declared source without changing its state.",
            coverage_state_label(&coverage.state)
        );
    }
    if coverage
        .artifact_ids
        .iter()
        .any(|artifact_id| !observed_artifact_ids.contains(artifact_id.as_str()))
    {
        return "Captured Distribution Point evidence is incomplete or outside the supported intake profile."
            .to_owned();
    }
    "Distribution Point coverage requires a complete supported source.".to_owned()
}

fn artifact_requests(gaps: &[SccmDistributionPointCoverageGap]) -> Vec<SccmArtifactRequest> {
    let mut requests = Vec::with_capacity(gaps.len());
    for gap in gaps {
        if gap.producer_role.is_none() {
            // An unscoped coverage gap does not identify a failed source. Ask
            // for the bounded sources required by the healthy DP profile.
            requests.push(SccmArtifactRequest {
                logical_id: "distmgr".to_owned(),
                role: SccmRole::SiteServer,
                reason: "Collect the complete distmgr.log file.".to_owned(),
            });
            requests.push(SccmArtifactRequest {
                logical_id: "pkgXferMgr".to_owned(),
                role: SccmRole::SiteServer,
                reason: "Collect the complete PkgXferMgr.log file.".to_owned(),
            });
            requests.push(SccmArtifactRequest {
                logical_id: "smsDpProv".to_owned(),
                role: SccmRole::DistributionPoint,
                reason: "Collect the complete SMSDPProv.log file.".to_owned(),
            });
        } else if gap.producer_role == Some(SccmRole::DistributionPoint) {
            requests.push(SccmArtifactRequest {
                logical_id: "smsDpProv".to_owned(),
                role: SccmRole::DistributionPoint,
                reason: "Collect the complete SMSDPProv.log file.".to_owned(),
            });
        } else {
            requests.push(SccmArtifactRequest {
                logical_id: "distmgr".to_owned(),
                role: SccmRole::SiteServer,
                reason: "Collect the complete distmgr.log file.".to_owned(),
            });
            requests.push(SccmArtifactRequest {
                logical_id: "pkgXferMgr".to_owned(),
                role: SccmRole::SiteServer,
                reason: "Collect the complete PkgXferMgr.log file.".to_owned(),
            });
        }
    }
    requests.sort_by(|left, right| {
        (
            left.logical_id.as_str(),
            role_sort_key(&left.role),
            left.reason.as_str(),
        )
            .cmp(&(
                right.logical_id.as_str(),
                role_sort_key(&right.role),
                right.reason.as_str(),
            ))
    });
    requests.dedup_by(|left, right| {
        left.logical_id == right.logical_id
            && left.role == right.role
            && left.reason == right.reason
    });
    requests
}

fn source_observation_sort_key(
    observation: &SccmDistributionPointSourceObservation,
) -> (String, u32, u32, String) {
    (
        observation.artifact_id.clone(),
        observation.evidence.line_start.unwrap_or_default(),
        observation.evidence.line_end.unwrap_or_default(),
        observation.evidence.entry_id.clone(),
    )
}

fn coverage_gap_sort_key(
    gap: &SccmDistributionPointCoverageGap,
) -> (String, String, String, String, Vec<String>) {
    (
        gap.source_id.clone(),
        gap.producer_role
            .as_ref()
            .map(role_sort_key)
            .unwrap_or_default()
            .to_owned(),
        gap.workflow_subject_role
            .as_ref()
            .map(role_sort_key)
            .unwrap_or_default()
            .to_owned(),
        gap.state
            .as_ref()
            .map(coverage_state_label)
            .unwrap_or_default()
            .to_owned(),
        gap.artifact_ids.clone(),
    )
}

fn coverage_state_label(state: &SccmCoverageState) -> &'static str {
    match state {
        SccmCoverageState::Captured => "captured",
        SccmCoverageState::Absent => "absent",
        SccmCoverageState::AccessDenied => "accessDenied",
        SccmCoverageState::Capped => "capped",
        SccmCoverageState::Skipped => "skipped",
        SccmCoverageState::Unsupported => "unsupported",
        SccmCoverageState::ParseFailed => "parseFailed",
    }
}

fn role_sort_key(role: &SccmRole) -> &str {
    match role {
        SccmRole::Client => "client",
        SccmRole::SiteServer => "siteServer",
        SccmRole::ManagementPoint => "managementPoint",
        SccmRole::DistributionPoint => "distributionPoint",
        SccmRole::SoftwareUpdatePoint => "softwareUpdatePoint",
        SccmRole::WsUs => "wsUs",
        SccmRole::Provider => "provider",
        SccmRole::AdminService => "adminService",
        SccmRole::Unknown(value) => value,
    }
}

#[cfg(test)]
mod artifact_request_tests {
    use super::*;

    fn gap(producer_role: Option<SccmRole>) -> SccmDistributionPointCoverageGap {
        SccmDistributionPointCoverageGap {
            source_id: SCCM_DISTRIBUTION_POINT_SOURCE_ID.to_owned(),
            producer_role,
            workflow_subject_role: Some(SccmRole::DistributionPoint),
            state: Some(SccmCoverageState::Absent),
            artifact_ids: Vec::new(),
            reason: "controlled coverage gap".to_owned(),
        }
    }

    fn contracts(requests: &[SccmArtifactRequest]) -> Vec<(&str, SccmRole, &str)> {
        requests
            .iter()
            .map(|request| {
                (
                    request.logical_id.as_str(),
                    request.role.clone(),
                    request.reason.as_str(),
                )
            })
            .collect()
    }

    fn expected_site_requests() -> Vec<(&'static str, SccmRole, &'static str)> {
        vec![
            (
                "distmgr",
                SccmRole::SiteServer,
                "Collect the complete distmgr.log file.",
            ),
            (
                "pkgXferMgr",
                SccmRole::SiteServer,
                "Collect the complete PkgXferMgr.log file.",
            ),
        ]
    }

    fn expected_all_requests() -> Vec<(&'static str, SccmRole, &'static str)> {
        let mut requests = expected_site_requests();
        requests.push((
            "smsDpProv",
            SccmRole::DistributionPoint,
            "Collect the complete SMSDPProv.log file.",
        ));
        requests
    }

    fn expected_dp_requests() -> Vec<(&'static str, SccmRole, &'static str)> {
        vec![(
            "smsDpProv",
            SccmRole::DistributionPoint,
            "Collect the complete SMSDPProv.log file.",
        )]
    }

    #[test]
    fn artifact_requests_cover_required_sources_by_gap_scope_deterministically() {
        let site_gap = gap(Some(SccmRole::SiteServer));
        let site_requests = artifact_requests(&[site_gap.clone(), site_gap.clone()]);
        assert_eq!(contracts(&site_requests), expected_site_requests());

        let unscoped_gap = gap(None);
        let unscoped_requests = artifact_requests(&[unscoped_gap.clone(), unscoped_gap.clone()]);
        assert_eq!(contracts(&unscoped_requests), expected_all_requests());

        let dp_gap = gap(Some(SccmRole::DistributionPoint));
        let dp_requests = artifact_requests(&[dp_gap.clone(), dp_gap.clone()]);
        assert_eq!(contracts(&dp_requests), expected_dp_requests());

        let forward = artifact_requests(&[site_gap.clone(), unscoped_gap.clone(), dp_gap.clone()]);
        let reversed = artifact_requests(&[dp_gap, unscoped_gap, site_gap]);
        assert_eq!(forward, reversed);
    }
}

#[cfg(test)]
mod content_identity_tests {
    use super::*;

    fn key(
        site_code: &str,
        profile_id: &str,
        profile_version: u32,
    ) -> SccmDistributionPointContentKey {
        SccmDistributionPointContentKey {
            package_id: "LAB00001".to_owned(),
            content_id: "content-alpha".to_owned(),
            content_version: 1,
            topology_site_handle: "synthetic:site:lab".to_owned(),
            site_code: site_code.to_owned(),
            distribution_point_handle: "safe:dp:lab-dp-01".to_owned(),
            extraction_profile_id: profile_id.to_owned(),
            extraction_profile_version: profile_version,
        }
    }

    #[test]
    fn transaction_identity_includes_site_topology_and_profile_version_deterministically() {
        let lab = key("LAB", "dp-server-5.00.test-v1", 1);
        let abc = key("ABC", "dp-server-5.00.test-v1", 1);
        let profile_v2 = key("LAB", "dp-server-5.00.test-v2", 2);

        assert_eq!(
            distribution_point_transaction_id(&lab),
            "dp:topology-site=synthetic:site:lab:site=LAB:package=LAB00001:content=content-alpha:content-version=1:dp=safe:dp:lab-dp-01:profile=dp-server-5.00.test-v1:profile-version=1"
        );
        assert_ne!(
            distribution_point_transaction_id(&lab),
            distribution_point_transaction_id(&abc)
        );
        assert_ne!(
            distribution_point_transaction_id(&lab),
            distribution_point_transaction_id(&profile_v2)
        );

        let mut forward = [&lab, &abc, &profile_v2]
            .into_iter()
            .map(distribution_point_transaction_id)
            .collect::<Vec<_>>();
        let mut reversed = [&profile_v2, &abc, &lab]
            .into_iter()
            .map(distribution_point_transaction_id)
            .collect::<Vec<_>>();
        forward.sort();
        reversed.sort();
        assert_eq!(forward, reversed);
    }

    #[test]
    fn transaction_identity_distinguishes_canonical_topology_with_identical_message_keys() {
        let lab = SccmDistributionPointContentKey {
            package_id: "LAB00001".to_owned(),
            content_id: "content-alpha".to_owned(),
            content_version: 1,
            topology_site_handle: "synthetic:site:lab".to_owned(),
            site_code: "LAB".to_owned(),
            distribution_point_handle: "safe:dp:lab-dp-01".to_owned(),
            extraction_profile_id: "dp-server-5.00.test-v1".to_owned(),
            extraction_profile_version: 1,
        };
        let peer = SccmDistributionPointContentKey {
            topology_site_handle: "synthetic:site:lab-peer".to_owned(),
            ..lab.clone()
        };

        let lab_id = distribution_point_transaction_id(&lab);
        let peer_id = distribution_point_transaction_id(&peer);
        assert_ne!(lab, peer);
        assert_ne!(lab_id, peer_id);

        let mut forward = [lab_id.as_str(), peer_id.as_str()];
        let mut reversed = [peer_id.as_str(), lab_id.as_str()];
        forward.sort();
        reversed.sort();
        assert_eq!(forward, reversed);
    }
}
