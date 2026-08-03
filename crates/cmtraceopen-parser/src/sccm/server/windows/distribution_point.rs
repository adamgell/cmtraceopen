//! Canonical-intake adapter for Distribution Point source evidence.
//!
//! This is deliberately an evidence and coverage reducer, not a content
//! transaction reducer. It consumes the already-normalized server intake
//! assessment and admits only the declared DP distribution CCM sources. Until
//! a versioned semantic fact profile is independently validated, it makes no
//! package outcome, client-impact, or cross-side causal claim.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use thiserror::Error;

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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmDistributionPointContentClassification {
    Success,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmDistributionPointContentConfidence {
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmDistributionPointContentKey {
    pub package_id: String,
    pub content_id: String,
    pub content_version: u32,
    pub site_code: String,
    pub distribution_point_handle: String,
    pub extraction_profile_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmDistributionPointContentObservation {
    pub phase: SccmDistributionPointContentPhase,
    pub terminal: bool,
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
    pub last_successful_phase: SccmDistributionPointContentPhase,
    pub evidence: Vec<SccmEvidenceRef>,
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
    terminal: bool,
    reference: SccmEvidenceRef,
    timestamp: SccmTimestamp,
}

/// Private canonical transaction envelope. Facts only originate from an
/// integrity-bound server intake assessment; callers cannot construct or
/// submit source facts directly.
#[derive(Debug)]
struct DistributionPointTransactionEnvelope {
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

/// Reduce the approved synthetic DP package profile from canonical server
/// intake. This first slice recognizes only a complete, source-local healthy
/// transaction; incomplete, retry, and terminal-failure facts intentionally
/// remain outside this API until their dedicated contracts are reviewed.
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
        let Some(fact) = parse_healthy_distribution_point_fact(
            observation,
            artifact,
            evidence,
            expected_site_code,
        ) else {
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
        let missing_roles = missing_healthy_phase_roles(&facts);
        let gap_facts = facts.clone();
        if let Some(transaction) =
            reduce_healthy_transaction(DistributionPointTransactionEnvelope { key, facts })
        {
            transactions.push(transaction);
            continue;
        }

        let mut matched_missing_role = false;
        for fact in &gap_facts {
            let artifact = artifacts_by_id
                .get(fact.reference.artifact_id.as_str())
                .copied();
            if artifact.is_some_and(|artifact| missing_roles.contains(&artifact.producer_role)) {
                note_semantic_gap(&mut semantic_gaps, artifact);
                matched_missing_role = true;
            }
        }
        if !matched_missing_role {
            for fact in &gap_facts {
                note_semantic_gap(
                    &mut semantic_gaps,
                    artifacts_by_id
                        .get(fact.reference.artifact_id.as_str())
                        .copied(),
                );
            }
        }
    }
    transactions.sort_by(|left, right| left.transaction_id.cmp(&right.transaction_id));

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
    let artifact_requests = artifact_requests(&coverage_gaps);
    if !coverage_gaps.is_empty() {
        for transaction in &mut transactions {
            transaction.confidence = SccmDistributionPointContentConfidence::Medium;
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

fn missing_healthy_phase_roles(facts: &[DistributionPointFact]) -> Vec<SccmRole> {
    let expected = [
        (
            SccmDistributionPointContentPhase::ReceiveContent,
            SccmRole::SiteServer,
        ),
        (
            SccmDistributionPointContentPhase::Distribute,
            SccmRole::SiteServer,
        ),
        (
            SccmDistributionPointContentPhase::Transfer,
            SccmRole::SiteServer,
        ),
        (
            SccmDistributionPointContentPhase::Validate,
            SccmRole::DistributionPoint,
        ),
        (
            SccmDistributionPointContentPhase::MakeAvailable,
            SccmRole::DistributionPoint,
        ),
        (
            SccmDistributionPointContentPhase::ServeOrReport,
            SccmRole::DistributionPoint,
        ),
    ];
    let mut roles = Vec::new();
    for (phase, role) in expected {
        if !facts.iter().any(|fact| fact.phase == phase) && !roles.contains(&role) {
            roles.push(role);
        }
    }
    roles
}

fn parse_healthy_distribution_point_fact(
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
    let profile_id = exact_message_token(&evidence.message, "ProfileId")?;

    if disposition != "succeeded"
        || profile_id != SCCM_DISTRIBUTION_POINT_CONTENT_PROFILE_ID
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
        | SccmDistributionPointContentPhase::MakeAvailable
        | SccmDistributionPointContentPhase::ServeOrReport => {
            observation.producer_role == SccmRole::DistributionPoint
                && artifact.original_basename.as_deref() == Some("SMSDPProv.log")
        }
    };
    let observed_distribution_point = match observation.producer_role {
        SccmRole::SiteServer => observation.workflow_subject_handle.as_deref(),
        SccmRole::DistributionPoint => observation.producer_host_handle.as_deref(),
        _ => None,
    };
    let expected_terminal = if phase == SccmDistributionPointContentPhase::ServeOrReport {
        "true"
    } else {
        "false"
    };
    if !expected_source
        || observed_distribution_point != Some(distribution_point_handle)
        || terminal != expected_terminal
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
        terminal: terminal == "true",
        reference: evidence.reference.clone(),
        timestamp: evidence.timestamp.clone(),
    })
}

fn selected_content_profile_site_code(topology_site_handle: &str) -> Option<&'static str> {
    match topology_site_handle {
        "synthetic:site:lab" => Some("LAB"),
        _ => None,
    }
}

fn reduce_healthy_transaction(
    mut envelope: DistributionPointTransactionEnvelope,
) -> Option<SccmDistributionPointContentTransaction> {
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
    let expected_phases = [
        SccmDistributionPointContentPhase::ReceiveContent,
        SccmDistributionPointContentPhase::Distribute,
        SccmDistributionPointContentPhase::Transfer,
        SccmDistributionPointContentPhase::Validate,
        SccmDistributionPointContentPhase::MakeAvailable,
        SccmDistributionPointContentPhase::ServeOrReport,
    ];
    if envelope.facts.len() != expected_phases.len()
        || envelope
            .facts
            .iter()
            .zip(expected_phases)
            .any(|(fact, expected)| fact.phase != expected)
    {
        return None;
    }

    let mut previous_timestamp = None;
    for fact in &envelope.facts {
        let timestamp = fact.timestamp.utc_millis?;
        if previous_timestamp.is_some_and(|previous| timestamp <= previous) {
            return None;
        }
        previous_timestamp = Some(timestamp);
    }
    if envelope.facts.iter().any(|fact| {
        fact.terminal != (fact.phase == SccmDistributionPointContentPhase::ServeOrReport)
    }) {
        return None;
    }

    let key = SccmDistributionPointContentKey {
        package_id: envelope.key.package_id,
        content_id: envelope.key.content_id,
        content_version: envelope.key.content_version,
        site_code: envelope.key.site_code,
        distribution_point_handle: envelope.key.distribution_point_handle,
        extraction_profile_id: SCCM_DISTRIBUTION_POINT_CONTENT_PROFILE_ID.to_owned(),
    };
    let transaction_id = format!(
        "dp:{}:{}:v{}:{}",
        key.package_id, key.content_id, key.content_version, key.distribution_point_handle
    );
    let evidence = envelope
        .facts
        .iter()
        .map(|fact| fact.reference.clone())
        .collect::<Vec<_>>();
    let observations = envelope
        .facts
        .into_iter()
        .map(|fact| SccmDistributionPointContentObservation {
            phase: fact.phase,
            terminal: fact.terminal,
            timestamp: fact.timestamp,
            evidence: fact.reference,
        })
        .collect::<Vec<_>>();

    Some(SccmDistributionPointContentTransaction {
        transaction_id,
        key,
        state: SccmDistributionPointContentState::Succeeded,
        classification: SccmDistributionPointContentClassification::Success,
        confidence: SccmDistributionPointContentConfidence::High,
        last_successful_phase: SccmDistributionPointContentPhase::ServeOrReport,
        evidence,
        observations,
    })
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
    value
        .strip_prefix("safe:dp:")
        .is_some_and(|handle| !handle.is_empty() && handle.len() <= 128 && !handle.contains(".."))
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

    artifact.source_id == SCCM_DISTRIBUTION_POINT_SOURCE_ID
        && artifact.source_kind == "ccmLog"
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
        && intake.source_version_is_profile_eligible(artifact.source_version.as_deref())
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
            // for one bounded representative from each DP side; later
            // source-specific gaps may request PkgXferMgr or PullDP exactly.
            requests.push(SccmArtifactRequest {
                logical_id: "distmgr".to_owned(),
                role: SccmRole::SiteServer,
                reason: "Collect the complete distmgr.log file.".to_owned(),
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
