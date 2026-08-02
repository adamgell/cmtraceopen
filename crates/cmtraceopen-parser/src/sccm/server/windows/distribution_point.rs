//! Canonical-intake adapter for Distribution Point source evidence.
//!
//! This is deliberately an evidence and coverage reducer, not a content
//! transaction reducer. It consumes the already-normalized server intake
//! assessment and admits only the declared DP distribution CCM sources. Until
//! a versioned semantic fact profile is independently validated, it makes no
//! package outcome, client-impact, or cross-side causal claim.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::sccm::{
    classify_artifact_name, SccmArtifactFamily, SccmArtifactRequest, SccmCoverageState,
    SccmEvidenceRef, SccmRole, SccmRotation, SccmTimeOrderingState, SccmTimestamp,
};

use super::{
    declared_server_source_catalog, SccmServerArtifactAssessment, SccmServerCoverage,
    SccmServerIntakeAssessment, SccmServerSourceKind,
};

pub const SCCM_DISTRIBUTION_POINT_ANALYSIS_SCHEMA_VERSION: u32 = 1;
pub const SCCM_DISTRIBUTION_POINT_INTAKE_PROFILE_ID: &str = "sccm-dp-intake-envelope";
pub const SCCM_DISTRIBUTION_POINT_INTAKE_PROFILE_VERSION: u32 = 1;
pub const SCCM_DISTRIBUTION_POINT_SOURCE_ID: &str = "server-dp-distribution";

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

/// Project only complete, profile-eligible logical CCM records from the
/// canonical server intake. The output is source-local and intentionally does
/// not interpret message text as a package/content success or failure.
pub fn analyze_distribution_point(
    intake: &SccmServerIntakeAssessment,
) -> SccmDistributionPointAnalysis {
    let artifacts = intake
        .artifacts
        .iter()
        .filter(|artifact| is_dp_distribution_artifact(artifact))
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

    let mut coverage_gaps = coverage_gaps(intake, &artifacts, &source_observations);
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
    evidence: &crate::sccm::SccmEvidence,
) -> bool {
    artifact.state == SccmCoverageState::Captured
        && artifact.profile_eligible
        && artifact.parser_eligible
        && artifact.fragment_complete != Some(false)
        && evidence.role == artifact.producer_role
        && evidence.timestamp.ordering_state == SccmTimeOrderingState::NormalizedUtc
}

fn coverage_gaps(
    intake: &SccmServerIntakeAssessment,
    artifacts: &BTreeMap<&str, &SccmServerArtifactAssessment>,
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
            let artifact_ids = coverage
                .artifact_ids
                .iter()
                .filter(|artifact_id| artifacts.contains_key(artifact_id.as_str()))
                .cloned()
                .collect::<Vec<_>>();
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
            "Distribution Point source coverage is {:?}; recollect the declared source without changing its state.",
            coverage.state
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
    let mut requests = gaps
        .iter()
        .map(|gap| match gap.producer_role.as_ref() {
            Some(SccmRole::DistributionPoint) => SccmArtifactRequest {
                logical_id: "smsDpProv".to_owned(),
                role: SccmRole::DistributionPoint,
                reason: "Collect the complete SMSDPProv.log file.".to_owned(),
            },
            _ => SccmArtifactRequest {
                logical_id: "distmgr".to_owned(),
                role: SccmRole::SiteServer,
                reason: "Collect the complete distmgr.log file.".to_owned(),
            },
        })
        .collect::<Vec<_>>();
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
        format!("{:?}", gap.state),
        gap.artifact_ids.clone(),
    )
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
