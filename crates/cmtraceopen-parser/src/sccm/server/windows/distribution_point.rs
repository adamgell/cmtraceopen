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
    evidence: &crate::sccm::SccmEvidence,
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
        && supported_source_version(artifact.source_version.as_deref())
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

fn supported_source_version(value: Option<&str>) -> bool {
    let Some(value) = value else {
        return false;
    };
    if value == "5.00.TEST" {
        return true;
    }
    let mut parts = value.split('.');
    matches!(
        (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ),
        (Some("5"), Some("00"), Some(build), Some(revision), None)
            if build.len() == 4
                && revision.len() == 4
                && build.bytes().all(|byte| byte.is_ascii_digit())
                && revision.bytes().all(|byte| byte.is_ascii_digit())
    )
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
