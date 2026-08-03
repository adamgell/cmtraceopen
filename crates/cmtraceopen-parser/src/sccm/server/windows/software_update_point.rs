//! Coverage-only projection for Software Update Point and supplemental WSUS intake.
//!
//! This adapter intentionally projects no parsed evidence, health, transaction,
//! or outcome interpretation. Canonical server intake owns source admission,
//! topology, and bounded recollection requests; this module retains that
//! coverage provenance as a deterministic, source-local view.

use serde::Serialize;

use crate::sccm::{SccmArtifactFamily, SccmArtifactRequest, SccmCoverageState, SccmRole};

use super::{declared_server_source_catalog, SccmServerIntakeAssessment};

pub const SCCM_SOFTWARE_UPDATE_POINT_ANALYSIS_SCHEMA_VERSION: u32 = 1;
pub const SCCM_SOFTWARE_UPDATE_POINT_SYNC_SOURCE_ID: &str = "server-sup-sync";
pub const SCCM_SOFTWARE_UPDATE_POINT_WSUS_SOURCE_ID: &str = "server-sup-wsus";
const SCCM_SOFTWARE_UPDATE_POINT_INTAKE_AUTHORITY_REASON: &str =
    "Canonical server intake authority could not be verified.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmSoftwareUpdatePointWorkflow {
    SoftwareUpdatePoint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmSoftwareUpdatePointDiagnosticMeaning {
    CoverageOnly,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmSoftwareUpdatePointCoverageRow {
    pub artifact_id: String,
    pub source_id: String,
    pub producer_role: SccmRole,
    pub producer_host_handle: Option<String>,
    pub workflow_subject_role: Option<SccmRole>,
    pub workflow_subject_handle: Option<String>,
    pub capture_state: SccmCoverageState,
    pub rotation_fragment_complete: Option<bool>,
    pub profile_eligible: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmSoftwareUpdatePointCoverageGap {
    pub artifact_id: Option<String>,
    pub source_id: String,
    pub producer_role: Option<SccmRole>,
    pub producer_host_handle: Option<String>,
    pub workflow_subject_role: Option<SccmRole>,
    pub workflow_subject_handle: Option<String>,
    pub capture_state: SccmCoverageState,
    pub rotation_fragment_complete: Option<bool>,
    pub profile_eligible: bool,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmSoftwareUpdatePointAnalysis {
    pub schema_version: u32,
    pub workflow: SccmSoftwareUpdatePointWorkflow,
    pub diagnostic_meaning: SccmSoftwareUpdatePointDiagnosticMeaning,
    pub coverage_rows: Vec<SccmSoftwareUpdatePointCoverageRow>,
    pub coverage_gaps: Vec<SccmSoftwareUpdatePointCoverageGap>,
    pub next_artifact_requests: Vec<SccmArtifactRequest>,
    pub cross_side_correlation_performed: bool,
}

/// Project canonical Software Update Point/WSUS capture coverage without
/// inspecting source text or inferring an operational outcome.
pub fn analyze_software_update_point(
    intake: &SccmServerIntakeAssessment,
) -> SccmSoftwareUpdatePointAnalysis {
    let adapter_authority_is_intake_bound = intake.adapter_authority_is_intake_bound();
    let topology_authority_is_intake_bound = intake.topology_authority_is_intake_bound();
    if !adapter_authority_is_intake_bound || !topology_authority_is_intake_bound {
        return intake_authority_invalid_analysis();
    }

    let mut coverage_rows = intake
        .artifacts
        .iter()
        .filter(|artifact| {
            artifact.family == SccmArtifactFamily::SoftwareUpdatePoint
                && is_software_update_point_source(&artifact.source_id)
        })
        .map(|artifact| SccmSoftwareUpdatePointCoverageRow {
            artifact_id: artifact.artifact_id.clone(),
            source_id: artifact.source_id.clone(),
            producer_role: artifact.producer_role.clone(),
            producer_host_handle: artifact.producer_host_handle.clone(),
            workflow_subject_role: artifact.workflow_subject_role.clone(),
            workflow_subject_handle: artifact.workflow_subject_handle.clone(),
            capture_state: artifact.state.clone(),
            rotation_fragment_complete: artifact.fragment_complete,
            profile_eligible: artifact.profile_eligible,
        })
        .collect::<Vec<_>>();
    coverage_rows
        .sort_by(|left, right| coverage_row_sort_key(left).cmp(&coverage_row_sort_key(right)));

    let coverage_gaps = coverage_rows
        .iter()
        .filter(|row| needs_coverage_gap(row))
        .map(coverage_gap_for_row)
        .collect();

    SccmSoftwareUpdatePointAnalysis {
        schema_version: SCCM_SOFTWARE_UPDATE_POINT_ANALYSIS_SCHEMA_VERSION,
        workflow: SccmSoftwareUpdatePointWorkflow::SoftwareUpdatePoint,
        diagnostic_meaning: SccmSoftwareUpdatePointDiagnosticMeaning::CoverageOnly,
        coverage_rows,
        coverage_gaps,
        next_artifact_requests: software_update_point_artifact_requests(
            &intake.next_artifact_requests,
        ),
        cross_side_correlation_performed: false,
    }
}

fn intake_authority_invalid_analysis() -> SccmSoftwareUpdatePointAnalysis {
    SccmSoftwareUpdatePointAnalysis {
        schema_version: SCCM_SOFTWARE_UPDATE_POINT_ANALYSIS_SCHEMA_VERSION,
        workflow: SccmSoftwareUpdatePointWorkflow::SoftwareUpdatePoint,
        diagnostic_meaning: SccmSoftwareUpdatePointDiagnosticMeaning::CoverageOnly,
        coverage_rows: Vec::new(),
        coverage_gaps: vec![SccmSoftwareUpdatePointCoverageGap {
            artifact_id: None,
            source_id: SCCM_SOFTWARE_UPDATE_POINT_SYNC_SOURCE_ID.to_owned(),
            producer_role: None,
            producer_host_handle: None,
            workflow_subject_role: Some(SccmRole::SoftwareUpdatePoint),
            workflow_subject_handle: None,
            capture_state: SccmCoverageState::ParseFailed,
            rotation_fragment_complete: None,
            profile_eligible: false,
            reason: SCCM_SOFTWARE_UPDATE_POINT_INTAKE_AUTHORITY_REASON.to_owned(),
        }],
        next_artifact_requests: Vec::new(),
        cross_side_correlation_performed: false,
    }
}

fn is_software_update_point_source(source_id: &str) -> bool {
    matches!(
        source_id,
        SCCM_SOFTWARE_UPDATE_POINT_SYNC_SOURCE_ID | SCCM_SOFTWARE_UPDATE_POINT_WSUS_SOURCE_ID
    )
}

fn needs_coverage_gap(row: &SccmSoftwareUpdatePointCoverageRow) -> bool {
    row.capture_state != SccmCoverageState::Captured
        || row.rotation_fragment_complete == Some(false)
        || !row.profile_eligible
}

fn coverage_gap_for_row(
    row: &SccmSoftwareUpdatePointCoverageRow,
) -> SccmSoftwareUpdatePointCoverageGap {
    SccmSoftwareUpdatePointCoverageGap {
        artifact_id: Some(row.artifact_id.clone()),
        source_id: row.source_id.clone(),
        producer_role: Some(row.producer_role.clone()),
        producer_host_handle: row.producer_host_handle.clone(),
        workflow_subject_role: row.workflow_subject_role.clone(),
        workflow_subject_handle: row.workflow_subject_handle.clone(),
        capture_state: row.capture_state.clone(),
        rotation_fragment_complete: row.rotation_fragment_complete,
        profile_eligible: row.profile_eligible,
        reason: coverage_gap_reason(row),
    }
}

fn coverage_gap_reason(row: &SccmSoftwareUpdatePointCoverageRow) -> String {
    if row.capture_state != SccmCoverageState::Captured {
        return format!(
            "Canonical intake reports Software Update Point source coverage as {}; no outcome is inferred.",
            coverage_state_label(&row.capture_state)
        );
    }
    if row.rotation_fragment_complete == Some(false) {
        return "Software Update Point source coverage has an incomplete rotation fragment."
            .to_owned();
    }
    "Software Update Point source is outside the canonical intake profile.".to_owned()
}

fn software_update_point_artifact_requests(
    requests: &[SccmArtifactRequest],
) -> Vec<SccmArtifactRequest> {
    requests
        .iter()
        .filter(|request| {
            declared_server_source_catalog().iter().any(|source| {
                is_software_update_point_source(source.source_id)
                    && source.producer_role == request.role
                    && source
                        .logical_names
                        .iter()
                        .any(|logical_name| *logical_name == request.logical_id)
            })
        })
        .cloned()
        .collect()
}

fn coverage_row_sort_key(
    row: &SccmSoftwareUpdatePointCoverageRow,
) -> (&str, &str, &str, &str, &str, &str, &str) {
    (
        row.source_id.as_str(),
        role_sort_key(&row.producer_role),
        row.producer_host_handle.as_deref().unwrap_or_default(),
        row.workflow_subject_role
            .as_ref()
            .map(role_sort_key)
            .unwrap_or_default(),
        row.workflow_subject_handle.as_deref().unwrap_or_default(),
        coverage_state_label(&row.capture_state),
        row.artifact_id.as_str(),
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
