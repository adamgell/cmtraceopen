use serde::{Serialize, Serializer};

use super::{
    assess_client_intake, SccmClientIntakeBundle, SccmClientIntakeCoverageGap,
    SccmClientIntakeError, SccmClientWorkflow,
};
use crate::sccm::{SccmCoverageState, SccmRole};

const HEALTH_SOURCE_GROUPS: &[&str] = &[
    "client-ccmsetup",
    "client-evaluation",
    "client-identity",
    "client-location",
];

/// Coverage-only readiness for the SCCM client health workflow.
///
/// This projection reports only intake coverage. It does not inspect source
/// bytes, evaluate client health, or produce findings.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmClientHealthCoverageReadiness {
    pub workflow: SccmClientWorkflow,
    pub source_groups: Vec<SccmClientHealthCoverageGroup>,
    #[serde(serialize_with = "serialize_coverage_gaps")]
    pub coverage_gaps: Vec<SccmClientIntakeCoverageGap>,
    pub coverage_complete: bool,
    pub next_required_source_group: Option<String>,
}

/// One required SCCM client health source group's projected coverage state.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmClientHealthCoverageGroup {
    pub logical_artifact_id: String,
    pub coverage: SccmCoverageState,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SccmClientHealthCoverageGapWire<'a> {
    logical_artifact_id: &'a str,
    artifact_id: &'a Option<String>,
    role: &'a SccmRole,
    coverage: &'a SccmCoverageState,
    reason: &'a str,
}

fn serialize_coverage_gaps<S>(
    coverage_gaps: &[SccmClientIntakeCoverageGap],
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    coverage_gaps
        .iter()
        .map(|gap| SccmClientHealthCoverageGapWire {
            logical_artifact_id: &gap.logical_artifact_id,
            artifact_id: &gap.artifact_id,
            role: &gap.role,
            coverage: &gap.coverage,
            reason: &gap.reason,
        })
        .collect::<Vec<_>>()
        .serialize(serializer)
}

/// Projects the required SCCM client health sources from canonical intake.
///
/// The bundle is always assessed here so callers cannot supply a forged intake
/// assessment as coverage authority.
pub fn assess_client_health_coverage(
    bundle: &SccmClientIntakeBundle,
) -> Result<SccmClientHealthCoverageReadiness, SccmClientIntakeError> {
    let assessment = assess_client_intake(bundle)?;
    let source_groups = HEALTH_SOURCE_GROUPS
        .iter()
        .map(|logical_artifact_id| {
            let group = assessment
                .groups
                .iter()
                .find(|group| group.logical_artifact_id == *logical_artifact_id)
                .expect("client intake always projects every declared client source group");
            SccmClientHealthCoverageGroup {
                logical_artifact_id: group.logical_artifact_id.clone(),
                coverage: group.coverage.clone(),
            }
        })
        .collect::<Vec<_>>();
    let next_required_source_group = source_groups
        .iter()
        .find(|group| group.coverage != SccmCoverageState::Captured)
        .map(|group| group.logical_artifact_id.clone());
    let coverage_complete = next_required_source_group.is_none();
    let coverage_gaps = assessment
        .coverage_gaps
        .into_iter()
        .filter(|gap| HEALTH_SOURCE_GROUPS.contains(&gap.logical_artifact_id.as_str()))
        .collect();

    Ok(SccmClientHealthCoverageReadiness {
        workflow: SccmClientWorkflow::Health,
        source_groups,
        coverage_gaps,
        coverage_complete,
        next_required_source_group,
    })
}
