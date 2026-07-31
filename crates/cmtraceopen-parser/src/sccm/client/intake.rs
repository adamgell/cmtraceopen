use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::sccm::{
    SccmArtifact, SccmCoverageState, SccmRole, SccmRotation, SCCM_DIAGNOSTICS_SCHEMA_VERSION,
};

const MAX_ARTIFACT_ID_CHARS: usize = 160;
const MAX_PATH_IDENTITY_CHARS: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmClientWorkflow {
    Health,
    Policy,
    Deployment,
    Updates,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmClientSourceRequiredness {
    Required,
    Supplemental,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmClientSourceGroupDefinition {
    pub logical_artifact_id: String,
    pub accepted_basenames: Vec<String>,
    pub workflows: Vec<SccmClientWorkflow>,
    pub requiredness: SccmClientSourceRequiredness,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SccmClientIntakeArtifact {
    pub artifact: SccmArtifact,
    pub path_fingerprint: Option<String>,
    pub relative_path: Option<String>,
    pub fragment_complete: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SccmClientIntakeBundle {
    pub artifacts: Vec<SccmClientIntakeArtifact>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmClientIntakeFragment {
    pub artifact_id: String,
    pub basename: String,
    pub rotation: SccmRotation,
    pub coverage: SccmCoverageState,
    pub path_fingerprint: Option<String>,
    pub relative_path: Option<String>,
    pub fragment_complete: Option<bool>,
    pub configmgr_version: Option<String>,
    pub collected_at_utc: Option<String>,
    pub encoding: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmClientIntakeGroup {
    pub logical_artifact_id: String,
    pub coverage: SccmCoverageState,
    pub fragments: Vec<SccmClientIntakeFragment>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmClientIntakeCoverageGap {
    pub logical_artifact_id: String,
    pub role: SccmRole,
    pub coverage: SccmCoverageState,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmClientUnsupportedArtifact {
    pub artifact_id: String,
    pub basename: String,
    pub declared_coverage: SccmCoverageState,
    pub classification: SccmCoverageState,
    pub rotation: SccmRotation,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmClientIntakeAssessment {
    pub schema_version: u32,
    pub groups: Vec<SccmClientIntakeGroup>,
    pub physical_artifacts: Vec<SccmClientIntakeFragment>,
    pub unsupported_artifacts: Vec<SccmClientUnsupportedArtifact>,
    pub coverage_gaps: Vec<SccmClientIntakeCoverageGap>,
}

impl SccmClientIntakeAssessment {
    pub fn group(&self, logical_artifact_id: &str) -> Option<&SccmClientIntakeGroup> {
        self.groups
            .iter()
            .find(|group| group.logical_artifact_id == logical_artifact_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SccmClientIntakeError {
    #[error("client intake artifact identity is empty, unsafe, or too long")]
    InvalidArtifactId,
    #[error("client intake accepts only artifacts explicitly classified as the client role")]
    RoleMismatch,
    #[error("client intake contains a duplicate artifact identity")]
    DuplicateArtifactId,
    #[error("client intake contains an invalid path fingerprint")]
    InvalidPathFingerprint,
    #[error("client intake contains an invalid bundle-relative evidence path")]
    InvalidRelativePath,
    #[error("client intake contains a colliding physical path identity")]
    CollidingPhysicalIdentity,
    #[error("a physical capture state is missing its collision-safe path provenance")]
    MissingPhysicalProvenance,
}

#[derive(Clone, Copy)]
struct ClientSourceGroupSpec {
    logical_artifact_id: &'static str,
    accepted_basenames: &'static [&'static str],
    workflows: &'static [SccmClientWorkflow],
    requiredness: SccmClientSourceRequiredness,
}

const HEALTH: &[SccmClientWorkflow] = &[SccmClientWorkflow::Health];
const POLICY: &[SccmClientWorkflow] = &[SccmClientWorkflow::Policy];
const DEPLOYMENT: &[SccmClientWorkflow] = &[SccmClientWorkflow::Deployment];
const UPDATES: &[SccmClientWorkflow] = &[SccmClientWorkflow::Updates];
const HEALTH_DEPLOYMENT: &[SccmClientWorkflow] =
    &[SccmClientWorkflow::Health, SccmClientWorkflow::Deployment];

const CLIENT_SOURCE_GROUPS: &[ClientSourceGroupSpec] = &[
    ClientSourceGroupSpec {
        logical_artifact_id: "client-app-enforce",
        accepted_basenames: &["AppEnforce.log", "ExecMgr.log"],
        workflows: DEPLOYMENT,
        requiredness: SccmClientSourceRequiredness::Required,
    },
    ClientSourceGroupSpec {
        logical_artifact_id: "client-app-intent",
        accepted_basenames: &["AppDiscovery.log", "AppIntentEval.log"],
        workflows: DEPLOYMENT,
        requiredness: SccmClientSourceRequiredness::Required,
    },
    ClientSourceGroupSpec {
        logical_artifact_id: "client-ccmsetup",
        accepted_basenames: &["ccmsetup.log", "client.msi.log"],
        workflows: HEALTH,
        requiredness: SccmClientSourceRequiredness::Required,
    },
    ClientSourceGroupSpec {
        logical_artifact_id: "client-content",
        accepted_basenames: &[
            "CAS.log",
            "ContentTransferManager.log",
            "DataTransferService.log",
            "LocationServices.log",
        ],
        workflows: DEPLOYMENT,
        requiredness: SccmClientSourceRequiredness::Required,
    },
    ClientSourceGroupSpec {
        logical_artifact_id: "client-evaluation",
        accepted_basenames: &["CcmEval.log", "CcmExec.log", "CcmRestart.log"],
        workflows: HEALTH,
        requiredness: SccmClientSourceRequiredness::Required,
    },
    ClientSourceGroupSpec {
        logical_artifact_id: "client-identity",
        accepted_basenames: &["ClientIDManagerStartup.log"],
        workflows: HEALTH,
        requiredness: SccmClientSourceRequiredness::Required,
    },
    ClientSourceGroupSpec {
        logical_artifact_id: "client-location",
        accepted_basenames: &[
            "CcmMessaging.log",
            "ClientLocation.log",
            "LocationServices.log",
        ],
        workflows: HEALTH_DEPLOYMENT,
        requiredness: SccmClientSourceRequiredness::Required,
    },
    ClientSourceGroupSpec {
        logical_artifact_id: "client-policy-agent",
        accepted_basenames: &[
            "PolicyAgent.log",
            "PolicyAgentProvider.log",
            "PolicyEvaluator.log",
            "Scheduler.log",
        ],
        workflows: POLICY,
        requiredness: SccmClientSourceRequiredness::Required,
    },
    ClientSourceGroupSpec {
        logical_artifact_id: "client-policy-state",
        accepted_basenames: &[
            "CIAgent.log",
            "CIDownloader.log",
            "StateMessage.log",
            "StatusAgent.log",
        ],
        workflows: POLICY,
        requiredness: SccmClientSourceRequiredness::Required,
    },
    ClientSourceGroupSpec {
        logical_artifact_id: "client-updates",
        accepted_basenames: &[
            "ScanAgent.log",
            "UpdatesDeployment.log",
            "UpdatesHandler.log",
            "UpdatesStore.log",
            "WUAHandler.log",
        ],
        workflows: UPDATES,
        requiredness: SccmClientSourceRequiredness::Required,
    },
    ClientSourceGroupSpec {
        logical_artifact_id: "client-windows-update-supplemental",
        accepted_basenames: &["ReportingEvents.log"],
        workflows: UPDATES,
        requiredness: SccmClientSourceRequiredness::Supplemental,
    },
];

pub fn declared_client_source_groups() -> Vec<SccmClientSourceGroupDefinition> {
    CLIENT_SOURCE_GROUPS
        .iter()
        .map(|group| SccmClientSourceGroupDefinition {
            logical_artifact_id: group.logical_artifact_id.to_owned(),
            accepted_basenames: group
                .accepted_basenames
                .iter()
                .map(|basename| (*basename).to_owned())
                .collect(),
            workflows: group.workflows.to_vec(),
            requiredness: group.requiredness,
        })
        .collect()
}

pub fn assess_client_intake(
    bundle: &SccmClientIntakeBundle,
) -> Result<SccmClientIntakeAssessment, SccmClientIntakeError> {
    validate_bundle(bundle)?;

    let mut physical_artifacts = Vec::new();
    let mut unsupported_artifacts = Vec::new();
    let mut memberships: BTreeMap<&str, Vec<SccmClientIntakeFragment>> = BTreeMap::new();

    for source in &bundle.artifacts {
        let matching_groups =
            matching_groups(&source.artifact.display_name, &source.artifact.rotation);
        if matching_groups.is_empty() {
            unsupported_artifacts.push(SccmClientUnsupportedArtifact {
                artifact_id: source.artifact.artifact_id.clone(),
                basename: source.artifact.display_name.clone(),
                declared_coverage: source.artifact.coverage.clone(),
                classification: SccmCoverageState::Unsupported,
                rotation: source.artifact.rotation.clone(),
            });
            continue;
        }

        let fragment = intake_fragment(source);
        physical_artifacts.push(fragment.clone());
        for group in matching_groups {
            memberships
                .entry(group.logical_artifact_id)
                .or_default()
                .push(fragment.clone());
        }
    }

    physical_artifacts.sort_by(compare_fragments);
    unsupported_artifacts.sort_by(|left, right| {
        left.artifact_id
            .cmp(&right.artifact_id)
            .then_with(|| left.basename.cmp(&right.basename))
    });

    let mut groups = Vec::with_capacity(CLIENT_SOURCE_GROUPS.len());
    let mut coverage_gaps = Vec::new();
    for definition in CLIENT_SOURCE_GROUPS {
        let mut fragments = memberships
            .remove(definition.logical_artifact_id)
            .unwrap_or_default();
        fragments.sort_by(compare_fragments);
        let coverage = group_coverage(&fragments);
        if coverage != SccmCoverageState::Captured {
            coverage_gaps.push(SccmClientIntakeCoverageGap {
                logical_artifact_id: definition.logical_artifact_id.to_owned(),
                role: SccmRole::Client,
                reason: coverage_reason(&coverage).to_owned(),
                coverage: coverage.clone(),
            });
        }
        groups.push(SccmClientIntakeGroup {
            logical_artifact_id: definition.logical_artifact_id.to_owned(),
            coverage,
            fragments,
        });
    }

    Ok(SccmClientIntakeAssessment {
        schema_version: SCCM_DIAGNOSTICS_SCHEMA_VERSION,
        groups,
        physical_artifacts,
        unsupported_artifacts,
        coverage_gaps,
    })
}

fn validate_bundle(bundle: &SccmClientIntakeBundle) -> Result<(), SccmClientIntakeError> {
    let mut artifact_ids = BTreeSet::new();
    let mut path_fingerprints = BTreeSet::new();
    let mut relative_paths = BTreeSet::new();

    for source in &bundle.artifacts {
        if source.artifact.role != SccmRole::Client {
            return Err(SccmClientIntakeError::RoleMismatch);
        }
        if !is_safe_artifact_id(&source.artifact.artifact_id) {
            return Err(SccmClientIntakeError::InvalidArtifactId);
        }
        if !artifact_ids.insert(source.artifact.artifact_id.to_ascii_lowercase()) {
            return Err(SccmClientIntakeError::DuplicateArtifactId);
        }

        if let Some(fingerprint) = source.path_fingerprint.as_deref() {
            if !is_safe_path_identity(fingerprint) {
                return Err(SccmClientIntakeError::InvalidPathFingerprint);
            }
        }
        if let Some(relative_path) = source.relative_path.as_deref() {
            if !is_safe_relative_path(relative_path) {
                return Err(SccmClientIntakeError::InvalidRelativePath);
            }
        }

        if is_physical_state(&source.artifact.coverage) {
            let fingerprint = source
                .path_fingerprint
                .as_deref()
                .ok_or(SccmClientIntakeError::MissingPhysicalProvenance)?;
            let relative_path = source
                .relative_path
                .as_deref()
                .ok_or(SccmClientIntakeError::MissingPhysicalProvenance)?;
            if !path_fingerprints.insert(fingerprint.to_ascii_lowercase())
                || !relative_paths.insert(relative_path.to_ascii_lowercase())
            {
                return Err(SccmClientIntakeError::CollidingPhysicalIdentity);
            }
        } else if source.relative_path.is_some() {
            return Err(SccmClientIntakeError::InvalidRelativePath);
        }
    }

    Ok(())
}

fn matching_groups(
    display_name: &str,
    rotation: &SccmRotation,
) -> Vec<&'static ClientSourceGroupSpec> {
    CLIENT_SOURCE_GROUPS
        .iter()
        .filter(|group| {
            group.accepted_basenames.iter().any(|basename| {
                expected_rotated_name(basename, rotation)
                    .is_some_and(|expected| expected.eq_ignore_ascii_case(display_name))
            })
        })
        .collect()
}

fn expected_rotated_name(basename: &str, rotation: &SccmRotation) -> Option<String> {
    match rotation {
        SccmRotation::Current => Some(basename.to_owned()),
        SccmRotation::LoUnderscore => basename
            .strip_suffix(".log")
            .map(|stem| format!("{stem}.lo_")),
        SccmRotation::Numbered(number) if *number > 0 => Some(format!("{basename}.{number}")),
        SccmRotation::Timestamped(timestamp) => Some(format!("{basename}.{timestamp}")),
        SccmRotation::Numbered(_) | SccmRotation::Unknown(_) => None,
    }
}

fn intake_fragment(source: &SccmClientIntakeArtifact) -> SccmClientIntakeFragment {
    SccmClientIntakeFragment {
        artifact_id: source.artifact.artifact_id.clone(),
        basename: source.artifact.display_name.clone(),
        rotation: source.artifact.rotation.clone(),
        coverage: source.artifact.coverage.clone(),
        path_fingerprint: source.path_fingerprint.clone(),
        relative_path: source.relative_path.clone(),
        fragment_complete: source.fragment_complete,
        configmgr_version: source.artifact.configmgr_version.clone(),
        collected_at_utc: source.artifact.collected_at_utc.clone(),
        encoding: source.artifact.encoding.clone(),
    }
}

fn group_coverage(fragments: &[SccmClientIntakeFragment]) -> SccmCoverageState {
    fragments
        .iter()
        .map(|fragment| fragment.coverage.clone())
        .max_by_key(coverage_rank)
        .unwrap_or(SccmCoverageState::Absent)
}

fn coverage_rank(coverage: &SccmCoverageState) -> u8 {
    match coverage {
        SccmCoverageState::Captured => 0,
        SccmCoverageState::Absent => 1,
        SccmCoverageState::Unsupported => 2,
        SccmCoverageState::Skipped => 3,
        SccmCoverageState::Capped => 4,
        SccmCoverageState::AccessDenied => 5,
        SccmCoverageState::ParseFailed => 6,
    }
}

fn coverage_reason(coverage: &SccmCoverageState) -> &'static str {
    match coverage {
        SccmCoverageState::Absent => {
            "No artifact for this bounded client source group was supplied."
        }
        SccmCoverageState::AccessDenied => {
            "Access was denied for this bounded client source group."
        }
        SccmCoverageState::Capped => "The bounded client source group reached its capture limit.",
        SccmCoverageState::Skipped => "The bounded client source group was intentionally skipped.",
        SccmCoverageState::Unsupported => {
            "The supplied client source group is unsupported by this contract."
        }
        SccmCoverageState::ParseFailed => {
            "The supplied client source group could not be normalized completely."
        }
        SccmCoverageState::Captured => "",
    }
}

fn compare_fragments(
    left: &SccmClientIntakeFragment,
    right: &SccmClientIntakeFragment,
) -> Ordering {
    compare_rotation(&left.rotation, &right.rotation)
        .then_with(|| {
            left.path_fingerprint
                .as_deref()
                .unwrap_or_default()
                .cmp(right.path_fingerprint.as_deref().unwrap_or_default())
        })
        .then_with(|| left.basename.cmp(&right.basename))
        .then_with(|| left.artifact_id.cmp(&right.artifact_id))
}

fn compare_rotation(left: &SccmRotation, right: &SccmRotation) -> Ordering {
    rotation_rank(left)
        .cmp(&rotation_rank(right))
        .then_with(|| match (left, right) {
            (SccmRotation::Numbered(left), SccmRotation::Numbered(right)) => left.cmp(right),
            (SccmRotation::Timestamped(left), SccmRotation::Timestamped(right)) => left.cmp(right),
            _ => Ordering::Equal,
        })
}

fn rotation_rank(rotation: &SccmRotation) -> u8 {
    match rotation {
        SccmRotation::Current => 0,
        SccmRotation::LoUnderscore => 1,
        SccmRotation::Numbered(_) => 2,
        SccmRotation::Timestamped(_) => 3,
        SccmRotation::Unknown(_) => 4,
    }
}

fn is_physical_state(coverage: &SccmCoverageState) -> bool {
    matches!(
        coverage,
        SccmCoverageState::Captured | SccmCoverageState::Capped | SccmCoverageState::ParseFailed
    )
}

fn is_safe_artifact_id(value: &str) -> bool {
    !value.is_empty()
        && value.chars().count() <= MAX_ARTIFACT_ID_CHARS
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-._:".contains(character))
}

fn is_safe_path_identity(value: &str) -> bool {
    !value.is_empty()
        && value.chars().count() <= MAX_PATH_IDENTITY_CHARS
        && !value.contains(['/', '\\', '@'])
        && !value.chars().any(char::is_whitespace)
}

fn is_safe_relative_path(value: &str) -> bool {
    value.starts_with("evidence/")
        && value.chars().count() <= MAX_PATH_IDENTITY_CHARS
        && !value.contains('\\')
        && !value.contains(':')
        && value
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}
