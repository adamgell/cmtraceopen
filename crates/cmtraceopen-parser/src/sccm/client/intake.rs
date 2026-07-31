use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use chrono::DateTime;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::sccm::{
    SccmArtifact, SccmCoverageState, SccmRole, SccmRotation, SCCM_DIAGNOSTICS_SCHEMA_VERSION,
};

const MAX_ARTIFACT_ID_CHARS: usize = 160;
const MAX_BASENAME_CHARS: usize = 160;
const MAX_COLLECTED_AT_CHARS: usize = 64;
const MAX_PATH_IDENTITY_CHARS: usize = 512;
const MAX_SYNTHETIC_FINGERPRINT_TOKENS: usize = 10;
const NATIVE_ARTIFACT_ID_PREFIX_V1: &str = "sccm-artifact:v1:sha256:";
const OPAQUE_UNSUPPORTED_BASENAME_PREFIX_V1: &str = "sccm-unknown-v1-sha256-";
const OPAQUE_ROTATION_KIND_V1: &str = "cmtraceopen.rotation.opaque.v1";
const REVIEWED_UNSUPPORTED_SYNTHETIC_BASENAMES: &[&str] = &[
    "CustomVendorHook.log",
    "CustomVendorHook.lo_",
    "PolicyAgent.log.backup",
];
// Synthetic fingerprints are fixture-only provenance. Keep their vocabulary
// finite so the public field cannot become an arbitrary user/context channel.
// Extending this list is a privacy-contract change that requires review.
const SYNTHETIC_FINGERPRINT_TOKENS: &[&str] = &[
    "a",
    "absent",
    "access",
    "agent",
    "app",
    "approved",
    "artifact",
    "auth",
    "b",
    "basename",
    "bits",
    "boundary",
    "c",
    "cache",
    "candidate",
    "capped",
    "ccmsetup",
    "client",
    "collision",
    "complete",
    "completeness",
    "content",
    "contradictory",
    "current",
    "custom",
    "deferred",
    "denied",
    "dependency",
    "deployment",
    "detect",
    "detection",
    "download",
    "dp",
    "enforce",
    "enforcement",
    "evaluate",
    "evaluation",
    "exit",
    "failure",
    "false",
    "fingerprint",
    "gate",
    "health",
    "identity",
    "incomplete",
    "intent",
    "invalid",
    "lo",
    "location",
    "lookalike",
    "malformed",
    "missing",
    "mp",
    "multiline",
    "negative",
    "no",
    "not",
    "numbered",
    "offset",
    "one",
    "or",
    "path",
    "persist",
    "policy",
    "recovery",
    "relative",
    "report",
    "reporting",
    "requirements",
    "root",
    "rotation",
    "rotations",
    "scheduler",
    "services",
    "setup",
    "site",
    "state",
    "success",
    "supplemental",
    "targeted",
    "time",
    "transfer",
    "transport",
    "two",
    "unknown",
    "unsafe",
    "update",
    "updates",
    "valid",
    "version",
];

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
    /// Collision-safe path identity. Mandatory for physical states; a
    /// non-physical marker may also carry one to pin which configured
    /// location the marker refers to (for example, absent under two
    /// sibling roots declared as distinct missing locations). A marker can
    /// never share its source identity (basename plus rotation) with a
    /// physical declaration, regardless of fingerprints: physical evidence
    /// for a source disproves any absent, denied, or skipped claim about
    /// that same source.
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
    pub path_fingerprint: Option<String>,
    pub relative_path: Option<String>,
    pub fragment_complete: Option<bool>,
    pub configmgr_version: Option<String>,
    pub collected_at_utc: Option<String>,
    pub encoding: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmClientIntakeAssessment {
    pub schema_version: u32,
    pub groups: Vec<SccmClientIntakeGroup>,
    /// Every recognized source declaration in deterministic order. This
    /// intentionally includes non-physical markers (absent, access denied,
    /// skipped) so callers see the full declared surface, not only the
    /// fragments with captured bytes.
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
    #[error("client intake artifact basename is empty, unsafe, or too long")]
    InvalidBasename,
    #[error("client intake artifact rotation is malformed or unsafe")]
    InvalidRotation,
    #[error("client intake artifact collection timestamp is not RFC 3339")]
    InvalidCollectedAt,
    #[error("client intake artifact ConfigMgr version is unsafe or too long")]
    InvalidConfigMgrVersion,
    #[error("client intake artifact encoding is unsafe or too long")]
    InvalidEncoding,
    #[error("client intake accepts only artifacts explicitly classified as the client role")]
    RoleMismatch,
    #[error("client intake contains a duplicate artifact identity")]
    DuplicateArtifactId,
    #[error("client intake contains an invalid path fingerprint")]
    InvalidPathFingerprint,
    #[error("client intake contains an invalid bundle-relative evidence path")]
    InvalidRelativePath,
    #[error("client intake contains a colliding path identity")]
    CollidingPhysicalIdentity,
    #[error("a physical capture state is missing its collision-safe path provenance")]
    MissingPhysicalProvenance,
    #[error("client intake fragment completeness must be explicitly declared")]
    MissingFragmentCompleteness,
    #[error("client intake fragment completeness contradicts its declared coverage state")]
    InvalidFragmentCompleteness,
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
                path_fingerprint: source.path_fingerprint.clone(),
                relative_path: source.relative_path.clone(),
                fragment_complete: source.fragment_complete,
                configmgr_version: source.artifact.configmgr_version.clone(),
                collected_at_utc: source.artifact.collected_at_utc.clone(),
                encoding: source.artifact.encoding.clone(),
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
        // In a mixed group the physical capture defines the group coverage,
        // so each sibling marker keeps its own explicit per-source gap that
        // names the affected source instead of indicting the whole group.
        if fragments
            .iter()
            .any(|fragment| is_physical_state(&fragment.coverage))
        {
            for fragment in &fragments {
                if let Some(reason) = marker_coverage_reason(&fragment.coverage, &fragment.basename)
                {
                    coverage_gaps.push(SccmClientIntakeCoverageGap {
                        logical_artifact_id: definition.logical_artifact_id.to_owned(),
                        role: SccmRole::Client,
                        coverage: fragment.coverage.clone(),
                        reason,
                    });
                }
            }
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
    // Canonical source identity (casefolded basename plus rotation
    // discriminator) for every declaration, split by declaration shape so
    // the identity intersects across ALL declarations for a source: a
    // marker can never contradict physical evidence, and a fingerprint-less
    // marker can never double-declare a source any other declaration
    // already claims. The sibling server intake instead makes the path
    // fingerprint mandatory on every declaration; the client keeps
    // optional marker fingerprints for the committed all-absent fixture
    // bundles, so this intersection is the fail-closed equivalent here.
    let mut physical_source_identities = BTreeSet::new();
    let mut pinned_marker_identities = BTreeSet::new();
    let mut unpinned_marker_identities = BTreeSet::new();

    for source in &bundle.artifacts {
        if source.artifact.role != SccmRole::Client {
            return Err(SccmClientIntakeError::RoleMismatch);
        }
        if !is_safe_artifact_id(&source.artifact.artifact_id) {
            return Err(SccmClientIntakeError::InvalidArtifactId);
        }
        if serde_json::to_value(&source.artifact.rotation).is_err()
            || !is_safe_unknown_rotation(&source.artifact.rotation)
        {
            return Err(SccmClientIntakeError::InvalidRotation);
        }
        if !is_safe_basename(&source.artifact.display_name, &source.artifact.rotation) {
            return Err(SccmClientIntakeError::InvalidBasename);
        }
        if source
            .artifact
            .collected_at_utc
            .as_deref()
            .is_some_and(|value| !is_safe_collected_at(value))
        {
            return Err(SccmClientIntakeError::InvalidCollectedAt);
        }
        if source
            .artifact
            .configmgr_version
            .as_deref()
            .is_some_and(|value| !is_safe_configmgr_version(value))
        {
            return Err(SccmClientIntakeError::InvalidConfigMgrVersion);
        }
        if source
            .artifact
            .encoding
            .as_deref()
            .is_some_and(|value| !is_supported_encoding(value))
        {
            return Err(SccmClientIntakeError::InvalidEncoding);
        }
        if !artifact_ids.insert(source.artifact.artifact_id.to_ascii_lowercase()) {
            return Err(SccmClientIntakeError::DuplicateArtifactId);
        }

        if let Some(fingerprint) = source.path_fingerprint.as_deref() {
            if !is_safe_path_identity(fingerprint) {
                return Err(SccmClientIntakeError::InvalidPathFingerprint);
            }
            if !path_fingerprints.insert(fingerprint.to_ascii_lowercase()) {
                return Err(SccmClientIntakeError::CollidingPhysicalIdentity);
            }
        }
        if let Some(relative_path) = source.relative_path.as_deref() {
            if !is_safe_relative_path(
                relative_path,
                &source.artifact.display_name,
                &source.artifact.rotation,
            ) {
                return Err(SccmClientIntakeError::InvalidRelativePath);
            }
            if !relative_paths.insert(relative_path.to_ascii_lowercase()) {
                return Err(SccmClientIntakeError::CollidingPhysicalIdentity);
            }
        }

        let fragment_complete = source
            .fragment_complete
            .ok_or(SccmClientIntakeError::MissingFragmentCompleteness)?;
        let source_identity = (
            source.artifact.display_name.to_ascii_lowercase(),
            rotation_identity(&source.artifact.rotation),
        );
        if is_physical_state(&source.artifact.coverage) {
            if source.artifact.coverage == SccmCoverageState::Capped && fragment_complete {
                return Err(SccmClientIntakeError::InvalidFragmentCompleteness);
            }
            // Captured means the whole source was copied; an admitted
            // incomplete capture must be declared as Capped instead.
            if source.artifact.coverage == SccmCoverageState::Captured && !fragment_complete {
                return Err(SccmClientIntakeError::InvalidFragmentCompleteness);
            }
            source
                .path_fingerprint
                .as_deref()
                .ok_or(SccmClientIntakeError::MissingPhysicalProvenance)?;
            source
                .relative_path
                .as_deref()
                .ok_or(SccmClientIntakeError::MissingPhysicalProvenance)?;
            // Physical evidence for a source disproves any non-physical
            // claim about that same source, regardless of fingerprints and
            // in either declaration order.
            if pinned_marker_identities.contains(&source_identity)
                || unpinned_marker_identities.contains(&source_identity)
            {
                return Err(SccmClientIntakeError::CollidingPhysicalIdentity);
            }
            physical_source_identities.insert(source_identity);
        } else {
            if source.relative_path.is_some() {
                return Err(SccmClientIntakeError::InvalidRelativePath);
            }
            if fragment_complete {
                return Err(SccmClientIntakeError::InvalidFragmentCompleteness);
            }
            // Non-physical markers have no payload lineage, so their
            // canonical identity is the declared source itself. A marker
            // for a physically declared source is a self-contradiction.
            if physical_source_identities.contains(&source_identity) {
                return Err(SccmClientIntakeError::CollidingPhysicalIdentity);
            }
            if source.path_fingerprint.is_some() {
                // Markers pinned to distinct configured roots by distinct
                // fingerprints stay distinct sources; reusing a fingerprint
                // already failed the shared fingerprint dedup above. An
                // unpinned marker claims the whole source, so a pinned
                // sibling for the same source is a double-declaration.
                if unpinned_marker_identities.contains(&source_identity) {
                    return Err(SccmClientIntakeError::DuplicateArtifactId);
                }
                pinned_marker_identities.insert(source_identity);
            } else {
                // Distinct caller labels must not double-declare the same
                // missing source, whether the sibling is pinned or not.
                if pinned_marker_identities.contains(&source_identity)
                    || unpinned_marker_identities.contains(&source_identity)
                {
                    return Err(SccmClientIntakeError::DuplicateArtifactId);
                }
                unpinned_marker_identities.insert(source_identity);
            }
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
                    .is_some_and(|expected| expected == display_name)
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
    // A captured fragment must never coexist with an all-absent claim: once
    // any physical evidence exists, the physical states alone decide the
    // group coverage and sibling markers surface as per-source gaps instead.
    let physical_coverage = fragments
        .iter()
        .filter(|fragment| is_physical_state(&fragment.coverage))
        .map(|fragment| fragment.coverage.clone())
        .max_by_key(coverage_rank);
    if let Some(coverage) = physical_coverage {
        return coverage;
    }

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

/// Per-source gap wording for a non-physical marker that shares a group with
/// physical evidence. Returns `None` for physical states, which are covered
/// by the group-level coverage instead.
fn marker_coverage_reason(coverage: &SccmCoverageState, basename: &str) -> Option<String> {
    match coverage {
        SccmCoverageState::Absent => Some(format!(
            "No artifact for client source {basename} was supplied alongside \
             this group's physical evidence."
        )),
        SccmCoverageState::AccessDenied => Some(format!(
            "Access was denied for client source {basename} alongside \
             this group's physical evidence."
        )),
        SccmCoverageState::Skipped => Some(format!(
            "Client source {basename} was intentionally skipped alongside \
             this group's physical evidence."
        )),
        SccmCoverageState::Unsupported => Some(format!(
            "Client source {basename} was declared unsupported alongside \
             this group's physical evidence."
        )),
        SccmCoverageState::Captured
        | SccmCoverageState::Capped
        | SccmCoverageState::ParseFailed => None,
    }
}

/// Stable rotation discriminator for the canonical source identity shared
/// by every declaration, physical or marker, so collisions intersect across
/// all declaration shapes for a source.
fn rotation_identity(rotation: &SccmRotation) -> String {
    match rotation {
        SccmRotation::Current => "current".to_owned(),
        SccmRotation::LoUnderscore => "lo".to_owned(),
        SccmRotation::Numbered(number) => format!("numbered-{number}"),
        SccmRotation::Timestamped(timestamp) => format!("timestamped-{timestamp}"),
        SccmRotation::Unknown(_) => "unknown".to_owned(),
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
    if value.is_empty() || value.chars().count() > MAX_ARTIFACT_ID_CHARS {
        return false;
    }

    if let Some(payload) = value.strip_prefix("fixture-") {
        return is_safe_synthetic_fingerprint(payload);
    }

    value
        .strip_prefix(NATIVE_ARTIFACT_ID_PREFIX_V1)
        .is_some_and(|digest| digest.len() == 64 && is_lowercase_hex_handle(digest))
}

fn is_safe_basename(value: &str, rotation: &SccmRotation) -> bool {
    let structurally_safe = !value.is_empty()
        && value == value.trim()
        && value.chars().count() <= MAX_BASENAME_CHARS
        && value.is_ascii()
        && !value.contains(['/', '\\', ':', '@'])
        && !value.chars().any(char::is_control);
    if !structurally_safe {
        return false;
    }

    if !matching_groups(value, rotation).is_empty() {
        return true;
    }

    if matches!(rotation, SccmRotation::Unknown(_)) && is_canonical_client_basename(value) {
        return true;
    }

    REVIEWED_UNSUPPORTED_SYNTHETIC_BASENAMES.contains(&value)
        || is_opaque_unsupported_basename(value)
}

fn is_canonical_client_basename(value: &str) -> bool {
    CLIENT_SOURCE_GROUPS
        .iter()
        .any(|group| group.accepted_basenames.contains(&value))
}

fn is_opaque_unsupported_basename(value: &str) -> bool {
    value
        .strip_prefix(OPAQUE_UNSUPPORTED_BASENAME_PREFIX_V1)
        .and_then(|value| value.strip_suffix(".log"))
        .is_some_and(|digest| digest.len() == 64 && is_lowercase_hex_handle(digest))
}

fn is_safe_collected_at(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_COLLECTED_AT_CHARS
        && value.is_ascii()
        && DateTime::parse_from_rfc3339(value).is_ok()
}

fn is_safe_unknown_rotation(rotation: &SccmRotation) -> bool {
    let SccmRotation::Unknown(unknown) = rotation else {
        return true;
    };

    unknown.kind == OPAQUE_ROTATION_KIND_V1
        && unknown.value.as_ref().is_some_and(|value| {
            value.as_str().is_some_and(|value| {
                value
                    .strip_prefix("sha256:")
                    .is_some_and(|digest| digest.len() == 64 && is_lowercase_hex_handle(digest))
            })
        })
}

fn is_safe_configmgr_version(value: &str) -> bool {
    if matches!(value, "5.00.TEST.0000" | "5.00.UNKNOWN.0000") {
        return true;
    }

    let mut components = value.split('.');
    matches!(components.next(), Some("5"))
        && matches!(components.next(), Some("00"))
        && components.next().is_some_and(is_four_ascii_digits)
        && components.next().is_some_and(is_four_ascii_digits)
        && components.next().is_none()
}

fn is_four_ascii_digits(value: &str) -> bool {
    value.len() == 4 && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn is_supported_encoding(value: &str) -> bool {
    matches!(value, "utf-8" | "utf-16le" | "utf-16be" | "windows-1252")
}

fn is_safe_path_identity(value: &str) -> bool {
    if value.is_empty() || value.chars().count() > MAX_PATH_IDENTITY_CHARS {
        return false;
    }

    if let Some(payload) = value.strip_prefix("synthetic-") {
        return is_safe_synthetic_fingerprint(payload);
    }

    match value.split_once(':') {
        Some(("synthetic", payload)) => is_safe_synthetic_fingerprint(payload),
        Some(("sha256", digest)) => digest.len() == 64 && is_lowercase_hex_handle(digest),
        _ => false,
    }
}

fn is_safe_synthetic_fingerprint(payload: &str) -> bool {
    let tokens = payload.split([':', '-']).collect::<Vec<_>>();
    tokens.len() <= MAX_SYNTHETIC_FINGERPRINT_TOKENS
        && tokens.iter().enumerate().all(|(index, token)| {
            !token.is_empty()
                && (SYNTHETIC_FINGERPRINT_TOKENS.contains(token)
                    || (token.len() <= 2
                        && token.bytes().all(|byte| byte.is_ascii_digit())
                        && index > 0
                        && index + 1 == tokens.len()
                        && tokens[index - 1] == "numbered"))
        })
}

fn is_safe_relative_path(value: &str, display_name: &str, rotation: &SccmRotation) -> bool {
    if value.chars().count() > MAX_PATH_IDENTITY_CHARS {
        return false;
    }

    let segments = value.split('/').collect::<Vec<_>>();
    let body = if segments.starts_with(&["evidence", "sccm", "client"]) {
        &segments[3..]
    } else if segments.starts_with(&["evidence"]) {
        &segments[1..]
    } else {
        return false;
    };

    let (group, rotation_segment, basename, root_is_safe) = match body {
        [group, basename] => (*group, None, *basename, true),
        [group, rotation, basename] => (*group, Some(*rotation), *basename, true),
        [group, root, rotation, basename] => (
            *group,
            Some(*rotation),
            *basename,
            is_safe_root_path_segment(root),
        ),
        _ => return false,
    };

    root_is_safe
        && is_safe_client_bundle_group(group)
        && is_expected_client_bundle_group(group, display_name, rotation)
        && basename == display_name
        && is_safe_path_segment(basename)
        && is_expected_rotation_path_segment(rotation_segment, rotation)
}

fn is_expected_client_bundle_group(
    group: &str,
    display_name: &str,
    rotation: &SccmRotation,
) -> bool {
    let matching_groups = matching_groups(display_name, rotation);
    match matching_groups.as_slice() {
        [] => group == "unknown",
        [matching_group] => group == matching_group.logical_artifact_id,
        _ => {
            group == "client-location-services-shared"
                && expected_rotated_name("LocationServices.log", rotation)
                    .is_some_and(|expected| expected == display_name)
        }
    }
}

fn is_expected_rotation_path_segment(segment: Option<&str>, rotation: &SccmRotation) -> bool {
    match (segment, rotation) {
        (None, SccmRotation::Current | SccmRotation::Unknown(_)) => true,
        (Some("current"), SccmRotation::Current) => true,
        (Some("lo"), SccmRotation::LoUnderscore) => true,
        (Some(segment), SccmRotation::Numbered(number)) => segment == format!("numbered-{number}"),
        (Some(segment), SccmRotation::Timestamped(timestamp)) => {
            segment == format!("timestamped-{timestamp}")
        }
        _ => false,
    }
}

fn is_safe_path_segment(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value.chars().count() <= MAX_BASENAME_CHARS
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-._".contains(character))
}

fn is_safe_client_bundle_group(value: &str) -> bool {
    value == "unknown"
        || value == "client-location-services-shared"
        || CLIENT_SOURCE_GROUPS
            .iter()
            .any(|group| group.logical_artifact_id == value)
}

fn is_safe_root_path_segment(value: &str) -> bool {
    value.strip_prefix("root-").is_some_and(|root| {
        // `root-a` and `root-b` are committed synthetic collision fixtures.
        // Native adapters use an opaque lowercase hexadecimal handle.
        matches!(root, "a" | "b") || is_lowercase_hex_handle(root)
    })
}

fn is_lowercase_hex_handle(value: &str) -> bool {
    matches!(value.len(), 16 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
