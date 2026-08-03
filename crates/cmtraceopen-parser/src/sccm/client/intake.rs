use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{
    de::{DeserializeSeed, Error as _, IgnoredAny, MapAccess, SeqAccess, Visitor},
    ser::{Error as _, SerializeStruct},
    Deserialize, Deserializer, Serialize, Serializer,
};
use thiserror::Error;

use crate::sccm::catalog::{
    classify_artifact_name, declared_client_source_memberships, SccmClientSourceMembership,
};
use crate::sccm::{
    SccmArtifact, SccmCoverageState, SccmRole, SccmRotation, SCCM_DIAGNOSTICS_SCHEMA_VERSION,
};

/// Maximum artifact declarations admitted by one SCCM client intake bundle.
///
/// This is the authoritative v1 ceiling for both pure client intake and the
/// native SCCM client manifest/capture boundary. Native readers, writers, and
/// collectors must import and reuse this constant rather than define a wider
/// or otherwise parallel limit. Pure intake validates it before allocating
/// per-artifact indexes so a malformed bundle cannot turn validation into an
/// unbounded allocation path.
pub const MAX_SCCM_CLIENT_INTAKE_ARTIFACTS: usize = 4096;

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
    /// sibling roots declared as distinct missing locations). A marker and a
    /// physical declaration may share basename and rotation only when both
    /// carry distinct configured-root fingerprints. An unpinned marker claims
    /// every configured root for that source and therefore collides with any
    /// physical declaration for it.
    pub path_fingerprint: Option<String>,
    /// Versioned, privacy-safe identity shared by rotations of one physical
    /// source. Optional for compatibility with pre-lineage intake values;
    /// repeating a path fingerprint requires an explicit matching lineage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation_lineage: Option<String>,
    pub relative_path: Option<String>,
    /// Whether the captured bytes begin and end on complete logical-record
    /// boundaries. This is independent of normalization success: a
    /// `ParseFailed` fragment may be complete when all bytes were copied but
    /// their contents could not be normalized as CCM evidence.
    pub fragment_complete: Option<bool>,
}

/// A coverage-only declaration for a recognized client source rotation that
/// was intentionally not retained. This is distinct from a physical artifact:
/// it never contains a bundle-relative path, bytes, or fragment-boundary
/// claim. The versioned opaque identity, configured-source fingerprint, and
/// rotation lineage retain only the provenance needed to prevent collisions.
#[derive(Debug, Clone, PartialEq)]
pub struct SccmClientIntakeCaptureGap {
    pub artifact_id: String,
    pub basename: String,
    pub rotation: SccmRotation,
    pub coverage: SccmCoverageState,
    pub path_fingerprint: String,
    pub rotation_lineage: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SccmClientIntakeCaptureGapWire {
    artifact_id: String,
    basename: String,
    rotation: SccmRotation,
    coverage: SccmCoverageState,
    path_fingerprint: String,
    rotation_lineage: String,
}

impl From<SccmClientIntakeCaptureGapWire> for SccmClientIntakeCaptureGap {
    fn from(wire: SccmClientIntakeCaptureGapWire) -> Self {
        Self {
            artifact_id: wire.artifact_id,
            basename: wire.basename,
            rotation: wire.rotation,
            coverage: wire.coverage,
            path_fingerprint: wire.path_fingerprint,
            rotation_lineage: wire.rotation_lineage,
        }
    }
}

impl From<&SccmClientIntakeCaptureGap> for SccmClientIntakeCaptureGapWire {
    fn from(capture_gap: &SccmClientIntakeCaptureGap) -> Self {
        Self {
            artifact_id: capture_gap.artifact_id.clone(),
            basename: capture_gap.basename.clone(),
            rotation: capture_gap.rotation.clone(),
            coverage: capture_gap.coverage.clone(),
            path_fingerprint: capture_gap.path_fingerprint.clone(),
            rotation_lineage: capture_gap.rotation_lineage.clone(),
        }
    }
}

impl Serialize for SccmClientIntakeCaptureGap {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        validate_capture_gap_shape(self).map_err(S::Error::custom)?;
        SccmClientIntakeCaptureGapWire::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SccmClientIntakeCaptureGap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let capture_gap = Self::from(SccmClientIntakeCaptureGapWire::deserialize(deserializer)?);
        validate_capture_gap_shape(&capture_gap).map_err(D::Error::custom)?;
        Ok(capture_gap)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SccmClientIntakeBundle {
    pub artifacts: Vec<SccmClientIntakeArtifact>,
    /// Additive v1 coverage-only declarations. Empty remains omitted on the
    /// wire so pre-gap bundle JSON round-trips unchanged.
    pub capture_gaps: Vec<SccmClientIntakeCaptureGap>,
}

impl Serialize for SccmClientIntakeBundle {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        validate_bundle(self).map_err(S::Error::custom)?;

        let field_count = 1 + usize::from(!self.capture_gaps.is_empty());
        let mut state = serializer.serialize_struct("SccmClientIntakeBundle", field_count)?;
        state.serialize_field("artifacts", &self.artifacts)?;
        if !self.capture_gaps.is_empty() {
            state.serialize_field("captureGaps", &self.capture_gaps)?;
        }
        state.end()
    }
}

impl<'de> Deserialize<'de> for SccmClientIntakeBundle {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        const FIELDS: &[&str] = &["artifacts", "captureGaps"];
        deserializer.deserialize_struct(
            "SccmClientIntakeBundle",
            FIELDS,
            SccmClientIntakeBundleVisitor,
        )
    }
}

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "camelCase")]
enum SccmClientIntakeBundleField {
    Artifacts,
    CaptureGaps,
}

struct SccmClientIntakeBundleVisitor;

impl<'de> Visitor<'de> for SccmClientIntakeBundleVisitor {
    type Value = SccmClientIntakeBundle;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an SCCM client intake bundle")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut artifacts = None;
        let mut capture_gaps = None;
        let mut remaining = MAX_SCCM_CLIENT_INTAKE_ARTIFACTS;

        while let Some(field) = map.next_key()? {
            match field {
                SccmClientIntakeBundleField::Artifacts => {
                    if artifacts.is_some() {
                        return Err(A::Error::duplicate_field("artifacts"));
                    }
                    let decoded = map.next_value_seed(BoundedArtifactsSeed { limit: remaining })?;
                    remaining -= decoded.len();
                    artifacts = Some(decoded);
                }
                SccmClientIntakeBundleField::CaptureGaps => {
                    if capture_gaps.is_some() {
                        return Err(A::Error::duplicate_field("captureGaps"));
                    }
                    let decoded =
                        map.next_value_seed(BoundedCaptureGapsSeed { limit: remaining })?;
                    remaining -= decoded.len();
                    capture_gaps = Some(decoded);
                }
            }
        }

        let bundle = SccmClientIntakeBundle {
            artifacts: artifacts.ok_or_else(|| A::Error::missing_field("artifacts"))?,
            capture_gaps: capture_gaps.unwrap_or_default(),
        };
        validate_bundle(&bundle).map_err(A::Error::custom)?;
        Ok(bundle)
    }
}

struct BoundedCaptureGapsSeed {
    limit: usize,
}

impl<'de> DeserializeSeed<'de> for BoundedCaptureGapsSeed {
    type Value = Vec<SccmClientIntakeCaptureGap>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(BoundedCaptureGapVisitor { limit: self.limit })
    }
}

struct BoundedCaptureGapVisitor {
    limit: usize,
}

impl<'de> Visitor<'de> for BoundedCaptureGapVisitor {
    type Value = Vec<SccmClientIntakeCaptureGap>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "at most {} SCCM client capture gaps", self.limit)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        if sequence.size_hint().is_some_and(|size| size > self.limit) {
            return Err(A::Error::custom(
                SccmClientIntakeError::ArtifactLimitExceeded,
            ));
        }

        let initial_capacity = sequence.size_hint().unwrap_or_default().min(self.limit);
        let mut capture_gaps = Vec::with_capacity(initial_capacity);
        while capture_gaps.len() < self.limit {
            let Some(capture_gap) = sequence.next_element()? else {
                return Ok(capture_gaps);
            };
            capture_gaps.push(capture_gap);
        }

        if sequence.next_element::<IgnoredAny>()?.is_some() {
            return Err(A::Error::custom(
                SccmClientIntakeError::ArtifactLimitExceeded,
            ));
        }

        Ok(capture_gaps)
    }
}

struct BoundedArtifactsSeed {
    limit: usize,
}

impl<'de> DeserializeSeed<'de> for BoundedArtifactsSeed {
    type Value = Vec<SccmClientIntakeArtifact>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(BoundedArtifactVisitor { limit: self.limit })
    }
}

struct BoundedArtifactVisitor {
    limit: usize,
}

impl<'de> Visitor<'de> for BoundedArtifactVisitor {
    type Value = Vec<SccmClientIntakeArtifact>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "at most {} SCCM client artifacts", self.limit)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        if sequence.size_hint().is_some_and(|size| size > self.limit) {
            return Err(A::Error::custom(
                SccmClientIntakeError::ArtifactLimitExceeded,
            ));
        }

        let initial_capacity = sequence.size_hint().unwrap_or_default().min(self.limit);
        let mut artifacts = Vec::with_capacity(initial_capacity);
        while artifacts.len() < self.limit {
            let Some(artifact) = sequence.next_element()? else {
                return Ok(artifacts);
            };
            artifacts.push(artifact);
        }

        if sequence.next_element::<IgnoredAny>()?.is_some() {
            return Err(A::Error::custom(
                SccmClientIntakeError::ArtifactLimitExceeded,
            ));
        }

        Ok(artifacts)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SccmClientIntakeFragment {
    pub artifact_id: String,
    pub basename: String,
    pub rotation: SccmRotation,
    pub coverage: SccmCoverageState,
    pub path_fingerprint: Option<String>,
    pub rotation_lineage: Option<String>,
    pub relative_path: Option<String>,
    /// Boundary completeness projected independently from `coverage`.
    /// In particular, `ParseFailed` plus `Some(true)` means the full fragment
    /// was copied but could not be normalized as CCM evidence.
    pub fragment_complete: Option<bool>,
    pub configmgr_version: Option<String>,
    pub collected_at_utc: Option<String>,
    pub encoding: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SccmClientIntakeGroup {
    pub logical_artifact_id: String,
    pub coverage: SccmCoverageState,
    pub fragments: Vec<SccmClientIntakeFragment>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SccmClientIntakeCoverageGap {
    pub logical_artifact_id: String,
    pub artifact_id: Option<String>,
    pub role: SccmRole,
    pub coverage: SccmCoverageState,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SccmClientUnsupportedArtifact {
    pub artifact_id: String,
    pub basename: String,
    pub declared_coverage: SccmCoverageState,
    pub classification: SccmCoverageState,
    pub rotation: SccmRotation,
    pub path_fingerprint: Option<String>,
    pub rotation_lineage: Option<String>,
    pub relative_path: Option<String>,
    pub fragment_complete: Option<bool>,
    pub configmgr_version: Option<String>,
    pub collected_at_utc: Option<String>,
    pub encoding: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SccmClientIntakeAssessment {
    pub schema_version: u32,
    pub groups: Vec<SccmClientIntakeGroup>,
    /// Every recognized physical source declaration in deterministic order.
    /// Non-physical markers remain in their group and coverage-gap projections
    /// but never masquerade as captured bundle artifacts.
    pub physical_artifacts: Vec<SccmClientIntakeFragment>,
    pub unsupported_artifacts: Vec<SccmClientUnsupportedArtifact>,
    /// Canonical coverage-only declarations. They preserve capture-limit
    /// provenance without becoming physical artifacts or log fragments.
    pub capture_gaps: Vec<SccmClientIntakeCaptureGap>,
    pub coverage_gaps: Vec<SccmClientIntakeCoverageGap>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SccmClientIntakeFragmentWire {
    artifact_id: String,
    basename: String,
    rotation: SccmRotation,
    coverage: SccmCoverageState,
    path_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rotation_lineage: Option<String>,
    relative_path: Option<String>,
    fragment_complete: Option<bool>,
    configmgr_version: Option<String>,
    collected_at_utc: Option<String>,
    encoding: Option<String>,
}

impl From<SccmClientIntakeFragmentWire> for SccmClientIntakeFragment {
    fn from(wire: SccmClientIntakeFragmentWire) -> Self {
        Self {
            artifact_id: wire.artifact_id,
            basename: wire.basename,
            rotation: wire.rotation,
            coverage: wire.coverage,
            path_fingerprint: wire.path_fingerprint,
            rotation_lineage: wire.rotation_lineage,
            relative_path: wire.relative_path,
            fragment_complete: wire.fragment_complete,
            configmgr_version: wire.configmgr_version,
            collected_at_utc: wire.collected_at_utc,
            encoding: wire.encoding,
        }
    }
}

impl From<&SccmClientIntakeFragment> for SccmClientIntakeFragmentWire {
    fn from(fragment: &SccmClientIntakeFragment) -> Self {
        Self {
            artifact_id: fragment.artifact_id.clone(),
            basename: fragment.basename.clone(),
            rotation: fragment.rotation.clone(),
            coverage: fragment.coverage.clone(),
            path_fingerprint: fragment.path_fingerprint.clone(),
            rotation_lineage: fragment.rotation_lineage.clone(),
            relative_path: fragment.relative_path.clone(),
            fragment_complete: fragment.fragment_complete,
            configmgr_version: fragment.configmgr_version.clone(),
            collected_at_utc: fragment.collected_at_utc.clone(),
            encoding: fragment.encoding.clone(),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SccmClientIntakeGroupWire {
    logical_artifact_id: String,
    coverage: SccmCoverageState,
    fragments: Vec<SccmClientIntakeFragmentWire>,
}

impl From<SccmClientIntakeGroupWire> for SccmClientIntakeGroup {
    fn from(wire: SccmClientIntakeGroupWire) -> Self {
        Self {
            logical_artifact_id: wire.logical_artifact_id,
            coverage: wire.coverage,
            fragments: wire.fragments.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<&SccmClientIntakeGroup> for SccmClientIntakeGroupWire {
    fn from(group: &SccmClientIntakeGroup) -> Self {
        Self {
            logical_artifact_id: group.logical_artifact_id.clone(),
            coverage: group.coverage.clone(),
            fragments: group.fragments.iter().map(Into::into).collect(),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SccmClientIntakeCoverageGapWire {
    logical_artifact_id: String,
    #[serde(default)]
    artifact_id: Option<String>,
    role: SccmRole,
    coverage: SccmCoverageState,
    reason: String,
}

impl From<SccmClientIntakeCoverageGapWire> for SccmClientIntakeCoverageGap {
    fn from(wire: SccmClientIntakeCoverageGapWire) -> Self {
        Self {
            logical_artifact_id: wire.logical_artifact_id,
            artifact_id: wire.artifact_id,
            role: wire.role,
            coverage: wire.coverage,
            reason: wire.reason,
        }
    }
}

impl From<&SccmClientIntakeCoverageGap> for SccmClientIntakeCoverageGapWire {
    fn from(gap: &SccmClientIntakeCoverageGap) -> Self {
        Self {
            logical_artifact_id: gap.logical_artifact_id.clone(),
            artifact_id: gap.artifact_id.clone(),
            role: gap.role.clone(),
            coverage: gap.coverage.clone(),
            reason: gap.reason.clone(),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SccmClientUnsupportedArtifactWire {
    artifact_id: String,
    basename: String,
    declared_coverage: SccmCoverageState,
    classification: SccmCoverageState,
    rotation: SccmRotation,
    path_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rotation_lineage: Option<String>,
    relative_path: Option<String>,
    fragment_complete: Option<bool>,
    configmgr_version: Option<String>,
    collected_at_utc: Option<String>,
    encoding: Option<String>,
}

impl From<SccmClientUnsupportedArtifactWire> for SccmClientUnsupportedArtifact {
    fn from(wire: SccmClientUnsupportedArtifactWire) -> Self {
        Self {
            artifact_id: wire.artifact_id,
            basename: wire.basename,
            declared_coverage: wire.declared_coverage,
            classification: wire.classification,
            rotation: wire.rotation,
            path_fingerprint: wire.path_fingerprint,
            rotation_lineage: wire.rotation_lineage,
            relative_path: wire.relative_path,
            fragment_complete: wire.fragment_complete,
            configmgr_version: wire.configmgr_version,
            collected_at_utc: wire.collected_at_utc,
            encoding: wire.encoding,
        }
    }
}

impl From<&SccmClientUnsupportedArtifact> for SccmClientUnsupportedArtifactWire {
    fn from(unsupported: &SccmClientUnsupportedArtifact) -> Self {
        Self {
            artifact_id: unsupported.artifact_id.clone(),
            basename: unsupported.basename.clone(),
            declared_coverage: unsupported.declared_coverage.clone(),
            classification: unsupported.classification.clone(),
            rotation: unsupported.rotation.clone(),
            path_fingerprint: unsupported.path_fingerprint.clone(),
            rotation_lineage: unsupported.rotation_lineage.clone(),
            relative_path: unsupported.relative_path.clone(),
            fragment_complete: unsupported.fragment_complete,
            configmgr_version: unsupported.configmgr_version.clone(),
            collected_at_utc: unsupported.collected_at_utc.clone(),
            encoding: unsupported.encoding.clone(),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SccmClientIntakeAssessmentWire {
    schema_version: u32,
    groups: Vec<SccmClientIntakeGroupWire>,
    physical_artifacts: Vec<SccmClientIntakeFragmentWire>,
    unsupported_artifacts: Vec<SccmClientUnsupportedArtifactWire>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_bounded_assessment_capture_gaps"
    )]
    capture_gaps: Vec<SccmClientIntakeCaptureGap>,
    coverage_gaps: Vec<SccmClientIntakeCoverageGapWire>,
}

fn deserialize_bounded_assessment_capture_gaps<'de, D>(
    deserializer: D,
) -> Result<Vec<SccmClientIntakeCaptureGap>, D::Error>
where
    D: Deserializer<'de>,
{
    // Each assessment capture gap reconstructs one canonical bundle
    // declaration in `validate_assessment_projection`. Decode no more than
    // that authoritative shared ceiling; the final projection validation
    // accounts for physical, nonphysical, unsupported, and gap declarations
    // together.
    BoundedCaptureGapsSeed {
        limit: MAX_SCCM_CLIENT_INTAKE_ARTIFACTS,
    }
    .deserialize(deserializer)
}

impl From<&SccmClientIntakeAssessment> for SccmClientIntakeAssessmentWire {
    fn from(assessment: &SccmClientIntakeAssessment) -> Self {
        Self {
            schema_version: assessment.schema_version,
            groups: assessment.groups.iter().map(Into::into).collect(),
            physical_artifacts: assessment
                .physical_artifacts
                .iter()
                .map(Into::into)
                .collect(),
            unsupported_artifacts: assessment
                .unsupported_artifacts
                .iter()
                .map(Into::into)
                .collect(),
            capture_gaps: assessment.capture_gaps.clone(),
            coverage_gaps: assessment.coverage_gaps.iter().map(Into::into).collect(),
        }
    }
}

impl Serialize for SccmClientIntakeAssessment {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        validate_assessment_projection(self).map_err(S::Error::custom)?;
        SccmClientIntakeAssessmentWire::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SccmClientIntakeAssessment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SccmClientIntakeAssessmentWire::deserialize(deserializer)?;
        let assessment = Self {
            schema_version: wire.schema_version,
            groups: wire.groups.into_iter().map(Into::into).collect(),
            physical_artifacts: wire
                .physical_artifacts
                .into_iter()
                .map(Into::into)
                .collect(),
            unsupported_artifacts: wire
                .unsupported_artifacts
                .into_iter()
                .map(Into::into)
                .collect(),
            capture_gaps: wire.capture_gaps,
            coverage_gaps: wire.coverage_gaps.into_iter().map(Into::into).collect(),
        };

        validate_assessment_projection(&assessment).map_err(D::Error::custom)?;
        Ok(assessment)
    }
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
    #[error("client intake artifact count exceeds the supported limit")]
    ArtifactLimitExceeded,
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
    #[error("client intake contains a duplicate artifact ID or source declaration")]
    DuplicateArtifactId,
    #[error("client intake contains an invalid path fingerprint")]
    InvalidPathFingerprint,
    #[error("client intake contains an invalid rotation lineage")]
    InvalidRotationLineage,
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
    #[error("client intake capture gap is malformed, unsupported, or not coverage-only")]
    InvalidCaptureGap,
}

#[derive(Clone, Copy)]
struct ClientSourceGroupSpec {
    logical_artifact_id: &'static str,
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
        workflows: DEPLOYMENT,
        requiredness: SccmClientSourceRequiredness::Required,
    },
    ClientSourceGroupSpec {
        logical_artifact_id: "client-app-intent",
        workflows: DEPLOYMENT,
        requiredness: SccmClientSourceRequiredness::Required,
    },
    ClientSourceGroupSpec {
        logical_artifact_id: "client-ccmsetup",
        workflows: HEALTH,
        requiredness: SccmClientSourceRequiredness::Required,
    },
    ClientSourceGroupSpec {
        logical_artifact_id: "client-content",
        workflows: DEPLOYMENT,
        requiredness: SccmClientSourceRequiredness::Required,
    },
    ClientSourceGroupSpec {
        logical_artifact_id: "client-evaluation",
        workflows: HEALTH,
        requiredness: SccmClientSourceRequiredness::Required,
    },
    ClientSourceGroupSpec {
        logical_artifact_id: "client-identity",
        workflows: HEALTH,
        requiredness: SccmClientSourceRequiredness::Required,
    },
    ClientSourceGroupSpec {
        logical_artifact_id: "client-location",
        workflows: HEALTH_DEPLOYMENT,
        requiredness: SccmClientSourceRequiredness::Required,
    },
    ClientSourceGroupSpec {
        logical_artifact_id: "client-policy-agent",
        workflows: POLICY,
        requiredness: SccmClientSourceRequiredness::Required,
    },
    ClientSourceGroupSpec {
        logical_artifact_id: "client-policy-state",
        workflows: POLICY,
        requiredness: SccmClientSourceRequiredness::Required,
    },
    ClientSourceGroupSpec {
        logical_artifact_id: "client-updates",
        workflows: UPDATES,
        requiredness: SccmClientSourceRequiredness::Required,
    },
    ClientSourceGroupSpec {
        logical_artifact_id: "client-windows-update-supplemental",
        workflows: UPDATES,
        requiredness: SccmClientSourceRequiredness::Supplemental,
    },
];

pub fn declared_client_source_groups() -> Vec<SccmClientSourceGroupDefinition> {
    CLIENT_SOURCE_GROUPS
        .iter()
        .map(|group| SccmClientSourceGroupDefinition {
            logical_artifact_id: group.logical_artifact_id.to_owned(),
            accepted_basenames: declared_client_source_memberships()
                .iter()
                .filter(|source| {
                    source
                        .logical_artifact_ids
                        .contains(&group.logical_artifact_id)
                })
                .map(|source| source.basename.to_owned())
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
    let mut capture_gap_memberships: BTreeMap<&str, Vec<SccmClientIntakeCaptureGap>> =
        BTreeMap::new();

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
                rotation_lineage: source.rotation_lineage.clone(),
                relative_path: source.relative_path.clone(),
                fragment_complete: source.fragment_complete,
                configmgr_version: source.artifact.configmgr_version.clone(),
                collected_at_utc: normalized_collected_at(
                    source.artifact.collected_at_utc.as_deref(),
                ),
                encoding: source.artifact.encoding.clone(),
            });
            continue;
        }

        let fragment = intake_fragment(source);
        if is_physical_state(&fragment.coverage) {
            physical_artifacts.push(fragment.clone());
        }
        for group in matching_groups {
            memberships
                .entry(group.logical_artifact_id)
                .or_default()
                .push(fragment.clone());
        }
    }

    for capture_gap in &bundle.capture_gaps {
        for group in matching_groups(&capture_gap.basename, &capture_gap.rotation) {
            capture_gap_memberships
                .entry(group.logical_artifact_id)
                .or_default()
                .push(capture_gap.clone());
        }
    }

    physical_artifacts.sort_by(compare_fragments);
    unsupported_artifacts.sort_by(|left, right| {
        left.artifact_id
            .cmp(&right.artifact_id)
            .then_with(|| left.basename.cmp(&right.basename))
    });
    let mut capture_gaps = bundle.capture_gaps.clone();
    capture_gaps.sort_by(compare_capture_gaps);

    let mut groups = Vec::with_capacity(CLIENT_SOURCE_GROUPS.len());
    let mut coverage_gaps = Vec::new();
    for definition in CLIENT_SOURCE_GROUPS {
        let mut fragments = memberships
            .remove(definition.logical_artifact_id)
            .unwrap_or_default();
        fragments.sort_by(compare_fragments);
        let mut group_capture_gaps = capture_gap_memberships
            .remove(definition.logical_artifact_id)
            .unwrap_or_default();
        group_capture_gaps.sort_by(compare_capture_gaps);
        let coverage = group_coverage(&fragments, &group_capture_gaps);
        if fragments.is_empty() && group_capture_gaps.is_empty() {
            coverage_gaps.push(SccmClientIntakeCoverageGap {
                logical_artifact_id: definition.logical_artifact_id.to_owned(),
                artifact_id: None,
                role: SccmRole::Client,
                reason: coverage_reason(&coverage).to_owned(),
                coverage: coverage.clone(),
            });
        } else {
            for fragment in &fragments {
                if let Some(reason) = source_coverage_reason(fragment) {
                    coverage_gaps.push(SccmClientIntakeCoverageGap {
                        logical_artifact_id: definition.logical_artifact_id.to_owned(),
                        artifact_id: Some(fragment.artifact_id.clone()),
                        role: SccmRole::Client,
                        coverage: fragment.coverage.clone(),
                        reason,
                    });
                }
            }
            for capture_gap in &group_capture_gaps {
                coverage_gaps.push(SccmClientIntakeCoverageGap {
                    logical_artifact_id: definition.logical_artifact_id.to_owned(),
                    artifact_id: Some(capture_gap.artifact_id.clone()),
                    role: SccmRole::Client,
                    coverage: capture_gap.coverage.clone(),
                    reason: capture_gap_coverage_reason(capture_gap),
                });
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
        capture_gaps,
        coverage_gaps,
    })
}

fn validate_assessment_projection(assessment: &SccmClientIntakeAssessment) -> Result<(), String> {
    let mut artifacts = assessment
        .physical_artifacts
        .iter()
        .map(fragment_as_intake_artifact)
        .collect::<Vec<_>>();
    let mut nonphysical_fragments = BTreeMap::new();

    for group in &assessment.groups {
        for fragment in &group.fragments {
            if is_physical_state(&fragment.coverage) {
                continue;
            }

            if let Some(existing) =
                nonphysical_fragments.insert(fragment.artifact_id.clone(), fragment.clone())
            {
                if existing != *fragment {
                    return Err(
                        "client intake assessment repeats one artifact ID with conflicting projections"
                            .to_owned(),
                    );
                }
            }
        }
    }

    artifacts.extend(
        nonphysical_fragments
            .values()
            .map(fragment_as_intake_artifact),
    );
    artifacts.extend(
        assessment
            .unsupported_artifacts
            .iter()
            .map(unsupported_as_intake_artifact),
    );

    let canonical = assess_client_intake(&SccmClientIntakeBundle {
        artifacts,
        capture_gaps: assessment.capture_gaps.clone(),
    })
    .map_err(|error| format!("invalid client intake assessment projection: {error}"))?;
    if canonical != *assessment {
        return Err(
            "client intake assessment is not the canonical projection of its artifacts".to_owned(),
        );
    }

    Ok(())
}

fn fragment_as_intake_artifact(fragment: &SccmClientIntakeFragment) -> SccmClientIntakeArtifact {
    SccmClientIntakeArtifact {
        artifact: SccmArtifact {
            artifact_id: fragment.artifact_id.clone(),
            display_name: fragment.basename.clone(),
            original_path: None,
            host: None,
            role: SccmRole::Client,
            configmgr_version: fragment.configmgr_version.clone(),
            collected_at_utc: fragment.collected_at_utc.clone(),
            rotation: fragment.rotation.clone(),
            coverage: fragment.coverage.clone(),
            encoding: fragment.encoding.clone(),
        },
        path_fingerprint: fragment.path_fingerprint.clone(),
        rotation_lineage: fragment.rotation_lineage.clone(),
        relative_path: fragment.relative_path.clone(),
        fragment_complete: fragment.fragment_complete,
    }
}

fn unsupported_as_intake_artifact(
    unsupported: &SccmClientUnsupportedArtifact,
) -> SccmClientIntakeArtifact {
    SccmClientIntakeArtifact {
        artifact: SccmArtifact {
            artifact_id: unsupported.artifact_id.clone(),
            display_name: unsupported.basename.clone(),
            original_path: None,
            host: None,
            role: SccmRole::Client,
            configmgr_version: unsupported.configmgr_version.clone(),
            collected_at_utc: unsupported.collected_at_utc.clone(),
            rotation: unsupported.rotation.clone(),
            coverage: unsupported.declared_coverage.clone(),
            encoding: unsupported.encoding.clone(),
        },
        path_fingerprint: unsupported.path_fingerprint.clone(),
        rotation_lineage: unsupported.rotation_lineage.clone(),
        relative_path: unsupported.relative_path.clone(),
        fragment_complete: unsupported.fragment_complete,
    }
}

fn validate_capture_gap_shape(
    capture_gap: &SccmClientIntakeCaptureGap,
) -> Result<(), SccmClientIntakeError> {
    if !is_safe_artifact_id(&capture_gap.artifact_id)
        || serde_json::to_value(&capture_gap.rotation).is_err()
        || !is_safe_unknown_rotation(&capture_gap.rotation)
        || !is_safe_basename(&capture_gap.basename, &capture_gap.rotation)
        || !matches!(
            capture_gap.coverage,
            SccmCoverageState::Capped | SccmCoverageState::ParseFailed
        )
        || !is_safe_path_identity(&capture_gap.path_fingerprint)
        || !is_safe_rotation_lineage(&capture_gap.rotation_lineage)
        || matching_groups(&capture_gap.basename, &capture_gap.rotation).is_empty()
    {
        return Err(SccmClientIntakeError::InvalidCaptureGap);
    }

    Ok(())
}

fn validate_bundle(bundle: &SccmClientIntakeBundle) -> Result<(), SccmClientIntakeError> {
    if bundle
        .artifacts
        .len()
        .saturating_add(bundle.capture_gaps.len())
        > MAX_SCCM_CLIENT_INTAKE_ARTIFACTS
    {
        return Err(SccmClientIntakeError::ArtifactLimitExceeded);
    }

    let mut artifact_ids = BTreeSet::new();
    let mut path_fingerprint_bindings: BTreeMap<String, (Option<String>, String)> = BTreeMap::new();
    let mut rotation_lineage_bindings = BTreeMap::new();
    let mut lineage_rotation_identities = BTreeSet::new();
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
        if source
            .rotation_lineage
            .as_deref()
            .is_some_and(|lineage| !is_safe_rotation_lineage(lineage))
        {
            return Err(SccmClientIntakeError::InvalidRotationLineage);
        }

        let path_fingerprint = match source.path_fingerprint.as_deref() {
            Some(fingerprint) if !is_safe_path_identity(fingerprint) => {
                return Err(SccmClientIntakeError::InvalidPathFingerprint);
            }
            Some(fingerprint) => Some(fingerprint.to_ascii_lowercase()),
            None => None,
        };

        let basename =
            source_basename_identity(&source.artifact.display_name, &source.artifact.rotation);
        if let Some(lineage) = source.rotation_lineage.as_deref() {
            if let Some((bound_basename, bound_fingerprint)) =
                rotation_lineage_bindings.get(lineage)
            {
                if bound_basename != &basename || bound_fingerprint != &path_fingerprint {
                    return Err(SccmClientIntakeError::CollidingPhysicalIdentity);
                }
            } else {
                rotation_lineage_bindings.insert(
                    lineage.to_owned(),
                    (basename.clone(), path_fingerprint.clone()),
                );
            }
            if !lineage_rotation_identities.insert((
                lineage.to_owned(),
                rotation_identity(&source.artifact.rotation),
            )) {
                return Err(SccmClientIntakeError::CollidingPhysicalIdentity);
            }
        }

        if let Some(fingerprint) = path_fingerprint {
            let lineage = source
                .rotation_lineage
                .as_ref()
                .map(|value| value.to_owned());
            if let Some((bound_lineage, bound_basename)) =
                path_fingerprint_bindings.get(&fingerprint)
            {
                if lineage.is_none() || bound_lineage != &lineage || bound_basename != &basename {
                    return Err(SccmClientIntakeError::CollidingPhysicalIdentity);
                }
            } else {
                path_fingerprint_bindings
                    .insert(fingerprint.clone(), (lineage.clone(), basename.clone()));
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
            source
                .path_fingerprint
                .as_deref()
                .ok_or(SccmClientIntakeError::MissingPhysicalProvenance)?;
            source
                .relative_path
                .as_deref()
                .ok_or(SccmClientIntakeError::MissingPhysicalProvenance)?;
            // A fingerprint-less marker claims every configured root for this
            // basename and rotation. A pinned marker for another root remains
            // a distinct source and is checked by the fingerprint identity.
            if unpinned_marker_identities.contains(&source_identity) {
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
            if source.path_fingerprint.is_some() {
                // Pinned markers and physical captures under other configured
                // roots are distinct sources. Reusing a fingerprint without
                // an explicit lineage, or reusing one lineage/rotation pair,
                // already failed the identity checks above.
                if unpinned_marker_identities.contains(&source_identity) {
                    return Err(SccmClientIntakeError::DuplicateArtifactId);
                }
                pinned_marker_identities.insert(source_identity);
            } else {
                // Distinct caller labels must not double-declare the same
                // missing source, whether the sibling is pinned or not.
                if physical_source_identities.contains(&source_identity) {
                    return Err(SccmClientIntakeError::CollidingPhysicalIdentity);
                }
                if pinned_marker_identities.contains(&source_identity)
                    || unpinned_marker_identities.contains(&source_identity)
                {
                    return Err(SccmClientIntakeError::DuplicateArtifactId);
                }
                unpinned_marker_identities.insert(source_identity);
            }
        }
    }

    for capture_gap in &bundle.capture_gaps {
        validate_capture_gap_shape(capture_gap)?;
        if !artifact_ids.insert(capture_gap.artifact_id.to_ascii_lowercase()) {
            return Err(SccmClientIntakeError::DuplicateArtifactId);
        }

        let path_fingerprint = capture_gap.path_fingerprint.to_ascii_lowercase();
        let lineage = capture_gap.rotation_lineage.clone();
        let basename = source_basename_identity(&capture_gap.basename, &capture_gap.rotation);
        if let Some((bound_basename, bound_fingerprint)) = rotation_lineage_bindings.get(&lineage) {
            if bound_basename != &basename
                || bound_fingerprint.as_deref() != Some(&path_fingerprint)
            {
                return Err(SccmClientIntakeError::CollidingPhysicalIdentity);
            }
        } else {
            rotation_lineage_bindings.insert(
                lineage.clone(),
                (basename.clone(), Some(path_fingerprint.clone())),
            );
        }
        if !lineage_rotation_identities
            .insert((lineage.clone(), rotation_identity(&capture_gap.rotation)))
        {
            return Err(SccmClientIntakeError::CollidingPhysicalIdentity);
        }
        if let Some((bound_lineage, bound_basename)) =
            path_fingerprint_bindings.get(&path_fingerprint)
        {
            if bound_lineage.as_deref() != Some(lineage.as_str()) || bound_basename != &basename {
                return Err(SccmClientIntakeError::CollidingPhysicalIdentity);
            }
        } else {
            path_fingerprint_bindings.insert(path_fingerprint, (Some(lineage), basename));
        }

        let source_identity = (
            capture_gap.basename.to_ascii_lowercase(),
            rotation_identity(&capture_gap.rotation),
        );
        if unpinned_marker_identities.contains(&source_identity) {
            return Err(SccmClientIntakeError::DuplicateArtifactId);
        }
        pinned_marker_identities.insert(source_identity);
    }

    Ok(())
}

fn matching_groups(
    display_name: &str,
    rotation: &SccmRotation,
) -> Vec<&'static ClientSourceGroupSpec> {
    let Some(source) = catalogued_client_source(display_name, rotation) else {
        return Vec::new();
    };

    source
        .logical_artifact_ids
        .iter()
        .filter_map(|logical_artifact_id| {
            CLIENT_SOURCE_GROUPS
                .iter()
                .find(|group| group.logical_artifact_id == *logical_artifact_id)
        })
        .collect()
}

fn catalogued_client_source(
    display_name: &str,
    rotation: &SccmRotation,
) -> Option<&'static SccmClientSourceMembership> {
    let classified = classify_artifact_name(display_name, SccmRole::Client);
    if !classified.supported_for_diagnosis || &classified.rotation != rotation {
        return None;
    }

    let source = declared_client_source_memberships()
        .iter()
        .find(|source| source.basename.eq_ignore_ascii_case(&classified.basename))?;
    expected_rotated_name(source.basename, rotation)
        .is_some_and(|expected| expected == display_name)
        .then_some(source)
}

fn source_basename_identity(display_name: &str, rotation: &SccmRotation) -> String {
    catalogued_client_source(display_name, rotation)
        .map(|source| source.basename.to_ascii_lowercase())
        .unwrap_or_else(|| display_name.to_ascii_lowercase())
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
        rotation_lineage: source.rotation_lineage.clone(),
        relative_path: source.relative_path.clone(),
        fragment_complete: source.fragment_complete,
        configmgr_version: source.artifact.configmgr_version.clone(),
        collected_at_utc: normalized_collected_at(source.artifact.collected_at_utc.as_deref()),
        encoding: source.artifact.encoding.clone(),
    }
}

fn normalized_collected_at(value: Option<&str>) -> Option<String> {
    value.map(|value| {
        DateTime::parse_from_rfc3339(value)
            .expect("client intake validates collection timestamps before projection")
            .with_timezone(&Utc)
            .to_rfc3339_opts(SecondsFormat::AutoSi, true)
    })
}

fn group_coverage(
    fragments: &[SccmClientIntakeFragment],
    capture_gaps: &[SccmClientIntakeCaptureGap],
) -> SccmCoverageState {
    fragments
        .iter()
        .map(|fragment| fragment.coverage.clone())
        .chain(
            capture_gaps
                .iter()
                .map(|capture_gap| capture_gap.coverage.clone()),
        )
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
            "The supplied client source group could not be normalized as CCM evidence."
        }
        SccmCoverageState::Captured => "",
    }
}

/// Per-source gap wording for every noncaptured declaration and for a
/// captured fragment that ends on an incomplete logical-record boundary.
/// The safe artifact ID disambiguates identical basenames declared under
/// separate configured roots.
fn source_coverage_reason(fragment: &SccmClientIntakeFragment) -> Option<String> {
    match &fragment.coverage {
        SccmCoverageState::Absent => Some(format!(
            "No artifact for client source {} was supplied.",
            fragment.basename
        )),
        SccmCoverageState::AccessDenied => Some(format!(
            "Access was denied for client source {}.",
            fragment.basename
        )),
        SccmCoverageState::Capped => Some(format!(
            "Client source {} reached its capture limit.",
            fragment.basename
        )),
        SccmCoverageState::Skipped => Some(format!(
            "Client source {} was intentionally skipped.",
            fragment.basename
        )),
        SccmCoverageState::Unsupported => Some(format!(
            "Client source {} was declared unsupported.",
            fragment.basename
        )),
        SccmCoverageState::ParseFailed => Some(format!(
            "Client source {} could not be normalized as CCM evidence.",
            fragment.basename
        )),
        SccmCoverageState::Captured if fragment.fragment_complete == Some(false) => Some(format!(
            "Client source {} was captured with an incomplete logical-record boundary.",
            fragment.basename
        )),
        SccmCoverageState::Captured => None,
    }
}

fn capture_gap_coverage_reason(capture_gap: &SccmClientIntakeCaptureGap) -> String {
    match capture_gap.coverage {
        SccmCoverageState::Capped => format!(
            "Client source rotation {} was omitted because its capture limit was reached.",
            capture_gap.basename
        ),
        SccmCoverageState::ParseFailed => format!(
            "Client source rotation {} was omitted because capture could not be completed.",
            capture_gap.basename
        ),
        _ => unreachable!("capture gaps are validated as Capped or ParseFailed"),
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
        SccmRotation::Unknown(unknown) => format!(
            "unknown:{}:{}",
            unknown.kind,
            unknown
                .value
                .as_ref()
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
        ),
    }
}

fn compare_fragments(
    left: &SccmClientIntakeFragment,
    right: &SccmClientIntakeFragment,
) -> Ordering {
    left.path_fingerprint
        .as_deref()
        .unwrap_or_default()
        .cmp(right.path_fingerprint.as_deref().unwrap_or_default())
        .then_with(|| {
            left.rotation_lineage
                .as_deref()
                .unwrap_or_default()
                .cmp(right.rotation_lineage.as_deref().unwrap_or_default())
        })
        .then_with(|| compare_rotation(&left.rotation, &right.rotation))
        .then_with(|| left.basename.cmp(&right.basename))
        .then_with(|| left.artifact_id.cmp(&right.artifact_id))
}

fn compare_capture_gaps(
    left: &SccmClientIntakeCaptureGap,
    right: &SccmClientIntakeCaptureGap,
) -> Ordering {
    left.path_fingerprint
        .cmp(&right.path_fingerprint)
        .then_with(|| left.rotation_lineage.cmp(&right.rotation_lineage))
        .then_with(|| compare_rotation(&left.rotation, &right.rotation))
        .then_with(|| left.basename.cmp(&right.basename))
        .then_with(|| left.artifact_id.cmp(&right.artifact_id))
}

fn compare_rotation(left: &SccmRotation, right: &SccmRotation) -> Ordering {
    rotation_rank(left)
        .cmp(&rotation_rank(right))
        .then_with(|| match (left, right) {
            (SccmRotation::Numbered(left), SccmRotation::Numbered(right)) => left.cmp(right),
            (SccmRotation::Timestamped(left), SccmRotation::Timestamped(right)) => left.cmp(right),
            (SccmRotation::Unknown(_), SccmRotation::Unknown(_)) => {
                rotation_identity(left).cmp(&rotation_identity(right))
            }
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
        .is_some_and(is_sha256_digest)
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
    declared_client_source_memberships()
        .iter()
        .any(|source| source.basename == value)
}

fn is_opaque_unsupported_basename(value: &str) -> bool {
    value
        .strip_prefix(OPAQUE_UNSUPPORTED_BASENAME_PREFIX_V1)
        .and_then(|value| value.strip_suffix(".log"))
        .is_some_and(is_sha256_digest)
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
            value
                .as_str()
                .is_some_and(|value| value.strip_prefix("sha256:").is_some_and(is_sha256_digest))
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
        Some(("sha256", digest)) => is_sha256_digest(digest),
        _ => false,
    }
}

fn is_safe_rotation_lineage(value: &str) -> bool {
    value
        .strip_prefix("synthetic:")
        .is_some_and(is_safe_synthetic_fingerprint)
        || value
            .strip_prefix("cmtraceopen.lineage.sha256.v1:")
            .is_some_and(is_sha256_digest)
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
                && catalogued_client_source(display_name, rotation)
                    .is_some_and(|source| source.basename == "LocationServices.log")
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

/// Opaque root handle emitted by a native adapter, in either accepted width.
fn is_lowercase_hex_handle(value: &str) -> bool {
    matches!(value.len(), 16 | 64) && is_lowercase_hex(value)
}

/// A SHA-256 digest is exactly 64 lowercase hexadecimal characters. Owning
/// that width here keeps every digest caller from restating it, so a new
/// caller cannot silently admit a shorter handle.
fn is_sha256_digest(value: &str) -> bool {
    value.len() == 64 && is_lowercase_hex(value)
}

fn is_lowercase_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
