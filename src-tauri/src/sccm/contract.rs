use std::cell::Cell;
use std::cmp::Ordering;
use std::fmt;
use std::marker::PhantomData;
use std::rc::Rc;

use cmtraceopen_parser::sccm::{
    classify_artifact_name, declared_client_source_groups, SccmCoverageState, SccmRole,
    SccmRotation, SccmTaskSequenceProvenance,
};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SCCM_MANIFEST_FILE_NAME: &str = "sccm-manifest.json";
pub const SCCM_MANIFEST_VERSION: u32 = 1;
pub const SCCM_CLIENT_SOURCE_CATALOG_VERSION: u32 = 1;
pub const MAX_SCCM_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
pub use cmtraceopen_parser::sccm::MAX_SCCM_CLIENT_INTAKE_ARTIFACTS as MAX_SCCM_MANIFEST_ARTIFACTS;

pub(crate) const SHA256_HEX_CHARS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmManifestProvenance {
    NativeClientCapture,
    LegacyGenericUnscoped,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmManifestProvenanceProfile {
    HmacSha256V1,
    #[default]
    LegacyGenericUnscoped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmManifestSourceState {
    Captured,
    Absent,
    AccessDenied,
    Capped,
    Skipped,
    Unsupported,
    UnsafePath,
    ParseFailed,
    FailedUnknownDetail,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmManifestCoverageScope {
    #[default]
    Source,
    RootEnumeration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmCaptureLimitKind {
    FileCount,
    Bytes,
    SourceDeclared,
}

impl SccmManifestSourceState {
    pub(crate) fn pure_coverage(self) -> SccmCoverageState {
        match self {
            Self::Captured => SccmCoverageState::Captured,
            Self::Absent => SccmCoverageState::Absent,
            Self::AccessDenied => SccmCoverageState::AccessDenied,
            Self::Capped => SccmCoverageState::Capped,
            Self::Skipped => SccmCoverageState::Skipped,
            Self::Unsupported | Self::UnsafePath | Self::FailedUnknownDetail => {
                SccmCoverageState::Unsupported
            }
            Self::ParseFailed => SccmCoverageState::ParseFailed,
        }
    }

    pub(crate) fn is_physical(self) -> bool {
        matches!(self, Self::Captured | Self::Capped | Self::ParseFailed)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SccmManifestArtifact {
    pub catalog_entry_id: String,
    pub logical_artifact_ids: Vec<String>,
    pub artifact_id: String,
    pub role: SccmRole,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation_lineage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_sequence_provenance: Option<SccmTaskSequenceProvenance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relative_path: Option<String>,
    pub basename: String,
    pub rotation: SccmRotation,
    pub state: SccmManifestSourceState,
    #[serde(default)]
    pub coverage_scope: SccmManifestCoverageScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_limit_kind: Option<SccmCaptureLimitKind>,
    pub bytes_copied: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit_applied: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_sha256: Option<String>,
    pub fragment_complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configmgr_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collected_at_utc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SccmManifestCaptureGap {
    pub artifact_id: String,
    pub catalog_entry_id: String,
    pub logical_artifact_ids: Vec<String>,
    pub source_handle: String,
    pub root_handle: String,
    pub path_fingerprint: String,
    pub rotation_lineage: String,
    pub basename: String,
    pub rotation: SccmRotation,
    pub state: SccmManifestSourceState,
    pub capture_limit_kind: SccmCaptureLimitKind,
    pub source_bytes: u64,
    pub bytes_retained: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmBundleManifestV1 {
    pub sccm_manifest_version: u32,
    pub diagnostics_schema_version: u32,
    pub source_catalog_version: u32,
    pub provenance: SccmManifestProvenance,
    #[serde(default)]
    pub provenance_profile: SccmManifestProvenanceProfile,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collected_at_utc: Option<String>,
    pub max_files_per_source: usize,
    pub max_bytes_per_source: u64,
    pub artifacts: Vec<SccmManifestArtifact>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capture_gaps: Vec<SccmManifestCaptureGap>,
}

struct SharedBoundedVecSeed<T> {
    total: Rc<Cell<usize>>,
    marker: PhantomData<T>,
}

impl<'de, T> DeserializeSeed<'de> for SharedBoundedVecSeed<T>
where
    T: Deserialize<'de>,
{
    type Value = Vec<T>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct BoundedVisitor<T> {
            total: Rc<Cell<usize>>,
            marker: PhantomData<T>,
        }

        impl<'de, T> Visitor<'de> for BoundedVisitor<T>
        where
            T: Deserialize<'de>,
        {
            type Value = Vec<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded SCCM manifest entry array")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let remaining = MAX_SCCM_MANIFEST_ARTIFACTS.saturating_sub(self.total.get());
                if sequence.size_hint().is_some_and(|size| size > remaining) {
                    return Err(de::Error::custom(
                        "SCCM manifest has too many artifacts or capture gaps",
                    ));
                }
                let mut values =
                    Vec::with_capacity(sequence.size_hint().unwrap_or_default().min(remaining));
                while self.total.get() < MAX_SCCM_MANIFEST_ARTIFACTS {
                    let Some(value) = sequence.next_element()? else {
                        return Ok(values);
                    };
                    self.total.set(self.total.get() + 1);
                    values.push(value);
                }
                if sequence.next_element::<de::IgnoredAny>()?.is_some() {
                    return Err(de::Error::custom(
                        "SCCM manifest has too many artifacts or capture gaps",
                    ));
                }
                Ok(values)
            }
        }

        deserializer.deserialize_seq(BoundedVisitor {
            total: self.total,
            marker: self.marker,
        })
    }
}

impl<'de> Deserialize<'de> for SccmBundleManifestV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "camelCase")]
        enum Field {
            SccmManifestVersion,
            DiagnosticsSchemaVersion,
            SourceCatalogVersion,
            Provenance,
            ProvenanceProfile,
            HostHandle,
            CollectedAtUtc,
            MaxFilesPerSource,
            MaxBytesPerSource,
            Artifacts,
            CaptureGaps,
        }

        const FIELDS: &[&str] = &[
            "sccmManifestVersion",
            "diagnosticsSchemaVersion",
            "sourceCatalogVersion",
            "provenance",
            "provenanceProfile",
            "hostHandle",
            "collectedAtUtc",
            "maxFilesPerSource",
            "maxBytesPerSource",
            "artifacts",
            "captureGaps",
        ];

        struct ManifestVisitor;
        impl<'de> Visitor<'de> for ManifestVisitor {
            type Value = SccmBundleManifestV1;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an SCCM v1 manifest")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let total = Rc::new(Cell::new(0));
                let mut sccm_manifest_version = None;
                let mut diagnostics_schema_version = None;
                let mut source_catalog_version = None;
                let mut provenance = None;
                let mut provenance_profile = None;
                let mut host_handle = None;
                let mut collected_at_utc = None;
                let mut max_files_per_source = None;
                let mut max_bytes_per_source = None;
                let mut artifacts = None;
                let mut capture_gaps = None;

                while let Some(field) = map.next_key()? {
                    match field {
                        Field::SccmManifestVersion => set_once(
                            &mut sccm_manifest_version,
                            map.next_value()?,
                            "sccmManifestVersion",
                        )?,
                        Field::DiagnosticsSchemaVersion => set_once(
                            &mut diagnostics_schema_version,
                            map.next_value()?,
                            "diagnosticsSchemaVersion",
                        )?,
                        Field::SourceCatalogVersion => set_once(
                            &mut source_catalog_version,
                            map.next_value()?,
                            "sourceCatalogVersion",
                        )?,
                        Field::Provenance => {
                            set_once(&mut provenance, map.next_value()?, "provenance")?
                        }
                        Field::ProvenanceProfile => set_once(
                            &mut provenance_profile,
                            map.next_value()?,
                            "provenanceProfile",
                        )?,
                        Field::HostHandle => {
                            set_once(&mut host_handle, map.next_value()?, "hostHandle")?
                        }
                        Field::CollectedAtUtc => {
                            set_once(&mut collected_at_utc, map.next_value()?, "collectedAtUtc")?
                        }
                        Field::MaxFilesPerSource => set_once(
                            &mut max_files_per_source,
                            map.next_value()?,
                            "maxFilesPerSource",
                        )?,
                        Field::MaxBytesPerSource => set_once(
                            &mut max_bytes_per_source,
                            map.next_value()?,
                            "maxBytesPerSource",
                        )?,
                        Field::Artifacts => {
                            if artifacts.is_some() {
                                return Err(de::Error::duplicate_field("artifacts"));
                            }
                            artifacts = Some(map.next_value_seed(SharedBoundedVecSeed {
                                total: Rc::clone(&total),
                                marker: PhantomData,
                            })?);
                        }
                        Field::CaptureGaps => {
                            if capture_gaps.is_some() {
                                return Err(de::Error::duplicate_field("captureGaps"));
                            }
                            capture_gaps = Some(map.next_value_seed(SharedBoundedVecSeed {
                                total: Rc::clone(&total),
                                marker: PhantomData,
                            })?);
                        }
                    }
                }

                Ok(SccmBundleManifestV1 {
                    sccm_manifest_version: required(sccm_manifest_version, "sccmManifestVersion")?,
                    diagnostics_schema_version: required(
                        diagnostics_schema_version,
                        "diagnosticsSchemaVersion",
                    )?,
                    source_catalog_version: required(
                        source_catalog_version,
                        "sourceCatalogVersion",
                    )?,
                    provenance: required(provenance, "provenance")?,
                    provenance_profile: provenance_profile.unwrap_or_default(),
                    host_handle: host_handle.unwrap_or(None),
                    collected_at_utc: collected_at_utc.unwrap_or(None),
                    max_files_per_source: required(max_files_per_source, "maxFilesPerSource")?,
                    max_bytes_per_source: required(max_bytes_per_source, "maxBytesPerSource")?,
                    artifacts: required(artifacts, "artifacts")?,
                    capture_gaps: capture_gaps.unwrap_or_default(),
                })
            }
        }

        fn set_once<E, T>(slot: &mut Option<T>, value: T, field: &'static str) -> Result<(), E>
        where
            E: de::Error,
        {
            if slot.replace(value).is_some() {
                return Err(E::duplicate_field(field));
            }
            Ok(())
        }

        fn required<E, T>(value: Option<T>, field: &'static str) -> Result<T, E>
        where
            E: de::Error,
        {
            value.ok_or_else(|| E::missing_field(field))
        }

        deserializer.deserialize_struct("SccmBundleManifestV1", FIELDS, ManifestVisitor)
    }
}

pub(crate) fn sha256_bytes(value: &[u8]) -> String {
    Sha256::digest(value)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn is_sha256_digest(value: &str) -> bool {
    value.len() == SHA256_HEX_CHARS
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

pub(crate) fn is_versioned_handle(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(is_sha256_digest)
}

pub(crate) fn catalog_entry_id(basename: &str) -> String {
    format!(
        "sccm-client-source:v1:sha256:{}",
        sha256_bytes(basename.as_bytes())
    )
}

pub(crate) fn logical_artifact_ids_for_basename(basename: &str) -> Vec<String> {
    let mut values = declared_client_source_groups()
        .into_iter()
        .filter(|group| {
            group
                .accepted_basenames
                .iter()
                .any(|value| value == basename)
        })
        .map(|group| group.logical_artifact_id)
        .collect::<Vec<_>>();
    values.sort();
    values
}

pub(crate) fn root_handle_digest(root_handle: &str) -> Option<&str> {
    let digest = root_handle.strip_prefix("root-")?;
    is_sha256_digest(digest).then_some(digest)
}

pub(crate) fn source_identity_digest(root_handle: &str, basename: &str) -> Option<String> {
    let root_digest = root_handle_digest(root_handle)?;
    Some(sha256_bytes(
        format!("cmtraceopen.sccm.source.v1\0{root_digest}\0{basename}").as_bytes(),
    ))
}

pub(crate) fn rotation_segment(rotation: &SccmRotation) -> String {
    match rotation {
        SccmRotation::Current => "current".to_owned(),
        SccmRotation::LoUnderscore => "lo".to_owned(),
        SccmRotation::Numbered(number) => format!("numbered-{number}"),
        SccmRotation::Timestamped(timestamp) => format!("timestamped-{timestamp}"),
        SccmRotation::Unknown(_) => "unknown".to_owned(),
    }
}

pub(crate) fn expected_bundle_group(logical_artifact_ids: &[String]) -> &str {
    if logical_artifact_ids == ["client-content", "client-location"] {
        "client-location-services-shared"
    } else {
        logical_artifact_ids
            .first()
            .map(String::as_str)
            .unwrap_or("unknown")
    }
}

pub(crate) fn expected_physical_artifact_id(
    fingerprint: &str,
    rotation: &SccmRotation,
    basename: &str,
) -> String {
    format!(
        "sccm-artifact:v1:sha256:{}",
        sha256_bytes(
            format!(
                "artifact:v1:{fingerprint}:{}:{basename}",
                rotation_segment(rotation)
            )
            .as_bytes()
        )
    )
}

pub(crate) fn expected_marker_artifact_id(
    catalog_entry_id: &str,
    state: SccmManifestSourceState,
    rotation: &SccmRotation,
    basename: &str,
    path_fingerprint: Option<&str>,
) -> String {
    format!(
        "sccm-artifact:v1:sha256:{}",
        sha256_bytes(
            format!(
                "marker:v1:{catalog_entry_id}:{}:{}:{basename}:{}",
                manifest_state_segment(state),
                rotation_segment(rotation),
                path_fingerprint.unwrap_or("unscoped")
            )
            .as_bytes()
        )
    )
}

fn manifest_state_segment(state: SccmManifestSourceState) -> &'static str {
    match state {
        SccmManifestSourceState::Captured => "captured",
        SccmManifestSourceState::Absent => "absent",
        SccmManifestSourceState::AccessDenied => "accessDenied",
        SccmManifestSourceState::Capped => "capped",
        SccmManifestSourceState::Skipped => "skipped",
        SccmManifestSourceState::Unsupported => "unsupported",
        SccmManifestSourceState::UnsafePath => "unsafePath",
        SccmManifestSourceState::ParseFailed => "parseFailed",
        SccmManifestSourceState::FailedUnknownDetail => "failedUnknownDetail",
    }
}

pub(crate) fn rotation_order(left: &SccmRotation, right: &SccmRotation) -> Ordering {
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

pub(crate) fn compare_manifest_artifacts(
    left: &SccmManifestArtifact,
    right: &SccmManifestArtifact,
) -> Ordering {
    left.logical_artifact_ids
        .cmp(&right.logical_artifact_ids)
        .then_with(|| {
            left.path_fingerprint
                .as_deref()
                .unwrap_or_default()
                .cmp(right.path_fingerprint.as_deref().unwrap_or_default())
        })
        .then_with(|| rotation_order(&left.rotation, &right.rotation))
        .then_with(|| left.basename.cmp(&right.basename))
        .then_with(|| left.artifact_id.cmp(&right.artifact_id))
}

pub(crate) fn compare_manifest_capture_gaps(
    left: &SccmManifestCaptureGap,
    right: &SccmManifestCaptureGap,
) -> Ordering {
    left.logical_artifact_ids
        .cmp(&right.logical_artifact_ids)
        .then_with(|| left.path_fingerprint.cmp(&right.path_fingerprint))
        .then_with(|| rotation_order(&left.rotation, &right.rotation))
        .then_with(|| left.basename.cmp(&right.basename))
        .then_with(|| left.artifact_id.cmp(&right.artifact_id))
}

pub(crate) fn canonical_client_source(basename: &str, rotation: &SccmRotation) -> Option<String> {
    let classified = classify_artifact_name(basename, SccmRole::Client);
    (classified.supported_for_diagnosis && classified.rotation == *rotation)
        .then_some(classified.basename)
}
