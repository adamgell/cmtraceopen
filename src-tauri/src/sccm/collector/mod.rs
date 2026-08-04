//! Privacy-preserving native SCCM discovery and collection.

mod client_manifest;
mod discovery;
mod engine;
mod server_manifest;

use std::fmt;
use std::path::PathBuf;

use serde::Serialize;

use super::{SccmCoverageState, SccmRole};

pub use discovery::{discover_environment, discover_environment_with, NativeDiscoveryProvider};
pub use engine::{capture_environment, MAX_BYTES_PER_SOURCE, MAX_FRAGMENTS_PER_SOURCE};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmDiscoveryBasis {
    Registry,
    Service,
    Cim,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmRotationCategory {
    Current,
    LoUnderscore,
    Numbered,
    Timestamped,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmSourceDetailCode {
    AccessDenied,
    ByteLimitExceeded,
    FileLimitExceeded,
    MalformedRotation,
    ReadFailed,
    UnsafePath,
    UnsupportedPlatform,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmDiscoveryIssueCode {
    UnsupportedPlatform,
    RegistryAccessDenied,
    CimAccessDenied,
    DiscoveryFailed,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmDetectedRole {
    pub role: SccmRole,
    pub basis: SccmDiscoveryBasis,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmSourceStatus {
    pub role: SccmRole,
    pub source_id: String,
    pub rotation: SccmRotationCategory,
    pub state: SccmCoverageState,
    pub retained_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail_code: Option<SccmSourceDetailCode>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmDiscoveryIssue {
    pub code: SccmDiscoveryIssueCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<SccmRole>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmEnvironmentDiscovery {
    pub supported: bool,
    pub configmgr_version: Option<String>,
    pub roles: Vec<SccmDetectedRole>,
    pub sources: Vec<SccmSourceStatus>,
    pub issues: Vec<SccmDiscoveryIssue>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmCaptureResult {
    pub bundle_root: String,
    pub captured_at_utc: String,
    pub roles: Vec<SccmRole>,
    pub sources: Vec<SccmSourceStatus>,
    pub artifact_count: usize,
    pub retained_bytes: u64,
}

/// Private discovery facts. These values are deliberately never serialized
/// across the Tauri boundary.
#[derive(Debug, Clone, Default)]
pub struct PrivateSccmEnvironment {
    pub supported: bool,
    pub configmgr_version: Option<String>,
    pub roles: Vec<SccmDetectedRole>,
    pub roots: Vec<SccmCaptureRoot>,
    pub issues: Vec<SccmDiscoveryIssue>,
    pub private_host: Option<String>,
    pub private_site_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SccmCaptureRoot {
    pub role: SccmRole,
    pub path: PathBuf,
}

pub trait SccmDiscoveryProvider {
    fn discover(&self) -> Result<PrivateSccmEnvironment, SccmDiscoveryFailure>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SccmDiscoveryFailure {
    Failed,
}

impl fmt::Display for SccmDiscoveryFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SCCM discovery failed")
    }
}

impl std::error::Error for SccmDiscoveryFailure {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SccmCollectorError {
    DiscoveryFailed,
    DestinationUnavailable,
    CaptureFailed,
    ManifestValidationFailed,
}

impl SccmCollectorError {
    pub fn code(self) -> &'static str {
        match self {
            Self::DiscoveryFailed => "discoveryFailed",
            Self::DestinationUnavailable => "destinationUnavailable",
            Self::CaptureFailed => "captureFailed",
            Self::ManifestValidationFailed => "manifestValidationFailed",
        }
    }
}

impl fmt::Display for SccmCollectorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for SccmCollectorError {}

pub(crate) fn role_key(role: &SccmRole) -> String {
    serde_json::to_value(role)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}

pub(crate) fn normalize_public_discovery(
    mut discovery: SccmEnvironmentDiscovery,
) -> SccmEnvironmentDiscovery {
    discovery
        .roles
        .sort_by_key(|role| (role_key(&role.role), role.basis));
    discovery.roles.dedup_by(|left, right| left == right);
    sort_sources(&mut discovery.sources);
    discovery.issues.sort_by_key(|issue| {
        (
            issue.code,
            issue.role.as_ref().map(role_key).unwrap_or_default(),
        )
    });
    discovery.issues.dedup();
    discovery
}

pub(crate) fn sort_sources(sources: &mut [SccmSourceStatus]) {
    sources.sort_by_key(|source| {
        (
            role_key(&source.role),
            source.source_id.clone(),
            source.rotation,
            coverage_key(&source.state),
        )
    });
}

fn coverage_key(state: &SccmCoverageState) -> u8 {
    match state {
        SccmCoverageState::Captured => 0,
        SccmCoverageState::Absent => 1,
        SccmCoverageState::AccessDenied => 2,
        SccmCoverageState::Capped => 3,
        SccmCoverageState::Skipped => 4,
        SccmCoverageState::Unsupported => 5,
        SccmCoverageState::ParseFailed => 6,
    }
}
