use serde::{Deserialize, Serialize};

pub const SCCM_DIAGNOSTICS_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmCoverageState {
    Captured,
    Absent,
    AccessDenied,
    Capped,
    Skipped,
    Unsupported,
    ParseFailed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmRole {
    Client,
    SiteServer,
    ManagementPoint,
    DistributionPoint,
    SoftwareUpdatePoint,
    WsUs,
    Provider,
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmFindingClass {
    Symptom,
    ConfirmedFailure,
    BlockedOrDeferred,
    LikelyContributor,
    InsufficientEvidence,
}

impl SccmFindingClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Symptom => "symptom",
            Self::ConfirmedFailure => "confirmedFailure",
            Self::BlockedOrDeferred => "blockedOrDeferred",
            Self::LikelyContributor => "likelyContributor",
            Self::InsufficientEvidence => "insufficientEvidence",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "camelCase")]
pub enum SccmRotation {
    Current,
    LoUnderscore,
    Numbered(u32),
    Timestamped(String),
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmArtifact {
    pub artifact_id: String,
    pub display_name: String,
    pub original_path: Option<String>,
    pub host: Option<String>,
    pub role: SccmRole,
    pub configmgr_version: Option<String>,
    pub collected_at_utc: Option<String>,
    pub rotation: SccmRotation,
    pub coverage: SccmCoverageState,
    pub encoding: Option<String>,
}

impl SccmArtifact {
    pub fn missing(
        artifact_id: impl Into<String>,
        display_name: impl Into<String>,
        role: SccmRole,
        coverage: SccmCoverageState,
    ) -> Self {
        Self {
            artifact_id: artifact_id.into(),
            display_name: display_name.into(),
            original_path: None,
            host: None,
            role,
            configmgr_version: None,
            collected_at_utc: None,
            rotation: SccmRotation::Current,
            coverage,
            encoding: None,
        }
    }
}
