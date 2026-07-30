use serde::ser::{Error as _, SerializeStruct};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use super::rotation::{is_canonical_rotation_number, is_canonical_rotation_timestamp};

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

#[derive(Debug, Clone, PartialEq)]
pub enum SccmRole {
    Client,
    SiteServer,
    ManagementPoint,
    DistributionPoint,
    SoftwareUpdatePoint,
    WsUs,
    Provider,
    AdminService,
    Unknown(String),
}

impl SccmRole {
    fn serialized_name(&self) -> &str {
        match self {
            Self::Client => "client",
            Self::SiteServer => "siteServer",
            Self::ManagementPoint => "managementPoint",
            Self::DistributionPoint => "distributionPoint",
            Self::SoftwareUpdatePoint => "softwareUpdatePoint",
            Self::WsUs => "wsUs",
            Self::Provider => "provider",
            Self::AdminService => "adminService",
            Self::Unknown(value) => value,
        }
    }
}

impl Serialize for SccmRole {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.serialized_name())
    }
}

impl<'de> Deserialize<'de> for SccmRole {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(match String::deserialize(deserializer)? {
            value if value == "client" => Self::Client,
            value if value == "siteServer" => Self::SiteServer,
            value if value == "managementPoint" => Self::ManagementPoint,
            value if value == "distributionPoint" => Self::DistributionPoint,
            value if value == "softwareUpdatePoint" => Self::SoftwareUpdatePoint,
            value if value == "wsUs" => Self::WsUs,
            value if value == "provider" => Self::Provider,
            value if value == "adminService" => Self::AdminService,
            value => Self::Unknown(value),
        })
    }
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

#[derive(Debug, Clone, PartialEq)]
pub enum SccmRotation {
    Current,
    LoUnderscore,
    Numbered(u32),
    Timestamped(String),
    Unknown(SccmUnknownRotation),
}

#[derive(Debug, Clone, PartialEq)]
pub struct SccmUnknownRotation {
    pub kind: String,
    pub value: Option<Value>,
}

impl Serialize for SccmRotation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Numbered(value) if !is_canonical_rotation_number(*value) => {
                return Err(S::Error::custom(
                    "numbered rotation value must be a nonzero u32",
                ));
            }
            Self::Timestamped(value) if !is_canonical_rotation_timestamp(value) => {
                return Err(S::Error::custom(
                    "timestamped rotation value must use canonical YYYYMMDD-HHMMSS",
                ));
            }
            _ => {}
        }

        let field_count = match self {
            Self::Current | Self::LoUnderscore => 1,
            Self::Numbered(_) | Self::Timestamped(_) => 2,
            Self::Unknown(unknown) => 1 + usize::from(unknown.value.is_some()),
        };
        let mut state = serializer.serialize_struct("SccmRotation", field_count)?;

        match self {
            Self::Current => state.serialize_field("kind", "current")?,
            Self::LoUnderscore => state.serialize_field("kind", "loUnderscore")?,
            Self::Numbered(value) => {
                state.serialize_field("kind", "numbered")?;
                state.serialize_field("value", value)?;
            }
            Self::Timestamped(value) => {
                state.serialize_field("kind", "timestamped")?;
                state.serialize_field("value", value)?;
            }
            Self::Unknown(unknown) => {
                state.serialize_field("kind", &unknown.kind)?;
                if let Some(value) = &unknown.value {
                    state.serialize_field("value", value)?;
                }
            }
        }

        state.end()
    }
}

impl<'de> Deserialize<'de> for SccmRotation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let Value::Object(mut fields) = Value::deserialize(deserializer)? else {
            return Err(serde::de::Error::custom(
                "SCCM rotation must be a tagged object",
            ));
        };
        let kind = fields
            .remove("kind")
            .and_then(|value| value.as_str().map(str::to_owned))
            .ok_or_else(|| serde::de::Error::custom("SCCM rotation kind must be a string"))?;
        let value = fields.remove("value");

        if !fields.is_empty() {
            return Err(serde::de::Error::custom(
                "SCCM rotation contains unsupported fields",
            ));
        }

        match kind.as_str() {
            "current" => {
                require_no_rotation_value::<D::Error>(&kind, value)?;
                Ok(Self::Current)
            }
            "loUnderscore" => {
                require_no_rotation_value::<D::Error>(&kind, value)?;
                Ok(Self::LoUnderscore)
            }
            "numbered" => {
                let number = value
                    .and_then(|value| value.as_u64())
                    .and_then(|value| u32::try_from(value).ok())
                    .ok_or_else(|| {
                        serde::de::Error::custom("numbered rotation value must be a u32")
                    })?;
                if !is_canonical_rotation_number(number) {
                    return Err(serde::de::Error::custom(
                        "numbered rotation value must be a nonzero u32",
                    ));
                }
                Ok(Self::Numbered(number))
            }
            "timestamped" => {
                let timestamp = value
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .ok_or_else(|| {
                        serde::de::Error::custom("timestamped rotation value must be a string")
                    })?;
                if !is_canonical_rotation_timestamp(&timestamp) {
                    return Err(serde::de::Error::custom(
                        "timestamped rotation value must use canonical YYYYMMDD-HHMMSS",
                    ));
                }
                Ok(Self::Timestamped(timestamp))
            }
            _ => Ok(Self::Unknown(SccmUnknownRotation { kind, value })),
        }
    }
}

fn require_no_rotation_value<E>(kind: &str, value: Option<Value>) -> Result<(), E>
where
    E: serde::de::Error,
{
    if value.is_some() {
        return Err(E::custom(format!(
            "{kind} rotation must not contain a value"
        )));
    }
    Ok(())
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
