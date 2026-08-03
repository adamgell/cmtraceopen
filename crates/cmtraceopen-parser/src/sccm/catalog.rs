use serde::de::Error as _;
use serde::ser::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use super::rotation::{is_canonical_rotation_timestamp, parse_canonical_rotation_number};
use super::{SccmRole, SccmRotation, SccmUnknownRotation};

const INVALID_SCCM_ARTIFACT_FAMILY_MESSAGE: &str =
    "InvalidArtifactFamily: unknown SCCM artifact family must be canonical and must not shadow a declared family";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SccmArtifactFamily {
    ClientSetup,
    ClientHealth,
    ClientIdentity,
    ClientLocation,
    ClientPolicy,
    ClientContent,
    ClientApplication,
    ClientUpdates,
    ClientTaskSequence,
    SiteComponent,
    SiteStatus,
    ManagementPoint,
    DistributionPoint,
    SoftwareUpdatePoint,
    Hierarchy,
    Provider,
    AdminService,
    Unknown(String),
}

impl SccmArtifactFamily {
    fn serialized_name(&self) -> &str {
        match self {
            Self::ClientSetup => "clientSetup",
            Self::ClientHealth => "clientHealth",
            Self::ClientIdentity => "clientIdentity",
            Self::ClientLocation => "clientLocation",
            Self::ClientPolicy => "clientPolicy",
            Self::ClientContent => "clientContent",
            Self::ClientApplication => "clientApplication",
            Self::ClientUpdates => "clientUpdates",
            Self::ClientTaskSequence => "clientTaskSequence",
            Self::SiteComponent => "siteComponent",
            Self::SiteStatus => "siteStatus",
            Self::ManagementPoint => "managementPoint",
            Self::DistributionPoint => "distributionPoint",
            Self::SoftwareUpdatePoint => "softwareUpdatePoint",
            Self::Hierarchy => "hierarchy",
            Self::Provider => "provider",
            Self::AdminService => "adminService",
            Self::Unknown(value) => value,
        }
    }

    /// Maps a wire value back to the declared variant that owns it.
    ///
    /// This is the single source of truth for which names are declared, so the
    /// shadow check below can never drift from what `Deserialize` accepts.
    fn declared_from_serialized_name(value: &str) -> Option<Self> {
        Some(match value {
            "clientSetup" => Self::ClientSetup,
            "clientHealth" => Self::ClientHealth,
            "clientIdentity" => Self::ClientIdentity,
            "clientLocation" => Self::ClientLocation,
            "clientPolicy" => Self::ClientPolicy,
            "clientContent" => Self::ClientContent,
            "clientApplication" => Self::ClientApplication,
            "clientUpdates" => Self::ClientUpdates,
            "clientTaskSequence" => Self::ClientTaskSequence,
            "siteComponent" => Self::SiteComponent,
            "siteStatus" => Self::SiteStatus,
            "managementPoint" => Self::ManagementPoint,
            "distributionPoint" => Self::DistributionPoint,
            "softwareUpdatePoint" => Self::SoftwareUpdatePoint,
            "hierarchy" => Self::Hierarchy,
            "provider" => Self::Provider,
            "adminService" => Self::AdminService,
            _ => return None,
        })
    }

    fn has_canonical_serialized_form(&self) -> bool {
        match self {
            Self::Unknown(value) => {
                !value.is_empty()
                    && value.trim() == value
                    && Self::declared_from_serialized_name(value).is_none()
            }
            _ => true,
        }
    }
}

impl Serialize for SccmArtifactFamily {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if !self.has_canonical_serialized_form() {
            return Err(S::Error::custom(INVALID_SCCM_ARTIFACT_FAMILY_MESSAGE));
        }
        serializer.serialize_str(self.serialized_name())
    }
}

impl<'de> Deserialize<'de> for SccmArtifactFamily {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let family = Self::declared_from_serialized_name(&value).unwrap_or(Self::Unknown(value));
        if !family.has_canonical_serialized_form() {
            return Err(D::Error::custom(INVALID_SCCM_ARTIFACT_FAMILY_MESSAGE));
        }
        Ok(family)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmSourceCatalogEntry {
    pub basename: String,
    pub logical_name: String,
    pub role: SccmRole,
    pub family: SccmArtifactFamily,
    pub rotation: SccmRotation,
    pub uses_ccm_records: bool,
    pub supported_for_diagnosis: bool,
}

struct CatalogSpec {
    basename: &'static str,
    logical_name: &'static str,
    role: SccmRole,
    family: SccmArtifactFamily,
}

const SOURCE_CATALOG: &[CatalogSpec] = &[
    CatalogSpec {
        basename: "CCMSetup",
        logical_name: "ccmSetup",
        role: SccmRole::Client,
        family: SccmArtifactFamily::ClientSetup,
    },
    CatalogSpec {
        basename: "CcmEval",
        logical_name: "ccmEval",
        role: SccmRole::Client,
        family: SccmArtifactFamily::ClientHealth,
    },
    CatalogSpec {
        basename: "CcmExec",
        logical_name: "ccmExec",
        role: SccmRole::Client,
        family: SccmArtifactFamily::ClientHealth,
    },
    CatalogSpec {
        basename: "CcmRestart",
        logical_name: "ccmRestart",
        role: SccmRole::Client,
        family: SccmArtifactFamily::ClientHealth,
    },
    CatalogSpec {
        basename: "ClientIDManagerStartup",
        logical_name: "clientIdManagerStartup",
        role: SccmRole::Client,
        family: SccmArtifactFamily::ClientIdentity,
    },
    CatalogSpec {
        basename: "ClientLocation",
        logical_name: "clientLocation",
        role: SccmRole::Client,
        family: SccmArtifactFamily::ClientLocation,
    },
    CatalogSpec {
        basename: "LocationServices",
        logical_name: "locationServices",
        role: SccmRole::Client,
        family: SccmArtifactFamily::ClientLocation,
    },
    CatalogSpec {
        basename: "CcmMessaging",
        logical_name: "ccmMessaging",
        role: SccmRole::Client,
        family: SccmArtifactFamily::ClientLocation,
    },
    CatalogSpec {
        basename: "PolicyAgent",
        logical_name: "policyAgent",
        role: SccmRole::Client,
        family: SccmArtifactFamily::ClientPolicy,
    },
    CatalogSpec {
        basename: "PolicyAgentProvider",
        logical_name: "policyAgentProvider",
        role: SccmRole::Client,
        family: SccmArtifactFamily::ClientPolicy,
    },
    CatalogSpec {
        basename: "PolicyEvaluator",
        logical_name: "policyEvaluator",
        role: SccmRole::Client,
        family: SccmArtifactFamily::ClientPolicy,
    },
    CatalogSpec {
        basename: "Scheduler",
        logical_name: "scheduler",
        role: SccmRole::Client,
        family: SccmArtifactFamily::ClientPolicy,
    },
    CatalogSpec {
        basename: "CAS",
        logical_name: "cas",
        role: SccmRole::Client,
        family: SccmArtifactFamily::ClientContent,
    },
    CatalogSpec {
        basename: "ContentTransferManager",
        logical_name: "contentTransferManager",
        role: SccmRole::Client,
        family: SccmArtifactFamily::ClientContent,
    },
    CatalogSpec {
        basename: "DataTransferService",
        logical_name: "dataTransferService",
        role: SccmRole::Client,
        family: SccmArtifactFamily::ClientContent,
    },
    CatalogSpec {
        basename: "AppIntentEval",
        logical_name: "appIntentEval",
        role: SccmRole::Client,
        family: SccmArtifactFamily::ClientApplication,
    },
    CatalogSpec {
        basename: "AppDiscovery",
        logical_name: "appDiscovery",
        role: SccmRole::Client,
        family: SccmArtifactFamily::ClientApplication,
    },
    CatalogSpec {
        basename: "AppEnforce",
        logical_name: "appEnforce",
        role: SccmRole::Client,
        family: SccmArtifactFamily::ClientApplication,
    },
    CatalogSpec {
        basename: "ScanAgent",
        logical_name: "scanAgent",
        role: SccmRole::Client,
        family: SccmArtifactFamily::ClientUpdates,
    },
    CatalogSpec {
        basename: "WUAHandler",
        logical_name: "wuaHandler",
        role: SccmRole::Client,
        family: SccmArtifactFamily::ClientUpdates,
    },
    CatalogSpec {
        basename: "UpdatesDeployment",
        logical_name: "updatesDeployment",
        role: SccmRole::Client,
        family: SccmArtifactFamily::ClientUpdates,
    },
    CatalogSpec {
        basename: "UpdatesHandler",
        logical_name: "updatesHandler",
        role: SccmRole::Client,
        family: SccmArtifactFamily::ClientUpdates,
    },
    CatalogSpec {
        basename: "UpdatesStore",
        logical_name: "updatesStore",
        role: SccmRole::Client,
        family: SccmArtifactFamily::ClientUpdates,
    },
    CatalogSpec {
        basename: "smsts",
        logical_name: "smsts",
        role: SccmRole::Client,
        family: SccmArtifactFamily::ClientTaskSequence,
    },
    CatalogSpec {
        basename: "sitecomp",
        logical_name: "sitecomp",
        role: SccmRole::SiteServer,
        family: SccmArtifactFamily::SiteComponent,
    },
    CatalogSpec {
        basename: "hman",
        logical_name: "hman",
        role: SccmRole::SiteServer,
        family: SccmArtifactFamily::SiteComponent,
    },
    CatalogSpec {
        basename: "statmgr",
        logical_name: "statmgr",
        role: SccmRole::SiteServer,
        family: SccmArtifactFamily::SiteStatus,
    },
    CatalogSpec {
        basename: "statesys",
        logical_name: "statesys",
        role: SccmRole::SiteServer,
        family: SccmArtifactFamily::SiteStatus,
    },
    CatalogSpec {
        basename: "MP_CliReg",
        logical_name: "mpCliReg",
        role: SccmRole::ManagementPoint,
        family: SccmArtifactFamily::ManagementPoint,
    },
    CatalogSpec {
        basename: "MP_GetAuth",
        logical_name: "mpGetAuth",
        role: SccmRole::ManagementPoint,
        family: SccmArtifactFamily::ManagementPoint,
    },
    CatalogSpec {
        basename: "MP_GetPolicy",
        logical_name: "mpGetPolicy",
        role: SccmRole::ManagementPoint,
        family: SccmArtifactFamily::ManagementPoint,
    },
    CatalogSpec {
        basename: "MP_Location",
        logical_name: "mpLocation",
        role: SccmRole::ManagementPoint,
        family: SccmArtifactFamily::ManagementPoint,
    },
    CatalogSpec {
        basename: "MP_RegistrationManager",
        logical_name: "mpRegistrationManager",
        role: SccmRole::ManagementPoint,
        family: SccmArtifactFamily::ManagementPoint,
    },
    CatalogSpec {
        basename: "mpcontrol",
        logical_name: "mpcontrol",
        role: SccmRole::SiteServer,
        family: SccmArtifactFamily::ManagementPoint,
    },
    CatalogSpec {
        basename: "distmgr",
        logical_name: "distmgr",
        role: SccmRole::SiteServer,
        family: SccmArtifactFamily::DistributionPoint,
    },
    CatalogSpec {
        basename: "PkgXferMgr",
        logical_name: "pkgXferMgr",
        role: SccmRole::SiteServer,
        family: SccmArtifactFamily::DistributionPoint,
    },
    CatalogSpec {
        basename: "SMSDPProv",
        logical_name: "smsDpProv",
        role: SccmRole::DistributionPoint,
        family: SccmArtifactFamily::DistributionPoint,
    },
    CatalogSpec {
        basename: "PullDP",
        logical_name: "pullDp",
        role: SccmRole::DistributionPoint,
        family: SccmArtifactFamily::DistributionPoint,
    },
    CatalogSpec {
        basename: "WCM",
        logical_name: "wcm",
        role: SccmRole::SiteServer,
        family: SccmArtifactFamily::SoftwareUpdatePoint,
    },
    CatalogSpec {
        basename: "WSUSCtrl",
        logical_name: "wsusCtrl",
        role: SccmRole::SoftwareUpdatePoint,
        family: SccmArtifactFamily::SoftwareUpdatePoint,
    },
    CatalogSpec {
        basename: "wsyncmgr",
        logical_name: "wsyncmgr",
        role: SccmRole::SiteServer,
        family: SccmArtifactFamily::SoftwareUpdatePoint,
    },
    CatalogSpec {
        basename: "SUPSetup",
        logical_name: "supSetup",
        role: SccmRole::SoftwareUpdatePoint,
        family: SccmArtifactFamily::SoftwareUpdatePoint,
    },
    CatalogSpec {
        basename: "replmgr",
        logical_name: "replmgr",
        role: SccmRole::SiteServer,
        family: SccmArtifactFamily::Hierarchy,
    },
    CatalogSpec {
        basename: "rcmctrl",
        logical_name: "rcmctrl",
        role: SccmRole::SiteServer,
        family: SccmArtifactFamily::Hierarchy,
    },
    CatalogSpec {
        basename: "sender",
        logical_name: "sender",
        role: SccmRole::SiteServer,
        family: SccmArtifactFamily::Hierarchy,
    },
    CatalogSpec {
        basename: "despool",
        logical_name: "despool",
        role: SccmRole::SiteServer,
        family: SccmArtifactFamily::Hierarchy,
    },
    CatalogSpec {
        basename: "Smsprov",
        logical_name: "smsprov",
        role: SccmRole::Provider,
        family: SccmArtifactFamily::Provider,
    },
    CatalogSpec {
        basename: "AdminService",
        logical_name: "adminService",
        role: SccmRole::Provider,
        family: SccmArtifactFamily::AdminService,
    },
];

pub fn classify_artifact_name(name: &str, role: SccmRole) -> SccmSourceCatalogEntry {
    let parsed = ParsedArtifactName::from_name(name);
    let known = SOURCE_CATALOG
        .iter()
        .find(|entry| entry.basename.eq_ignore_ascii_case(parsed.basename) && entry.role == role);

    if let Some(entry) = known {
        return SccmSourceCatalogEntry {
            basename: format!("{}.log", entry.basename),
            logical_name: entry.logical_name.to_string(),
            role,
            family: entry.family.clone(),
            rotation: parsed.rotation,
            uses_ccm_records: true,
            supported_for_diagnosis: parsed.rotation_supported,
        };
    }

    let logical_name = lower_camel_identifier(parsed.basename);
    SccmSourceCatalogEntry {
        basename: format!("{}.log", parsed.basename),
        family: unclassified_family(&logical_name),
        logical_name,
        role,
        rotation: parsed.rotation,
        uses_ccm_records: false,
        supported_for_diagnosis: false,
    }
}

pub fn declared_source_catalog() -> Vec<SccmSourceCatalogEntry> {
    let mut declared = Vec::with_capacity(SOURCE_CATALOG.len());

    for entry in SOURCE_CATALOG {
        declared.push(declared_catalog_entry(entry, entry.role.clone()));
    }

    declared
}

fn declared_catalog_entry(entry: &CatalogSpec, role: SccmRole) -> SccmSourceCatalogEntry {
    SccmSourceCatalogEntry {
        basename: format!("{}.log", entry.basename),
        logical_name: entry.logical_name.to_string(),
        role,
        family: entry.family.clone(),
        rotation: SccmRotation::Current,
        uses_ccm_records: true,
        supported_for_diagnosis: true,
    }
}

struct ParsedArtifactName<'a> {
    basename: &'a str,
    rotation: SccmRotation,
    rotation_supported: bool,
}

impl<'a> ParsedArtifactName<'a> {
    fn from_name(name: &'a str) -> Self {
        let lowercase = name.to_ascii_lowercase();

        if lowercase.ends_with(".log") {
            return Self {
                basename: &name[..name.len() - ".log".len()],
                rotation: SccmRotation::Current,
                rotation_supported: true,
            };
        }

        if let Some(separator) = lowercase.rfind(".log.") {
            let suffix = &name[separator + ".log.".len()..];
            let rotation = if let Some(number) = parse_canonical_rotation_number(suffix) {
                Some(SccmRotation::Numbered(number))
            } else if is_canonical_rotation_timestamp(suffix) {
                Some(SccmRotation::Timestamped(suffix.to_string()))
            } else {
                None
            };

            if let Some(rotation) = rotation {
                return Self {
                    basename: &name[..separator],
                    rotation,
                    rotation_supported: true,
                };
            }

            return Self {
                basename: &name[..separator],
                rotation: unknown_filename_suffix(&name[separator + ".log".len()..]),
                rotation_supported: false,
            };
        }

        if lowercase.ends_with(".lo_") {
            return Self {
                basename: &name[..name.len() - ".lo_".len()],
                rotation: SccmRotation::LoUnderscore,
                rotation_supported: true,
            };
        }

        if let Some(separator) = name.rfind('.') {
            return Self {
                basename: &name[..separator],
                rotation: unknown_filename_suffix(&name[separator..]),
                rotation_supported: false,
            };
        }

        Self {
            basename: name,
            rotation: unknown_filename_suffix(""),
            rotation_supported: false,
        }
    }
}

fn unknown_filename_suffix(raw_suffix: &str) -> SccmRotation {
    SccmRotation::Unknown(SccmUnknownRotation {
        kind: "filenameSuffix".to_string(),
        value: Some(Value::String(raw_suffix.to_string())),
    })
}

/// Builds the `Unknown` family for an artifact the catalog does not declare.
///
/// The family is derived from the artifact's own name, which can collide with a
/// declared family name: `AdminService.log` under a role the catalog does not
/// pair it with derives `adminService`. Emitting that verbatim would round-trip
/// back as the declared `AdminService` variant, so collisions are prefixed to
/// keep the unclassified identity distinct.
fn unclassified_family(logical_name: &str) -> SccmArtifactFamily {
    if SccmArtifactFamily::declared_from_serialized_name(logical_name).is_none() {
        return SccmArtifactFamily::Unknown(logical_name.to_string());
    }

    let mut characters = logical_name.chars();
    let mut name = String::from("unclassified");
    if let Some(first) = characters.next() {
        name.extend(first.to_uppercase());
        name.extend(characters);
    }
    SccmArtifactFamily::Unknown(name)
}

fn lower_camel_identifier(value: &str) -> String {
    let mut words = value
        .split(|character: char| !character.is_alphanumeric())
        .filter(|word| !word.is_empty());
    let Some(first) = words.next() else {
        return "unknown".to_string();
    };

    let mut result = lower_leading_initialism(first);
    for word in words {
        let mut characters = word.chars();
        if let Some(first) = characters.next() {
            result.extend(first.to_uppercase());
            result.extend(characters);
        }
    }
    result
}

fn lower_leading_initialism(word: &str) -> String {
    let characters: Vec<char> = word.chars().collect();
    let uppercase_run = characters
        .iter()
        .take_while(|character| character.is_uppercase())
        .count();
    let lowercase_count = if uppercase_run > 1
        && uppercase_run < characters.len()
        && characters[uppercase_run].is_lowercase()
    {
        uppercase_run - 1
    } else {
        uppercase_run
    };

    let mut result = String::new();
    for character in &characters[..lowercase_count] {
        result.extend(character.to_lowercase());
    }
    for character in &characters[lowercase_count..] {
        result.push(*character);
    }
    result
}
