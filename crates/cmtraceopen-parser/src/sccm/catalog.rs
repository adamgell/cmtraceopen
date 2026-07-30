use serde::{Deserialize, Serialize};

use super::{SccmRole, SccmRotation};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmSourceCatalogEntry {
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
        role: SccmRole::ManagementPoint,
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
        role: SccmRole::SoftwareUpdatePoint,
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
        role: SccmRole::SoftwareUpdatePoint,
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
    let known = if parsed.is_log_name {
        SOURCE_CATALOG.iter().find(|entry| {
            entry.basename.eq_ignore_ascii_case(parsed.basename) && entry.role == role
        })
    } else {
        None
    };

    if let Some(entry) = known {
        return SccmSourceCatalogEntry {
            logical_name: entry.logical_name.to_string(),
            role,
            family: entry.family.clone(),
            rotation: parsed.rotation,
            uses_ccm_records: true,
            supported_for_diagnosis: true,
        };
    }

    let logical_name = lower_camel_identifier(parsed.basename);
    SccmSourceCatalogEntry {
        family: SccmArtifactFamily::Unknown(logical_name.clone()),
        logical_name,
        role,
        rotation: parsed.rotation,
        uses_ccm_records: false,
        supported_for_diagnosis: false,
    }
}

struct ParsedArtifactName<'a> {
    basename: &'a str,
    rotation: SccmRotation,
    is_log_name: bool,
}

impl<'a> ParsedArtifactName<'a> {
    fn from_name(name: &'a str) -> Self {
        let lowercase = name.to_ascii_lowercase();

        if lowercase.ends_with(".log.lo_") {
            return Self {
                basename: &name[..name.len() - ".log.lo_".len()],
                rotation: SccmRotation::LoUnderscore,
                is_log_name: true,
            };
        }

        if lowercase.ends_with(".lo_") {
            return Self {
                basename: &name[..name.len() - ".lo_".len()],
                rotation: SccmRotation::LoUnderscore,
                is_log_name: true,
            };
        }

        if let Some(separator) = lowercase.rfind(".log.") {
            let suffix = &lowercase[separator + ".log.".len()..];
            if !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit()) {
                if let Ok(number) = suffix.parse::<u32>() {
                    return Self {
                        basename: &name[..separator],
                        rotation: SccmRotation::Numbered(number),
                        is_log_name: true,
                    };
                }
            }
        }

        if lowercase.ends_with(".log") {
            return Self {
                basename: &name[..name.len() - ".log".len()],
                rotation: SccmRotation::Current,
                is_log_name: true,
            };
        }

        Self {
            basename: name,
            rotation: SccmRotation::Current,
            is_log_name: false,
        }
    }
}

fn lower_camel_identifier(value: &str) -> String {
    let mut result = String::new();
    let mut capitalize_next = false;

    for character in value.chars() {
        if !character.is_alphanumeric() {
            capitalize_next = !result.is_empty();
            continue;
        }

        if result.is_empty() {
            result.extend(character.to_lowercase());
        } else if capitalize_next {
            result.extend(character.to_uppercase());
            capitalize_next = false;
        } else {
            result.push(character);
        }
    }

    if result.is_empty() {
        "unknown".to_string()
    } else {
        result
    }
}
