use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use super::rotation::{is_canonical_rotation_timestamp, parse_canonical_rotation_number};
use super::{SccmRole, SccmRotation, SccmUnknownRotation};

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
    ClientInventory,
    ClientCompliance,
    ClientMetering,
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
    pub(crate) fn serialized_name(&self) -> &str {
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
            Self::ClientInventory => "clientInventory",
            Self::ClientCompliance => "clientCompliance",
            Self::ClientMetering => "clientMetering",
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
}

impl Serialize for SccmArtifactFamily {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.serialized_name())
    }
}

impl<'de> Deserialize<'de> for SccmArtifactFamily {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(match String::deserialize(deserializer)? {
            value if value == "clientSetup" => Self::ClientSetup,
            value if value == "clientHealth" => Self::ClientHealth,
            value if value == "clientIdentity" => Self::ClientIdentity,
            value if value == "clientLocation" => Self::ClientLocation,
            value if value == "clientPolicy" => Self::ClientPolicy,
            value if value == "clientContent" => Self::ClientContent,
            value if value == "clientApplication" => Self::ClientApplication,
            value if value == "clientUpdates" => Self::ClientUpdates,
            value if value == "clientTaskSequence" => Self::ClientTaskSequence,
            value if value == "clientInventory" => Self::ClientInventory,
            value if value == "clientCompliance" => Self::ClientCompliance,
            value if value == "clientMetering" => Self::ClientMetering,
            value if value == "siteComponent" => Self::SiteComponent,
            value if value == "siteStatus" => Self::SiteStatus,
            value if value == "managementPoint" => Self::ManagementPoint,
            value if value == "distributionPoint" => Self::DistributionPoint,
            value if value == "softwareUpdatePoint" => Self::SoftwareUpdatePoint,
            value if value == "hierarchy" => Self::Hierarchy,
            value if value == "provider" => Self::Provider,
            value if value == "adminService" => Self::AdminService,
            value => Self::Unknown(value),
        })
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

/// Immutable client intake membership owned by the shared SCCM source
/// catalog. A physical source may feed more than one logical intake group;
/// `LocationServices.log` is intentionally captured once and projected into
/// both location and content coverage.
#[derive(Clone, Copy)]
pub(crate) struct SccmClientSourceMembership {
    pub basename: &'static str,
    pub logical_artifact_ids: &'static [&'static str],
}

const CLIENT_SOURCE_MEMBERSHIPS: &[SccmClientSourceMembership] = &[
    SccmClientSourceMembership {
        basename: "AppEnforce.log",
        logical_artifact_ids: &["client-app-enforce"],
    },
    SccmClientSourceMembership {
        basename: "ExecMgr.log",
        logical_artifact_ids: &["client-app-enforce"],
    },
    SccmClientSourceMembership {
        basename: "AppDiscovery.log",
        logical_artifact_ids: &["client-app-intent"],
    },
    SccmClientSourceMembership {
        basename: "AppIntentEval.log",
        logical_artifact_ids: &["client-app-intent"],
    },
    SccmClientSourceMembership {
        basename: "ccmsetup.log",
        logical_artifact_ids: &["client-ccmsetup"],
    },
    SccmClientSourceMembership {
        basename: "client.msi.log",
        logical_artifact_ids: &["client-ccmsetup"],
    },
    SccmClientSourceMembership {
        basename: "CAS.log",
        logical_artifact_ids: &["client-content"],
    },
    SccmClientSourceMembership {
        basename: "ContentTransferManager.log",
        logical_artifact_ids: &["client-content"],
    },
    SccmClientSourceMembership {
        basename: "DataTransferService.log",
        logical_artifact_ids: &["client-content"],
    },
    SccmClientSourceMembership {
        basename: "CcmEval.log",
        logical_artifact_ids: &["client-evaluation"],
    },
    SccmClientSourceMembership {
        basename: "CcmExec.log",
        logical_artifact_ids: &["client-evaluation"],
    },
    SccmClientSourceMembership {
        basename: "CcmRestart.log",
        logical_artifact_ids: &["client-evaluation"],
    },
    SccmClientSourceMembership {
        basename: "ClientIDManagerStartup.log",
        logical_artifact_ids: &["client-identity"],
    },
    SccmClientSourceMembership {
        basename: "CcmMessaging.log",
        logical_artifact_ids: &["client-location"],
    },
    SccmClientSourceMembership {
        basename: "ClientLocation.log",
        logical_artifact_ids: &["client-location"],
    },
    SccmClientSourceMembership {
        basename: "LocationServices.log",
        logical_artifact_ids: &[
            "client-location",
            "client-content",
            "client-location-services-shared",
        ],
    },
    SccmClientSourceMembership {
        basename: "PolicyAgent.log",
        logical_artifact_ids: &["client-policy-agent"],
    },
    SccmClientSourceMembership {
        basename: "PolicyAgentProvider.log",
        logical_artifact_ids: &["client-policy-agent"],
    },
    SccmClientSourceMembership {
        basename: "PolicyEvaluator.log",
        logical_artifact_ids: &["client-policy-agent"],
    },
    SccmClientSourceMembership {
        basename: "Scheduler.log",
        logical_artifact_ids: &["client-policy-agent"],
    },
    SccmClientSourceMembership {
        basename: "CIAgent.log",
        logical_artifact_ids: &["client-policy-state"],
    },
    SccmClientSourceMembership {
        basename: "CIDownloader.log",
        logical_artifact_ids: &["client-policy-state"],
    },
    SccmClientSourceMembership {
        basename: "StateMessage.log",
        logical_artifact_ids: &["client-policy-state"],
    },
    SccmClientSourceMembership {
        basename: "StatusAgent.log",
        logical_artifact_ids: &["client-policy-state"],
    },
    SccmClientSourceMembership {
        basename: "ScanAgent.log",
        logical_artifact_ids: &["client-updates"],
    },
    SccmClientSourceMembership {
        basename: "UpdatesDeployment.log",
        logical_artifact_ids: &["client-updates"],
    },
    SccmClientSourceMembership {
        basename: "UpdatesHandler.log",
        logical_artifact_ids: &["client-updates"],
    },
    SccmClientSourceMembership {
        basename: "UpdatesStore.log",
        logical_artifact_ids: &["client-updates"],
    },
    SccmClientSourceMembership {
        basename: "WUAHandler.log",
        logical_artifact_ids: &["client-updates"],
    },
    SccmClientSourceMembership {
        basename: "ServiceWindowManager.log",
        logical_artifact_ids: &["client-maintenance-window"],
    },
    SccmClientSourceMembership {
        basename: "RebootCoordinator.log",
        logical_artifact_ids: &["client-reboot"],
    },
    SccmClientSourceMembership {
        basename: "CBS.log",
        logical_artifact_ids: &["client-windows-update-supplemental"],
    },
    SccmClientSourceMembership {
        basename: "ReportingEvents.log",
        logical_artifact_ids: &["client-windows-update-supplemental"],
    },
    SccmClientSourceMembership {
        basename: "smsts.log",
        logical_artifact_ids: &["client-task-sequence-smsts"],
    },
    SccmClientSourceMembership {
        basename: "InventoryAgent.log",
        logical_artifact_ids: &["client-inventory"],
    },
    SccmClientSourceMembership {
        basename: "InventoryProvider.log",
        logical_artifact_ids: &["client-inventory"],
    },
    SccmClientSourceMembership {
        basename: "InventoryAgentProvider.log",
        logical_artifact_ids: &["client-inventory"],
    },
    SccmClientSourceMembership {
        basename: "CITaskMgr.log",
        logical_artifact_ids: &["client-compliance"],
    },
    SccmClientSourceMembership {
        basename: "DCMAgent.log",
        logical_artifact_ids: &["client-compliance"],
    },
    SccmClientSourceMembership {
        basename: "DCMReporting.log",
        logical_artifact_ids: &["client-compliance"],
    },
    SccmClientSourceMembership {
        basename: "SWMTRReportGen.log",
        logical_artifact_ids: &["client-metering"],
    },
];

pub(crate) fn declared_client_source_memberships() -> &'static [SccmClientSourceMembership] {
    CLIENT_SOURCE_MEMBERSHIPS
}

const SOURCE_CATALOG: &[CatalogSpec] = &[
    CatalogSpec {
        basename: "ccmsetup",
        logical_name: "ccmSetup",
        role: SccmRole::Client,
        family: SccmArtifactFamily::ClientSetup,
    },
    CatalogSpec {
        basename: "client.msi",
        logical_name: "clientMsi",
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
        basename: "CIAgent",
        logical_name: "ciAgent",
        role: SccmRole::Client,
        family: SccmArtifactFamily::ClientPolicy,
    },
    CatalogSpec {
        basename: "CIDownloader",
        logical_name: "ciDownloader",
        role: SccmRole::Client,
        family: SccmArtifactFamily::ClientPolicy,
    },
    CatalogSpec {
        basename: "StateMessage",
        logical_name: "stateMessage",
        role: SccmRole::Client,
        family: SccmArtifactFamily::ClientPolicy,
    },
    CatalogSpec {
        basename: "StatusAgent",
        logical_name: "statusAgent",
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
        basename: "ExecMgr",
        logical_name: "execMgr",
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
        basename: "ServiceWindowManager",
        logical_name: "serviceWindowManager",
        role: SccmRole::Client,
        family: SccmArtifactFamily::ClientUpdates,
    },
    CatalogSpec {
        basename: "RebootCoordinator",
        logical_name: "rebootCoordinator",
        role: SccmRole::Client,
        family: SccmArtifactFamily::ClientUpdates,
    },
    CatalogSpec {
        basename: "CBS",
        logical_name: "componentBasedServicing",
        role: SccmRole::Client,
        family: SccmArtifactFamily::ClientUpdates,
    },
    CatalogSpec {
        basename: "ReportingEvents",
        logical_name: "reportingEvents",
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
        basename: "InventoryAgent",
        logical_name: "inventoryAgent",
        role: SccmRole::Client,
        family: SccmArtifactFamily::ClientInventory,
    },
    CatalogSpec {
        basename: "InventoryProvider",
        logical_name: "inventoryProvider",
        role: SccmRole::Client,
        family: SccmArtifactFamily::ClientInventory,
    },
    CatalogSpec {
        basename: "InventoryAgentProvider",
        logical_name: "inventoryAgentProvider",
        role: SccmRole::Client,
        family: SccmArtifactFamily::ClientInventory,
    },
    CatalogSpec {
        basename: "CITaskMgr",
        logical_name: "ciTaskMgr",
        role: SccmRole::Client,
        family: SccmArtifactFamily::ClientCompliance,
    },
    CatalogSpec {
        basename: "DCMAgent",
        logical_name: "dcmAgent",
        role: SccmRole::Client,
        family: SccmArtifactFamily::ClientCompliance,
    },
    CatalogSpec {
        basename: "DCMReporting",
        logical_name: "dcmReporting",
        role: SccmRole::Client,
        family: SccmArtifactFamily::ClientCompliance,
    },
    CatalogSpec {
        basename: "SWMTRReportGen",
        logical_name: "swmtrReportGen",
        role: SccmRole::Client,
        family: SccmArtifactFamily::ClientMetering,
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
        basename: "SMSdpmon",
        logical_name: "smsDpmon",
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
            uses_ccm_records: catalog_entry_uses_ccm_records(entry),
            supported_for_diagnosis: parsed.rotation_supported,
        };
    }

    let logical_name = lower_camel_identifier(parsed.basename);
    SccmSourceCatalogEntry {
        basename: format!("{}.log", parsed.basename),
        family: SccmArtifactFamily::Unknown(logical_name.clone()),
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
        uses_ccm_records: catalog_entry_uses_ccm_records(entry),
        supported_for_diagnosis: true,
    }
}

fn catalog_entry_uses_ccm_records(entry: &CatalogSpec) -> bool {
    !matches!(
        entry.logical_name,
        "clientMsi" | "reportingEvents" | "componentBasedServicing"
    )
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
