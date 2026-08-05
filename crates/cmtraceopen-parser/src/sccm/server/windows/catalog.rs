use serde::{Deserialize, Serialize};

use crate::sccm::{
    classify_artifact_name, SccmArtifactFamily, SccmRole, SccmRotation, SccmSourceCatalogEntry,
};

pub const SCCM_SERVER_HIERARCHY_SOURCE_CONTRACT_VERSION: u32 = 1;
pub const SCCM_SERVER_SITE_DATABASE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmServerHierarchyDirection {
    Origin,
    Target,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SccmServerHierarchyRotationContract {
    Current,
    LoUnderscore,
}

#[derive(Debug)]
pub struct SccmServerHierarchySourceContract {
    pub contract_version: u32,
    pub source_id: &'static str,
    pub logical_name: &'static str,
    pub producer_role: SccmRole,
    pub expected_component: &'static str,
    pub(crate) allowed_rotations: &'static [SccmServerHierarchyRotationContract],
}

impl SccmServerHierarchySourceContract {
    pub fn allows_rotation(&self, rotation: &SccmRotation) -> bool {
        let expected = match rotation {
            SccmRotation::Current => SccmServerHierarchyRotationContract::Current,
            SccmRotation::LoUnderscore => SccmServerHierarchyRotationContract::LoUnderscore,
            SccmRotation::Numbered(_) | SccmRotation::Timestamped(_) | SccmRotation::Unknown(_) => {
                return false
            }
        };
        self.allowed_rotations.contains(&expected)
    }
}

const CURRENT_ROTATION: &[SccmServerHierarchyRotationContract] =
    &[SccmServerHierarchyRotationContract::Current];
const LO_ROTATION: &[SccmServerHierarchyRotationContract] =
    &[SccmServerHierarchyRotationContract::LoUnderscore];

const SERVER_HIERARCHY_SOURCE_CONTRACTS: &[SccmServerHierarchySourceContract] = &[
    SccmServerHierarchySourceContract {
        contract_version: SCCM_SERVER_HIERARCHY_SOURCE_CONTRACT_VERSION,
        source_id: "server-hierarchy-control",
        logical_name: "replmgr",
        producer_role: SccmRole::SiteServer,
        expected_component: "SMS_REPLICATION_MANAGER",
        allowed_rotations: CURRENT_ROTATION,
    },
    SccmServerHierarchySourceContract {
        contract_version: SCCM_SERVER_HIERARCHY_SOURCE_CONTRACT_VERSION,
        source_id: "server-hierarchy-control",
        logical_name: "rcmctrl",
        producer_role: SccmRole::SiteServer,
        expected_component: "SMS_REPLICATION_CONFIGURATION_MONITOR",
        allowed_rotations: CURRENT_ROTATION,
    },
    SccmServerHierarchySourceContract {
        contract_version: SCCM_SERVER_HIERARCHY_SOURCE_CONTRACT_VERSION,
        source_id: "server-hierarchy-control",
        logical_name: "rcmctrl",
        producer_role: SccmRole::SiteServer,
        expected_component: "SMS_REPLICATION_CONFIGURATION_MONITOR",
        allowed_rotations: LO_ROTATION,
    },
    SccmServerHierarchySourceContract {
        contract_version: SCCM_SERVER_HIERARCHY_SOURCE_CONTRACT_VERSION,
        source_id: "server-hierarchy-transfer",
        logical_name: "sender",
        producer_role: SccmRole::SiteServer,
        expected_component: "SMS_LAN_SENDER",
        allowed_rotations: CURRENT_ROTATION,
    },
    SccmServerHierarchySourceContract {
        contract_version: SCCM_SERVER_HIERARCHY_SOURCE_CONTRACT_VERSION,
        source_id: "server-hierarchy-transfer",
        logical_name: "despool",
        producer_role: SccmRole::SiteServer,
        expected_component: "SMS_DESPOOLER",
        allowed_rotations: CURRENT_ROTATION,
    },
];

pub fn declared_hierarchy_source_contracts() -> &'static [SccmServerHierarchySourceContract] {
    SERVER_HIERARCHY_SOURCE_CONTRACTS
}

pub(crate) fn classify_declared_hierarchy_source(
    source_id: &str,
    producer_role: &SccmRole,
    logical_name: &str,
    rotation: &SccmRotation,
) -> Option<&'static SccmServerHierarchySourceContract> {
    SERVER_HIERARCHY_SOURCE_CONTRACTS.iter().find(|contract| {
        contract.source_id == source_id
            && &contract.producer_role == producer_role
            && contract.logical_name == logical_name
            && contract.allows_rotation(rotation)
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SccmServerSourceKind {
    CcmLog,
    IisW3c,
    StructuredSupplement,
    ProfileDefined,
}

#[derive(Debug)]
pub struct SccmServerSourceSpec {
    pub source_id: &'static str,
    pub producer_role: SccmRole,
    pub workflow_subject_role: Option<SccmRole>,
    pub logical_names: &'static [&'static str],
    /// Exact basename required for a bounded, profile-defined supplemental
    /// source. CCM sources use `logical_names` instead.
    pub explicit_basename: Option<&'static str>,
    pub source_kind: SccmServerSourceKind,
    pub supplemental: bool,
}

const SERVER_SOURCE_SPECS: &[SccmServerSourceSpec] = &[
    SccmServerSourceSpec {
        source_id: "server-sitecomp",
        producer_role: SccmRole::SiteServer,
        workflow_subject_role: None,
        logical_names: &["sitecomp", "hman"],
        explicit_basename: None,
        source_kind: SccmServerSourceKind::CcmLog,
        supplemental: false,
    },
    SccmServerSourceSpec {
        source_id: "server-status",
        producer_role: SccmRole::SiteServer,
        workflow_subject_role: None,
        logical_names: &["statmgr", "statesys"],
        explicit_basename: None,
        source_kind: SccmServerSourceKind::CcmLog,
        supplemental: false,
    },
    SccmServerSourceSpec {
        source_id: "server-hierarchy-control",
        producer_role: SccmRole::SiteServer,
        workflow_subject_role: None,
        logical_names: &["replmgr", "rcmctrl"],
        explicit_basename: None,
        source_kind: SccmServerSourceKind::CcmLog,
        supplemental: false,
    },
    SccmServerSourceSpec {
        source_id: "server-hierarchy-transfer",
        producer_role: SccmRole::SiteServer,
        workflow_subject_role: None,
        logical_names: &["sender", "despool"],
        explicit_basename: None,
        source_kind: SccmServerSourceKind::CcmLog,
        supplemental: false,
    },
    SccmServerSourceSpec {
        source_id: "server-mp-auth",
        producer_role: SccmRole::ManagementPoint,
        workflow_subject_role: None,
        logical_names: &["mpGetAuth", "mpCliReg", "mpRegistrationManager"],
        explicit_basename: None,
        source_kind: SccmServerSourceKind::CcmLog,
        supplemental: false,
    },
    SccmServerSourceSpec {
        source_id: "server-mp-policy",
        producer_role: SccmRole::ManagementPoint,
        workflow_subject_role: None,
        logical_names: &["mpGetPolicy", "mpLocation"],
        explicit_basename: None,
        source_kind: SccmServerSourceKind::CcmLog,
        supplemental: false,
    },
    SccmServerSourceSpec {
        source_id: "server-mp-policy",
        producer_role: SccmRole::SiteServer,
        workflow_subject_role: Some(SccmRole::ManagementPoint),
        logical_names: &["mpcontrol"],
        explicit_basename: None,
        source_kind: SccmServerSourceKind::CcmLog,
        supplemental: false,
    },
    SccmServerSourceSpec {
        source_id: "server-mp-iis",
        producer_role: SccmRole::ManagementPoint,
        workflow_subject_role: None,
        logical_names: &[],
        explicit_basename: None,
        source_kind: SccmServerSourceKind::IisW3c,
        supplemental: true,
    },
    SccmServerSourceSpec {
        source_id: "server-dp-distribution",
        producer_role: SccmRole::SiteServer,
        workflow_subject_role: Some(SccmRole::DistributionPoint),
        logical_names: &["distmgr", "pkgXferMgr"],
        explicit_basename: None,
        source_kind: SccmServerSourceKind::CcmLog,
        supplemental: false,
    },
    SccmServerSourceSpec {
        source_id: "server-dp-distribution",
        producer_role: SccmRole::DistributionPoint,
        workflow_subject_role: None,
        logical_names: &["smsDpProv", "pullDp"],
        explicit_basename: None,
        source_kind: SccmServerSourceKind::CcmLog,
        supplemental: false,
    },
    SccmServerSourceSpec {
        source_id: "server-dp-serve",
        producer_role: SccmRole::DistributionPoint,
        workflow_subject_role: None,
        logical_names: &["smsDpmon"],
        explicit_basename: None,
        source_kind: SccmServerSourceKind::CcmLog,
        supplemental: true,
    },
    SccmServerSourceSpec {
        source_id: "server-sup-sync",
        producer_role: SccmRole::SiteServer,
        workflow_subject_role: Some(SccmRole::SoftwareUpdatePoint),
        logical_names: &["wcm", "wsyncmgr"],
        explicit_basename: None,
        source_kind: SccmServerSourceKind::CcmLog,
        supplemental: false,
    },
    SccmServerSourceSpec {
        source_id: "server-sup-sync",
        producer_role: SccmRole::SoftwareUpdatePoint,
        workflow_subject_role: Some(SccmRole::SoftwareUpdatePoint),
        logical_names: &["wsusCtrl", "supSetup"],
        explicit_basename: None,
        source_kind: SccmServerSourceKind::CcmLog,
        supplemental: false,
    },
    SccmServerSourceSpec {
        source_id: "server-sup-wsus",
        producer_role: SccmRole::WsUs,
        workflow_subject_role: Some(SccmRole::SoftwareUpdatePoint),
        logical_names: &[],
        explicit_basename: Some("WsusHealth.json"),
        source_kind: SccmServerSourceKind::ProfileDefined,
        supplemental: true,
    },
    SccmServerSourceSpec {
        source_id: "server-provider",
        producer_role: SccmRole::Provider,
        workflow_subject_role: Some(SccmRole::Provider),
        logical_names: &["smsprov"],
        explicit_basename: None,
        source_kind: SccmServerSourceKind::CcmLog,
        supplemental: false,
    },
    SccmServerSourceSpec {
        source_id: "server-admin-service",
        producer_role: SccmRole::AdminService,
        workflow_subject_role: Some(SccmRole::AdminService),
        logical_names: &["adminService"],
        explicit_basename: None,
        source_kind: SccmServerSourceKind::CcmLog,
        supplemental: false,
    },
    SccmServerSourceSpec {
        source_id: "server-admin-service-iis",
        producer_role: SccmRole::AdminService,
        workflow_subject_role: Some(SccmRole::AdminService),
        logical_names: &[],
        explicit_basename: None,
        source_kind: SccmServerSourceKind::IisW3c,
        supplemental: true,
    },
];

const SERVER_STRUCTURED_SUPPLEMENT_SPEC: SccmServerSourceSpec = SccmServerSourceSpec {
    source_id: "server-hierarchy-site-database",
    producer_role: SccmRole::SiteServer,
    workflow_subject_role: None,
    logical_names: &[],
    explicit_basename: Some("site-database.supplement"),
    source_kind: SccmServerSourceKind::StructuredSupplement,
    supplemental: true,
};

pub fn declared_server_source_catalog() -> &'static [SccmServerSourceSpec] {
    SERVER_SOURCE_SPECS
}

pub(crate) fn is_declared_server_source_id(source_id: &str) -> bool {
    SERVER_SOURCE_SPECS
        .iter()
        .chain(std::iter::once(&SERVER_STRUCTURED_SUPPLEMENT_SPEC))
        .any(|spec| spec.source_id == source_id)
}

pub(crate) fn classify_declared_server_source(
    source_id: &str,
    producer_role: &SccmRole,
    workflow_subject_role: Option<&SccmRole>,
    source_kind: &str,
    basename: &str,
) -> Option<(
    &'static SccmServerSourceSpec,
    Option<SccmSourceCatalogEntry>,
)> {
    let spec = SERVER_SOURCE_SPECS
        .iter()
        .chain(std::iter::once(&SERVER_STRUCTURED_SUPPLEMENT_SPEC))
        .find(|spec| {
            spec.source_id == source_id
                && &spec.producer_role == producer_role
                && spec.workflow_subject_role.as_ref() == workflow_subject_role
                && source_kind_matches(spec.source_kind, source_kind)
        })?;

    if spec.source_kind != SccmServerSourceKind::CcmLog {
        if spec
            .explicit_basename
            .is_some_and(|declared| declared != basename)
        {
            return None;
        }
        return Some((spec, None));
    }

    let classified = classify_artifact_name(basename, producer_role.clone());
    if !classified.supported_for_diagnosis
        || !spec
            .logical_names
            .iter()
            .any(|logical_name| *logical_name == classified.logical_name)
    {
        return None;
    }

    Some((spec, Some(classified)))
}

pub(crate) fn expected_family(source_id: &str) -> Option<SccmArtifactFamily> {
    Some(match source_id {
        "server-sitecomp" => SccmArtifactFamily::SiteComponent,
        "server-status" => SccmArtifactFamily::SiteStatus,
        "server-hierarchy-control"
        | "server-hierarchy-transfer"
        | "server-hierarchy-site-database" => SccmArtifactFamily::Hierarchy,
        "server-mp-auth" | "server-mp-policy" | "server-mp-iis" => {
            SccmArtifactFamily::ManagementPoint
        }
        "server-dp-distribution" | "server-dp-serve" => SccmArtifactFamily::DistributionPoint,
        "server-sup-sync" | "server-sup-wsus" => SccmArtifactFamily::SoftwareUpdatePoint,
        "server-provider" => SccmArtifactFamily::Provider,
        "server-admin-service" | "server-admin-service-iis" => SccmArtifactFamily::AdminService,
        _ => return None,
    })
}

fn source_kind_matches(expected: SccmServerSourceKind, actual: &str) -> bool {
    matches!(
        (expected, actual),
        (SccmServerSourceKind::CcmLog, "ccmLog")
            | (SccmServerSourceKind::IisW3c, "iisW3c")
            | (
                SccmServerSourceKind::StructuredSupplement,
                "structuredSupplement"
            )
            | (SccmServerSourceKind::ProfileDefined, "profileDefined")
    )
}
