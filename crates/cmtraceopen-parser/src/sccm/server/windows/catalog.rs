use crate::sccm::{classify_artifact_name, SccmArtifactFamily, SccmRole, SccmSourceCatalogEntry};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SccmServerSourceKind {
    CcmLog,
    IisW3c,
    StructuredSupplement,
}

#[derive(Debug)]
pub struct SccmServerSourceSpec {
    pub source_id: &'static str,
    pub producer_role: SccmRole,
    pub workflow_subject_role: Option<SccmRole>,
    pub logical_names: &'static [&'static str],
    pub source_kind: SccmServerSourceKind,
    pub supplemental: bool,
}

const SERVER_SOURCE_SPECS: &[SccmServerSourceSpec] = &[
    SccmServerSourceSpec {
        source_id: "server-sitecomp",
        producer_role: SccmRole::SiteServer,
        workflow_subject_role: None,
        logical_names: &["sitecomp", "hman"],
        source_kind: SccmServerSourceKind::CcmLog,
        supplemental: false,
    },
    SccmServerSourceSpec {
        source_id: "server-status",
        producer_role: SccmRole::SiteServer,
        workflow_subject_role: None,
        logical_names: &["statmgr", "statesys"],
        source_kind: SccmServerSourceKind::CcmLog,
        supplemental: false,
    },
    SccmServerSourceSpec {
        source_id: "server-mp-auth",
        producer_role: SccmRole::ManagementPoint,
        workflow_subject_role: None,
        logical_names: &["mpGetAuth", "mpCliReg", "mpRegistrationManager"],
        source_kind: SccmServerSourceKind::CcmLog,
        supplemental: false,
    },
    SccmServerSourceSpec {
        source_id: "server-mp-policy",
        producer_role: SccmRole::ManagementPoint,
        workflow_subject_role: None,
        logical_names: &["mpGetPolicy", "mpLocation"],
        source_kind: SccmServerSourceKind::CcmLog,
        supplemental: false,
    },
    SccmServerSourceSpec {
        source_id: "server-mp-policy",
        producer_role: SccmRole::SiteServer,
        workflow_subject_role: Some(SccmRole::ManagementPoint),
        logical_names: &["mpcontrol"],
        source_kind: SccmServerSourceKind::CcmLog,
        supplemental: false,
    },
    SccmServerSourceSpec {
        source_id: "server-mp-iis",
        producer_role: SccmRole::ManagementPoint,
        workflow_subject_role: None,
        logical_names: &[],
        source_kind: SccmServerSourceKind::IisW3c,
        supplemental: true,
    },
    SccmServerSourceSpec {
        source_id: "server-dp-distribution",
        producer_role: SccmRole::SiteServer,
        workflow_subject_role: Some(SccmRole::DistributionPoint),
        logical_names: &["distmgr", "pkgXferMgr"],
        source_kind: SccmServerSourceKind::CcmLog,
        supplemental: false,
    },
    SccmServerSourceSpec {
        source_id: "server-dp-distribution",
        producer_role: SccmRole::DistributionPoint,
        workflow_subject_role: None,
        logical_names: &["smsDpProv", "pullDp"],
        source_kind: SccmServerSourceKind::CcmLog,
        supplemental: false,
    },
    SccmServerSourceSpec {
        source_id: "server-sup-sync",
        producer_role: SccmRole::SiteServer,
        workflow_subject_role: Some(SccmRole::SoftwareUpdatePoint),
        logical_names: &["wcm", "wsyncmgr"],
        source_kind: SccmServerSourceKind::CcmLog,
        supplemental: false,
    },
    SccmServerSourceSpec {
        source_id: "server-sup-sync",
        producer_role: SccmRole::SoftwareUpdatePoint,
        workflow_subject_role: None,
        logical_names: &["wsusCtrl", "supSetup"],
        source_kind: SccmServerSourceKind::CcmLog,
        supplemental: false,
    },
];

pub fn declared_server_source_catalog() -> &'static [SccmServerSourceSpec] {
    SERVER_SOURCE_SPECS
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
    let spec = SERVER_SOURCE_SPECS.iter().find(|spec| {
        spec.source_id == source_id
            && &spec.producer_role == producer_role
            && spec.workflow_subject_role.as_ref() == workflow_subject_role
            && source_kind_matches(spec.source_kind, source_kind)
    })?;

    if spec.source_kind != SccmServerSourceKind::CcmLog {
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
        "server-mp-auth" | "server-mp-policy" | "server-mp-iis" => {
            SccmArtifactFamily::ManagementPoint
        }
        "server-dp-distribution" => SccmArtifactFamily::DistributionPoint,
        "server-sup-sync" => SccmArtifactFamily::SoftwareUpdatePoint,
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
    )
}
