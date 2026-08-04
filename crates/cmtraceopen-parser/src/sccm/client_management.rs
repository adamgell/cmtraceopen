use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::catalog::classify_artifact_name;
use super::models::{SccmArtifact, SccmCoverageState, SccmEvidence, SccmEvidenceRef, SccmRole};
use super::SccmConfidence;

pub const SCCM_MANAGEMENT_TEST_PROFILE_ID: &str = "sccm-client-management-5.00.test-v1";
pub const SCCM_MANAGEMENT_TEST_VERSION_PREFIX: &str = "5.00.TEST.";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmManagementWorkload {
    Scripts,
    ClientNotification,
    SoftwareCenter,
}

impl SccmManagementWorkload {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Scripts => "Scripts",
            Self::ClientNotification => "ClientNotification",
            Self::SoftwareCenter => "SoftwareCenter",
        }
    }

    fn source_kind(&self) -> SccmManagementSourceKind {
        match self {
            Self::Scripts => SccmManagementSourceKind::Scripts,
            Self::ClientNotification => SccmManagementSourceKind::Notification,
            Self::SoftwareCenter => SccmManagementSourceKind::SoftwareCenterCandidate,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmManagementSourceKind {
    CoManagement,
    Scripts,
    Notification,
    SoftwareCenterCandidate,
    UnknownCandidate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmManagementOwnership {
    SccmOwned,
    IntuneOwned,
    SharedOrTransitioning,
    UnknownOwnership,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmManagementSourceState {
    Admitted,
    CandidateUnsupported,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmManagementExtractionProfile {
    pub id: String,
    pub version_prefix: String,
}

impl SccmManagementExtractionProfile {
    pub fn synthetic_test() -> Self {
        Self {
            id: SCCM_MANAGEMENT_TEST_PROFILE_ID.to_owned(),
            version_prefix: SCCM_MANAGEMENT_TEST_VERSION_PREFIX.to_owned(),
        }
    }

    fn is_supported(&self) -> bool {
        self.id == SCCM_MANAGEMENT_TEST_PROFILE_ID
            && self.version_prefix == SCCM_MANAGEMENT_TEST_VERSION_PREFIX
    }

    fn accepts_version(&self, artifact: &SccmArtifact) -> bool {
        artifact
            .configmgr_version
            .as_deref()
            .and_then(|version| version.strip_prefix(&self.version_prefix))
            .is_some_and(|suffix| {
                suffix.len() == 4 && suffix.bytes().all(|byte| byte.is_ascii_digit())
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmManagementSourceAdmission {
    pub artifact_id: String,
    pub source_name: String,
    pub logical_name: String,
    pub state: SccmManagementSourceState,
    pub source_kind: SccmManagementSourceKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmManagementOwnershipResult {
    pub workload: SccmManagementWorkload,
    pub classification: SccmManagementOwnership,
    pub confidence: SccmConfidence,
    pub terminal_handoff: bool,
    pub evidence: Vec<SccmEvidenceRef>,
    pub coverage_gap_artifact_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SccmManagementError {
    UnsupportedProfile,
    NonClientArtifact(String),
    InvalidEvidenceReference(String),
}

impl std::fmt::Display for SccmManagementError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedProfile => formatter.write_str("unsupported SCCM management profile"),
            Self::NonClientArtifact(id) => write!(
                formatter,
                "management artifact {id} is not a client artifact"
            ),
            Self::InvalidEvidenceReference(id) => {
                write!(formatter, "evidence references unknown artifact {id}")
            }
        }
    }
}

impl std::error::Error for SccmManagementError {}

pub fn admit_management_sources(
    profile: &SccmManagementExtractionProfile,
    artifacts: &[SccmArtifact],
) -> Result<Vec<SccmManagementSourceAdmission>, SccmManagementError> {
    if !profile.is_supported() {
        return Err(SccmManagementError::UnsupportedProfile);
    }

    let mut admissions = artifacts
        .iter()
        .map(|artifact| {
            if artifact.role != SccmRole::Client {
                return Err(SccmManagementError::NonClientArtifact(
                    artifact.artifact_id.clone(),
                ));
            }

            let catalog = classify_artifact_name(&artifact.display_name, SccmRole::Client);
            let source_kind = management_source_kind(&artifact.display_name);
            let state = if artifact.coverage != SccmCoverageState::Captured {
                SccmManagementSourceState::Unavailable
            } else if matches!(
                source_kind,
                SccmManagementSourceKind::CoManagement
                    | SccmManagementSourceKind::Scripts
                    | SccmManagementSourceKind::Notification
            ) && matches!(catalog.rotation, super::models::SccmRotation::Current)
                && profile.accepts_version(artifact)
            {
                SccmManagementSourceState::Admitted
            } else {
                SccmManagementSourceState::CandidateUnsupported
            };

            Ok(SccmManagementSourceAdmission {
                artifact_id: artifact.artifact_id.clone(),
                source_name: artifact.display_name.clone(),
                logical_name: catalog.logical_name,
                state,
                source_kind,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    admissions.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
    Ok(admissions)
}

pub fn resolve_management_ownership(
    profile: &SccmManagementExtractionProfile,
    workload: SccmManagementWorkload,
    artifacts: &[SccmArtifact],
    evidence: &[SccmEvidence],
) -> Result<SccmManagementOwnershipResult, SccmManagementError> {
    let admissions = admit_management_sources(profile, artifacts)?;
    let mut artifacts_by_id = BTreeMap::new();
    for artifact in artifacts {
        if artifacts_by_id
            .insert(artifact.artifact_id.as_str(), artifact)
            .is_some()
        {
            return Err(SccmManagementError::InvalidEvidenceReference(
                artifact.artifact_id.clone(),
            ));
        }
    }
    let admitted_ids = admissions
        .iter()
        .filter(|admission| {
            admission.state == SccmManagementSourceState::Admitted
                && admission.source_kind == SccmManagementSourceKind::CoManagement
        })
        .map(|admission| admission.artifact_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut facts = Vec::new();

    for record in evidence {
        let artifact_id = record.reference.artifact_id.as_str();
        let Some(artifact) = artifacts_by_id.get(artifact_id) else {
            return Err(SccmManagementError::InvalidEvidenceReference(
                artifact_id.to_owned(),
            ));
        };
        if record.role != SccmRole::Client
            || artifact.role != SccmRole::Client
            || !admitted_ids.contains(artifact_id)
        {
            continue;
        }
        let Some(fields) = parse_fixture_fields(&record.message) else {
            continue;
        };
        if fields.get("Workload").map(String::as_str) != Some(workload.as_str()) {
            continue;
        }
        let Some(ownership) = fields
            .get("Ownership")
            .and_then(|value| parse_ownership(value))
        else {
            continue;
        };
        let terminal = fields.get("Terminal").map(String::as_str) == Some("true");
        let disposition = fields.get("Disposition").map(String::as_str);
        if !ownership_contract_is_valid(&ownership, terminal, disposition) {
            continue;
        }
        facts.push((ownership, record.reference.clone()));
    }

    facts.sort_by(|left, right| {
        evidence_ref_sort_key(&left.1).cmp(&evidence_ref_sort_key(&right.1))
    });
    let mut evidence_refs = facts.iter().map(|fact| fact.1.clone()).collect::<Vec<_>>();
    evidence_refs.dedup();
    let coverage_gap_artifact_ids = unavailable_management_ids(&admissions, &workload);

    if facts.is_empty() {
        return Ok(SccmManagementOwnershipResult {
            workload,
            classification: SccmManagementOwnership::UnknownOwnership,
            confidence: SccmConfidence::Low,
            terminal_handoff: false,
            evidence: evidence_refs,
            coverage_gap_artifact_ids,
        });
    }

    let first = facts[0].0.clone();
    let consistent = facts.iter().all(|fact| fact.0 == first);
    let (classification, confidence, terminal_handoff) = if !consistent {
        (
            SccmManagementOwnership::UnknownOwnership,
            SccmConfidence::Low,
            false,
        )
    } else {
        match first {
            SccmManagementOwnership::SccmOwned => (
                SccmManagementOwnership::SccmOwned,
                SccmConfidence::High,
                false,
            ),
            SccmManagementOwnership::IntuneOwned => (
                SccmManagementOwnership::IntuneOwned,
                SccmConfidence::High,
                true,
            ),
            SccmManagementOwnership::SharedOrTransitioning => (
                SccmManagementOwnership::SharedOrTransitioning,
                SccmConfidence::Moderate,
                false,
            ),
            SccmManagementOwnership::UnknownOwnership => (
                SccmManagementOwnership::UnknownOwnership,
                SccmConfidence::Low,
                false,
            ),
        }
    };

    Ok(SccmManagementOwnershipResult {
        workload,
        classification,
        confidence,
        terminal_handoff,
        evidence: evidence_refs,
        coverage_gap_artifact_ids: if consistent {
            Vec::new()
        } else {
            coverage_gap_artifact_ids
        },
    })
}

fn unavailable_management_ids(
    admissions: &[SccmManagementSourceAdmission],
    workload: &SccmManagementWorkload,
) -> Vec<String> {
    let required_kind = workload.source_kind();
    admissions
        .iter()
        .filter(|admission| {
            (admission.source_kind == SccmManagementSourceKind::CoManagement
                || admission.source_kind == required_kind)
                && admission.state != SccmManagementSourceState::Admitted
        })
        .map(|admission| admission.artifact_id.clone())
        .collect()
}

fn management_source_kind(name: &str) -> SccmManagementSourceKind {
    match name.to_ascii_lowercase().as_str() {
        "comanagementhandler.log" => SccmManagementSourceKind::CoManagement,
        "scripts.log" => SccmManagementSourceKind::Scripts,
        "ccmnotificationagent.log" => SccmManagementSourceKind::Notification,
        value if value.starts_with("scclient_") && value.ends_with(".log") => {
            SccmManagementSourceKind::SoftwareCenterCandidate
        }
        _ => SccmManagementSourceKind::UnknownCandidate,
    }
}

fn parse_fixture_fields(message: &str) -> Option<BTreeMap<String, String>> {
    let body = message
        .split_once("SYNTHETIC FIXTURE ")
        .map(|(_, body)| body)?;
    let mut fields = BTreeMap::new();
    for token in body.split_whitespace() {
        let Some((key, value)) = token.split_once('=') else {
            continue;
        };
        if key.is_empty()
            || value.is_empty()
            || fields.insert(key.to_owned(), value.to_owned()).is_some()
        {
            return None;
        }
    }
    Some(fields)
}

fn parse_ownership(value: &str) -> Option<SccmManagementOwnership> {
    match value {
        "SccmOwned" => Some(SccmManagementOwnership::SccmOwned),
        "IntuneOwned" => Some(SccmManagementOwnership::IntuneOwned),
        "SharedOrTransitioning" => Some(SccmManagementOwnership::SharedOrTransitioning),
        "UnknownOwnership" => Some(SccmManagementOwnership::UnknownOwnership),
        _ => None,
    }
}

fn ownership_contract_is_valid(
    ownership: &SccmManagementOwnership,
    terminal: bool,
    disposition: Option<&str>,
) -> bool {
    match ownership {
        SccmManagementOwnership::SccmOwned => terminal && disposition == Some("Owned"),
        SccmManagementOwnership::IntuneOwned => terminal && disposition == Some("Handoff"),
        SccmManagementOwnership::SharedOrTransitioning => {
            !terminal && disposition == Some("Transitioning")
        }
        SccmManagementOwnership::UnknownOwnership => false,
    }
}

fn evidence_ref_sort_key(reference: &SccmEvidenceRef) -> (String, u32, u32, String) {
    (
        reference.artifact_id.clone(),
        reference.line_start.unwrap_or(u32::MAX),
        reference.line_end.unwrap_or(u32::MAX),
        reference.entry_id.clone(),
    )
}
