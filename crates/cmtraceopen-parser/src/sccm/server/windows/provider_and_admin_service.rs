use std::collections::BTreeMap;

use regex::Regex;
use serde::{Deserialize, Serialize};

use super::super::super::models::{SccmCoverageState, SccmEvidence, SccmEvidenceRef, SccmRole};

const PROVIDER_SOURCE_ID: &str = "server-provider";
const ADMIN_SERVICE_SOURCE_ID: &str = "server-admin-service";
const IIS_SOURCE_ID: &str = "server-admin-service-iis";
const PROVIDER_PROFILE_ID: &str = "provider-server-5.00.test-v1";
const ADMIN_SERVICE_PROFILE_ID: &str = "admin-service-server-5.00.test-v1";
const TEST_VERSION_PREFIX: &str = "5.00.TEST.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProviderAdminServiceLayer {
    Provider,
    AdminService,
}

impl ProviderAdminServiceLayer {
    fn profile_id(self) -> &'static str {
        match self {
            Self::Provider => PROVIDER_PROFILE_ID,
            Self::AdminService => ADMIN_SERVICE_PROFILE_ID,
        }
    }

    fn phase_order(self) -> &'static [&'static str] {
        match self {
            Self::Provider => &[
                "receive",
                "authenticateOrAuthorize",
                "executeProviderOperation",
                "respond",
                "recordOutcome",
            ],
            Self::AdminService => &[
                "receive",
                "authenticateOrAuthorize",
                "route",
                "executeBackendOperation",
                "respond",
                "recordOutcome",
            ],
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Self::Provider => "Provider",
            Self::AdminService => "Admin Service",
        }
    }

    fn serialized_name(self) -> &'static str {
        match self {
            Self::Provider => "provider",
            Self::AdminService => "adminService",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderAdminServiceArtifact {
    pub artifact_id: String,
    pub source_id: String,
    pub endpoint_id: String,
    pub producer_host_handle: Option<String>,
    pub producer_role: SccmRole,
    pub source_version: Option<String>,
    pub coverage: SccmCoverageState,
    pub evidence: Vec<SccmEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderAdminServiceKey {
    pub request_id: String,
    pub operation_handle: String,
    pub endpoint_id: String,
    pub producer_host_handle: String,
    pub confidence: String,
    pub extraction_profile_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderAdminServiceObservation {
    pub observation_id: String,
    pub phase: String,
    pub disposition: String,
    pub terminal: bool,
    pub evidence: Vec<SccmEvidenceRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderAdminServiceTransaction {
    pub transaction_id: String,
    pub layer: ProviderAdminServiceLayer,
    pub key: ProviderAdminServiceKey,
    pub state: String,
    pub classification: String,
    pub confidence: String,
    pub terminal_evidence: bool,
    pub public_summary: String,
    pub observations: Vec<ProviderAdminServiceObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderAdminServiceGap {
    pub artifact_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderAdminServiceReport {
    pub transactions: Vec<ProviderAdminServiceTransaction>,
    pub gaps: Vec<ProviderAdminServiceGap>,
}

#[derive(Debug, Clone)]
struct Candidate {
    evidence: SccmEvidence,
    request_id: String,
    operation_handle: String,
    endpoint_id: String,
    phase: String,
    disposition: String,
    terminal: bool,
}

/// Analyze only the two explicitly catalogued CCM request layers.
///
/// This function consumes normalized public evidence and never exports the
/// source message. It deliberately requires a synthetic, versioned profile
/// admission until a real SCCM version profile has been reviewed.
pub fn analyze_provider_admin_service(
    artifacts: &[ProviderAdminServiceArtifact],
) -> ProviderAdminServiceReport {
    let mut grouped: BTreeMap<
        (ProviderAdminServiceLayer, String, String, String, String),
        Vec<Candidate>,
    > = BTreeMap::new();
    let mut gaps = Vec::new();

    for artifact in artifacts {
        let Some(layer) = source_layer(&artifact.source_id) else {
            gaps.push(ProviderAdminServiceGap {
                artifact_id: artifact.artifact_id.clone(),
                reason: if artifact.source_id == IIS_SOURCE_ID {
                    "supplemental IIS evidence is not a transaction".to_owned()
                } else {
                    "unsupported provider/admin service source".to_owned()
                },
            });
            continue;
        };

        if artifact.producer_role != SccmRole::Provider {
            gaps.push(ProviderAdminServiceGap {
                artifact_id: artifact.artifact_id.clone(),
                reason: "source producer role is not provider".to_owned(),
            });
            continue;
        }
        if artifact.coverage != SccmCoverageState::Captured {
            gaps.push(ProviderAdminServiceGap {
                artifact_id: artifact.artifact_id.clone(),
                reason: "source is not captured".to_owned(),
            });
            continue;
        }
        if artifact.endpoint_id.is_empty() {
            gaps.push(ProviderAdminServiceGap {
                artifact_id: artifact.artifact_id.clone(),
                reason: "endpoint context is missing".to_owned(),
            });
            continue;
        }
        let Some(host_handle) = artifact
            .producer_host_handle
            .as_deref()
            .filter(|host| is_safe_host_handle(host))
        else {
            gaps.push(ProviderAdminServiceGap {
                artifact_id: artifact.artifact_id.clone(),
                reason: "producer host context is missing".to_owned(),
            });
            continue;
        };
        if !artifact
            .source_version
            .as_deref()
            .is_some_and(is_admitted_test_version)
        {
            gaps.push(ProviderAdminServiceGap {
                artifact_id: artifact.artifact_id.clone(),
                reason: if artifact.source_version.is_some() {
                    "unvalidated source version".to_owned()
                } else {
                    "source version is missing".to_owned()
                },
            });
            continue;
        }

        let mut artifact_candidates = Vec::new();
        for evidence in &artifact.evidence {
            match parse_candidate(evidence, layer, &artifact.endpoint_id) {
                Ok(candidate) => artifact_candidates.push(candidate),
                Err(reason) => gaps.push(ProviderAdminServiceGap {
                    artifact_id: artifact.artifact_id.clone(),
                    reason,
                }),
            }
        }

        if artifact_candidates.is_empty() {
            continue;
        }

        let first = &artifact_candidates[0];
        if artifact_candidates.iter().any(|candidate| {
            candidate.request_id != first.request_id
                || candidate.operation_handle != first.operation_handle
                || candidate.endpoint_id != first.endpoint_id
        }) {
            gaps.push(ProviderAdminServiceGap {
                artifact_id: artifact.artifact_id.clone(),
                reason: "evidence contains incompatible request keys".to_owned(),
            });
            continue;
        }

        grouped
            .entry((
                layer,
                first.request_id.clone(),
                first.operation_handle.clone(),
                first.endpoint_id.clone(),
                host_handle.to_owned(),
            ))
            .or_default()
            .extend(artifact_candidates);
    }

    let transactions = grouped
        .into_iter()
        .map(
            |((layer, request_id, operation_handle, endpoint_id, host_handle), mut candidates)| {
                candidates.sort_by_key(|candidate| {
                    (
                        candidate.evidence.timestamp.utc_millis,
                        candidate.evidence.reference.artifact_id.clone(),
                        candidate.evidence.reference.line_start,
                    )
                });
                build_transaction(
                    layer,
                    request_id,
                    operation_handle,
                    endpoint_id,
                    host_handle,
                    candidates,
                )
            },
        )
        .collect();

    ProviderAdminServiceReport { transactions, gaps }
}

fn source_layer(source_id: &str) -> Option<ProviderAdminServiceLayer> {
    match source_id {
        PROVIDER_SOURCE_ID => Some(ProviderAdminServiceLayer::Provider),
        ADMIN_SERVICE_SOURCE_ID => Some(ProviderAdminServiceLayer::AdminService),
        _ => None,
    }
}

fn is_admitted_test_version(version: &str) -> bool {
    let suffix = version
        .strip_prefix(TEST_VERSION_PREFIX)
        .unwrap_or_default();
    !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
}

fn parse_candidate(
    evidence: &SccmEvidence,
    layer: ProviderAdminServiceLayer,
    endpoint_id: &str,
) -> Result<Candidate, String> {
    if evidence.role != SccmRole::Provider {
        return Err("evidence producer role is not provider".to_owned());
    }
    let fields = parse_fields(&evidence.message);
    let expected_profile = layer.profile_id();
    if fields.get("profileid").map(String::as_str) != Some(expected_profile) {
        return Err("evidence profile is not admitted for source layer".to_owned());
    }
    if fields.get("layer").map(String::as_str) != Some(layer.serialized_name()) {
        return Err("evidence layer does not match source layer".to_owned());
    }
    if fields.get("endpointid").map(String::as_str) != Some(endpoint_id) {
        return Err("evidence endpoint does not match source endpoint".to_owned());
    }

    let request_id = fields
        .get("requestid")
        .filter(|value| UUID_RE.is_match(value))
        .cloned()
        .ok_or_else(|| "request ID is missing or malformed".to_owned())?;
    let operation_handle = fields
        .get("operationhandle")
        .filter(|value| is_safe_operation_handle(value))
        .cloned()
        .ok_or_else(|| "operation handle is missing or unsafe".to_owned())?;
    let phase = fields
        .get("phase")
        .cloned()
        .ok_or_else(|| "phase is missing".to_owned())?;
    if !layer.phase_order().contains(&phase.as_str()) {
        return Err("phase is not valid for source layer".to_owned());
    }
    let disposition = fields
        .get("disposition")
        .filter(|value| matches!(value.as_str(), "succeeded" | "failed" | "pending"))
        .cloned()
        .ok_or_else(|| "disposition is missing or unsupported".to_owned())?;
    let terminal = fields
        .get("terminal")
        .map(String::as_str)
        .ok_or_else(|| "terminal marker is missing".to_owned())?
        .parse::<bool>()
        .map_err(|_| "terminal marker is malformed".to_owned())?;
    if terminal && phase != "recordOutcome" {
        return Err("terminal evidence is only valid for recordOutcome".to_owned());
    }

    Ok(Candidate {
        evidence: evidence.clone(),
        request_id,
        operation_handle,
        endpoint_id: endpoint_id.to_owned(),
        phase,
        disposition,
        terminal,
    })
}

fn parse_fields(message: &str) -> BTreeMap<String, String> {
    message
        .split(';')
        .filter_map(|part| {
            let (key, value) = part.split_once('=')?;
            let key = key.trim().to_ascii_lowercase();
            let value = value.trim().trim_matches(['"', '\'']);
            (!key.is_empty() && !value.is_empty()).then(|| (key, value.to_owned()))
        })
        .collect()
}

fn is_safe_operation_handle(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn is_safe_host_handle(value: &str) -> bool {
    value.strip_prefix("safe:").is_some_and(|suffix| {
        !suffix.is_empty()
            && suffix.len() <= 96
            && suffix.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b':' | b'-')
            })
    })
}

fn build_transaction(
    layer: ProviderAdminServiceLayer,
    request_id: String,
    operation_handle: String,
    endpoint_id: String,
    host_handle: String,
    candidates: Vec<Candidate>,
) -> ProviderAdminServiceTransaction {
    let expected_phases = layer.phase_order();
    let observations = candidates
        .iter()
        .enumerate()
        .map(|(index, candidate)| ProviderAdminServiceObservation {
            observation_id: format!("{}-{index:02}", candidate.evidence.evidence_id),
            phase: candidate.phase.clone(),
            disposition: candidate.disposition.clone(),
            terminal: candidate.terminal,
            evidence: vec![candidate.evidence.reference.clone()],
        })
        .collect::<Vec<_>>();
    let mut previous_phase = None;
    let has_valid_order = observations.iter().all(|observation| {
        let Some(index) = expected_phases
            .iter()
            .position(|phase| *phase == observation.phase)
        else {
            return false;
        };
        let valid = previous_phase.is_none_or(|previous| index > previous);
        previous_phase = Some(index);
        valid
    });
    let terminal = observations
        .iter()
        .find(|observation| observation.phase == "recordOutcome" && observation.terminal);
    let terminal_disposition = terminal.map(|observation| observation.disposition.as_str());
    let complete = has_valid_order && terminal.is_some();
    let (state, classification, confidence, summary) = match (complete, terminal_disposition) {
        (true, Some("succeeded")) => (
            "succeeded",
            "success",
            "high",
            format!(
                "{} operation completed with explicit terminal evidence.",
                layer.display_name()
            ),
        ),
        (true, Some("failed")) => (
            "failed",
            "confirmedFailure",
            "high",
            format!(
                "{} recorded an explicit terminal operation failure.",
                layer.display_name()
            ),
        ),
        _ => (
            "incomplete",
            "insufficientEvidence",
            "low",
            format!(
                "{} evidence stops before a valid explicit terminal outcome.",
                layer.display_name()
            ),
        ),
    };

    ProviderAdminServiceTransaction {
        transaction_id: format!(
            "{}:{request_id}:{operation_handle}:{endpoint_id}:{host_handle}",
            layer.serialized_name(),
        ),
        layer,
        key: ProviderAdminServiceKey {
            request_id,
            operation_handle,
            endpoint_id,
            producer_host_handle: host_handle,
            confidence: "exact".to_owned(),
            extraction_profile_id: layer.profile_id().to_owned(),
        },
        state: state.to_owned(),
        classification: classification.to_owned(),
        confidence: confidence.to_owned(),
        terminal_evidence: terminal.is_some(),
        public_summary: summary,
        observations,
    }
}

static UUID_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
        .expect("request ID regex compiles")
});
