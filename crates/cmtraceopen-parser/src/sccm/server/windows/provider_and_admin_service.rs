use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::models::log_entry::Severity;
use crate::sccm::{
    extract_keys, SccmArtifactFamily, SccmArtifactRequest, SccmConfidence, SccmCorrelationKeyKind,
    SccmCoverageState, SccmEvidence, SccmEvidenceRef, SccmExtractionProfile, SccmFinding,
    SccmFindingBuilder, SccmFindingClass, SccmFindingCoverageGap, SccmKeyConfidence, SccmPhase,
    SccmRole, SccmTerminalEvidence, SccmTimeOrderingState,
};

use super::{SccmServerArtifactAssessment, SccmServerIntakeAssessment};

const PROVIDER_SOURCE_ID: &str = "server-provider";
const ADMIN_SOURCE_ID: &str = "server-admin-service";
const IIS_SOURCE_ID: &str = "server-admin-service-iis";
const SYNTHETIC_VERSION: &str = "5.00.TEST";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProviderAdminServiceLayer {
    Provider,
    AdminService,
}

impl ProviderAdminServiceLayer {
    fn role(self) -> SccmRole {
        match self {
            Self::Provider => SccmRole::Provider,
            Self::AdminService => SccmRole::AdminService,
        }
    }

    fn source_id(self) -> &'static str {
        match self {
            Self::Provider => PROVIDER_SOURCE_ID,
            Self::AdminService => ADMIN_SOURCE_ID,
        }
    }

    fn endpoint_token(self) -> &'static str {
        match self {
            Self::Provider => "provider-local",
            Self::AdminService => "admin-service-lab",
        }
    }

    fn logical_artifact_id(self) -> &'static str {
        match self {
            Self::Provider => "smsprov",
            Self::AdminService => "adminService",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProviderAdminServicePhase {
    Receive,
    AuthenticateOrAuthorize,
    ExecuteProviderOperation,
    Route,
    ExecuteBackendOperation,
    Respond,
    RecordOutcome,
}

impl ProviderAdminServicePhase {
    fn rank(self, layer: ProviderAdminServiceLayer) -> Option<usize> {
        match (layer, self) {
            (_, Self::Receive) => Some(0),
            (_, Self::AuthenticateOrAuthorize) => Some(1),
            (ProviderAdminServiceLayer::Provider, Self::ExecuteProviderOperation) => Some(2),
            (ProviderAdminServiceLayer::AdminService, Self::Route) => Some(2),
            (ProviderAdminServiceLayer::AdminService, Self::ExecuteBackendOperation) => Some(3),
            (ProviderAdminServiceLayer::Provider, Self::Respond) => Some(3),
            (ProviderAdminServiceLayer::AdminService, Self::Respond) => Some(4),
            (ProviderAdminServiceLayer::Provider, Self::RecordOutcome) => Some(4),
            (ProviderAdminServiceLayer::AdminService, Self::RecordOutcome) => Some(5),
            _ => None,
        }
    }

    fn is_last(self) -> bool {
        self == Self::RecordOutcome
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProviderAdminServiceDisposition {
    Succeeded,
    Failed,
    Pending,
    RetryableFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProviderAdminServiceState {
    Succeeded,
    Recovered,
    Failed,
    Contradictory,
    BlockedOrDeferred,
    Incomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProviderAdminServiceClassification {
    Success,
    Recovered,
    ConfirmedFailure,
    ContradictoryEvidence,
    BlockedOrDeferred,
    InsufficientEvidence,
}

impl ProviderAdminServiceClassification {
    pub fn shared_finding_class(self) -> Option<SccmFindingClass> {
        match self {
            Self::Success => None,
            Self::Recovered => Some(SccmFindingClass::Recovered),
            Self::ConfirmedFailure => Some(SccmFindingClass::ConfirmedFailure),
            Self::ContradictoryEvidence => Some(SccmFindingClass::ContradictoryEvidence),
            Self::BlockedOrDeferred => Some(SccmFindingClass::BlockedOrDeferred),
            Self::InsufficientEvidence => Some(SccmFindingClass::InsufficientEvidence),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProviderAdminServiceTopologyCompatibility {
    Exact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProviderAdminServiceTimestampOrdering {
    Usable,
    Unusable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProviderAdminServiceProfileSelection {
    SelectedSynthetic,
    UnknownVersion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProviderAdminServiceSupportState {
    SyntheticProfileOnly,
    IntakeAuthorityInvalid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderAdminServiceProfile {
    pub layer: ProviderAdminServiceLayer,
    pub selection_state: ProviderAdminServiceProfileSelection,
    pub extraction_profile: SccmExtractionProfile,
    pub limitation: &'static str,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderAdminServiceCoverage {
    pub artifact_id: String,
    pub source_id: String,
    pub producer_role: SccmRole,
    pub producer_host_handle: Option<String>,
    pub workflow_subject_handle: Option<String>,
    pub source_version: Option<String>,
    pub state: SccmCoverageState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderAdminServiceKey {
    pub request_handle: String,
    pub operation_handle: String,
    pub endpoint_handle: String,
    pub producer_host_handle: String,
    pub confidence: SccmKeyConfidence,
    pub extraction_profile: SccmExtractionProfile,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderAdminServiceArtifactRequest {
    pub layer: ProviderAdminServiceLayer,
    pub producer_role: SccmRole,
    pub producer_host_handle: String,
    pub workflow_subject_handle: String,
    pub source_version: Option<String>,
    pub request: SccmArtifactRequest,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderAdminServiceFinding {
    pub subject_id: String,
    pub layer: ProviderAdminServiceLayer,
    pub source_id: String,
    pub producer_host_handle: String,
    pub workflow_subject_handle: String,
    pub source_version: Option<String>,
    pub last_successful_phase: Option<ProviderAdminServicePhase>,
    pub finding: SccmFinding,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderAdminServiceObservation {
    pub observation_id: String,
    pub phase: ProviderAdminServicePhase,
    pub disposition: ProviderAdminServiceDisposition,
    pub terminal: bool,
    pub evidence: Vec<SccmEvidenceRef>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderAdminServiceTransaction {
    pub transaction_id: String,
    pub layer: ProviderAdminServiceLayer,
    pub producer_role: SccmRole,
    pub source_version: String,
    pub key: ProviderAdminServiceKey,
    pub topology_compatibility: ProviderAdminServiceTopologyCompatibility,
    pub timestamp_ordering: ProviderAdminServiceTimestampOrdering,
    pub correlation_eligible: bool,
    pub state: ProviderAdminServiceState,
    pub classification: ProviderAdminServiceClassification,
    pub confidence: SccmConfidence,
    pub confidence_ceiling: SccmConfidence,
    pub terminal_evidence: bool,
    pub last_successful_phase: Option<ProviderAdminServicePhase>,
    pub coverage_gap_artifact_ids: Vec<String>,
    pub next_artifact_requests: Vec<ProviderAdminServiceArtifactRequest>,
    pub public_summary: String,
    pub observations: Vec<ProviderAdminServiceObservation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProviderAdminServiceSourceLocalKind {
    SupplementalOnly,
    RotationFragment,
    PrivacyRedacted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderAdminServiceSourceLocalObservation {
    pub observation_id: String,
    pub kind: ProviderAdminServiceSourceLocalKind,
    pub artifact_ids: Vec<String>,
    pub correlation_eligible: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderAdminServiceAnalysis {
    pub workflow: &'static str,
    pub support_state: ProviderAdminServiceSupportState,
    pub profiles: Vec<ProviderAdminServiceProfile>,
    pub coverage: Vec<ProviderAdminServiceCoverage>,
    pub transactions: Vec<ProviderAdminServiceTransaction>,
    pub findings: Vec<ProviderAdminServiceFinding>,
    pub source_local_observations: Vec<ProviderAdminServiceSourceLocalObservation>,
    pub artifact_requests: Vec<ProviderAdminServiceArtifactRequest>,
    pub cross_side_causal_claims: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FactKey {
    layer: ProviderAdminServiceLayer,
    request_id: String,
    operation: String,
    endpoint_handle: String,
    host_handle: String,
}

#[derive(Debug, Clone)]
struct Fact {
    key: FactKey,
    phase: ProviderAdminServicePhase,
    disposition: ProviderAdminServiceDisposition,
    terminal: bool,
    evidence: SccmEvidenceRef,
    utc_millis: Option<i64>,
    extraction_profile: SccmExtractionProfile,
}

struct ReducedTransaction {
    transaction: ProviderAdminServiceTransaction,
    finding: Option<ProviderAdminServiceFinding>,
}

enum ParsedFact {
    Valid(Fact),
    OrderingPoison(Fact),
}

pub fn analyze_provider_admin_service(
    intake: &SccmServerIntakeAssessment,
) -> ProviderAdminServiceAnalysis {
    if !intake.adapter_authority_is_intake_bound() || !intake.topology_authority_is_intake_bound() {
        return empty_analysis();
    }

    let scoped = intake
        .artifacts
        .iter()
        .filter(|artifact| {
            matches!(
                artifact.source_id.as_str(),
                PROVIDER_SOURCE_ID | ADMIN_SOURCE_ID | IIS_SOURCE_ID
            )
        })
        .collect::<Vec<_>>();
    let mut coverage = scoped
        .iter()
        .map(|artifact| ProviderAdminServiceCoverage {
            artifact_id: artifact.artifact_id.clone(),
            source_id: artifact.source_id.clone(),
            producer_role: artifact.producer_role.clone(),
            producer_host_handle: artifact.producer_host_handle.clone(),
            workflow_subject_handle: artifact.workflow_subject_handle.clone(),
            source_version: artifact.source_version.clone(),
            state: artifact.state.clone(),
        })
        .collect::<Vec<_>>();
    coverage.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));

    let mut facts = BTreeMap::<FactKey, Vec<Fact>>::new();
    let mut poisoned = BTreeSet::<FactKey>::new();
    for artifact in &scoped {
        let Some(layer) = transaction_layer(artifact) else {
            continue;
        };
        if !artifact_admits_facts(intake, artifact, layer) {
            continue;
        }
        for evidence in intake
            .evidence
            .iter()
            .filter(|evidence| evidence.reference.artifact_id == artifact.artifact_id)
        {
            match parse_fact(artifact, evidence, layer) {
                Some(ParsedFact::Valid(fact)) => {
                    facts.entry(fact.key.clone()).or_default().push(fact);
                }
                Some(ParsedFact::OrderingPoison(fact)) => {
                    poisoned.insert(fact.key.clone());
                    facts.entry(fact.key.clone()).or_default().push(fact);
                }
                None => {}
            }
        }
    }

    let mut reduced = facts
        .into_iter()
        .filter_map(|(key, group)| {
            reduce_transaction(key.clone(), group, poisoned.contains(&key), &scoped)
        })
        .collect::<Vec<_>>();
    reduced.sort_by(|left, right| {
        left.transaction
            .transaction_id
            .cmp(&right.transaction.transaction_id)
    });
    let transactions = reduced
        .iter()
        .map(|reduced| reduced.transaction.clone())
        .collect::<Vec<_>>();
    let mut findings = reduced
        .into_iter()
        .filter_map(|reduced| reduced.finding)
        .collect::<Vec<_>>();
    findings.extend(coverage_findings(&scoped));
    findings.sort_by(|left, right| left.finding.finding_id.cmp(&right.finding.finding_id));

    let mut source_local_observations = source_local_observations(&scoped, &intake.evidence);
    source_local_observations.sort_by(|left, right| left.observation_id.cmp(&right.observation_id));

    let mut artifact_requests = global_artifact_requests(&scoped);
    for request in transactions
        .iter()
        .flat_map(|transaction| transaction.next_artifact_requests.clone())
    {
        if !artifact_requests.contains(&request) {
            artifact_requests.push(request);
        }
    }
    artifact_requests.sort_by(|left, right| {
        (
            left.layer,
            left.producer_host_handle.as_str(),
            left.workflow_subject_handle.as_str(),
            left.request.logical_id.as_str(),
        )
            .cmp(&(
                right.layer,
                right.producer_host_handle.as_str(),
                right.workflow_subject_handle.as_str(),
                right.request.logical_id.as_str(),
            ))
    });

    ProviderAdminServiceAnalysis {
        workflow: "providerAndAdminService",
        support_state: ProviderAdminServiceSupportState::SyntheticProfileOnly,
        profiles: selected_profiles(&scoped),
        coverage,
        transactions,
        findings,
        source_local_observations,
        artifact_requests,
        cross_side_causal_claims: Vec::new(),
    }
}

fn empty_analysis() -> ProviderAdminServiceAnalysis {
    ProviderAdminServiceAnalysis {
        workflow: "providerAndAdminService",
        support_state: ProviderAdminServiceSupportState::IntakeAuthorityInvalid,
        profiles: Vec::new(),
        coverage: Vec::new(),
        transactions: Vec::new(),
        findings: Vec::new(),
        source_local_observations: Vec::new(),
        artifact_requests: Vec::new(),
        cross_side_causal_claims: Vec::new(),
    }
}

fn selected_profiles(
    artifacts: &[&SccmServerArtifactAssessment],
) -> Vec<ProviderAdminServiceProfile> {
    [
        ProviderAdminServiceLayer::Provider,
        ProviderAdminServiceLayer::AdminService,
    ]
    .into_iter()
    .filter(|layer| {
        artifacts
            .iter()
            .any(|artifact| artifact.source_id == layer.source_id())
    })
    .filter_map(|layer| {
        let selected = artifacts.iter().any(|artifact| {
            artifact.source_id == layer.source_id()
                && artifact.source_version.as_deref() == Some(SYNTHETIC_VERSION)
        });
        let extraction_profile = registered_profile(layer)?;
        Some(ProviderAdminServiceProfile {
            layer,
            selection_state: if selected {
                ProviderAdminServiceProfileSelection::SelectedSynthetic
            } else {
                ProviderAdminServiceProfileSelection::UnknownVersion
            },
            extraction_profile,
            limitation:
                "Synthetic fixtures only; no reviewed real SCCM version or Windows lab validation.",
        })
    })
    .collect()
}

fn registered_profile(layer: ProviderAdminServiceLayer) -> Option<SccmExtractionProfile> {
    Some(SccmExtractionProfile::for_artifact_family(
        Some(SYNTHETIC_VERSION),
        &match layer {
            ProviderAdminServiceLayer::Provider => SccmArtifactFamily::Provider,
            ProviderAdminServiceLayer::AdminService => SccmArtifactFamily::AdminService,
        },
    ))
}

fn transaction_layer(artifact: &SccmServerArtifactAssessment) -> Option<ProviderAdminServiceLayer> {
    match artifact.source_id.as_str() {
        PROVIDER_SOURCE_ID => Some(ProviderAdminServiceLayer::Provider),
        ADMIN_SOURCE_ID => Some(ProviderAdminServiceLayer::AdminService),
        _ => None,
    }
}

fn artifact_admits_facts(
    intake: &SccmServerIntakeAssessment,
    artifact: &SccmServerArtifactAssessment,
    layer: ProviderAdminServiceLayer,
) -> bool {
    artifact.state == SccmCoverageState::Captured
        && artifact.parser_eligible
        && artifact.profile_eligible
        && artifact.fragment_complete != Some(false)
        && artifact.source_version.as_deref() == Some(SYNTHETIC_VERSION)
        && artifact.producer_role == layer.role()
        && artifact.workflow_subject_role == Some(layer.role())
        && artifact.workflow_subject_handle.is_some()
        && intake.topology.roles_observed.contains(&layer.role())
        && matches!(
            (
                layer,
                &artifact.family,
                artifact.original_basename.as_deref()
            ),
            (
                ProviderAdminServiceLayer::Provider,
                SccmArtifactFamily::Provider,
                Some("Smsprov.log")
            ) | (
                ProviderAdminServiceLayer::AdminService,
                SccmArtifactFamily::AdminService,
                Some("AdminService.log")
            )
        )
}

fn parse_fact(
    artifact: &SccmServerArtifactAssessment,
    evidence: &SccmEvidence,
    layer: ProviderAdminServiceLayer,
) -> Option<ParsedFact> {
    if evidence.role != layer.role() {
        return None;
    }
    let fields = parse_fields(&evidence.message)?;
    let extraction_profile = SccmExtractionProfile::for_artifact_family(
        artifact.source_version.as_deref(),
        &artifact.family,
    );
    if fields.get("Layer")?.as_str() != layer_name(layer)
        || fields.get("ProfileId")?.as_str() != extraction_profile.profile_id
        || fields.get("EndpointId")?.as_str() != layer.endpoint_token()
    {
        return None;
    }
    let request_id = fields.get("RequestId")?.to_ascii_lowercase();
    let operation = fields.get("OperationHandle")?.clone();
    if !uuid_is_exact(&request_id) || !safe_operation(&operation) {
        return None;
    }
    let extraction = extract_keys(evidence, &extraction_profile);
    let shared_request_keys = extraction
        .keys
        .iter()
        .filter(|key| key.kind == SccmCorrelationKeyKind::RequestId)
        .collect::<Vec<_>>();
    let [shared_request_key] = shared_request_keys.as_slice() else {
        return None;
    };
    if shared_request_key.normalized != request_id
        || shared_request_key.confidence != SccmKeyConfidence::Low
        || shared_request_key.extraction_profile_id.as_deref()
            != Some(extraction_profile.profile_id.as_str())
    {
        return None;
    }
    let key = FactKey {
        layer,
        request_id,
        operation,
        endpoint_handle: artifact.workflow_subject_handle.clone()?,
        host_handle: artifact.producer_host_handle.clone()?,
    };
    let phase = parse_phase(fields.get("Phase")?, layer)?;
    let disposition = parse_disposition(fields.get("Disposition")?)?;
    let terminal = match fields.get("Terminal")?.as_str() {
        "true" => true,
        "false" => false,
        _ => return None,
    };
    if terminal
        && (!phase.is_last()
            || !matches!(
                disposition,
                ProviderAdminServiceDisposition::Succeeded
                    | ProviderAdminServiceDisposition::Failed
            ))
    {
        return None;
    }
    let utc_millis = match (
        &evidence.timestamp.ordering_state,
        evidence.timestamp.utc_millis,
    ) {
        (SccmTimeOrderingState::NormalizedUtc, Some(value)) => Some(value),
        _ => None,
    };
    let fact = Fact {
        key,
        phase,
        disposition,
        terminal,
        evidence: evidence.reference.clone(),
        utc_millis,
        extraction_profile,
    };
    Some(if fact.utc_millis.is_some() {
        ParsedFact::Valid(fact)
    } else {
        ParsedFact::OrderingPoison(fact)
    })
}

fn parse_fields(message: &str) -> Option<BTreeMap<&str, String>> {
    let message = message.strip_prefix("[sccm-public-message-v1] ")?;
    let body = message.strip_prefix("SYNTHETIC FIXTURE; ")?;
    let mut fields = BTreeMap::new();
    for segment in body.split(';').map(str::trim) {
        if segment == "[redacted:sccm-public-message-v1]" {
            continue;
        }
        let (name, value) = segment.split_once('=')?;
        if !matches!(
            name,
            "Phase"
                | "Disposition"
                | "Terminal"
                | "RequestId"
                | "OperationHandle"
                | "EndpointId"
                | "Layer"
                | "ProfileId"
                | "CallerHandle"
                | "Authorization"
                | "QueryHandle"
        ) || fields.insert(name, value.to_owned()).is_some()
        {
            return None;
        }
    }
    Some(fields)
}

fn parse_phase(value: &str, layer: ProviderAdminServiceLayer) -> Option<ProviderAdminServicePhase> {
    let phase = match value {
        "receive" => ProviderAdminServicePhase::Receive,
        "authenticateOrAuthorize" => ProviderAdminServicePhase::AuthenticateOrAuthorize,
        "executeProviderOperation" => ProviderAdminServicePhase::ExecuteProviderOperation,
        "route" => ProviderAdminServicePhase::Route,
        "executeBackendOperation" => ProviderAdminServicePhase::ExecuteBackendOperation,
        "respond" => ProviderAdminServicePhase::Respond,
        "recordOutcome" => ProviderAdminServicePhase::RecordOutcome,
        _ => return None,
    };
    phase.rank(layer).map(|_| phase)
}

fn parse_disposition(value: &str) -> Option<ProviderAdminServiceDisposition> {
    Some(match value {
        "succeeded" => ProviderAdminServiceDisposition::Succeeded,
        "failed" => ProviderAdminServiceDisposition::Failed,
        "pending" => ProviderAdminServiceDisposition::Pending,
        "retryableFailure" => ProviderAdminServiceDisposition::RetryableFailure,
        _ => return None,
    })
}

fn reduce_transaction(
    key: FactKey,
    mut facts: Vec<Fact>,
    ordering_poisoned: bool,
    artifacts: &[&SccmServerArtifactAssessment],
) -> Option<ReducedTransaction> {
    if !ordering_poisoned {
        facts.sort_by_key(|fact| fact.utc_millis);
    }
    if facts
        .first()
        .is_none_or(|fact| fact.phase != ProviderAdminServicePhase::Receive)
    {
        return None;
    }
    let strict_time = !ordering_poisoned
        && facts.windows(2).all(|pair| {
            matches!((pair[0].utc_millis, pair[1].utc_millis), (Some(left), Some(right)) if left < right)
        });
    let observations = facts
        .iter()
        .enumerate()
        .map(|(index, fact)| ProviderAdminServiceObservation {
            observation_id: format!("{}-{:02}", fact.evidence.entry_id, index + 1),
            phase: fact.phase,
            disposition: fact.disposition,
            terminal: fact.terminal,
            evidence: vec![fact.evidence.clone()],
        })
        .collect::<Vec<_>>();
    let terminal_success = facts.iter().any(|fact| {
        fact.terminal && fact.disposition == ProviderAdminServiceDisposition::Succeeded
    });
    let terminal_failure = facts
        .iter()
        .any(|fact| fact.terminal && fact.disposition == ProviderAdminServiceDisposition::Failed);
    let contradictory = terminal_success && terminal_failure;
    let deferred = facts
        .iter()
        .any(|fact| fact.disposition == ProviderAdminServiceDisposition::Pending);
    let phase_valid = phase_chain_is_valid(key.layer, &facts);
    let full_success = full_success_chain(key.layer, &facts);
    let gap_artifacts = artifacts
        .iter()
        .filter(|artifact| {
            artifact.source_id == key.layer.source_id()
                && artifact.producer_host_handle.as_deref() == Some(&key.host_handle)
                && artifact.workflow_subject_handle.as_deref() == Some(&key.endpoint_handle)
                && (artifact.state != SccmCoverageState::Captured
                    || artifact.fragment_complete == Some(false))
        })
        .collect::<Vec<_>>();
    let gaps = gap_artifacts
        .iter()
        .map(|artifact| artifact.artifact_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let ordering_usable = strict_time && !ordering_poisoned;
    let last_successful_phase = if ordering_usable {
        facts
            .iter()
            .rev()
            .find(|fact| fact.disposition == ProviderAdminServiceDisposition::Succeeded)
            .map(|fact| fact.phase)
    } else {
        None
    };
    let recovered = facts.windows(2).any(|pair| {
        pair[0].phase == pair[1].phase
            && pair[0].disposition == ProviderAdminServiceDisposition::RetryableFailure
            && pair[1].disposition == ProviderAdminServiceDisposition::Succeeded
    });
    let conclusive = ordering_usable && phase_valid && gaps.is_empty() && !contradictory;
    let (state, classification, confidence, summary) = if contradictory {
        (
            ProviderAdminServiceState::Contradictory,
            ProviderAdminServiceClassification::ContradictoryEvidence,
            SccmConfidence::Low,
            format!(
                "{} records mutually exclusive terminal outcomes.",
                display_layer(key.layer)
            ),
        )
    } else if !gaps.is_empty() || !phase_valid || !ordering_usable {
        (
            ProviderAdminServiceState::Incomplete,
            ProviderAdminServiceClassification::InsufficientEvidence,
            SccmConfidence::Low,
            format!(
                "{} evidence is incomplete, contradictory, or not comparably ordered.",
                display_layer(key.layer)
            ),
        )
    } else if deferred && !terminal_success && !terminal_failure {
        (
            ProviderAdminServiceState::BlockedOrDeferred,
            ProviderAdminServiceClassification::BlockedOrDeferred,
            SccmConfidence::Moderate,
            format!(
                "{} evidence records a blocked or deferred request without a terminal outcome.",
                display_layer(key.layer)
            ),
        )
    } else if conclusive && terminal_failure && !terminal_success {
        (
            ProviderAdminServiceState::Failed,
            ProviderAdminServiceClassification::ConfirmedFailure,
            SccmConfidence::High,
            format!(
                "{} recorded an explicit terminal operation failure.",
                display_layer(key.layer)
            ),
        )
    } else if conclusive && terminal_success && full_success && recovered {
        (
            ProviderAdminServiceState::Recovered,
            ProviderAdminServiceClassification::Recovered,
            SccmConfidence::High,
            format!(
                "{} operation recovered after an explicit retryable failure.",
                display_layer(key.layer)
            ),
        )
    } else if conclusive && terminal_success && full_success {
        (
            ProviderAdminServiceState::Succeeded,
            ProviderAdminServiceClassification::Success,
            SccmConfidence::High,
            format!(
                "{} operation completed with explicit terminal evidence.",
                display_layer(key.layer)
            ),
        )
    } else {
        (
            ProviderAdminServiceState::Incomplete,
            ProviderAdminServiceClassification::InsufficientEvidence,
            SccmConfidence::Low,
            format!(
                "{} evidence stops before a valid explicit terminal outcome.",
                display_layer(key.layer)
            ),
        )
    };
    let mut requests = gap_artifacts
        .iter()
        .filter_map(|artifact| scoped_artifact_request(artifact, key.layer))
        .collect::<Vec<_>>();
    if requests.is_empty()
        && matches!(
            state,
            ProviderAdminServiceState::Incomplete | ProviderAdminServiceState::BlockedOrDeferred
        )
    {
        requests.push(ProviderAdminServiceArtifactRequest {
            layer: key.layer,
            producer_role: key.layer.role(),
            producer_host_handle: key.host_handle.clone(),
            workflow_subject_handle: key.endpoint_handle.clone(),
            source_version: Some(SYNTHETIC_VERSION.to_owned()),
            request: artifact_request(key.layer),
        });
    }
    deduplicate_requests(&mut requests);
    let request_handle = public_handle("request", &key.request_id);
    let operation_handle = public_handle("operation", &key.operation);
    let transaction_id = format!(
        "{}:{request_handle}:{operation_handle}:{}:{}",
        layer_name(key.layer),
        key.host_handle,
        key.endpoint_handle
    );
    let extraction_profile = facts.first()?.extraction_profile.clone();
    let transaction = ProviderAdminServiceTransaction {
        transaction_id,
        layer: key.layer,
        producer_role: key.layer.role(),
        source_version: SYNTHETIC_VERSION.to_owned(),
        key: ProviderAdminServiceKey {
            request_handle,
            operation_handle,
            endpoint_handle: key.endpoint_handle,
            producer_host_handle: key.host_handle,
            confidence: SccmKeyConfidence::Low,
            extraction_profile,
        },
        topology_compatibility: ProviderAdminServiceTopologyCompatibility::Exact,
        timestamp_ordering: if ordering_usable {
            ProviderAdminServiceTimestampOrdering::Usable
        } else {
            ProviderAdminServiceTimestampOrdering::Unusable
        },
        correlation_eligible: false,
        state,
        classification,
        confidence,
        confidence_ceiling: confidence,
        terminal_evidence: terminal_success || terminal_failure,
        last_successful_phase,
        coverage_gap_artifact_ids: gaps,
        next_artifact_requests: requests,
        public_summary: summary,
        observations,
    };
    let finding = transaction_finding(&transaction, &facts, &gap_artifacts);
    Some(ReducedTransaction {
        transaction,
        finding,
    })
}

fn transaction_finding(
    transaction: &ProviderAdminServiceTransaction,
    facts: &[Fact],
    gap_artifacts: &[&&SccmServerArtifactAssessment],
) -> Option<ProviderAdminServiceFinding> {
    let mut class = transaction.classification.shared_finding_class()?;
    if class == SccmFindingClass::InsufficientEvidence && gap_artifacts.is_empty() {
        class = SccmFindingClass::Symptom;
    }
    let severity = match transaction.classification {
        ProviderAdminServiceClassification::Success => return None,
        ProviderAdminServiceClassification::Recovered => Severity::Success,
        ProviderAdminServiceClassification::ConfirmedFailure => Severity::Error,
        ProviderAdminServiceClassification::ContradictoryEvidence
        | ProviderAdminServiceClassification::BlockedOrDeferred
        | ProviderAdminServiceClassification::InsufficientEvidence => Severity::Warning,
    };
    let evidence = facts
        .iter()
        .map(|fact| fact.evidence.clone())
        .collect::<Vec<_>>();
    let terminal_evidence = facts
        .iter()
        .filter(|fact| fact.terminal && fact.disposition == ProviderAdminServiceDisposition::Failed)
        .map(|fact| SccmTerminalEvidence::observed_failure(fact.evidence.clone()))
        .collect::<Vec<_>>();
    let coverage_gaps = gap_artifacts
        .iter()
        .map(|artifact| SccmFindingCoverageGap {
            artifact_id: artifact.artifact_id.clone(),
            role: artifact.producer_role.clone(),
            coverage: artifact.state.clone(),
        })
        .collect::<Vec<_>>();
    let finding_id = format!(
        "provider-admin-finding:{}",
        public_handle("finding", &transaction.transaction_id)
    );
    let finding = SccmFindingBuilder::new(finding_id)
        .class(class)
        .phase(SccmPhase::Unknown("providerAndAdminService".to_owned()))
        .role(transaction.producer_role.clone())
        .severity(severity)
        .confidence(transaction.confidence)
        .title(format!(
            "{} {}",
            display_layer(transaction.layer),
            classification_name(transaction.classification)
        ))
        .summary(transaction.public_summary.clone())
        .evidence(evidence)
        .terminal_evidence(terminal_evidence)
        .coverage_gaps(coverage_gaps)
        .next_artifacts(
            transaction
                .next_artifact_requests
                .iter()
                .map(|request| request.request.clone())
                .collect(),
        )
        .build()
        .expect("provider/admin reducer must emit a valid shared finding");
    Some(ProviderAdminServiceFinding {
        subject_id: transaction.transaction_id.clone(),
        layer: transaction.layer,
        source_id: transaction.layer.source_id().to_owned(),
        producer_host_handle: transaction.key.producer_host_handle.clone(),
        workflow_subject_handle: transaction.key.endpoint_handle.clone(),
        source_version: Some(transaction.source_version.clone()),
        last_successful_phase: transaction.last_successful_phase,
        finding,
    })
}

fn coverage_findings(
    artifacts: &[&SccmServerArtifactAssessment],
) -> Vec<ProviderAdminServiceFinding> {
    artifacts
        .iter()
        .filter_map(|artifact| {
            let layer = transaction_layer(artifact)?;
            if artifact.state == SccmCoverageState::Captured
                && artifact.fragment_complete != Some(false)
            {
                return None;
            }
            let request = scoped_artifact_request(artifact, layer)?;
            let finding = SccmFindingBuilder::new(format!(
                "provider-admin-coverage:{}",
                artifact.artifact_id
            ))
            .class(SccmFindingClass::InsufficientEvidence)
            .phase(SccmPhase::Unknown("providerAndAdminService".to_owned()))
            .role(artifact.producer_role.clone())
            .severity(Severity::Warning)
            .confidence(SccmConfidence::Low)
            .title(format!("{} evidence unavailable", display_layer(layer)))
            .summary(format!(
                "{} cannot be evaluated because its scoped source is not a complete capture.",
                display_layer(layer)
            ))
            .coverage_gap(SccmFindingCoverageGap {
                artifact_id: artifact.artifact_id.clone(),
                role: artifact.producer_role.clone(),
                coverage: artifact.state.clone(),
            })
            .next_artifact(request.request.clone())
            .build()
            .expect("provider/admin coverage reducer must emit a valid shared finding");
            Some(ProviderAdminServiceFinding {
                subject_id: artifact.artifact_id.clone(),
                layer,
                source_id: artifact.source_id.clone(),
                producer_host_handle: artifact.producer_host_handle.clone()?,
                workflow_subject_handle: artifact.workflow_subject_handle.clone()?,
                source_version: artifact.source_version.clone(),
                last_successful_phase: None,
                finding,
            })
        })
        .collect()
}

fn phase_chain_is_valid(layer: ProviderAdminServiceLayer, facts: &[Fact]) -> bool {
    let mut previous_rank = None;
    let mut retry_phase = None;
    for fact in facts {
        let Some(rank) = fact.phase.rank(layer) else {
            return false;
        };
        if let Some(previous) = previous_rank {
            if (rank < previous || rank > previous + 1) && !fact.terminal {
                return false;
            }
            if rank == previous {
                let retry_recovery = retry_phase == Some(rank)
                    && fact.disposition == ProviderAdminServiceDisposition::Succeeded;
                let terminal_contradiction = fact.phase.is_last() && fact.terminal;
                if !retry_recovery && !terminal_contradiction {
                    return false;
                }
            }
        }
        retry_phase =
            (fact.disposition == ProviderAdminServiceDisposition::RetryableFailure).then_some(rank);
        previous_rank = Some(rank);
    }
    true
}

fn full_success_chain(layer: ProviderAdminServiceLayer, facts: &[Fact]) -> bool {
    let last_rank = ProviderAdminServicePhase::RecordOutcome
        .rank(layer)
        .unwrap_or_default();
    (0..=last_rank).all(|rank| {
        facts.iter().any(|fact| {
            fact.phase.rank(layer) == Some(rank)
                && fact.disposition == ProviderAdminServiceDisposition::Succeeded
        })
    })
}

fn source_local_observations(
    artifacts: &[&SccmServerArtifactAssessment],
    evidence: &[SccmEvidence],
) -> Vec<ProviderAdminServiceSourceLocalObservation> {
    let mut result = Vec::new();
    for artifact in artifacts {
        if artifact.source_id == IIS_SOURCE_ID {
            result.push(ProviderAdminServiceSourceLocalObservation {
                observation_id: format!("{}-supplemental", artifact.artifact_id),
                kind: ProviderAdminServiceSourceLocalKind::SupplementalOnly,
                artifact_ids: vec![artifact.artifact_id.clone()],
                correlation_eligible: false,
            });
        }
        if artifact.fragment_complete == Some(false) {
            result.push(ProviderAdminServiceSourceLocalObservation {
                observation_id: format!("{}-rotation", artifact.artifact_id),
                kind: ProviderAdminServiceSourceLocalKind::RotationFragment,
                artifact_ids: vec![artifact.artifact_id.clone()],
                correlation_eligible: false,
            });
        }
        if evidence.iter().any(|item| {
            item.reference.artifact_id == artifact.artifact_id
                && item.message.contains("[redacted:")
        }) {
            result.push(ProviderAdminServiceSourceLocalObservation {
                observation_id: format!("{}-privacy", artifact.artifact_id),
                kind: ProviderAdminServiceSourceLocalKind::PrivacyRedacted,
                artifact_ids: vec![artifact.artifact_id.clone()],
                correlation_eligible: false,
            });
        }
    }
    result
}

fn global_artifact_requests(
    artifacts: &[&SccmServerArtifactAssessment],
) -> Vec<ProviderAdminServiceArtifactRequest> {
    let mut requests = artifacts
        .iter()
        .filter_map(|artifact| {
            let layer = transaction_layer(artifact)?;
            (artifact.state != SccmCoverageState::Captured
                || artifact.fragment_complete == Some(false))
            .then(|| scoped_artifact_request(artifact, layer))?
        })
        .collect::<Vec<_>>();
    deduplicate_requests(&mut requests);
    requests
}

fn scoped_artifact_request(
    artifact: &SccmServerArtifactAssessment,
    layer: ProviderAdminServiceLayer,
) -> Option<ProviderAdminServiceArtifactRequest> {
    Some(ProviderAdminServiceArtifactRequest {
        layer,
        producer_role: artifact.producer_role.clone(),
        producer_host_handle: artifact.producer_host_handle.clone()?,
        workflow_subject_handle: artifact.workflow_subject_handle.clone()?,
        source_version: artifact.source_version.clone(),
        request: artifact_request(layer),
    })
}

fn deduplicate_requests(requests: &mut Vec<ProviderAdminServiceArtifactRequest>) {
    requests.sort_by(|left, right| {
        (
            left.layer,
            left.producer_host_handle.as_str(),
            left.workflow_subject_handle.as_str(),
            left.source_version.as_deref(),
            left.request.logical_id.as_str(),
        )
            .cmp(&(
                right.layer,
                right.producer_host_handle.as_str(),
                right.workflow_subject_handle.as_str(),
                right.source_version.as_deref(),
                right.request.logical_id.as_str(),
            ))
    });
    requests.dedup_by(|left, right| left == right);
}

fn artifact_request(layer: ProviderAdminServiceLayer) -> SccmArtifactRequest {
    SccmArtifactRequest {
        logical_id: layer.logical_artifact_id().to_owned(),
        role: layer.role(),
        reason: format!(
            "Collect the complete {} file.",
            if layer == ProviderAdminServiceLayer::Provider {
                "Smsprov.log"
            } else {
                "AdminService.log"
            }
        ),
    }
}

fn public_handle(domain: &str, value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"cmtraceopen.provider-admin-service.public-handle.v1\0");
    hasher.update(domain.as_bytes());
    hasher.update(b"\0");
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for byte in digest {
        hex.push(char::from(DIGITS[usize::from(byte >> 4)]));
        hex.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    format!("cmtraceopen.{domain}.sha256.v1:{hex}")
}

fn uuid_is_exact(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn safe_operation(value: &str) -> bool {
    value.strip_prefix("safe-operation-").is_some_and(|suffix| {
        !suffix.is_empty()
            && value.len() <= 96
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    })
}

fn layer_name(layer: ProviderAdminServiceLayer) -> &'static str {
    match layer {
        ProviderAdminServiceLayer::Provider => "provider",
        ProviderAdminServiceLayer::AdminService => "adminService",
    }
}

fn display_layer(layer: ProviderAdminServiceLayer) -> &'static str {
    match layer {
        ProviderAdminServiceLayer::Provider => "Provider",
        ProviderAdminServiceLayer::AdminService => "Admin Service",
    }
}

fn classification_name(classification: ProviderAdminServiceClassification) -> &'static str {
    match classification {
        ProviderAdminServiceClassification::Success => "success",
        ProviderAdminServiceClassification::Recovered => "recovered",
        ProviderAdminServiceClassification::ConfirmedFailure => "confirmed failure",
        ProviderAdminServiceClassification::ContradictoryEvidence => "contradictory evidence",
        ProviderAdminServiceClassification::BlockedOrDeferred => "blocked or deferred",
        ProviderAdminServiceClassification::InsufficientEvidence => "insufficient evidence",
    }
}
