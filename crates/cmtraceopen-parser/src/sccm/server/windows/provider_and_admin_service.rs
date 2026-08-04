use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::sccm::{
    SccmArtifactFamily, SccmArtifactRequest, SccmConfidence, SccmCoverageState, SccmEvidence,
    SccmEvidenceRef, SccmFindingClass, SccmKeyConfidence, SccmRole, SccmTimeOrderingState,
};

use super::{SccmServerArtifactAssessment, SccmServerIntakeAssessment};

const PROVIDER_SOURCE_ID: &str = "server-provider";
const ADMIN_SOURCE_ID: &str = "server-admin-service";
const IIS_SOURCE_ID: &str = "server-admin-service-iis";
const SYNTHETIC_VERSION: &str = "5.00.TEST";
const PROVIDER_PROFILE: &str = "provider-server-5.00.test-v1";
const ADMIN_PROFILE: &str = "admin-service-server-5.00.test-v1";

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

    fn profile_id(self) -> &'static str {
        match self {
            Self::Provider => PROVIDER_PROFILE,
            Self::AdminService => ADMIN_PROFILE,
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
    Failed,
    BlockedOrDeferred,
    Incomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProviderAdminServiceClassification {
    Success,
    ConfirmedFailure,
    BlockedOrDeferred,
    InsufficientEvidence,
}

impl ProviderAdminServiceClassification {
    pub fn shared_finding_class(self) -> Option<SccmFindingClass> {
        match self {
            Self::Success => None,
            Self::ConfirmedFailure => Some(SccmFindingClass::ConfirmedFailure),
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
    pub profile_id: &'static str,
    pub source_version: &'static str,
    pub limitation: &'static str,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderAdminServiceCoverage {
    pub artifact_id: String,
    pub source_id: String,
    pub producer_role: SccmRole,
    pub endpoint_handle: Option<String>,
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
    pub extraction_profile_id: &'static str,
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
    pub next_artifact_request: Option<SccmArtifactRequest>,
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
    pub source_local_observations: Vec<ProviderAdminServiceSourceLocalObservation>,
    pub artifact_requests: Vec<SccmArtifactRequest>,
    pub cross_side_causal_claims: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FactKey {
    layer: ProviderAdminServiceLayer,
    request_id: String,
    operation: String,
    endpoint_handle: String,
    host_handle: String,
    profile_id: String,
}

#[derive(Debug, Clone)]
struct Fact {
    key: FactKey,
    phase: ProviderAdminServicePhase,
    disposition: ProviderAdminServiceDisposition,
    terminal: bool,
    evidence: SccmEvidenceRef,
    utc_millis: Option<i64>,
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
            endpoint_handle: artifact.workflow_subject_handle.clone(),
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

    let mut transactions = facts
        .into_iter()
        .filter_map(|(key, group)| {
            reduce_transaction(key.clone(), group, poisoned.contains(&key), &scoped)
        })
        .collect::<Vec<_>>();
    transactions.sort_by(|left, right| left.transaction_id.cmp(&right.transaction_id));

    let mut source_local_observations = source_local_observations(&scoped, &intake.evidence);
    source_local_observations.sort_by(|left, right| left.observation_id.cmp(&right.observation_id));

    let mut artifact_requests = global_artifact_requests(&scoped);
    for request in transactions
        .iter()
        .filter_map(|transaction| transaction.next_artifact_request.clone())
    {
        if !artifact_requests.iter().any(|existing| {
            existing.logical_id == request.logical_id && existing.role == request.role
        }) {
            artifact_requests.push(request);
        }
    }
    artifact_requests.sort_by(|left, right| {
        (left.logical_id.as_str(), role_name(&left.role))
            .cmp(&(right.logical_id.as_str(), role_name(&right.role)))
    });
    artifact_requests.truncate(1);

    ProviderAdminServiceAnalysis {
        workflow: "providerAndAdminService",
        support_state: ProviderAdminServiceSupportState::SyntheticProfileOnly,
        profiles: selected_profiles(&scoped),
        coverage,
        transactions,
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
    .map(|layer| ProviderAdminServiceProfile {
        layer,
        selection_state: if artifacts.iter().any(|artifact| {
            artifact.source_id == layer.source_id()
                && artifact.source_version.as_deref() == Some(SYNTHETIC_VERSION)
        }) {
            ProviderAdminServiceProfileSelection::SelectedSynthetic
        } else {
            ProviderAdminServiceProfileSelection::UnknownVersion
        },
        profile_id: layer.profile_id(),
        source_version: SYNTHETIC_VERSION,
        limitation:
            "Synthetic fixtures only; no reviewed real SCCM version or Windows lab validation.",
    })
    .collect()
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
    if fields.get("Layer")?.as_str() != layer_name(layer)
        || fields.get("ProfileId")?.as_str() != layer.profile_id()
        || fields.get("EndpointId")?.as_str() != layer.endpoint_token()
    {
        return None;
    }
    let request_id = fields.get("RequestId")?.to_ascii_lowercase();
    let operation = fields.get("OperationHandle")?.clone();
    if !uuid_is_exact(&request_id) || !safe_operation(&operation) {
        return None;
    }
    let key = FactKey {
        layer,
        request_id,
        operation,
        endpoint_handle: artifact.workflow_subject_handle.clone()?,
        host_handle: artifact.producer_host_handle.clone()?,
        profile_id: layer.profile_id().to_owned(),
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
) -> Option<ProviderAdminServiceTransaction> {
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
    let gaps = artifacts
        .iter()
        .filter(|artifact| {
            artifact.source_id == key.layer.source_id()
                && artifact.workflow_subject_handle.as_deref() == Some(&key.endpoint_handle)
                && (artifact.state != SccmCoverageState::Captured
                    || artifact.fragment_complete == Some(false))
        })
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
    let conclusive = ordering_usable && phase_valid && gaps.is_empty() && !contradictory;
    let (state, classification, confidence, summary) =
        if !gaps.is_empty() || contradictory || !phase_valid || !ordering_usable {
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
    let request = matches!(
        state,
        ProviderAdminServiceState::Incomplete | ProviderAdminServiceState::BlockedOrDeferred
    )
    .then(|| artifact_request(key.layer));
    let request_handle = public_handle("request", &key.request_id);
    let operation_handle = public_handle("operation", &key.operation);
    let transaction_id = format!(
        "{}:{request_handle}:{operation_handle}:{}",
        layer_name(key.layer),
        key.endpoint_handle
    );
    Some(ProviderAdminServiceTransaction {
        transaction_id,
        layer: key.layer,
        producer_role: key.layer.role(),
        source_version: SYNTHETIC_VERSION.to_owned(),
        key: ProviderAdminServiceKey {
            request_handle,
            operation_handle,
            endpoint_handle: key.endpoint_handle,
            producer_host_handle: key.host_handle,
            confidence: SccmKeyConfidence::Exact,
            extraction_profile_id: match key.profile_id.as_str() {
                PROVIDER_PROFILE => PROVIDER_PROFILE,
                _ => ADMIN_PROFILE,
            },
        },
        topology_compatibility: ProviderAdminServiceTopologyCompatibility::Exact,
        timestamp_ordering: if ordering_usable {
            ProviderAdminServiceTimestampOrdering::Usable
        } else {
            ProviderAdminServiceTimestampOrdering::Unusable
        },
        correlation_eligible: conclusive
            && matches!(
                state,
                ProviderAdminServiceState::Succeeded | ProviderAdminServiceState::Failed
            ),
        state,
        classification,
        confidence,
        confidence_ceiling: confidence,
        terminal_evidence: terminal_success || terminal_failure,
        last_successful_phase,
        coverage_gap_artifact_ids: gaps,
        next_artifact_request: request,
        public_summary: summary,
        observations,
    })
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
) -> Vec<SccmArtifactRequest> {
    let mut layers = artifacts
        .iter()
        .filter_map(|artifact| {
            let layer = transaction_layer(artifact)?;
            (artifact.state != SccmCoverageState::Captured
                || artifact.fragment_complete == Some(false))
            .then_some(layer)
        })
        .collect::<BTreeSet<_>>();
    layers
        .pop_first()
        .map(artifact_request)
        .into_iter()
        .collect()
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

fn role_name(role: &SccmRole) -> &'static str {
    match role {
        SccmRole::Provider => "provider",
        SccmRole::AdminService => "adminService",
        _ => "other",
    }
}
