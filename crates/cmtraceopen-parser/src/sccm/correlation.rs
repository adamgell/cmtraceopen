//! Deterministic, conservative correlation of independently reduced SCCM evidence.
//!
//! This layer borrows only public analyzer output. Pair adapters immediately
//! project counterpart-ready facts into a bounded private representation; the
//! shared reducer never parses raw records and never mutates either source
//! analysis.

use std::collections::BTreeSet;

use serde::Serialize;
use sha2::{Digest, Sha256};

use super::client::{
    SccmClientUpdateCoverageState, SccmClientUpdatesAnalysis, SccmDeploymentAnalysis,
    SccmDeploymentProfileSelectionState, SccmPolicyAnalysis, SccmPolicyCondition,
    SccmPolicyProfileSelectionState, SccmPolicyState, SCCM_DEPLOYMENT_PROFILE_ID,
};
use super::server::windows::{
    SccmDistributionPointContentAnalysis, SccmDistributionPointContentState,
    SccmManagementPointAnalysis, SccmManagementPointState, SccmSoftwareUpdatePointAnalysis,
    SccmSoftwareUpdatePointDisposition, SccmSoftwareUpdatePointProfileSelection,
    SccmSoftwareUpdatePointSourceLocalClassification, SccmSoftwareUpdatePointState,
    SCCM_DISTRIBUTION_POINT_CONTENT_PROFILE_ID, SCCM_DISTRIBUTION_POINT_CONTENT_PROFILE_VERSION,
    SCCM_MANAGEMENT_POINT_TEST_PROFILE_ID, SCCM_SOFTWARE_UPDATE_POINT_PROFILE_ID,
};
use super::{
    SccmCorrelationKeyKind, SccmCoverageState, SccmKeyConfidence, SccmTimeOrderingState,
    SCCM_EXPERIMENTAL_KEY_PROFILE_ID, SCCM_POLICY_KEY_PROFILE_ID,
};

pub const SCCM_CORRELATION_SCHEMA_VERSION: u32 = 1;
pub const SCCM_CORRELATION_IMPLEMENTATION_MODULE: &str = "sccm::correlation";
const MAX_FACTS_PER_SIDE: usize = 128;
const MAX_RESULTS: usize = 256;

const ALL_GUARDS: [SccmCorrelationGuard; 13] = [
    SccmCorrelationGuard::ConflictingExactKey,
    SccmCorrelationGuard::IncompatibleTopology,
    SccmCorrelationGuard::InvalidTimestampOffset,
    SccmCorrelationGuard::MissingClientCounterpart,
    SccmCorrelationGuard::MissingServerCounterpart,
    SccmCorrelationGuard::PartialCapture,
    SccmCorrelationGuard::RedactionBoundary,
    SccmCorrelationGuard::ReorderedInput,
    SccmCorrelationGuard::RotationSplit,
    SccmCorrelationGuard::SameTimeNoKey,
    SccmCorrelationGuard::UnknownExtractionProfile,
    SccmCorrelationGuard::UnrelatedTerminalError,
    SccmCorrelationGuard::VersionMismatch,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmCorrelationPair {
    ContentDistributionPoint,
    PolicyManagementPoint,
    UpdatesSoftwareUpdatePoint,
}

impl SccmCorrelationPair {
    fn stable_name(self) -> &'static str {
        match self {
            Self::ContentDistributionPoint => "content-distribution-point",
            Self::PolicyManagementPoint => "policy-management-point",
            Self::UpdatesSoftwareUpdatePoint => "updates-software-update-point",
        }
    }

    fn client_request(self) -> &'static str {
        match self {
            Self::ContentDistributionPoint => "client-content",
            Self::PolicyManagementPoint => "client-policy-agent",
            Self::UpdatesSoftwareUpdatePoint => "client-updates",
        }
    }

    fn server_request(self) -> &'static str {
        match self {
            Self::ContentDistributionPoint => "server-dp-distribution",
            Self::PolicyManagementPoint => "server-mp-policy",
            Self::UpdatesSoftwareUpdatePoint => "server-sup-sync",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmCorrelationOutcome {
    CausalFinding,
    CandidateOnly,
    CounterpartRequested,
    CoverageGap,
    Incompatible,
    NotCausal,
    ProfileGap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmCorrelationLinkStrength {
    ExactCorroborated,
    ExactPartial,
    Candidate,
    Incompatible,
    Unlinked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmCorrelationConfidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SccmCorrelationGuard {
    ConflictingExactKey,
    IncompatibleTopology,
    InvalidTimestampOffset,
    MissingClientCounterpart,
    MissingServerCounterpart,
    PartialCapture,
    RedactionBoundary,
    ReorderedInput,
    RotationSplit,
    SameTimeNoKey,
    UnknownExtractionProfile,
    UnrelatedTerminalError,
    VersionMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmCorrelationGuardState {
    Passed,
    Triggered,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmCorrelationGuardCheck {
    pub guard_id: SccmCorrelationGuard,
    pub state: SccmCorrelationGuardState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SccmCorrelationReason {
    ClientCounterpartMissing,
    ExactKeyConflict,
    InputCapExceeded,
    OrderingNotCausal,
    OrderingUnavailable,
    PartialSourceCoverage,
    ProfileUnvalidated,
    ProfileVersionMismatch,
    RotationIncomplete,
    SameTimeWithoutExactKey,
    ServerCounterpartMissing,
    TerminalRelationMissing,
    TopologyMismatch,
    UnrelatedServerTerminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmCorrelationSide {
    Client,
    Server,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmCorrelationArtifactRequest {
    pub side: SccmCorrelationSide,
    pub logical_artifact_id: String,
    pub reason_code: SccmCorrelationReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmCorrelationResult {
    pub result_id: String,
    pub outcome: SccmCorrelationOutcome,
    pub link_strength: SccmCorrelationLinkStrength,
    pub confidence: SccmCorrelationConfidence,
    pub guard_checks: Vec<SccmCorrelationGuardCheck>,
    pub reason_codes: Vec<SccmCorrelationReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_fact_handle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_fact_handle: Option<String>,
    pub artifact_requests: Vec<SccmCorrelationArtifactRequest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmCorrelationAnalysis {
    pub schema_version: u32,
    pub pair: SccmCorrelationPair,
    pub source_findings_preserved: bool,
    pub results: Vec<SccmCorrelationResult>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProfileAuthority {
    Validated,
    Unknown,
    VersionMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CanonicalFact {
    exact_key: String,
    topology: String,
    utc_millis: Option<i64>,
    ordering_usable: bool,
    terminal_failure: bool,
    stable_source: String,
}

impl CanonicalFact {
    fn handle(&self, side: SccmCorrelationSide, pair: SccmCorrelationPair) -> String {
        let preimage = format!(
            "{}|{:?}|{}|{}|{:?}|{}|{}",
            pair.stable_name(),
            side,
            self.exact_key,
            self.topology,
            self.utc_millis,
            self.terminal_failure,
            self.stable_source
        );
        format!("corrfact:sha256:{}", sha256_hex(preimage.as_bytes()))
    }
}

#[derive(Debug, Clone)]
struct CanonicalInput {
    pair: SccmCorrelationPair,
    client_facts: Vec<CanonicalFact>,
    server_facts: Vec<CanonicalFact>,
    client_profile: ProfileAuthority,
    server_profile: ProfileAuthority,
    client_coverage_complete: bool,
    server_coverage_complete: bool,
    client_rotation_complete: bool,
    server_rotation_complete: bool,
    input_capped: bool,
}

impl CanonicalInput {
    fn normalize(mut self) -> Self {
        self.client_facts.sort();
        self.client_facts.dedup();
        self.server_facts.sort();
        self.server_facts.dedup();
        self.input_capped |= self.client_facts.len() > MAX_FACTS_PER_SIDE
            || self.server_facts.len() > MAX_FACTS_PER_SIDE;
        self.client_facts.truncate(MAX_FACTS_PER_SIDE);
        self.server_facts.truncate(MAX_FACTS_PER_SIDE);
        self
    }
}

#[derive(Debug, Clone)]
pub struct SccmPolicyManagementPointInput {
    canonical: CanonicalInput,
}

impl SccmPolicyManagementPointInput {
    pub fn from_analyses(
        client: &SccmPolicyAnalysis,
        server: &SccmManagementPointAnalysis,
    ) -> Self {
        let mut client_profile = match (
            client.extraction_profile.selection_state,
            client.extraction_profile.profile_id.as_deref(),
        ) {
            (SccmPolicyProfileSelectionState::Selected, Some(SCCM_POLICY_KEY_PROFILE_ID)) => {
                ProfileAuthority::Validated
            }
            (SccmPolicyProfileSelectionState::Selected, Some(_)) => {
                ProfileAuthority::VersionMismatch
            }
            _ => ProfileAuthority::Unknown,
        };
        if client_profile == ProfileAuthority::Validated
            && client.transactions.iter().any(|transaction| {
                transaction.key.extraction_profile_id != SCCM_POLICY_KEY_PROFILE_ID
            })
        {
            client_profile = ProfileAuthority::VersionMismatch;
        }
        let client_facts = client
            .transactions
            .iter()
            .filter_map(|transaction| {
                let request_id = transaction.key.request_id.as_ref()?;
                let site_code = unique_exact_site_code(&transaction.correlation_keys)?;
                let observation = transaction.observations.iter().max_by(|left, right| {
                    left.timestamp
                        .utc_millis
                        .cmp(&right.timestamp.utc_millis)
                        .then_with(|| left.observation_id.cmp(&right.observation_id))
                })?;
                Some(CanonicalFact {
                    exact_key: format!("policy={}|request={request_id}", transaction.key.policy_id),
                    topology: format!("site={site_code}"),
                    utc_millis: observation.timestamp.utc_millis,
                    ordering_usable: observation.timestamp.ordering_state
                        == SccmTimeOrderingState::NormalizedUtc
                        && observation.timestamp.utc_millis.is_some(),
                    terminal_failure: transaction.state == SccmPolicyState::Failed
                        && transaction.observations.iter().any(|item| item.terminal),
                    stable_source: transaction.transaction_id.clone(),
                })
            })
            .collect();
        let server_facts = server
            .counterpart_ready_facts
            .iter()
            .filter_map(|fact| {
                let policy_id = fact.key.policy_id.as_ref()?;
                Some(CanonicalFact {
                    exact_key: format!("policy={policy_id}|request={}", fact.key.request_id),
                    topology: format!("site={}", fact.key.site_code),
                    utc_millis: fact.timestamp.utc_millis,
                    ordering_usable: fact.timestamp.ordering_state
                        == SccmTimeOrderingState::NormalizedUtc
                        && fact.timestamp.utc_millis.is_some(),
                    terminal_failure: fact.state == SccmManagementPointState::Failed
                        && fact.terminal_evidence.is_some(),
                    stable_source: fact.transaction_id.clone(),
                })
            })
            .collect::<Vec<_>>();
        let server_profile = profile_authority(
            server
                .counterpart_ready_facts
                .iter()
                .map(|fact| fact.key.extraction_profile_id.as_str()),
            SCCM_MANAGEMENT_POINT_TEST_PROFILE_ID,
        );
        Self {
            canonical: CanonicalInput {
                pair: SccmCorrelationPair::PolicyManagementPoint,
                client_facts,
                server_facts,
                client_profile,
                server_profile,
                client_coverage_complete: !client.coverage.is_empty()
                    && client
                        .coverage
                        .iter()
                        .all(|coverage| coverage.state == SccmCoverageState::Captured)
                    && client.profile_gaps.is_empty(),
                server_coverage_complete: server.coverage_gaps.is_empty(),
                client_rotation_complete: !client
                    .source_local_observations
                    .iter()
                    .any(|item| item.condition == SccmPolicyCondition::RotationSplit),
                server_rotation_complete: !server
                    .source_local_observations
                    .iter()
                    .any(|item| item.observation_id.contains("rotation")),
                input_capped: false,
            }
            .normalize(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SccmContentDistributionPointInput {
    canonical: CanonicalInput,
}

impl SccmContentDistributionPointInput {
    pub fn from_analyses(
        client: &SccmDeploymentAnalysis,
        server: &SccmDistributionPointContentAnalysis,
    ) -> Self {
        let mut client_profile = match client.extraction_profile.selection_state {
            SccmDeploymentProfileSelectionState::Selected
                if client.extraction_profile.profile_id == SCCM_DEPLOYMENT_PROFILE_ID =>
            {
                ProfileAuthority::Validated
            }
            SccmDeploymentProfileSelectionState::Selected => ProfileAuthority::VersionMismatch,
            SccmDeploymentProfileSelectionState::Unselected => ProfileAuthority::Unknown,
        };
        if client_profile == ProfileAuthority::Validated
            && client
                .transactions
                .iter()
                .filter_map(|transaction| transaction.counterpart_ready_fact.as_ref())
                .any(|fact| fact.extraction_profile_id != SCCM_DEPLOYMENT_PROFILE_ID)
        {
            client_profile = ProfileAuthority::VersionMismatch;
        }
        let client_facts = client
            .transactions
            .iter()
            .filter_map(|transaction| transaction.counterpart_ready_fact.as_ref())
            .map(|fact| {
                let utc_millis = parse_rfc3339_millis(&fact.timestamp_provenance.normalized_utc);
                CanonicalFact {
                    exact_key: format!(
                        "package={}|content={}|version={}",
                        fact.package_id, fact.content_id, fact.content_version
                    ),
                    topology: format!("dp={}", fact.distribution_point_host_handle),
                    utc_millis,
                    ordering_usable: utc_millis.is_some(),
                    terminal_failure: false,
                    stable_source: fact.request_id.clone(),
                }
            })
            .collect();
        let server_facts = server
            .transactions
            .iter()
            .filter_map(|transaction| {
                let observation = terminal_or_latest_dp_observation(transaction)?;
                Some(CanonicalFact {
                    exact_key: format!(
                        "package={}|content={}|version={}",
                        transaction.key.package_id,
                        transaction.key.content_id,
                        transaction.key.content_version
                    ),
                    topology: format!("dp={}", transaction.key.distribution_point_handle),
                    utc_millis: observation.timestamp.utc_millis,
                    ordering_usable: observation.timestamp.ordering_state
                        == SccmTimeOrderingState::NormalizedUtc
                        && observation.timestamp.utc_millis.is_some(),
                    terminal_failure: transaction.state
                        == SccmDistributionPointContentState::Failed
                        && observation.terminal
                        && !transaction.recovered,
                    stable_source: transaction.transaction_id.clone(),
                })
            })
            .collect::<Vec<_>>();
        let server_profile = if server.profile.id == SCCM_DISTRIBUTION_POINT_CONTENT_PROFILE_ID
            && server.profile.version == SCCM_DISTRIBUTION_POINT_CONTENT_PROFILE_VERSION
            && server.transactions.iter().all(|transaction| {
                transaction.key.extraction_profile_id == SCCM_DISTRIBUTION_POINT_CONTENT_PROFILE_ID
                    && transaction.key.extraction_profile_version
                        == SCCM_DISTRIBUTION_POINT_CONTENT_PROFILE_VERSION
            }) {
            ProfileAuthority::Validated
        } else if server.profile.id.is_empty() {
            ProfileAuthority::Unknown
        } else {
            ProfileAuthority::VersionMismatch
        };
        Self {
            canonical: CanonicalInput {
                pair: SccmCorrelationPair::ContentDistributionPoint,
                client_facts,
                server_facts,
                client_profile,
                server_profile,
                client_coverage_complete: !client.coverage.is_empty()
                    && client.coverage.iter().all(|coverage| {
                        coverage.state == SccmCoverageState::Captured && coverage.capture_complete
                    })
                    && client.coverage_gaps.is_empty(),
                server_coverage_complete: server.coverage_gaps.is_empty()
                    && server
                        .transactions
                        .iter()
                        .all(|transaction| !transaction.content_version_mismatch),
                client_rotation_complete: !client
                    .source_local_observations
                    .iter()
                    .any(|item| item.reason.to_ascii_lowercase().contains("rotation")),
                server_rotation_complete: !server
                    .coverage_gaps
                    .iter()
                    .any(|gap| gap.reason.to_ascii_lowercase().contains("rotation")),
                input_capped: false,
            }
            .normalize(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SccmUpdatesSoftwareUpdatePointInput {
    canonical: CanonicalInput,
}

impl SccmUpdatesSoftwareUpdatePointInput {
    pub fn from_analyses(
        client: &SccmClientUpdatesAnalysis,
        server: &SccmSoftwareUpdatePointAnalysis,
    ) -> Self {
        let mut client_profile =
            if client.extraction_profile.profile_id == SCCM_EXPERIMENTAL_KEY_PROFILE_ID {
                ProfileAuthority::Validated
            } else if client.extraction_profile.profile_id.is_empty() {
                ProfileAuthority::Unknown
            } else {
                ProfileAuthority::VersionMismatch
            };
        if client_profile == ProfileAuthority::Validated
            && client
                .correlation_handoff
                .counterpart_ready_facts
                .iter()
                .any(|fact| fact.extraction_profile_id != SCCM_EXPERIMENTAL_KEY_PROFILE_ID)
        {
            client_profile = ProfileAuthority::VersionMismatch;
        }
        let client_facts = client
            .correlation_handoff
            .counterpart_ready_facts
            .iter()
            .filter(|fact| fact.key_confidence == SccmKeyConfidence::Exact)
            .map(|fact| CanonicalFact {
                exact_key: format!("update={}", fact.update_id),
                topology: format!("site={}|sup={}", fact.site_code, fact.sup_host_handle),
                utc_millis: Some(fact.timestamp_provenance.utc_millis),
                ordering_usable: fact.timestamp_provenance.ordering_state
                    == SccmTimeOrderingState::NormalizedUtc,
                terminal_failure: false,
                stable_source: format!(
                    "{}:{}:{}",
                    fact.evidence.artifact_id, fact.evidence.start_line, fact.evidence.end_line
                ),
            })
            .collect();
        let server_facts = server
            .transactions
            .iter()
            .filter(|transaction| transaction.correlation_eligible)
            .filter_map(|transaction| {
                let update_id = transaction.key.update_id.as_ref()?;
                let observation = terminal_or_latest_sup_observation(transaction)?;
                let utc_millis = observation.timestamp.utc_millis;
                Some(CanonicalFact {
                    exact_key: format!("update={update_id}"),
                    topology: format!(
                        "site={}|sup={}",
                        transaction.key.site_code, transaction.key.sup_handle
                    ),
                    utc_millis,
                    ordering_usable: observation.timestamp.ordering_state
                        == SccmTimeOrderingState::NormalizedUtc
                        && utc_millis.is_some(),
                    terminal_failure: transaction.state == SccmSoftwareUpdatePointState::Failed
                        && observation.terminal
                        && observation.disposition == SccmSoftwareUpdatePointDisposition::Failed,
                    stable_source: transaction.transaction_id.clone(),
                })
            })
            .collect::<Vec<_>>();
        let mut server_profile = match (
            server.extraction_profile.selection_state,
            server.extraction_profile.profile_id.as_deref(),
        ) {
            (
                SccmSoftwareUpdatePointProfileSelection::SelectedSynthetic,
                Some(SCCM_SOFTWARE_UPDATE_POINT_PROFILE_ID),
            ) => ProfileAuthority::Validated,
            (SccmSoftwareUpdatePointProfileSelection::SelectedSynthetic, Some(_)) => {
                ProfileAuthority::VersionMismatch
            }
            _ => ProfileAuthority::Unknown,
        };
        if server_profile == ProfileAuthority::Validated
            && server.transactions.iter().any(|transaction| {
                transaction.key.extraction_profile_id != SCCM_SOFTWARE_UPDATE_POINT_PROFILE_ID
            })
        {
            server_profile = ProfileAuthority::VersionMismatch;
        }
        Self {
            canonical: CanonicalInput {
                pair: SccmCorrelationPair::UpdatesSoftwareUpdatePoint,
                client_facts,
                server_facts,
                client_profile,
                server_profile,
                client_coverage_complete: !client.coverage.is_empty()
                    && client
                        .coverage
                        .iter()
                        .all(|coverage| coverage.state == SccmClientUpdateCoverageState::Captured)
                    && client
                        .transactions
                        .iter()
                        .all(|transaction| transaction.coverage_gap_artifact_ids.is_empty()),
                server_coverage_complete: !server.coverage.is_empty()
                    && server
                        .coverage
                        .iter()
                        .all(|coverage| coverage.state == SccmCoverageState::Captured)
                    && server
                        .transactions
                        .iter()
                        .all(|transaction| transaction.coverage_gap_artifact_ids.is_empty()),
                client_rotation_complete: !client
                    .observations
                    .iter()
                    .any(|item| item.reason.to_ascii_lowercase().contains("rotation")),
                server_rotation_complete: !server.source_local_observations.iter().any(|item| {
                    item.classification
                        == SccmSoftwareUpdatePointSourceLocalClassification::RotationSplit
                }),
                input_capped: false,
            }
            .normalize(),
        }
    }
}

pub fn correlate_policy_management_point(
    input: &SccmPolicyManagementPointInput,
) -> SccmCorrelationAnalysis {
    correlate(&input.canonical)
}

pub fn correlate_content_distribution_point(
    input: &SccmContentDistributionPointInput,
) -> SccmCorrelationAnalysis {
    correlate(&input.canonical)
}

pub fn correlate_updates_software_update_point(
    input: &SccmUpdatesSoftwareUpdatePointInput,
) -> SccmCorrelationAnalysis {
    correlate(&input.canonical)
}

fn correlate(input: &CanonicalInput) -> SccmCorrelationAnalysis {
    let mut results = Vec::new();
    if input.client_facts.is_empty() || input.server_facts.is_empty() {
        results.push(reduce_missing(input));
    } else {
        for client in &input.client_facts {
            if results.len() == MAX_RESULTS {
                break;
            }
            results.push(reduce_client_fact(input, client));
        }
    }
    results.sort_by(|left, right| left.result_id.cmp(&right.result_id));
    results.dedup_by(|left, right| left.result_id == right.result_id);
    SccmCorrelationAnalysis {
        schema_version: SCCM_CORRELATION_SCHEMA_VERSION,
        pair: input.pair,
        source_findings_preserved: true,
        results,
    }
}

fn reduce_missing(input: &CanonicalInput) -> SccmCorrelationResult {
    let client_missing = input.client_facts.is_empty();
    let server_missing = input.server_facts.is_empty();
    let mut triggered = BTreeSet::new();
    let mut reasons = BTreeSet::new();
    let mut requests = Vec::new();
    if client_missing {
        triggered.insert(SccmCorrelationGuard::MissingClientCounterpart);
        reasons.insert(SccmCorrelationReason::ClientCounterpartMissing);
        requests.push(SccmCorrelationArtifactRequest {
            side: SccmCorrelationSide::Client,
            logical_artifact_id: input.pair.client_request().to_owned(),
            reason_code: SccmCorrelationReason::ClientCounterpartMissing,
        });
    }
    if server_missing {
        triggered.insert(SccmCorrelationGuard::MissingServerCounterpart);
        reasons.insert(SccmCorrelationReason::ServerCounterpartMissing);
        requests.push(SccmCorrelationArtifactRequest {
            side: SccmCorrelationSide::Server,
            logical_artifact_id: input.pair.server_request().to_owned(),
            reason_code: SccmCorrelationReason::ServerCounterpartMissing,
        });
    }
    apply_global_guards(input, &mut triggered, &mut reasons, &mut requests);
    build_result(
        input.pair,
        SccmCorrelationOutcome::CounterpartRequested,
        SccmCorrelationLinkStrength::Unlinked,
        SccmCorrelationConfidence::Low,
        triggered,
        reasons,
        None,
        None,
        requests,
    )
}

fn reduce_client_fact(input: &CanonicalInput, client: &CanonicalFact) -> SccmCorrelationResult {
    let identity_matches = input
        .server_facts
        .iter()
        .filter(|server| server.exact_key == client.exact_key)
        .collect::<Vec<_>>();
    let topology_matches = identity_matches
        .iter()
        .copied()
        .filter(|server| server.topology == client.topology)
        .collect::<Vec<_>>();
    let mut triggered = BTreeSet::new();
    let mut reasons = BTreeSet::new();
    let mut requests = Vec::new();
    apply_global_guards(input, &mut triggered, &mut reasons, &mut requests);

    let server = if identity_matches.is_empty() {
        triggered.insert(SccmCorrelationGuard::ConflictingExactKey);
        reasons.insert(SccmCorrelationReason::ExactKeyConflict);
        if input
            .server_facts
            .iter()
            .any(|item| item.utc_millis == client.utc_millis && item.utc_millis.is_some())
        {
            triggered.insert(SccmCorrelationGuard::SameTimeNoKey);
            reasons.insert(SccmCorrelationReason::SameTimeWithoutExactKey);
        }
        if input.server_facts.iter().any(|item| item.terminal_failure) {
            triggered.insert(SccmCorrelationGuard::UnrelatedTerminalError);
            reasons.insert(SccmCorrelationReason::UnrelatedServerTerminal);
        }
        None
    } else if topology_matches.is_empty() {
        triggered.insert(SccmCorrelationGuard::IncompatibleTopology);
        reasons.insert(SccmCorrelationReason::TopologyMismatch);
        None
    } else if topology_matches.len() != 1 {
        triggered.insert(SccmCorrelationGuard::ConflictingExactKey);
        reasons.insert(SccmCorrelationReason::ExactKeyConflict);
        None
    } else {
        topology_matches.first().copied()
    };

    if let Some(server) = server {
        if !client.ordering_usable || !server.ordering_usable {
            triggered.insert(SccmCorrelationGuard::InvalidTimestampOffset);
            reasons.insert(SccmCorrelationReason::OrderingUnavailable);
        } else if server.utc_millis < client.utc_millis {
            reasons.insert(SccmCorrelationReason::OrderingNotCausal);
        }
        if !server.terminal_failure {
            reasons.insert(SccmCorrelationReason::TerminalRelationMissing);
        }
    }

    let profile_gap = triggered.contains(&SccmCorrelationGuard::UnknownExtractionProfile);
    let incompatible = triggered.contains(&SccmCorrelationGuard::VersionMismatch)
        || triggered.contains(&SccmCorrelationGuard::ConflictingExactKey)
        || triggered.contains(&SccmCorrelationGuard::IncompatibleTopology);
    let coverage_gap = triggered.contains(&SccmCorrelationGuard::PartialCapture)
        || triggered.contains(&SccmCorrelationGuard::RotationSplit);
    let exact = server.is_some() && reasons.is_empty();
    let same_time = triggered.contains(&SccmCorrelationGuard::SameTimeNoKey);
    let (outcome, strength, confidence) = if exact {
        (
            SccmCorrelationOutcome::CausalFinding,
            SccmCorrelationLinkStrength::ExactCorroborated,
            SccmCorrelationConfidence::High,
        )
    } else if profile_gap {
        (
            SccmCorrelationOutcome::ProfileGap,
            SccmCorrelationLinkStrength::Candidate,
            SccmCorrelationConfidence::Low,
        )
    } else if same_time {
        (
            SccmCorrelationOutcome::CandidateOnly,
            SccmCorrelationLinkStrength::Candidate,
            SccmCorrelationConfidence::Low,
        )
    } else if incompatible {
        (
            SccmCorrelationOutcome::Incompatible,
            SccmCorrelationLinkStrength::Incompatible,
            SccmCorrelationConfidence::Low,
        )
    } else if coverage_gap {
        (
            SccmCorrelationOutcome::CoverageGap,
            SccmCorrelationLinkStrength::ExactPartial,
            SccmCorrelationConfidence::Low,
        )
    } else {
        (
            SccmCorrelationOutcome::NotCausal,
            if server.is_some() {
                SccmCorrelationLinkStrength::ExactPartial
            } else {
                SccmCorrelationLinkStrength::Unlinked
            },
            SccmCorrelationConfidence::Medium,
        )
    };
    build_result(
        input.pair,
        outcome,
        strength,
        confidence,
        triggered,
        reasons,
        Some(client.handle(SccmCorrelationSide::Client, input.pair)),
        server.map(|fact| fact.handle(SccmCorrelationSide::Server, input.pair)),
        requests,
    )
}

fn apply_global_guards(
    input: &CanonicalInput,
    triggered: &mut BTreeSet<SccmCorrelationGuard>,
    reasons: &mut BTreeSet<SccmCorrelationReason>,
    requests: &mut Vec<SccmCorrelationArtifactRequest>,
) {
    for authority in [input.client_profile, input.server_profile] {
        match authority {
            ProfileAuthority::Validated => {}
            ProfileAuthority::Unknown => {
                triggered.insert(SccmCorrelationGuard::UnknownExtractionProfile);
                reasons.insert(SccmCorrelationReason::ProfileUnvalidated);
            }
            ProfileAuthority::VersionMismatch => {
                triggered.insert(SccmCorrelationGuard::VersionMismatch);
                reasons.insert(SccmCorrelationReason::ProfileVersionMismatch);
            }
        }
    }
    if !input.client_coverage_complete || !input.server_coverage_complete || input.input_capped {
        triggered.insert(SccmCorrelationGuard::PartialCapture);
        reasons.insert(SccmCorrelationReason::PartialSourceCoverage);
        if input.input_capped {
            reasons.insert(SccmCorrelationReason::InputCapExceeded);
        }
        if !input.client_coverage_complete {
            requests.push(SccmCorrelationArtifactRequest {
                side: SccmCorrelationSide::Client,
                logical_artifact_id: input.pair.client_request().to_owned(),
                reason_code: SccmCorrelationReason::PartialSourceCoverage,
            });
        }
        if !input.server_coverage_complete {
            requests.push(SccmCorrelationArtifactRequest {
                side: SccmCorrelationSide::Server,
                logical_artifact_id: input.pair.server_request().to_owned(),
                reason_code: SccmCorrelationReason::PartialSourceCoverage,
            });
        }
    }
    if !input.client_rotation_complete || !input.server_rotation_complete {
        triggered.insert(SccmCorrelationGuard::RotationSplit);
        reasons.insert(SccmCorrelationReason::RotationIncomplete);
        if !input.client_rotation_complete {
            requests.push(SccmCorrelationArtifactRequest {
                side: SccmCorrelationSide::Client,
                logical_artifact_id: input.pair.client_request().to_owned(),
                reason_code: SccmCorrelationReason::RotationIncomplete,
            });
        }
        if !input.server_rotation_complete {
            requests.push(SccmCorrelationArtifactRequest {
                side: SccmCorrelationSide::Server,
                logical_artifact_id: input.pair.server_request().to_owned(),
                reason_code: SccmCorrelationReason::RotationIncomplete,
            });
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn build_result(
    pair: SccmCorrelationPair,
    outcome: SccmCorrelationOutcome,
    link_strength: SccmCorrelationLinkStrength,
    confidence: SccmCorrelationConfidence,
    triggered: BTreeSet<SccmCorrelationGuard>,
    reasons: BTreeSet<SccmCorrelationReason>,
    client_fact_handle: Option<String>,
    server_fact_handle: Option<String>,
    mut artifact_requests: Vec<SccmCorrelationArtifactRequest>,
) -> SccmCorrelationResult {
    artifact_requests.sort();
    artifact_requests.dedup();
    let guard_checks = ALL_GUARDS
        .into_iter()
        .map(|guard_id| SccmCorrelationGuardCheck {
            guard_id,
            state: if triggered.contains(&guard_id) {
                SccmCorrelationGuardState::Triggered
            } else {
                SccmCorrelationGuardState::Passed
            },
        })
        .collect::<Vec<_>>();
    let reason_codes = reasons.into_iter().collect::<Vec<_>>();
    let result_preimage = format!(
        "{}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}",
        pair.stable_name(),
        outcome,
        link_strength,
        confidence,
        reason_codes,
        client_fact_handle,
        server_fact_handle
    );
    SccmCorrelationResult {
        result_id: format!("corr:sha256:{}", sha256_hex(result_preimage.as_bytes())),
        outcome,
        link_strength,
        confidence,
        guard_checks,
        reason_codes,
        client_fact_handle,
        server_fact_handle,
        artifact_requests,
    }
}

fn unique_exact_site_code(keys: &[super::SccmCorrelationKey]) -> Option<String> {
    let values = keys
        .iter()
        .filter(|key| {
            key.kind == SccmCorrelationKeyKind::SiteCode
                && key.confidence == SccmKeyConfidence::Exact
        })
        .map(|key| key.normalized.clone())
        .collect::<BTreeSet<_>>();
    (values.len() == 1)
        .then(|| values.into_iter().next())
        .flatten()
}

fn profile_authority<'a>(
    profiles: impl Iterator<Item = &'a str>,
    expected: &str,
) -> ProfileAuthority {
    let profiles = profiles.collect::<BTreeSet<_>>();
    if profiles.is_empty() {
        ProfileAuthority::Unknown
    } else if profiles.len() == 1 && profiles.contains(expected) {
        ProfileAuthority::Validated
    } else {
        ProfileAuthority::VersionMismatch
    }
}

fn terminal_or_latest_dp_observation(
    transaction: &super::server::windows::SccmDistributionPointContentTransaction,
) -> Option<&super::server::windows::SccmDistributionPointContentObservation> {
    transaction
        .observations
        .iter()
        .filter(|observation| observation.terminal)
        .max_by_key(|observation| observation.timestamp.utc_millis)
        .or_else(|| {
            transaction
                .observations
                .iter()
                .max_by_key(|observation| observation.timestamp.utc_millis)
        })
}

fn terminal_or_latest_sup_observation(
    transaction: &super::server::windows::SccmSoftwareUpdatePointTransaction,
) -> Option<&super::server::windows::SccmSoftwareUpdatePointObservation> {
    transaction
        .observations
        .iter()
        .rfind(|observation| observation.terminal)
        .or_else(|| transaction.observations.last())
}

fn parse_rfc3339_millis(value: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|timestamp| timestamp.timestamp_millis())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
#[path = "correlation_tests.rs"]
mod tests;
