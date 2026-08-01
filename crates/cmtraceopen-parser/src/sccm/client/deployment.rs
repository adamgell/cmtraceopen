//! Issue #322: application, package, and content deployment transactions.
//!
//! The reducer is pure. It turns a normalized client bundle into conservative
//! transactions whose every claim cites complete logical records. It never
//! reads the file system, never contacts a server, and never states a
//! distribution-point or site-server cause: the only cross-side output is a
//! counterpart-ready client content request that issue #333 may later match.
//!
//! Deployment state chain:
//!
//! ```text
//! Intent -> Requirements -> LocateContent -> Transfer -> Cache -> Enforce -> Detect -> Report
//! ```

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::models::log_entry::Severity;
use crate::sccm::{
    classify_artifact_name, SccmArtifact, SccmArtifactRequest, SccmConfidence, SccmCoverageState,
    SccmEvidence, SccmEvidenceRef, SccmFinding, SccmFindingBuilder, SccmFindingClass,
    SccmFindingCoverageGap, SccmPhase, SccmRecordCompleteness, SccmRole, SccmRotation,
    SccmTerminalEvidence, SccmTimeOrderingState,
};

use super::SccmNormalizedBundle;

pub const SCCM_DEPLOYMENT_ANALYSIS_SCHEMA_VERSION: u32 = 1;
pub const SCCM_DEPLOYMENT_TEST_PROFILE_ID: &str = "deployment-client-5.00.test-v1";
pub const SCCM_DEPLOYMENT_TEST_VERSION_PREFIX: &str = "5.00.TEST.";

const GROUP_APP_INTENT: &str = "client-app-intent";
const GROUP_APP_ENFORCE: &str = "client-app-enforce";
const GROUP_CONTENT: &str = "client-content";
const GROUP_POLICY_STATE: &str = "client-policy-state";

const REASON_LOCATION_RESPONSE_MISSING: &str =
    "capture a complete terminal location response; a client request alone cannot prove DP content state";
const REASON_LOCATION_ACCESS_DENIED: &str =
    "access denied is a coverage state, not proof of content success or failure";
const REASON_LOCATION_ROTATION: &str =
    "capture a complete logical CCM content record without joining physical rotation fragments";
const REASON_LOCATION_ABSENT: &str =
    "Capture an exact client content-location response for this assignment and CI.";
const REASON_INTENT: &str =
    "capture the complete client application intent record for this assignment and CI";
const REASON_REQUIREMENTS: &str =
    "capture the complete client requirement and dependency outcome for this assignment and CI";
const REASON_TRANSFER: &str = "capture the complete client content transfer outcome for this key";
const REASON_CACHE: &str = "capture the complete client cache commit outcome for this key";
const REASON_ENFORCE: &str = "capture the complete client enforcement outcome for this key";
const REASON_DETECT: &str = "capture the complete client detection outcome for this key";
const REASON_REPORT: &str = "capture the complete client deployment state report for this key";
const REASON_CHRONOLOGY: &str =
    "capture records whose timestamps can be ordered against the earlier phases of this key";

const COUNTERPART_READY_KEY_KINDS: [&str; 5] = [
    "contentId",
    "contentVersion",
    "distributionPointHostHandle",
    "packageId",
    "requestId",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmDeploymentWorkflow {
    Deployment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmDeploymentPhase {
    Intent,
    Requirements,
    LocateContent,
    Transfer,
    Cache,
    Enforce,
    Detect,
    Report,
}

impl SccmDeploymentPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Intent => "intent",
            Self::Requirements => "requirements",
            Self::LocateContent => "locateContent",
            Self::Transfer => "transfer",
            Self::Cache => "cache",
            Self::Enforce => "enforce",
            Self::Detect => "detect",
            Self::Report => "report",
        }
    }

    fn artifact_group(self) -> &'static str {
        match self {
            Self::Intent | Self::Requirements | Self::Detect => GROUP_APP_INTENT,
            Self::LocateContent | Self::Transfer | Self::Cache => GROUP_CONTENT,
            Self::Enforce => GROUP_APP_ENFORCE,
            Self::Report => GROUP_POLICY_STATE,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmDeploymentState {
    NotTargeted,
    InsufficientEvidence,
    Failed,
    DetectionMismatch,
    Succeeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmDeploymentClassification {
    NotTargeted,
    InsufficientEvidence,
    Symptom,
    ConfirmedFailure,
    Success,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmDeploymentConfidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmDeploymentKeyProfileKind {
    AssignmentCi,
    AssignmentCiContentTopology,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmDeploymentKeyConfidence {
    Candidate,
    Exact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmDeploymentTimestampProvenanceKind {
    ExplicitOffset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmDeploymentCounterpartFactKind {
    ClientContentRequest,
}

/// Exact, version-profiled identity of one deployment transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmDeploymentKey {
    pub key_profile_kind: SccmDeploymentKeyProfileKind,
    pub assignment_id: String,
    pub ci_id: String,
    pub package_id: Option<String>,
    pub content_id: Option<String>,
    pub content_version: Option<u32>,
    pub distribution_point_host_handle: Option<String>,
    pub request_id: Option<String>,
    pub bits_job_id: Option<String>,
    pub product_code: Option<String>,
    pub exit_code: Option<String>,
    pub confidence: SccmDeploymentKeyConfidence,
    pub extraction_profile_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmDeploymentTimestampProvenance {
    pub kind: SccmDeploymentTimestampProvenanceKind,
    pub offset_minutes: i32,
    pub normalized_utc: String,
}

/// The only issue #333 handoff this reducer produces.
///
/// It restates an exact client-side content request. It is not a distribution
/// point observation and carries no claim about a server outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmDeploymentCounterpartFact {
    pub fact_kind: SccmDeploymentCounterpartFactKind,
    pub phase: SccmDeploymentPhase,
    pub extraction_profile_id: String,
    pub package_id: String,
    pub content_id: String,
    pub content_version: u32,
    pub distribution_point_host_handle: String,
    pub request_id: String,
    pub timestamp_provenance: SccmDeploymentTimestampProvenance,
    pub evidence: SccmEvidenceRef,
}

/// The smallest next evidence bundle, named by deployment artifact group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmDeploymentArtifactRequest {
    pub logical_artifact_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmDeploymentTransaction {
    pub transaction_id: String,
    pub key: SccmDeploymentKey,
    pub counterpart_ready_fact: Option<SccmDeploymentCounterpartFact>,
    pub phase: SccmDeploymentPhase,
    pub state: SccmDeploymentState,
    pub last_successful_phase: Option<SccmDeploymentPhase>,
    pub classification: SccmDeploymentClassification,
    pub confidence: SccmDeploymentConfidence,
    pub confidence_ceiling: SccmDeploymentConfidence,
    pub coverage_gap_artifact_ids: Vec<String>,
    pub next_artifact: Option<SccmDeploymentArtifactRequest>,
    pub evidence: Vec<SccmEvidenceRef>,
}

/// Coverage of one deployment artifact group. Absence is a state, never proof.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmDeploymentCoverage {
    pub logical_artifact_id: String,
    pub state: SccmCoverageState,
    pub artifact_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmDeploymentExtractionProfile {
    pub profile_id: String,
    pub source_version_prefix: String,
    pub content_version_required: bool,
    pub key_kinds: Vec<String>,
    pub validated_artifact_families: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmDeploymentCorrelationHandoff {
    pub issue: String,
    pub performed: bool,
    pub time_only_eligible: bool,
    pub topology_compatibility_evaluated: bool,
    pub server_cause_claimed: bool,
    pub counterpart_ready_key_kinds: Vec<String>,
    pub emitted_counterpart_ready_fact: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmDeploymentObservationKeyConfidence {
    None,
    Candidate,
}

/// Bytes that were seen but can never become a fact.
///
/// A fragment, a capped tail, or an unvalidated supplemental installer line
/// stays here: it is capped at Low confidence and is never correlation
/// eligible, so it can neither override nor join a keyed transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmDeploymentObservation {
    pub observation_id: String,
    pub artifact_id: String,
    pub complete_logical_record: bool,
    pub key_confidence: SccmDeploymentObservationKeyConfidence,
    pub confidence_ceiling: SccmDeploymentConfidence,
    pub correlation_eligible: bool,
    pub reason: String,
    pub evidence: SccmEvidenceRef,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmDeploymentFinding {
    #[serde(flatten)]
    pub finding: SccmFinding,
    pub deployment_phase: SccmDeploymentPhase,
    pub last_successful_phase: Option<SccmDeploymentPhase>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmDeploymentAnalysis {
    pub schema_version: u32,
    pub workflow: SccmDeploymentWorkflow,
    pub extraction_profile: SccmDeploymentExtractionProfile,
    pub coverage: Vec<SccmDeploymentCoverage>,
    pub transactions: Vec<SccmDeploymentTransaction>,
    pub source_local_observations: Vec<SccmDeploymentObservation>,
    pub findings: Vec<SccmDeploymentFinding>,
    pub coverage_gaps: Vec<SccmFindingCoverageGap>,
    pub artifact_requests: Vec<SccmArtifactRequest>,
    pub correlation_handoff: SccmDeploymentCorrelationHandoff,
}

/// Reduce a normalized client bundle into deployment transactions.
pub fn analyze_client_deployment(bundle: &SccmNormalizedBundle) -> SccmDeploymentAnalysis {
    let coverage = coverage_rows(bundle);

    if bundle_identity_collides(bundle) {
        return finalize(coverage, Vec::new(), Vec::new(), Vec::new(), Vec::new());
    }

    // Only client-role artifacts may participate. Building this map from the
    // full artifact list would let another role's identical artifact ID decide
    // which source a record came from.
    let artifacts_by_id = bundle
        .artifacts
        .iter()
        .filter(|artifact| artifact.role == SccmRole::Client)
        .map(|artifact| (artifact.artifact_id.as_str(), artifact))
        .collect::<BTreeMap<_, _>>();

    let mut facts = bundle
        .evidence
        .iter()
        .filter(|evidence| evidence.role == SccmRole::Client)
        .flat_map(|evidence| {
            artifacts_by_id
                .get(evidence.reference.artifact_id.as_str())
                .map(|artifact| parse_deployment_facts(evidence, artifact))
                .unwrap_or_default()
        })
        .collect::<Vec<_>>();
    facts.sort_by(|left, right| compare_references(&left.reference, &right.reference));

    let mut by_assignment = BTreeMap::<&str, Vec<&DeploymentFact>>::new();
    for fact in &facts {
        by_assignment
            .entry(fact.assignment_id.as_str())
            .or_default()
            .push(fact);
    }

    let mut transactions = Vec::new();
    let mut seeds = Vec::new();
    for (assignment_id, assignment_facts) in by_assignment {
        let Some((transaction, seed)) =
            build_transaction(assignment_id, &assignment_facts, &coverage)
        else {
            continue;
        };
        transactions.push(transaction);
        if let Some(seed) = seed {
            seeds.push(seed);
        }
    }

    let admitted_artifact_ids = facts
        .iter()
        .map(|fact| fact.reference.artifact_id.as_str())
        .collect::<BTreeSet<_>>();
    // A family counts as validated only where the profile actually read a
    // record. Captured bytes it could not read prove collection, not coverage
    // of the workflow.
    let validated_artifact_families = admitted_artifact_ids
        .iter()
        .filter_map(|artifact_id| artifacts_by_id.get(artifact_id))
        .map(|artifact| deployment_group_id(&artifact.display_name))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let observations = source_local_observations(bundle, &artifacts_by_id, &admitted_artifact_ids);
    let findings = build_findings(&seeds, &artifacts_by_id);

    finalize(
        coverage,
        transactions,
        observations,
        findings,
        validated_artifact_families,
    )
}

fn finalize(
    coverage: Vec<SccmDeploymentCoverage>,
    transactions: Vec<SccmDeploymentTransaction>,
    source_local_observations: Vec<SccmDeploymentObservation>,
    findings: Vec<SccmDeploymentFinding>,
    validated_artifact_families: Vec<String>,
) -> SccmDeploymentAnalysis {
    let emitted_counterpart_ready_fact = transactions
        .iter()
        .any(|transaction| transaction.counterpart_ready_fact.is_some());

    let mut coverage_gaps = findings
        .iter()
        .flat_map(|finding| finding.finding.coverage_gaps.iter().cloned())
        .collect::<Vec<_>>();
    coverage_gaps.sort_by(|left, right| {
        left.artifact_id
            .cmp(&right.artifact_id)
            .then_with(|| coverage_order(&left.coverage).cmp(&coverage_order(&right.coverage)))
    });
    coverage_gaps.dedup();

    let mut artifact_requests = findings
        .iter()
        .flat_map(|finding| finding.finding.next_artifacts.iter().cloned())
        .collect::<Vec<_>>();
    artifact_requests.sort_by(|left, right| {
        left.logical_id
            .cmp(&right.logical_id)
            .then_with(|| left.reason.cmp(&right.reason))
    });
    artifact_requests.dedup();

    SccmDeploymentAnalysis {
        schema_version: SCCM_DEPLOYMENT_ANALYSIS_SCHEMA_VERSION,
        workflow: SccmDeploymentWorkflow::Deployment,
        extraction_profile: extraction_profile(validated_artifact_families, &transactions),
        coverage,
        transactions,
        source_local_observations,
        findings,
        coverage_gaps,
        artifact_requests,
        correlation_handoff: SccmDeploymentCorrelationHandoff {
            issue: "#333".to_owned(),
            performed: false,
            time_only_eligible: false,
            topology_compatibility_evaluated: false,
            server_cause_claimed: false,
            counterpart_ready_key_kinds: COUNTERPART_READY_KEY_KINDS
                .iter()
                .map(|kind| (*kind).to_owned())
                .collect(),
            emitted_counterpart_ready_fact,
        },
    }
}

fn extraction_profile(
    validated_artifact_families: Vec<String>,
    transactions: &[SccmDeploymentTransaction],
) -> SccmDeploymentExtractionProfile {
    let mut key_kinds = BTreeSet::new();
    for transaction in transactions {
        key_kinds.insert("assignmentId");
        key_kinds.insert("ciId");
        for (kind, present) in [
            ("packageId", transaction.key.package_id.is_some()),
            ("contentId", transaction.key.content_id.is_some()),
            ("contentVersion", transaction.key.content_version.is_some()),
            (
                "distributionPointHostHandle",
                transaction.key.distribution_point_host_handle.is_some(),
            ),
            ("requestId", transaction.key.request_id.is_some()),
            ("bitsJobId", transaction.key.bits_job_id.is_some()),
            ("productCode", transaction.key.product_code.is_some()),
            ("exitCode", transaction.key.exit_code.is_some()),
        ] {
            if present {
                key_kinds.insert(kind);
            }
        }
    }

    SccmDeploymentExtractionProfile {
        profile_id: SCCM_DEPLOYMENT_TEST_PROFILE_ID.to_owned(),
        source_version_prefix: SCCM_DEPLOYMENT_TEST_VERSION_PREFIX.to_owned(),
        content_version_required: true,
        key_kinds: key_kinds.into_iter().map(str::to_owned).collect(),
        validated_artifact_families,
    }
}

// ---------------------------------------------------------------------------
// Identity guards
// ---------------------------------------------------------------------------

/// Duplicate artifact or evidence identities make source authority ambiguous.
/// The reducer then reports coverage only: vector order must never elect one.
fn bundle_identity_collides(bundle: &SccmNormalizedBundle) -> bool {
    let mut artifact_ids = BTreeSet::new();
    for artifact in bundle
        .artifacts
        .iter()
        .filter(|artifact| artifact.role == SccmRole::Client)
    {
        if !artifact_ids.insert(artifact.artifact_id.as_str()) {
            return true;
        }
    }

    let mut evidence_ids = BTreeSet::new();
    let mut references = BTreeSet::new();
    for evidence in bundle
        .evidence
        .iter()
        .filter(|evidence| evidence.role == SccmRole::Client)
    {
        if !evidence_ids.insert(evidence.evidence_id.as_str()) {
            return true;
        }
        if !references.insert((
            evidence.reference.artifact_id.as_str(),
            evidence.reference.entry_id.as_str(),
            evidence.reference.line_start,
            evidence.reference.line_end,
        )) {
            return true;
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Coverage
// ---------------------------------------------------------------------------

fn coverage_rows(bundle: &SccmNormalizedBundle) -> Vec<SccmDeploymentCoverage> {
    let mut grouped = BTreeMap::<String, Vec<&SccmArtifact>>::new();
    for artifact in bundle
        .artifacts
        .iter()
        .filter(|artifact| artifact.role == SccmRole::Client)
    {
        grouped
            .entry(deployment_group_id(&artifact.display_name))
            .or_default()
            .push(artifact);
    }

    grouped
        .into_iter()
        .map(|(logical_artifact_id, artifacts)| {
            let states = artifacts
                .iter()
                .map(|artifact| artifact.coverage.clone())
                .collect::<Vec<_>>();
            let mut artifact_ids = artifacts
                .iter()
                .filter(|artifact| artifact.coverage != SccmCoverageState::Captured)
                .map(|artifact| artifact.artifact_id.clone())
                .collect::<Vec<_>>();
            artifact_ids.sort();
            artifact_ids.dedup();

            SccmDeploymentCoverage {
                logical_artifact_id,
                state: combine_coverage(&states),
                artifact_ids,
            }
        })
        .collect()
}

/// Any complete capture makes the group usable; otherwise the most explanatory
/// incomplete state wins. Conflicting noncapture states stay `ParseFailed` so
/// no caller can read a single cause out of a mixed group.
fn combine_coverage(states: &[SccmCoverageState]) -> SccmCoverageState {
    for candidate in [
        SccmCoverageState::Captured,
        SccmCoverageState::Capped,
        SccmCoverageState::Partial,
    ] {
        if states.contains(&candidate) {
            return candidate;
        }
    }

    let distinct = states
        .iter()
        .map(coverage_order)
        .collect::<BTreeSet<_>>()
        .len();
    match (distinct, states.first()) {
        (1, Some(state)) => state.clone(),
        _ => SccmCoverageState::ParseFailed,
    }
}

fn coverage_order(coverage: &SccmCoverageState) -> u8 {
    match coverage {
        SccmCoverageState::Captured => 0,
        SccmCoverageState::Partial => 1,
        SccmCoverageState::Absent => 2,
        SccmCoverageState::AccessDenied => 3,
        SccmCoverageState::Capped => 4,
        SccmCoverageState::Skipped => 5,
        SccmCoverageState::Unsupported => 6,
        SccmCoverageState::ParseFailed => 7,
    }
}

fn coverage_for_group<'a>(
    coverage: &'a [SccmDeploymentCoverage],
    group: &str,
) -> Option<&'a SccmDeploymentCoverage> {
    coverage.iter().find(|row| row.logical_artifact_id == group)
}

// ---------------------------------------------------------------------------
// Source classification
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeploymentSourceKind {
    Intent,
    Discovery,
    Enforce,
    ContentAccess,
    Transfer,
    StateReport,
}

#[derive(Debug, Clone, Copy)]
struct DeploymentSource {
    group: &'static str,
    kind: DeploymentSourceKind,
}

/// Exact logical-name table. An unlisted source is never a deployment fact
/// source, no matter how similar its text looks.
fn deployment_source(logical_name: &str) -> Option<DeploymentSource> {
    let (group, kind) = match logical_name {
        "appIntentEval" => (GROUP_APP_INTENT, DeploymentSourceKind::Intent),
        "appDiscovery" => (GROUP_APP_INTENT, DeploymentSourceKind::Discovery),
        "appEnforce" => (GROUP_APP_ENFORCE, DeploymentSourceKind::Enforce),
        "cas" => (GROUP_CONTENT, DeploymentSourceKind::ContentAccess),
        "dataTransferService" | "contentTransferManager" => {
            (GROUP_CONTENT, DeploymentSourceKind::Transfer)
        }
        "stateMessage" => (GROUP_POLICY_STATE, DeploymentSourceKind::StateReport),
        _ => return None,
    };
    Some(DeploymentSource { group, kind })
}

fn deployment_group_id(display_name: &str) -> String {
    let catalog = classify_artifact_name(display_name, SccmRole::Client);
    match deployment_source(&catalog.logical_name) {
        Some(source) => source.group.to_owned(),
        None => format!("client-{}", kebab_case(&catalog.logical_name)),
    }
}

fn kebab_case(value: &str) -> String {
    let mut result = String::with_capacity(value.len() + 4);
    for character in value.chars() {
        if character.is_ascii_uppercase() {
            if !result.is_empty() {
                result.push('-');
            }
            result.push(character.to_ascii_lowercase());
        } else {
            result.push(character);
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Facts
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeploymentFactKind {
    IntentTargeted,
    IntentNotApplicable,
    RequirementsSatisfied,
    RequirementsFailed,
    DependencyFailed,
    ContentLocated,
    ContentRequested,
    TransferStarted,
    TransferCompleted,
    TransferFailed,
    CacheCommitted,
    CacheFailed,
    EnforceSucceeded,
    EnforceFailed,
    Detected,
    DetectionMismatch,
    ReportSucceeded,
    ReportFailed,
}

#[derive(Debug, Clone)]
struct DeploymentFact {
    kind: DeploymentFactKind,
    reference: SccmEvidenceRef,
    utc_millis: Option<i64>,
    offset_minutes: Option<i32>,
    time_comparable: bool,
    assignment_id: String,
    ci_id: Option<String>,
    package_id: Option<String>,
    content_id: Option<String>,
    content_version: Option<u32>,
    distribution_point_host_handle: Option<String>,
    request_id: Option<String>,
    bits_job_id: Option<String>,
    product_code: Option<String>,
    exit_code: Option<String>,
}

fn parse_deployment_facts(evidence: &SccmEvidence, artifact: &SccmArtifact) -> Vec<DeploymentFact> {
    let Some(source) = admitted_source(evidence, artifact) else {
        return Vec::new();
    };
    let Some(payload) = deployment_event_payload(&evidence.message) else {
        return Vec::new();
    };
    let phrase = event_phrase(payload);
    let Some(assignment_id) =
        field_value(payload, "assignmentId").filter(|value| valid_guid(value))
    else {
        return Vec::new();
    };

    let kinds = match source.kind {
        DeploymentSourceKind::Intent => intent_fact_kinds(&phrase, payload),
        DeploymentSourceKind::Discovery => discovery_fact_kinds(&phrase, payload),
        DeploymentSourceKind::Enforce => enforce_fact_kinds(&phrase, payload),
        DeploymentSourceKind::ContentAccess => content_fact_kinds(&phrase, payload),
        DeploymentSourceKind::Transfer => transfer_fact_kinds(&phrase, payload),
        DeploymentSourceKind::StateReport => report_fact_kinds(&phrase, payload),
    };
    if kinds.is_empty() {
        return Vec::new();
    }

    let template = DeploymentFact {
        kind: DeploymentFactKind::IntentTargeted,
        reference: evidence.reference.clone(),
        utc_millis: evidence.timestamp.utc_millis,
        offset_minutes: evidence.timestamp.offset_minutes,
        time_comparable: evidence.timestamp.ordering_state == SccmTimeOrderingState::NormalizedUtc
            && evidence.timestamp.utc_millis.is_some(),
        assignment_id: assignment_id.to_owned(),
        ci_id: field_value(payload, "ciId")
            .filter(|value| valid_guid(value))
            .map(str::to_owned),
        package_id: field_value(payload, "packageId")
            .filter(|value| valid_package_id(value))
            .map(str::to_owned),
        content_id: field_value(payload, "contentId")
            .filter(|value| valid_guid(value))
            .map(str::to_owned),
        content_version: field_value(payload, "contentVersion").and_then(parse_content_version),
        distribution_point_host_handle: field_value(payload, "distributionPointHostHandle")
            .filter(|value| valid_safe_handle(value))
            .map(str::to_owned),
        request_id: field_value(payload, "requestId")
            .filter(|value| valid_guid(value))
            .map(str::to_owned),
        bits_job_id: field_value(payload, "bitsJobId")
            .filter(|value| valid_guid(value))
            .map(str::to_owned),
        product_code: field_value(payload, "productCode")
            .filter(|value| valid_guid(value))
            .map(str::to_owned),
        exit_code: field_value(payload, "exitCode")
            .filter(|value| valid_exit_code(value))
            .map(str::to_owned),
    };

    kinds
        .into_iter()
        .map(|kind| DeploymentFact {
            kind,
            ..template.clone()
        })
        .collect()
}

/// Record completeness, version profile, role, coverage, rotation, and catalog
/// identity must all agree before a record may become a fact.
///
/// Completeness is read from the record, never inferred from the artifact: a
/// fully collected file can still hold a physical line that no logical record
/// covers, and that line is not evidence of anything.
fn admitted_source(evidence: &SccmEvidence, artifact: &SccmArtifact) -> Option<DeploymentSource> {
    if evidence.completeness != SccmRecordCompleteness::LogicalRecord
        || artifact.role != SccmRole::Client
        || evidence.role != SccmRole::Client
        || artifact.coverage != SccmCoverageState::Captured
        || !valid_reference(&evidence.reference)
    {
        return None;
    }
    if !artifact
        .configmgr_version
        .as_deref()
        .is_some_and(|version| version.starts_with(SCCM_DEPLOYMENT_TEST_VERSION_PREFIX))
    {
        return None;
    }

    let catalog = classify_artifact_name(&artifact.display_name, SccmRole::Client);
    if !catalog.supported_for_diagnosis || artifact.rotation != catalog.rotation {
        return None;
    }
    deployment_source(&catalog.logical_name)
}

fn intent_fact_kinds(phrase: &str, payload: &str) -> Vec<DeploymentFactKind> {
    let mut kinds = Vec::new();
    let state = field_value(payload, "state");
    let terminal = is_terminal(payload);

    if matches!(phrase, "intent" | "targeted" | "requirements satisfied")
        && state == Some("targeted")
    {
        kinds.push(DeploymentFactKind::IntentTargeted);
    }
    if matches!(
        phrase,
        "explicitly not targeted" | "not targeted" | "not applicable"
    ) && state == Some("notApplicable")
        && terminal
    {
        kinds.push(DeploymentFactKind::IntentNotApplicable);
    }
    if phrase == "requirements satisfied" {
        kinds.push(DeploymentFactKind::RequirementsSatisfied);
    }
    if phrase == "requirements terminal failure"
        && terminal
        && field_value(payload, "requirementId").is_some_and(valid_safe_key)
    {
        kinds.push(DeploymentFactKind::RequirementsFailed);
    }
    if phrase == "dependency terminal failure"
        && terminal
        && field_value(payload, "dependencyCiId").is_some_and(valid_guid)
    {
        kinds.push(DeploymentFactKind::DependencyFailed);
    }
    kinds
}

fn discovery_fact_kinds(phrase: &str, payload: &str) -> Vec<DeploymentFactKind> {
    match (phrase, field_value(payload, "detected")) {
        ("detected", Some("true")) => vec![DeploymentFactKind::Detected],
        ("detection false negative", Some("false")) => vec![DeploymentFactKind::DetectionMismatch],
        _ => Vec::new(),
    }
}

/// A nonzero exit code alone stays a symptom. A confirmed enforcement failure
/// needs the terminal marker on the same complete record.
fn enforce_fact_kinds(phrase: &str, payload: &str) -> Vec<DeploymentFactKind> {
    let Some(exit_code) = field_value(payload, "exitCode").filter(|value| valid_exit_code(value))
    else {
        return Vec::new();
    };
    if !is_terminal(payload) {
        return Vec::new();
    }
    match phrase {
        "enforcement completed" if exit_code == "0" => vec![DeploymentFactKind::EnforceSucceeded],
        "enforcement terminal failure" if exit_code != "0" => {
            vec![DeploymentFactKind::EnforceFailed]
        }
        _ => Vec::new(),
    }
}

fn content_fact_kinds(phrase: &str, payload: &str) -> Vec<DeploymentFactKind> {
    let has_topology = field_value(payload, "packageId").is_some_and(valid_package_id)
        && field_value(payload, "contentId").is_some_and(valid_guid)
        && field_value(payload, "contentVersion")
            .and_then(parse_content_version)
            .is_some()
        && field_value(payload, "distributionPointHostHandle").is_some_and(valid_safe_handle)
        && field_value(payload, "requestId").is_some_and(valid_guid);

    match phrase {
        "content located" if has_topology => vec![DeploymentFactKind::ContentLocated],
        "content request observed"
            if has_topology && field_value(payload, "responseState") == Some("unknown") =>
        {
            vec![DeploymentFactKind::ContentRequested]
        }
        "cache commit completed"
            if field_value(payload, "contentId").is_some_and(valid_guid)
                && field_value(payload, "contentVersion")
                    .and_then(parse_content_version)
                    .is_some() =>
        {
            vec![DeploymentFactKind::CacheCommitted]
        }
        "cache commit terminal failure" if is_terminal(payload) && has_nonzero_error(payload) => {
            vec![DeploymentFactKind::CacheFailed]
        }
        _ => Vec::new(),
    }
}

fn transfer_fact_kinds(phrase: &str, payload: &str) -> Vec<DeploymentFactKind> {
    let content_id = field_value(payload, "contentId").is_some_and(valid_guid);
    let bits_job_id = field_value(payload, "bitsJobId").is_some_and(valid_guid);
    match phrase {
        "transfer started"
            if content_id
                && bits_job_id
                && field_value(payload, "requestId").is_some_and(valid_guid) =>
        {
            vec![DeploymentFactKind::TransferStarted]
        }
        "transfer completed" if content_id && bits_job_id => {
            vec![DeploymentFactKind::TransferCompleted]
        }
        "transfer terminal failure"
            if content_id && bits_job_id && is_terminal(payload) && has_nonzero_error(payload) =>
        {
            vec![DeploymentFactKind::TransferFailed]
        }
        _ => Vec::new(),
    }
}

fn report_fact_kinds(phrase: &str, payload: &str) -> Vec<DeploymentFactKind> {
    match (phrase, field_value(payload, "state")) {
        ("reported", Some("succeeded")) => vec![DeploymentFactKind::ReportSucceeded],
        ("reported", Some("failed")) => vec![DeploymentFactKind::ReportFailed],
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Message grammar
// ---------------------------------------------------------------------------

const PUBLIC_MESSAGE_PREFIX: &str = "[sccm-public-message-v1] ";
const EVENT_QUALIFIERS: [&str; 4] = ["SYNTHETIC", "FIXTURE", "deployment", "success"];

fn deployment_event_payload(message: &str) -> Option<&str> {
    message.strip_prefix(PUBLIC_MESSAGE_PREFIX)
}

/// The leading clause of a record, with documented capture and scope
/// qualifiers removed. Only a phrase that starts the clause selects an event,
/// so an embedded label such as `Base requirements satisfied` never matches
/// `requirements satisfied`.
fn event_phrase(payload: &str) -> String {
    payload
        .split_whitespace()
        .take_while(|word| !word.contains('='))
        .skip_while(|word| EVENT_QUALIFIERS.contains(word))
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

/// Exact-token lookup. A duplicated label, or a label that is only the tail of
/// a longer token, yields nothing rather than a guess.
///
/// Every occurrence is counted before any boundary rule is applied. Filtering
/// first would silently discard a punctuation-adjacent conflict such as
/// `terminal=true (terminal=false)` and let the first value win.
fn field_value<'a>(message: &'a str, key: &str) -> Option<&'a str> {
    let marker = format!("{key}=");
    let mut occurrences = message.match_indices(&marker);
    let (first, _) = occurrences.next()?;
    if occurrences.next().is_some() {
        return None;
    }
    if first != 0 && !message.as_bytes()[first - 1].is_ascii_whitespace() {
        return None;
    }

    let value_start = first + marker.len();
    let value = &message[value_start..];
    let value_end = value
        .find(|character: char| character.is_ascii_whitespace() || matches!(character, ',' | ';'))
        .unwrap_or(value.len());
    (!value[..value_end].is_empty()).then_some(&value[..value_end])
}

fn is_terminal(payload: &str) -> bool {
    field_value(payload, "terminal") == Some("true")
}

fn has_nonzero_error(payload: &str) -> bool {
    field_value(payload, "errorCode")
        .and_then(parse_hex_u32)
        .is_some_and(|value| value != 0)
}

fn parse_hex_u32(value: &str) -> Option<u32> {
    let hex = value.strip_prefix("0x")?;
    (hex.len() == 8 && hex.chars().all(|character| character.is_ascii_hexdigit()))
        .then(|| u32::from_str_radix(hex, 16).ok())
        .flatten()
}

fn parse_content_version(value: &str) -> Option<u32> {
    if value.len() > 1 && value.starts_with('0') {
        return None;
    }
    value
        .chars()
        .all(|character| character.is_ascii_digit())
        .then(|| value.parse::<u32>().ok())
        .flatten()
}

fn valid_exit_code(value: &str) -> bool {
    parse_content_version(value).is_some()
}

fn valid_guid(value: &str) -> bool {
    value.len() == 36
        && value.chars().enumerate().all(|(index, character)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                character == '-'
            } else {
                character.is_ascii_hexdigit()
            }
        })
}

fn valid_package_id(value: &str) -> bool {
    value.len() == 8
        && value
            .chars()
            .all(|character| character.is_ascii_uppercase() || character.is_ascii_digit())
}

/// Distribution point identities stay opaque handles. A raw host name is never
/// admitted, so no public output can carry a real server name.
fn valid_safe_handle(value: &str) -> bool {
    let Some(body) = value.strip_prefix("safe:") else {
        return false;
    };
    !body.is_empty()
        && body.len() <= 128
        && body.split(':').all(|segment| {
            !segment.is_empty()
                && !segment.starts_with('-')
                && !segment.ends_with('-')
                && segment.chars().all(|character| {
                    character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
                })
        })
}

fn valid_safe_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.chars().all(|character| {
            character.is_ascii_uppercase() || character.is_ascii_digit() || character == '-'
        })
}

fn valid_reference(reference: &SccmEvidenceRef) -> bool {
    valid_public_id(&reference.artifact_id)
        && valid_public_id(&reference.entry_id)
        && matches!(
            (reference.line_start, reference.line_end),
            (Some(start), Some(end)) if start > 0 && end >= start
        )
}

fn valid_public_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | ':')
        })
}

// ---------------------------------------------------------------------------
// Chronology
// ---------------------------------------------------------------------------

/// Records in one physical artifact order by line. Records in different
/// artifacts order only when both carry a valid offset. Anything else is
/// incomparable and must downgrade confidence, never assume a sequence.
fn compare_fact_order(left: &DeploymentFact, right: &DeploymentFact) -> Option<Ordering> {
    if left.reference.artifact_id == right.reference.artifact_id {
        return Some(
            left.reference
                .line_start
                .cmp(&right.reference.line_start)
                .then_with(|| left.reference.line_end.cmp(&right.reference.line_end)),
        );
    }
    if left.time_comparable && right.time_comparable {
        return Some(left.utc_millis.cmp(&right.utc_millis));
    }
    None
}

fn fact_is_strictly_before(earlier: &DeploymentFact, later: &DeploymentFact) -> bool {
    compare_fact_order(earlier, later) == Some(Ordering::Less)
}

fn chain_has_usable_order(facts: &[&DeploymentFact]) -> bool {
    facts
        .windows(2)
        .all(|pair| fact_is_strictly_before(pair[0], pair[1]))
}

fn compare_references(left: &SccmEvidenceRef, right: &SccmEvidenceRef) -> Ordering {
    left.artifact_id
        .cmp(&right.artifact_id)
        .then_with(|| left.line_start.cmp(&right.line_start))
        .then_with(|| left.line_end.cmp(&right.line_end))
        .then_with(|| left.entry_id.cmp(&right.entry_id))
}

// ---------------------------------------------------------------------------
// Transaction composition
// ---------------------------------------------------------------------------

struct Outcome {
    phase: SccmDeploymentPhase,
    state: SccmDeploymentState,
    classification: SccmDeploymentClassification,
    confidence: SccmDeploymentConfidence,
    last_successful_phase: Option<SccmDeploymentPhase>,
    next_artifact: Option<SccmDeploymentArtifactRequest>,
    coverage_gap_artifact_ids: Vec<String>,
    finding_id: Option<&'static str>,
    terminal_evidence: Vec<SccmEvidenceRef>,
}

/// One transaction's contribution to a bundle-level finding.
struct FindingSeed {
    finding_id: &'static str,
    class: SccmFindingClass,
    phase: SccmDeploymentPhase,
    confidence: SccmConfidence,
    last_successful_phase: Option<SccmDeploymentPhase>,
    evidence: Vec<SccmEvidenceRef>,
    terminal_evidence: Vec<SccmEvidenceRef>,
    coverage_gap_artifact_ids: Vec<String>,
    coverage_gap_group: Option<&'static str>,
    request_phase: Option<SccmDeploymentPhase>,
}

fn build_transaction(
    assignment_id: &str,
    facts: &[&DeploymentFact],
    coverage: &[SccmDeploymentCoverage],
) -> Option<(SccmDeploymentTransaction, Option<FindingSeed>)> {
    let ci_id = unique_value(facts.iter().filter_map(|fact| fact.ci_id.clone()))?;
    let key = build_key(assignment_id, &ci_id, facts);
    let outcome = resolve_outcome(facts, coverage);
    let evidence = merged_evidence(facts);

    let seed = outcome.finding_id.map(|finding_id| FindingSeed {
        finding_id,
        class: match outcome.classification {
            SccmDeploymentClassification::ConfirmedFailure => SccmFindingClass::ConfirmedFailure,
            SccmDeploymentClassification::Symptom => SccmFindingClass::Symptom,
            _ => SccmFindingClass::InsufficientEvidence,
        },
        phase: outcome.phase,
        confidence: match outcome.confidence {
            SccmDeploymentConfidence::High => SccmConfidence::High,
            SccmDeploymentConfidence::Medium => SccmConfidence::Moderate,
            SccmDeploymentConfidence::Low => SccmConfidence::Low,
        },
        last_successful_phase: outcome.last_successful_phase,
        evidence: if outcome.terminal_evidence.is_empty() {
            evidence.clone()
        } else {
            outcome.terminal_evidence.clone()
        },
        terminal_evidence: outcome.terminal_evidence.clone(),
        coverage_gap_artifact_ids: outcome.coverage_gap_artifact_ids.clone(),
        coverage_gap_group: (outcome.classification
            == SccmDeploymentClassification::InsufficientEvidence)
            .then(|| outcome.phase.artifact_group()),
        request_phase: outcome.next_artifact.as_ref().map(|_| outcome.phase),
    });

    Some((
        SccmDeploymentTransaction {
            transaction_id: format!("deployment:assignment:{assignment_id}"),
            counterpart_ready_fact: counterpart_ready_fact(facts, &key),
            key,
            phase: outcome.phase,
            state: outcome.state,
            last_successful_phase: outcome.last_successful_phase,
            classification: outcome.classification,
            confidence: outcome.confidence,
            confidence_ceiling: outcome.confidence,
            coverage_gap_artifact_ids: outcome.coverage_gap_artifact_ids,
            next_artifact: outcome.next_artifact,
            evidence,
        },
        seed,
    ))
}

/// Distinct values collapse to one key only when they agree. Two different
/// values are ambiguity, not a choice.
fn unique_value<T: Ord>(values: impl Iterator<Item = T>) -> Option<T> {
    let mut distinct = values.collect::<BTreeSet<_>>();
    (distinct.len() == 1)
        .then(|| distinct.pop_first())
        .flatten()
}

fn build_key(assignment_id: &str, ci_id: &str, facts: &[&DeploymentFact]) -> SccmDeploymentKey {
    let package_id = unique_value(facts.iter().filter_map(|fact| fact.package_id.clone()));
    let content_id = unique_value(facts.iter().filter_map(|fact| fact.content_id.clone()));
    let content_version = unique_value(facts.iter().filter_map(|fact| fact.content_version));
    let distribution_point_host_handle = unique_value(
        facts
            .iter()
            .filter_map(|fact| fact.distribution_point_host_handle.clone()),
    );
    let request_id = unique_value(facts.iter().filter_map(|fact| fact.request_id.clone()));
    let has_topology = package_id.is_some()
        && content_id.is_some()
        && content_version.is_some()
        && distribution_point_host_handle.is_some()
        && request_id.is_some();

    SccmDeploymentKey {
        key_profile_kind: if has_topology {
            SccmDeploymentKeyProfileKind::AssignmentCiContentTopology
        } else {
            SccmDeploymentKeyProfileKind::AssignmentCi
        },
        assignment_id: assignment_id.to_owned(),
        ci_id: ci_id.to_owned(),
        package_id,
        content_id,
        content_version,
        distribution_point_host_handle,
        request_id,
        bits_job_id: unique_value(facts.iter().filter_map(|fact| fact.bits_job_id.clone())),
        product_code: unique_value(facts.iter().filter_map(|fact| fact.product_code.clone())),
        exit_code: unique_value(
            facts
                .iter()
                .filter(|fact| {
                    matches!(
                        fact.kind,
                        DeploymentFactKind::EnforceSucceeded | DeploymentFactKind::EnforceFailed
                    )
                })
                .filter_map(|fact| fact.exit_code.clone()),
        ),
        confidence: SccmDeploymentKeyConfidence::Exact,
        extraction_profile_id: SCCM_DEPLOYMENT_TEST_PROFILE_ID.to_owned(),
    }
}

/// One reference per physical artifact, spanning the first through the last
/// cited record. Callers can reopen exactly the bytes that produced the claim.
fn merged_evidence(facts: &[&DeploymentFact]) -> Vec<SccmEvidenceRef> {
    let mut spans = BTreeMap::<&str, (u32, u32)>::new();
    for fact in facts {
        let (Some(start), Some(end)) = (fact.reference.line_start, fact.reference.line_end) else {
            continue;
        };
        spans
            .entry(fact.reference.artifact_id.as_str())
            .and_modify(|span| {
                span.0 = span.0.min(start);
                span.1 = span.1.max(end);
            })
            .or_insert((start, end));
    }

    spans
        .into_iter()
        .map(|(artifact_id, (start, end))| SccmEvidenceRef {
            artifact_id: artifact_id.to_owned(),
            entry_id: format!("{artifact_id}:{start}-{end}"),
            line_start: Some(start),
            line_end: Some(end),
        })
        .collect()
}

fn first_fact<'a>(
    facts: &[&'a DeploymentFact],
    kind: DeploymentFactKind,
) -> Option<&'a DeploymentFact> {
    facts.iter().copied().find(|fact| fact.kind == kind)
}

/// Every failure that no later success of the same phase can be ordered after.
///
/// All of them are returned. Two records that are equally terminal for one key
/// are both evidence; picking one would let sort order decide what the caller
/// is shown.
fn unrecovered_failures<'a>(
    facts: &[&'a DeploymentFact],
    failure_kind: DeploymentFactKind,
    success_kind: DeploymentFactKind,
) -> Vec<&'a DeploymentFact> {
    facts
        .iter()
        .copied()
        .filter(|fact| fact.kind == failure_kind)
        .filter(|failure| {
            !facts.iter().any(|candidate| {
                candidate.kind == success_kind && fact_is_strictly_before(failure, candidate)
            })
        })
        .collect()
}

fn facts_of_kind<'a>(
    facts: &[&'a DeploymentFact],
    kind: DeploymentFactKind,
) -> Vec<&'a DeploymentFact> {
    facts
        .iter()
        .copied()
        .filter(|fact| fact.kind == kind)
        .collect()
}

/// The one cross-side output, and the only place a client key value leaves this
/// reducer. It republishes the transaction key that already survived the
/// ambiguity guard, and only when exactly one complete content record carries
/// it. Two differently keyed content records are a conflict, not a choice
/// between them, so nothing is published.
fn counterpart_ready_fact(
    facts: &[&DeploymentFact],
    key: &SccmDeploymentKey,
) -> Option<SccmDeploymentCounterpartFact> {
    let candidates = facts
        .iter()
        .copied()
        .filter(|fact| {
            matches!(
                fact.kind,
                DeploymentFactKind::ContentLocated | DeploymentFactKind::ContentRequested
            )
        })
        .collect::<Vec<_>>();
    let [fact] = candidates.as_slice() else {
        return None;
    };

    let package_id = key.package_id.clone()?;
    let content_id = key.content_id.clone()?;
    let content_version = key.content_version?;
    let distribution_point_host_handle = key.distribution_point_host_handle.clone()?;
    let request_id = key.request_id.clone()?;
    if fact.package_id.as_deref() != Some(package_id.as_str())
        || fact.content_id.as_deref() != Some(content_id.as_str())
        || fact.content_version != Some(content_version)
        || fact.distribution_point_host_handle.as_deref()
            != Some(distribution_point_host_handle.as_str())
        || fact.request_id.as_deref() != Some(request_id.as_str())
    {
        return None;
    }

    let offset_minutes = fact.offset_minutes?;
    if !fact.time_comparable {
        return None;
    }

    Some(SccmDeploymentCounterpartFact {
        fact_kind: SccmDeploymentCounterpartFactKind::ClientContentRequest,
        phase: SccmDeploymentPhase::LocateContent,
        extraction_profile_id: SCCM_DEPLOYMENT_TEST_PROFILE_ID.to_owned(),
        package_id,
        content_id,
        content_version,
        distribution_point_host_handle,
        request_id,
        timestamp_provenance: SccmDeploymentTimestampProvenance {
            kind: SccmDeploymentTimestampProvenanceKind::ExplicitOffset,
            offset_minutes,
            normalized_utc: format_normalized_utc(fact.utc_millis?)?,
        },
        evidence: fact.reference.clone(),
    })
}

fn format_normalized_utc(millis: i64) -> Option<String> {
    let timestamp = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(millis)?;
    Some(if millis.rem_euclid(1_000) == 0 {
        timestamp.format("%Y-%m-%dT%H:%M:%SZ").to_string()
    } else {
        timestamp.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
    })
}

fn resolve_outcome(facts: &[&DeploymentFact], coverage: &[SccmDeploymentCoverage]) -> Outcome {
    let mut chain: Vec<&DeploymentFact> = Vec::new();
    let mut last: Option<SccmDeploymentPhase> = None;

    if let Some(not_applicable) = first_fact(facts, DeploymentFactKind::IntentNotApplicable) {
        return conclude(
            &[not_applicable],
            SccmDeploymentPhase::Intent,
            SccmDeploymentState::NotTargeted,
            SccmDeploymentClassification::NotTargeted,
            None,
            None,
            &[],
        );
    }

    let Some(intent) = first_fact(facts, DeploymentFactKind::IntentTargeted) else {
        return insufficient(SccmDeploymentPhase::Intent, last, REASON_INTENT, coverage);
    };
    chain.push(intent);
    last = Some(SccmDeploymentPhase::Intent);

    let requirement_failures = facts_of_kind(facts, DeploymentFactKind::RequirementsFailed);
    let dependency_failures = facts_of_kind(facts, DeploymentFactKind::DependencyFailed);
    if !requirement_failures.is_empty() || !dependency_failures.is_empty() {
        // A failed requirement gates the dependency check, so it names the
        // cause when both are present; the citations stay per cause.
        let (finding_id, terminals) = if requirement_failures.is_empty() {
            (FINDING_DEPENDENCY_TERMINAL, dependency_failures)
        } else {
            (FINDING_REQUIREMENTS_TERMINAL, requirement_failures)
        };
        return conclude(
            &chain,
            SccmDeploymentPhase::Requirements,
            SccmDeploymentState::Failed,
            SccmDeploymentClassification::ConfirmedFailure,
            last,
            Some(finding_id),
            &terminals,
        );
    }
    let Some(requirements) = first_fact(facts, DeploymentFactKind::RequirementsSatisfied) else {
        return insufficient(
            SccmDeploymentPhase::Requirements,
            last,
            REASON_REQUIREMENTS,
            coverage,
        );
    };
    chain.push(requirements);
    last = Some(SccmDeploymentPhase::Requirements);

    let Some(located) = first_fact(facts, DeploymentFactKind::ContentLocated) else {
        let reason = if first_fact(facts, DeploymentFactKind::ContentRequested).is_some() {
            REASON_LOCATION_RESPONSE_MISSING
        } else {
            match coverage_for_group(coverage, GROUP_CONTENT).map(|row| &row.state) {
                Some(SccmCoverageState::Partial) => REASON_LOCATION_ROTATION,
                Some(SccmCoverageState::AccessDenied) => REASON_LOCATION_ACCESS_DENIED,
                _ => REASON_LOCATION_ABSENT,
            }
        };
        return insufficient(SccmDeploymentPhase::LocateContent, last, reason, coverage);
    };
    chain.push(located);
    last = Some(SccmDeploymentPhase::LocateContent);

    let transfer_failures = unrecovered_failures(
        facts,
        DeploymentFactKind::TransferFailed,
        DeploymentFactKind::TransferCompleted,
    );
    if !transfer_failures.is_empty() {
        let mut failed_chain = chain.clone();
        failed_chain.extend(first_fact(facts, DeploymentFactKind::TransferStarted));
        return conclude(
            &failed_chain,
            SccmDeploymentPhase::Transfer,
            SccmDeploymentState::Failed,
            SccmDeploymentClassification::ConfirmedFailure,
            last,
            Some(FINDING_TRANSFER_TERMINAL),
            &transfer_failures,
        );
    }
    let started = first_fact(facts, DeploymentFactKind::TransferStarted);
    let completed = first_fact(facts, DeploymentFactKind::TransferCompleted);
    let (Some(started), Some(completed)) = (started, completed) else {
        return insufficient(
            SccmDeploymentPhase::Transfer,
            last,
            REASON_TRANSFER,
            coverage,
        );
    };
    chain.push(started);
    chain.push(completed);
    last = Some(SccmDeploymentPhase::Transfer);

    let cache_failures = unrecovered_failures(
        facts,
        DeploymentFactKind::CacheFailed,
        DeploymentFactKind::CacheCommitted,
    );
    if !cache_failures.is_empty() {
        return conclude(
            &chain,
            SccmDeploymentPhase::Cache,
            SccmDeploymentState::Failed,
            SccmDeploymentClassification::ConfirmedFailure,
            last,
            Some(FINDING_CACHE_TERMINAL),
            &cache_failures,
        );
    }
    let Some(cached) = first_fact(facts, DeploymentFactKind::CacheCommitted) else {
        return insufficient(SccmDeploymentPhase::Cache, last, REASON_CACHE, coverage);
    };
    chain.push(cached);
    last = Some(SccmDeploymentPhase::Cache);

    let enforce_failures = unrecovered_failures(
        facts,
        DeploymentFactKind::EnforceFailed,
        DeploymentFactKind::EnforceSucceeded,
    );
    if !enforce_failures.is_empty() {
        return conclude(
            &chain,
            SccmDeploymentPhase::Enforce,
            SccmDeploymentState::Failed,
            SccmDeploymentClassification::ConfirmedFailure,
            last,
            Some(FINDING_ENFORCE_TERMINAL),
            &enforce_failures,
        );
    }
    let Some(enforced) = first_fact(facts, DeploymentFactKind::EnforceSucceeded) else {
        return insufficient(SccmDeploymentPhase::Enforce, last, REASON_ENFORCE, coverage);
    };
    chain.push(enforced);
    last = Some(SccmDeploymentPhase::Enforce);

    if let Some(mismatch) = first_fact(facts, DeploymentFactKind::DetectionMismatch) {
        let mut mismatch_chain = chain.clone();
        mismatch_chain.push(mismatch);
        return conclude(
            &mismatch_chain,
            SccmDeploymentPhase::Detect,
            SccmDeploymentState::DetectionMismatch,
            SccmDeploymentClassification::Symptom,
            last,
            Some(FINDING_DETECTION_MISMATCH),
            &[],
        );
    }
    let Some(detected) = first_fact(facts, DeploymentFactKind::Detected) else {
        return insufficient(SccmDeploymentPhase::Detect, last, REASON_DETECT, coverage);
    };
    chain.push(detected);
    last = Some(SccmDeploymentPhase::Detect);

    let report_failures = unrecovered_failures(
        facts,
        DeploymentFactKind::ReportFailed,
        DeploymentFactKind::ReportSucceeded,
    );
    if !report_failures.is_empty() {
        return conclude(
            &chain,
            SccmDeploymentPhase::Report,
            SccmDeploymentState::Failed,
            SccmDeploymentClassification::ConfirmedFailure,
            last,
            Some(FINDING_REPORT_TERMINAL),
            &report_failures,
        );
    }
    let Some(reported) = first_fact(facts, DeploymentFactKind::ReportSucceeded) else {
        return insufficient(SccmDeploymentPhase::Report, last, REASON_REPORT, coverage);
    };
    chain.push(reported);

    conclude(
        &chain,
        SccmDeploymentPhase::Report,
        SccmDeploymentState::Succeeded,
        SccmDeploymentClassification::Success,
        last,
        None,
        &[],
    )
}

/// Terminal and success outcomes require a usable chronology through every
/// prerequisite phase. Without one the transaction becomes a low-confidence
/// symptom that names the missing ordering evidence.
#[allow(clippy::too_many_arguments)]
fn conclude(
    chain: &[&DeploymentFact],
    phase: SccmDeploymentPhase,
    state: SccmDeploymentState,
    classification: SccmDeploymentClassification,
    last_successful_phase: Option<SccmDeploymentPhase>,
    finding_id: Option<&'static str>,
    terminals: &[&DeploymentFact],
) -> Outcome {
    // Every cited terminal record must be orderable through the prerequisite
    // chain. One that is not would be published on the strength of another.
    let terminals_are_ordered = terminals.iter().all(|terminal| {
        let mut candidate = chain.to_vec();
        if !candidate.iter().any(|fact| std::ptr::eq(*fact, *terminal)) {
            candidate.push(terminal);
        }
        chain_has_usable_order(&candidate)
    });
    if !chain_has_usable_order(chain) || !terminals_are_ordered {
        return Outcome {
            phase,
            state: SccmDeploymentState::InsufficientEvidence,
            classification: SccmDeploymentClassification::Symptom,
            confidence: SccmDeploymentConfidence::Low,
            last_successful_phase,
            next_artifact: Some(SccmDeploymentArtifactRequest {
                logical_artifact_id: phase.artifact_group().to_owned(),
                reason: REASON_CHRONOLOGY.to_owned(),
            }),
            coverage_gap_artifact_ids: Vec::new(),
            finding_id: Some(FINDING_CHRONOLOGY_UNCERTAIN),
            terminal_evidence: Vec::new(),
        };
    }

    let (confidence, last_successful_phase) = match state {
        SccmDeploymentState::Succeeded => (SccmDeploymentConfidence::High, Some(phase)),
        SccmDeploymentState::DetectionMismatch => {
            (SccmDeploymentConfidence::Medium, last_successful_phase)
        }
        _ => (SccmDeploymentConfidence::High, last_successful_phase),
    };

    Outcome {
        phase,
        state,
        classification,
        confidence,
        last_successful_phase,
        next_artifact: None,
        coverage_gap_artifact_ids: Vec::new(),
        finding_id,
        terminal_evidence: terminals
            .iter()
            .map(|fact| fact.reference.clone())
            .collect(),
    }
}

fn insufficient(
    phase: SccmDeploymentPhase,
    last_successful_phase: Option<SccmDeploymentPhase>,
    reason: &str,
    coverage: &[SccmDeploymentCoverage],
) -> Outcome {
    let group = phase.artifact_group();
    Outcome {
        phase,
        state: SccmDeploymentState::InsufficientEvidence,
        classification: SccmDeploymentClassification::InsufficientEvidence,
        confidence: SccmDeploymentConfidence::Low,
        last_successful_phase,
        next_artifact: Some(SccmDeploymentArtifactRequest {
            logical_artifact_id: group.to_owned(),
            reason: reason.to_owned(),
        }),
        coverage_gap_artifact_ids: coverage_for_group(coverage, group)
            .map(|row| row.artifact_ids.clone())
            .unwrap_or_default(),
        finding_id: Some(coverage_gap_finding_id(phase)),
        terminal_evidence: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Source-local observations
// ---------------------------------------------------------------------------

/// Every client artifact holding bytes that no admitted fact represents.
///
/// This covers two shapes: an artifact that produced no admitted fact at all,
/// and an artifact whose complete records were admitted but which still holds
/// physical lines no record covers. The second shape is why the sweep keys on
/// record completeness rather than on whether the artifact contributed facts.
fn source_local_observations(
    bundle: &SccmNormalizedBundle,
    artifacts_by_id: &BTreeMap<&str, &SccmArtifact>,
    admitted_artifact_ids: &BTreeSet<&str>,
) -> Vec<SccmDeploymentObservation> {
    let mut evidence_by_artifact = BTreeMap::<&str, Vec<&SccmEvidence>>::new();
    for evidence in bundle
        .evidence
        .iter()
        .filter(|evidence| evidence.role == SccmRole::Client)
    {
        let artifact_id = evidence.reference.artifact_id.as_str();
        if !artifacts_by_id.contains_key(artifact_id) || !valid_reference(&evidence.reference) {
            continue;
        }
        evidence_by_artifact
            .entry(artifact_id)
            .or_default()
            .push(evidence);
    }

    evidence_by_artifact
        .into_iter()
        .filter_map(|(artifact_id, evidence)| {
            let artifact = artifacts_by_id.get(artifact_id)?;
            let fragments = evidence
                .iter()
                .copied()
                .filter(|item| item.completeness == SccmRecordCompleteness::PhysicalFragment)
                .collect::<Vec<_>>();
            if fragments.is_empty() && admitted_artifact_ids.contains(artifact_id) {
                return None;
            }

            // Cite the fragments when there are any: they are what no fact
            // represents. Otherwise the whole artifact went unrepresented.
            let cited = if fragments.is_empty() {
                &evidence
            } else {
                &fragments
            };
            let start = cited
                .iter()
                .filter_map(|item| item.reference.line_start)
                .min()?;
            let end = cited
                .iter()
                .filter_map(|item| item.reference.line_end)
                .max()?;
            let key_confidence = if cited.iter().any(|item| has_candidate_key(&item.message)) {
                SccmDeploymentObservationKeyConfidence::Candidate
            } else {
                SccmDeploymentObservationKeyConfidence::None
            };
            let complete_logical_record = observation_is_complete(artifact, &fragments);

            Some(SccmDeploymentObservation {
                observation_id: format!(
                    "{}:{artifact_id}",
                    if complete_logical_record {
                        "supplemental"
                    } else {
                        "fragment"
                    }
                ),
                artifact_id: artifact_id.to_owned(),
                complete_logical_record,
                key_confidence,
                confidence_ceiling: SccmDeploymentConfidence::Low,
                correlation_eligible: false,
                reason: observation_reason(artifact, complete_logical_record).to_owned(),
                evidence: SccmEvidenceRef {
                    artifact_id: artifact_id.to_owned(),
                    entry_id: format!("{artifact_id}:{start}-{end}"),
                    line_start: Some(start),
                    line_end: Some(end),
                },
            })
        })
        .collect()
}

/// Completeness of what the observation cites, decided by the record and by the
/// source's framing rather than by the artifact's coverage state.
///
/// A source that frames CCM records has no complete unit smaller than a record,
/// so any fragment is incomplete. For an unframed text source the physical line
/// is itself the unit, and it is complete unless the collected bytes were cut
/// short.
fn observation_is_complete(artifact: &SccmArtifact, fragments: &[&SccmEvidence]) -> bool {
    if fragments.is_empty() {
        return true;
    }
    let catalog = classify_artifact_name(&artifact.display_name, SccmRole::Client);
    !catalog.uses_ccm_records && artifact.coverage == SccmCoverageState::Captured
}

fn observation_reason(artifact: &SccmArtifact, complete_logical_record: bool) -> &'static str {
    if complete_logical_record {
        return "unvalidated supplemental text cannot override an exact keyed client transaction";
    }
    match (&artifact.coverage, &artifact.rotation) {
        (SccmCoverageState::Partial, SccmRotation::Current) => {
            "current-file fragment cannot complete the archived physical record"
        }
        (SccmCoverageState::Partial, SccmRotation::LoUnderscore) => {
            "archived-file fragment cannot be joined across a physical rotation boundary"
        }
        (SccmCoverageState::Partial, _) => {
            "a physical rotation fragment cannot form a logical record"
        }
        (SccmCoverageState::Capped, _) => {
            "capped bytes do not form a logical record and cannot attach by time"
        }
        _ => "an unframed physical line is not a logical record and cannot attach by time",
    }
}

/// A fragment may still show something that looks like a key. Saying so is not
/// the same as trusting it: the observation stays capped at Low and unlinked.
fn has_candidate_key(message: &str) -> bool {
    let Some(payload) = deployment_event_payload(message) else {
        return false;
    };
    field_value(payload, "assignmentId").is_some_and(valid_guid)
        || field_value(payload, "ciId").is_some_and(valid_guid)
        || field_value(payload, "contentId").is_some_and(valid_guid)
        || field_value(payload, "requestId").is_some_and(valid_guid)
        || field_value(payload, "bitsJobId").is_some_and(valid_guid)
        || field_value(payload, "productCode").is_some_and(valid_guid)
        || field_value(payload, "packageId").is_some_and(valid_package_id)
        || field_value(payload, "distributionPointHostHandle").is_some_and(valid_safe_handle)
        || field_value(payload, "contentVersion")
            .and_then(parse_content_version)
            .is_some()
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

const FINDING_REQUIREMENTS_TERMINAL: &str = "deployment-requirements-terminal";
const FINDING_DEPENDENCY_TERMINAL: &str = "deployment-dependency-terminal";
const FINDING_TRANSFER_TERMINAL: &str = "deployment-transfer-terminal";
const FINDING_CACHE_TERMINAL: &str = "deployment-cache-terminal";
const FINDING_ENFORCE_TERMINAL: &str = "deployment-enforce-terminal";
const FINDING_REPORT_TERMINAL: &str = "deployment-report-terminal";
const FINDING_DETECTION_MISMATCH: &str = "deployment-detection-mismatch";
const FINDING_CHRONOLOGY_UNCERTAIN: &str = "deployment-chronology-uncertain";

/// Most causes can only occur at one phase, so their identity is already
/// unique. An unusable chronology can occur at any of the eight, so its
/// identity carries the phase and two of them never merge.
fn emitted_finding_id(base_id: &str, phase: SccmDeploymentPhase) -> String {
    if base_id == FINDING_CHRONOLOGY_UNCERTAIN {
        return format!("{base_id}-{}", kebab_case(phase.as_str()));
    }
    base_id.to_owned()
}

fn coverage_gap_finding_id(phase: SccmDeploymentPhase) -> &'static str {
    match phase {
        SccmDeploymentPhase::Intent => "deployment-intent-coverage-gap",
        SccmDeploymentPhase::Requirements => "deployment-requirements-coverage-gap",
        SccmDeploymentPhase::LocateContent => "deployment-location-coverage-gap",
        SccmDeploymentPhase::Transfer => "deployment-transfer-coverage-gap",
        SccmDeploymentPhase::Cache => "deployment-cache-coverage-gap",
        SccmDeploymentPhase::Enforce => "deployment-enforce-coverage-gap",
        SccmDeploymentPhase::Detect => "deployment-detect-coverage-gap",
        SccmDeploymentPhase::Report => "deployment-report-coverage-gap",
    }
}

/// Titles and summaries never name a distribution point, a server, a download
/// cause, or a policy prerequisite: those claims belong to other issues.
fn finding_text(finding_id: &str) -> (&'static str, &'static str) {
    match finding_id {
        FINDING_REQUIREMENTS_TERMINAL => (
            "Client requirement evaluation recorded a terminal failure",
            "A complete version-profiled requirement record ended this assignment before any content phase.",
        ),
        FINDING_DEPENDENCY_TERMINAL => (
            "Client dependency evaluation recorded a terminal failure",
            "A complete version-profiled dependency record ended this assignment before any content phase.",
        ),
        FINDING_TRANSFER_TERMINAL => (
            "Client content transfer recorded a terminal failure",
            "The same exact content key recorded a terminal transfer error after content was located.",
        ),
        FINDING_CACHE_TERMINAL => (
            "Client cache commit recorded a terminal failure",
            "The same exact content key recorded a terminal cache error after the transfer completed.",
        ),
        FINDING_ENFORCE_TERMINAL => (
            "Client enforcement recorded a terminal failure",
            "A complete enforcement record ended with a nonzero terminal exit code after the cache commit.",
        ),
        FINDING_REPORT_TERMINAL => (
            "Client deployment state report recorded a terminal failure",
            "A complete state report ended this assignment with a failed deployment state.",
        ),
        FINDING_DETECTION_MISMATCH => (
            "Post-enforcement detection did not find the application",
            "Enforcement completed with a zero exit code and detection still reported the application absent.",
        ),
        FINDING_CHRONOLOGY_UNCERTAIN => (
            "Deployment chronology is not usable",
            "Records for this key cannot be ordered through the earlier phases, so no outcome is claimed.",
        ),
        "deployment-intent-coverage-gap" => (
            "Client application intent evidence is incomplete",
            "No complete client intent record was available for this assignment and CI.",
        ),
        "deployment-requirements-coverage-gap" => (
            "Client requirement evidence is incomplete",
            "No complete client requirement or dependency outcome was available for this assignment and CI.",
        ),
        "deployment-location-coverage-gap" => (
            "Client content-location evidence is incomplete",
            "No complete client content-location record was available for this assignment and CI.",
        ),
        "deployment-transfer-coverage-gap" => (
            "Client content transfer evidence is incomplete",
            "No complete client transfer outcome was available for this content key.",
        ),
        "deployment-cache-coverage-gap" => (
            "Client cache commit evidence is incomplete",
            "No complete client cache commit outcome was available for this content key.",
        ),
        "deployment-enforce-coverage-gap" => (
            "Client enforcement evidence is incomplete",
            "No complete client enforcement outcome was available for this content key.",
        ),
        "deployment-detect-coverage-gap" => (
            "Client detection evidence is incomplete",
            "No complete client detection outcome was available for this content key.",
        ),
        _ => (
            "Client deployment state report evidence is incomplete",
            "No complete client state report was available for this content key.",
        ),
    }
}

/// The smallest catalog source that can close the gap for a phase.
fn phase_artifact_request(phase: SccmDeploymentPhase) -> SccmArtifactRequest {
    let (logical_id, basename) = match phase {
        SccmDeploymentPhase::Intent | SccmDeploymentPhase::Requirements => {
            ("appIntentEval", "AppIntentEval.log")
        }
        SccmDeploymentPhase::LocateContent | SccmDeploymentPhase::Cache => ("cas", "CAS.log"),
        SccmDeploymentPhase::Transfer => ("dataTransferService", "DataTransferService.log"),
        SccmDeploymentPhase::Enforce => ("appEnforce", "AppEnforce.log"),
        SccmDeploymentPhase::Detect => ("appDiscovery", "AppDiscovery.log"),
        SccmDeploymentPhase::Report => ("stateMessage", "StateMessage.log"),
    };
    SccmArtifactRequest {
        logical_id: logical_id.to_owned(),
        role: SccmRole::Client,
        reason: format!("Collect the complete {basename} file."),
    }
}

/// Transactions blocked by the same cause share one finding: repeating an
/// identical coverage claim per assignment would overstate the evidence.
fn build_findings(
    seeds: &[FindingSeed],
    artifacts_by_id: &BTreeMap<&str, &SccmArtifact>,
) -> Vec<SccmDeploymentFinding> {
    let mut grouped = BTreeMap::<(&str, SccmDeploymentPhase), Vec<&FindingSeed>>::new();
    for seed in seeds {
        grouped
            .entry((seed.finding_id, seed.phase))
            .or_default()
            .push(seed);
    }

    grouped
        .into_iter()
        .filter_map(|((base_id, phase), seeds)| {
            let first = seeds.first()?;
            let (title, summary) = finding_text(base_id);
            let finding_id = emitted_finding_id(base_id, phase);
            // Every seed in this group shares the finding cause and the phase,
            // so the representative can only speak for evidence it represents.
            // The reported progress is still the least any of them reached.
            let last_successful_phase = seeds
                .iter()
                .map(|seed| seed.last_successful_phase)
                .min()
                .unwrap_or(first.last_successful_phase);

            let evidence = if !first.terminal_evidence.is_empty() {
                let mut references = seeds
                    .iter()
                    .flat_map(|seed| seed.evidence.iter().cloned())
                    .collect::<Vec<_>>();
                references.sort_by(compare_references);
                references.dedup();
                references
            } else {
                merge_reference_spans(seeds.iter().flat_map(|seed| seed.evidence.iter()))
            };

            let mut terminal_evidence = seeds
                .iter()
                .flat_map(|seed| seed.terminal_evidence.iter().cloned())
                .map(SccmTerminalEvidence::observed_failure)
                .collect::<Vec<_>>();
            terminal_evidence
                .sort_by(|left, right| compare_references(&left.reference, &right.reference));
            terminal_evidence.dedup();

            let mut coverage_gaps = seeds
                .iter()
                .flat_map(|seed| {
                    seed.coverage_gap_artifact_ids
                        .iter()
                        .filter_map(|artifact_id| {
                            let artifact = artifacts_by_id.get(artifact_id.as_str())?;
                            Some(SccmFindingCoverageGap {
                                artifact_id: artifact_id.clone(),
                                role: SccmRole::Client,
                                coverage: artifact.coverage.clone(),
                            })
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            coverage_gaps.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
            coverage_gaps.dedup();
            if coverage_gaps.is_empty() {
                // An insufficient-evidence finding always names what is
                // missing. With no incomplete artifact to blame, the gap is the
                // group itself: bytes exist, the needed record does not.
                if let Some(group) = first.coverage_gap_group {
                    coverage_gaps.push(SccmFindingCoverageGap {
                        artifact_id: group.to_owned(),
                        role: SccmRole::Client,
                        coverage: SccmCoverageState::Partial,
                    });
                }
            }

            let mut builder = SccmFindingBuilder::new(finding_id)
                .class(first.class.clone())
                .phase(SccmPhase::Unknown(phase.as_str().to_owned()))
                .role(SccmRole::Client)
                .severity(match first.class {
                    SccmFindingClass::ConfirmedFailure => Severity::Error,
                    _ => Severity::Warning,
                })
                .confidence(first.confidence)
                .title(title)
                .summary(summary)
                .evidence(evidence)
                .terminal_evidence(terminal_evidence)
                .coverage_gaps(coverage_gaps);
            if first.request_phase.is_some() {
                builder = builder.next_artifact(phase_artifact_request(phase));
            }

            Some(SccmDeploymentFinding {
                finding: builder
                    .build()
                    .expect("deployment finding must satisfy the shared contract"),
                deployment_phase: phase,
                last_successful_phase,
            })
        })
        .collect()
}

fn merge_reference_spans<'a>(
    references: impl Iterator<Item = &'a SccmEvidenceRef>,
) -> Vec<SccmEvidenceRef> {
    let mut spans = BTreeMap::<String, (u32, u32)>::new();
    for reference in references {
        let (Some(start), Some(end)) = (reference.line_start, reference.line_end) else {
            continue;
        };
        spans
            .entry(reference.artifact_id.clone())
            .and_modify(|span| {
                span.0 = span.0.min(start);
                span.1 = span.1.max(end);
            })
            .or_insert((start, end));
    }

    spans
        .into_iter()
        .map(|(artifact_id, (start, end))| SccmEvidenceRef {
            entry_id: format!("{artifact_id}:{start}-{end}"),
            artifact_id,
            line_start: Some(start),
            line_end: Some(end),
        })
        .collect()
}
