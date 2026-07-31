use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::Value;

const CONTRACT_SCHEMA_VERSION: &str = "1.0.0";
const WORKFLOWS: [&str; 2] = ["contentDistributionPoint", "policyManagementPoint"];
const GUARD_IDS: [&str; 13] = [
    "conflicting-exact-key",
    "incompatible-topology",
    "invalid-timestamp-offset",
    "missing-client-counterpart",
    "missing-server-counterpart",
    "partial-capture",
    "redaction-boundary",
    "reordered-input",
    "rotation-split",
    "same-time-no-key",
    "unknown-extraction-profile",
    "unrelated-terminal-error",
    "version-mismatch",
];
/// Closed obligation vocabulary: each guard's requiredOutputs are pinned
/// here and every token has an executable predicate over the scenario's
/// expected contract in `output_obligation_holds`.
const GUARD_REQUIRED_OUTPUTS: [(&str, &[&str]); 13] = [
    (
        "conflicting-exact-key",
        &["incompatibilityReason", "sourceLocalResults"],
    ),
    (
        "incompatible-topology",
        &["incompatibilityReason", "sourceLocalResults"],
    ),
    (
        "invalid-timestamp-offset",
        &["orderingUnavailable", "sourceLocalResults"],
    ),
    (
        "missing-client-counterpart",
        &["clientArtifactRequest", "serverLocalResults"],
    ),
    (
        "missing-server-counterpart",
        &["clientLocalResults", "serverArtifactRequest"],
    ),
    ("partial-capture", &["coverageGap", "sourceLocalResults"]),
    (
        "redaction-boundary",
        &["publicSafeHandles", "redactedProjection"],
    ),
    (
        "reordered-input",
        &["deterministicSerialization", "sourceLocalResults"],
    ),
    ("rotation-split", &["coverageGap", "sourceLocalResults"]),
    (
        "same-time-no-key",
        &["candidateSymptom", "sourceLocalResults"],
    ),
    (
        "unknown-extraction-profile",
        &["profileGap", "sourceLocalResults"],
    ),
    (
        "unrelated-terminal-error",
        &["sourceLocalResults", "unlinkedTerminalEvidence"],
    ),
    (
        "version-mismatch",
        &["incompatibilityReason", "sourceLocalResults"],
    ),
];

const POLICY_SCENARIOS: [&str; 14] = [
    "policy-client-only",
    "policy-conflicting-key",
    "policy-invalid-offset",
    "policy-partial-capture",
    "policy-redaction",
    "policy-reordered-input-a",
    "policy-reordered-input-b",
    "policy-rotation-split",
    "policy-same-time-no-key",
    "policy-server-only",
    "policy-topology-mismatch",
    "policy-unknown-profile",
    "policy-unrelated-terminal-error",
    "policy-version-mismatch",
];
const CONTENT_SCENARIOS: [&str; 14] = [
    "content-client-only",
    "content-conflicting-key",
    "content-invalid-offset",
    "content-partial-capture",
    "content-redaction",
    "content-reordered-input-a",
    "content-reordered-input-b",
    "content-rotation-split",
    "content-same-time-no-key",
    "content-server-only",
    "content-topology-mismatch",
    "content-unknown-profile",
    "content-unrelated-terminal-error",
    "content-version-mismatch",
];

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GuardMatrix {
    schema_version: String,
    guards: Vec<GuardContract>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GuardContract {
    guard_id: String,
    applies_to: Vec<String>,
    forbidden_strengths: Vec<String>,
    forbidden_confidences: Vec<String>,
    required_outputs: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ScenarioMatrix {
    schema_version: String,
    workflow: String,
    scenarios: Vec<ScenarioContract>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ScenarioContract {
    scenario_id: String,
    guard_ids: Vec<String>,
    client_issue: String,
    server_issue: String,
    client_fixture_ref: String,
    server_fixture_ref: String,
    #[serde(default)]
    ordered_input_evidence: Vec<String>,
    profile_state: ProfileState,
    key_relation: KeyRelation,
    topology: TopologyState,
    timestamp_provenance: TimestampState,
    coverage: CoverageState,
    rotation: RotationState,
    terminal_relation: TerminalRelation,
    private_input_markers: Vec<String>,
    expected_public_projection: Value,
    expected: ExpectedCeiling,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
enum ProfileState {
    Validated,
    Unknown,
    VersionMismatch,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
enum KeyRelation {
    Exact,
    Conflicting,
    Missing,
    VersionMismatch,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
enum TopologyState {
    Compatible,
    Incomplete,
    Incompatible,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
enum TimestampState {
    Usable,
    Missing,
    InvalidOffset,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
enum CoverageState {
    Complete,
    ClientOnly,
    ServerOnly,
    Partial,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
enum RotationState {
    Complete,
    Split,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
enum TerminalRelation {
    Corroborating,
    Missing,
    Contradictory,
    Unrelated,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExpectedCeiling {
    link_strength_ceiling: String,
    confidence_ceiling: String,
    high_confidence_cause_allowed: bool,
    exact_corroborated_allowed: bool,
    source_findings_mutable: bool,
    reason_codes: Vec<String>,
    artifact_requests: Vec<String>,
    deterministic_result_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PairRegistry {
    schema_version: String,
    pairs: Vec<PairContract>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PairContract {
    pair_id: String,
    workflow: String,
    client_issue: String,
    server_issue: String,
    state: PairState,
    production_enabled: bool,
    rule_validated: bool,
    implementation_module: Option<String>,
    required_guard_ids: Vec<String>,
    blockers: Vec<String>,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
enum PairState {
    ContractPrepared,
    Candidate,
}

/// Upstream acceptance state of one side of a correlation pair.
///
/// `Merged` sides may only cite already merged synthetic corpus directories
/// under their own side prefix (or pair-local `synthetic:` inputs). `Pending`
/// sides have no accepted corpus on the program baseline, so they must stay
/// honestly marked with `issue:` refs until the upstream issue is accepted.
enum SideCorpus {
    Merged { repo_prefix: &'static str },
    Pending { issue: &'static str },
}

struct MatrixSpec {
    workflow: &'static str,
    scenario_ids: &'static [&'static str],
    client_issue: &'static str,
    server_issue: &'static str,
    client_side: SideCorpus,
    server_side: SideCorpus,
}

const POLICY_SPEC: MatrixSpec = MatrixSpec {
    workflow: "policyManagementPoint",
    scenario_ids: &POLICY_SCENARIOS,
    client_issue: "#321",
    server_issue: "#328",
    client_side: SideCorpus::Merged {
        repo_prefix: "crates/cmtraceopen-parser/tests/fixtures/sccm/client/policy/",
    },
    server_side: SideCorpus::Merged {
        repo_prefix: "crates/cmtraceopen-parser/tests/fixtures/sccm/server/management-point/",
    },
};

const CONTENT_SPEC: MatrixSpec = MatrixSpec {
    workflow: "contentDistributionPoint",
    scenario_ids: &CONTENT_SCENARIOS,
    client_issue: "#322",
    server_issue: "#329",
    client_side: SideCorpus::Merged {
        repo_prefix: "crates/cmtraceopen-parser/tests/fixtures/sccm/client/deployment/",
    },
    // #329 DP evidence is not independently accepted yet, so the server side
    // may only name pending scenarios and must never cite a merged corpus.
    server_side: SideCorpus::Pending { issue: "#329" },
};

const PAIR_OWNERSHIP: [(&str, &str, &str, &str); 3] = [
    (
        "content-distribution-point",
        "contentDistributionPoint",
        "#322",
        "#329",
    ),
    (
        "policy-management-point",
        "policyManagementPoint",
        "#321",
        "#328",
    ),
    (
        "updates-software-update-point",
        "updatesSoftwareUpdatePoint",
        "#323",
        "#330",
    ),
];

const CONTENT_PENDING_BLOCKER: &str = "#329 public fact interface not independently accepted";

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sccm/correlation")
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("parser crate has a repository root")
        .to_path_buf()
}

fn read_json(path: &Path) -> Value {
    let contents = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{} is readable: {error}", path.display()));
    serde_json::from_str(&contents)
        .unwrap_or_else(|error| panic!("{} is JSON: {error}", path.display()))
}

fn typed<T: for<'de> Deserialize<'de>>(value: Value) -> Result<T, String> {
    serde_json::from_value(value)
        .map_err(|error| format!("fixture is not typed contract JSON: {error}"))
}

fn is_sorted_unique(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn validate_issue(value: &str) -> bool {
    value.strip_prefix('#').is_some_and(|digits| {
        !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn is_synthetic_slug(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn check_fixture_ref(value: &str, side: &SideCorpus, side_name: &str) -> Result<(), String> {
    if value == "absent" {
        return Ok(());
    }
    if let Some(path) = value.strip_prefix("repo:") {
        let SideCorpus::Merged { repo_prefix } = side else {
            return Err(format!(
                "{side_name} fixture ref {value} cites a merged corpus while the upstream side is pending"
            ));
        };
        if !path.starts_with(repo_prefix) {
            return Err(format!(
                "{side_name} fixture ref {value} is outside the side corpus {repo_prefix}"
            ));
        }
        if path.contains("..") || !repo_root().join(path).is_dir() {
            return Err(format!(
                "{side_name} fixture ref {value} does not name a merged corpus directory"
            ));
        }
        return Ok(());
    }
    if let Some(synthetic_id) = value.strip_prefix("synthetic:") {
        if !matches!(side, SideCorpus::Merged { .. }) {
            return Err(format!(
                "{side_name} fixture ref {value} hides a pending upstream side behind a synthetic input"
            ));
        }
        if !is_synthetic_slug(synthetic_id) {
            return Err(format!(
                "{side_name} fixture ref {value} has a malformed synthetic slug"
            ));
        }
        return Ok(());
    }
    if let Some(pending) = value.strip_prefix("issue:") {
        let SideCorpus::Pending { issue } = side else {
            return Err(format!(
                "{side_name} fixture ref {value} claims a pending upstream while the side corpus is merged"
            ));
        };
        let valid = pending
            .strip_prefix(issue)
            .and_then(|rest| rest.strip_prefix(':'))
            .is_some_and(is_synthetic_slug);
        if !valid {
            return Err(format!(
                "{side_name} fixture ref {value} is not a pending {issue} scenario"
            ));
        }
        return Ok(());
    }
    Err(format!("{side_name} fixture ref {value} has no known form"))
}

fn collect_decoded_strings(value: &Value, sink: &mut Vec<String>) {
    match value {
        Value::String(text) => sink.push(text.clone()),
        Value::Array(items) => {
            for item in items {
                collect_decoded_strings(item, sink);
            }
        }
        Value::Object(entries) => {
            for (key, item) in entries {
                sink.push(key.clone());
                collect_decoded_strings(item, sink);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn projection_string_is_safe(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
}

fn check_scenario(scenario: &ScenarioContract, spec: &MatrixSpec) -> Result<(), String> {
    let scenario_id = scenario.scenario_id.as_str();
    if scenario.client_issue != spec.client_issue {
        return Err(format!("{scenario_id}: unexpected client issue"));
    }
    if scenario.server_issue != spec.server_issue {
        return Err(format!("{scenario_id}: unexpected server issue"));
    }
    if !validate_issue(&scenario.client_issue) || !validate_issue(&scenario.server_issue) {
        return Err(format!("{scenario_id}: malformed issue reference"));
    }
    check_fixture_ref(&scenario.client_fixture_ref, &spec.client_side, "client")
        .map_err(|error| format!("{scenario_id}: {error}"))?;
    check_fixture_ref(&scenario.server_fixture_ref, &spec.server_side, "server")
        .map_err(|error| format!("{scenario_id}: {error}"))?;
    if !scenario.ordered_input_evidence.is_empty() {
        if scenario.ordered_input_evidence.len() < 2 {
            return Err(format!(
                "{scenario_id}: reordered input evidence needs at least two entries"
            ));
        }
        for entry in &scenario.ordered_input_evidence {
            let side_tagged = entry
                .strip_prefix("client:")
                .or_else(|| entry.strip_prefix("server:"))
                .is_some_and(is_synthetic_slug);
            if !side_tagged {
                return Err(format!(
                    "{scenario_id}: reordered evidence entry {entry} is not a side-tagged synthetic token"
                ));
            }
        }
        for side in ["client:", "server:"] {
            if !scenario
                .ordered_input_evidence
                .iter()
                .any(|entry| entry.starts_with(side))
            {
                return Err(format!(
                    "{scenario_id}: reordered evidence must include the {side} side"
                ));
            }
        }
    }
    if scenario.guard_ids.is_empty() || !is_sorted_unique(&scenario.guard_ids) {
        return Err(format!(
            "{scenario_id}: guard IDs must be nonempty, sorted, and unique"
        ));
    }
    if !scenario
        .guard_ids
        .iter()
        .all(|guard| GUARD_IDS.contains(&guard.as_str()))
    {
        return Err(format!("{scenario_id}: unknown guard"));
    }
    if scenario.expected.high_confidence_cause_allowed {
        return Err(format!(
            "{scenario_id}: adversarial fixture cannot permit high-confidence cause"
        ));
    }
    if scenario.expected.exact_corroborated_allowed {
        return Err(format!(
            "{scenario_id}: adversarial fixture cannot permit ExactCorroborated"
        ));
    }
    if scenario.expected.source_findings_mutable {
        return Err(format!(
            "{scenario_id}: source findings must stay immutable"
        ));
    }
    if scenario.expected.link_strength_ceiling == "exactCorroborated" {
        return Err(format!(
            "{scenario_id}: link ceiling reached exactCorroborated"
        ));
    }
    if scenario.expected.confidence_ceiling == "high" {
        return Err(format!("{scenario_id}: confidence ceiling reached high"));
    }
    if !["candidate", "exactPartial", "incompatible", "unlinked"]
        .contains(&scenario.expected.link_strength_ceiling.as_str())
    {
        return Err(format!("{scenario_id}: unknown link strength ceiling"));
    }
    if !["low", "medium"].contains(&scenario.expected.confidence_ceiling.as_str()) {
        return Err(format!("{scenario_id}: unknown confidence ceiling"));
    }
    if scenario.expected.reason_codes.is_empty()
        || !is_sorted_unique(&scenario.expected.reason_codes)
    {
        return Err(format!(
            "{scenario_id}: reason codes must be nonempty, sorted, and unique"
        ));
    }
    if !is_sorted_unique(&scenario.expected.artifact_requests) {
        return Err(format!(
            "{scenario_id}: artifact requests must be sorted and unique"
        ));
    }
    if scenario.expected.deterministic_result_id.is_empty() {
        return Err(format!("{scenario_id}: deterministic result id is empty"));
    }

    let mut decoded_strings = Vec::new();
    collect_decoded_strings(&scenario.expected_public_projection, &mut decoded_strings);
    for text in &decoded_strings {
        if !projection_string_is_safe(text) {
            return Err(format!(
                "{scenario_id}: decoded projection string {text:?} is outside the closed public grammar"
            ));
        }
    }
    for marker in &scenario.private_input_markers {
        if marker.is_empty() {
            return Err(format!("{scenario_id}: private marker is empty"));
        }
        if decoded_strings.iter().any(|text| text.contains(marker)) {
            return Err(format!(
                "{scenario_id}: private marker leaked into a decoded projection value"
            ));
        }
    }
    if scenario.profile_state != ProfileState::Validated
        && !scenario
            .guard_ids
            .iter()
            .any(|guard| guard == "unknown-extraction-profile" || guard == "version-mismatch")
    {
        return Err(format!("{scenario_id}: unvalidated profile lacks a guard"));
    }
    if scenario.key_relation == KeyRelation::Missing
        && !scenario.guard_ids.contains(&"same-time-no-key".to_owned())
    {
        return Err(format!(
            "{scenario_id}: missing key lacks the same-time guard"
        ));
    }
    if scenario.key_relation == KeyRelation::VersionMismatch
        && !scenario.guard_ids.contains(&"version-mismatch".to_owned())
    {
        return Err(format!(
            "{scenario_id}: key version mismatch lacks its guard"
        ));
    }
    if scenario.coverage == CoverageState::ClientOnly
        && scenario.expected.artifact_requests.is_empty()
    {
        return Err(format!(
            "{scenario_id}: client-only coverage must request server artifacts"
        ));
    }
    if scenario.coverage == CoverageState::ServerOnly
        && scenario.expected.artifact_requests.is_empty()
    {
        return Err(format!(
            "{scenario_id}: server-only coverage must request client artifacts"
        ));
    }

    if (scenario.client_fixture_ref == "absent") != (scenario.coverage == CoverageState::ServerOnly)
    {
        return Err(format!(
            "{scenario_id}: an absent client fixture ref must match server-only coverage"
        ));
    }
    if (scenario.server_fixture_ref == "absent") != (scenario.coverage == CoverageState::ClientOnly)
    {
        return Err(format!(
            "{scenario_id}: an absent server fixture ref must match client-only coverage"
        ));
    }
    for guard in GUARD_IDS {
        let declared = scenario.guard_ids.iter().any(|declared| declared == guard);
        let demonstrated = guard_demonstrated(guard, scenario);
        if declared && !demonstrated {
            return Err(format!(
                "{scenario_id}: guard {guard} is declared but not demonstrated by the inputs"
            ));
        }
        if demonstrated && !declared {
            return Err(format!(
                "{scenario_id}: inputs demonstrate guard {guard} which is not declared"
            ));
        }
    }
    for guard in &scenario.guard_ids {
        let (_, outputs) = GUARD_REQUIRED_OUTPUTS
            .iter()
            .find(|(pinned_id, _)| pinned_id == guard)
            .ok_or_else(|| {
                format!("{scenario_id}: guard {guard} has no pinned output obligations")
            })?;
        for output in *outputs {
            if !output_obligation_holds(output, scenario) {
                return Err(format!(
                    "{scenario_id}: guard {guard} obligation {output} is not satisfied by the expected contract"
                ));
            }
        }
    }
    Ok(())
}

/// Evaluates one required-output token against the scenario's expected
/// results and public projection, so obligations are executable
/// constraints instead of declarative strings.
fn output_obligation_holds(output: &str, scenario: &ScenarioContract) -> bool {
    let projection = &scenario.expected_public_projection;
    match output {
        "incompatibilityReason" => {
            projection["outcome"] == "incompatible"
                && scenario.expected.link_strength_ceiling == "incompatible"
        }
        "sourceLocalResults" => projection["sourceFindingsPreserved"] == true,
        "clientLocalResults" => {
            projection["sourceFindingsPreserved"] == true
                && scenario.coverage == CoverageState::ClientOnly
        }
        "serverLocalResults" => {
            projection["sourceFindingsPreserved"] == true
                && scenario.coverage == CoverageState::ServerOnly
        }
        "clientArtifactRequest" => {
            projection["outcome"] == "counterpartRequested"
                && scenario
                    .expected
                    .artifact_requests
                    .iter()
                    .any(|request| request.starts_with("client-"))
        }
        "serverArtifactRequest" => {
            projection["outcome"] == "counterpartRequested"
                && scenario
                    .expected
                    .artifact_requests
                    .iter()
                    .any(|request| request.starts_with("server-"))
        }
        "orderingUnavailable" => projection["ordering"] == "unavailable",
        "coverageGap" => projection["outcome"] == "coverageGap",
        "candidateSymptom" => {
            projection["outcome"] == "candidateOnly"
                && scenario.expected.link_strength_ceiling == "candidate"
        }
        "profileGap" => projection["outcome"] == "profileGap",
        "unlinkedTerminalEvidence" => scenario
            .expected
            .reason_codes
            .iter()
            .any(|code| code == "unrelated-server-terminal"),
        "publicSafeHandles" => projection.as_object().is_some_and(|entries| {
            entries
                .iter()
                .filter(|(key, value)| {
                    key.ends_with("Handle") && value.as_str().is_some_and(is_synthetic_slug)
                })
                .count()
                >= 2
        }),
        "redactedProjection" => !scenario.private_input_markers.is_empty(),
        "deterministicSerialization" => {
            !scenario.ordered_input_evidence.is_empty()
                && !scenario.expected.deterministic_result_id.is_empty()
        }
        _ => false,
    }
}

/// True when the scenario's own input state instantiates the guard's
/// adversarial construction. Every declared guard must be demonstrated by
/// the inputs, and every demonstrated guard must be declared, so a guard
/// label can never outlive a neutralized input.
fn guard_demonstrated(guard: &str, scenario: &ScenarioContract) -> bool {
    match guard {
        "conflicting-exact-key" => scenario.key_relation == KeyRelation::Conflicting,
        "incompatible-topology" => scenario.topology == TopologyState::Incompatible,
        "invalid-timestamp-offset" => {
            scenario.timestamp_provenance == TimestampState::InvalidOffset
        }
        "missing-client-counterpart" => {
            scenario.coverage == CoverageState::ServerOnly
                && scenario.client_fixture_ref == "absent"
                && scenario.server_fixture_ref != "absent"
        }
        "missing-server-counterpart" => {
            scenario.coverage == CoverageState::ClientOnly
                && scenario.server_fixture_ref == "absent"
                && scenario.client_fixture_ref != "absent"
        }
        "partial-capture" => scenario.coverage == CoverageState::Partial,
        "redaction-boundary" => !scenario.private_input_markers.is_empty(),
        "reordered-input" => !scenario.ordered_input_evidence.is_empty(),
        "rotation-split" => scenario.rotation == RotationState::Split,
        "same-time-no-key" => {
            scenario.key_relation == KeyRelation::Missing
                && scenario.timestamp_provenance == TimestampState::Usable
        }
        "unknown-extraction-profile" => scenario.profile_state == ProfileState::Unknown,
        "unrelated-terminal-error" => scenario.terminal_relation == TerminalRelation::Unrelated,
        "version-mismatch" => {
            scenario.profile_state == ProfileState::VersionMismatch
                && scenario.key_relation == KeyRelation::VersionMismatch
        }
        _ => false,
    }
}

fn check_matrix_contract(matrix: &ScenarioMatrix, spec: &MatrixSpec) -> Result<(), String> {
    if matrix.schema_version != CONTRACT_SCHEMA_VERSION {
        return Err(format!(
            "unexpected schema version {}",
            matrix.schema_version
        ));
    }
    if matrix.workflow != spec.workflow {
        return Err(format!("unexpected workflow {}", matrix.workflow));
    }
    let scenario_ids = matrix
        .scenarios
        .iter()
        .map(|scenario| scenario.scenario_id.as_str())
        .collect::<Vec<_>>();
    if scenario_ids != spec.scenario_ids {
        return Err(format!("{}: scenario matrix changed", spec.workflow));
    }

    let mut exercised_guards = BTreeSet::new();
    for scenario in &matrix.scenarios {
        check_scenario(scenario, spec)?;
        exercised_guards.extend(scenario.guard_ids.iter().map(String::as_str));
    }
    if exercised_guards != GUARD_IDS.into_iter().collect() {
        return Err(format!(
            "{}: every shared guard needs a pair-specific adversarial scenario",
            spec.workflow
        ));
    }
    check_reordered_pair(matrix, spec)?;
    Ok(())
}

/// The reordered A/B cases must feed one identical input set through two
/// opposite evidence orders and still pin one deterministic contract.
fn check_reordered_pair(matrix: &ScenarioMatrix, spec: &MatrixSpec) -> Result<(), String> {
    let reordered = matrix
        .scenarios
        .iter()
        .filter(|scenario| scenario.guard_ids.contains(&"reordered-input".to_owned()))
        .collect::<Vec<_>>();
    let [first, second] = reordered.as_slice() else {
        return Err(format!(
            "{}: exactly two reordered-input scenarios are required",
            spec.workflow
        ));
    };
    if first.client_fixture_ref != second.client_fixture_ref
        || first.server_fixture_ref != second.server_fixture_ref
    {
        return Err(format!(
            "{}: reordered scenarios must share identical fixture refs",
            spec.workflow
        ));
    }
    if first.profile_state != second.profile_state
        || first.key_relation != second.key_relation
        || first.topology != second.topology
        || first.timestamp_provenance != second.timestamp_provenance
        || first.coverage != second.coverage
        || first.rotation != second.rotation
        || first.terminal_relation != second.terminal_relation
    {
        return Err(format!(
            "{}: reordered scenarios must share identical input state",
            spec.workflow
        ));
    }
    if second.ordered_input_evidence == first.ordered_input_evidence {
        return Err(format!(
            "{}: reordered cases must not present the same order twice",
            spec.workflow
        ));
    }
    let reversed = first
        .ordered_input_evidence
        .iter()
        .rev()
        .cloned()
        .collect::<Vec<_>>();
    if second.ordered_input_evidence != reversed {
        return Err(format!(
            "{}: reordered case B must replay case A's evidence in opposite order",
            spec.workflow
        ));
    }
    if first.expected != second.expected {
        return Err(format!(
            "{}: reordered scenarios must pin one expected result",
            spec.workflow
        ));
    }
    let projection_a = serde_json::to_string(&first.expected_public_projection)
        .expect("expected public projection serializes");
    let projection_b = serde_json::to_string(&second.expected_public_projection)
        .expect("expected public projection serializes");
    if projection_a != projection_b {
        return Err(format!(
            "{}: reordered scenarios must serialize one deterministic public projection",
            spec.workflow
        ));
    }
    Ok(())
}

fn check_guard_matrix(matrix: &GuardMatrix) -> Result<(), String> {
    if matrix.schema_version != CONTRACT_SCHEMA_VERSION {
        return Err(format!(
            "unexpected schema version {}",
            matrix.schema_version
        ));
    }
    let guard_ids = matrix
        .guards
        .iter()
        .map(|guard| guard.guard_id.as_str())
        .collect::<Vec<_>>();
    if guard_ids != GUARD_IDS {
        return Err("shared guard list changed".to_owned());
    }

    for guard in &matrix.guards {
        let guard_id = guard.guard_id.as_str();
        if guard.applies_to != WORKFLOWS {
            return Err(format!("{guard_id}: guard must apply to both first pairs"));
        }
        if guard.forbidden_strengths != ["exactCorroborated"] {
            return Err(format!("{guard_id}: guard must forbid exactCorroborated"));
        }
        if guard.forbidden_confidences != ["high"] {
            return Err(format!("{guard_id}: guard must forbid high confidence"));
        }
        let (_, pinned_outputs) = GUARD_REQUIRED_OUTPUTS
            .iter()
            .find(|(pinned_id, _)| *pinned_id == guard_id)
            .ok_or_else(|| format!("{guard_id}: guard has no pinned output obligations"))?;
        if guard.required_outputs != *pinned_outputs {
            return Err(format!(
                "{guard_id}: required outputs must stay the pinned executable obligations"
            ));
        }
    }
    Ok(())
}

fn check_pair_registry(registry: &PairRegistry) -> Result<(), String> {
    if registry.schema_version != CONTRACT_SCHEMA_VERSION {
        return Err(format!(
            "unexpected schema version {}",
            registry.schema_version
        ));
    }
    let pair_ids = registry
        .pairs
        .iter()
        .map(|pair| pair.pair_id.as_str())
        .collect::<Vec<_>>();
    if pair_ids
        != [
            "content-distribution-point",
            "policy-management-point",
            "updates-software-update-point",
        ]
    {
        return Err("pair registry membership changed".to_owned());
    }

    let mut workflow_states = BTreeMap::new();
    for pair in &registry.pairs {
        let pair_id = pair.pair_id.as_str();
        if !validate_issue(&pair.client_issue) || !validate_issue(&pair.server_issue) {
            return Err(format!("{pair_id}: malformed issue reference"));
        }
        let (_, workflow, client_issue, server_issue) = PAIR_OWNERSHIP
            .iter()
            .find(|(owner_id, _, _, _)| *owner_id == pair_id)
            .ok_or_else(|| format!("{pair_id}: pair has no pinned ownership"))?;
        if pair.workflow != *workflow {
            return Err(format!("{pair_id}: workflow ownership changed"));
        }
        if pair.client_issue != *client_issue || pair.server_issue != *server_issue {
            return Err(format!(
                "{pair_id}: issue ownership must stay {client_issue} to {server_issue}"
            ));
        }
        if pair_id == "content-distribution-point"
            && !pair
                .blockers
                .iter()
                .any(|blocker| blocker == CONTENT_PENDING_BLOCKER)
        {
            return Err(format!(
                "{pair_id}: the #329 pending acceptance blocker must stay declared"
            ));
        }
        if pair.production_enabled {
            return Err(format!("{pair_id}: production must stay disabled"));
        }
        if pair.rule_validated {
            return Err(format!("{pair_id}: no pair may claim RuleValidated"));
        }
        if pair.implementation_module.is_some() {
            return Err(format!("{pair_id}: no implementation module is permitted"));
        }
        if pair.required_guard_ids != GUARD_IDS {
            return Err(format!("{pair_id}: required guard list changed"));
        }
        if pair.blockers.is_empty() || !is_sorted_unique(&pair.blockers) {
            return Err(format!(
                "{pair_id}: blockers must be nonempty, sorted, and unique"
            ));
        }
        workflow_states.insert(pair.workflow.clone(), &pair.state);
    }
    if workflow_states
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != [
            "contentDistributionPoint",
            "policyManagementPoint",
            "updatesSoftwareUpdatePoint",
        ]
        .into_iter()
        .collect()
    {
        return Err("pair registry workflows changed".to_owned());
    }
    if *workflow_states["contentDistributionPoint"] != PairState::ContractPrepared {
        return Err("content pair left ContractPrepared".to_owned());
    }
    if *workflow_states["policyManagementPoint"] != PairState::ContractPrepared {
        return Err("policy pair left ContractPrepared".to_owned());
    }
    if *workflow_states["updatesSoftwareUpdatePoint"] != PairState::Candidate {
        return Err("updates pair must stay Candidate".to_owned());
    }
    Ok(())
}

const POLICY_MATRIX_FIXTURE: &str = "policy_management_point/adversarial-matrix.json";
const CONTENT_MATRIX_FIXTURE: &str = "content_distribution_point/adversarial-matrix.json";

fn check_mutated_matrix(
    fixture: &str,
    spec: &MatrixSpec,
    mutate: impl FnOnce(&mut Value),
) -> Result<(), String> {
    let mut value = read_json(&corpus_root().join(fixture));
    mutate(&mut value);
    let matrix: ScenarioMatrix = typed(value)?;
    check_matrix_contract(&matrix, spec)
}

fn scenario_slot<'a>(matrix: &'a mut Value, scenario_id: &str) -> &'a mut Value {
    matrix["scenarios"]
        .as_array_mut()
        .expect("scenario matrix fixture has a scenarios array")
        .iter_mut()
        .find(|scenario| scenario["scenarioId"] == scenario_id)
        .unwrap_or_else(|| panic!("scenario {scenario_id} exists in the fixture"))
}

fn check_mutated_registry(mutate: impl FnOnce(&mut Value)) -> Result<(), String> {
    let mut value = read_json(&corpus_root().join("pair-registry.json"));
    mutate(&mut value);
    let registry: PairRegistry = typed(value)?;
    check_pair_registry(&registry)
}

fn pair_slot<'a>(registry: &'a mut Value, pair_id: &str) -> &'a mut Value {
    registry["pairs"]
        .as_array_mut()
        .expect("pair registry fixture has a pairs array")
        .iter_mut()
        .find(|pair| pair["pairId"] == pair_id)
        .unwrap_or_else(|| panic!("pair {pair_id} exists in the registry"))
}

#[test]
fn adversarial_fixture_ref_and_ownership_mutations_fail_closed() {
    let error = check_mutated_matrix(CONTENT_MATRIX_FIXTURE, &CONTENT_SPEC, |matrix| {
        scenario_slot(matrix, "content-invalid-offset")["serverFixtureRef"] = Value::String(
            "repo:crates/cmtraceopen-parser/tests/fixtures/sccm/client/deployment/success"
                .to_owned(),
        );
    })
    .expect_err("the pending #329 server corpus cannot be replaced by a merged client corpus");
    assert!(error.contains("content-invalid-offset"), "{error}");

    let error = check_mutated_matrix(CONTENT_MATRIX_FIXTURE, &CONTENT_SPEC, |matrix| {
        scenario_slot(matrix, "content-conflicting-key")["serverFixtureRef"] =
            Value::String("synthetic:content-divergent-server".to_owned());
    })
    .expect_err("the pending #329 server side cannot dodge into a synthetic ref");
    assert!(error.contains("content-conflicting-key"), "{error}");

    let error = check_mutated_matrix(POLICY_MATRIX_FIXTURE, &POLICY_SPEC, |matrix| {
        scenario_slot(matrix, "policy-conflicting-key")["serverFixtureRef"] = Value::String(
            "repo:crates/cmtraceopen-parser/tests/fixtures/sccm/client/policy/complete".to_owned(),
        );
    })
    .expect_err("a server fixture ref cannot cite a client-side corpus directory");
    assert!(error.contains("policy-conflicting-key"), "{error}");

    let error = check_mutated_matrix(POLICY_MATRIX_FIXTURE, &POLICY_SPEC, |matrix| {
        scenario_slot(matrix, "policy-conflicting-key")["serverFixtureRef"] =
            Value::String("issue:#328:healthy-policy".to_owned());
    })
    .expect_err("a merged upstream side cannot claim a pending issue ref");
    assert!(error.contains("policy-conflicting-key"), "{error}");

    let error = check_mutated_registry(|registry| {
        pair_slot(registry, "content-distribution-point")["serverIssue"] =
            Value::String("#328".to_owned());
    })
    .expect_err("the content pair server issue is pinned to #329");
    assert!(error.contains("content-distribution-point"), "{error}");

    let error = check_mutated_registry(|registry| {
        pair_slot(registry, "content-distribution-point")["blockers"] = serde_json::json!([
            "#318 finding interface exact-head review pending",
            "#322 public fact interface not implemented"
        ]);
    })
    .expect_err("the content pair must stay honest about #329 pending acceptance");
    assert!(error.contains("content-distribution-point"), "{error}");
}

#[test]
fn reordered_scenarios_encode_opposite_order_input_evidence() {
    for (fixture, prefix) in [
        (POLICY_MATRIX_FIXTURE, "policy"),
        (CONTENT_MATRIX_FIXTURE, "content"),
    ] {
        let mut matrix = read_json(&corpus_root().join(fixture));
        let first = scenario_slot(&mut matrix, &format!("{prefix}-reordered-input-a")).clone();
        let second = scenario_slot(&mut matrix, &format!("{prefix}-reordered-input-b")).clone();

        let manifest = |scenario: &Value, label: &str| -> Vec<String> {
            scenario["orderedInputEvidence"]
                .as_array()
                .unwrap_or_else(|| panic!("{fixture}: scenario {label} encodes ordered inputs"))
                .iter()
                .map(|entry| {
                    entry
                        .as_str()
                        .unwrap_or_else(|| panic!("{fixture}: {label} evidence entry is a string"))
                        .to_owned()
                })
                .collect()
        };
        let evidence_a = manifest(&first, "a");
        let evidence_b = manifest(&second, "b");

        assert!(
            evidence_a.len() >= 2,
            "{fixture}: too little ordered evidence"
        );
        assert_ne!(
            evidence_a, evidence_b,
            "{fixture}: A and B are not reordered"
        );
        let reversed_a = evidence_a.iter().rev().cloned().collect::<Vec<_>>();
        assert_eq!(
            evidence_b, reversed_a,
            "{fixture}: B must replay A's evidence in opposite order"
        );
        let mut multiset_a = evidence_a.clone();
        let mut multiset_b = evidence_b.clone();
        multiset_a.sort();
        multiset_b.sort();
        assert_eq!(
            multiset_a, multiset_b,
            "{fixture}: A and B must carry the same evidence multiset"
        );
        for side in ["client:", "server:"] {
            assert!(
                evidence_a.iter().any(|entry| entry.starts_with(side)),
                "{fixture}: ordered evidence must include the {side} side"
            );
        }

        for field in [
            "clientFixtureRef",
            "serverFixtureRef",
            "profileState",
            "keyRelation",
            "topology",
            "timestampProvenance",
            "coverage",
            "rotation",
            "terminalRelation",
        ] {
            assert_eq!(
                first[field], second[field],
                "{fixture}: {field} must be identical between A and B"
            );
        }
        for section in ["expected", "expectedPublicProjection"] {
            let serialized_a = serde_json::to_string(&first[section])
                .expect("reordered contract section serializes");
            let serialized_b = serde_json::to_string(&second[section])
                .expect("reordered contract section serializes");
            assert_eq!(
                serialized_a, serialized_b,
                "{fixture}: {section} must serialize deterministically across A and B"
            );
        }
        assert_eq!(
            first["expected"]["deterministicResultId"], second["expected"]["deterministicResultId"],
            "{fixture}: A and B must share one deterministic result id"
        );
    }
}

fn check_mutated_guard_matrix(mutate: impl FnOnce(&mut Value)) -> Result<(), String> {
    let mut value = read_json(&corpus_root().join("shared/adversarial-matrix.json"));
    mutate(&mut value);
    let matrix: GuardMatrix = typed(value)?;
    check_guard_matrix(&matrix)
}

fn guard_slot<'a>(matrix: &'a mut Value, guard_id: &str) -> &'a mut Value {
    matrix["guards"]
        .as_array_mut()
        .expect("guard matrix fixture has a guards array")
        .iter_mut()
        .find(|guard| guard["guardId"] == guard_id)
        .unwrap_or_else(|| panic!("guard {guard_id} exists in the fixture"))
}

#[test]
fn adversarial_required_output_mutations_fail_closed() {
    let error = check_mutated_guard_matrix(|matrix| {
        guard_slot(matrix, "invalid-timestamp-offset")["requiredOutputs"] =
            serde_json::json!(["arbitraryOutput"]);
    })
    .expect_err("required outputs must stay pinned executable obligations, not free strings");
    assert!(error.contains("invalid-timestamp-offset"), "{error}");

    let error = check_mutated_matrix(POLICY_MATRIX_FIXTURE, &POLICY_SPEC, |matrix| {
        scenario_slot(matrix, "policy-invalid-offset")["expectedPublicProjection"] =
            serde_json::json!({ "outcome": "notCausal" });
    })
    .expect_err("dropping the ordering obligation from the projection must fail");
    assert!(error.contains("policy-invalid-offset"), "{error}");

    let error = check_mutated_matrix(POLICY_MATRIX_FIXTURE, &POLICY_SPEC, |matrix| {
        scenario_slot(matrix, "policy-client-only")["expected"]["artifactRequests"] =
            serde_json::json!(["diagnostic-bundle"]);
    })
    .expect_err("a client-only scenario must request server-side artifacts");
    assert!(error.contains("policy-client-only"), "{error}");
}

#[test]
fn adversarial_reordered_input_mutations_fail_closed() {
    let error = check_mutated_matrix(POLICY_MATRIX_FIXTURE, &POLICY_SPEC, |matrix| {
        let order_a =
            scenario_slot(matrix, "policy-reordered-input-a")["orderedInputEvidence"].clone();
        scenario_slot(matrix, "policy-reordered-input-b")["orderedInputEvidence"] = order_a;
    })
    .expect_err("the B case must replay A's evidence in opposite order, not the same order");
    assert!(error.contains("reordered"), "{error}");

    let error = check_mutated_matrix(POLICY_MATRIX_FIXTURE, &POLICY_SPEC, |matrix| {
        scenario_slot(matrix, "policy-reordered-input-b")["clientFixtureRef"] =
            Value::String("synthetic:policy-divergent-client".to_owned());
    })
    .expect_err("the A/B pair must reorder one input set, not compare different inputs");
    assert!(error.contains("reordered"), "{error}");

    let error = check_mutated_matrix(POLICY_MATRIX_FIXTURE, &POLICY_SPEC, |matrix| {
        scenario_slot(matrix, "policy-reordered-input-a")["orderedInputEvidence"] =
            serde_json::json!([]);
    })
    .expect_err("a reordered-input guard without encoded ordered evidence is undemonstrated");
    assert!(error.contains("reordered"), "{error}");

    let error = check_mutated_matrix(POLICY_MATRIX_FIXTURE, &POLICY_SPEC, |matrix| {
        scenario_slot(matrix, "policy-reordered-input-a")["orderedInputEvidence"][0] =
            Value::String("policy-request-assignments".to_owned());
    })
    .expect_err("ordered evidence entries must be side-tagged synthetic tokens");
    assert!(error.contains("reordered"), "{error}");
}

#[test]
fn adversarial_neutralized_guard_state_mutations_fail_closed() {
    let neutralizations: [(&str, &[(&str, &str)]); 9] = [
        ("policy-same-time-no-key", &[("keyRelation", "exact")]),
        ("policy-conflicting-key", &[("keyRelation", "exact")]),
        ("policy-topology-mismatch", &[("topology", "compatible")]),
        ("policy-unknown-profile", &[("profileState", "validated")]),
        (
            "policy-invalid-offset",
            &[("timestampProvenance", "usable")],
        ),
        ("policy-rotation-split", &[("rotation", "complete")]),
        ("policy-partial-capture", &[("coverage", "complete")]),
        (
            "policy-unrelated-terminal-error",
            &[("terminalRelation", "corroborating")],
        ),
        (
            "policy-version-mismatch",
            &[("profileState", "validated"), ("keyRelation", "exact")],
        ),
    ];
    for (scenario_id, edits) in neutralizations {
        let error = check_mutated_matrix(POLICY_MATRIX_FIXTURE, &POLICY_SPEC, |matrix| {
            let scenario = scenario_slot(matrix, scenario_id);
            for (field, neutral) in edits {
                scenario[*field] = Value::String((*neutral).to_owned());
            }
        })
        .expect_err(&format!(
            "{scenario_id}: neutralized inputs cannot keep the guard label green"
        ));
        assert!(error.contains(scenario_id), "{error}");
    }

    let error = check_mutated_matrix(CONTENT_MATRIX_FIXTURE, &CONTENT_SPEC, |matrix| {
        scenario_slot(matrix, "content-client-only")["coverage"] =
            Value::String("complete".to_owned());
    })
    .expect_err("an absent server counterpart cannot claim complete coverage");
    assert!(error.contains("content-client-only"), "{error}");
}

#[test]
fn adversarial_projection_privacy_mutations_fail_closed() {
    let error = check_mutated_matrix(POLICY_MATRIX_FIXTURE, &POLICY_SPEC, |matrix| {
        scenario_slot(matrix, "policy-redaction")["expectedPublicProjection"]["rawIdentity"] =
            Value::String("LAB\\SyntheticUser".to_owned());
    })
    .expect_err("a decoded declared private marker cannot enter the public projection");
    assert!(error.contains("policy-redaction"), "{error}");

    let error = check_mutated_matrix(POLICY_MATRIX_FIXTURE, &POLICY_SPEC, |matrix| {
        scenario_slot(matrix, "policy-invalid-offset")["expectedPublicProjection"]
            ["evidencePath"] = Value::String("C:\\Windows\\CCM\\Logs\\PolicyAgent.log".to_owned());
    })
    .expect_err("an undeclared raw Windows path cannot enter the public projection");
    assert!(error.contains("policy-invalid-offset"), "{error}");

    let error = check_mutated_matrix(POLICY_MATRIX_FIXTURE, &POLICY_SPEC, |matrix| {
        scenario_slot(matrix, "policy-redaction")["expectedPublicProjection"]
            ["LAB\\SyntheticUser"] = Value::Bool(true);
    })
    .expect_err("a decoded private marker cannot hide inside a projection key");
    assert!(error.contains("policy-redaction"), "{error}");
}

#[test]
fn correlation_preparation_contains_no_production_module() {
    assert!(
        !PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src/sccm/correlation")
            .exists(),
        "#333 preparation must not add production correlation before upstream facts stabilize"
    );
}

#[test]
fn shared_false_causality_guards_are_exact_and_pair_complete() {
    let matrix: GuardMatrix = typed(read_json(
        &corpus_root().join("shared/adversarial-matrix.json"),
    ))
    .unwrap_or_else(|error| panic!("{error}"));
    check_guard_matrix(&matrix).unwrap_or_else(|error| panic!("{error}"));
}

#[test]
fn policy_to_management_point_adversarial_matrix_is_conservative() {
    let matrix: ScenarioMatrix = typed(read_json(
        &corpus_root().join("policy_management_point/adversarial-matrix.json"),
    ))
    .unwrap_or_else(|error| panic!("{error}"));
    check_matrix_contract(&matrix, &POLICY_SPEC).unwrap_or_else(|error| panic!("{error}"));
}

#[test]
fn content_to_distribution_point_adversarial_matrix_is_conservative() {
    let matrix: ScenarioMatrix = typed(read_json(
        &corpus_root().join("content_distribution_point/adversarial-matrix.json"),
    ))
    .unwrap_or_else(|error| panic!("{error}"));
    check_matrix_contract(&matrix, &CONTENT_SPEC).unwrap_or_else(|error| panic!("{error}"));
}

#[test]
fn reordered_contracts_pin_identical_expected_results() {
    for path in [
        "policy_management_point/adversarial-matrix.json",
        "content_distribution_point/adversarial-matrix.json",
    ] {
        let matrix: ScenarioMatrix =
            typed(read_json(&corpus_root().join(path))).unwrap_or_else(|error| panic!("{error}"));
        let reordered = matrix
            .scenarios
            .iter()
            .filter(|scenario| scenario.guard_ids.contains(&"reordered-input".to_owned()))
            .collect::<Vec<_>>();
        assert_eq!(reordered.len(), 2, "{path}");
        assert_eq!(reordered[0].expected, reordered[1].expected, "{path}");
        assert_eq!(
            reordered[0].expected_public_projection, reordered[1].expected_public_projection,
            "{path}"
        );
    }
}

#[test]
fn pair_registry_is_non_executable_and_expansion_is_gated() {
    let registry: PairRegistry = typed(read_json(&corpus_root().join("pair-registry.json")))
        .unwrap_or_else(|error| panic!("{error}"));
    check_pair_registry(&registry).unwrap_or_else(|error| panic!("{error}"));
}
