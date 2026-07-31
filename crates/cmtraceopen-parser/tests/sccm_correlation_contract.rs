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

fn read_typed<T: for<'de> Deserialize<'de>>(path: &Path) -> T {
    let contents = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{} is readable: {error}", path.display()));
    serde_json::from_str(&contents)
        .unwrap_or_else(|error| panic!("{} is typed JSON: {error}", path.display()))
}

fn is_sorted_unique(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn validate_issue(value: &str) -> bool {
    value.strip_prefix('#').is_some_and(|digits| {
        !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn validate_fixture_ref(value: &str, issue: &str) -> bool {
    if value == "absent" {
        return true;
    }
    if let Some(path) = value.strip_prefix("repo:") {
        return !path.contains("..") && repo_root().join(path).is_dir();
    }
    if let Some(synthetic_id) = value.strip_prefix("synthetic:") {
        return !synthetic_id.is_empty()
            && synthetic_id
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    }
    if let Some(pending) = value.strip_prefix("issue:") {
        return pending
            .strip_prefix(issue)
            .and_then(|rest| rest.strip_prefix(':'))
            .is_some_and(|scenario| {
                !scenario.is_empty()
                    && scenario.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            });
    }
    false
}

fn assert_matrix_contract(
    matrix: &ScenarioMatrix,
    expected_workflow: &str,
    expected_scenarios: &[&str],
    client_issue: &str,
    server_issue: &str,
) {
    assert_eq!(matrix.schema_version, CONTRACT_SCHEMA_VERSION);
    assert_eq!(matrix.workflow, expected_workflow);
    let scenario_ids = matrix
        .scenarios
        .iter()
        .map(|scenario| scenario.scenario_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(scenario_ids, expected_scenarios);

    let mut exercised_guards = BTreeSet::new();
    for scenario in &matrix.scenarios {
        assert_eq!(
            scenario.client_issue, client_issue,
            "{}",
            scenario.scenario_id
        );
        assert_eq!(
            scenario.server_issue, server_issue,
            "{}",
            scenario.scenario_id
        );
        assert!(validate_issue(&scenario.client_issue));
        assert!(validate_issue(&scenario.server_issue));
        assert!(
            validate_fixture_ref(&scenario.client_fixture_ref, &scenario.client_issue),
            "{}: invalid client fixture ref {}",
            scenario.scenario_id,
            scenario.client_fixture_ref
        );
        assert!(
            validate_fixture_ref(&scenario.server_fixture_ref, &scenario.server_issue),
            "{}: invalid server fixture ref {}",
            scenario.scenario_id,
            scenario.server_fixture_ref
        );
        assert!(
            !scenario.guard_ids.is_empty() && is_sorted_unique(&scenario.guard_ids),
            "{}: guard IDs must be nonempty, sorted, and unique",
            scenario.scenario_id
        );
        assert!(
            scenario
                .guard_ids
                .iter()
                .all(|guard| GUARD_IDS.contains(&guard.as_str())),
            "{}: unknown guard",
            scenario.scenario_id
        );
        exercised_guards.extend(scenario.guard_ids.iter().map(String::as_str));
        assert!(
            !scenario.expected.high_confidence_cause_allowed,
            "{}: adversarial fixture cannot permit high-confidence cause",
            scenario.scenario_id
        );
        assert!(
            !scenario.expected.exact_corroborated_allowed,
            "{}: adversarial fixture cannot permit ExactCorroborated",
            scenario.scenario_id
        );
        assert!(!scenario.expected.source_findings_mutable);
        assert_ne!(scenario.expected.link_strength_ceiling, "exactCorroborated");
        assert_ne!(scenario.expected.confidence_ceiling, "high");
        assert!(["candidate", "exactPartial", "incompatible", "unlinked"]
            .contains(&scenario.expected.link_strength_ceiling.as_str()));
        assert!(["low", "medium"].contains(&scenario.expected.confidence_ceiling.as_str()));
        assert!(
            !scenario.expected.reason_codes.is_empty()
                && is_sorted_unique(&scenario.expected.reason_codes)
        );
        assert!(is_sorted_unique(&scenario.expected.artifact_requests));
        assert!(!scenario.expected.deterministic_result_id.is_empty());

        let public_json = serde_json::to_string(&scenario.expected_public_projection)
            .expect("expected public projection serializes");
        for marker in &scenario.private_input_markers {
            assert!(
                !public_json.contains(marker),
                "{}: private marker leaked into expected public projection",
                scenario.scenario_id
            );
        }
        assert_eq!(
            scenario.private_input_markers.is_empty(),
            !scenario
                .guard_ids
                .contains(&"redaction-boundary".to_owned()),
            "{}: private markers and the redaction guard must be declared together",
            scenario.scenario_id
        );

        if scenario.profile_state != ProfileState::Validated {
            assert!(scenario
                .guard_ids
                .iter()
                .any(|guard| guard == "unknown-extraction-profile" || guard == "version-mismatch"));
        }
        if scenario.key_relation == KeyRelation::Missing {
            assert!(scenario.guard_ids.contains(&"same-time-no-key".to_owned()));
        }
        if scenario.key_relation == KeyRelation::Conflicting {
            assert!(scenario
                .guard_ids
                .contains(&"conflicting-exact-key".to_owned()));
        }
        if scenario.key_relation == KeyRelation::VersionMismatch {
            assert!(scenario.guard_ids.contains(&"version-mismatch".to_owned()));
        }
        if scenario.topology == TopologyState::Incompatible {
            assert!(scenario
                .guard_ids
                .contains(&"incompatible-topology".to_owned()));
        }
        if scenario.timestamp_provenance == TimestampState::InvalidOffset {
            assert!(scenario
                .guard_ids
                .contains(&"invalid-timestamp-offset".to_owned()));
        }
        if scenario.coverage == CoverageState::ClientOnly {
            assert!(scenario
                .guard_ids
                .contains(&"missing-server-counterpart".to_owned()));
            assert!(!scenario.expected.artifact_requests.is_empty());
        }
        if scenario.coverage == CoverageState::ServerOnly {
            assert!(scenario
                .guard_ids
                .contains(&"missing-client-counterpart".to_owned()));
            assert!(!scenario.expected.artifact_requests.is_empty());
        }
        if scenario.coverage == CoverageState::Partial {
            assert!(scenario.guard_ids.contains(&"partial-capture".to_owned()));
        }
        if scenario.rotation == RotationState::Split {
            assert!(scenario.guard_ids.contains(&"rotation-split".to_owned()));
        }
        if scenario.terminal_relation == TerminalRelation::Unrelated {
            assert!(scenario
                .guard_ids
                .contains(&"unrelated-terminal-error".to_owned()));
        }
    }
    assert_eq!(
        exercised_guards,
        GUARD_IDS.into_iter().collect(),
        "{expected_workflow}: every shared guard needs a pair-specific adversarial scenario"
    );
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
    let matrix: GuardMatrix = read_typed(&corpus_root().join("shared/adversarial-matrix.json"));
    assert_eq!(matrix.schema_version, CONTRACT_SCHEMA_VERSION);
    let guard_ids = matrix
        .guards
        .iter()
        .map(|guard| guard.guard_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(guard_ids, GUARD_IDS);

    for guard in matrix.guards {
        assert_eq!(guard.applies_to, WORKFLOWS);
        assert_eq!(guard.forbidden_strengths, ["exactCorroborated"]);
        assert_eq!(guard.forbidden_confidences, ["high"]);
        assert!(!guard.required_outputs.is_empty());
        assert!(is_sorted_unique(&guard.required_outputs));
    }
}

#[test]
fn policy_to_management_point_adversarial_matrix_is_conservative() {
    let matrix: ScenarioMatrix =
        read_typed(&corpus_root().join("policy_management_point/adversarial-matrix.json"));
    assert_matrix_contract(
        &matrix,
        "policyManagementPoint",
        &POLICY_SCENARIOS,
        "#321",
        "#328",
    );
}

#[test]
fn content_to_distribution_point_adversarial_matrix_is_conservative() {
    let matrix: ScenarioMatrix =
        read_typed(&corpus_root().join("content_distribution_point/adversarial-matrix.json"));
    assert_matrix_contract(
        &matrix,
        "contentDistributionPoint",
        &CONTENT_SCENARIOS,
        "#322",
        "#329",
    );
}

#[test]
fn reordered_contracts_pin_identical_expected_results() {
    for path in [
        "policy_management_point/adversarial-matrix.json",
        "content_distribution_point/adversarial-matrix.json",
    ] {
        let matrix: ScenarioMatrix = read_typed(&corpus_root().join(path));
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
    let registry: PairRegistry = read_typed(&corpus_root().join("pair-registry.json"));
    assert_eq!(registry.schema_version, CONTRACT_SCHEMA_VERSION);
    let pair_ids = registry
        .pairs
        .iter()
        .map(|pair| pair.pair_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        pair_ids,
        [
            "content-distribution-point",
            "policy-management-point",
            "updates-software-update-point",
        ]
    );

    let mut workflow_states = BTreeMap::new();
    for pair in registry.pairs {
        assert!(validate_issue(&pair.client_issue));
        assert!(validate_issue(&pair.server_issue));
        assert!(!pair.production_enabled);
        assert!(!pair.rule_validated);
        assert!(pair.implementation_module.is_none());
        assert_eq!(pair.required_guard_ids, GUARD_IDS);
        assert!(!pair.blockers.is_empty());
        assert!(is_sorted_unique(&pair.blockers));
        workflow_states.insert(pair.workflow, pair.state);
    }
    assert_eq!(
        workflow_states
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        [
            "contentDistributionPoint",
            "policyManagementPoint",
            "updatesSoftwareUpdatePoint",
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(
        workflow_states["contentDistributionPoint"],
        PairState::ContractPrepared
    );
    assert_eq!(
        workflow_states["policyManagementPoint"],
        PairState::ContractPrepared
    );
    assert_eq!(
        workflow_states["updatesSoftwareUpdatePoint"],
        PairState::Candidate
    );
}
