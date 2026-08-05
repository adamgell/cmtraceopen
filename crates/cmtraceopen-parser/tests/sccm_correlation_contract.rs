use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use cmtraceopen_parser::sccm::{
    SCCM_CORRELATION_IMPLEMENTATION_MODULE, SCCM_CORRELATION_SCHEMA_VERSION,
};
use serde::Deserialize;
use serde_json::Value;

const CONTRACT_SCHEMA_VERSION: &str = "1.0.0";
const WORKFLOWS: [&str; 3] = [
    "contentDistributionPoint",
    "policyManagementPoint",
    "updatesSoftwareUpdatePoint",
];
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
const MATRIX_PATHS: [(&str, &str, &str); 3] = [
    (
        "content_distribution_point/adversarial-matrix.json",
        "contentDistributionPoint",
        "content",
    ),
    (
        "policy_management_point/adversarial-matrix.json",
        "policyManagementPoint",
        "policy",
    ),
    (
        "updates_software_update_point/adversarial-matrix.json",
        "updatesSoftwareUpdatePoint",
        "updates",
    ),
];

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
    state: String,
    production_enabled: bool,
    rule_validated: bool,
    implementation_module: String,
    required_guard_ids: Vec<String>,
    blockers: Vec<String>,
}

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
struct OracleMatrix {
    schema_version: String,
    pair: String,
    scenarios: Vec<OracleScenario>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OracleScenario {
    scenario_id: String,
    mutation: String,
    expected_outcome: String,
    expected_link_strength: String,
    expected_confidence: String,
    expected_reason_codes: Vec<String>,
    expected_triggered_guards: Vec<String>,
    expected_output_sha256: String,
}

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sccm/correlation")
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(
        &fs::read(path).unwrap_or_else(|error| panic!("{} is readable: {error}", path.display())),
    )
    .unwrap_or_else(|error| panic!("{} is JSON: {error}", path.display()))
}

fn typed<T: for<'de> Deserialize<'de>>(value: Value) -> Result<T, String> {
    serde_json::from_value(value)
        .map_err(|error| format!("fixture is not typed contract JSON: {error}"))
}

fn sorted_unique(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn valid_issue(value: &str) -> bool {
    value.strip_prefix('#').is_some_and(|digits| {
        !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn check_registry(registry: &PairRegistry) -> Result<(), String> {
    if registry.schema_version != CONTRACT_SCHEMA_VERSION {
        return Err("registry schema version changed".to_owned());
    }
    let expected = [
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
    if registry.pairs.len() != expected.len() {
        return Err("registry must contain exactly three pairs".to_owned());
    }
    for (pair, (pair_id, workflow, client_issue, server_issue)) in
        registry.pairs.iter().zip(expected)
    {
        if (
            pair.pair_id.as_str(),
            pair.workflow.as_str(),
            pair.client_issue.as_str(),
            pair.server_issue.as_str(),
        ) != (pair_id, workflow, client_issue, server_issue)
        {
            return Err(format!("{}: ownership changed", pair.pair_id));
        }
        if !valid_issue(&pair.client_issue) || !valid_issue(&pair.server_issue) {
            return Err(format!("{}: malformed issue ownership", pair.pair_id));
        }
        if pair.state != "ruleValidated"
            || !pair.production_enabled
            || !pair.rule_validated
            || pair.implementation_module != SCCM_CORRELATION_IMPLEMENTATION_MODULE
            || !pair.blockers.is_empty()
        {
            return Err(format!("{}: pair is not production admitted", pair.pair_id));
        }
        if pair.required_guard_ids != GUARD_IDS {
            return Err(format!("{}: guard registry changed", pair.pair_id));
        }
    }
    Ok(())
}

fn check_guard_matrix(matrix: &GuardMatrix) -> Result<(), String> {
    if matrix.schema_version != CONTRACT_SCHEMA_VERSION {
        return Err("guard schema version changed".to_owned());
    }
    if matrix
        .guards
        .iter()
        .map(|guard| guard.guard_id.as_str())
        .collect::<Vec<_>>()
        != GUARD_IDS
    {
        return Err("shared guard membership changed".to_owned());
    }
    for guard in &matrix.guards {
        if guard.applies_to != WORKFLOWS {
            return Err(format!(
                "{}: not applied to all three pairs",
                guard.guard_id
            ));
        }
        let invariant_guard = matches!(
            guard.guard_id.as_str(),
            "redaction-boundary" | "reordered-input"
        );
        let forbidden_contract = if invariant_guard {
            guard.forbidden_strengths.is_empty() && guard.forbidden_confidences.is_empty()
        } else {
            guard.forbidden_strengths == ["exactCorroborated"]
                && guard.forbidden_confidences == ["high"]
        };
        if !forbidden_contract
            || guard.required_outputs.is_empty()
            || !sorted_unique(&guard.required_outputs)
        {
            return Err(format!("{}: guard obligations changed", guard.guard_id));
        }
    }
    Ok(())
}

fn mutation_guard(mutation: &str) -> Option<&'static str> {
    match mutation {
        "conflictingExactKey" => Some("conflicting-exact-key"),
        "incompatibleTopology" => Some("incompatible-topology"),
        "invalidTimestampOffset" => Some("invalid-timestamp-offset"),
        "missingClientCounterpart" => Some("missing-client-counterpart"),
        "missingServerCounterpart" => Some("missing-server-counterpart"),
        "partialCapture" => Some("partial-capture"),
        "redactionBoundary" => Some("redaction-boundary"),
        "reorderedInputA" | "reorderedInputB" => Some("reordered-input"),
        "rotationSplit" => Some("rotation-split"),
        "sameTimeNoKey" => Some("same-time-no-key"),
        "unknownExtractionProfile" => Some("unknown-extraction-profile"),
        "unrelatedTerminalError" => Some("unrelated-terminal-error"),
        "versionMismatch" => Some("version-mismatch"),
        "healthy" => None,
        other => panic!("unknown executable oracle mutation {other}"),
    }
}

fn check_matrix(matrix: &OracleMatrix, workflow: &str, prefix: &str) -> Result<(), String> {
    if matrix.schema_version != CONTRACT_SCHEMA_VERSION || matrix.pair != workflow {
        return Err(format!("{workflow}: matrix identity changed"));
    }
    if matrix.scenarios.len() != 15 {
        return Err(format!(
            "{workflow}: expected healthy plus 14 adversarial cases"
        ));
    }
    let mut scenario_ids = BTreeSet::new();
    let mut guards = BTreeSet::new();
    let mut reordered_hashes = Vec::new();
    for scenario in &matrix.scenarios {
        if !scenario.scenario_id.starts_with(&format!("{prefix}-"))
            || !scenario_ids.insert(scenario.scenario_id.as_str())
        {
            return Err(format!(
                "{}: malformed or duplicate scenario ID",
                scenario.scenario_id
            ));
        }
        if !valid_hash(&scenario.expected_output_sha256) {
            return Err(format!(
                "{}: output hash is not exact SHA-256",
                scenario.scenario_id
            ));
        }
        if !sorted_unique(&scenario.expected_reason_codes)
            || !sorted_unique(&scenario.expected_triggered_guards)
        {
            return Err(format!(
                "{}: expected lists are not deterministic",
                scenario.scenario_id
            ));
        }
        if ![
            "causalFinding",
            "candidateOnly",
            "counterpartRequested",
            "coverageGap",
            "incompatible",
            "notCausal",
            "profileGap",
        ]
        .contains(&scenario.expected_outcome.as_str())
            || ![
                "exactCorroborated",
                "exactPartial",
                "candidate",
                "incompatible",
                "unlinked",
            ]
            .contains(&scenario.expected_link_strength.as_str())
            || !["low", "medium", "high"].contains(&scenario.expected_confidence.as_str())
        {
            return Err(format!(
                "{}: expected output vocabulary changed",
                scenario.scenario_id
            ));
        }
        if let Some(guard) = mutation_guard(&scenario.mutation) {
            guards.insert(guard);
        }
        if scenario.mutation.starts_with("reorderedInput") {
            reordered_hashes.push(scenario.expected_output_sha256.as_str());
        }
        if scenario.expected_link_strength == "exactCorroborated"
            && scenario.expected_confidence != "high"
        {
            return Err(format!(
                "{}: exact link is not high confidence",
                scenario.scenario_id
            ));
        }
        if scenario.expected_confidence == "high"
            && scenario.expected_link_strength != "exactCorroborated"
        {
            return Err(format!(
                "{}: high confidence escaped exact linking",
                scenario.scenario_id
            ));
        }
    }
    if guards != GUARD_IDS.into_iter().collect() {
        return Err(format!(
            "{workflow}: not every shared guard has an executable scenario"
        ));
    }
    if reordered_hashes.len() != 2 || reordered_hashes[0] != reordered_hashes[1] {
        return Err(format!(
            "{workflow}: reordered inputs do not pin identical full output"
        ));
    }
    Ok(())
}

fn check_mutated_registry(mutate: impl FnOnce(&mut Value)) -> Result<(), String> {
    let mut value = read_json(&corpus_root().join("pair-registry.json"));
    mutate(&mut value);
    check_registry(&typed(value)?)
}

fn check_mutated_matrix(
    path: &str,
    workflow: &str,
    prefix: &str,
    mutate: impl FnOnce(&mut Value),
) -> Result<(), String> {
    let mut value = read_json(&corpus_root().join(path));
    mutate(&mut value);
    check_matrix(&typed(value)?, workflow, prefix)
}

#[test]
fn public_module_and_pair_registry_are_production_exact() {
    assert_eq!(SCCM_CORRELATION_SCHEMA_VERSION, 1);
    assert_eq!(SCCM_CORRELATION_IMPLEMENTATION_MODULE, "sccm::correlation");
    let registry: PairRegistry =
        typed(read_json(&corpus_root().join("pair-registry.json"))).expect("typed registry");
    check_registry(&registry).unwrap_or_else(|error| panic!("{error}"));
}

#[test]
fn all_shared_guards_apply_to_all_three_pairs() {
    let matrix: GuardMatrix = typed(read_json(
        &corpus_root().join("shared/adversarial-matrix.json"),
    ))
    .expect("typed guard matrix");
    check_guard_matrix(&matrix).unwrap_or_else(|error| panic!("{error}"));
}

#[test]
fn all_three_pair_matrices_are_exact_executable_oracles() {
    for (path, workflow, prefix) in MATRIX_PATHS {
        let matrix: OracleMatrix =
            typed(read_json(&corpus_root().join(path))).expect("typed pair matrix");
        check_matrix(&matrix, workflow, prefix).unwrap_or_else(|error| panic!("{error}"));
    }
}

#[test]
fn production_registry_mutations_fail_closed() {
    let error = check_mutated_registry(|registry| {
        registry["pairs"][0]["productionEnabled"] = Value::Bool(false);
    })
    .expect_err("production disablement cannot remain admitted");
    assert!(error.contains("production admitted"), "{error}");

    let error = check_mutated_registry(|registry| {
        registry["pairs"][1]["implementationModule"] = Value::String("sccm::other".to_owned());
    })
    .expect_err("module ownership cannot drift");
    assert!(error.contains("production admitted"), "{error}");

    let error = check_mutated_registry(|registry| {
        registry["pairs"][2]["requiredGuardIds"]
            .as_array_mut()
            .expect("guard list")
            .pop();
    })
    .expect_err("no pair may omit a shared guard");
    assert!(error.contains("guard registry"), "{error}");
}

#[test]
fn exact_oracle_hash_and_reordering_mutations_fail_closed() {
    let (path, workflow, prefix) = MATRIX_PATHS[0];
    let error = check_mutated_matrix(path, workflow, prefix, |matrix| {
        matrix["scenarios"][0]["expectedOutputSha256"] = Value::String("not-a-hash".to_owned());
    })
    .expect_err("malformed full-output hash cannot pass");
    assert!(error.contains("SHA-256"), "{error}");

    let error = check_mutated_matrix(path, workflow, prefix, |matrix| {
        let first = matrix["scenarios"][8]["expectedOutputSha256"].clone();
        matrix["scenarios"][9]["expectedOutputSha256"] = Value::String(format!(
            "{}0",
            first.as_str().expect("hash").trim_end_matches('0')
        ));
    })
    .expect_err("opposite orders must retain the same full-output hash");
    assert!(error.contains("reordered"), "{error}");
}

#[test]
fn guard_matrix_scope_mutation_fails_closed() {
    let mut value = read_json(&corpus_root().join("shared/adversarial-matrix.json"));
    value["guards"][0]["appliesTo"]
        .as_array_mut()
        .expect("appliesTo")
        .pop();
    let matrix: GuardMatrix = typed(value).expect("typed mutated guard matrix");
    let error = check_guard_matrix(&matrix).expect_err("two-pair scope cannot pass");
    assert!(error.contains("all three pairs"), "{error}");
}
