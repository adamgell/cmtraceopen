use cmtraceopen_parser::{
    models::log_entry::LogFormat,
    parser::{parse_content_with_selection, ResolvedParser},
};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

const STATE_CHAIN: [&str; 8] = [
    "scan",
    "evaluate",
    "locateSup",
    "download",
    "maintenanceWindow",
    "install",
    "reboot",
    "report",
];
const EXPECTED_ARTIFACTS: usize = 51;
const EXPECTED_PHYSICAL_FILES: usize = 43;
const EXPECTED_CORPUS_FNV1A64: u64 = 0x1ff6_72e5_1adb_eb52;
const EXPECTED_CAPPED_CONTENT: &[u8] = b"<![LOG[SYNTHETIC FIXTURE updates capped: ContentId=CONTENT-UPDATE-CAP-001 error-looking 0x80000001 coverage only]LOG]!><time=\"1\n";

#[derive(Clone, Copy)]
struct ScenarioContract {
    name: &'static str,
    transactions: usize,
    observations: usize,
    findings: usize,
    phase: Option<&'static str>,
    state: &'static str,
    classification: &'static str,
    confidence_ceiling: &'static str,
    last_successful_phase: Option<&'static str>,
    next_artifact: Option<&'static str>,
    coverage: &'static [(&'static str, &'static str)],
    counterpart_facts: usize,
}

const SCENARIOS: [ScenarioContract; 17] = [
    ScenarioContract {
        name: "access-denied",
        transactions: 1,
        observations: 0,
        findings: 1,
        phase: Some("install"),
        state: "incomplete",
        classification: "insufficientEvidence",
        confidence_ceiling: "medium",
        last_successful_phase: Some("scan"),
        next_artifact: Some("client-updates"),
        coverage: &[("client-updates", "accessDenied")],
        counterpart_facts: 0,
    },
    ScenarioContract {
        name: "capped",
        transactions: 1,
        observations: 0,
        findings: 1,
        phase: Some("download"),
        state: "incomplete",
        classification: "insufficientEvidence",
        confidence_ceiling: "medium",
        last_successful_phase: Some("locateSup"),
        next_artifact: Some("client-content"),
        coverage: &[("client-content", "capped")],
        counterpart_facts: 1,
    },
    ScenarioContract {
        name: "content-failure",
        transactions: 1,
        observations: 0,
        findings: 1,
        phase: Some("download"),
        state: "failed",
        classification: "confirmedFailure",
        confidence_ceiling: "high",
        last_successful_phase: Some("locateSup"),
        next_artifact: None,
        coverage: &[
            ("client-content", "captured"),
            ("client-location-services-shared", "captured"),
            ("client-updates", "captured"),
        ],
        counterpart_facts: 1,
    },
    ScenarioContract {
        name: "evaluation-failure",
        transactions: 1,
        observations: 0,
        findings: 1,
        phase: Some("evaluate"),
        state: "failed",
        classification: "confirmedFailure",
        confidence_ceiling: "high",
        last_successful_phase: Some("scan"),
        next_artifact: None,
        coverage: &[("client-updates", "captured")],
        counterpart_facts: 0,
    },
    ScenarioContract {
        name: "incomplete",
        transactions: 1,
        observations: 0,
        findings: 1,
        phase: Some("maintenanceWindow"),
        state: "incomplete",
        classification: "insufficientEvidence",
        confidence_ceiling: "medium",
        last_successful_phase: Some("download"),
        next_artifact: Some("client-maintenance-window"),
        coverage: &[
            ("client-maintenance-window", "absent"),
            ("client-policy-state", "absent"),
            ("client-reboot", "absent"),
            ("client-updates", "captured"),
        ],
        counterpart_facts: 0,
    },
    ScenarioContract {
        name: "install-failure",
        transactions: 1,
        observations: 0,
        findings: 1,
        phase: Some("install"),
        state: "failed",
        classification: "confirmedFailure",
        confidence_ceiling: "high",
        last_successful_phase: Some("maintenanceWindow"),
        next_artifact: None,
        coverage: &[
            ("client-content", "captured"),
            ("client-location-services-shared", "captured"),
            ("client-updates", "captured"),
        ],
        counterpart_facts: 1,
    },
    ScenarioContract {
        name: "invalid-offset",
        transactions: 1,
        observations: 0,
        findings: 1,
        phase: Some("evaluate"),
        state: "contradictory",
        classification: "insufficientEvidence",
        confidence_ceiling: "low",
        last_successful_phase: Some("scan"),
        next_artifact: Some("client-updates"),
        coverage: &[("client-updates", "captured")],
        counterpart_facts: 0,
    },
    ScenarioContract {
        name: "maintenance-window",
        transactions: 1,
        observations: 0,
        findings: 1,
        phase: Some("maintenanceWindow"),
        state: "blockedOrDeferred",
        classification: "blockedOrDeferred",
        confidence_ceiling: "medium",
        last_successful_phase: Some("download"),
        next_artifact: Some("client-maintenance-window"),
        coverage: &[
            ("client-content", "captured"),
            ("client-location-services-shared", "captured"),
            ("client-maintenance-window", "captured"),
            ("client-updates", "captured"),
        ],
        counterpart_facts: 1,
    },
    ScenarioContract {
        name: "malformed",
        transactions: 0,
        observations: 1,
        findings: 1,
        phase: None,
        state: "malformed",
        classification: "lowConfidenceSymptom",
        confidence_ceiling: "low",
        last_successful_phase: None,
        next_artifact: Some("client-updates"),
        coverage: &[
            ("client-updates", "parseFailed"),
            ("client-windows-update-supplemental", "unsupported"),
        ],
        counterpart_facts: 0,
    },
    ScenarioContract {
        name: "no-sup",
        transactions: 1,
        observations: 0,
        findings: 1,
        phase: Some("locateSup"),
        state: "incomplete",
        classification: "insufficientEvidence",
        confidence_ceiling: "medium",
        last_successful_phase: Some("evaluate"),
        next_artifact: Some("client-location-services-shared"),
        coverage: &[
            ("client-location-services-shared", "absent"),
            ("client-updates", "captured"),
        ],
        counterpart_facts: 0,
    },
    ScenarioContract {
        name: "reboot-pending",
        transactions: 1,
        observations: 0,
        findings: 1,
        phase: Some("reboot"),
        state: "blockedOrDeferred",
        classification: "blockedOrDeferred",
        confidence_ceiling: "medium",
        last_successful_phase: Some("install"),
        next_artifact: Some("client-reboot"),
        coverage: &[
            ("client-location-services-shared", "captured"),
            ("client-reboot", "captured"),
            ("client-updates", "captured"),
        ],
        counterpart_facts: 1,
    },
    ScenarioContract {
        name: "reporting-failure",
        transactions: 1,
        observations: 0,
        findings: 1,
        phase: Some("report"),
        state: "failed",
        classification: "confirmedFailure",
        confidence_ceiling: "high",
        last_successful_phase: Some("reboot"),
        next_artifact: None,
        coverage: &[
            ("client-location-services-shared", "captured"),
            ("client-policy-state", "captured"),
            ("client-updates", "captured"),
        ],
        counterpart_facts: 1,
    },
    ScenarioContract {
        name: "rotation-boundary",
        transactions: 0,
        observations: 1,
        findings: 1,
        phase: None,
        state: "incomplete",
        classification: "insufficientEvidence",
        confidence_ceiling: "low",
        last_successful_phase: None,
        next_artifact: Some("client-updates"),
        coverage: &[("client-updates", "partial")],
        counterpart_facts: 0,
    },
    ScenarioContract {
        name: "same-minute-separate",
        transactions: 2,
        observations: 0,
        findings: 1,
        phase: Some("report"),
        state: "succeeded",
        classification: "success",
        confidence_ceiling: "high",
        last_successful_phase: Some("report"),
        next_artifact: None,
        coverage: &[("client-updates", "captured")],
        counterpart_facts: 0,
    },
    ScenarioContract {
        name: "scan-failure",
        transactions: 1,
        observations: 0,
        findings: 1,
        phase: Some("scan"),
        state: "failed",
        classification: "confirmedFailure",
        confidence_ceiling: "high",
        last_successful_phase: None,
        next_artifact: None,
        coverage: &[("client-updates", "captured")],
        counterpart_facts: 0,
    },
    ScenarioContract {
        name: "success",
        transactions: 1,
        observations: 0,
        findings: 0,
        phase: Some("report"),
        state: "succeeded",
        classification: "success",
        confidence_ceiling: "high",
        last_successful_phase: Some("report"),
        next_artifact: None,
        coverage: &[
            ("client-content", "captured"),
            ("client-location-services-shared", "captured"),
            ("client-maintenance-window", "captured"),
            ("client-policy-state", "captured"),
            ("client-reboot", "captured"),
            ("client-updates", "captured"),
            ("client-windows-update-supplemental", "skipped"),
        ],
        counterpart_facts: 1,
    },
    ScenarioContract {
        name: "supplemental-conflict",
        transactions: 1,
        observations: 1,
        findings: 1,
        phase: Some("install"),
        state: "contradictory",
        classification: "lowConfidenceSymptom",
        confidence_ceiling: "low",
        last_successful_phase: Some("install"),
        next_artifact: Some("client-windows-update-supplemental"),
        coverage: &[
            ("client-updates", "captured"),
            ("client-windows-update-supplemental", "captured"),
        ],
        counterpart_facts: 0,
    },
];

fn updates_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sccm/client/updates")
}

fn read_json(path: &Path) -> Value {
    let contents = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{} must be readable: {error}", path.display()));
    serde_json::from_str(&contents)
        .unwrap_or_else(|error| panic!("{} must contain valid JSON: {error}", path.display()))
}

fn scenario_directories() -> Vec<String> {
    let mut scenarios = std::fs::read_dir(updates_root())
        .expect("the #323 updates fixture root must exist")
        .map(|entry| entry.expect("updates directory entry is readable").path())
        .filter(|path| path.is_dir())
        .map(|path| {
            path.file_name()
                .expect("scenario directory has a name")
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    scenarios.sort();
    scenarios
}

fn json_string(value: &Value, field: &str) -> String {
    value[field]
        .as_str()
        .unwrap_or_else(|| panic!("{field} must be a string"))
        .to_owned()
}

fn optional_json_string(value: &Value, field: &str) -> Option<String> {
    value[field].as_str().map(str::to_owned)
}

fn sorted_strings(values: &Value, field: &str) -> Vec<String> {
    values[field]
        .as_array()
        .unwrap_or_else(|| panic!("{field} must be an array"))
        .iter()
        .map(|value| {
            value
                .as_str()
                .unwrap_or_else(|| panic!("{field} values must be strings"))
                .to_owned()
        })
        .collect()
}

fn subject<'a>(expected: &'a Value, contract: &ScenarioContract) -> &'a Value {
    if contract.observations > 0 {
        &expected["sourceLocalObservations"][0]
    } else {
        &expected["transactions"][0]
    }
}

fn expected_boundary_failures(expected: &Value, contract: &ScenarioContract) -> Vec<String> {
    let mut failures = Vec::new();
    let scenario = contract.name;

    if expected["contractState"] != "proposedPending318" {
        failures.push(format!(
            "{scenario}: contractState must remain proposedPending318"
        ));
    }
    if expected["workflow"] != "updates" || expected["scenario"] != scenario {
        failures.push(format!("{scenario}: workflow/scenario identity drifted"));
    }
    let state_chain = sorted_strings(expected, "stateChain");
    if state_chain != STATE_CHAIN {
        failures.push(format!("{scenario}: state chain drifted: {state_chain:?}"));
    }
    let analysis = &expected["analysisContract"];
    if analysis["independentReducer"] != true
        || analysis["consumesOtherReducerOutput"] != false
        || analysis["policyOutputRequired"] != false
        || analysis["crossSideCorrelationPerformed"] != false
    {
        failures.push(format!(
            "{scenario}: reducer must remain independent and client-only"
        ));
    }
    if expected["reorderedInputDeterministic"] != true {
        failures.push(format!(
            "{scenario}: input reordering must be deterministic"
        ));
    }

    let transactions = expected["transactions"]
        .as_array()
        .expect("transactions must be an array");
    let observations = expected["sourceLocalObservations"]
        .as_array()
        .expect("sourceLocalObservations must be an array");
    let findings = expected["findings"]
        .as_array()
        .expect("findings must be an array");
    if transactions.len() != contract.transactions
        || observations.len() != contract.observations
        || findings.len() != contract.findings
    {
        failures.push(format!(
            "{scenario}: expected {}/{}/{} transactions/observations/findings, got {}/{}/{}",
            contract.transactions,
            contract.observations,
            contract.findings,
            transactions.len(),
            observations.len(),
            findings.len()
        ));
    }
    let transaction_ids = transactions
        .iter()
        .map(|transaction| json_string(transaction, "transactionId"))
        .collect::<Vec<_>>();
    let mut sorted_transaction_ids = transaction_ids.clone();
    sorted_transaction_ids.sort();
    if transaction_ids != sorted_transaction_ids
        || transaction_ids.iter().collect::<BTreeSet<_>>().len() != transaction_ids.len()
    {
        failures.push(format!(
            "{scenario}: transaction IDs must be unique and sorted"
        ));
    }
    for transaction in transactions {
        if transaction["key"]["confidence"] != "exact"
            || transaction["key"]["extractionProfileId"] != "updates-client-5.00.test-v1"
            || transaction["evidence"].as_array().is_none_or(Vec::is_empty)
        {
            failures.push(format!(
                "{scenario}: every transaction needs an exact profiled key and evidence"
            ));
        }
    }
    for observation in observations {
        if !observation["key"].is_null()
            || observation["keyConfidence"] != "none"
            || observation["correlationEligible"] != false
            || observation["evidence"].as_array().is_none_or(Vec::is_empty)
        {
            failures.push(format!(
                "{scenario}: source-local observations must stay keyless and uncorrelatable"
            ));
        }
    }
    let subject_ids = transactions
        .iter()
        .map(|transaction| json_string(transaction, "transactionId"))
        .chain(
            observations
                .iter()
                .map(|observation| json_string(observation, "observationId")),
        )
        .collect::<BTreeSet<_>>();
    for finding in findings {
        let subject_id = json_string(finding, "subjectId");
        if !subject_ids.contains(&subject_id)
            || finding["evidence"].as_array().is_none_or(Vec::is_empty)
            || (finding["class"] == "confirmedFailure"
                && (finding["confidence"] != "high" || finding["confidenceCeiling"] != "high"))
        {
            failures.push(format!(
                "{scenario}: findings must cite a known subject/evidence and validate terminal confidence"
            ));
        }
    }

    if contract.transactions + contract.observations > 0 {
        let subject = subject(expected, contract);
        if optional_json_string(subject, "phase").as_deref() != contract.phase
            || json_string(subject, "state") != contract.state
            || json_string(subject, "classification") != contract.classification
            || json_string(subject, "confidenceCeiling") != contract.confidence_ceiling
            || optional_json_string(subject, "lastSuccessfulPhase").as_deref()
                != contract.last_successful_phase
        {
            failures.push(format!("{scenario}: primary subject outcome drifted"));
        }
        let next_artifact = subject["nextArtifact"]["logicalArtifactId"].as_str();
        if next_artifact != contract.next_artifact {
            failures.push(format!(
                "{scenario}: expected next artifact {:?}, got {next_artifact:?}",
                contract.next_artifact
            ));
        }
    }

    let coverage = expected["coverage"]
        .as_array()
        .expect("coverage must be an array");
    let coverage_ids = coverage
        .iter()
        .map(|entry| json_string(entry, "logicalArtifactId"))
        .collect::<Vec<_>>();
    let mut sorted_coverage_ids = coverage_ids.clone();
    sorted_coverage_ids.sort();
    if coverage_ids != sorted_coverage_ids {
        failures.push(format!("{scenario}: coverage must be sorted"));
    }
    for (logical_id, state) in contract.coverage {
        if !coverage
            .iter()
            .any(|entry| entry["logicalArtifactId"] == *logical_id && entry["state"] == *state)
        {
            failures.push(format!("{scenario}: missing coverage {logical_id}={state}"));
        }
    }

    let handoff = &expected["correlationHandoff"];
    let facts = handoff["counterpartReadyFacts"]
        .as_array()
        .expect("counterpartReadyFacts must be an array");
    if handoff["issue"] != "#333"
        || handoff["serverPrerequisiteIssue"] != "#330"
        || handoff["performed"] != false
        || handoff["timeOnlyEligible"] != false
        || handoff["topologyCompatibilityEvaluated"] != false
        || handoff["serverCauseClaimed"] != false
        || handoff["nativeAcceptanceClaimed"] != false
        || facts.len() != contract.counterpart_facts
        || handoff["emittedCounterpartReadyFact"] != (contract.counterpart_facts > 0)
    {
        failures.push(format!("{scenario}: correlation handoff boundary drifted"));
    }
    for fact in facts {
        if fact["keyConfidence"] != "exact"
            || fact["correlationEligible"] != true
            || fact["timeOnlyEligible"] != false
            || fact["extractionProfileId"] != "updates-client-5.00.test-v1"
            || fact["siteCode"] != "LAB"
            || !fact["clientHandle"]
                .as_str()
                .is_some_and(|value| value.starts_with("safe:client:updates-"))
            || !fact["supHostHandle"]
                .as_str()
                .is_some_and(|value| value.starts_with("safe:sup:lab-"))
        {
            failures.push(format!(
                "{scenario}: counterpart fact is not exact/profile-qualified"
            ));
        }
        if fact["evidence"]["artifactId"].as_str().is_none()
            || fact["evidence"]["startLine"].as_u64().is_none()
            || fact["evidence"]["endLine"].as_u64().is_none()
        {
            failures.push(format!(
                "{scenario}: counterpart fact must cite exact physical evidence"
            ));
        }
    }

    let prohibited = sorted_strings(expected, "prohibitedClaims").join("\n");
    for required in [
        "SUP or server root cause",
        "time-only cross-artifact causality",
        "policy reducer dependency",
        "native Windows acceptance",
    ] {
        if !prohibited.contains(required) {
            failures.push(format!(
                "{scenario}: prohibited claims must include {required:?}"
            ));
        }
    }

    let profile = &expected["extractionProfile"];
    if scenario == "malformed" {
        if profile["selectionState"] != "unvalidatedVersion"
            || !profile["profileId"].is_null()
            || !profile["sourceVersionPrefix"].is_null()
        {
            failures.push(
                "malformed: unknown source version must not select an extraction profile"
                    .to_owned(),
            );
        }
    } else if profile["selectionState"] != "selected"
        || profile["profileId"] != "updates-client-5.00.test-v1"
        || profile["sourceVersionPrefix"] != "5.00.TEST."
    {
        failures.push(format!(
            "{scenario}: selected synthetic profile identity drifted"
        ));
    }
    if scenario == "invalid-offset"
        && (transactions[0]["ordering"]["crossArtifactComparable"] != false
            || transactions[0]["ordering"]["highConfidenceEligible"] != false
            || transactions[0]["ordering"]["reason"] != "invalidOffset")
    {
        failures.push(
            "invalid-offset: invalid provenance must disable cross-artifact high confidence"
                .to_owned(),
        );
    }
    if scenario == "same-minute-separate" {
        let update_ids = transactions
            .iter()
            .map(|transaction| json_string(&transaction["key"], "updateId"))
            .collect::<BTreeSet<_>>();
        if update_ids.len() != 2 {
            failures.push(
                "same-minute-separate: exact update keys must remain two transactions".to_owned(),
            );
        }
    }
    if scenario == "supplemental-conflict"
        && (transactions[0]["state"] != "succeeded"
            || observations[0]["keyConfidence"] != "none"
            || observations[0]["confidenceCeiling"] != "low")
    {
        failures.push(
            "supplemental-conflict: unkeyed CBS evidence cannot override client success".to_owned(),
        );
    }

    failures
}

fn counterpart_source_failures(
    scenario_dir: &Path,
    manifest: &Value,
    expected: &Value,
) -> Vec<String> {
    let mut failures = Vec::new();
    let Some(artifacts) = manifest["artifacts"].as_array() else {
        return vec!["manifest artifacts must be an array".to_owned()];
    };
    let Some(facts) = expected["correlationHandoff"]["counterpartReadyFacts"].as_array() else {
        return vec!["counterpartReadyFacts must be an array".to_owned()];
    };

    for fact in facts {
        let Some(artifact_id) = fact["evidence"]["artifactId"].as_str() else {
            failures.push(
                "counterpart fact needs explicit LocationServices LocateSup evidence".to_owned(),
            );
            continue;
        };
        let Some(artifact) = artifacts
            .iter()
            .find(|artifact| artifact["artifactId"] == artifact_id)
        else {
            failures.push(format!(
                "{artifact_id}: counterpart fact needs explicit LocationServices LocateSup evidence"
            ));
            continue;
        };
        let is_complete_location_source = artifact["designOnlyCatalog"]["entryId"]
            == "client-location-services-shared"
            && artifact["kind"] == "ccmLog"
            && artifact["captureState"] == "captured"
            && artifact["rotation"]["fragmentComplete"] == true
            && artifact["originalBasename"] == "LocationServices.log";
        let start_line = fact["evidence"]["startLine"].as_u64();
        let end_line = fact["evidence"]["endLine"].as_u64();
        let Some(relative_path) = artifact["relativePath"].as_str() else {
            failures.push(format!(
                "{artifact_id}: counterpart fact needs explicit LocationServices LocateSup evidence"
            ));
            continue;
        };
        let cited_line = start_line
            .filter(|line| Some(*line) == end_line && *line > 0)
            .and_then(|line| {
                std::fs::read_to_string(scenario_dir.join(relative_path))
                    .ok()?
                    .lines()
                    .nth((line - 1) as usize)
                    .map(str::to_owned)
            });
        let direct_markers = [
            format!(
                "UpdateId={{{}}}",
                fact["updateId"].as_str().unwrap_or_default()
            ),
            format!("CiId={}", fact["ciId"].as_str().unwrap_or_default()),
            format!(
                "ContentId={}",
                fact["contentId"].as_str().unwrap_or_default()
            ),
            format!(
                "UpdateJobId={}",
                fact["updateJobId"].as_str().unwrap_or_default()
            ),
            format!(
                "ClientHandle={}",
                fact["clientHandle"].as_str().unwrap_or_default()
            ),
            format!("SiteCode={}", fact["siteCode"].as_str().unwrap_or_default()),
            format!(
                "SupHostHandle={}",
                fact["supHostHandle"].as_str().unwrap_or_default()
            ),
        ];
        if !is_complete_location_source
            || cited_line.as_deref().is_none_or(|line| {
                !line.contains("LocateSup selected")
                    || direct_markers.iter().any(|marker| !line.contains(marker))
            })
        {
            failures.push(format!(
                "{artifact_id}: counterpart fact needs explicit LocationServices LocateSup evidence"
            ));
        }
    }

    failures
}

fn manifest_artifact_failures(scenario_dir: &Path, artifact: &Value) -> Vec<String> {
    let mut failures = Vec::new();
    let artifact_id = artifact["artifactId"].as_str().unwrap_or("<missing>");
    let state = artifact["captureState"].as_str().unwrap_or("<missing>");
    let fragment_complete = artifact["rotation"]["fragmentComplete"]
        .as_bool()
        .unwrap_or(false);
    let physical = matches!(state, "captured" | "capped");

    if matches!(
        state,
        "absent" | "accessDenied" | "capped" | "skipped" | "unsupported" | "parseFailed"
    ) && fragment_complete
    {
        failures.push(format!(
            "{artifact_id}: {state} coverage cannot claim a complete fragment"
        ));
    }

    if physical {
        let Some(relative_path) = artifact["relativePath"].as_str() else {
            return vec![format!(
                "{artifact_id}: {state} artifact must have relativePath"
            )];
        };
        let relative = Path::new(relative_path);
        if !relative_path.starts_with("evidence/")
            || relative.is_absolute()
            || relative_path.contains('\\')
            || relative.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::ParentDir
                        | std::path::Component::RootDir
                        | std::path::Component::Prefix(_)
                )
            })
        {
            failures.push(format!(
                "{artifact_id}: unsafe relativePath {relative_path}"
            ));
            return failures;
        }
        let fixture = scenario_dir.join(relative);
        if !fixture.is_file() {
            failures.push(format!(
                "{artifact_id}: relativePath does not resolve: {}",
                fixture.display()
            ));
            return failures;
        }
        let actual = std::fs::metadata(&fixture)
            .expect("evidence metadata is readable")
            .len();
        if artifact["bytesCopied"].as_u64() != Some(actual) {
            failures.push(format!(
                "{artifact_id}: bytesCopied {:?} does not match {actual}",
                artifact["bytesCopied"].as_u64()
            ));
        }
        if artifact["encoding"] != "utf-8" {
            failures.push(format!("{artifact_id}: physical evidence must be UTF-8"));
        }
        let byte_limit = artifact["collectionLimit"]["byteLimit"]
            .as_u64()
            .unwrap_or_default();
        if byte_limit < actual {
            failures.push(format!(
                "{artifact_id}: byteLimit {byte_limit} is below {actual}"
            ));
        }
        if state == "capped"
            && (artifact["collectionLimit"]["limitApplied"] != true
                || artifact["truncated"] != true
                || byte_limit != actual)
        {
            failures.push(format!(
                "{artifact_id}: capped evidence must pin the applied exact limit"
            ));
        }
        let basename = Path::new(relative_path)
            .file_name()
            .expect("relative evidence path has a basename")
            .to_string_lossy();
        if artifact["originalBasename"].as_str() != Some(basename.as_ref()) {
            failures.push(format!(
                "{artifact_id}: originalBasename does not match physical file"
            ));
        }
        if !artifact["sanitizedSourcePath"]
            .as_str()
            .is_some_and(|value| {
                value.starts_with("SYNTHETIC://") && value.ends_with(basename.as_ref())
            })
        {
            failures.push(format!(
                "{artifact_id}: sanitized provenance must be an exact synthetic basename path"
            ));
        }
    } else if matches!(
        state,
        "absent" | "accessDenied" | "skipped" | "unsupported" | "parseFailed"
    ) {
        if !artifact["relativePath"].is_null() || artifact["bytesCopied"].as_u64() != Some(0) {
            failures.push(format!(
                "{artifact_id}: {state} artifact cannot claim physical bytes"
            ));
        }
    } else {
        failures.push(format!("{artifact_id}: unknown captureState {state}"));
    }

    failures
}

fn artifact_matches_coverage(artifact: &Value, logical_id: &str, state: &str) -> bool {
    let memberships = artifact["designOnlyCatalog"]["groupMemberships"]
        .as_array()
        .expect("groupMemberships must be an array");
    if !memberships.iter().any(|value| value == logical_id) {
        return false;
    }
    if state == "partial" {
        artifact["captureState"] == "captured" && artifact["rotation"]["fragmentComplete"] == false
    } else {
        artifact["captureState"] == state
    }
}

fn visit_files(root: &Path, files: &mut Vec<PathBuf>) {
    if !root.exists() {
        return;
    }
    for entry in std::fs::read_dir(root).expect("fixture directory is readable") {
        let path = entry.expect("fixture entry is readable").path();
        if path.is_dir() {
            visit_files(&path, files);
        } else if path.is_file() {
            files.push(path);
        }
    }
}

fn collect_evidence_refs(value: &Value, refs: &mut Vec<(String, u64, u64)>) {
    match value {
        Value::Object(map) => {
            if let (Some(artifact_id), Some(start_line), Some(end_line)) = (
                map.get("artifactId").and_then(Value::as_str),
                map.get("startLine").and_then(Value::as_u64),
                map.get("endLine").and_then(Value::as_u64),
            ) {
                refs.push((artifact_id.to_owned(), start_line, end_line));
            }
            for child in map.values() {
                collect_evidence_refs(child, refs);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_evidence_refs(child, refs);
            }
        }
        _ => {}
    }
}

fn fnv1a64(bytes: &[u8], mut hash: u64) -> u64 {
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[test]
fn software_update_fixture_matrix_pins_independent_conservative_outcomes() {
    let actual_scenarios = scenario_directories();
    let expected_scenarios = SCENARIOS
        .iter()
        .map(|contract| contract.name.to_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        actual_scenarios, expected_scenarios,
        "#323 scenario matrix changed"
    );

    let mut failures = Vec::new();
    for contract in &SCENARIOS {
        let scenario_dir = updates_root().join(contract.name);
        let manifest = read_json(&scenario_dir.join("manifest.json"));
        let expected = read_json(&scenario_dir.join("expected.json"));

        if manifest["sccmManifestVersion"] != 1
            || manifest["proposalOnly"] != true
            || manifest["syntheticFixture"] != true
            || manifest["bundle"]["role"] != "client"
            || manifest["bundle"]["workflow"] != "updates"
            || manifest["bundle"]["captureHost"] != "LAB-CLIENT-01"
            || manifest["bundle"]["siteCode"] != "LAB"
        {
            failures.push(format!(
                "{}: manifest identity/proposal boundary drifted",
                contract.name
            ));
        }

        let artifacts = manifest["artifacts"]
            .as_array()
            .expect("manifest artifacts must be an array");
        let artifact_ids = artifacts
            .iter()
            .map(|artifact| json_string(artifact, "artifactId"))
            .collect::<Vec<_>>();
        let mut sorted_artifact_ids = artifact_ids.clone();
        sorted_artifact_ids.sort();
        if artifact_ids != sorted_artifact_ids {
            failures.push(format!(
                "{}: manifest artifacts must be sorted by artifactId",
                contract.name
            ));
        }
        if artifact_ids.iter().collect::<BTreeSet<_>>().len() != artifact_ids.len() {
            failures.push(format!("{}: artifact IDs must be unique", contract.name));
        }

        for (logical_id, state) in contract.coverage {
            if !artifacts
                .iter()
                .any(|artifact| artifact_matches_coverage(artifact, logical_id, state))
            {
                failures.push(format!(
                    "{}: manifest does not support expected coverage {logical_id}={state}",
                    contract.name
                ));
            }
        }
        failures.extend(expected_boundary_failures(&expected, contract));
        failures.extend(counterpart_source_failures(
            &scenario_dir,
            &manifest,
            &expected,
        ));
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn software_update_fixture_bytes_paths_lines_and_ccm_records_are_exact() {
    let mut failures = Vec::new();
    let mut artifact_count = 0;
    let mut declared_files = BTreeSet::new();
    let mut physical_files = Vec::new();
    let mut corpus_items = Vec::new();
    let mut line_counts = BTreeMap::new();

    for contract in &SCENARIOS {
        let scenario_dir = updates_root().join(contract.name);
        let manifest = read_json(&scenario_dir.join("manifest.json"));
        let expected = read_json(&scenario_dir.join("expected.json"));
        let artifacts = manifest["artifacts"]
            .as_array()
            .expect("manifest artifacts must be an array");
        artifact_count += artifacts.len();

        for artifact in artifacts {
            failures.extend(
                manifest_artifact_failures(&scenario_dir, artifact)
                    .into_iter()
                    .map(|failure| format!("{}: {failure}", contract.name)),
            );
            let artifact_id = json_string(artifact, "artifactId");
            let Some(relative_path) = artifact["relativePath"].as_str() else {
                continue;
            };
            let full_path = scenario_dir.join(relative_path);
            declared_files.insert(full_path.clone());
            let bytes = std::fs::read(&full_path).unwrap_or_else(|error| {
                panic!("{} must be readable: {error}", full_path.display())
            });
            if !bytes
                .windows(b"SYNTHETIC FIXTURE".len())
                .any(|window| window == b"SYNTHETIC FIXTURE")
            {
                failures.push(format!(
                    "{}: {} lacks the synthetic marker",
                    contract.name, artifact_id
                ));
            }
            let contents = std::str::from_utf8(&bytes)
                .unwrap_or_else(|error| panic!("{} must be UTF-8: {error}", full_path.display()));
            for prohibited in [
                "CONTOSO",
                "C:\\",
                "Bearer ",
                "token=",
                "TenantId=",
                "UserSid=",
                "Certificate=",
            ] {
                if contents.contains(prohibited) {
                    failures.push(format!(
                        "{}: {} contains prohibited evidence material {prohibited:?}",
                        contract.name, artifact_id
                    ));
                }
            }
            for suffix in contents.split("SiteCode=").skip(1) {
                let site_code = suffix
                    .chars()
                    .take_while(|character| character.is_ascii_alphanumeric())
                    .collect::<String>();
                if site_code != "LAB" {
                    failures.push(format!(
                        "{}: {} contains noncanonical site code {site_code:?}",
                        contract.name, artifact_id
                    ));
                }
            }
            let lines = contents.lines().count() as u64;
            line_counts.insert(artifact_id.clone(), lines);

            if artifact["kind"] == "ccmLog" {
                let parsed =
                    parse_content_with_selection(contents, relative_path, &ResolvedParser::ccm());
                if artifact["rotation"]["fragmentComplete"] == true {
                    if parsed.parse_errors != 0
                        || parsed.entries.len() as u64 != lines
                        || parsed
                            .entries
                            .iter()
                            .any(|entry| entry.format != LogFormat::Ccm)
                    {
                        failures.push(format!(
                            "{}: {} must contain complete CCM logical records",
                            contract.name, artifact_id
                        ));
                    }
                } else if parsed.parse_errors == 0 {
                    failures.push(format!(
                        "{}: {} partial/capped fixture unexpectedly parsed complete",
                        contract.name, artifact_id
                    ));
                }
            }

            let relative_corpus_path = full_path
                .strip_prefix(updates_root())
                .expect("evidence is below updates root")
                .to_string_lossy()
                .into_owned();
            corpus_items.push((relative_corpus_path, bytes));
        }

        let mut refs = Vec::new();
        collect_evidence_refs(&expected, &mut refs);
        for (artifact_id, start_line, end_line) in refs {
            let Some(line_count) = line_counts.get(&artifact_id) else {
                failures.push(format!(
                    "{}: expected evidence references unknown/nonphysical artifact {}",
                    contract.name, artifact_id
                ));
                continue;
            };
            if start_line == 0 || end_line < start_line || end_line > *line_count {
                failures.push(format!(
                    "{}: {} has invalid line range {}-{} of {}",
                    contract.name, artifact_id, start_line, end_line, line_count
                ));
            }
        }
        visit_files(&scenario_dir.join("evidence"), &mut physical_files);
    }

    assert_eq!(
        artifact_count, EXPECTED_ARTIFACTS,
        "#323 artifact matrix changed"
    );
    physical_files.sort();
    assert_eq!(
        physical_files.len(),
        EXPECTED_PHYSICAL_FILES,
        "#323 physical fixture count changed"
    );
    assert_eq!(
        declared_files.len(),
        EXPECTED_PHYSICAL_FILES,
        "#323 declared physical fixture count changed"
    );
    let physical_set = physical_files.into_iter().collect::<BTreeSet<_>>();
    assert_eq!(
        physical_set, declared_files,
        "#323 evidence has a missing manifest reference or orphan file"
    );

    corpus_items.sort_by(|left, right| left.0.cmp(&right.0));
    let corpus_hash =
        corpus_items
            .iter()
            .fold(0xcbf2_9ce4_8422_2325, |hash, (relative_path, bytes)| {
                let hash = fnv1a64(relative_path.as_bytes(), hash);
                let hash = fnv1a64(&[0], hash);
                fnv1a64(bytes, hash)
            });
    assert_eq!(
        corpus_hash, EXPECTED_CORPUS_FNV1A64,
        "#323 path-qualified evidence corpus drifted"
    );

    let capped = std::fs::read(
        updates_root().join("capped/evidence/client-content/current/DataTransferService.log"),
    )
    .expect("capped update fixture is readable");
    assert_eq!(capped, EXPECTED_CAPPED_CONTENT);

    let rotation_manifest = read_json(&updates_root().join("rotation-boundary/manifest.json"));
    let rollovers = rotation_manifest["artifacts"]
        .as_array()
        .expect("rotation artifacts are an array")
        .iter()
        .filter(|artifact| artifact["rotation"]["kind"] == "lo")
        .collect::<Vec<_>>();
    assert_eq!(rollovers.len(), 1, "exactly one .lo_ rollover is allowed");
    let rollover = rollovers[0];
    assert_eq!(rollover["originalBasename"], "ScanAgent.lo_");
    assert_eq!(
        rollover["relativePath"],
        "evidence/client-updates/lo/ScanAgent.lo_"
    );
    assert_eq!(
        rollover["sanitizedSourcePath"],
        "SYNTHETIC://root-a/CCM/Logs/ScanAgent.lo_"
    );

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn software_update_fixture_contract_rejects_coverage_and_causality_mutations() {
    let scenario_dir = updates_root().join("success");
    let mut wrong_site = read_json(&scenario_dir.join("manifest.json"));
    wrong_site["bundle"]["siteCode"] = Value::String("ABC".to_owned());
    assert_ne!(wrong_site["bundle"]["siteCode"], "LAB");

    let capped_dir = updates_root().join("capped");
    let capped_manifest = read_json(&capped_dir.join("manifest.json"));
    let capped = capped_manifest["artifacts"]
        .as_array()
        .expect("capped artifacts are an array")
        .iter()
        .find(|artifact| artifact["captureState"] == "capped")
        .expect("capped scenario has capped evidence");

    let mut complete_capped = capped.clone();
    complete_capped["rotation"]["fragmentComplete"] = Value::Bool(true);
    assert!(manifest_artifact_failures(&capped_dir, &complete_capped)
        .iter()
        .any(|failure| failure.contains("cannot claim a complete fragment")));

    let mut unsafe_capped = capped.clone();
    unsafe_capped["relativePath"] = Value::String("../DataTransferService.log".to_owned());
    assert!(manifest_artifact_failures(&capped_dir, &unsafe_capped)
        .iter()
        .any(|failure| failure.contains("unsafe relativePath")));

    let access_dir = updates_root().join("access-denied");
    let access_manifest = read_json(&access_dir.join("manifest.json"));
    let denied = access_manifest["artifacts"]
        .as_array()
        .expect("access artifacts are an array")
        .iter()
        .find(|artifact| artifact["captureState"] == "accessDenied")
        .expect("access scenario has denied evidence");
    let mut denied_with_bytes = denied.clone();
    denied_with_bytes["relativePath"] = Value::String("evidence/denied.log".to_owned());
    denied_with_bytes["bytesCopied"] = Value::from(1);
    assert!(manifest_artifact_failures(&access_dir, &denied_with_bytes)
        .iter()
        .any(|failure| failure.contains("cannot claim physical bytes")));

    let mut time_only = read_json(&updates_root().join("success/expected.json"));
    time_only["correlationHandoff"]["timeOnlyEligible"] = Value::Bool(true);
    assert!(expected_boundary_failures(
        &time_only,
        SCENARIOS
            .iter()
            .find(|contract| contract.name == "success")
            .expect("success contract exists")
    )
    .iter()
    .any(|failure| failure.contains("correlation handoff boundary")));

    let mut policy_dependent = read_json(&updates_root().join("success/expected.json"));
    policy_dependent["analysisContract"]["policyOutputRequired"] = Value::Bool(true);
    assert!(expected_boundary_failures(
        &policy_dependent,
        SCENARIOS
            .iter()
            .find(|contract| contract.name == "success")
            .expect("success contract exists")
    )
    .iter()
    .any(|failure| failure.contains("independent and client-only")));

    let mut merged = read_json(&updates_root().join("same-minute-separate/expected.json"));
    merged["transactions"]
        .as_array_mut()
        .expect("same-minute transactions are an array")
        .pop();
    assert!(expected_boundary_failures(
        &merged,
        SCENARIOS
            .iter()
            .find(|contract| contract.name == "same-minute-separate")
            .expect("same-minute contract exists")
    )
    .iter()
    .any(|failure| failure.contains("transactions/observations/findings")));

    let success_dir = updates_root().join("success");
    let success_manifest = read_json(&success_dir.join("manifest.json"));
    let mut wrong_sup_source = read_json(&success_dir.join("expected.json"));
    wrong_sup_source["correlationHandoff"]["counterpartReadyFacts"][0]["evidence"]["artifactId"] =
        Value::String("updates-success-01-scan".to_owned());
    assert!(
        counterpart_source_failures(&success_dir, &success_manifest, &wrong_sup_source)
            .iter()
            .any(|failure| failure.contains("explicit LocationServices LocateSup evidence"))
    );
}
