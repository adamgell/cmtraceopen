use chrono::{DateTime, SecondsFormat, Utc};
use cmtraceopen_parser::{
    models::log_entry::LogFormat,
    parser::{parse_content_with_selection, ResolvedParser},
    sccm::{
        extract_keys, normalize_ccm_artifact, SccmArtifact, SccmCoverageState, SccmEvidence,
        SccmExtractionGapKind, SccmExtractionProfile, SccmKeyConfidence, SccmRole, SccmRotation,
        SccmTimeOrderingState, SCCM_EXPERIMENTAL_KEY_PROFILE_ID,
    },
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
const EXPECTED_PHYSICAL_BYTES: u64 = 23_142;
const EXPECTED_PHYSICAL_LINES: u64 = 61;
const EXPECTED_COMPLETE_CCM_RECORDS: usize = 57;
const EXPECTED_PARTIAL_FILES: usize = 2;
const EXPECTED_CAPPED_FILES: usize = 1;
const EXPECTED_CORPUS_FNV1A64: u64 = 0x1ff6_72e5_1adb_eb52;
const EXPECTED_CORPUS_SHA256: &str =
    "b7670821f385f90eb0178528480307f617c508c28abacf21e927d30ed3bdffef";
const EXPECTED_CAPPED_CONTENT: &[u8] = b"<![LOG[SYNTHETIC FIXTURE updates capped: ContentId=CONTENT-UPDATE-CAP-001 error-looking 0x80000001 coverage only]LOG]!><time=\"1\n";
const SHA256_ROUND_CONSTANTS: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

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
        coverage: &[
            ("client-content", "capped"),
            ("client-location-services-shared", "captured"),
            ("client-updates", "captured"),
        ],
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

fn string_array(values: &Value, field: &str) -> Vec<String> {
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

fn manifest_identity_failures(manifest: &Value, scenario: &str) -> Vec<String> {
    let mut failures = Vec::new();
    if manifest["sccmManifestVersion"] != 1
        || manifest["proposalOnly"] != true
        || manifest["syntheticFixture"] != true
        || manifest["bundle"]["role"] != "client"
        || manifest["bundle"]["workflow"] != "updates"
        || manifest["bundle"]["captureHost"] != "LAB-CLIENT-01"
        || manifest["bundle"]["siteCode"] != "LAB"
    {
        failures.push(format!(
            "{scenario}: manifest identity/proposal boundary drifted"
        ));
    }
    failures
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
    let state_chain = string_array(expected, "stateChain");
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
    let coverage_pairs = coverage
        .iter()
        .map(|entry| {
            (
                json_string(entry, "logicalArtifactId"),
                json_string(entry, "state"),
            )
        })
        .collect::<Vec<_>>();
    let expected_coverage_pairs = contract
        .coverage
        .iter()
        .map(|(logical_id, state)| ((*logical_id).to_owned(), (*state).to_owned()))
        .collect::<Vec<_>>();
    if coverage_pairs != expected_coverage_pairs {
        failures.push(format!(
            "{scenario}: coverage projection drifted: expected {expected_coverage_pairs:?}, got {coverage_pairs:?}"
        ));
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
            || fact["correlationEligible"] != false
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

    let prohibited = string_array(expected, "prohibitedClaims").join("\n");
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

#[derive(Clone)]
struct IndexedArtifact {
    manifest: Value,
    physical_lines: Vec<String>,
    complete_ccm_records: Vec<SccmEvidence>,
}

fn safe_evidence_relative_path(relative_path: &str) -> bool {
    let relative = Path::new(relative_path);
    relative_path.starts_with("evidence/")
        && !relative.is_absolute()
        && !relative_path.contains('\\')
        && !relative.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
}

fn sccm_coverage_state(state: &str) -> Option<SccmCoverageState> {
    match state {
        "captured" => Some(SccmCoverageState::Captured),
        "absent" => Some(SccmCoverageState::Absent),
        "accessDenied" => Some(SccmCoverageState::AccessDenied),
        "capped" => Some(SccmCoverageState::Capped),
        "skipped" => Some(SccmCoverageState::Skipped),
        "unsupported" => Some(SccmCoverageState::Unsupported),
        "parseFailed" => Some(SccmCoverageState::ParseFailed),
        _ => None,
    }
}

fn evidence_index(
    scenario_dir: &Path,
    manifest: &Value,
) -> (BTreeMap<String, IndexedArtifact>, Vec<String>) {
    let mut index = BTreeMap::new();
    let mut failures = Vec::new();
    let Some(artifacts) = manifest["artifacts"].as_array() else {
        return (
            index,
            vec!["manifest artifacts must be an array".to_owned()],
        );
    };

    for artifact in artifacts {
        let Some(artifact_id) = artifact["artifactId"].as_str() else {
            failures.push("manifest artifactId must be a string".to_owned());
            continue;
        };
        let mut physical_lines = Vec::new();
        let mut complete_ccm_records = Vec::new();
        if let Some(relative_path) = artifact["relativePath"].as_str() {
            if safe_evidence_relative_path(relative_path) {
                let path = scenario_dir.join(relative_path);
                if let Ok(contents) = std::fs::read_to_string(&path) {
                    physical_lines = contents.lines().map(str::to_owned).collect();
                    if artifact["captureState"] == "captured"
                        && artifact["rotation"]["fragmentComplete"] == true
                        && artifact["kind"] == "ccmLog"
                    {
                        let Some(display_name) = artifact["originalBasename"].as_str() else {
                            failures
                                .push(format!("{artifact_id}: originalBasename must be a string"));
                            continue;
                        };
                        let Some(coverage) = artifact["captureState"]
                            .as_str()
                            .and_then(sccm_coverage_state)
                        else {
                            failures.push(format!(
                                "{artifact_id}: captureState cannot build SCCM evidence"
                            ));
                            continue;
                        };
                        complete_ccm_records = normalize_ccm_artifact(
                            SccmArtifact {
                                artifact_id: artifact_id.to_owned(),
                                display_name: display_name.to_owned(),
                                original_path: artifact["sanitizedSourcePath"]
                                    .as_str()
                                    .map(str::to_owned),
                                host: None,
                                role: SccmRole::Client,
                                configmgr_version: artifact["sourceVersion"]
                                    .as_str()
                                    .map(str::to_owned),
                                collected_at_utc: artifact["capturedUtc"]
                                    .as_str()
                                    .map(str::to_owned),
                                rotation: SccmRotation::Current,
                                coverage,
                                encoding: artifact["encoding"].as_str().map(str::to_owned),
                            },
                            &contents,
                        );
                    }
                }
            }
        }

        if index
            .insert(
                artifact_id.to_owned(),
                IndexedArtifact {
                    manifest: artifact.clone(),
                    physical_lines,
                    complete_ccm_records,
                },
            )
            .is_some()
        {
            failures.push(format!("{artifact_id}: artifact ID is duplicated"));
        }
    }

    (index, failures)
}

fn citation_triples(
    value: &Value,
    label: &str,
    failures: &mut Vec<String>,
) -> Vec<(String, u64, u64)> {
    let Some(citations) = value.as_array() else {
        failures.push(format!("{label}: evidence citations must be an array"));
        return Vec::new();
    };
    citations
        .iter()
        .filter_map(|citation| {
            let Some(artifact_id) = citation["artifactId"].as_str() else {
                failures.push(format!("{label}: citation artifactId must be a string"));
                return None;
            };
            let Some(start_line) = citation["startLine"].as_u64() else {
                failures.push(format!("{label}: citation startLine must be an integer"));
                return None;
            };
            let Some(end_line) = citation["endLine"].as_u64() else {
                failures.push(format!("{label}: citation endLine must be an integer"));
                return None;
            };
            Some((artifact_id.to_owned(), start_line, end_line))
        })
        .collect()
}

fn citation_failures(
    label: &str,
    citations: &Value,
    index: &BTreeMap<String, IndexedArtifact>,
) -> Vec<String> {
    let mut failures = Vec::new();
    for (artifact_id, start_line, end_line) in citation_triples(citations, label, &mut failures) {
        let Some(artifact) = index.get(&artifact_id) else {
            failures.push(format!(
                "{label}: same-scenario citation references unknown artifact {artifact_id}"
            ));
            continue;
        };
        let line_count = artifact.physical_lines.len() as u64;
        if line_count == 0 {
            failures.push(format!(
                "{label}: same-scenario citation references nonphysical artifact {artifact_id}"
            ));
        } else if start_line == 0 || end_line < start_line || end_line > line_count {
            failures.push(format!(
                "{label}: same-scenario citation {artifact_id}:{start_line}-{end_line} exceeds {line_count} lines"
            ));
        }
    }
    failures
}

fn cited_complete_records<'a>(
    citations: &Value,
    index: &'a BTreeMap<String, IndexedArtifact>,
) -> Vec<&'a SccmEvidence> {
    let mut ignored_failures = Vec::new();
    citation_triples(citations, "cited records", &mut ignored_failures)
        .into_iter()
        .flat_map(|(artifact_id, start_line, end_line)| {
            index
                .get(&artifact_id)
                .into_iter()
                .flat_map(move |artifact| {
                    artifact.complete_ccm_records.iter().filter(move |record| {
                        record.reference.line_start.is_some_and(|line| {
                            u64::from(line) >= start_line
                                && record
                                    .reference
                                    .line_end
                                    .is_some_and(|end| u64::from(end) <= end_line)
                        })
                    })
                })
        })
        .collect()
}

fn exact_message_field<'a>(message: &'a str, field: &str) -> Option<&'a str> {
    message.split_ascii_whitespace().find_map(|token| {
        let (name, value) = token.split_once('=')?;
        (name == field).then(|| value.trim_matches(['{', '}']))
    })
}

fn record_matches_transaction_key(record: &SccmEvidence, key: &Value) -> bool {
    [
        ("updateId", "UpdateId"),
        ("ciId", "CiId"),
        ("contentId", "ContentId"),
        ("updateJobId", "UpdateJobId"),
        ("clientHandle", "ClientHandle"),
        ("siteCode", "SiteCode"),
    ]
    .iter()
    .all(|(json_field, message_field)| {
        key[*json_field]
            .as_str()
            .is_some_and(|value| exact_message_field(&record.message, message_field) == Some(value))
    }) && key["supHostHandle"].as_str().is_none_or(|sup_handle| {
        exact_message_field(&record.message, "SupHostHandle") == Some(sup_handle)
    })
}

fn message_contains_tokens(message: &str, expected: &[&str]) -> bool {
    let tokens = message.split_ascii_whitespace().collect::<Vec<_>>();
    tokens
        .windows(expected.len())
        .any(|window| window == expected)
}

fn phase_source_is_compatible(phase: &str, basename: &str) -> bool {
    match phase {
        "scan" => basename == "ScanAgent.log",
        "evaluate" => matches!(basename, "ScanAgent.log" | "WUAHandler.log"),
        "locateSup" => basename == "LocationServices.log",
        "download" => matches!(
            basename,
            "DataTransferService.log" | "ContentTransferManager.log" | "UpdatesDeployment.log"
        ),
        "maintenanceWindow" => matches!(
            basename,
            "ServiceWindowManager.log" | "UpdatesHandler.log" | "UpdatesDeployment.log"
        ),
        "install" => matches!(basename, "UpdatesHandler.log" | "UpdatesDeployment.log"),
        "reboot" => matches!(basename, "RebootCoordinator.log" | "UpdatesDeployment.log"),
        "report" => matches!(basename, "StateMessage.log" | "UpdatesHandler.log"),
        _ => false,
    }
}

fn phase_token(phase: &str) -> Option<&'static str> {
    match phase {
        "scan" => Some("Scan"),
        "evaluate" => Some("Evaluate"),
        "locateSup" => Some("LocateSup"),
        "download" => Some("Download"),
        "maintenanceWindow" => Some("MaintenanceWindow"),
        "install" => Some("Install"),
        "reboot" => Some("Reboot"),
        "report" => Some("Report"),
        _ => None,
    }
}

fn record_proves_phase_outcome(
    record: &SccmEvidence,
    artifact: &IndexedArtifact,
    transaction: &Value,
) -> bool {
    let Some(phase) = transaction["phase"].as_str() else {
        return false;
    };
    let Some(phase_token) = phase_token(phase) else {
        return false;
    };
    let Some(basename) = artifact.manifest["originalBasename"].as_str() else {
        return false;
    };
    if !phase_source_is_compatible(phase, basename)
        || !record_matches_transaction_key(record, &transaction["key"])
    {
        return false;
    }

    match (
        transaction["classification"].as_str(),
        transaction["state"].as_str(),
    ) {
        (Some("success"), Some("succeeded")) => {
            message_contains_tokens(&record.message, &[phase_token, "succeeded"])
        }
        (Some("confirmedFailure"), Some("failed")) => {
            message_contains_tokens(&record.message, &[phase_token, "terminal", "failure"])
        }
        _ => false,
    }
}

fn expected_transaction_gaps(scenario: &str) -> &'static [&'static str] {
    match scenario {
        "access-denied" => &["client-updates"],
        "capped" => &["client-content"],
        "incomplete" | "maintenance-window" => &["client-maintenance-window"],
        "invalid-offset" => &["client-updates"],
        "no-sup" => &["client-location-services-shared"],
        "reboot-pending" => &["client-reboot"],
        _ => &[],
    }
}

fn transaction_binding_failures(
    scenario: &str,
    expected: &Value,
    index: &BTreeMap<String, IndexedArtifact>,
) -> Vec<String> {
    let mut failures = Vec::new();
    let Some(transactions) = expected["transactions"].as_array() else {
        return vec![format!("{scenario}: transactions must be an array")];
    };
    let profile_id = expected["extractionProfile"]["profileId"].as_str();
    let source_prefix = expected["extractionProfile"]["sourceVersionPrefix"].as_str();
    let key_fields = [
        ("updateId", "UpdateId"),
        ("ciId", "CiId"),
        ("contentId", "ContentId"),
        ("updateJobId", "UpdateJobId"),
        ("clientHandle", "ClientHandle"),
        ("siteCode", "SiteCode"),
    ];

    for transaction in transactions {
        let transaction_id = transaction["transactionId"]
            .as_str()
            .unwrap_or("<missing-transaction-id>");
        failures.extend(citation_failures(
            transaction_id,
            &transaction["evidence"],
            index,
        ));
        let cited_records = cited_complete_records(&transaction["evidence"], index);
        let compatible_records = cited_records
            .iter()
            .copied()
            .filter(|record| {
                index
                    .get(&record.reference.artifact_id)
                    .and_then(|artifact| artifact.manifest["sourceVersion"].as_str())
                    .zip(source_prefix)
                    .is_some_and(|(version, prefix)| version.starts_with(prefix))
            })
            .collect::<Vec<_>>();
        let key = &transaction["key"];
        for (json_field, message_field) in key_fields {
            let Some(value) = key[json_field].as_str() else {
                failures.push(format!(
                    "{scenario}: exact transaction key {transaction_id} has missing/non-string {json_field}"
                ));
                continue;
            };
            if !compatible_records
                .iter()
                .any(|record| exact_message_field(&record.message, message_field) == Some(value))
            {
                failures.push(format!(
                    "{scenario}: exact transaction key {transaction_id} {json_field}={value:?} is not bound to cited profile-compatible CCM evidence"
                ));
            }
        }
        if !compatible_records
            .iter()
            .any(|record| record_matches_transaction_key(record, key))
        {
            failures.push(format!(
                "{scenario}: complete exact key tuple for {transaction_id} does not co-occur in one cited profile-compatible CCM record"
            ));
        }
        if key["confidence"] != "exact"
            || key["extractionProfileId"].as_str() != profile_id
            || key["siteCode"] != "LAB"
            || key["updateId"].as_str().is_none_or(|update_id| {
                transaction["transactionId"] != format!("updates:update:{update_id}")
            })
        {
            failures.push(format!(
                "{scenario}: exact transaction key metadata drifted for {transaction_id}"
            ));
        }

        let sup_handle_present = key
            .as_object()
            .is_some_and(|object| object.contains_key("supHostHandle"));
        match key["supHostHandle"].as_str() {
            Some(sup_handle) => {
                let exact_location = compatible_records.iter().any(|record| {
                    index
                        .get(&record.reference.artifact_id)
                        .is_some_and(|artifact| {
                            artifact.manifest["designOnlyCatalog"]["entryId"]
                                == "client-location-services-shared"
                                && record.message.contains("LocateSup selected")
                                && exact_message_field(&record.message, "SupHostHandle")
                                    == Some(sup_handle)
                        })
                });
                if !exact_location {
                    failures.push(format!(
                        "{scenario}: SUP handle without LocateSup evidence is not exact"
                    ));
                }
            }
            None if sup_handle_present && key["supHostHandle"].is_null() => {}
            None => failures.push(format!(
                "{scenario}: unavailable supHostHandle must be represented as null"
            )),
        }

        let requires_phase_outcome = transaction["confidence"] == "high"
            && transaction["confidenceCeiling"] == "high"
            && matches!(
                (
                    transaction["classification"].as_str(),
                    transaction["state"].as_str()
                ),
                (Some("success"), Some("succeeded")) | (Some("confirmedFailure"), Some("failed"))
            );
        if requires_phase_outcome
            && !compatible_records.iter().any(|record| {
                index
                    .get(&record.reference.artifact_id)
                    .is_some_and(|artifact| {
                        record_proves_phase_outcome(record, artifact, transaction)
                    })
            })
        {
            failures.push(format!(
                "{scenario}: phase outcome evidence is missing for {transaction_id}"
            ));
        }

        let actual_gaps = string_array(transaction, "coverageGapArtifactIds");
        if actual_gaps != expected_transaction_gaps(scenario) {
            failures.push(format!(
                "{scenario}: coverage gaps drifted for {transaction_id}: {actual_gaps:?}"
            ));
        }
    }
    failures
}

fn finding_binding_failures(scenario: &str, expected: &Value) -> Vec<String> {
    let mut failures = Vec::new();
    let mut subjects = BTreeMap::new();
    for transaction in expected["transactions"].as_array().into_iter().flatten() {
        if let Some(id) = transaction["transactionId"].as_str() {
            subjects.insert(id, transaction);
        }
    }
    for observation in expected["sourceLocalObservations"]
        .as_array()
        .into_iter()
        .flatten()
    {
        if let Some(id) = observation["observationId"].as_str() {
            subjects.insert(id, observation);
        }
    }

    for finding in expected["findings"].as_array().into_iter().flatten() {
        let Some(subject_id) = finding["subjectId"].as_str() else {
            failures.push(format!("{scenario}: finding subjectId must be a string"));
            continue;
        };
        let Some(subject) = subjects.get(subject_id) else {
            failures.push(format!(
                "{scenario}: finding/subject binding references unknown {subject_id}"
            ));
            continue;
        };
        if finding["class"] != subject["classification"]
            || finding["phase"] != subject["phase"]
            || finding["lastSuccessfulPhase"] != subject["lastSuccessfulPhase"]
            || finding["confidence"] != subject["confidence"]
            || finding["confidenceCeiling"] != subject["confidenceCeiling"]
            || finding["nextArtifact"] != subject["nextArtifact"]
            || finding["evidence"] != subject["evidence"]
        {
            failures.push(format!(
                "{scenario}: finding/subject binding drifted for {subject_id}"
            ));
        }
    }
    failures
}

fn conservative_outcome_failures(scenario: &str, expected: &Value) -> Vec<String> {
    let mut failures = Vec::new();
    if scenario == "supplemental-conflict" {
        let observation = &expected["sourceLocalObservations"][0];
        let finding = &expected["findings"][0];
        let transaction = &expected["transactions"][0];
        if observation["confidence"] != "low"
            || observation["confidenceCeiling"] != "low"
            || observation["correlationEligible"] != false
            || finding["confidence"] != "low"
            || finding["confidenceCeiling"] != "low"
            || transaction["phase"] != "install"
            || transaction["state"] != "succeeded"
            || transaction["classification"] != "success"
        {
            failures.push(
                "supplemental-conflict: conservative confidence/outcome boundary drifted"
                    .to_owned(),
            );
        }
    }
    if scenario == "invalid-offset" {
        let transaction = &expected["transactions"][0];
        let finding = &expected["findings"][0];
        if transaction["confidence"] != "low"
            || transaction["confidenceCeiling"] != "low"
            || finding["confidence"] != "low"
            || finding["confidenceCeiling"] != "low"
            || transaction["ordering"]["crossArtifactComparable"] != false
            || transaction["ordering"]["highConfidenceEligible"] != false
            || transaction["ordering"]["reason"] != "invalidOffset"
        {
            failures.push(
                "invalid-offset: conservative confidence/ordering boundary drifted".to_owned(),
            );
        }
    }
    if scenario == "same-minute-separate" {
        let transactions = &expected["transactions"];
        let first = &transactions[0];
        let second = &transactions[1];
        let separate = first["transactionId"]
            == "updates:update:32300000-0000-0000-0000-000000000015"
            && first["key"]["updateId"] == "32300000-0000-0000-0000-000000000015"
            && first["phase"] == "report"
            && first["state"] == "succeeded"
            && first["classification"] == "success"
            && first["evidence"]
                == serde_json::json!([{
                    "artifactId": "updates-same-minute-separate-01-updates",
                    "startLine": 1,
                    "endLine": 1
                }])
            && second["transactionId"] == "updates:update:32300000-0000-0000-0000-000000000016"
            && second["key"]["updateId"] == "32300000-0000-0000-0000-000000000016"
            && second["phase"] == "install"
            && second["state"] == "failed"
            && second["classification"] == "confirmedFailure"
            && second["evidence"]
                == serde_json::json!([{
                    "artifactId": "updates-same-minute-separate-01-updates",
                    "startLine": 2,
                    "endLine": 2
                }]);
        if !separate {
            failures
                .push("same-minute-separate: same-minute transaction outcomes drifted".to_owned());
        }
    }
    failures
}

fn experimental_profile_causality_failures(expected: &Value) -> Vec<String> {
    let mut failures = Vec::new();
    let profile_id = expected["extractionProfile"]["profileId"].as_str();
    for transaction in expected["transactions"].as_array().into_iter().flatten() {
        let uses_experimental_profile = profile_id == Some(SCCM_EXPERIMENTAL_KEY_PROFILE_ID)
            || transaction["key"]["extractionProfileId"] == SCCM_EXPERIMENTAL_KEY_PROFILE_ID;
        if uses_experimental_profile
            && (transaction["key"]["confidence"] != "low"
                || transaction["confidence"] != "low"
                || transaction["confidenceCeiling"] != "low"
                || transaction["classification"] == "confirmedFailure")
        {
            failures.push(
                "experimental Low key profile cannot establish causal transaction confidence"
                    .to_owned(),
            );
        }
    }
    for fact in expected["correlationHandoff"]["counterpartReadyFacts"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let uses_experimental_profile = profile_id == Some(SCCM_EXPERIMENTAL_KEY_PROFILE_ID)
            || fact["extractionProfileId"] == SCCM_EXPERIMENTAL_KEY_PROFILE_ID;
        if uses_experimental_profile
            && (fact["keyConfidence"] != "low" || fact["correlationEligible"] != false)
        {
            failures.push(
                "experimental Low key profile cannot emit a correlation-eligible fact".to_owned(),
            );
        }
    }
    failures
}

fn expected_catalog_group(basename: &str) -> Option<&'static str> {
    match basename {
        "ScanAgent.log"
        | "ScanAgent.lo_"
        | "WUAHandler.log"
        | "UpdatesDeployment.log"
        | "UpdatesHandler.log"
        | "UpdatesStore.log" => Some("client-updates"),
        "LocationServices.log" => Some("client-location-services-shared"),
        "DataTransferService.log" | "ContentTransferManager.log" => Some("client-content"),
        "ServiceWindowManager.log" => Some("client-maintenance-window"),
        "RebootCoordinator.log" => Some("client-reboot"),
        "StateMessage.log" => Some("client-policy-state"),
        "CBS.log" | "ReportingEvents.log" => Some("client-windows-update-supplemental"),
        _ => None,
    }
}

fn expected_rotation_kind(basename: &str) -> &'static str {
    if basename.ends_with(".lo_") {
        "lo"
    } else {
        "current"
    }
}

fn manifest_artifact_identity_failures(artifact: &Value) -> Vec<String> {
    let mut failures = Vec::new();
    let artifact_id = artifact["artifactId"].as_str().unwrap_or("<missing>");
    if artifact["role"] != "client" {
        failures.push(format!("{artifact_id}: artifact role must remain client"));
    }

    let basename = artifact["originalBasename"].as_str();
    let entry_id = artifact["designOnlyCatalog"]["entryId"].as_str();
    let expected_group = basename.and_then(expected_catalog_group);
    if expected_group.is_none() || entry_id != expected_group {
        failures.push(format!(
            "{artifact_id}: catalog entry/logical group is incompatible with basename {basename:?}"
        ));
    }
    if expected_group.is_none_or(|group| {
        artifact["designOnlyCatalog"]["groupMemberships"] != serde_json::json!([group])
    }) {
        failures.push(format!(
            "{artifact_id}: group memberships must contain one canonical logical group"
        ));
    }

    let rotation_kind = artifact["rotation"]["kind"].as_str();
    if basename.is_none_or(|basename| rotation_kind != Some(expected_rotation_kind(basename))) {
        failures.push(format!(
            "{artifact_id}: rotation kind is incompatible with the original basename"
        ));
    }

    if let (Some(relative_path), Some(entry_id), Some(rotation_kind), Some(basename)) = (
        artifact["relativePath"].as_str(),
        entry_id,
        rotation_kind,
        basename,
    ) {
        let expected_path = format!("evidence/{entry_id}/{rotation_kind}/{basename}");
        if relative_path != expected_path {
            failures.push(format!(
                "{artifact_id}: relativePath is incompatible with catalog group/rotation/basename; expected {expected_path}"
            ));
        }
    }

    failures
}

fn manifest_artifact_kind_failures(artifact: &Value) -> Vec<String> {
    let artifact_id = artifact["artifactId"].as_str().unwrap_or("<missing>");
    let group = artifact["designOnlyCatalog"]["entryId"].as_str();
    let basename = artifact["originalBasename"].as_str();
    let expected_kind = if basename == Some("CBS.log") {
        "cbsLog"
    } else {
        "ccmLog"
    };
    if group.is_none()
        || (group != Some("client-windows-update-supplemental") && artifact["kind"] != "ccmLog")
        || artifact["kind"] != expected_kind
    {
        vec![format!(
            "{artifact_id}: artifact kind {:?} is incompatible with group/basename",
            artifact["kind"]
        )]
    } else {
        Vec::new()
    }
}

fn coverage_state_for_artifact(artifact: &Value) -> Option<String> {
    let state = artifact["captureState"].as_str()?;
    if state == "captured" && artifact["rotation"]["fragmentComplete"] == false {
        Some("partial".to_owned())
    } else {
        Some(state.to_owned())
    }
}

fn coverage_projection(manifest: &Value) -> (Value, Vec<String>) {
    let mut states_by_family = BTreeMap::<String, BTreeSet<String>>::new();
    let mut failures = Vec::new();
    let Some(artifacts) = manifest["artifacts"].as_array() else {
        return (
            Value::Array(Vec::new()),
            vec!["coverage projection requires manifest artifacts".to_owned()],
        );
    };
    for artifact in artifacts {
        let Some(state) = coverage_state_for_artifact(artifact) else {
            failures.push("coverage projection found invalid captureState".to_owned());
            continue;
        };
        let Some(groups) = artifact["designOnlyCatalog"]["groupMemberships"].as_array() else {
            failures.push("coverage projection found invalid groupMemberships".to_owned());
            continue;
        };
        for group in groups {
            let Some(group) = group.as_str() else {
                failures.push("coverage projection found non-string family".to_owned());
                continue;
            };
            states_by_family
                .entry(group.to_owned())
                .or_default()
                .insert(state.clone());
        }
    }

    let mut projection = Vec::new();
    for (family, mut states) in states_by_family {
        if states.len() > 1 {
            states.remove("captured");
        }
        if states.len() != 1 {
            failures.push(format!(
                "coverage projection has conflicting states for {family}: {states:?}"
            ));
            continue;
        }
        let state = states
            .into_iter()
            .next()
            .expect("one projected coverage state remains");
        projection.push(serde_json::json!({
            "logicalArtifactId": family,
            "state": state
        }));
    }
    (Value::Array(projection), failures)
}

fn artifact_provenance_projection(manifest: &Value) -> (Value, Vec<String>) {
    let mut projection = Vec::new();
    let mut failures = Vec::new();
    let Some(artifacts) = manifest["artifacts"].as_array() else {
        return (
            Value::Array(projection),
            vec!["artifact provenance requires manifest artifacts".to_owned()],
        );
    };
    for artifact in artifacts {
        let Some(artifact_id) = artifact["artifactId"].as_str() else {
            failures.push("artifact provenance found invalid artifactId".to_owned());
            continue;
        };
        let Some(capture_state) = artifact["captureState"].as_str() else {
            failures.push(format!(
                "{artifact_id}: artifact provenance found invalid captureState"
            ));
            continue;
        };
        let physical = matches!(capture_state, "captured" | "capped");
        let encoding = if physical {
            artifact["encoding"].clone()
        } else {
            Value::Null
        };
        let byte_limit = if physical {
            artifact["collectionLimit"]["byteLimit"].clone()
        } else {
            Value::Null
        };
        let limit_applied = if physical {
            artifact["collectionLimit"]["limitApplied"].clone()
        } else {
            Value::Bool(false)
        };
        projection.push(serde_json::json!({
            "artifactId": artifact_id,
            "captureState": capture_state,
            "encoding": encoding,
            "byteLimit": byte_limit,
            "limitApplied": limit_applied
        }));
    }
    (Value::Array(projection), failures)
}

fn profile_binding_failures(manifest: &Value, expected: &Value, scenario: &str) -> Vec<String> {
    let mut failures = Vec::new();
    let profile = &expected["extractionProfile"];
    let validated_families = string_array(profile, "validatedArtifactFamilies");
    if profile["selectionState"] == "unvalidatedVersion" {
        if !validated_families.is_empty() {
            failures.push(format!(
                "{scenario}: source profile/version cannot validate families for an unknown profile"
            ));
        }
        return failures;
    }
    let Some(prefix) = profile["sourceVersionPrefix"].as_str() else {
        return vec![format!(
            "{scenario}: source profile/version prefix must be a string"
        )];
    };
    let Some(artifacts) = manifest["artifacts"].as_array() else {
        return vec![format!(
            "{scenario}: source profile/version requires manifest artifacts"
        )];
    };
    let derived = artifacts
        .iter()
        .filter(|artifact| {
            artifact["captureState"] == "captured"
                && artifact["rotation"]["fragmentComplete"] == true
                && artifact["kind"] == "ccmLog"
                && artifact["sourceVersion"]
                    .as_str()
                    .is_some_and(|version| version.starts_with(prefix))
        })
        .filter_map(|artifact| artifact["designOnlyCatalog"]["entryId"].as_str())
        .map(str::to_owned)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if validated_families != derived {
        failures.push(format!(
            "{scenario}: source profile/version family projection drifted: expected {derived:?}, got {validated_families:?}"
        ));
    }
    failures
}

fn manifest_expected_binding_failures(
    scenario_dir: &Path,
    manifest: &Value,
    expected: &Value,
    scenario: &str,
) -> Vec<String> {
    let mut failures = manifest_identity_failures(manifest, scenario);
    let Some(artifacts) = manifest["artifacts"].as_array() else {
        failures.push(format!("{scenario}: manifest artifacts must be an array"));
        return failures;
    };
    let artifact_ids = artifacts
        .iter()
        .filter_map(|artifact| artifact["artifactId"].as_str())
        .collect::<Vec<_>>();
    let mut sorted_ids = artifact_ids.clone();
    sorted_ids.sort_unstable();
    if artifact_ids != sorted_ids
        || artifact_ids.iter().collect::<BTreeSet<_>>().len() != artifact_ids.len()
    {
        failures.push(format!(
            "{scenario}: manifest artifact IDs must be unique and sorted"
        ));
    }
    let mut relative_path_owners = BTreeMap::new();
    let mut path_fingerprint_owners = BTreeMap::new();
    for artifact in artifacts {
        let artifact_id = artifact["artifactId"].as_str().unwrap_or("<missing>");
        if let Some(relative_path) = artifact["relativePath"].as_str() {
            if let Some(first_id) =
                relative_path_owners.insert(relative_path.to_owned(), artifact_id.to_owned())
            {
                failures.push(format!(
                    "{scenario}: duplicate physical alias relativePath {relative_path:?} for {first_id} and {artifact_id}"
                ));
            }
        }
        if let Some(path_fingerprint) = artifact["pathFingerprint"].as_str() {
            if let Some(first_id) =
                path_fingerprint_owners.insert(path_fingerprint.to_owned(), artifact_id.to_owned())
            {
                failures.push(format!(
                    "{scenario}: duplicate physical alias pathFingerprint {path_fingerprint:?} for {first_id} and {artifact_id}"
                ));
            }
        }
        failures.extend(
            manifest_artifact_failures(scenario_dir, artifact)
                .into_iter()
                .map(|failure| format!("{scenario}: {failure}")),
        );
        failures.extend(
            manifest_artifact_identity_failures(artifact)
                .into_iter()
                .map(|failure| format!("{scenario}: {failure}")),
        );
        failures.extend(
            manifest_artifact_kind_failures(artifact)
                .into_iter()
                .map(|failure| format!("{scenario}: {failure}")),
        );
    }

    let (derived_coverage, coverage_failures) = coverage_projection(manifest);
    failures.extend(
        coverage_failures
            .into_iter()
            .map(|failure| format!("{scenario}: {failure}")),
    );
    if expected["coverage"] != derived_coverage {
        failures.push(format!(
            "{scenario}: coverage projection does not match the manifest"
        ));
    }

    let (derived_provenance, provenance_failures) = artifact_provenance_projection(manifest);
    failures.extend(
        provenance_failures
            .into_iter()
            .map(|failure| format!("{scenario}: {failure}")),
    );
    if expected["artifactProvenance"] != derived_provenance {
        failures.push(format!(
            "{scenario}: artifact provenance does not match the manifest one-to-one"
        ));
    }
    failures.extend(profile_binding_failures(manifest, expected, scenario));

    let (index, index_failures) = evidence_index(scenario_dir, manifest);
    failures.extend(
        index_failures
            .into_iter()
            .map(|failure| format!("{scenario}: {failure}")),
    );
    failures.extend(transaction_binding_failures(scenario, expected, &index));
    for observation in expected["sourceLocalObservations"]
        .as_array()
        .into_iter()
        .flatten()
    {
        failures.extend(citation_failures(
            observation["observationId"]
                .as_str()
                .unwrap_or("<missing-observation-id>"),
            &observation["evidence"],
            &index,
        ));
    }
    for finding in expected["findings"].as_array().into_iter().flatten() {
        failures.extend(citation_failures(
            finding["findingId"]
                .as_str()
                .unwrap_or("<missing-finding-id>"),
            &finding["evidence"],
            &index,
        ));
    }
    failures.extend(finding_binding_failures(scenario, expected));
    failures.extend(conservative_outcome_failures(scenario, expected));
    failures.extend(experimental_profile_causality_failures(expected));
    failures
}

fn counterpart_source_failures(
    scenario_dir: &Path,
    manifest: &Value,
    expected: &Value,
) -> Vec<String> {
    let mut failures = Vec::new();
    let Some(facts) = expected["correlationHandoff"]["counterpartReadyFacts"].as_array() else {
        return vec!["counterpartReadyFacts must be an array".to_owned()];
    };
    let Some(transactions) = expected["transactions"].as_array() else {
        return vec!["transactions must be an array".to_owned()];
    };
    let (index, _) = evidence_index(scenario_dir, manifest);
    let source_prefix = expected["extractionProfile"]["sourceVersionPrefix"].as_str();
    let fact_fields = [
        ("updateId", "UpdateId"),
        ("ciId", "CiId"),
        ("contentId", "ContentId"),
        ("updateJobId", "UpdateJobId"),
        ("clientHandle", "ClientHandle"),
        ("siteCode", "SiteCode"),
        ("supHostHandle", "SupHostHandle"),
    ];

    for fact in facts {
        if expected["correlationHandoff"]["topologyCompatibilityEvaluated"].as_bool() != Some(true)
            && (fact
                .as_object()
                .is_some_and(|fact| fact.contains_key("topologyCompatible"))
                || fact["correlationEligible"] != false)
        {
            failures.push(
                "counterpart fact cannot claim unevaluated topology compatibility or correlation eligibility"
                    .to_owned(),
            );
        }
        if fact["topologyCompatible"] == false && fact["correlationEligible"] != false {
            failures.push(
                "counterpart topology mismatch cannot remain correlation eligible".to_owned(),
            );
        }
        if fact["keyConfidence"] != "exact"
            || fact["correlationEligible"] != false
            || fact["timeOnlyEligible"] != false
            || fact["extractionProfileId"] != expected["extractionProfile"]["profileId"]
            || fact["phase"] != "locateSup"
        {
            failures.push("counterpart fact exact/correlation metadata drifted".to_owned());
        }

        let mut exact_values = Vec::new();
        for (json_field, message_field) in fact_fields {
            let Some(value) = fact[json_field].as_str() else {
                failures.push(format!(
                    "exact counterpart key field {json_field} must be a string"
                ));
                continue;
            };
            exact_values.push((json_field, message_field, value));
        }
        let matching_transaction = fact["updateId"].as_str().and_then(|update_id| {
            transactions
                .iter()
                .find(|transaction| transaction["key"]["updateId"] == update_id)
        });
        if matching_transaction.is_none_or(|transaction| {
            exact_values
                .iter()
                .any(|(json_field, _, value)| transaction["key"][*json_field] != **value)
        }) {
            failures.push(
                "exact counterpart key does not match one exact client transaction".to_owned(),
            );
        }

        let citations = Value::Array(vec![fact["evidence"].clone()]);
        failures.extend(citation_failures("counterpart fact", &citations, &index));
        let Some(artifact_id) = fact["evidence"]["artifactId"].as_str() else {
            failures.push(
                "counterpart fact needs explicit LocationServices LocateSup evidence".to_owned(),
            );
            continue;
        };
        let Some(artifact) = index.get(artifact_id) else {
            failures.push(format!(
                "{artifact_id}: counterpart fact needs explicit LocationServices LocateSup evidence"
            ));
            continue;
        };
        let is_complete_location_source = artifact.manifest["designOnlyCatalog"]["entryId"]
            == "client-location-services-shared"
            && artifact.manifest["kind"] == "ccmLog"
            && artifact.manifest["captureState"] == "captured"
            && artifact.manifest["rotation"]["fragmentComplete"] == true
            && artifact.manifest["originalBasename"] == "LocationServices.log"
            && artifact.manifest["sourceVersion"]
                .as_str()
                .zip(source_prefix)
                .is_some_and(|(version, prefix)| version.starts_with(prefix));
        let cited_records = cited_complete_records(&citations, &index);
        if !is_complete_location_source || cited_records.len() != 1 {
            failures.push(format!(
                "{artifact_id}: counterpart fact needs explicit LocationServices LocateSup evidence"
            ));
            continue;
        }
        let record = cited_records[0];
        if !record.message.contains("LocateSup selected")
            || exact_values.iter().any(|(_, message_field, value)| {
                exact_message_field(&record.message, message_field) != Some(*value)
            })
        {
            failures.push(format!(
                "{artifact_id}: exact counterpart key is not bound to the cited LocateSup record"
            ));
        }

        let usable_timestamp = match (
            &record.timestamp.ordering_state,
            record.timestamp.utc_millis,
            record.timestamp.offset_minutes,
        ) {
            (SccmTimeOrderingState::NormalizedUtc, Some(utc_millis), Some(offset_minutes)) => {
                DateTime::<Utc>::from_timestamp_millis(utc_millis).map(|timestamp| {
                    serde_json::json!({
                        "normalizedUtc": timestamp.to_rfc3339_opts(SecondsFormat::Millis, true),
                        "utcMillis": utc_millis,
                        "offsetMinutes": offset_minutes,
                        "orderingState": "normalizedUtc"
                    })
                })
            }
            _ => None,
        };
        if usable_timestamp.as_ref() != Some(&fact["timestampProvenance"]) {
            failures.push(format!(
                "{artifact_id}: counterpart timestamp provenance is missing, unusable, or not bound to the cited CCM record"
            ));
        }
    }

    failures
}

fn scenario_semantic_failures(
    scenario_dir: &Path,
    manifest: &Value,
    expected: &Value,
    contract: &ScenarioContract,
) -> Vec<String> {
    let mut failures =
        manifest_expected_binding_failures(scenario_dir, manifest, expected, contract.name);
    failures.extend(expected_boundary_failures(expected, contract));
    failures.extend(counterpart_source_failures(
        scenario_dir,
        manifest,
        expected,
    ));
    failures
}

fn manifest_artifact_failures(scenario_dir: &Path, artifact: &Value) -> Vec<String> {
    let mut failures = Vec::new();
    let artifact_id = artifact["artifactId"].as_str().unwrap_or("<missing>");
    let state = artifact["captureState"].as_str().unwrap_or("<missing>");
    let fragment_complete_field = artifact
        .get("rotation")
        .and_then(Value::as_object)
        .and_then(|rotation| rotation.get("fragmentComplete"));
    let fragment_complete = fragment_complete_field.and_then(Value::as_bool);
    let physical = matches!(state, "captured" | "capped");

    if physical
        && artifact["pathFingerprint"]
            .as_str()
            .is_none_or(|fingerprint| fingerprint.trim().is_empty())
    {
        failures.push(format!(
            "{artifact_id}: physical artifact must have non-empty pathFingerprint"
        ));
    }
    if physical && fragment_complete.is_none() {
        failures.push(format!(
            "{artifact_id}: physical artifact must declare fragmentComplete"
        ));
    }
    if matches!(state, "absent" | "skipped") && fragment_complete_field.is_some() {
        failures.push(format!(
            "{artifact_id}: nonphysical rotation fragmentComplete must be omitted for {state}"
        ));
    }
    if matches!(
        state,
        "absent" | "accessDenied" | "capped" | "skipped" | "unsupported" | "parseFailed"
    ) && fragment_complete == Some(true)
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
        if !safe_evidence_relative_path(relative_path) {
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
        let byte_limit = match artifact["collectionLimit"]["byteLimit"].as_u64() {
            Some(byte_limit) => byte_limit,
            None => {
                failures.push(format!(
                    "{artifact_id}: physical artifact must declare byteLimit"
                ));
                0
            }
        };
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

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let bit_length = (bytes.len() as u64)
        .checked_mul(8)
        .expect("fixture byte length fits SHA-256");
    let mut padded = bytes.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_length.to_be_bytes());

    let mut state = [
        0x6a09e667u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    for chunk in padded.chunks_exact(64) {
        let mut words = [0u32; 64];
        for (index, word) in words.iter_mut().take(16).enumerate() {
            let offset = index * 4;
            *word = u32::from_be_bytes([
                chunk[offset],
                chunk[offset + 1],
                chunk[offset + 2],
                chunk[offset + 3],
            ]);
        }
        for index in 16..64 {
            let sigma0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let sigma1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(sigma0)
                .wrapping_add(words[index - 7])
                .wrapping_add(sigma1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ ((!e) & g);
            let temporary1 = h
                .wrapping_add(sum1)
                .wrapping_add(choose)
                .wrapping_add(SHA256_ROUND_CONSTANTS[index])
                .wrapping_add(words[index]);
            let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temporary2 = sum0.wrapping_add(majority);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temporary1);
            d = c;
            c = b;
            b = a;
            a = temporary1.wrapping_add(temporary2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    let mut digest = [0u8; 32];
    for (index, word) in state.iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
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

        failures.extend(scenario_semantic_failures(
            &scenario_dir,
            &manifest,
            &expected,
            contract,
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
    let mut physical_bytes = 0u64;
    let mut physical_lines = 0u64;
    let mut complete_ccm_records = 0usize;
    let mut partial_files = 0usize;
    let mut capped_files = 0usize;

    for contract in &SCENARIOS {
        let scenario_dir = updates_root().join(contract.name);
        let manifest = read_json(&scenario_dir.join("manifest.json"));
        let expected = read_json(&scenario_dir.join("expected.json"));
        let mut line_counts = BTreeMap::new();
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
            physical_bytes += bytes.len() as u64;
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
            physical_lines += lines;
            line_counts.insert(artifact_id.clone(), lines);
            if artifact["captureState"] == "capped" {
                capped_files += 1;
            } else if artifact["captureState"] == "captured"
                && artifact["rotation"]["fragmentComplete"] == false
            {
                partial_files += 1;
            }

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
                    complete_ccm_records += parsed.entries.len();
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
    assert_eq!(
        physical_bytes, EXPECTED_PHYSICAL_BYTES,
        "#323 physical evidence byte total drifted"
    );
    assert_eq!(
        physical_lines, EXPECTED_PHYSICAL_LINES,
        "#323 physical evidence line total drifted"
    );
    assert_eq!(
        complete_ccm_records, EXPECTED_COMPLETE_CCM_RECORDS,
        "#323 complete CCM record total drifted"
    );
    assert_eq!(
        partial_files, EXPECTED_PARTIAL_FILES,
        "#323 partial-fragment file total drifted"
    );
    assert_eq!(
        capped_files, EXPECTED_CAPPED_FILES,
        "#323 capped file total drifted"
    );

    corpus_items.sort_by(|left, right| left.0.cmp(&right.0));
    let per_file_hashes = corpus_items
        .iter()
        .map(|(relative_path, bytes)| format!("{relative_path} {}", hex_digest(&sha256(bytes))))
        .collect::<Vec<_>>();
    let corpus_hash =
        corpus_items
            .iter()
            .fold(0xcbf2_9ce4_8422_2325, |hash, (relative_path, bytes)| {
                let hash = fnv1a64(relative_path.as_bytes(), hash);
                let hash = fnv1a64(&[0], hash);
                fnv1a64(bytes, hash)
            });
    assert_eq!(
        corpus_hash,
        EXPECTED_CORPUS_FNV1A64,
        "#323 path-qualified evidence corpus FNV drifted; per-file SHA-256:\n{}",
        per_file_hashes.join("\n")
    );
    let mut corpus_sha_input = Vec::new();
    for (relative_path, bytes) in &corpus_items {
        corpus_sha_input.extend_from_slice(relative_path.as_bytes());
        corpus_sha_input.push(0);
        corpus_sha_input.extend_from_slice(bytes);
    }
    assert_eq!(
        hex_digest(&sha256(&corpus_sha_input)),
        EXPECTED_CORPUS_SHA256,
        "#323 path-qualified evidence corpus SHA-256 drifted; per-file SHA-256:\n{}",
        per_file_hashes.join("\n")
    );

    let capped = std::fs::read(
        updates_root().join("capped/evidence/client-content/current/DataTransferService.log"),
    )
    .expect("capped update fixture is readable");
    assert_eq!(
        capped,
        EXPECTED_CAPPED_CONTENT,
        "#323 capped content drifted; actual SHA-256 {}",
        hex_digest(&sha256(&capped))
    );

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
    let rotation_dir = updates_root().join("rotation-boundary/evidence/client-updates");
    let current_fragment = std::fs::read_to_string(rotation_dir.join("current/ScanAgent.log"))
        .expect("current rotation fragment is readable");
    let lo_fragment = std::fs::read_to_string(rotation_dir.join("lo/ScanAgent.lo_"))
        .expect(".lo_ rotation fragment is readable");
    for joined in [
        format!("{current_fragment}{lo_fragment}"),
        format!("{lo_fragment}{current_fragment}"),
    ] {
        let parsed =
            parse_content_with_selection(&joined, "joined-rotation.log", &ResolvedParser::ccm());
        assert_eq!(
            parsed.parse_errors, 2,
            "physical rotation fragments must retain both CCM parse errors"
        );
        assert!(
            parsed
                .entries
                .iter()
                .all(|entry| entry.format != LogFormat::Ccm),
            "physical rotation fragments must never join into a logical CCM record"
        );
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn software_update_fixture_contract_rejects_coverage_and_causality_mutations() {
    let scenario_dir = updates_root().join("success");
    let mut wrong_site = read_json(&scenario_dir.join("manifest.json"));
    wrong_site["bundle"]["siteCode"] = Value::String("ABC".to_owned());
    assert!(manifest_identity_failures(&wrong_site, "success")
        .iter()
        .any(|failure| failure.contains("manifest identity")));

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

#[test]
fn software_update_fixture_contract_rejects_review_adversarial_mutations() {
    fn failures_for(scenario: &str, manifest: &Value, expected: &Value) -> Vec<String> {
        let contract = SCENARIOS
            .iter()
            .find(|contract| contract.name == scenario)
            .expect("scenario contract exists");
        scenario_semantic_failures(&updates_root().join(scenario), manifest, expected, contract)
    }

    fn assert_rejected(failures: &[String], marker: &str) {
        assert!(
            failures.iter().any(|failure| failure.contains(marker)),
            "expected rejection containing {marker:?}, got:\n{}",
            failures.join("\n")
        );
    }

    let success_dir = updates_root().join("success");
    let success_manifest = read_json(&success_dir.join("manifest.json"));
    let success_expected = read_json(&success_dir.join("expected.json"));

    let mut wrong_key = success_expected.clone();
    wrong_key["transactions"][0]["key"]["updateId"] =
        Value::String("32300000-0000-0000-0000-000000009999".to_owned());
    wrong_key["transactions"][0]["key"]["ciId"] = Value::String("CI-DRIFT".to_owned());
    wrong_key["transactions"][0]["key"]["updateJobId"] = Value::String("JOB-DRIFT".to_owned());
    assert_rejected(
        &failures_for("success", &success_manifest, &wrong_key),
        "exact transaction key",
    );

    let mut foreign_citation = success_expected.clone();
    foreign_citation["transactions"][0]["evidence"][0]["artifactId"] =
        Value::String("updates-access-denied-01-scan".to_owned());
    assert_rejected(
        &failures_for("success", &success_manifest, &foreign_citation),
        "same-scenario citation",
    );

    let mut conflicting_coverage = success_expected.clone();
    conflicting_coverage["coverage"]
        .as_array_mut()
        .expect("coverage is an array")
        .push(serde_json::json!({
            "logicalArtifactId": "client-updates",
            "state": "absent"
        }));
    assert_rejected(
        &failures_for("success", &success_manifest, &conflicting_coverage),
        "coverage projection",
    );

    let mut wrong_gap = success_expected.clone();
    wrong_gap["transactions"][0]["coverageGapArtifactIds"] = serde_json::json!(["client-updates"]);
    assert_rejected(
        &failures_for("success", &success_manifest, &wrong_gap),
        "coverage gaps",
    );

    let mut wrong_provenance = success_expected.clone();
    wrong_provenance["artifactProvenance"][0]["captureState"] = Value::String("absent".to_owned());
    assert_rejected(
        &failures_for("success", &success_manifest, &wrong_provenance),
        "artifact provenance",
    );

    let mut wrong_kind_manifest = success_manifest.clone();
    wrong_kind_manifest["artifacts"][0]["kind"] = Value::String("cbsLog".to_owned());
    assert_rejected(
        &failures_for("success", &wrong_kind_manifest, &success_expected),
        "artifact kind",
    );

    let mut wrong_version_manifest = success_manifest.clone();
    wrong_version_manifest["artifacts"][1]["sourceVersion"] =
        Value::String("9.99.UNKNOWN".to_owned());
    assert_rejected(
        &failures_for("success", &wrong_version_manifest, &success_expected),
        "source profile/version",
    );

    let mut bogus_timestamp = success_expected.clone();
    bogus_timestamp["correlationHandoff"]["counterpartReadyFacts"][0]["timestampProvenance"] = serde_json::json!({
        "normalizedUtc": "2099-01-01T00:00:00.000Z",
        "utcMillis": 4070908800000_i64,
        "offsetMinutes": 840,
        "orderingState": "normalizedUtc"
    });
    assert_rejected(
        &failures_for("success", &success_manifest, &bogus_timestamp),
        "counterpart timestamp provenance",
    );

    let mut prefix_key = success_expected.clone();
    prefix_key["correlationHandoff"]["counterpartReadyFacts"][0]["ciId"] =
        Value::String("CI-UPDATE".to_owned());
    assert_rejected(
        &failures_for("success", &success_manifest, &prefix_key),
        "exact counterpart key",
    );

    let mut wrong_site = success_manifest.clone();
    wrong_site["bundle"]["siteCode"] = Value::String("ABC".to_owned());
    assert_rejected(
        &failures_for("success", &wrong_site, &success_expected),
        "manifest identity",
    );

    let supplemental_dir = updates_root().join("supplemental-conflict");
    let supplemental_manifest = read_json(&supplemental_dir.join("manifest.json"));
    let mut elevated_supplemental = read_json(&supplemental_dir.join("expected.json"));
    elevated_supplemental["sourceLocalObservations"][0]["confidence"] =
        Value::String("high".to_owned());
    elevated_supplemental["sourceLocalObservations"][0]["confidenceCeiling"] =
        Value::String("high".to_owned());
    elevated_supplemental["findings"][0]["confidence"] = Value::String("high".to_owned());
    elevated_supplemental["findings"][0]["confidenceCeiling"] = Value::String("high".to_owned());
    assert_rejected(
        &failures_for(
            "supplemental-conflict",
            &supplemental_manifest,
            &elevated_supplemental,
        ),
        "conservative confidence",
    );

    let invalid_dir = updates_root().join("invalid-offset");
    let invalid_manifest = read_json(&invalid_dir.join("manifest.json"));
    let mut elevated_invalid = read_json(&invalid_dir.join("expected.json"));
    elevated_invalid["findings"][0]["confidence"] = Value::String("high".to_owned());
    elevated_invalid["findings"][0]["confidenceCeiling"] = Value::String("high".to_owned());
    assert_rejected(
        &failures_for("invalid-offset", &invalid_manifest, &elevated_invalid),
        "conservative confidence",
    );

    let same_minute_dir = updates_root().join("same-minute-separate");
    let same_minute_manifest = read_json(&same_minute_dir.join("manifest.json"));
    let mut merged_outcome = read_json(&same_minute_dir.join("expected.json"));
    merged_outcome["transactions"][1]["state"] = Value::String("succeeded".to_owned());
    merged_outcome["transactions"][1]["classification"] = Value::String("success".to_owned());
    assert_rejected(
        &failures_for(
            "same-minute-separate",
            &same_minute_manifest,
            &merged_outcome,
        ),
        "same-minute transaction outcomes",
    );

    let no_sup_dir = updates_root().join("no-sup");
    let no_sup_manifest = read_json(&no_sup_dir.join("manifest.json"));
    let no_sup_expected = read_json(&no_sup_dir.join("expected.json"));
    let mut invented_sup = no_sup_expected.clone();
    invented_sup["transactions"][0]["key"]["supHostHandle"] =
        Value::String("safe:sup:lab-sup-01".to_owned());
    assert_rejected(
        &failures_for("no-sup", &no_sup_manifest, &invented_sup),
        "SUP handle without LocateSup",
    );

    let mut nonphysical_fragment = no_sup_manifest.clone();
    nonphysical_fragment["artifacts"][1]["rotation"]["fragmentComplete"] = Value::Bool(false);
    assert_rejected(
        &failures_for("no-sup", &nonphysical_fragment, &no_sup_expected),
        "nonphysical rotation fragmentComplete",
    );
}

#[test]
fn software_update_fixture_rejects_report_success_without_report_evidence() {
    let scenario = "success";
    let scenario_dir = updates_root().join(scenario);
    let manifest = read_json(&scenario_dir.join("manifest.json"));
    let mut expected = read_json(&scenario_dir.join("expected.json"));
    expected["transactions"][0]["evidence"] = serde_json::json!([
        {
            "artifactId": "updates-success-01-scan",
            "startLine": 1,
            "endLine": 2
        },
        {
            "artifactId": "updates-success-02-sup",
            "startLine": 1,
            "endLine": 1
        }
    ]);
    let contract = SCENARIOS
        .iter()
        .find(|contract| contract.name == scenario)
        .expect("success contract exists");
    let failures = scenario_semantic_failures(&scenario_dir, &manifest, &expected, contract);
    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("phase outcome evidence")),
        "Report/High success without Report evidence was accepted:\n{}",
        failures.join("\n")
    );
}

#[test]
fn software_update_fixture_rejects_install_failure_without_terminal_evidence() {
    let scenario = "install-failure";
    let scenario_dir = updates_root().join(scenario);
    let manifest = read_json(&scenario_dir.join("manifest.json"));
    let mut expected = read_json(&scenario_dir.join("expected.json"));
    let reduced_evidence = serde_json::json!([
        {
            "artifactId": "updates-install-failure-01-scan",
            "startLine": 1,
            "endLine": 2
        },
        {
            "artifactId": "updates-install-failure-02-sup",
            "startLine": 1,
            "endLine": 1
        }
    ]);
    expected["transactions"][0]["evidence"] = reduced_evidence.clone();
    expected["findings"][0]["evidence"] = reduced_evidence;
    let contract = SCENARIOS
        .iter()
        .find(|contract| contract.name == scenario)
        .expect("install-failure contract exists");
    let failures = scenario_semantic_failures(&scenario_dir, &manifest, &expected, contract);
    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("phase outcome evidence")),
        "Install/High confirmedFailure without terminal evidence was accepted:\n{}",
        failures.join("\n")
    );
}

#[test]
fn software_update_fixture_rejects_cross_record_exact_key_chimeras() {
    let scenario_dir = updates_root().join("same-minute-separate");
    let manifest = read_json(&scenario_dir.join("manifest.json"));
    let mut expected = read_json(&scenario_dir.join("expected.json"));
    expected["transactions"][0]["evidence"][0]["endLine"] = Value::from(2);
    for field in ["ciId", "contentId", "updateJobId", "clientHandle"] {
        expected["transactions"][0]["key"][field] =
            expected["transactions"][1]["key"][field].clone();
    }
    let (index, index_failures) = evidence_index(&scenario_dir, &manifest);
    assert!(index_failures.is_empty(), "{}", index_failures.join("\n"));
    let failures = transaction_binding_failures("same-minute-separate", &expected, &index);
    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("complete exact key tuple")),
        "same-minute cross-record key chimera was accepted:\n{}",
        failures.join("\n")
    );
}

#[test]
fn software_update_fixture_rejects_manifest_aliases_and_identity_drift() {
    let scenario = "success";
    let scenario_dir = updates_root().join(scenario);
    let base_manifest = read_json(&scenario_dir.join("manifest.json"));
    let base_expected = read_json(&scenario_dir.join("expected.json"));
    let contract = SCENARIOS
        .iter()
        .find(|contract| contract.name == scenario)
        .expect("success contract exists");
    let mut missing_rejections = Vec::new();
    let mut require_rejection = |label: &str, manifest: &Value, expected: &Value, marker: &str| {
        let failures = scenario_semantic_failures(&scenario_dir, manifest, expected, contract);
        if !failures.iter().any(|failure| failure.contains(marker)) {
            missing_rejections.push(format!(
                "{label} (wanted {marker:?}; got {})",
                failures.join(" | ")
            ));
        }
    };

    let mut duplicate_group = base_manifest.clone();
    duplicate_group["artifacts"][0]["designOnlyCatalog"]["groupMemberships"]
        .as_array_mut()
        .expect("group memberships are an array")
        .push(Value::String("client-updates".to_owned()));
    require_rejection(
        "duplicate group alias",
        &duplicate_group,
        &base_expected,
        "group memberships",
    );

    let mut duplicate_artifact = base_manifest.clone();
    let mut artifact_alias = duplicate_artifact["artifacts"][0].clone();
    artifact_alias["artifactId"] = Value::String("updates-success-09-scan-alias".to_owned());
    duplicate_artifact["artifacts"]
        .as_array_mut()
        .expect("artifacts are an array")
        .push(artifact_alias);
    let mut alias_expected = base_expected.clone();
    let mut provenance_alias = alias_expected["artifactProvenance"][0].clone();
    provenance_alias["artifactId"] = Value::String("updates-success-09-scan-alias".to_owned());
    alias_expected["artifactProvenance"]
        .as_array_mut()
        .expect("artifact provenance is an array")
        .push(provenance_alias);
    require_rejection(
        "relativePath/pathFingerprint artifact alias",
        &duplicate_artifact,
        &alias_expected,
        "duplicate physical alias",
    );

    let mut server_role = base_manifest.clone();
    server_role["artifacts"][0]["role"] = Value::String("server".to_owned());
    require_rejection(
        "server role in client corpus",
        &server_role,
        &base_expected,
        "artifact role",
    );

    let mut catalog_substitution = base_manifest.clone();
    catalog_substitution["artifacts"][6]["designOnlyCatalog"]["entryId"] =
        Value::String("client-content".to_owned());
    let mut profile_substitution = base_expected.clone();
    profile_substitution["extractionProfile"]["validatedArtifactFamilies"]
        .as_array_mut()
        .expect("validated families are an array")
        .retain(|family| family != "client-policy-state");
    require_rejection(
        "catalog entry/profile family substitution",
        &catalog_substitution,
        &profile_substitution,
        "catalog entry/logical group",
    );

    let mut wrong_rotation = base_manifest.clone();
    wrong_rotation["artifacts"][0]["rotation"]["kind"] = Value::String("lo".to_owned());
    require_rejection(
        "rotation/path mismatch",
        &wrong_rotation,
        &base_expected,
        "rotation kind",
    );

    let mut redirected_report = base_manifest.clone();
    let scan = redirected_report["artifacts"][0].clone();
    for field in [
        "relativePath",
        "originalBasename",
        "sanitizedSourcePath",
        "bytesCopied",
        "encoding",
        "collectionLimit",
        "sourceVersion",
        "rotation",
    ] {
        redirected_report["artifacts"][6][field] = scan[field].clone();
    }
    require_rejection(
        "report artifact redirected to scan path",
        &redirected_report,
        &base_expected,
        "relativePath is incompatible",
    );

    assert!(
        missing_rejections.is_empty(),
        "semantic validator accepted manifest drift:\n{}",
        missing_rejections.join("\n")
    );
}

#[test]
fn software_update_fixture_rejects_missing_or_blank_physical_path_fingerprints() {
    let scenario = "success";
    let scenario_dir = updates_root().join(scenario);
    let base_manifest = read_json(&scenario_dir.join("manifest.json"));
    let expected = read_json(&scenario_dir.join("expected.json"));
    let contract = SCENARIOS
        .iter()
        .find(|contract| contract.name == scenario)
        .expect("success contract exists");
    let mut missing_rejections = Vec::new();

    let mut missing = base_manifest.clone();
    missing["artifacts"][0]
        .as_object_mut()
        .expect("artifact is an object")
        .remove("pathFingerprint");
    let mut mutations = vec![("missing", missing)];
    for (label, value) in [
        ("null", Value::Null),
        ("empty", Value::String(String::new())),
        ("blank", Value::String(" \t".to_owned())),
    ] {
        let mut manifest = base_manifest.clone();
        manifest["artifacts"][0]["pathFingerprint"] = value;
        mutations.push((label, manifest));
    }

    for (label, manifest) in mutations {
        let failures = scenario_semantic_failures(&scenario_dir, &manifest, &expected, contract);
        if !failures.iter().any(|failure| {
            failure.contains("physical artifact must have non-empty pathFingerprint")
        }) {
            missing_rejections.push(format!("{label}: {}", failures.join(" | ")));
        }
    }

    assert!(
        missing_rejections.is_empty(),
        "physical artifact fingerprint mutations were accepted:\n{}",
        missing_rejections.join("\n")
    );
}

#[test]
fn software_update_fixture_rejects_unevaluated_topology_claims_and_eligibility() {
    let scenario = "success";
    let scenario_dir = updates_root().join(scenario);
    let manifest = read_json(&scenario_dir.join("manifest.json"));
    let base_expected = read_json(&scenario_dir.join("expected.json"));
    let contract = SCENARIOS
        .iter()
        .find(|contract| contract.name == scenario)
        .expect("success contract exists");
    let mut missing_rejections = Vec::new();

    for (label, value) in [
        ("compatible", Value::Bool(true)),
        ("incompatible", Value::Bool(false)),
        ("malformed-string", Value::String("unknown".to_owned())),
        ("malformed-null", Value::Null),
    ] {
        let mut expected = base_expected.clone();
        expected["correlationHandoff"]["counterpartReadyFacts"][0]["correlationEligible"] =
            Value::Bool(false);
        expected["correlationHandoff"]["counterpartReadyFacts"][0]["topologyCompatible"] = value;
        let failures = scenario_semantic_failures(&scenario_dir, &manifest, &expected, contract);
        if !failures
            .iter()
            .any(|failure| failure.contains("unevaluated topology compatibility"))
        {
            missing_rejections.push(format!("{label}: {}", failures.join(" | ")));
        }
    }

    for label in ["missing-evaluation", "null-evaluation"] {
        let mut expected = base_expected.clone();
        expected["correlationHandoff"]["counterpartReadyFacts"][0]["correlationEligible"] =
            Value::Bool(false);
        expected["correlationHandoff"]["counterpartReadyFacts"][0]["topologyCompatible"] =
            Value::Bool(true);
        if label == "missing-evaluation" {
            expected["correlationHandoff"]
                .as_object_mut()
                .expect("correlation handoff is an object")
                .remove("topologyCompatibilityEvaluated");
        } else {
            expected["correlationHandoff"]["topologyCompatibilityEvaluated"] = Value::Null;
        }
        let failures = counterpart_source_failures(&scenario_dir, &manifest, &expected);
        if !failures
            .iter()
            .any(|failure| failure.contains("unevaluated topology compatibility"))
        {
            missing_rejections.push(format!("{label}: {}", failures.join(" | ")));
        }
    }

    let mut eligible = base_expected;
    eligible["correlationHandoff"]["counterpartReadyFacts"][0]
        .as_object_mut()
        .expect("counterpart fact is an object")
        .remove("topologyCompatible");
    eligible["correlationHandoff"]["counterpartReadyFacts"][0]["correlationEligible"] =
        Value::Bool(true);
    let failures = scenario_semantic_failures(&scenario_dir, &manifest, &eligible, contract);
    if !failures
        .iter()
        .any(|failure| failure.contains("unevaluated topology compatibility"))
    {
        missing_rejections.push(format!(
            "correlation-eligible without topology evaluation: {}",
            failures.join(" | ")
        ));
    }

    assert!(
        missing_rejections.is_empty(),
        "unevaluated topology mutations were accepted:\n{}",
        missing_rejections.join("\n")
    );
}

#[test]
fn software_update_fixture_rejects_topology_mismatch_as_correlation_eligible() {
    let scenario = "success";
    let scenario_dir = updates_root().join(scenario);
    let manifest = read_json(&scenario_dir.join("manifest.json"));
    let mut expected = read_json(&scenario_dir.join("expected.json"));
    expected["correlationHandoff"]["counterpartReadyFacts"][0]["topologyCompatible"] =
        Value::Bool(false);
    expected["correlationHandoff"]["counterpartReadyFacts"][0]["correlationEligible"] =
        Value::Bool(true);
    let failures = counterpart_source_failures(&scenario_dir, &manifest, &expected);
    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("topology mismatch")),
        "topology-incompatible correlation fact was accepted:\n{}",
        failures.join("\n")
    );
}

#[test]
fn software_update_fixture_never_elevates_experimental_low_keys_to_causal_confidence() {
    let scenario_dir = updates_root().join("success");
    let manifest = read_json(&scenario_dir.join("manifest.json"));
    let expected = read_json(&scenario_dir.join("expected.json"));
    let (index, failures) = evidence_index(&scenario_dir, &manifest);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    let evidence = index["updates-success-01-scan"]
        .complete_ccm_records
        .first()
        .expect("success scan supplies one complete CCM record");
    let result = extract_keys(
        evidence,
        &SccmExtractionProfile::for_version(Some("5.00.9128.1007")),
    );
    assert!(!result.keys.is_empty());
    assert!(result
        .keys
        .iter()
        .all(|key| key.confidence == SccmKeyConfidence::Low));
    assert!(result
        .gaps
        .iter()
        .any(|gap| gap.kind == SccmExtractionGapKind::ExperimentalProfile));

    let mut elevated = expected;
    elevated["extractionProfile"]["profileId"] =
        Value::String(SCCM_EXPERIMENTAL_KEY_PROFILE_ID.to_owned());
    elevated["transactions"][0]["key"]["extractionProfileId"] =
        Value::String(SCCM_EXPERIMENTAL_KEY_PROFILE_ID.to_owned());
    elevated["correlationHandoff"]["counterpartReadyFacts"][0]["extractionProfileId"] =
        Value::String(SCCM_EXPERIMENTAL_KEY_PROFILE_ID.to_owned());
    assert!(experimental_profile_causality_failures(&elevated)
        .iter()
        .any(|failure| failure.contains("experimental Low key profile")));
}
