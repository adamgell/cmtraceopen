use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

const SCENARIOS: [&str; 12] = [
    "bits-transfer-failure",
    "cache-failure",
    "dependency-failure",
    "detection-false-negative",
    "dp-content-missing",
    "enforcement-exit",
    "incomplete",
    "location-missing",
    "not-targeted",
    "requirements-failure",
    "rotation-boundary",
    "success",
];

const STATE_CHAIN: [&str; 8] = [
    "intent",
    "requirements",
    "locateContent",
    "transfer",
    "cache",
    "enforce",
    "detect",
    "report",
];

fn deployment_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sccm/client/deployment")
}

fn load_json(path: &Path) -> Value {
    let contents = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{} is readable: {error}", path.display()));
    serde_json::from_str(&contents)
        .unwrap_or_else(|error| panic!("{} contains valid JSON: {error}", path.display()))
}

fn scenario_names() -> Vec<String> {
    let mut scenarios = std::fs::read_dir(deployment_root())
        .expect("deployment fixture root exists")
        .map(|entry| {
            entry
                .expect("deployment fixture directory entry is readable")
                .path()
        })
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

fn walk_files(root: &Path) -> Vec<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(path) = pending.pop() {
        if path.is_dir() {
            let mut children = std::fs::read_dir(&path)
                .expect("fixture directory is readable")
                .map(|entry| entry.expect("fixture entry is readable").path())
                .collect::<Vec<_>>();
            children.sort();
            pending.extend(children.into_iter().rev());
        } else {
            files.push(path);
        }
    }
    files
}

fn collect_evidence_refs(value: &Value, refs: &mut Vec<(String, u64, u64)>) {
    match value {
        Value::Object(object) => {
            if let (Some(artifact_id), Some(start_line), Some(end_line)) = (
                object.get("artifactId").and_then(Value::as_str),
                object.get("startLine").and_then(Value::as_u64),
                object.get("endLine").and_then(Value::as_u64),
            ) {
                refs.push((artifact_id.to_owned(), start_line, end_line));
            }
            for child in object.values() {
                collect_evidence_refs(child, refs);
            }
        }
        Value::Array(array) => {
            for child in array {
                collect_evidence_refs(child, refs);
            }
        }
        _ => {}
    }
}

fn json_string_array(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("value is an array")
        .iter()
        .map(|item| item.as_str().expect("array item is a string").to_owned())
        .collect()
}

fn sorted_ids(value: &Value, field: &str) -> Vec<String> {
    value
        .as_array()
        .expect("value is an array")
        .iter()
        .map(|item| {
            item[field]
                .as_str()
                .unwrap_or_else(|| panic!("{field} is a string"))
                .to_owned()
        })
        .collect()
}

#[test]
fn deployment_fixture_matrix_is_exact_safe_and_deterministic() {
    assert_eq!(
        scenario_names(),
        SCENARIOS.map(str::to_owned),
        "the #322 scenario matrix changed"
    );

    for scenario in SCENARIOS {
        let scenario_root = deployment_root().join(scenario);
        let manifest = load_json(&scenario_root.join("manifest.json"));
        let expected = load_json(&scenario_root.join("expected.json"));

        assert_eq!(
            manifest["scenario"], scenario,
            "{scenario}: manifest scenario"
        );
        assert_eq!(
            manifest["proposalOnly"], true,
            "{scenario}: proposal boundary"
        );
        assert_eq!(
            manifest["syntheticFixture"], true,
            "{scenario}: synthetic boundary"
        );
        assert_eq!(manifest["bundle"]["role"], "client", "{scenario}: role");
        assert_eq!(
            manifest["bundle"]["workflow"], "deployment",
            "{scenario}: workflow"
        );
        assert_eq!(
            manifest["bundle"]["siteCode"], "LAB",
            "{scenario}: exact synthetic site code"
        );

        assert_eq!(
            expected["contractState"], "proposedPending318And319",
            "{scenario}: dependency boundary"
        );
        assert_eq!(expected["workflow"], "deployment", "{scenario}: workflow");
        assert_eq!(
            expected["scenario"], scenario,
            "{scenario}: expected scenario"
        );
        assert_eq!(
            json_string_array(&expected["stateChain"]),
            STATE_CHAIN.map(str::to_owned),
            "{scenario}: phase chain"
        );
        assert_eq!(
            expected["analysisContract"]["independentReducer"], true,
            "{scenario}: independent reducer"
        );
        assert_eq!(
            expected["analysisContract"]["consumesPolicyReducerOutput"], false,
            "{scenario}: deployment must not consume policy output"
        );
        assert_eq!(
            expected["analysisContract"]["policyCoverageRequired"], false,
            "{scenario}: missing policy coverage must not block deployment facts"
        );
        assert_eq!(
            expected["analysisContract"]["crossSideCorrelationPerformed"], false,
            "{scenario}: no cross-side correlation"
        );
        assert_eq!(
            expected["reorderedInputDeterministic"], true,
            "{scenario}: deterministic input reordering contract"
        );

        let artifacts = manifest["artifacts"]
            .as_array()
            .expect("manifest artifacts are an array");
        let mut artifacts_by_id = BTreeMap::new();
        let mut referenced_files = BTreeSet::new();

        for artifact in artifacts {
            let artifact_id = artifact["artifactId"]
                .as_str()
                .expect("artifactId is a string");
            assert!(
                artifacts_by_id.insert(artifact_id, artifact).is_none(),
                "{scenario}: duplicate artifactId {artifact_id}"
            );
            assert_eq!(artifact["role"], "client", "{scenario}/{artifact_id}: role");

            let state = artifact["captureState"]
                .as_str()
                .expect("captureState is a string");
            let captured = matches!(state, "captured" | "capped");
            if captured {
                assert_eq!(
                    artifact["encoding"], "utf-8",
                    "{scenario}/{artifact_id}: encoding"
                );
                let relative_path = artifact["relativePath"]
                    .as_str()
                    .expect("captured artifact has a relativePath");
                let relative = Path::new(relative_path);
                assert!(
                    !relative.is_absolute()
                        && relative
                            .components()
                            .all(|component| matches!(component, Component::Normal(_))),
                    "{scenario}/{artifact_id}: unsafe relativePath {relative_path}"
                );
                assert_eq!(
                    relative.components().next(),
                    Some(Component::Normal(std::ffi::OsStr::new("evidence"))),
                    "{scenario}/{artifact_id}: evidence path root"
                );

                let fixture_path = scenario_root.join(relative);
                assert!(
                    fixture_path.is_file(),
                    "{scenario}/{artifact_id}: missing {}",
                    fixture_path.display()
                );
                let actual_bytes = std::fs::metadata(&fixture_path)
                    .expect("evidence metadata is readable")
                    .len();
                assert_eq!(
                    artifact["bytesCopied"].as_u64(),
                    Some(actual_bytes),
                    "{scenario}/{artifact_id}: exact bytes"
                );
                let contents =
                    std::fs::read_to_string(&fixture_path).expect("evidence fixture is UTF-8");
                if artifact["rotation"]["fragmentComplete"] == true {
                    assert!(
                        contents.contains("SYNTHETIC FIXTURE"),
                        "{scenario}/{artifact_id}: complete evidence needs a marker"
                    );
                }
                referenced_files.insert(
                    fixture_path
                        .canonicalize()
                        .expect("evidence fixture canonicalizes"),
                );
            } else {
                assert_eq!(
                    artifact["bytesCopied"], 0,
                    "{scenario}/{artifact_id}: noncapture bytes"
                );
                assert!(
                    artifact["relativePath"].is_null(),
                    "{scenario}/{artifact_id}: noncapture relativePath"
                );
                assert!(
                    artifact["encoding"].is_null(),
                    "{scenario}/{artifact_id}: noncapture encoding"
                );
                assert!(
                    artifact["collectionLimit"].is_null(),
                    "{scenario}/{artifact_id}: noncapture collectionLimit"
                );
            }
        }

        let evidence_files = walk_files(&scenario_root.join("evidence"))
            .into_iter()
            .map(|path| path.canonicalize().expect("evidence path canonicalizes"))
            .collect::<BTreeSet<_>>();
        assert_eq!(
            evidence_files, referenced_files,
            "{scenario}: evidence files must be referenced exactly once"
        );

        let provenance = expected["artifactProvenance"]
            .as_array()
            .expect("artifactProvenance is an array");
        let provenance_ids = sorted_ids(&expected["artifactProvenance"], "artifactId");
        let mut sorted_provenance_ids = provenance_ids.clone();
        sorted_provenance_ids.sort();
        assert_eq!(
            provenance_ids, sorted_provenance_ids,
            "{scenario}: provenance order"
        );
        for item in provenance {
            let artifact_id = item["artifactId"]
                .as_str()
                .expect("provenance artifactId is a string");
            let artifact = artifacts_by_id
                .get(artifact_id)
                .unwrap_or_else(|| panic!("{scenario}: unknown provenance {artifact_id}"));
            assert_eq!(
                item["bytesCopied"], artifact["bytesCopied"],
                "{scenario}/{artifact_id}: expected bytes mirror manifest"
            );
            assert_eq!(
                item["encoding"], artifact["encoding"],
                "{scenario}/{artifact_id}: expected encoding mirrors manifest"
            );
        }

        let transaction_ids = sorted_ids(&expected["transactions"], "transactionId");
        let mut sorted_transaction_ids = transaction_ids.clone();
        sorted_transaction_ids.sort();
        assert_eq!(
            transaction_ids, sorted_transaction_ids,
            "{scenario}: transaction order"
        );
        let finding_ids = sorted_ids(&expected["findings"], "findingId");
        let mut sorted_finding_ids = finding_ids.clone();
        sorted_finding_ids.sort();
        assert_eq!(finding_ids, sorted_finding_ids, "{scenario}: finding order");

        let mut evidence_refs = Vec::new();
        collect_evidence_refs(&expected, &mut evidence_refs);
        for (artifact_id, start_line, end_line) in evidence_refs {
            let artifact = artifacts_by_id
                .get(artifact_id.as_str())
                .unwrap_or_else(|| panic!("{scenario}: unknown evidence artifact {artifact_id}"));
            let relative_path = artifact["relativePath"]
                .as_str()
                .unwrap_or_else(|| panic!("{scenario}/{artifact_id}: evidence is not captured"));
            let contents = std::fs::read_to_string(scenario_root.join(relative_path))
                .expect("evidence fixture is readable");
            let line_count = contents.lines().count() as u64;
            assert!(
                start_line >= 1 && end_line >= start_line && end_line <= line_count,
                "{scenario}/{artifact_id}: invalid evidence lines {start_line}-{end_line}/{line_count}"
            );
        }

        for transaction in expected["transactions"]
            .as_array()
            .expect("transactions are an array")
        {
            if let Some(next_artifact) = transaction["nextArtifact"].as_object() {
                let logical_id = next_artifact["logicalArtifactId"]
                    .as_str()
                    .expect("next artifact logical ID is a string");
                assert!(
                    matches!(
                        logical_id,
                        "client-app-intent"
                            | "client-app-enforce"
                            | "client-content"
                            | "client-policy-state"
                    ),
                    "{scenario}: unbounded next artifact {logical_id}"
                );
                assert_ne!(
                    logical_id, "client-policy-agent",
                    "{scenario}: deployment must not depend on policy output"
                );
            }
        }

        for file in walk_files(&scenario_root) {
            let contents = std::fs::read_to_string(&file).expect("fixture file is UTF-8");
            for forbidden in [
                "CONTOSO",
                ".log.lo_",
                "C:\\Users\\",
                "Authorization:",
                "Bearer ",
                "client_secret",
                "S-1-",
            ] {
                assert!(
                    !contents.contains(forbidden),
                    "{} contains forbidden fixture material {forbidden}",
                    file.display()
                );
            }
        }
    }
}

#[test]
fn deployment_outcomes_keep_phases_and_coverage_conservative() {
    let cases = [
        (
            "bits-transfer-failure",
            1,
            "transfer",
            "failed",
            "locateContent",
            "confirmedFailure",
            "high",
            None,
        ),
        (
            "cache-failure",
            1,
            "cache",
            "failed",
            "transfer",
            "confirmedFailure",
            "high",
            None,
        ),
        (
            "dependency-failure",
            1,
            "requirements",
            "failed",
            "intent",
            "confirmedFailure",
            "high",
            None,
        ),
        (
            "detection-false-negative",
            1,
            "detect",
            "detectionMismatch",
            "enforce",
            "symptom",
            "medium",
            None,
        ),
        (
            "dp-content-missing",
            1,
            "locateContent",
            "insufficientEvidence",
            "requirements",
            "insufficientEvidence",
            "low",
            Some("client-content"),
        ),
        (
            "enforcement-exit",
            1,
            "enforce",
            "failed",
            "cache",
            "confirmedFailure",
            "high",
            None,
        ),
        (
            "incomplete",
            2,
            "locateContent",
            "insufficientEvidence",
            "requirements",
            "insufficientEvidence",
            "low",
            Some("client-content"),
        ),
        (
            "location-missing",
            1,
            "locateContent",
            "insufficientEvidence",
            "requirements",
            "insufficientEvidence",
            "low",
            Some("client-content"),
        ),
        (
            "not-targeted",
            1,
            "intent",
            "notTargeted",
            "",
            "notTargeted",
            "high",
            None,
        ),
        (
            "requirements-failure",
            1,
            "requirements",
            "failed",
            "intent",
            "confirmedFailure",
            "high",
            None,
        ),
        (
            "rotation-boundary",
            1,
            "locateContent",
            "insufficientEvidence",
            "requirements",
            "insufficientEvidence",
            "low",
            Some("client-content"),
        ),
        (
            "success",
            1,
            "report",
            "succeeded",
            "report",
            "success",
            "high",
            None,
        ),
    ];

    for (
        scenario,
        transaction_count,
        phase,
        state,
        last_success,
        classification,
        confidence,
        next_artifact,
    ) in cases
    {
        let expected = load_json(&deployment_root().join(scenario).join("expected.json"));
        let transactions = expected["transactions"]
            .as_array()
            .expect("transactions are an array");
        assert_eq!(
            transactions.len(),
            transaction_count,
            "{scenario}: transaction count"
        );
        for transaction in transactions {
            assert_eq!(transaction["phase"], phase, "{scenario}: phase");
            assert_eq!(transaction["state"], state, "{scenario}: state");
            if last_success.is_empty() {
                assert!(
                    transaction["lastSuccessfulPhase"].is_null(),
                    "{scenario}: last successful phase"
                );
            } else {
                assert_eq!(
                    transaction["lastSuccessfulPhase"], last_success,
                    "{scenario}: last successful phase"
                );
            }
            assert_eq!(
                transaction["classification"], classification,
                "{scenario}: classification"
            );
            assert_eq!(
                transaction["confidence"], confidence,
                "{scenario}: confidence"
            );
            assert_eq!(
                transaction["confidenceCeiling"], confidence,
                "{scenario}: confidence ceiling"
            );
            match next_artifact {
                Some(logical_id) => assert_eq!(
                    transaction["nextArtifact"]["logicalArtifactId"], logical_id,
                    "{scenario}: next artifact"
                ),
                None => assert!(
                    transaction["nextArtifact"].is_null(),
                    "{scenario}: unexpected next artifact"
                ),
            }
        }
    }
}

#[test]
fn counterpart_facts_require_exact_keys_and_adversarial_inputs_stay_unlinked() {
    let counterpart_scenarios = [
        "bits-transfer-failure",
        "cache-failure",
        "detection-false-negative",
        "dp-content-missing",
        "enforcement-exit",
        "success",
    ];

    for scenario in SCENARIOS {
        let expected = load_json(&deployment_root().join(scenario).join("expected.json"));
        let should_emit = counterpart_scenarios.contains(&scenario);
        let mut emitted = 0;

        for transaction in expected["transactions"]
            .as_array()
            .expect("transactions are an array")
        {
            let fact = &transaction["counterpartReadyFact"];
            if fact.is_null() {
                continue;
            }
            emitted += 1;
            assert!(should_emit, "{scenario}: unexpected counterpart-ready fact");
            assert_eq!(
                transaction["key"]["confidence"], "exact",
                "{scenario}: counterpart transaction key confidence"
            );
            assert_eq!(
                transaction["key"]["extractionProfileId"], "deployment-client-5.00.test-v1",
                "{scenario}: counterpart transaction profile"
            );
            assert_eq!(
                fact["extractionProfileId"], transaction["key"]["extractionProfileId"],
                "{scenario}: counterpart profile"
            );
            for field in [
                "packageId",
                "contentId",
                "contentVersion",
                "distributionPointHostHandle",
                "requestId",
            ] {
                assert_eq!(
                    fact[field], transaction["key"][field],
                    "{scenario}: counterpart {field}"
                );
            }
            assert_eq!(
                fact["timestampProvenance"]["kind"], "explicitOffset",
                "{scenario}: timestamp provenance"
            );
            assert_eq!(
                fact["timestampProvenance"]["offsetMinutes"], 0,
                "{scenario}: timestamp offset"
            );
            assert_eq!(
                fact["phase"], "locateContent",
                "{scenario}: counterpart phase"
            );
        }

        assert_eq!(
            emitted,
            usize::from(should_emit),
            "{scenario}: counterpart-ready fact count"
        );
        assert_eq!(
            expected["correlationHandoff"]["performed"], false,
            "{scenario}: #333 is not performed"
        );
        assert_eq!(
            expected["correlationHandoff"]["timeOnlyEligible"], false,
            "{scenario}: time-only cannot correlate"
        );
        assert_eq!(
            expected["correlationHandoff"]["topologyCompatibilityEvaluated"], false,
            "{scenario}: topology belongs to #333"
        );
        assert_eq!(
            expected["correlationHandoff"]["serverCauseClaimed"], false,
            "{scenario}: no DP/server cause"
        );
    }

    let incomplete = load_json(&deployment_root().join("incomplete").join("expected.json"));
    let transactions = incomplete["transactions"]
        .as_array()
        .expect("incomplete transactions are an array");
    assert_eq!(transactions.len(), 2);
    assert_ne!(
        transactions[0]["transactionId"], transactions[1]["transactionId"],
        "same-minute exact keys must stay separate"
    );
    assert_eq!(
        incomplete["adversarialControls"]["sameMinuteDifferentExactKeysStaySeparate"],
        true
    );

    let enforcement = load_json(
        &deployment_root()
            .join("enforcement-exit")
            .join("expected.json"),
    );
    let observations = enforcement["sourceLocalObservations"]
        .as_array()
        .expect("source-local observations are an array");
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0]["keyConfidence"], "none");
    assert_eq!(observations[0]["confidenceCeiling"], "low");
    assert_eq!(observations[0]["correlationEligible"], false);

    let success = load_json(&deployment_root().join("success").join("expected.json"));
    assert!(
        success["coverage"]
            .as_array()
            .expect("success coverage is an array")
            .iter()
            .any(|coverage| {
                coverage["logicalArtifactId"] == "client-policy-agent"
                    && coverage["state"] == "absent"
            }),
        "success must prove deployment independence from absent policy coverage"
    );
    assert_eq!(success["transactions"][0]["state"], "succeeded");
}
