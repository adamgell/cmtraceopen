use std::collections::{BTreeMap, BTreeSet};

use chrono::DateTime;
use cmtraceopen_parser::sccm::{
    classify_artifact_name, normalize_ccm_artifact, SccmArtifact, SccmArtifactFamily,
    SccmCoverageState, SccmEvidence, SccmRole, SccmRotation, SccmTimeOrderingState,
};
use serde_json::Value;

const SCENARIOS: &[&str] = &[
    "absent-remote-source",
    "backlog-retry",
    "clock-offset-unknown",
    "healthy-link",
    "incomplete",
    "receiver-processing-failure",
    "recovery",
    "rotation-boundary",
    "sender-failure",
    "topology-mismatch",
];

const STATE_CHAIN: &[&str] = &[
    "initiate",
    "queueOrSerialize",
    "send",
    "receive",
    "process",
    "acknowledge",
    "healthyOrTerminal",
];

const EXACT_PROFILE: &str = "hierarchy-server-5.00.test-v1";

fn corpus_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sccm/server/hierarchy_and_replication")
}

fn read_json(scenario: &str, filename: &str) -> Result<Value, String> {
    let path = corpus_root().join(scenario).join(filename);
    let contents = std::fs::read_to_string(&path)
        .map_err(|error| format!("{} is readable: {error}", path.display()))?;
    serde_json::from_str(&contents)
        .map_err(|error| format!("{} contains valid JSON: {error}", path.display()))
}

fn actual_scenarios() -> Result<Vec<String>, String> {
    let root = corpus_root();
    let mut scenarios = std::fs::read_dir(&root)
        .map_err(|error| format!("{} is readable: {error}", root.display()))?
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            path.is_dir().then(|| {
                path.file_name()
                    .expect("scenario directory has a name")
                    .to_string_lossy()
                    .into_owned()
            })
        })
        .collect::<Vec<_>>();
    scenarios.sort();
    Ok(scenarios)
}

fn required_string<'a>(value: &'a Value, field: &str, context: &str) -> Result<&'a str, String> {
    value[field]
        .as_str()
        .ok_or_else(|| format!("{context}.{field} must be a string"))
}

fn safe_segmented_path(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|suffix| {
        !suffix.is_empty()
            && !suffix.contains('\\')
            && suffix.split('/').all(|segment| {
                !segment.is_empty()
                    && !matches!(segment, "." | "..")
                    && segment.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                    })
            })
    })
}

fn coverage_state(value: &str) -> Option<SccmCoverageState> {
    match value {
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

fn rotation(value: &Value) -> Option<SccmRotation> {
    match value["kind"].as_str()? {
        "current" if value.get("value").is_none() => Some(SccmRotation::Current),
        "lo_" if value.get("value").is_none() => Some(SccmRotation::LoUnderscore),
        "numbered" => value["value"]
            .as_u64()
            .and_then(|number| u32::try_from(number).ok())
            .map(SccmRotation::Numbered),
        "timestamped" => value["value"]
            .as_str()
            .map(str::to_owned)
            .map(SccmRotation::Timestamped),
        _ => None,
    }
}

fn parse_fixture_fields(message: &str) -> Result<BTreeMap<String, String>, String> {
    let message = message
        .strip_prefix("[sccm-public-message-v1] ")
        .ok_or_else(|| "record lacks the public SCCM projection".to_owned())?;
    let mut segments = message.split(';').map(str::trim);
    if segments.next() != Some("SYNTHETIC FIXTURE") {
        return Err("record lacks the semantic synthetic marker".to_owned());
    }
    let allowed = [
        "Phase",
        "Disposition",
        "Terminal",
        "MessageId",
        "LinkId",
        "OriginSite",
        "TargetSite",
        "ProfileId",
    ];
    let mut fields = BTreeMap::new();
    for segment in segments {
        let (name, value) = segment
            .split_once('=')
            .ok_or_else(|| format!("fixture field is not Name=Value: {segment}"))?;
        if !allowed.contains(&name) || value.is_empty() {
            return Err(format!("unsupported or empty fixture field {name}"));
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(format!("fixture field {name} contains unsupported syntax"));
        }
        if fields.insert(name.to_owned(), value.to_owned()).is_some() {
            return Err(format!("duplicate fixture field {name}"));
        }
    }
    Ok(fields)
}

fn normalized_records(
    scenario: &str,
    manifest: &Value,
) -> BTreeMap<(String, u32, u32), SccmEvidence> {
    let mut records = BTreeMap::new();
    for artifact in manifest["artifacts"]
        .as_array()
        .expect("manifest artifacts are an array")
    {
        let state = artifact["captureState"].as_str().unwrap_or_default();
        if !matches!(state, "captured" | "capped") {
            continue;
        }
        let artifact_id = artifact["artifactId"]
            .as_str()
            .expect("artifact ID is a string");
        let relative_path = artifact["relativePath"]
            .as_str()
            .expect("physical artifact has a relative path");
        let content = std::fs::read_to_string(corpus_root().join(scenario).join(relative_path))
            .expect("fixture evidence is readable UTF-8");
        let model = SccmArtifact {
            artifact_id: artifact_id.to_owned(),
            display_name: artifact["originalBasename"]
                .as_str()
                .expect("artifact basename is a string")
                .to_owned(),
            original_path: None,
            host: artifact["producerHostHandle"].as_str().map(str::to_owned),
            role: SccmRole::SiteServer,
            configmgr_version: artifact["sourceVersion"].as_str().map(str::to_owned),
            collected_at_utc: artifact["collectedUtc"].as_str().map(str::to_owned),
            rotation: rotation(&artifact["rotation"]).expect("rotation is valid"),
            coverage: coverage_state(state).expect("coverage is valid"),
            encoding: Some("utf-8".to_owned()),
        };
        for record in normalize_ccm_artifact(model, &content) {
            let line_start = record
                .reference
                .line_start
                .expect("normalized evidence has a start line");
            let line_end = record
                .reference
                .line_end
                .expect("normalized evidence has an end line");
            assert!(
                records
                    .insert((artifact_id.to_owned(), line_start, line_end), record)
                    .is_none(),
                "{scenario}: duplicate physical logical evidence"
            );
        }
    }
    records
}

fn phase_is_owned_by(basename: &str, phase: &str) -> bool {
    matches!(
        (basename, phase),
        ("replmgr.log", "initiate" | "queueOrSerialize")
            | ("sender.log", "send")
            | ("despool.log", "receive" | "process" | "healthyOrTerminal")
            | ("rcmctrl.log", "acknowledge" | "healthyOrTerminal")
    )
}

fn expected_transaction_ids(scenario: &str) -> &'static [&'static str] {
    match scenario {
        "absent-remote-source" => &["hierarchy:msg-absent-01:LAB:CHD:link-lab-chd"],
        "backlog-retry" => &["hierarchy:msg-backlog-01:LAB:CHD:link-lab-chd"],
        "clock-offset-unknown" => &["hierarchy:msg-clock-01:LAB:CHD:link-lab-chd"],
        "healthy-link" => &["hierarchy:msg-healthy-01:LAB:CHD:link-lab-chd"],
        "receiver-processing-failure" => &["hierarchy:msg-receiver-01:LAB:CHD:link-lab-chd"],
        "recovery" => &["hierarchy:msg-recovery-01:LAB:CHD:link-lab-chd"],
        "sender-failure" => &[
            "hierarchy:msg-send-chd:LAB:CHD:link-lab-chd",
            "hierarchy:msg-send-sec:LAB:SEC:link-lab-sec",
        ],
        "incomplete" | "rotation-boundary" | "topology-mismatch" => &[],
        _ => &[],
    }
}

fn expected_observation_ids(scenario: &str) -> &'static [&'static str] {
    match scenario {
        "absent-remote-source" => &["absent-01-send"],
        "backlog-retry" => &["backlog-01-queue"],
        "clock-offset-unknown" => &["clock-01-send", "clock-02-process"],
        "healthy-link" => &[
            "healthy-01-initiate",
            "healthy-02-queue",
            "healthy-03-send",
            "healthy-04-receive",
            "healthy-05-process",
            "healthy-06-acknowledge",
            "healthy-07-terminal",
        ],
        "receiver-processing-failure" => &[
            "receiver-01-send",
            "receiver-02-receive",
            "receiver-03-process",
        ],
        "recovery" => &[
            "recovery-01-retry",
            "recovery-02-send",
            "recovery-03-receive",
            "recovery-04-process",
            "recovery-05-terminal",
        ],
        "sender-failure" => &["sender-01-chd-failure", "sender-02-sec-failure"],
        "incomplete" | "rotation-boundary" | "topology-mismatch" => &[],
        _ => &[],
    }
}

fn expected_source_local_ids(scenario: &str) -> &'static [&'static str] {
    match scenario {
        "incomplete" => &["incomplete-01-fragment"],
        "rotation-boundary" => &["rotation-01-split"],
        "topology-mismatch" => &["mismatch-01-origin", "mismatch-02-target"],
        _ => &[],
    }
}

fn object_has_only(value: &Value, fields: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|object| object.keys().all(|field| fields.contains(&field.as_str())))
}

fn identity_and_schema_failures(scenario: &str, manifest: &Value, expected: &Value) -> Vec<String> {
    let mut failures = Vec::new();
    if !object_has_only(
        manifest,
        &[
            "sccmManifestVersion",
            "proposalOnly",
            "syntheticFixture",
            "scenario",
            "bundle",
            "topology",
            "artifacts",
        ],
    ) || !object_has_only(
        &manifest["bundle"],
        &["bundleRole", "workflow", "capturedUtc"],
    ) || !object_has_only(
        &manifest["topology"],
        &[
            "originSiteCode",
            "targetSiteCode",
            "originHostHandle",
            "targetHostHandle",
            "rolesObserved",
        ],
    ) {
        failures.push("manifest contains an unsupported field or shape".to_owned());
    }
    let role_values = manifest["topology"]["rolesObserved"].as_array();
    if role_values.is_none_or(|roles| {
        roles.len() != 1 || roles.iter().any(|role| role.as_str() != Some("siteServer"))
    }) {
        failures.push("topology roles are not exact strings".to_owned());
    }

    let artifacts = manifest["artifacts"].as_array();
    if artifacts.is_none() {
        failures.push("artifacts is not an array".to_owned());
    }
    let mut artifact_ids = Vec::new();
    let mut destinations = BTreeSet::new();
    let mut fingerprints = BTreeSet::new();
    for artifact in artifacts.into_iter().flatten() {
        if !object_has_only(
            artifact,
            &[
                "artifactId",
                "sourceId",
                "producerRole",
                "producerHostHandle",
                "direction",
                "originalBasename",
                "sanitizedSourcePath",
                "pathFingerprint",
                "rotation",
                "captureState",
                "sourceVersion",
                "collectedUtc",
                "encoding",
                "collectionLimit",
                "bytesCopied",
                "relativePath",
            ],
        ) || !object_has_only(
            &artifact["rotation"],
            &["kind", "value", "lineageId", "fragmentComplete"],
        ) || artifact.get("collectionLimit").is_some()
            && !object_has_only(&artifact["collectionLimit"], &["byteLimit", "limitApplied"])
        {
            failures.push("artifact contains an unsupported field or shape".to_owned());
        }
        let Some(artifact_id) = artifact["artifactId"].as_str() else {
            failures.push("artifactId is not a string".to_owned());
            continue;
        };
        artifact_ids.push(artifact_id);
        let state = artifact["captureState"].as_str();
        if state.and_then(coverage_state).is_none() {
            failures.push(format!("{artifact_id}: invalid coverage type/state"));
        }
        if artifact["producerRole"] != "siteServer"
            || !matches!(artifact["direction"].as_str(), Some("origin" | "target"))
            || !artifact["sourceVersion"]
                .as_str()
                .is_some_and(|value| value.starts_with("5.00.TEST.") && value.len() > 10)
            || !artifact["sanitizedSourcePath"]
                .as_str()
                .is_some_and(|value| safe_segmented_path(value, "SYNTHETIC://"))
            || !artifact["pathFingerprint"].as_str().is_some_and(|value| {
                value
                    .strip_prefix("synthetic:")
                    .is_some_and(|suffix| !suffix.is_empty())
            })
        {
            failures.push(format!("{artifact_id}: invalid typed provenance"));
        }
        if artifact["pathFingerprint"]
            .as_str()
            .map(str::to_ascii_lowercase)
            .is_none_or(|value| !fingerprints.insert(value))
        {
            failures.push(format!("{artifact_id}: duplicate or invalid fingerprint"));
        }
        if rotation(&artifact["rotation"]).is_none()
            || artifact["rotation"]["lineageId"]
                .as_str()
                .is_none_or(str::is_empty)
        {
            failures.push(format!("{artifact_id}: invalid rotation provenance"));
        }
        match state {
            Some("captured" | "capped" | "parseFailed") => {
                let relative_path = artifact["relativePath"].as_str();
                if relative_path.is_none_or(|value| !safe_segmented_path(value, "evidence/"))
                    || relative_path
                        .map(str::to_ascii_lowercase)
                        .is_none_or(|value| !destinations.insert(value))
                    || artifact["bytesCopied"].as_u64().is_none()
                    || artifact["encoding"] != "utf-8"
                    || artifact["collectionLimit"]["byteLimit"].as_u64().is_none()
                    || artifact["collectionLimit"]["limitApplied"]
                        .as_bool()
                        .is_none()
                    || artifact["rotation"]["fragmentComplete"].as_bool().is_none()
                {
                    failures.push(format!("{artifact_id}: invalid physical provenance"));
                }
            }
            Some("absent" | "accessDenied" | "skipped" | "unsupported") => {
                if artifact.get("relativePath").is_some()
                    || artifact.get("bytesCopied").is_some()
                    || artifact.get("encoding").is_some()
                    || artifact.get("collectionLimit").is_some()
                    || artifact["rotation"].get("fragmentComplete").is_some()
                {
                    failures.push(format!(
                        "{artifact_id}: nonphysical state invents physical provenance"
                    ));
                }
            }
            _ => {}
        }
    }
    let mut sorted_artifact_ids = artifact_ids.clone();
    sorted_artifact_ids.sort_unstable();
    sorted_artifact_ids.dedup();
    if artifact_ids != sorted_artifact_ids {
        failures.push("artifact IDs are not sorted and unique".to_owned());
    }

    if !object_has_only(
        expected,
        &[
            "contractState",
            "workflow",
            "scenario",
            "stateChain",
            "analysisContract",
            "extractionProfile",
            "coverage",
            "transactions",
            "sourceLocalObservations",
            "artifactRequests",
            "crossSideCausalClaims",
            "correlationHandoff",
        ],
    ) || expected["contractState"] != "proposedPendingReviewed318And335"
        || expected["workflow"] != "hierarchyAndReplication"
        || expected["scenario"] != scenario
    {
        failures.push("expected output loses the preparation boundary".to_owned());
    }
    let state_values = expected["stateChain"].as_array();
    let state_chain = state_values
        .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .unwrap_or_default();
    if state_values.is_none_or(|values| values.len() != state_chain.len())
        || state_chain != STATE_CHAIN
    {
        failures.push("state chain is not exact typed #331 grammar".to_owned());
    }
    if expected["analysisContract"]["independentReducer"] != true
        || expected["analysisContract"]["crossSideCorrelationPerformed"] != false
        || expected["analysisContract"]["nativeCollectionPerformed"] != false
        || expected["extractionProfile"]["selectionState"] != "selectedSynthetic"
        || expected["extractionProfile"]["profileId"] != EXACT_PROFILE
        || expected["extractionProfile"]["validatedRole"] != "siteServer"
        || expected["crossSideCausalClaims"] != Value::Array(Vec::new())
        || expected["correlationHandoff"]["issue"] != "#333"
        || expected["correlationHandoff"]["performed"] != false
        || expected["correlationHandoff"]["timeOnlyEligible"] != false
    {
        failures
            .push("expected output enables unsupported production/correlation state".to_owned());
    }

    let transactions = expected["transactions"].as_array();
    let transaction_ids = transactions
        .into_iter()
        .flatten()
        .filter_map(|transaction| transaction["transactionId"].as_str())
        .collect::<Vec<_>>();
    if transaction_ids != expected_transaction_ids(scenario) {
        failures.push("transaction identity/cardinality matrix changed".to_owned());
    }
    for transaction in transactions.into_iter().flatten() {
        if !object_has_only(
            transaction,
            &[
                "transactionId",
                "key",
                "topologyCompatibility",
                "timestampOrdering",
                "terminalEvidence",
                "state",
                "classification",
                "confidence",
                "confidenceCeiling",
                "coverageGapArtifactIds",
                "observations",
            ],
        ) || !object_has_only(
            &transaction["key"],
            &[
                "messageId",
                "linkId",
                "originSiteCode",
                "targetSiteCode",
                "confidence",
                "extractionProfileId",
            ],
        ) {
            failures.push("transaction contains an unsupported field or shape".to_owned());
        }
        let transaction_id = transaction["transactionId"].as_str().unwrap_or_default();
        let key = &transaction["key"];
        let derived_id = [
            key["messageId"].as_str(),
            key["originSiteCode"].as_str(),
            key["targetSiteCode"].as_str(),
            key["linkId"].as_str(),
        ];
        if derived_id
            .iter()
            .any(|value| value.is_none_or(str::is_empty))
            || key["confidence"] != "exact"
            || key["extractionProfileId"] != EXACT_PROFILE
            || transaction_id
                != format!(
                    "hierarchy:{}:{}:{}:{}",
                    derived_id[0].unwrap_or_default(),
                    derived_id[1].unwrap_or_default(),
                    derived_id[2].unwrap_or_default(),
                    derived_id[3].unwrap_or_default()
                )
        {
            failures.push("transaction is not derived from one exact immutable key".to_owned());
        }
        let gap_values = transaction["coverageGapArtifactIds"].as_array();
        let gap_ids = gap_values
            .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>())
            .unwrap_or_default();
        let mut sorted_gap_ids = gap_ids.clone();
        sorted_gap_ids.sort_unstable();
        sorted_gap_ids.dedup();
        if gap_values.is_none_or(|values| values.len() != gap_ids.len())
            || gap_ids != sorted_gap_ids
        {
            failures.push("coverage gap IDs are not exact sorted strings".to_owned());
        }
        if transaction["confidence"] == "high"
            && (transaction["confidenceCeiling"] != "high"
                || transaction["topologyCompatibility"] != "exact"
                || transaction["timestampOrdering"] != "usable"
                || transaction["terminalEvidence"] != true
                || !gap_ids.is_empty())
        {
            failures
                .push("high confidence bypasses topology/time/terminal/coverage gates".to_owned());
        }
        let observations = transaction["observations"].as_array();
        for observation in observations.into_iter().flatten() {
            if !object_has_only(
                observation,
                &[
                    "observationId",
                    "phase",
                    "disposition",
                    "terminal",
                    "evidence",
                ],
            ) {
                failures.push("observation contains an unsupported field or shape".to_owned());
            }
            let references = observation["evidence"].as_array();
            if references.is_none_or(Vec::is_empty) {
                failures.push("transaction observation lacks cited evidence".to_owned());
            }
            for reference in references.into_iter().flatten() {
                if !object_has_only(reference, &["artifactId", "startLine", "endLine"])
                    || reference["artifactId"].as_str().is_none()
                    || reference["startLine"]
                        .as_u64()
                        .and_then(|value| u32::try_from(value).ok())
                        .is_none()
                    || reference["endLine"]
                        .as_u64()
                        .and_then(|value| u32::try_from(value).ok())
                        .is_none()
                {
                    failures.push("evidence reference is not exact and typed".to_owned());
                }
            }
        }
    }
    let observation_ids = transactions
        .into_iter()
        .flatten()
        .flat_map(|transaction| transaction["observations"].as_array().into_iter().flatten())
        .filter_map(|observation| observation["observationId"].as_str())
        .collect::<Vec<_>>();
    if observation_ids != expected_observation_ids(scenario) {
        failures.push("observation identity/cardinality matrix changed".to_owned());
    }
    let source_local_ids = expected["sourceLocalObservations"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|observation| observation["observationId"].as_str())
        .collect::<Vec<_>>();
    if source_local_ids != expected_source_local_ids(scenario) {
        failures.push("source-local identity/cardinality matrix changed".to_owned());
    }

    failures
}

#[test]
fn hierarchy_and_replication_scenario_matrix_is_exact() {
    assert_eq!(
        actual_scenarios().expect("hierarchy corpus root exists"),
        SCENARIOS,
        "the #331 scenario matrix changed"
    );

    for scenario in SCENARIOS {
        let manifest = read_json(scenario, "manifest.json")
            .unwrap_or_else(|error| panic!("{scenario}: {error}"));
        let expected = read_json(scenario, "expected.json")
            .unwrap_or_else(|error| panic!("{scenario}: {error}"));
        assert_eq!(manifest["scenario"], *scenario);
        assert_eq!(expected["scenario"], *scenario);
        assert_eq!(manifest["proposalOnly"], true);
        assert_eq!(manifest["syntheticFixture"], true);
        assert_eq!(expected["extractionProfile"]["profileId"], EXACT_PROFILE);
        assert_eq!(
            expected["stateChain"]
                .as_array()
                .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>())
                .as_deref(),
            Some(STATE_CHAIN)
        );
    }
}

#[test]
fn hierarchy_candidates_are_deterministic_and_collision_resistant() {
    for scenario in SCENARIOS {
        let manifest = read_json(scenario, "manifest.json")
            .unwrap_or_else(|error| panic!("{scenario}: {error}"));
        let artifacts = manifest["artifacts"]
            .as_array()
            .unwrap_or_else(|| panic!("{scenario}: artifacts are an array"));
        let ids = artifacts
            .iter()
            .filter_map(|artifact| artifact["artifactId"].as_str())
            .collect::<Vec<_>>();
        let mut sorted_ids = ids.clone();
        sorted_ids.sort_unstable();
        assert_eq!(ids, sorted_ids, "{scenario}: artifacts are stably sorted");
        assert_eq!(
            ids.iter().copied().collect::<BTreeSet<_>>().len(),
            ids.len(),
            "{scenario}: artifact IDs are unique"
        );

        let canonical = artifacts
            .iter()
            .map(|artifact| {
                (
                    artifact["artifactId"].as_str(),
                    artifact["direction"].as_str(),
                    artifact["originalBasename"].as_str(),
                    artifact["captureState"].as_str(),
                )
            })
            .collect::<BTreeSet<_>>();
        let reversed = artifacts
            .iter()
            .rev()
            .map(|artifact| {
                (
                    artifact["artifactId"].as_str(),
                    artifact["direction"].as_str(),
                    artifact["originalBasename"].as_str(),
                    artifact["captureState"].as_str(),
                )
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            canonical, reversed,
            "{scenario}: input order changed candidate projection"
        );
    }
}

#[test]
fn hierarchy_outputs_never_promote_coverage_or_time_to_cause() {
    for scenario in SCENARIOS {
        let expected = read_json(scenario, "expected.json")
            .unwrap_or_else(|error| panic!("{scenario}: {error}"));
        assert_eq!(expected["crossSideCausalClaims"], Value::Array(Vec::new()));
        assert_eq!(expected["correlationHandoff"]["performed"], false);
        assert_eq!(expected["correlationHandoff"]["timeOnlyEligible"], false);

        let coverage = expected["coverage"]
            .as_array()
            .unwrap_or_else(|| panic!("{scenario}: coverage is an array"));
        let coverage_by_id = coverage
            .iter()
            .filter_map(|row| {
                Some((
                    row["artifactId"].as_str()?.to_owned(),
                    row["state"].as_str()?.to_owned(),
                ))
            })
            .collect::<BTreeMap<_, _>>();
        for transaction in expected["transactions"]
            .as_array()
            .unwrap_or_else(|| panic!("{scenario}: transactions are an array"))
        {
            let confidence = transaction["confidence"].as_str().unwrap_or_default();
            let gaps = transaction["coverageGapArtifactIds"]
                .as_array()
                .unwrap_or_else(|| panic!("{scenario}: coverage gaps are an array"));
            if confidence == "high" {
                assert!(
                    gaps.is_empty(),
                    "{scenario}: high confidence retained a coverage gap"
                );
                assert_eq!(transaction["topologyCompatibility"], "exact");
                assert_eq!(transaction["timestampOrdering"], "usable");
                assert_eq!(transaction["terminalEvidence"], true);
            }
            for gap in gaps {
                let artifact_id = gap
                    .as_str()
                    .unwrap_or_else(|| panic!("{scenario}: gap ID is a string"));
                assert_ne!(
                    coverage_by_id.get(artifact_id).map(String::as_str),
                    Some("captured"),
                    "{scenario}: complete capture was labeled a gap"
                );
            }
        }
    }
}

#[test]
fn hierarchy_manifest_sources_and_physical_evidence_are_bounded() {
    let mut failures = Vec::new();
    for scenario in SCENARIOS {
        let scenario_root = corpus_root().join(scenario);
        let manifest = read_json(scenario, "manifest.json")
            .unwrap_or_else(|error| panic!("{scenario}: {error}"));
        if manifest["sccmManifestVersion"] != 1
            || manifest["bundle"]["bundleRole"] != "server"
            || manifest["bundle"]["workflow"] != "hierarchyAndReplication"
        {
            failures.push(format!(
                "{scenario}: manifest loses the additive server boundary"
            ));
        }
        if DateTime::parse_from_rfc3339(
            manifest["bundle"]["capturedUtc"]
                .as_str()
                .unwrap_or_default(),
        )
        .is_err()
        {
            failures.push(format!("{scenario}: capture time is not RFC3339"));
        }
        let roles = manifest["topology"]["rolesObserved"].as_array();
        if roles.is_none_or(|values| {
            values.len() != 1 || values.first().and_then(Value::as_str) != Some("siteServer")
        }) {
            failures.push(format!("{scenario}: topology roles are not exact strings"));
        }

        let mut destinations = BTreeSet::new();
        let mut fingerprints = BTreeSet::new();
        let artifacts = manifest["artifacts"]
            .as_array()
            .unwrap_or_else(|| panic!("{scenario}: artifacts are an array"));
        for artifact in artifacts {
            let artifact_id =
                required_string(artifact, "artifactId", scenario).unwrap_or("<invalid>");
            let context = format!("{scenario}/{artifact_id}");
            let role = required_string(artifact, "producerRole", &context).unwrap_or("invalid");
            let basename =
                required_string(artifact, "originalBasename", &context).unwrap_or("invalid");
            let direction = required_string(artifact, "direction", &context).unwrap_or("invalid");
            let state = required_string(artifact, "captureState", &context).unwrap_or("invalid");
            let source_id = required_string(artifact, "sourceId", &context).unwrap_or("invalid");
            if role != "siteServer"
                || !matches!(direction, "origin" | "target")
                || !matches!(
                    (source_id, basename),
                    ("server-hierarchy-control", "replmgr.log" | "rcmctrl.log")
                        | (
                            "server-hierarchy-transfer",
                            "sender.log" | "sender.lo_" | "despool.log"
                        )
                )
            {
                failures.push(format!("{context}: uncatalogued source tuple"));
            }
            let catalog = classify_artifact_name(basename, SccmRole::SiteServer);
            if catalog.family != SccmArtifactFamily::Hierarchy || !catalog.uses_ccm_records {
                failures.push(format!(
                    "{context}: source escapes the raw CCM hierarchy catalog"
                ));
            }
            if !artifact["producerHostHandle"]
                .as_str()
                .is_some_and(|value| value.starts_with("safe:server:"))
                || !artifact["sanitizedSourcePath"]
                    .as_str()
                    .is_some_and(|value| safe_segmented_path(value, "SYNTHETIC://"))
                || !artifact["pathFingerprint"].as_str().is_some_and(|value| {
                    value
                        .strip_prefix("synthetic:")
                        .is_some_and(|suffix| !suffix.is_empty())
                })
                || !artifact["sourceVersion"]
                    .as_str()
                    .is_some_and(|value| value.starts_with("5.00.TEST.") && value.len() > 10)
            {
                failures.push(format!("{context}: unsafe or empty provenance"));
            }
            if artifact["pathFingerprint"]
                .as_str()
                .map(str::to_ascii_lowercase)
                .is_some_and(|value| !fingerprints.insert(value))
            {
                failures.push(format!("{context}: duplicate physical fingerprint"));
            }
            let Some(coverage) = coverage_state(state) else {
                failures.push(format!("{context}: unknown coverage state"));
                continue;
            };
            let Some(rotation) = rotation(&artifact["rotation"]) else {
                failures.push(format!("{context}: invalid rotation shape"));
                continue;
            };
            let physical = matches!(state, "captured" | "capped" | "parseFailed");
            if physical {
                let relative_path = artifact["relativePath"].as_str().unwrap_or_default();
                if !safe_segmented_path(relative_path, "evidence/")
                    || !destinations.insert(relative_path.to_ascii_lowercase())
                    || artifact["encoding"] != "utf-8"
                    || artifact["bytesCopied"].as_u64().is_none()
                    || artifact["collectionLimit"]["byteLimit"].as_u64().is_none()
                    || artifact["collectionLimit"]["limitApplied"]
                        .as_bool()
                        .is_none()
                {
                    failures.push(format!("{context}: invalid physical storage provenance"));
                    continue;
                }
                let path = scenario_root.join(relative_path);
                let bytes = match std::fs::read(&path) {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        failures.push(format!("{} is readable: {error}", path.display()));
                        continue;
                    }
                };
                if artifact["bytesCopied"].as_u64() != Some(bytes.len() as u64)
                    || !String::from_utf8_lossy(&bytes).contains("SYNTHETIC FIXTURE")
                {
                    failures.push(format!("{context}: physical bytes are not exact/synthetic"));
                }
                let model = SccmArtifact {
                    artifact_id: artifact_id.to_owned(),
                    display_name: basename.to_owned(),
                    original_path: None,
                    host: artifact["producerHostHandle"].as_str().map(str::to_owned),
                    role: SccmRole::SiteServer,
                    configmgr_version: artifact["sourceVersion"].as_str().map(str::to_owned),
                    collected_at_utc: artifact["collectedUtc"].as_str().map(str::to_owned),
                    rotation,
                    coverage,
                    encoding: Some("utf-8".to_owned()),
                };
                let normalized = normalize_ccm_artifact(model, &String::from_utf8_lossy(&bytes));
                if artifact["rotation"]["fragmentComplete"] == false && !normalized.is_empty() {
                    failures.push(format!(
                        "{context}: incomplete rotation fragment emitted a logical record"
                    ));
                }
                if artifact["rotation"]["fragmentComplete"] == true
                    && normalized.iter().any(|record| {
                        !record.message.contains("SYNTHETIC FIXTURE")
                            || record.reference.line_start.is_none()
                            || record.reference.line_end.is_none()
                    })
                {
                    failures.push(format!("{context}: logical evidence is not line-cited"));
                }
            } else if artifact.get("relativePath").is_some()
                || artifact.get("bytesCopied").is_some()
                || artifact.get("encoding").is_some()
                || artifact.get("collectionLimit").is_some()
                || artifact["rotation"].get("fragmentComplete").is_some()
            {
                failures.push(format!(
                    "{context}: nonphysical coverage invents file provenance"
                ));
            }
        }
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn hierarchy_transactions_require_exact_keys_topology_time_and_citations() {
    let mut failures = Vec::new();
    for scenario in SCENARIOS {
        let manifest = read_json(scenario, "manifest.json")
            .unwrap_or_else(|error| panic!("{scenario}: {error}"));
        let expected = read_json(scenario, "expected.json")
            .unwrap_or_else(|error| panic!("{scenario}: {error}"));
        let records = normalized_records(scenario, &manifest);
        let artifacts = manifest["artifacts"]
            .as_array()
            .expect("manifest artifacts are an array")
            .iter()
            .filter_map(|artifact| {
                Some((
                    artifact["artifactId"].as_str()?.to_owned(),
                    artifact.clone(),
                ))
            })
            .collect::<BTreeMap<_, _>>();

        let manifest_coverage = artifacts
            .iter()
            .filter_map(|(artifact_id, artifact)| {
                Some((
                    artifact_id.clone(),
                    artifact["captureState"].as_str()?.to_owned(),
                ))
            })
            .collect::<BTreeMap<_, _>>();
        let declared_coverage = expected["coverage"]
            .as_array()
            .expect("expected coverage is an array")
            .iter()
            .filter_map(|row| {
                Some((
                    row["artifactId"].as_str()?.to_owned(),
                    row["state"].as_str()?.to_owned(),
                ))
            })
            .collect::<BTreeMap<_, _>>();
        if manifest_coverage != declared_coverage {
            failures.push(format!(
                "{scenario}: coverage is not the exact manifest projection"
            ));
        }

        let transactions = expected["transactions"]
            .as_array()
            .expect("transactions are an array");
        let transaction_ids = transactions
            .iter()
            .filter_map(|transaction| transaction["transactionId"].as_str())
            .collect::<Vec<_>>();
        let mut sorted_transaction_ids = transaction_ids.clone();
        sorted_transaction_ids.sort_unstable();
        sorted_transaction_ids.dedup();
        if transaction_ids != sorted_transaction_ids {
            failures.push(format!(
                "{scenario}: transactions are not sorted and unique"
            ));
        }

        for transaction in transactions {
            let transaction_id = transaction["transactionId"].as_str().unwrap_or("<invalid>");
            let key = &transaction["key"];
            let key_fields = [
                ("MessageId", key["messageId"].as_str()),
                ("LinkId", key["linkId"].as_str()),
                ("OriginSite", key["originSiteCode"].as_str()),
                ("TargetSite", key["targetSiteCode"].as_str()),
                ("ProfileId", key["extractionProfileId"].as_str()),
            ];
            if key_fields
                .iter()
                .any(|(_, value)| value.is_none_or(str::is_empty))
                || key["confidence"] != "exact"
                || key["extractionProfileId"] != EXACT_PROFILE
            {
                failures.push(format!("{scenario}/{transaction_id}: key is not exact"));
                continue;
            }
            let derived_id = format!(
                "hierarchy:{}:{}:{}:{}",
                key["messageId"].as_str().unwrap_or_default(),
                key["originSiteCode"].as_str().unwrap_or_default(),
                key["targetSiteCode"].as_str().unwrap_or_default(),
                key["linkId"].as_str().unwrap_or_default()
            );
            if transaction_id != derived_id {
                failures.push(format!(
                    "{scenario}/{transaction_id}: ID is not key-derived"
                ));
            }

            let observations = transaction["observations"]
                .as_array()
                .expect("transaction observations are an array");
            let observation_ids = observations
                .iter()
                .filter_map(|observation| observation["observationId"].as_str())
                .collect::<Vec<_>>();
            let mut sorted_observation_ids = observation_ids.clone();
            sorted_observation_ids.sort_unstable();
            sorted_observation_ids.dedup();
            if observation_ids != sorted_observation_ids || observation_ids.is_empty() {
                failures.push(format!(
                    "{scenario}/{transaction_id}: observations are not exact sorted identities"
                ));
            }

            let mut prior_phase = 0usize;
            let mut prior_utc = i64::MIN;
            let mut cited_terminal = false;
            let mut cited_records = BTreeSet::new();
            for observation in observations {
                let observation_id = observation["observationId"].as_str().unwrap_or("<invalid>");
                let phase = observation["phase"].as_str().unwrap_or("invalid");
                let disposition = observation["disposition"].as_str().unwrap_or("invalid");
                let terminal = observation["terminal"].as_bool().unwrap_or(false);
                let Some(phase_index) =
                    STATE_CHAIN.iter().position(|candidate| *candidate == phase)
                else {
                    failures.push(format!("{scenario}/{observation_id}: unsupported phase"));
                    continue;
                };
                if phase_index < prior_phase {
                    failures.push(format!(
                        "{scenario}/{transaction_id}: backward phase ordering"
                    ));
                }
                prior_phase = phase_index;
                if !matches!(
                    (disposition, terminal),
                    ("succeeded", false | true)
                        | ("failed", true)
                        | ("retrying" | "deferred", false)
                ) {
                    failures.push(format!(
                        "{scenario}/{observation_id}: incoherent disposition/terminality"
                    ));
                }
                cited_terminal |= terminal;

                let references = observation["evidence"]
                    .as_array()
                    .expect("observation evidence is an array");
                if references.is_empty() {
                    failures.push(format!("{scenario}/{observation_id}: no evidence"));
                }
                for reference in references {
                    let artifact_id = reference["artifactId"].as_str().unwrap_or_default();
                    let line_start = reference["startLine"]
                        .as_u64()
                        .and_then(|value| u32::try_from(value).ok());
                    let line_end = reference["endLine"]
                        .as_u64()
                        .and_then(|value| u32::try_from(value).ok());
                    let Some(record) = line_start.zip(line_end).and_then(|(start, end)| {
                        records.get(&(artifact_id.to_owned(), start, end))
                    }) else {
                        failures.push(format!(
                            "{scenario}/{observation_id}: evidence is not a physical logical record"
                        ));
                        continue;
                    };
                    if !cited_records.insert((
                        artifact_id.to_owned(),
                        line_start.unwrap_or_default(),
                        line_end.unwrap_or_default(),
                    )) {
                        failures.push(format!(
                            "{scenario}/{transaction_id}: physical evidence reused"
                        ));
                    }
                    let Some(artifact) = artifacts.get(artifact_id) else {
                        failures.push(format!("{scenario}/{observation_id}: unknown artifact"));
                        continue;
                    };
                    if !phase_is_owned_by(
                        artifact["originalBasename"].as_str().unwrap_or_default(),
                        phase,
                    ) {
                        failures.push(format!(
                            "{scenario}/{observation_id}: source cannot own phase {phase}"
                        ));
                    }
                    let fields = match parse_fixture_fields(&record.message) {
                        Ok(fields) => fields,
                        Err(error) => {
                            failures.push(format!("{scenario}/{observation_id}: {error}"));
                            continue;
                        }
                    };
                    for (field, value) in &key_fields {
                        if fields.get(*field).map(String::as_str) != *value {
                            failures.push(format!(
                                "{scenario}/{observation_id}: evidence key {field} diverges"
                            ));
                        }
                    }
                    if fields.get("Phase").map(String::as_str) != Some(phase)
                        || fields.get("Disposition").map(String::as_str) != Some(disposition)
                        || fields.get("Terminal").map(String::as_str)
                            != Some(if terminal { "true" } else { "false" })
                    {
                        failures.push(format!(
                            "{scenario}/{observation_id}: evidence semantics diverge"
                        ));
                    }
                    match transaction["timestampOrdering"].as_str() {
                        Some("usable") => {
                            if record.timestamp.ordering_state
                                != SccmTimeOrderingState::NormalizedUtc
                                || record.timestamp.utc_millis.is_none()
                                || record
                                    .timestamp
                                    .utc_millis
                                    .is_some_and(|utc| utc < prior_utc)
                            {
                                failures.push(format!(
                                    "{scenario}/{transaction_id}: unusable or reversed time"
                                ));
                            }
                            if let Some(utc) = record.timestamp.utc_millis {
                                prior_utc = utc;
                            }
                        }
                        Some("unusableInvalidOffset") => {
                            if record.timestamp.ordering_state
                                != SccmTimeOrderingState::OffsetInvalid
                            {
                                failures.push(format!(
                                    "{scenario}/{transaction_id}: invalid offset was treated as usable"
                                ));
                            }
                        }
                        _ => failures.push(format!(
                            "{scenario}/{transaction_id}: unknown timestamp ordering"
                        )),
                    }
                }
            }
            if transaction["terminalEvidence"].as_bool() != Some(cited_terminal) {
                failures.push(format!(
                    "{scenario}/{transaction_id}: terminality is not citation-derived"
                ));
            }
        }

        let outcome = transactions
            .iter()
            .map(|transaction| {
                (
                    transaction["state"].as_str(),
                    transaction["classification"].as_str(),
                    transaction["confidence"].as_str(),
                )
            })
            .collect::<Vec<_>>();
        let expected_outcome: &[(Option<&str>, Option<&str>, Option<&str>)] = match *scenario {
            "absent-remote-source" | "clock-offset-unknown" => &[(
                Some("incomplete"),
                Some("insufficientEvidence"),
                Some("low"),
            )],
            "backlog-retry" => &[(Some("deferred"), Some("blockedOrDeferred"), Some("medium"))],
            "healthy-link" => &[(Some("succeeded"), Some("success"), Some("high"))],
            "incomplete" | "rotation-boundary" | "topology-mismatch" => &[],
            "receiver-processing-failure" => {
                &[(Some("failed"), Some("confirmedFailure"), Some("high"))]
            }
            "recovery" => &[(Some("recovered"), Some("success"), Some("high"))],
            "sender-failure" => &[
                (Some("failed"), Some("confirmedFailure"), Some("high")),
                (Some("failed"), Some("confirmedFailure"), Some("high")),
            ],
            _ => &[],
        };
        if outcome != expected_outcome {
            failures.push(format!("{scenario}: outcome matrix changed"));
        }

        if *scenario == "topology-mismatch" {
            let fields = records
                .values()
                .map(|record| parse_fixture_fields(&record.message).expect("fields parse"))
                .collect::<Vec<_>>();
            if fields.len() != 2
                || fields[0].get("MessageId") != fields[1].get("MessageId")
                || fields[0].get("LinkId") == fields[1].get("LinkId")
                || fields[0].get("TargetSite") == fields[1].get("TargetSite")
            {
                failures.push(
                    "topology-mismatch: adversarial facts are not exact-key mismatches".to_owned(),
                );
            }
        }
        if *scenario == "rotation-boundary" && !records.is_empty() {
            failures.push("rotation-boundary: split fragments formed evidence".to_owned());
        }
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn hierarchy_gaps_requests_and_source_local_controls_are_bounded() {
    let mut failures = Vec::new();
    for scenario in SCENARIOS {
        let manifest = read_json(scenario, "manifest.json")
            .unwrap_or_else(|error| panic!("{scenario}: {error}"));
        let expected = read_json(scenario, "expected.json")
            .unwrap_or_else(|error| panic!("{scenario}: {error}"));
        let records = normalized_records(scenario, &manifest);
        let artifacts = manifest["artifacts"]
            .as_array()
            .expect("artifacts are an array")
            .iter()
            .filter_map(|artifact| {
                Some((
                    artifact["artifactId"].as_str()?.to_owned(),
                    artifact.clone(),
                ))
            })
            .collect::<BTreeMap<_, _>>();

        let requests = expected["artifactRequests"]
            .as_array()
            .expect("artifact requests are an array");
        let request_keys = requests
            .iter()
            .map(|request| {
                (
                    request["sourceId"].as_str(),
                    request["direction"].as_str(),
                    request["targetSiteCode"].as_str(),
                    request["reasonCode"].as_str(),
                )
            })
            .collect::<Vec<_>>();
        let mut sorted_request_keys = request_keys.clone();
        sorted_request_keys.sort_unstable();
        sorted_request_keys.dedup();
        if request_keys != sorted_request_keys {
            failures.push(format!("{scenario}: requests are not sorted and unique"));
        }
        for request in requests {
            let source_id = request["sourceId"].as_str();
            let direction = request["direction"].as_str();
            let target_site = request["targetSiteCode"].as_str();
            let reason = request["reasonCode"].as_str();
            let basenames = request["basenames"]
                .as_array()
                .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>())
                .unwrap_or_default();
            let mut sorted_basenames = basenames.clone();
            sorted_basenames.sort_unstable();
            sorted_basenames.dedup();
            if !matches!(
                source_id,
                Some("server-hierarchy-control" | "server-hierarchy-transfer")
            ) || request["producerRole"] != "siteServer"
                || !matches!(direction, Some("origin" | "target" | "both"))
                || target_site.is_none_or(|site| {
                    site.len() != 3
                        || !site
                            .bytes()
                            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
                })
                || !matches!(
                    reason,
                    Some(
                        "coverageAbsent"
                            | "coverageCapped"
                            | "coverageRotationSplit"
                            | "invalidOffset"
                    )
                )
                || basenames != sorted_basenames
                || basenames.iter().any(|basename| {
                    !matches!(
                        *basename,
                        "replmgr.log" | "sender.log" | "sender.lo_" | "despool.log"
                    )
                })
            {
                failures.push(format!("{scenario}: request is broad or malformed"));
            }
            let backed = match reason {
                Some("coverageAbsent") => artifacts.values().any(|artifact| {
                    artifact["sourceId"] == request["sourceId"]
                        && artifact["direction"] == request["direction"]
                        && artifact["captureState"] == "absent"
                }),
                Some("coverageCapped") => artifacts.values().any(|artifact| {
                    artifact["sourceId"] == request["sourceId"]
                        && artifact["direction"] == request["direction"]
                        && artifact["captureState"] == "capped"
                }),
                Some("coverageRotationSplit") => {
                    artifacts
                        .values()
                        .filter(|artifact| {
                            artifact["sourceId"] == request["sourceId"]
                                && artifact["direction"] == request["direction"]
                                && artifact["rotation"]["fragmentComplete"] == false
                        })
                        .count()
                        >= 2
                }
                Some("invalidOffset") => records.values().any(|record| {
                    record.timestamp.ordering_state == SccmTimeOrderingState::OffsetInvalid
                }),
                _ => false,
            };
            if !backed {
                failures.push(format!(
                    "{scenario}: request is not backed by exact coverage/time evidence"
                ));
            }
        }

        let request_reason_codes = requests
            .iter()
            .filter_map(|request| request["reasonCode"].as_str())
            .collect::<Vec<_>>();
        let expected_reasons: &[&str] = match *scenario {
            "absent-remote-source" => &["coverageAbsent"],
            "clock-offset-unknown" => &["invalidOffset"],
            "incomplete" => &["coverageCapped"],
            "rotation-boundary" => &["coverageRotationSplit"],
            _ => &[],
        };
        if request_reason_codes != expected_reasons {
            failures.push(format!("{scenario}: bounded request matrix changed"));
        }

        let source_local = expected["sourceLocalObservations"]
            .as_array()
            .expect("source-local observations are an array");
        let source_local_classes = source_local
            .iter()
            .filter_map(|observation| observation["classification"].as_str())
            .collect::<Vec<_>>();
        let expected_classes: &[&str] = match *scenario {
            "incomplete" => &["coverageOnly"],
            "rotation-boundary" => &["rotationSplit"],
            "topology-mismatch" => &["topologyMismatch", "topologyMismatch"],
            _ => &[],
        };
        if source_local_classes != expected_classes {
            failures.push(format!("{scenario}: source-local control matrix changed"));
        }
        for observation in source_local {
            if observation["confidence"] != "low" || observation["correlationEligible"] != false {
                failures.push(format!(
                    "{scenario}: source-local evidence became correlatable"
                ));
            }
            for reference in observation["evidence"]
                .as_array()
                .expect("source-local evidence is an array")
            {
                let key = (
                    reference["artifactId"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned(),
                    reference["startLine"]
                        .as_u64()
                        .and_then(|value| u32::try_from(value).ok())
                        .unwrap_or_default(),
                    reference["endLine"]
                        .as_u64()
                        .and_then(|value| u32::try_from(value).ok())
                        .unwrap_or_default(),
                );
                if !records.contains_key(&key) {
                    failures.push(format!(
                        "{scenario}: source-local evidence is not physically cited"
                    ));
                }
            }
        }
    }

    let contract =
        include_str!("../../../docs/sccm/preparation/issue-331-hierarchy-replication-corpus.md");
    for required in [
        "Raw CCM remains the transport grammar",
        "timestamp proximity\nalone cannot create a transaction",
        "A missing remote artifact\nis a coverage state, not evidence that the remote role is absent or broken",
        "time alone is never eligible",
        "not an\nacceptance source",
    ] {
        if !contract.contains(required) {
            failures.push(format!("preparation document lost boundary: {required}"));
        }
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn hierarchy_schema_and_identity_mutations_fail_closed() {
    for scenario in SCENARIOS {
        let manifest = read_json(scenario, "manifest.json")
            .unwrap_or_else(|error| panic!("{scenario}: {error}"));
        let expected = read_json(scenario, "expected.json")
            .unwrap_or_else(|error| panic!("{scenario}: {error}"));
        assert!(
            identity_and_schema_failures(scenario, &manifest, &expected).is_empty(),
            "{scenario}: committed schema is invalid"
        );
    }

    let healthy_manifest = read_json("healthy-link", "manifest.json").expect("manifest loads");
    let healthy_expected = read_json("healthy-link", "expected.json").expect("expected loads");
    let absent_manifest =
        read_json("absent-remote-source", "manifest.json").expect("manifest loads");
    let absent_expected =
        read_json("absent-remote-source", "expected.json").expect("expected loads");
    let clock_manifest =
        read_json("clock-offset-unknown", "manifest.json").expect("manifest loads");
    let clock_expected =
        read_json("clock-offset-unknown", "expected.json").expect("expected loads");
    let mut accepted = Vec::new();

    let mut unknown_manifest_field = healthy_manifest.clone();
    unknown_manifest_field["serverRootCause"] = Value::String("network".to_owned());
    if identity_and_schema_failures("healthy-link", &unknown_manifest_field, &healthy_expected)
        .is_empty()
    {
        accepted.push("unknown manifest cause field");
    }

    let mut non_string_role = healthy_manifest.clone();
    non_string_role["topology"]["rolesObserved"]
        .as_array_mut()
        .expect("roles are mutable")
        .push(Value::from(7));
    if identity_and_schema_failures("healthy-link", &non_string_role, &healthy_expected).is_empty()
    {
        accepted.push("non-string topology role");
    }

    let mut aliased_destination = healthy_manifest.clone();
    aliased_destination["artifacts"][1]["relativePath"] =
        Value::String("evidence/server-hierarchy-control/origin/current/./replmgr.log".to_owned());
    if identity_and_schema_failures("healthy-link", &aliased_destination, &healthy_expected)
        .is_empty()
    {
        accepted.push("dot-segment evidence alias");
    }

    let mut unsafe_source = healthy_manifest.clone();
    unsafe_source["artifacts"][0]["sanitizedSourcePath"] =
        Value::String("SYNTHETIC://../../Users/Real/replmgr.log".to_owned());
    if identity_and_schema_failures("healthy-link", &unsafe_source, &healthy_expected).is_empty() {
        accepted.push("unsafe sanitized source path");
    }

    let mut empty_fingerprint = healthy_manifest.clone();
    empty_fingerprint["artifacts"][0]["pathFingerprint"] = Value::String("synthetic:".to_owned());
    if identity_and_schema_failures("healthy-link", &empty_fingerprint, &healthy_expected)
        .is_empty()
    {
        accepted.push("empty path fingerprint");
    }

    let mut unknown_version = healthy_manifest.clone();
    unknown_version["artifacts"][0]["sourceVersion"] = Value::String("9.99.UNKNOWN".to_owned());
    if identity_and_schema_failures("healthy-link", &unknown_version, &healthy_expected).is_empty()
    {
        accepted.push("unknown source version retained selected profile");
    }

    let mut nonphysical_file = absent_manifest.clone();
    nonphysical_file["artifacts"][1]["relativePath"] = Value::Bool(false);
    if identity_and_schema_failures("absent-remote-source", &nonphysical_file, &absent_expected)
        .is_empty()
    {
        accepted.push("nonphysical coverage invented a malformed path");
    }

    let mut non_string_state = healthy_expected.clone();
    non_string_state["stateChain"]
        .as_array_mut()
        .expect("state chain is mutable")
        .push(Value::from(7));
    if identity_and_schema_failures("healthy-link", &healthy_manifest, &non_string_state).is_empty()
    {
        accepted.push("non-string state-chain entry");
    }

    let mut missing_observation = healthy_expected.clone();
    missing_observation["transactions"][0]["observations"]
        .as_array_mut()
        .expect("observations are mutable")
        .remove(1);
    if identity_and_schema_failures("healthy-link", &healthy_manifest, &missing_observation)
        .is_empty()
    {
        accepted.push("required observation deleted");
    }

    let mut mismatched_key = healthy_expected.clone();
    mismatched_key["transactions"][0]["key"]["targetSiteCode"] = Value::String("SEC".to_owned());
    if identity_and_schema_failures("healthy-link", &healthy_manifest, &mismatched_key).is_empty() {
        accepted.push("transaction ID diverged from immutable topology key");
    }

    let mut time_only_high = clock_expected.clone();
    time_only_high["transactions"][0]["confidence"] = Value::String("high".to_owned());
    time_only_high["transactions"][0]["confidenceCeiling"] = Value::String("high".to_owned());
    if identity_and_schema_failures("clock-offset-unknown", &clock_manifest, &time_only_high)
        .is_empty()
    {
        accepted.push("invalid-offset transaction became high confidence");
    }

    let mut causal_claim = healthy_expected.clone();
    causal_claim["crossSideCausalClaims"] =
        Value::Array(vec![Value::String("same-time client impact".to_owned())]);
    if identity_and_schema_failures("healthy-link", &healthy_manifest, &causal_claim).is_empty() {
        accepted.push("cross-side causal claim");
    }

    assert!(
        accepted.is_empty(),
        "hierarchy contract accepted adversarial mutations: {accepted:?}"
    );
}
