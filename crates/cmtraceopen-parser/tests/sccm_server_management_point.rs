use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use cmtraceopen_parser::sccm::{
    analyze_management_point, declared_source_catalog, normalize_ccm_artifact, SccmArtifact,
    SccmArtifactFamily, SccmCoverageState, SccmManagementPointBundle, SccmManagementPointSource,
    SccmManagementPointTopology, SccmRole, SccmRotation,
};
use serde::Deserialize;
use serde_json::{json, Value};

const FIXTURE_ROOT: &str = "tests/fixtures/sccm/server/management-point";
const SCENARIOS: &[&str] = &[
    "healthy-policy",
    "auth-failure",
    "registration-failure",
    "location-failure",
    "policy-failure",
    "iis-supplemental",
    "unrelated-client-like-key",
    "rotation-boundary",
    "incomplete",
];

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureManifest {
    topology: FixtureTopology,
    artifacts: Vec<FixtureArtifact>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureTopology {
    site_code: String,
    management_point_host_handle: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureArtifact {
    artifact_id: String,
    design_only_catalog: FixtureCatalog,
    role: String,
    producer: String,
    capture_state: String,
    original_basename: String,
    rotation: FixtureRotation,
    source_version: Option<String>,
    collected_utc: Option<String>,
    encoding: Option<String>,
    relative_path: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureCatalog {
    entry_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureRotation {
    kind: String,
    value: Option<Value>,
    fragment_complete: Option<bool>,
}

fn fixture_directory(scenario: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(FIXTURE_ROOT)
        .join(scenario)
}

fn load_json(path: &Path) -> Value {
    serde_json::from_str(&fs::read_to_string(path).expect("fixture JSON must be readable"))
        .expect("fixture JSON must be valid")
}

fn coverage_state(value: &str) -> SccmCoverageState {
    match value {
        "captured" => SccmCoverageState::Captured,
        "absent" => SccmCoverageState::Absent,
        "accessDenied" => SccmCoverageState::AccessDenied,
        "capped" => SccmCoverageState::Capped,
        "skipped" => SccmCoverageState::Skipped,
        "unsupported" => SccmCoverageState::Unsupported,
        "parseFailed" => SccmCoverageState::ParseFailed,
        other => panic!("unsupported fixture coverage state {other}"),
    }
}

fn rotation(value: &FixtureRotation) -> SccmRotation {
    match value.kind.as_str() {
        "current" => SccmRotation::Current,
        "lo" | "loUnderscore" => SccmRotation::LoUnderscore,
        "numbered" => SccmRotation::Numbered(
            value
                .value
                .as_ref()
                .and_then(Value::as_u64)
                .and_then(|number| u32::try_from(number).ok())
                .expect("numbered rotation must contain a u32"),
        ),
        "timestamped" => SccmRotation::Timestamped(
            value
                .value
                .as_ref()
                .and_then(Value::as_str)
                .expect("timestamped rotation must contain a string")
                .to_owned(),
        ),
        other => panic!("unsupported fixture rotation {other}"),
    }
}

fn load_bundle(scenario: &str) -> SccmManagementPointBundle {
    let directory = fixture_directory(scenario);
    let manifest: FixtureManifest =
        serde_json::from_value(load_json(&directory.join("manifest.json")))
            .expect("fixture manifest must match its declared contract");

    let mut sources = Vec::new();
    let mut evidence = Vec::new();
    for source in manifest.artifacts {
        assert_eq!(
            source.role, "managementPoint",
            "MP fixtures must preserve their server role"
        );
        let artifact = SccmArtifact {
            artifact_id: source.artifact_id,
            display_name: source.original_basename,
            original_path: None,
            host: None,
            role: SccmRole::ManagementPoint,
            configmgr_version: source.source_version,
            collected_at_utc: source.collected_utc,
            rotation: rotation(&source.rotation),
            coverage: coverage_state(&source.capture_state),
            encoding: source.encoding,
        };

        let physical_line_end = if let Some(relative_path) = source.relative_path {
            let content = fs::read_to_string(directory.join(relative_path))
                .expect("captured MP evidence must be readable UTF-8");
            let line_count = u32::try_from(content.lines().count())
                .expect("synthetic fixture line count must fit in u32");
            evidence.extend(normalize_ccm_artifact(artifact.clone(), &content));
            Some(line_count.max(1))
        } else {
            None
        };

        sources.push(SccmManagementPointSource {
            artifact,
            source_group: source.design_only_catalog.entry_id,
            producer: source.producer,
            fragment_complete: source.rotation.fragment_complete,
            physical_line_end,
        });
    }

    sources.sort_by(|left, right| left.artifact.artifact_id.cmp(&right.artifact.artifact_id));
    evidence.sort_by(|left, right| left.evidence_id.cmp(&right.evidence_id));
    SccmManagementPointBundle {
        topology: SccmManagementPointTopology {
            site_code: manifest.topology.site_code,
            management_point_host_handle: manifest.topology.management_point_host_handle,
        },
        sources,
        evidence,
    }
}

fn expected_transaction_projection(expected: &Value) -> Vec<Value> {
    expected["transactions"]
        .as_array()
        .expect("expected transactions")
        .iter()
        .map(|transaction| {
            json!({
                "transactionId": transaction["transactionId"],
                "phase": transaction["phase"],
                "state": transaction["state"],
                "lastSuccessfulPhase": transaction["lastSuccessfulPhase"],
                "classification": transaction["classification"],
                "confidence": transaction["confidence"],
                "coverageGapArtifactIds": transaction["coverageGapArtifactIds"],
                "nextArtifactLogicalId": transaction["nextArtifact"]["logicalArtifactId"],
            })
        })
        .collect()
}

fn actual_transaction_projection(analysis: &Value) -> Vec<Value> {
    analysis["transactions"]
        .as_array()
        .expect("analysis transactions")
        .iter()
        .map(|transaction| {
            json!({
                "transactionId": transaction["transactionId"],
                "phase": transaction["phase"],
                "state": transaction["state"],
                "lastSuccessfulPhase": transaction["lastSuccessfulPhase"],
                "classification": transaction["classification"],
                "confidence": transaction["confidence"],
                "coverageGapArtifactIds": transaction["coverageGapArtifactIds"],
                "nextArtifactLogicalId": transaction["nextArtifacts"]
                    .as_array()
                    .and_then(|requests| requests.first())
                    .map(|request| request["logicalArtifactId"].clone())
                    .unwrap_or(Value::Null),
            })
        })
        .collect()
}

fn reference_is_within_expected_ranges(reference: &Value, expected_ranges: &[Value]) -> bool {
    let Some(artifact_id) = reference["artifactId"].as_str() else {
        return false;
    };
    let Some(line_start) = reference["lineStart"].as_u64() else {
        return false;
    };
    let Some(line_end) = reference["lineEnd"].as_u64() else {
        return false;
    };

    expected_ranges.iter().any(|expected_reference| {
        expected_reference["artifactId"].as_str() == Some(artifact_id)
            && expected_reference["startLine"]
                .as_u64()
                .is_some_and(|start| start <= line_start)
            && expected_reference["endLine"]
                .as_u64()
                .is_some_and(|end| line_end <= end)
    })
}

fn assert_transaction_contract(scenario: &str, analysis: &Value, expected: &Value) {
    let actual_by_id = analysis["transactions"]
        .as_array()
        .expect("analysis transactions")
        .iter()
        .map(|transaction| {
            (
                transaction["transactionId"]
                    .as_str()
                    .expect("transaction ID"),
                transaction,
            )
        })
        .collect::<BTreeMap<_, _>>();

    for expected_transaction in expected["transactions"]
        .as_array()
        .expect("expected transactions")
    {
        let transaction_id = expected_transaction["transactionId"]
            .as_str()
            .expect("expected transaction ID");
        let actual = actual_by_id
            .get(transaction_id)
            .unwrap_or_else(|| panic!("{scenario}: missing transaction {transaction_id}"));
        let expected_key = &expected_transaction["key"];
        assert_eq!(
            actual["key"],
            json!({
                "requestId": expected_key["requestId"],
                "policyId": expected_key["policyId"],
                "clientHandle": expected_key["clientHandle"],
                "siteCode": expected_key["siteCode"],
                "managementPointHostHandle": expected_key["managementPointHostHandle"],
                "confidence": expected_key["confidence"],
                "extractionProfileId": expected_key["extractionProfileId"],
            }),
            "{scenario}: {transaction_id} key"
        );

        let expected_ranges = expected_transaction["evidence"]
            .as_array()
            .expect("expected transaction evidence");
        let actual_references = actual["evidence"]
            .as_array()
            .expect("analysis transaction evidence");
        assert!(
            actual_references
                .iter()
                .all(|reference| reference_is_within_expected_ranges(reference, expected_ranges)),
            "{scenario}: {transaction_id} emitted uncited evidence"
        );
        for expected_reference in expected_ranges {
            assert!(
                actual_references.iter().any(|reference| {
                    reference["artifactId"] == expected_reference["artifactId"]
                }),
                "{scenario}: {transaction_id} omitted expected artifact evidence"
            );
        }

        let observations = actual["observations"]
            .as_array()
            .expect("transaction observations");
        assert!(!observations.is_empty(), "{scenario}: observations");
        assert!(observations.iter().all(|observation| {
            observation["evidence"]
                .as_array()
                .is_some_and(|references| !references.is_empty())
        }));
    }
}

fn source_local_projection(value: &Value, actual: bool) -> Vec<Value> {
    value["sourceLocalObservations"]
        .as_array()
        .expect("source-local observations")
        .iter()
        .map(|observation| {
            let next_logical_id = if actual {
                observation["nextArtifacts"]
                    .as_array()
                    .and_then(|requests| requests.first())
                    .map(|request| request["logicalArtifactId"].clone())
                    .unwrap_or(Value::Null)
            } else {
                observation["nextArtifact"]["logicalArtifactId"].clone()
            };
            json!({
                "observationId": observation["observationId"],
                "phase": observation["phase"],
                "classification": observation["classification"],
                "confidence": observation["confidence"],
                "correlationEligible": observation["correlationEligible"],
                "nextArtifactLogicalId": next_logical_id,
            })
        })
        .collect()
}

fn map_shared_request_to_group(logical_id: &str) -> Option<&'static str> {
    match logical_id {
        "mpCliReg" | "mpGetAuth" | "mpRegistrationManager" => Some("server-mp-auth"),
        "mpGetPolicy" | "mpLocation" => Some("server-mp-policy"),
        _ => None,
    }
}

fn expected_finding_signatures(expected: &Value) -> Vec<Value> {
    let mut signatures = expected["findings"]
        .as_array()
        .expect("expected findings")
        .iter()
        .map(|finding| {
            let class = match finding["class"].as_str().expect("finding class") {
                "contradictoryEvidence" | "lowConfidenceSymptom" => "symptom",
                class => class,
            };
            let confidence = match finding["confidence"].as_str().expect("finding confidence") {
                "medium" => "moderate",
                confidence => confidence,
            };
            json!({
                "subjectId": finding["subjectId"],
                "class": class,
                "phase": finding["phase"],
                "lastSuccessfulPhase": finding["lastSuccessfulPhase"],
                "confidence": confidence,
                "nextArtifactGroup": finding["nextArtifact"]["logicalArtifactId"],
            })
        })
        .collect::<Vec<_>>();
    signatures.sort_by_key(Value::to_string);
    signatures
}

fn actual_finding_signatures(analysis: &Value) -> Vec<Value> {
    let mut signatures = analysis["findings"]
        .as_array()
        .expect("analysis findings")
        .iter()
        .map(|finding| {
            let request_groups = finding["nextArtifacts"]
                .as_array()
                .expect("finding requests")
                .iter()
                .filter_map(|request| {
                    request["logicalId"]
                        .as_str()
                        .and_then(map_shared_request_to_group)
                })
                .collect::<BTreeSet<_>>();
            assert!(
                request_groups.len() <= 1,
                "one MP finding requested unrelated source groups"
            );
            json!({
                "subjectId": finding["subjectId"],
                "class": finding["class"],
                "phase": finding["phase"],
                "lastSuccessfulPhase": finding["lastSuccessfulPhase"],
                "confidence": finding["confidence"],
                "nextArtifactGroup": request_groups.first().copied(),
            })
        })
        .collect::<Vec<_>>();
    signatures.sort_by_key(Value::to_string);
    signatures
}

fn assert_findings_are_cited_and_conservative(analysis: &Value) {
    for finding in analysis["findings"].as_array().expect("analysis findings") {
        assert_eq!(finding["role"], "managementPoint");
        let evidence = finding["evidence"].as_array().expect("finding evidence");
        let terminal = finding["terminalEvidence"]
            .as_array()
            .expect("terminal evidence");
        let gaps = finding["coverageGaps"]
            .as_array()
            .expect("finding coverage gaps");
        let requests = finding["nextArtifacts"]
            .as_array()
            .expect("finding requests");

        for terminal_reference in terminal {
            assert!(
                evidence.contains(&terminal_reference["reference"]),
                "terminal evidence must also be cited"
            );
        }
        match finding["class"].as_str().expect("finding class") {
            "confirmedFailure" if finding["confidence"] == "high" => {
                assert!(
                    !terminal.is_empty(),
                    "high confirmed failure needs terminal evidence"
                );
            }
            "insufficientEvidence" => {
                assert!(!gaps.is_empty(), "insufficient evidence needs a gap");
                assert!(
                    !requests.is_empty(),
                    "insufficient evidence needs a request"
                );
            }
            _ => {}
        }
    }
}

#[test]
fn management_point_reducer_matches_the_frozen_terminal_and_coverage_contracts() {
    for scenario in SCENARIOS {
        let directory = fixture_directory(scenario);
        let expected = load_json(&directory.join("expected.json"));
        let analysis = serde_json::to_value(analyze_management_point(&load_bundle(scenario)))
            .expect("MP analysis must serialize");

        assert_eq!(analysis["schemaVersion"], 1, "{scenario}");
        assert_eq!(analysis["workflow"], "managementPoint", "{scenario}");
        assert_eq!(
            analysis["stateChain"],
            json!([
                "receiveRequest",
                "authenticate",
                "registerOrIdentify",
                "resolveLocationOrPolicy",
                "respond",
                "recordOutcome"
            ]),
            "{scenario}"
        );
        assert_eq!(
            analysis["crossSideCorrelationPerformed"], false,
            "{scenario}"
        );
        assert_eq!(
            actual_transaction_projection(&analysis),
            expected_transaction_projection(&expected),
            "{scenario}"
        );
        assert_transaction_contract(scenario, &analysis, &expected);
        assert_eq!(
            source_local_projection(&analysis, true),
            source_local_projection(&expected, false),
            "{scenario}"
        );
        assert_eq!(
            actual_finding_signatures(&analysis),
            expected_finding_signatures(&expected),
            "{scenario}: finding semantics"
        );
        assert_findings_are_cited_and_conservative(&analysis);

        let serialized = serde_json::to_string(&analysis).expect("analysis JSON");
        for prohibited in [
            "SYNTHETIC FIXTURE",
            "synthetic-mp-",
            "SYNTHETIC://",
            "captureHost",
            "executionContext",
            "root cause",
            "client impact",
        ] {
            assert!(
                !serialized.contains(prohibited),
                "{scenario}: public analysis leaked or claimed {prohibited}"
            );
        }
    }
}

#[test]
fn management_point_analysis_is_deterministic_under_bundle_reordering() {
    for scenario in SCENARIOS {
        let bundle = load_bundle(scenario);
        let expected =
            serde_json::to_string(&analyze_management_point(&bundle)).expect("analysis JSON");

        let mut reordered = bundle.clone();
        reordered.sources.reverse();
        reordered.evidence.reverse();
        let actual =
            serde_json::to_string(&analyze_management_point(&reordered)).expect("analysis JSON");
        assert_eq!(actual, expected, "{scenario}");
    }
}

#[test]
fn management_point_counterpart_handoff_requires_an_exact_policy_key() {
    for scenario in SCENARIOS {
        let analysis =
            serde_json::to_value(analyze_management_point(&load_bundle(scenario))).unwrap();
        for fact in analysis["counterpartReadyFacts"]
            .as_array()
            .expect("counterpart-ready facts")
        {
            assert_eq!(fact["key"]["confidence"], "exact", "{scenario}");
            assert!(
                fact["key"]["policyId"].as_str().is_some(),
                "{scenario}: policy counterpart fact needs a policy ID"
            );
            assert_eq!(
                fact["key"]["extractionProfileId"], "mp-server-5.00.test-v1",
                "{scenario}"
            );
            assert!(
                fact["evidence"]["lineStart"].as_u64().is_some(),
                "{scenario}: counterpart fact must cite evidence"
            );
        }
    }

    let unrelated = serde_json::to_value(analyze_management_point(&load_bundle(
        "unrelated-client-like-key",
    )))
    .unwrap();
    assert!(
        unrelated["counterpartReadyFacts"]
            .as_array()
            .expect("counterpart facts")
            .is_empty(),
        "a matching-looking client key cannot become an MP counterpart fact"
    );
}

#[test]
fn management_point_catalog_declares_every_reducer_source() {
    let sources = declared_source_catalog()
        .into_iter()
        .filter(|source| {
            source.role == SccmRole::ManagementPoint
                && source.family == SccmArtifactFamily::ManagementPoint
        })
        .map(|source| (source.basename, source.logical_name))
        .collect::<BTreeSet<_>>();

    for expected in [
        ("MP_CliReg.log", "mpCliReg"),
        ("MP_GetAuth.log", "mpGetAuth"),
        ("MP_GetPolicy.log", "mpGetPolicy"),
        ("MP_Location.log", "mpLocation"),
        ("MP_RegistrationManager.log", "mpRegistrationManager"),
        ("mpcontrol.log", "mpcontrol"),
    ] {
        let expected = (expected.0.to_owned(), expected.1.to_owned());
        assert!(
            sources.contains(&expected),
            "missing MP source {expected:?}"
        );
    }
}
